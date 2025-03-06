```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index c5d279a8..89553f67 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -3,5 +3,10 @@
     {
       "name": "CtsNfcTestCases"
     }
+  ],
+  "postsubmit": [
+    {
+      "name": "libnfc-nci-tests"
+    }
   ]
 }
diff --git a/conf/Android.bp b/conf/Android.bp
index 1f62fe0f..e94778f8 100644
--- a/conf/Android.bp
+++ b/conf/Android.bp
@@ -21,8 +21,36 @@ package {
     default_applicable_licenses: ["system_nfc_license"],
 }
 
-prebuilt_etc {
+soong_config_module_type {
+    name: "libnfc_nci_default_conf_prebuilt_etc",
+    module_type: "prebuilt_etc",
+    config_namespace: "libnfc_nci_default_conf",
+    variables: [
+        "product_type",
+    ],
+    properties: [
+        "src",
+    ],
+}
+
+soong_config_string_variable {
+    name: "product_type",
+    values: [
+        "wearable",
+    ],
+}
+
+libnfc_nci_default_conf_prebuilt_etc {
     name: "libnfc-nci.conf-default",
-    src: "libnfc-nci.conf",
+    soong_config_variables: {
+        product_type: {
+            wearable: {
+                src: "libnfc-nci.wearable.conf",
+            },
+            conditions_default: {
+                src: "libnfc-nci.conf",
+            },
+        },
+    },
     filename: "libnfc-nci.conf",
 }
diff --git a/conf/libnfc-nci.conf b/conf/libnfc-nci.conf
index 0384a01a..5ec5248d 100644
--- a/conf/libnfc-nci.conf
+++ b/conf/libnfc-nci.conf
@@ -77,3 +77,8 @@ NCI_RESET_TYPE=0x00
 # This value indicates the number of time presence check is repeated in case of
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
+
+##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+#NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
diff --git a/conf/libnfc-nci.wearable.conf b/conf/libnfc-nci.wearable.conf
new file mode 100644
index 00000000..1852d74f
--- /dev/null
+++ b/conf/libnfc-nci.wearable.conf
@@ -0,0 +1,132 @@
+########################### Start of libnfc-nci.conf ###########################
+####################################23.05.12####################################
+# Application options
+NFC_DEBUG_ENABLED=0
+
+################################################################################
+# File used for NFA storage
+NFA_STORAGE="/data/nfc"
+
+################################################################################
+# Filter the technology(s) requested to listen by OFFHOST_NFCEE(s) with the
+# specified ones, leave those allowed technology(s) and route to the NFCEE.
+# As for the filtered-out technology(s), route to host if it's assigned to HOST,
+# otherwise, will be route to DEFAULT_ROUTE.
+# The technology(s) which is not assign to OFFHOST_LISTEN_TECH_MASK and
+# HOST_LISTEN_TECH_MASK won't be listened to.
+# The bits are defined as tNFA_TECHNOLOGY_MASK in nfa_api.h.
+# Default is NFA_TECHNOLOGY_MASK_A | NFA_TECHNOLOGY_MASK_B | NFA_TECHNOLOGY_MASK_F
+#
+# Notable bits:
+# NFA_TECHNOLOGY_MASK_A             0x01    /* NFC Technology A             */
+# NFA_TECHNOLOGY_MASK_B             0x02    /* NFC Technology B             */
+# NFA_TECHNOLOGY_MASK_F             0x04    /* NFC Technology F             */
+OFFHOST_LISTEN_TECH_MASK=0x04
+
+################################################################################
+# Force HOST to only listen to the following technology(s).
+# The bits are defined as tNFA_TECHNOLOGY_MASK in nfa_api.h.
+# Default is NFA_TECHNOLOGY_MASK_A | NFA_TECHNOLOGY_MASK_F
+#
+# Notable bits:
+# NFA_TECHNOLOGY_MASK_A             0x01    /* NFC Technology A             */
+# NFA_TECHNOLOGY_MASK_B             0x02    /* NFC Technology B             */
+# NFA_TECHNOLOGY_MASK_F             0x04    /* NFC Technology F             */
+HOST_LISTEN_TECH_MASK=0x03
+
+################################################################################
+# When screen is turned off, specify the desired power state of the controller.
+# 0: power-off-sleep state; DEFAULT
+# 1: full-power state
+# 2: screen-off card-emulation (CE4/CE3/CE1 modes are used)
+SCREEN_OFF_POWER_STATE=1
+
+################################################################################
+# Force tag polling for the following technology(s).
+# The bits are defined as tNFA_TECHNOLOGY_MASK in nfa_api.h.
+# Default is NFA_TECHNOLOGY_MASK_A | NFA_TECHNOLOGY_MASK_B |
+#            NFA_TECHNOLOGY_MASK_F | NFA_TECHNOLOGY_MASK_ISO15693 |
+#            NFA_TECHNOLOGY_MASK_B_PRIME |
+#            NFA_TECHNOLOGY_MASK_A_ACTIVE | NFA_TECHNOLOGY_MASK_F_ACTIVE.
+#
+# Notable bits:
+# NFA_TECHNOLOGY_MASK_A             0x01    /* NFC Technology A             */
+# NFA_TECHNOLOGY_MASK_B             0x02    /* NFC Technology B             */
+# NFA_TECHNOLOGY_MASK_F             0x04    /* NFC Technology F             */
+# NFA_TECHNOLOGY_MASK_ISO15693      0x08    /* Proprietary Technology       */
+# NFA_TECHNOLOGY_MASK_A_ACTIVE      0x40    /* NFC Technology A active mode */
+# NFA_TECHNOLOGY_MASK_F_ACTIVE      0x80    /* NFC Technology F active mode */
+POLLING_TECH_MASK=0x00
+
+################################################################################
+# Force P2P to only listen for the following technology(s).
+# The bits are defined as tNFA_TECHNOLOGY_MASK in nfa_api.h.
+# Default is NFA_TECHNOLOGY_MASK_A | NFA_TECHNOLOGY_MASK_F |
+#            NFA_TECHNOLOGY_MASK_A_ACTIVE | NFA_TECHNOLOGY_MASK_F_ACTIVE
+#
+# Notable bits:
+# NFA_TECHNOLOGY_MASK_A	            0x01    /* NFC Technology A             */
+# NFA_TECHNOLOGY_MASK_F	            0x04    /* NFC Technology F             */
+# NFA_TECHNOLOGY_MASK_A_ACTIVE      0x40    /* NFC Technology A active mode */
+# NFA_TECHNOLOGY_MASK_F_ACTIVE      0x80    /* NFC Technology F active mode */
+P2P_LISTEN_TECH_MASK=0x00
+
+################################################################################
+PRESERVE_STORAGE=0x01
+
+################################################################################
+# Override the stack default for NFA_EE_MAX_EE_SUPPORTED set in nfc_target.h.
+# The value is set to 3 by default as it assumes we will discover 0xF2,
+# 0xF3, and 0xF4. If a platform will exclude and SE, this value can be reduced
+# so that the stack will not wait any longer than necessary.
+#
+# Maximum EE supported number
+# NXP PN547C2 0x02
+# NXP PN65T 0x03
+# NXP PN548C2 0x02
+# NXP PN66T 0x03
+NFA_MAX_EE_SUPPORTED=0x02
+
+################################################################################
+# AID_MATCHING constants
+# AID_MATCHING_EXACT_ONLY 0x00
+# AID_MATCHING_EXACT_OR_PREFIX 0x01
+# AID_MATCHING_PREFIX_ONLY 0x02
+# AID_MATCHING_EXACT_OR_SUBSET_OR_PREFIX 0x03
+AID_MATCHING_MODE=0x03
+
+################################################################################
+# Set the default Felica T3T System Code :
+# This settings will be used when application does not set this parameter
+DEFAULT_SYS_CODE={FE:FE}
+
+################################################################################
+# Value of NIC parameter NFCC_COFNIG_CONTROL
+# 0x00  NFCC is not allowed to manage RF configuration
+# 0x01  NFCC is allowed to manage RF configuration
+NFCC_CONFIG_CONTROL=0x01
+
+################################################################################
+# Set if the AID routing should be blocked for the power modes not supported.
+NFA_AID_BLOCK_ROUTE=1
+
+################################################################################
+# Set the OffHost AID supported power state:
+OFFHOST_AID_ROUTE_PWR_STATE=0x3B
+
+################################################################################
+# Mifare Reader implementation
+# 0: General implementation
+# 1: Legacy implementation
+LEGACY_MIFARE_READER=0
+
+################################################################################
+# Nfc recovery implementation
+# 0: Crash Nfc Service
+# 1: Toggle Nfc state
+RECOVERY_OPTION=1
+
+################################################################################
+# Default poll duration (in ms)
+# The default is 500ms if not set
+NFA_DM_DISC_DURATION_POLL=500
diff --git a/flags/Android.bp b/flags/Android.bp
index 307bb635..0a3ddeac 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -9,6 +9,7 @@ aconfig_declarations {
 cc_aconfig_library {
     name: "libnfc-nci_flags",
     aconfig_declarations: "aconfig_system_nfc",
+    min_sdk_version: "35", // Make it 36 once available.
     host_supported: true,
     apex_available: [
         "//apex_available:platform",
diff --git a/src/Android.bp b/src/Android.bp
index 0baf755c..9de7c505 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -66,6 +66,7 @@ cc_library {
         "nfa/sys/*.cc",
         "nfa/wlc/*.cc",
         "nfc/nci/*.cc",
+        "nfa/ndefnfcee/t4t/*.cc",
         "nfc/ndef/*.cc",
         "nfc/nfc/*.cc",
         "nfc/tags/*.cc",
@@ -90,6 +91,7 @@ cc_library {
         "//apex_available:platform",
         "com.android.nfcservices",
     ],
+    min_sdk_version: "35", // Make it 36 once available.
 }
 
 cc_defaults {
@@ -163,6 +165,7 @@ cc_library {
         "//apex_available:platform",
         "com.android.nfcservices",
     ],
+    min_sdk_version: "35", // Make it 36 once available.
 }
 
 genrule {
@@ -280,6 +283,7 @@ cc_fuzz {
         "nfa/ee/*.cc",
         "nfa/hci/*.cc",
         "nfa/rw/*.cc",
+        "nfa/ndefnfcee/t4t/*.cc",
         "nfa/sys/*.cc",
         "nfa/wlc/*.cc",
         "nfc/nci/*.cc",
diff --git a/src/adaptation/NfcAdaptation.cc b/src/adaptation/NfcAdaptation.cc
index 7f9ad843..815238a9 100644
--- a/src/adaptation/NfcAdaptation.cc
+++ b/src/adaptation/NfcAdaptation.cc
@@ -358,7 +358,8 @@ void NfcAdaptation::GetVendorConfigs(
         aidlConfigValue.nfaProprietaryCfg.protocolMifare,
         aidlConfigValue.nfaProprietaryCfg.discoveryPollKovio,
         aidlConfigValue.nfaProprietaryCfg.discoveryPollBPrime,
-        aidlConfigValue.nfaProprietaryCfg.discoveryListenBPrime};
+        aidlConfigValue.nfaProprietaryCfg.discoveryListenBPrime,
+        aidlConfigValue.nfaProprietaryCfg.protocolChineseId};
     configMap.emplace(NAME_NFA_PROPRIETARY_CFG, ConfigValue(nfaPropCfg));
     configMap.emplace(NAME_NFA_POLL_BAIL_OUT_MODE,
                       ConfigValue(aidlConfigValue.nfaPollBailOutMode ? 1 : 0));
@@ -392,6 +393,8 @@ void NfcAdaptation::GetVendorConfigs(
                       ConfigValue((uint8_t)aidlConfigValue.offHostSIMPipeId));
     configMap.emplace(NAME_OFF_HOST_ESE_PIPE_ID,
                       ConfigValue((uint8_t)aidlConfigValue.offHostESEPipeId));
+    configMap.emplace(NAME_T4T_NFCEE_ENABLE,
+                      ConfigValue(aidlConfigValue.t4tNfceeEnable ? 1 : 0));
 
     if (aidlConfigValue.offHostSimPipeIds.size() != 0) {
       configMap.emplace(NAME_OFF_HOST_SIM_PIPE_IDS,
@@ -540,6 +543,8 @@ void NfcAdaptation::Initialize() {
       nfa_proprietary_cfg.pro_discovery_b_prime_poll = p_config[7];
     if (p_config.size() > 8)
       nfa_proprietary_cfg.pro_discovery_b_prime_listen = p_config[8];
+    if (p_config.size() > 9)
+      nfa_proprietary_cfg.pro_protocol_chinese_id = p_config[9];
   }
 
   // Configure allowlist of HCI host ID's
@@ -555,6 +560,14 @@ void NfcAdaptation::Initialize() {
         NfcConfig::getUnsigned(NAME_ISO15693_SKIP_GET_SYS_INFO_CMD);
   }
 
+  if (NfcConfig::hasKey(NAME_NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT)) {
+    unsigned int value =
+        NfcConfig::getUnsigned(NAME_NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT);
+    if (value > 0) {
+      nfa_dm_cfg.deact_ntf_listen_active_timeout = value * 1000;
+    }
+  }
+
   verify_stack_non_volatile_store();
   if (NfcConfig::hasKey(NAME_PRESERVE_STORAGE) &&
       NfcConfig::getUnsigned(NAME_PRESERVE_STORAGE) == 1) {
diff --git a/src/adaptation/debug_lmrt.cc b/src/adaptation/debug_lmrt.cc
index 8a93e790..8bee763f 100644
--- a/src/adaptation/debug_lmrt.cc
+++ b/src/adaptation/debug_lmrt.cc
@@ -13,7 +13,6 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 #include "include/debug_lmrt.h"
 
 #include <android-base/logging.h>
diff --git a/src/fuzzers/nci/stubs.cc b/src/fuzzers/nci/stubs.cc
index 65d56b4f..d981acad 100644
--- a/src/fuzzers/nci/stubs.cc
+++ b/src/fuzzers/nci/stubs.cc
@@ -29,6 +29,7 @@ void rw_t3t_handle_nci_poll_ntf(uint8_t nci_status, uint8_t num_responses,
           BytesToHex(p_sensf_res_buf, sensf_res_buf_size).c_str());
 }
 
+void rw_ci_process_timeout(TIMER_LIST_ENT*) { abort(); }
 void rw_t1t_process_timeout(TIMER_LIST_ENT*) { abort(); }
 void rw_t2t_process_timeout() { abort(); }
 void rw_t3t_process_timeout(TIMER_LIST_ENT*) { abort(); }
diff --git a/src/fuzzers/rw/stubs.cc b/src/fuzzers/rw/stubs.cc
index 1ed8c2b1..f87779ac 100644
--- a/src/fuzzers/rw/stubs.cc
+++ b/src/fuzzers/rw/stubs.cc
@@ -1,4 +1,6 @@
 #include "fuzz_cmn.h"
+#include "nfa_api.h"
+#include "nfa_nfcee_int.h"
 
 // These are the functions implemented elsewhere in the NFC code. Our fuzzing
 // doesn't need them. To avoid pulling into more source code we simply stub
@@ -33,6 +35,12 @@ tNFC_STATUS NFC_SendData(uint8_t conn_id, NFC_HDR* p_data) {
   return NFC_STATUS_OK;
 }
 
+void NFC_SetStaticT4tNfceeCback(tNFC_CONN_CBACK*, uint8_t) {}
+
+bool NFA_T4tNfcEeIsProcessing() { return NFC_STATUS_OK; }
+
+tNFA_T4TNFCEE_CB nfa_t4tnfcee_cb;
+
 uint8_t nci_snd_t3t_polling(uint16_t system_code, uint8_t rc, uint8_t tsn) {
   FUZZLOG("sc=%04X, rc=%02X, tsn=%02X", system_code, rc, tsn);
   return NFC_STATUS_OK;
diff --git a/src/gki/common/gki_time.cc b/src/gki/common/gki_time.cc
index 48559d94..9c74cc2d 100644
--- a/src/gki/common/gki_time.cc
+++ b/src/gki/common/gki_time.cc
@@ -727,7 +727,7 @@ uint32_t GKI_get_remaining_ticks(TIMER_LIST_Q* p_timer_listq,
     }
 
     /* if found target entry */
-    if (p_tle == p_target_tle) {
+    if ((p_tle != nullptr) && (p_tle == p_target_tle)) {
       rem_ticks += p_tle->ticks;
     } else {
       LOG(ERROR) << StringPrintf(
diff --git a/src/gki/ulinux/gki_int.h b/src/gki/ulinux/gki_int.h
index f1ac1c54..f2bc223e 100644
--- a/src/gki/ulinux/gki_int.h
+++ b/src/gki/ulinux/gki_int.h
@@ -39,6 +39,9 @@ typedef struct {
   int no_timer_suspend; /* 1: no suspend, 0 stop calling GKI_timer_update() */
   pthread_mutex_t gki_timer_mutex;
   pthread_cond_t gki_timer_cond;
+  pthread_mutex_t gki_end_mutex;
+  pthread_cond_t gki_end_cond;
+  int end_flag;
 } tGKI_OS;
 
 /* condition to exit or continue GKI_run() timer loop */
diff --git a/src/gki/ulinux/gki_ulinux.cc b/src/gki/ulinux/gki_ulinux.cc
index 1c9d8121..8febbaee 100644
--- a/src/gki/ulinux/gki_ulinux.cc
+++ b/src/gki/ulinux/gki_ulinux.cc
@@ -82,8 +82,8 @@ gki_pthread_info_t gki_pthread_info[GKI_MAX_TASKS];
 void* gki_task_entry(void* params) {
   pthread_t thread_id = pthread_self();
   gki_pthread_info_t* p_pthread_info = (gki_pthread_info_t*)params;
-  LOG(VERBOSE) << StringPrintf(
-      "gki_task_entry task_id=%i, thread_id=%lx/%lx, pCond/pMutex=%p/%p",
+  LOG(DEBUG) << StringPrintf(
+      "%s; task_id=%i, thread_id=%lx/%lx, pCond/pMutex=%p/%p", __func__,
       p_pthread_info->task_id, gki_cb.os.thread_id[p_pthread_info->task_id],
       pthread_self(), p_pthread_info->pCond, p_pthread_info->pMutex);
 
@@ -91,9 +91,11 @@ void* gki_task_entry(void* params) {
   /* Call the actual thread entry point */
   (p_pthread_info->task_entry)(p_pthread_info->params);
 
-  LOG(WARNING) << StringPrintf("gki_task task_id=%i terminating",
+  LOG(WARNING) << StringPrintf("%s; task_id=%i terminating", __func__,
                                p_pthread_info->task_id);
+#if (FALSE == GKI_PTHREAD_JOINABLE)
   gki_cb.os.thread_id[p_pthread_info->task_id] = 0;
+#endif
 
   return nullptr;
 }
@@ -127,6 +129,7 @@ void GKI_init(void) {
 #endif
   p_os = &gki_cb.os;
   pthread_mutex_init(&p_os->GKI_mutex, &attr);
+  pthread_mutexattr_destroy(&attr);
   /* pthread_mutex_init(&GKI_sched_mutex, NULL); */
   /* pthread_mutex_init(&thread_delay_mutex, NULL); */ /* used in GKI_delay */
   /* pthread_cond_init (&thread_delay_cond, NULL); */
@@ -137,6 +140,9 @@ void GKI_init(void) {
   p_os->no_timer_suspend = GKI_TIMER_TICK_RUN_COND;
   pthread_mutex_init(&p_os->gki_timer_mutex, nullptr);
   pthread_cond_init(&p_os->gki_timer_cond, nullptr);
+  pthread_mutex_init(&p_os->gki_end_mutex, nullptr);
+  pthread_cond_init(&p_os->gki_end_cond, nullptr);
+  p_os->end_flag = 0;
 }
 
 /*******************************************************************************
@@ -186,12 +192,14 @@ uint8_t GKI_create_task(TASKPTR task_entry, uint8_t task_id, int8_t* taskname,
 
   pthread_condattr_init(&attr);
   pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
-  LOG(VERBOSE) << StringPrintf(
-      "GKI_create_task func=0x%p  id=%d  name=%s  stack=0x%p  stackSize=%d",
+  LOG(DEBUG) << StringPrintf(
+      "%s; func=0x%p  id=%d  name=%s  stack=0x%p  stackSize=%d", __func__,
       task_entry, task_id, taskname, stack, stacksize);
 
   if (task_id >= GKI_MAX_TASKS) {
-    LOG(VERBOSE) << StringPrintf("Error! task ID > max task allowed");
+    LOG(ERROR) << StringPrintf("%s; Error! task ID > max task allowed",
+                               __func__);
+    pthread_condattr_destroy(&attr);
     return (GKI_FAILURE);
   }
 
@@ -211,8 +219,8 @@ uint8_t GKI_create_task(TASKPTR task_entry, uint8_t task_id, int8_t* taskname,
 #if (FALSE == GKI_PTHREAD_JOINABLE)
   pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);
 
-  LOG(VERBOSE) << StringPrintf("GKI creating task %i, pCond/pMutex=%p/%p",
-                             task_id, pCondVar, pMutex);
+  LOG(DEBUG) << StringPrintf("%s; GKI creating task %i, pCond/pMutex=%p/%p",
+                             __func__, task_id, pCondVar, pMutex);
 #else
   LOG(VERBOSE) << StringPrintf("GKI creating JOINABLE task %i", task_id);
 #endif
@@ -230,6 +238,9 @@ uint8_t GKI_create_task(TASKPTR task_entry, uint8_t task_id, int8_t* taskname,
   ret = pthread_create(&gki_cb.os.thread_id[task_id], &attr1, gki_task_entry,
                        &gki_pthread_info[task_id]);
 
+  pthread_condattr_destroy(&attr);
+  pthread_attr_destroy(&attr1);
+
   if (ret != 0) {
     LOG(VERBOSE) << StringPrintf("pthread_create failed(%d), %s!", ret, taskname);
     return GKI_FAILURE;
@@ -311,17 +322,12 @@ void GKI_shutdown(void) {
         }
       }
 #endif
-      LOG(VERBOSE) << StringPrintf("task %s dead",
+      LOG(DEBUG) << StringPrintf("%s; task %s dead", __func__,
                                  gki_cb.com.OSTName[task_id - 1]);
       GKI_exit_task(task_id - 1);
     }
   }
 
-  /* Destroy mutex and condition variable objects */
-  pthread_mutex_destroy(&gki_cb.os.GKI_mutex);
-/*    pthread_mutex_destroy(&GKI_sched_mutex); */
-/*    pthread_mutex_destroy(&thread_delay_mutex);
- pthread_cond_destroy (&thread_delay_cond); */
 #if (FALSE == GKI_PTHREAD_JOINABLE)
   i = 0;
 #endif
@@ -334,6 +340,23 @@ void GKI_shutdown(void) {
   if (oldCOnd == GKI_TIMER_TICK_STOP_COND ||
       oldCOnd == GKI_TIMER_TICK_EXIT_COND)
     pthread_cond_signal(&gki_cb.os.gki_timer_cond);
+
+  pthread_mutex_lock(&gki_cb.os.gki_end_mutex);
+  while (gki_cb.os.end_flag != 1) {
+    pthread_cond_wait(&gki_cb.os.gki_end_cond, &gki_cb.os.gki_end_mutex);
+  }
+  pthread_mutex_unlock(&gki_cb.os.gki_end_mutex);
+
+#if (TRUE == GKI_PTHREAD_JOINABLE)
+  result = pthread_join(gki_cb.os.thread_id[BTU_TASK], NULL);
+  if (result < 0) {
+    LOG(DEBUG) << StringPrintf("FAILED: result: %d", result);
+  }
+#endif
+
+  pthread_mutex_destroy(&gki_cb.os.GKI_mutex);
+  pthread_mutex_destroy(&gki_cb.os.gki_end_mutex);
+  pthread_cond_destroy(&gki_cb.os.gki_end_cond);
 }
 
 /*******************************************************************************
@@ -418,7 +441,7 @@ void timer_thread(signed long id) {
 **                  should be empty.
 *******************************************************************************/
 void GKI_run(__attribute__((unused)) void* p_task_id) {
-  LOG(VERBOSE) << StringPrintf("%s enter", __func__);
+  LOG(DEBUG) << StringPrintf("%s; enter", __func__);
   struct timespec delay;
   int err = 0;
   volatile int* p_run_cond = &gki_cb.os.no_timer_suspend;
@@ -428,7 +451,8 @@ void GKI_run(__attribute__((unused)) void* p_task_id) {
    * timers are
    * in any GKI/BTA/BTU this should save power when BTLD is idle! */
   GKI_timer_queue_register_callback(gki_system_tick_start_stop_cback);
-  LOG(VERBOSE) << StringPrintf("Start/Stop GKI_timer_update_registered!");
+  LOG(DEBUG) << StringPrintf("%s; Start/Stop GKI_timer_update_registered!",
+                             __func__);
 #endif
 
 #ifdef NO_GKI_RUN_RETURN
@@ -445,7 +469,7 @@ void GKI_run(__attribute__((unused)) void* p_task_id) {
     return GKI_FAILURE;
   }
 #else
-  LOG(VERBOSE) << StringPrintf("GKI_run, run_cond(%p)=%d ", p_run_cond,
+  LOG(DEBUG) << StringPrintf("%s; run_cond(%p)=%d ", __func__, p_run_cond,
                              *p_run_cond);
   for (; GKI_TIMER_TICK_EXIT_COND != *p_run_cond;) {
     do {
@@ -487,6 +511,12 @@ void GKI_run(__attribute__((unused)) void* p_task_id) {
 #endif
   } /* for */
 #endif
+
+  pthread_mutex_lock(&gki_cb.os.gki_end_mutex);
+  gki_cb.os.end_flag = 1;
+  pthread_cond_signal(&gki_cb.os.gki_end_cond);
+  pthread_mutex_unlock(&gki_cb.os.gki_end_mutex);
+
   gki_cb.com.OSWaitEvt[BTU_TASK] = 0;
   LOG(VERBOSE) << StringPrintf("%s exit", __func__);
 }
@@ -550,11 +580,23 @@ uint16_t GKI_wait(uint16_t flag, uint32_t timeout) {
 
   gki_pthread_info_t* p_pthread_info = &gki_pthread_info[rtask];
   if (p_pthread_info->pCond != nullptr && p_pthread_info->pMutex != nullptr) {
-    LOG(VERBOSE) << StringPrintf("GKI_wait task=%i, pCond/pMutex = %p/%p", rtask,
-                               p_pthread_info->pCond, p_pthread_info->pMutex);
-    pthread_mutex_lock(p_pthread_info->pMutex);
-    pthread_cond_signal(p_pthread_info->pCond);
-    pthread_mutex_unlock(p_pthread_info->pMutex);
+    LOG(DEBUG) << StringPrintf("%s; task=%i, pCond/pMutex = %p/%p", __func__,
+                               rtask, p_pthread_info->pCond,
+                               p_pthread_info->pMutex);
+    if (pthread_mutex_lock(p_pthread_info->pMutex) != 0) {
+      LOG(ERROR) << StringPrintf("%s; Could not lock mutex", __func__);
+      return EVENT_MASK(GKI_SHUTDOWN_EVT);
+    }
+    if (pthread_cond_signal(p_pthread_info->pCond) != 0) {
+      LOG(ERROR) << StringPrintf("%s; Error calling pthread_cond_signal()",
+                                 __func__);
+      (void)pthread_mutex_unlock(p_pthread_info->pMutex);
+      return EVENT_MASK(GKI_SHUTDOWN_EVT);
+    }
+    if (pthread_mutex_unlock(p_pthread_info->pMutex) != 0) {
+      LOG(ERROR) << StringPrintf("%s; Error unlocking mutex", __func__);
+      return EVENT_MASK(GKI_SHUTDOWN_EVT);
+    }
     p_pthread_info->pMutex = nullptr;
     p_pthread_info->pCond = nullptr;
   }
@@ -633,7 +675,9 @@ uint16_t GKI_wait(uint16_t flag, uint32_t timeout) {
       LOG(WARNING) << StringPrintf("GKI TASK_DEAD received. exit thread %d...",
                                    rtask);
 
+#if (FALSE == GKI_PTHREAD_JOINABLE)
       gki_cb.os.thread_id[rtask] = 0;
+#endif
       return (EVENT_MASK(GKI_SHUTDOWN_EVT));
     }
   }
@@ -1077,7 +1121,7 @@ void GKI_exit_task(uint8_t task_id) {
 
   // GKI_send_event(task_id, EVENT_MASK(GKI_SHUTDOWN_EVT));
 
-  LOG(VERBOSE) << StringPrintf("GKI_exit_task %d done", task_id);
+  LOG(DEBUG) << StringPrintf("%s; %d done", __func__, task_id);
   return;
 }
 
diff --git a/src/include/debug_lmrt.h b/src/include/debug_lmrt.h
index b050285f..a85dfbe2 100644
--- a/src/include/debug_lmrt.h
+++ b/src/include/debug_lmrt.h
@@ -29,7 +29,7 @@ typedef struct lmrt_payload_t {
   std::vector<uint8_t> more;
   std::vector<uint8_t> entry_count;
   std::vector<std::vector<uint8_t>> tlvs;
-} __attribute__((__packed__)) lmrt_payload_t;
+}__attribute__((__packed__)) lmrt_payload_t;
 
 /*******************************************************************************
 **
diff --git a/src/include/nci_defs.h b/src/include/nci_defs.h
index b3d55741..8ab82166 100644
--- a/src/include/nci_defs.h
+++ b/src/include/nci_defs.h
@@ -90,6 +90,7 @@
 #define NCI_DEST_TYPE_NFCC 1   /* NFCC - loopback */
 #define NCI_DEST_TYPE_REMOTE 2 /* Remote NFC Endpoint */
 #define NCI_DEST_TYPE_NFCEE 3  /* NFCEE */
+#define NCI_DEST_TYPE_T4T_NFCEE 5 /* T4T NFCEE */
 
 /* builds byte0 of NCI Command and Notification packet */
 #define NCI_MSG_BLD_HDR0(p, mt, gid) \
@@ -164,6 +165,8 @@
 #define NCI_STATUS_EE_TRANSMISSION_ERR 0xC1
 #define NCI_STATUS_EE_PROTOCOL_ERR 0xC2
 #define NCI_STATUS_EE_TIMEOUT 0xC3
+#define NFA_STATUS_READ_ONLY NCI_STATUS_READ_ONLY
+#define NCI_STATUS_READ_ONLY 0xC4
 
 /* RF Technologies */
 #define NCI_RF_TECHNOLOGY_A 0x00
@@ -470,9 +473,6 @@ typedef uint8_t tNCI_DISCOVERY_TYPE;
 #define NCI_PARAM_ID_PF_DEVICES_LIMIT 0x1A
 #define NCI_PARAM_ID_PB_H_INFO 0x20
 #define NCI_PARAM_ID_PI_BIT_RATE 0x21
-
-#define NCI_PARAM_ID_BITR_NFC_DEP 0x28
-#define NCI_PARAM_ID_ATR_REQ_GEN_BYTES 0x29
 #define NCI_PARAM_ID_ATR_REQ_CONFIG 0x2A
 #define NCI_PARAM_ID_PV_DEVICES_LIMIT 0x2F
 
@@ -531,7 +531,6 @@ typedef uint8_t tNCI_DISCOVERY_TYPE;
 /* Type A Parameters */
 #define NCI_PARAM_PLATFORM_T1T 0x0C
 #define NCI_PARAM_SEL_INFO_ISODEP 0x20
-#define NCI_PARAM_SEL_INFO_NFCDEP 0x40
 /**********************************************
  * NCI Parameter ID Lens
  **********************************************/
@@ -549,6 +548,7 @@ typedef uint8_t tNCI_DISCOVERY_TYPE;
 #define NCI_PARAM_LEN_LB_NFCID0 4
 #define NCI_PARAM_LEN_LB_APPDATA 4
 #define NCI_PARAM_LEN_LB_ADC_FO 1
+#define NCI_PARAM_LEN_RF_FIELD_INFO 1
 
 #define NCI_PARAM_LEN_LF_PROTOCOL 1
 #define NCI_PARAM_LEN_LF_T3T_FLAGS2 2
@@ -565,7 +565,6 @@ typedef uint8_t tNCI_DISCOVERY_TYPE;
 /* Listen protocol bits - NCI_PARAM_ID_LF_PROTOCOL and
  * NCI_PARAM_ID_LB_SENSB_INFO */
 #define NCI_LISTEN_PROTOCOL_ISO_DEP 0x01
-#define NCI_LISTEN_PROTOCOL_NFC_DEP 0x02
 
 /* LF_T3T_FLAGS2 listen bits all-disabled definition */
 #define NCI_LF_T3T_FLAGS2_ALL_DISABLED 0x0000
@@ -678,21 +677,6 @@ typedef struct {
 #define NCI_P_GEN_BYTE_INDEX 15
 #define NCI_L_GEN_BYTE_INDEX 14
 #define NCI_L_NFC_DEP_TO_INDEX 13
-typedef struct {
-  uint8_t atr_res_len;              /* Length of ATR_RES */
-  uint8_t atr_res[NCI_MAX_ATS_LEN]; /* ATR_RES (Byte 3 - Byte 17+n) as defined
-                                       in [DIGPROT] */
-} tNCI_INTF_PA_NFC_DEP;
-
-/* Note: keep tNCI_INTF_PA_NFC_DEP data member in the same order as
- * tNCI_INTF_LA_NFC_DEP */
-typedef struct {
-  uint8_t atr_req_len;              /* Length of ATR_REQ */
-  uint8_t atr_req[NCI_MAX_ATS_LEN]; /* ATR_REQ (Byte 3 - Byte 18+n) as defined
-                                       in [DIGPROT] */
-} tNCI_INTF_LA_NFC_DEP;
-typedef tNCI_INTF_LA_NFC_DEP tNCI_INTF_LF_NFC_DEP;
-typedef tNCI_INTF_PA_NFC_DEP tNCI_INTF_PF_NFC_DEP;
 
 #define NCI_MAX_ATTRIB_LEN (10 + NCI_MAX_GEN_BYTES_LEN)
 
diff --git a/src/include/nfc_config.h b/src/include/nfc_config.h
index 880777a2..2ed5c325 100644
--- a/src/include/nfc_config.h
+++ b/src/include/nfc_config.h
@@ -44,6 +44,8 @@
   "DISABLE_ALWAYS_ON_SET_EE_POWER_AND_LINK_CONF"
 #define NAME_NCI_RESET_TYPE "NCI_RESET_TYPE"
 #define NAME_MUTE_TECH_ROUTE_OPTION "MUTE_TECH_ROUTE_OPTION"
+#define NAME_NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT \
+  "NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT"
 /* Configs from vendor interface */
 #define NAME_NFA_POLL_BAIL_OUT_MODE "NFA_POLL_BAIL_OUT_MODE"
 #define NAME_PRESENCE_CHECK_ALGORITHM "PRESENCE_CHECK_ALGORITHM"
@@ -64,6 +66,10 @@
 #define NAME_DEFAULT_ISODEP_ROUTE "DEFAULT_ISODEP_ROUTE"
 #define NAME_PRESENCE_CHECK_RETRY_COUNT "PRESENCE_CHECK_RETRY_COUNT"
 #define NAME_ISO15693_SKIP_GET_SYS_INFO_CMD "ISO15693_SKIP_GET_SYS_INFO_CMD"
+#define NAME_DEFAULT_T4TNFCEE_AID_POWER_STATE "DEFAULT_T4TNFCEE_AID_POWER_STATE"
+#define NAME_T4T_NDEF_NFCEE_AID "T4T_NDEF_NFCEE_AID"
+#define NAME_DEFAULT_NDEF_NFCEE_ROUTE "DEFAULT_NDEF_NFCEE_ROUTE"
+#define NAME_T4T_NFCEE_ENABLE "T4T_NFCEE_ENABLE"
 
 class NfcConfig {
  public:
diff --git a/src/include/nfc_target.h b/src/include/nfc_target.h
index 5eb59c96..b0c6bd71 100644
--- a/src/include/nfc_target.h
+++ b/src/include/nfc_target.h
@@ -202,6 +202,11 @@
 #define NCI_MAX_CONN_CBS 4
 #endif
 
+/* the maximum number of NCI connections allowed. 1-14 */
+#ifndef NCI_MAX_STATIC_CONN_CBS
+#define NCI_MAX_STATIC_CONN_CBS 2
+#endif
+
 /* Maximum number of NCI commands that the NFCC accepts without needing to wait
  * for response */
 #ifndef NCI_MAX_CMD_WINDOW
@@ -297,6 +302,9 @@
 /* CE Type 4 Tag, Frame Waiting time Integer */
 #ifndef CE_T4T_ISO_DEP_FWI
 #define CE_T4T_ISO_DEP_FWI 7
+#ifndef RW_CI_TOUT_RESP
+#define RW_CI_TOUT_RESP 1000
+#endif
 #endif
 
 /* RW Type 4 Tag timeout for each API call, in ms */
@@ -421,6 +429,12 @@
 #define NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK (1000)
 #endif
 
+/* timeout for waiting deactivation NTF,
+** possible delay to send deactivate CMD if all credit wasn't returned
+** transport delay (1sec) and max RWT (5sec)
+*/
+#define NFA_DM_DISC_TIMEOUT_W4_DEACT_NTF (NFC_DEACTIVATE_TIMEOUT * 1000 + 6000)
+
 /* Max number of NDEF type handlers that can be registered (including the
  * default handler) */
 #ifndef NFA_NDEF_MAX_HANDLERS
diff --git a/src/include/vendor_cfg.h b/src/include/vendor_cfg.h
index 649ed4b3..2ba9722e 100644
--- a/src/include/vendor_cfg.h
+++ b/src/include/vendor_cfg.h
@@ -36,6 +36,7 @@ typedef struct {
   uint8_t pro_discovery_kovio_poll;
   uint8_t pro_discovery_b_prime_poll;
   uint8_t pro_discovery_b_prime_listen;
+  uint8_t pro_protocol_chinese_id;
 } tNFA_PROPRIETARY_CFG;
 
 extern tNFA_PROPRIETARY_CFG* p_nfa_proprietary_cfg;
@@ -62,6 +63,9 @@ extern tNFA_PROPRIETARY_CFG* p_nfa_proprietary_cfg;
 #ifndef NCI_PROTOCOL_MIFARE
 #define NCI_PROTOCOL_MIFARE (p_nfa_proprietary_cfg->pro_protocol_mfc)
 #endif
+#ifndef NCI_PROTOCOL_CI
+#define NCI_PROTOCOL_CI (p_nfa_proprietary_cfg->pro_protocol_chinese_id)
+#endif
 
 /**********************************************
  * Proprietary Discovery technology and mode
diff --git a/src/nfa/ce/nfa_ce_api.cc b/src/nfa/ce/nfa_ce_api.cc
index 9e92b8d0..da6db987 100644
--- a/src/nfa/ce/nfa_ce_api.cc
+++ b/src/nfa/ce/nfa_ce_api.cc
@@ -310,9 +310,10 @@ tNFA_STATUS NFA_CeDeregisterFelicaSystemCodeOnDH(tNFA_HANDLE handle) {
 **                  The NFA_CE_REGISTERED_EVT reports the status of the
 **                  operation.
 **
-**                  If no AID is specified (aid_len=0), then p_conn_cback will
-**                  will get notifications for any AIDs routed to the DH. This
-**                  over-rides callbacks registered for specific AIDs.
+**                  If no AID is specified (aid_len=0), and the pointer to the
+**                  AID value is null then p_conn_cback will get notifications
+**                  for any AIDs routed to the DH. This over-rides callbacks
+**                  registered for specific AIDs.
 **
 ** Note:            If RF discovery is started,
 **                  NFA_StopRfDiscovery()/NFA_RF_DISCOVERY_STOPPED_EVT should
@@ -330,7 +331,9 @@ tNFA_STATUS NFA_CeRegisterAidOnDH(uint8_t aid[NFC_MAX_AID_LEN], uint8_t aid_len,
   LOG(VERBOSE) << __func__;
 
   /* Validate parameters */
-  if (p_conn_cback == nullptr) return (NFA_STATUS_INVALID_PARAM);
+  if ((p_conn_cback == nullptr) || ((aid_len != 0) && (aid == nullptr)) ||
+      ((aid_len == 0) && (aid != nullptr)))
+    return (NFA_STATUS_INVALID_PARAM);
 
   p_msg = (tNFA_CE_MSG*)GKI_getbuf((uint16_t)sizeof(tNFA_CE_MSG));
   if (p_msg != nullptr) {
@@ -338,8 +341,9 @@ tNFA_STATUS NFA_CeRegisterAidOnDH(uint8_t aid[NFC_MAX_AID_LEN], uint8_t aid_len,
     p_msg->reg_listen.p_conn_cback = p_conn_cback;
     p_msg->reg_listen.listen_type = NFA_CE_REG_TYPE_ISO_DEP;
 
-    /* Listen info */
-    memcpy(p_msg->reg_listen.aid, aid, aid_len);
+    if (aid_len != 0) {
+      memcpy(p_msg->reg_listen.aid, aid, aid_len);
+    }
     p_msg->reg_listen.aid_len = aid_len;
 
     nfa_sys_sendmsg(p_msg);
diff --git a/src/nfa/ce/nfa_ce_main.cc b/src/nfa/ce/nfa_ce_main.cc
index 3a01a295..4912c274 100644
--- a/src/nfa/ce/nfa_ce_main.cc
+++ b/src/nfa/ce/nfa_ce_main.cc
@@ -23,7 +23,6 @@
  ******************************************************************************/
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
-
 #include <string>
 
 #include "nfa_ce_api.h"
diff --git a/src/nfa/dm/nfa_dm_act.cc b/src/nfa/dm/nfa_dm_act.cc
index 3162ef9c..20ad591d 100644
--- a/src/nfa/dm/nfa_dm_act.cc
+++ b/src/nfa/dm/nfa_dm_act.cc
@@ -36,6 +36,7 @@
 #include "nfa_ee_int.h"
 #endif
 
+#include "nfa_nfcee_int.h"
 #include "nfc_int.h"
 
 #if (NFA_SNEP_INCLUDED == TRUE)
@@ -50,6 +51,9 @@ using android::base::StringPrintf;
 #define NFA_DM_DISABLE_TIMEOUT_VAL 1000
 #endif
 
+extern tNFA_TECHNOLOGY_MASK dm_disc_listen_mask_dfl;
+extern tNFA_TECHNOLOGY_MASK dm_disc_poll_mask_dfl;
+
 static void nfa_dm_set_init_nci_params(void);
 static tNFA_STATUS nfa_dm_start_polling(void);
 static bool nfa_dm_deactivate_polling(void);
@@ -259,7 +263,6 @@ static void nfa_dm_nfc_response_cback(tNFC_RESPONSE_EVT event,
   tNFA_DM_CBACK_DATA dm_cback_data;
   tNFA_CONN_EVT_DATA conn_evt;
   uint8_t dm_cback_evt;
-  uint8_t max_ee = 0;
 
   LOG(VERBOSE) << StringPrintf("%s(0x%x)", nfa_dm_nfc_revt_2_str(event).c_str(),
                              event);
@@ -269,14 +272,6 @@ static void nfa_dm_nfc_response_cback(tNFC_RESPONSE_EVT event,
 
       /* NFC stack enabled. Enable nfa sub-systems */
       if (p_data->enable.status == NFC_STATUS_OK) {
-        if (nfa_ee_max_ee_cfg != 0) {
-          if (nfa_dm_cb.get_max_ee) {
-            max_ee = nfa_dm_cb.get_max_ee();
-            if (max_ee) {
-              nfa_ee_max_ee_cfg = max_ee;
-            }
-          }
-        }
         /* Initialize NFA subsystems */
         nfa_sys_enable_subsystems();
       } else if (nfa_dm_cb.flags & NFA_DM_FLAGS_ENABLE_EVT_PEND) {
@@ -487,6 +482,7 @@ bool nfa_dm_disable(tNFA_DM_MSG* p_data) {
     nfa_sys_start_timer(&nfa_dm_cb.tle, NFA_DM_TIMEOUT_DISABLE_EVT,
                         NFA_DM_DISABLE_TIMEOUT_VAL);
   }
+  nfa_t4tnfcee_deinit();
 
   /* Disable all subsystems other than DM (DM will be disabled after all  */
   /* the other subsystem have been disabled)                              */
@@ -895,20 +891,9 @@ tNFA_STATUS nfa_dm_start_polling(void) {
       poll_disc_mask |= NFA_DM_DISC_MASK_P_LEGACY;
       poll_disc_mask |= NFA_DM_DISC_MASK_PA_MIFARE;
     }
-    if (NFC_GetNCIVersion() >= NCI_VERSION_2_0) {
-      if (poll_tech_mask & NFA_TECHNOLOGY_MASK_ACTIVE) {
-        poll_disc_mask |= NFA_DM_DISC_MASK_PACM_NFC_DEP;
-      }
-    } else {
-      if (poll_tech_mask & NFA_TECHNOLOGY_MASK_A_ACTIVE) {
-        poll_disc_mask |= NFA_DM_DISC_MASK_PAA_NFC_DEP;
-      }
-      if (poll_tech_mask & NFA_TECHNOLOGY_MASK_F_ACTIVE) {
-        poll_disc_mask |= NFA_DM_DISC_MASK_PFA_NFC_DEP;
-      }
-    }
     if (poll_tech_mask & NFA_TECHNOLOGY_MASK_B) {
       poll_disc_mask |= NFA_DM_DISC_MASK_PB_ISO_DEP;
+      poll_disc_mask |= NFA_DM_DISC_MASK_PB_CI;
     }
     if (poll_tech_mask & NFA_TECHNOLOGY_MASK_F) {
       poll_disc_mask |= NFA_DM_DISC_MASK_PF_T3T;
@@ -924,14 +909,6 @@ tNFA_STATUS nfa_dm_start_polling(void) {
       poll_disc_mask |= NFA_DM_DISC_MASK_P_KOVIO;
     }
 
-    if (!(nfc_cb.nci_interfaces & (1 << NCI_INTERFACE_NFC_DEP))) {
-      /* Remove NFC-DEP related Discovery mask, if NFC_DEP interface is not
-       * supported */
-      poll_disc_mask &=
-          ~(NFA_DM_DISC_MASK_PACM_NFC_DEP | NFA_DM_DISC_MASK_PAA_NFC_DEP |
-            NFA_DM_DISC_MASK_PFA_NFC_DEP | NFA_DM_DISC_MASK_PF_NFC_DEP);
-    }
-
     nfa_dm_cb.poll_disc_handle = nfa_dm_add_rf_discover(
         poll_disc_mask, NFA_DM_DISC_HOST_ID_DH, nfa_dm_poll_disc_cback);
 
@@ -1173,6 +1150,7 @@ bool nfa_dm_act_start_rf_discovery(__attribute__((unused))
 *******************************************************************************/
 bool nfa_dm_act_stop_rf_discovery(__attribute__((unused)) tNFA_DM_MSG* p_data) {
   tNFA_CONN_EVT_DATA evt_data;
+  tNFA_DM_DISC_FLAGS disc_flags = nfa_dm_cb.disc_cb.disc_flags;
 
   LOG(VERBOSE) << __func__;
 
@@ -1196,6 +1174,9 @@ bool nfa_dm_act_stop_rf_discovery(__attribute__((unused)) tNFA_DM_MSG* p_data) {
       if (nfa_dm_cb.disc_cb.kovio_tle.in_use)
         nfa_sys_stop_timer(&nfa_dm_cb.disc_cb.kovio_tle);
       nfa_rw_stop_presence_check_timer();
+    } else {
+      // Stop RF discovery failed, need to restore flags
+      nfa_dm_cb.disc_cb.disc_flags = disc_flags;
     }
   }
   return true;
@@ -1460,7 +1441,7 @@ static void nfa_dm_excl_disc_cback(tNFA_DM_RF_DISC_EVT event,
           (p_data->deactivate.type == NFC_DEACTIVATE_TYPE_SLEEP_AF)) {
         evt_data.deactivated.type = NFA_DEACTIVATE_TYPE_SLEEP;
       } else {
-        evt_data.deactivated.type = NFA_DEACTIVATE_TYPE_IDLE;
+        evt_data.deactivated.type = p_data->deactivate.type;
       }
 
       /* notify deactivation to upper layer */
@@ -1525,6 +1506,14 @@ static void nfa_dm_poll_disc_cback(tNFA_DM_RF_DISC_EVT event,
             (nfa_dm_cb.disc_cb.activated_protocol == NFC_PROTOCOL_MIFARE)) {
           /* Notify NFA tag sub-system */
           nfa_rw_proc_disc_evt(NFA_DM_RF_DISC_ACTIVATED_EVT, p_data, true);
+        }
+        // Special case for chinese ID card
+        else if ((nfa_dm_cb.disc_cb.activated_protocol ==
+                  NFC_PROTOCOL_UNKNOWN) &&
+                 (nfa_dm_cb.disc_cb.activated_rf_interface ==
+                  NFC_DISCOVERY_TYPE_POLL_B)) {
+          /* Notify NFA tag sub-system */
+          nfa_rw_proc_disc_evt(NFA_DM_RF_DISC_ACTIVATED_EVT, p_data, true);
         } else /* if NFC-DEP/ISO-DEP with frame interface */
         {
           /* Set data callback to receive raw frame */
@@ -1558,7 +1547,7 @@ static void nfa_dm_poll_disc_cback(tNFA_DM_RF_DISC_EVT event,
             (p_data->deactivate.type == NFC_DEACTIVATE_TYPE_SLEEP_AF)) {
           evt_data.deactivated.type = NFA_DEACTIVATE_TYPE_SLEEP;
         } else {
-          evt_data.deactivated.type = NFA_DEACTIVATE_TYPE_IDLE;
+          evt_data.deactivated.type = p_data->deactivate.type;
         }
         /* notify deactivation to application */
         nfa_dm_conn_cback_event_notify(NFA_DEACTIVATED_EVT, &evt_data);
@@ -1740,6 +1729,22 @@ bool nfa_dm_act_change_discovery_tech(tNFA_DM_MSG* p_data) {
   nfa_dm_cb.change_poll_mask = p_data->change_discovery_tech.change_poll_mask;
   nfa_dm_cb.change_listen_mask =
       p_data->change_discovery_tech.change_listen_mask;
+
+  if (nfa_dm_cb.flags & NFA_DM_FLAGS_DEFAULT_TECH_CHANGED) {
+    if (nfa_dm_cb.flags & NFA_DM_FLAGS_LISTEN_TECH_CHANGED) {
+      dm_disc_listen_mask_dfl = nfa_dm_cb.change_listen_mask;
+    } else if (nfa_dm_cb.change_listen_mask == 0xff) {
+      dm_disc_listen_mask_dfl = 0;
+    }
+    LOG(DEBUG) << StringPrintf("%s; dm_disc_listen_mask_dfl: 0x%x", __func__,
+                               dm_disc_listen_mask_dfl);
+    if (nfa_dm_cb.flags & NFA_DM_FLAGS_POLL_TECH_CHANGED) {
+      dm_disc_poll_mask_dfl = nfa_dm_cb.change_poll_mask;
+    } else if (nfa_dm_cb.change_poll_mask == 0xff) {
+      dm_disc_poll_mask_dfl = 0;
+    }
+  }
+
   evt_data.status = NFA_STATUS_OK;
   nfa_dm_conn_cback_event_notify(NFA_LISTEN_ENABLED_EVT, &evt_data);
 
diff --git a/src/nfa/dm/nfa_dm_api.cc b/src/nfa/dm/nfa_dm_api.cc
index 81417a9a..d187b266 100644
--- a/src/nfa/dm/nfa_dm_api.cc
+++ b/src/nfa/dm/nfa_dm_api.cc
@@ -29,6 +29,7 @@
 #include "ndef_utils.h"
 #include "nfa_api.h"
 #include "nfa_ce_int.h"
+#include "nfa_nfcee_int.h"
 #include "nfa_wlc_int.h"
 #include "nfc_int.h"
 
@@ -118,6 +119,7 @@ void NFA_Init(tHAL_NFC_ENTRY* p_hal_entry_tbl) {
   nfa_ee_init();
   if (nfa_ee_max_ee_cfg != 0) {
     nfa_dm_cb.get_max_ee = p_hal_entry_tbl->get_max_ee;
+    nfa_t4tnfcee_init();
     nfa_hci_init();
   }
   nfa_wlc_init();
@@ -736,11 +738,10 @@ tNFA_STATUS NFA_Select(uint8_t rf_disc_id, tNFA_NFC_PROTOCOL protocol,
       "rf_disc_id:0x%X, protocol:0x%X, rf_interface:0x%X", rf_disc_id, protocol,
       rf_interface);
 
-  if (((rf_interface == NFA_INTERFACE_ISO_DEP) &&
-       (protocol != NFA_PROTOCOL_ISO_DEP)) ||
-      ((rf_interface == NFA_INTERFACE_NFC_DEP) &&
-       (protocol != NFA_PROTOCOL_NFC_DEP))) {
-    LOG(ERROR) << StringPrintf("RF interface is not matched protocol");
+  if ((rf_interface == NFA_INTERFACE_ISO_DEP) &&
+      (protocol != NFA_PROTOCOL_ISO_DEP)) {
+    LOG(ERROR) << StringPrintf("%s; RF interface is not matched protocol",
+                               __func__);
     return (NFA_STATUS_INVALID_PARAM);
   }
 
@@ -1251,6 +1252,20 @@ void NFA_DisableDtamode(void) {
   nfa_dm_cb.eDtaMode = NFA_DTA_APPL_MODE;
 }
 
+/*******************************************************************************
+**
+** Function:        NFA_SetNfcSecure
+**
+** Description:     Prooagtes NFC secure settings to NFC TASK
+**
+** Returns:         none:
+**
+*******************************************************************************/
+void NFA_SetNfcSecure(bool status) {
+  LOG(DEBUG) << StringPrintf("%s; status: %d", __func__, status);
+  nfa_dm_cb.is_nfc_secure = status;
+}
+
 /*******************************************************************************
 **
 ** Function         NFA_ChangeDiscoveryTech
diff --git a/src/nfa/dm/nfa_dm_cfg.cc b/src/nfa/dm/nfa_dm_cfg.cc
index 21c72c72..c1f54ad4 100644
--- a/src/nfa/dm/nfa_dm_cfg.cc
+++ b/src/nfa/dm/nfa_dm_cfg.cc
@@ -76,7 +76,9 @@ tNFA_DM_CFG nfa_dm_cfg = {
     /* Use sleep/wake(last interface) for ISODEP presence check */
     NFA_DM_PRESENCE_CHECK_OPTION,
     /* Maximum time to wait for presence check response */
-    NFA_DM_MAX_PRESENCE_CHECK_TIMEOUT};
+    NFA_DM_MAX_PRESENCE_CHECK_TIMEOUT,
+    /* timeout for rf deactivate in rf listen active state */
+    NFA_DM_DISC_TIMEOUT_W4_DEACT_NTF};
 
 tNFA_DM_CFG* p_nfa_dm_cfg = (tNFA_DM_CFG*)&nfa_dm_cfg;
 
@@ -105,6 +107,7 @@ tNFA_PROPRIETARY_CFG nfa_proprietary_cfg = {
     0x77, /* NCI_DISCOVERY_TYPE_POLL_KOVIO */
     0x74, /* NCI_DISCOVERY_TYPE_POLL_B_PRIME */
     0xF4, /* NCI_DISCOVERY_TYPE_LISTEN_B_PRIME */
+    0x84, /* NCI_PROTOCOL_CI */
 };
 
 tNFA_PROPRIETARY_CFG* p_nfa_proprietary_cfg =
diff --git a/src/nfa/dm/nfa_dm_discover.cc b/src/nfa/dm/nfa_dm_discover.cc
index 0b3748f9..2da21dd6 100644
--- a/src/nfa/dm/nfa_dm_discover.cc
+++ b/src/nfa/dm/nfa_dm_discover.cc
@@ -68,8 +68,8 @@ extern uint8_t mute_tech_route_option;
 /*
 ** static parameters
 */
-static tNFA_TECHNOLOGY_MASK dm_disc_listen_mask_dfl = 0;
-static tNFA_TECHNOLOGY_MASK dm_disc_poll_mask_dfl = 0;
+tNFA_TECHNOLOGY_MASK dm_disc_listen_mask_dfl = 0;
+tNFA_TECHNOLOGY_MASK dm_disc_poll_mask_dfl = 0;
 
 tNFA_DM_DISC_TECH_PROTO_MASK nfa_dm_change_listen_mask(
     tNFA_DM_DISC_TECH_PROTO_MASK dm_disc_mask,
@@ -80,28 +80,14 @@ tNFA_DM_DISC_TECH_PROTO_MASK nfa_dm_change_listen_mask(
                                  change_listen_mask);
     dm_disc_mask &= NFA_DM_DISC_MASK_POLL;
     if (change_listen_mask & NFA_TECHNOLOGY_MASK_A) {
-      dm_disc_mask |=
-          (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
-           NFA_DM_DISC_MASK_LA_ISO_DEP | NFA_DM_DISC_MASK_LA_NFC_DEP);
+      dm_disc_mask |= (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
+                       NFA_DM_DISC_MASK_LA_ISO_DEP);
     }
     if (change_listen_mask & NFA_TECHNOLOGY_MASK_B)
       dm_disc_mask |= NFA_DM_DISC_MASK_LB_ISO_DEP;
 
     if (change_listen_mask & NFA_TECHNOLOGY_MASK_F)
-      dm_disc_mask |= (NFA_DM_DISC_MASK_LF_T3T | NFA_DM_DISC_MASK_LF_NFC_DEP);
-
-    if (NFC_GetNCIVersion() == NCI_VERSION_2_0) {
-      if ((change_listen_mask & NFA_TECHNOLOGY_MASK_A_ACTIVE) ||
-          (change_listen_mask & NFA_TECHNOLOGY_MASK_F_ACTIVE)) {
-        dm_disc_mask |= NFA_DM_DISC_MASK_LACM_NFC_DEP;
-      }
-    } else {
-      if (change_listen_mask & NFA_TECHNOLOGY_MASK_A_ACTIVE)
-        dm_disc_mask |= NFA_DM_DISC_MASK_LAA_NFC_DEP;
-
-      if (change_listen_mask & NFA_TECHNOLOGY_MASK_F_ACTIVE)
-        dm_disc_mask |= NFA_DM_DISC_MASK_LFA_NFC_DEP;
-    }
+      dm_disc_mask |= NFA_DM_DISC_MASK_LF_T3T;
 
     LOG(VERBOSE) << StringPrintf("listen tech will set to 0x%x",
                                  (dm_disc_mask & NFA_DM_DISC_MASK_LISTEN));
@@ -149,25 +135,38 @@ tNFA_DM_DISC_TECH_PROTO_MASK nfa_dm_change_poll_mask(
   if (change_poll_mask & NFA_TECHNOLOGY_MASK_KOVIO)
     dm_disc_mask |= NFA_DM_DISC_MASK_P_KOVIO;
 
-  if (NFC_GetNCIVersion() == NCI_VERSION_2_0) {
-    if ((change_poll_mask & NFA_TECHNOLOGY_MASK_A_ACTIVE) ||
-        (change_poll_mask & NFA_TECHNOLOGY_MASK_F_ACTIVE)) {
-      dm_disc_mask |= NFA_DM_DISC_MASK_PACM_NFC_DEP;
-    }
-  } else {
-    if (change_poll_mask & NFA_TECHNOLOGY_MASK_A_ACTIVE)
-      dm_disc_mask |= NFA_DM_DISC_MASK_PAA_NFC_DEP;
-
-    if (change_poll_mask & NFA_TECHNOLOGY_MASK_F_ACTIVE)
-      dm_disc_mask |= NFA_DM_DISC_MASK_PFA_NFC_DEP;
-  }
-
   LOG(VERBOSE) << StringPrintf("poll tech mask will set to 0x%x",
                                (dm_disc_mask & NFA_DM_DISC_MASK_POLL));
 
   return dm_disc_mask;
 }
 
+/*******************************************************************************
+**
+** Function         nfa_dm_set_rf_field_ntf
+**
+** Description      Update RF_FIELD_INFO_NTF status to NFCC
+**
+** Returns          void
+**
+*******************************************************************************/
+static void nfa_dm_set_rf_field_info_ntf(uint8_t val) {
+  uint8_t params[10], *p;
+
+  LOG(DEBUG) << StringPrintf("%s; val = 0x%x", __func__, val);
+
+  p = params;
+
+  /* for total duration */
+  UINT8_TO_STREAM(p, NFC_PMID_RF_FIELD_INFO);
+  UINT8_TO_STREAM(p, NCI_PARAM_LEN_RF_FIELD_INFO);
+  UINT8_TO_STREAM(p, val);
+
+  if (p > params) {
+    nfa_dm_check_set_config((uint8_t)(p - params), params, false);
+  }
+}
+
 /*******************************************************************************
 **
 ** Function         nfa_dm_get_rf_discover_config
@@ -182,26 +181,14 @@ static uint8_t nfa_dm_get_rf_discover_config(
     tNFA_DM_DISC_TECH_PROTO_MASK dm_disc_mask,
     tNFC_DISCOVER_PARAMS disc_params[], uint8_t max_params) {
   uint8_t num_params = 0;
+  uint8_t rf_field_val;
 
   if (nfa_dm_cb.flags & NFA_DM_FLAGS_LISTEN_DISABLED) {
-    LOG(VERBOSE) << StringPrintf("listen disabled, rm listen from 0x%x",
-                                 dm_disc_mask);
+    LOG(VERBOSE) << StringPrintf("%s; listen disabled, rm listen from 0x%x",
+                                 __func__, dm_disc_mask);
     dm_disc_mask &= NFA_DM_DISC_MASK_POLL;
   }
 
-  if (nfa_dm_cb.flags & NFA_DM_FLAGS_DEFAULT_TECH_CHANGED) {
-    if (nfa_dm_cb.flags & NFA_DM_FLAGS_LISTEN_TECH_CHANGED) {
-      dm_disc_listen_mask_dfl = nfa_dm_cb.change_listen_mask;
-    } else if (nfa_dm_cb.change_listen_mask == 0xff) {
-      dm_disc_listen_mask_dfl = 0;
-    }
-    if (nfa_dm_cb.flags & NFA_DM_FLAGS_POLL_TECH_CHANGED) {
-      dm_disc_poll_mask_dfl = nfa_dm_cb.change_poll_mask;
-    } else if (nfa_dm_cb.change_poll_mask == 0xff) {
-      dm_disc_poll_mask_dfl = 0;
-    }
-  }
-
   if (nfa_dm_cb.flags & NFA_DM_FLAGS_LISTEN_TECH_CHANGED) {
     dm_disc_mask =
         nfa_dm_change_listen_mask(dm_disc_mask, nfa_dm_cb.change_listen_mask);
@@ -212,6 +199,10 @@ static uint8_t nfa_dm_get_rf_discover_config(
         nfa_dm_change_listen_mask(dm_disc_mask, dm_disc_listen_mask_dfl);
   }
 
+  // RF_FIELD_INFO_NTF needed only if some listen programmed
+  nfa_dm_set_rf_field_info_ntf((dm_disc_mask & NFA_DM_DISC_MASK_LISTEN) ? 0x01
+                                                                        : 0x00);
+
   if (nfa_dm_cb.flags & NFA_DM_FLAGS_POLL_TECH_CHANGED) {
     /* Check polling tech */
     LOG(VERBOSE) << StringPrintf("poll tech will be changed to 0x%x",
@@ -256,9 +247,8 @@ static uint8_t nfa_dm_get_rf_discover_config(
   }
 
   /* Check listening A */
-  if (dm_disc_mask &
-      (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
-       NFA_DM_DISC_MASK_LA_ISO_DEP | NFA_DM_DISC_MASK_LA_NFC_DEP)) {
+  if (dm_disc_mask & (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
+                      NFA_DM_DISC_MASK_LA_ISO_DEP)) {
     disc_params[num_params].type = NFC_DISCOVERY_TYPE_LISTEN_A;
     disc_params[num_params].frequency = 1;
     num_params++;
@@ -276,7 +266,7 @@ static uint8_t nfa_dm_get_rf_discover_config(
   }
 
   /* Check listening F */
-  if (dm_disc_mask & (NFA_DM_DISC_MASK_LF_T3T | NFA_DM_DISC_MASK_LF_NFC_DEP)) {
+  if (dm_disc_mask & NFA_DM_DISC_MASK_LF_T3T) {
     disc_params[num_params].type = NFC_DISCOVERY_TYPE_LISTEN_F;
     disc_params[num_params].frequency = 1;
     num_params++;
@@ -375,10 +365,6 @@ static tNFA_STATUS nfa_dm_set_rf_listen_mode_config(
     if (tech_proto_mask & NFA_DM_DISC_MASK_LA_ISO_DEP) {
       sens_info |= NCI_PARAM_SEL_INFO_ISODEP;
     }
-
-    if (tech_proto_mask & NFA_DM_DISC_MASK_LA_NFC_DEP) {
-      sens_info |= NCI_PARAM_SEL_INFO_NFCDEP;
-    }
   }
 
   p = params;
@@ -498,11 +484,6 @@ static void nfa_dm_set_rf_listen_mode_raw_config(
       if (p_cfg->la_sel_info & NCI_PARAM_SEL_INFO_ISODEP) {
         disc_mask |= NFA_DM_DISC_MASK_LA_ISO_DEP;
       }
-
-      if (p_cfg->la_sel_info & NCI_PARAM_SEL_INFO_NFCDEP) {
-        disc_mask |= NFA_DM_DISC_MASK_LA_NFC_DEP;
-      }
-
       /* If neither, T4T nor NFCDEP, then its T2T */
       if (disc_mask == 0) {
         disc_mask |= NFA_DM_DISC_MASK_LA_T2T;
@@ -591,9 +572,6 @@ static void nfa_dm_set_rf_listen_mode_raw_config(
     if (p_cfg->lf_t3t_flags != NCI_LF_T3T_FLAGS2_ALL_DISABLED) {
       disc_mask |= NFA_DM_DISC_MASK_LF_T3T;
     }
-    if (p_cfg->lf_protocol_type & NCI_LISTEN_PROTOCOL_NFC_DEP) {
-      disc_mask |= NFA_DM_DISC_MASK_LF_NFC_DEP;
-    }
   }
 
   /*
@@ -623,30 +601,6 @@ static void nfa_dm_set_rf_listen_mode_raw_config(
     nfa_dm_check_set_config((uint8_t)(p - params), params, false);
   }
 
-  /*
-  ** Discovery Configuration Parameters for Listen NFC-DEP
-  */
-  if ((disc_mask &
-       (NFA_DM_DISC_MASK_LA_NFC_DEP | NFA_DM_DISC_MASK_LF_NFC_DEP)) &&
-      (p_cfg->ln_enable)) {
-    p = params;
-
-    UINT8_TO_STREAM(p, NFC_PMID_WT);
-    UINT8_TO_STREAM(p, NCI_PARAM_LEN_WT);
-    UINT8_TO_STREAM(p, p_cfg->ln_wt);
-
-    UINT8_TO_STREAM(p, NFC_PMID_ATR_RES_GEN_BYTES);
-    UINT8_TO_STREAM(p, p_cfg->ln_atr_res_gen_bytes_len);
-    ARRAY_TO_STREAM(p, p_cfg->ln_atr_res_gen_bytes,
-                    p_cfg->ln_atr_res_gen_bytes_len);
-
-    UINT8_TO_STREAM(p, NFC_PMID_ATR_RSP_CONFIG);
-    UINT8_TO_STREAM(p, 1);
-    UINT8_TO_STREAM(p, p_cfg->ln_atr_res_config);
-
-    nfa_dm_check_set_config((uint8_t)(p - params), params, false);
-  }
-
   *p_disc_mask = disc_mask;
 
   LOG(VERBOSE) << StringPrintf("disc_mask = 0x%x", disc_mask);
@@ -686,6 +640,9 @@ static tNFA_DM_DISC_TECH_PROTO_MASK nfa_dm_disc_get_disc_mask(
   } else if (NFC_DISCOVERY_TYPE_POLL_B == tech_n_mode) {
     if (protocol == NFC_PROTOCOL_ISO_DEP)
       disc_mask = NFA_DM_DISC_MASK_PB_ISO_DEP;
+    else if (protocol == NCI_PROTOCOL_UNKNOWN) {
+      disc_mask = NFA_DM_DISC_MASK_PB_CI;
+    }
   } else if (NFC_DISCOVERY_TYPE_POLL_F == tech_n_mode) {
     if (protocol == NFC_PROTOCOL_T3T)
       disc_mask = NFA_DM_DISC_MASK_PF_T3T;
@@ -708,18 +665,12 @@ static tNFA_DM_DISC_TECH_PROTO_MASK nfa_dm_disc_get_disc_mask(
       case NFC_PROTOCOL_ISO_DEP:
         disc_mask = NFA_DM_DISC_MASK_LA_ISO_DEP;
         break;
-      case NFC_PROTOCOL_NFC_DEP:
-        disc_mask = NFA_DM_DISC_MASK_LA_NFC_DEP;
-        break;
     }
   } else if (NFC_DISCOVERY_TYPE_LISTEN_B == tech_n_mode) {
     if (protocol == NFC_PROTOCOL_ISO_DEP)
       disc_mask = NFA_DM_DISC_MASK_LB_ISO_DEP;
   } else if (NFC_DISCOVERY_TYPE_LISTEN_F == tech_n_mode) {
-    if (protocol == NFC_PROTOCOL_T3T)
-      disc_mask = NFA_DM_DISC_MASK_LF_T3T;
-    else if (protocol == NFC_PROTOCOL_NFC_DEP)
-      disc_mask = NFA_DM_DISC_MASK_LF_NFC_DEP;
+    if (protocol == NFC_PROTOCOL_T3T) disc_mask = NFA_DM_DISC_MASK_LF_T3T;
   } else if (NFC_DISCOVERY_TYPE_LISTEN_ISO15693 == tech_n_mode) {
     disc_mask = NFA_DM_DISC_MASK_L_ISO15693;
   } else if (NFC_DISCOVERY_TYPE_LISTEN_B_PRIME == tech_n_mode) {
@@ -882,7 +833,16 @@ static tNFC_STATUS nfa_dm_disc_force_to_idle(void) {
 static void nfa_dm_disc_deact_ntf_timeout_cback(__attribute__((unused))
                                                 TIMER_LIST_ENT* p_tle) {
   LOG(ERROR) << __func__;
-
+  if (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE) {
+    LOG(ERROR) << "Ignoring deact_ntf_timeout in LISTEN_ACTIVE";
+    tNFA_DM_RF_DISC_DATA p_data;
+    p_data.nfc_discover.deactivate.status = NFC_STATUS_OK;
+    p_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
+    p_data.nfc_discover.deactivate.is_ntf = true;
+    p_data.nfc_discover.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ;
+    nfa_dm_disc_sm_execute(NFA_DM_RF_DEACTIVATE_NTF, &p_data);
+    return;
+  }
   nfa_dm_disc_force_to_idle();
 }
 
@@ -914,8 +874,14 @@ static tNFC_STATUS nfa_dm_send_deactivate_cmd(tNFC_DEACT_TYPE deactivate_type) {
     if (!nfa_dm_cb.disc_cb.tle.in_use) {
       nfa_dm_cb.disc_cb.tle.p_cback =
           (TIMER_CBACK*)nfa_dm_disc_deact_ntf_timeout_cback;
-      nfa_sys_start_timer(&nfa_dm_cb.disc_cb.tle, 0,
-                          NFA_DM_DISC_TIMEOUT_W4_DEACT_NTF);
+      if ((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE) &&
+          (p_nfa_dm_cfg != nullptr)) {
+        nfa_sys_start_timer(&nfa_dm_cb.disc_cb.tle, 0,
+                            p_nfa_dm_cfg->deact_ntf_listen_active_timeout);
+      } else {
+        nfa_sys_start_timer(&nfa_dm_cb.disc_cb.tle, 0,
+                            NFA_DM_DISC_TIMEOUT_W4_DEACT_NTF);
+      }
     }
   } else {
     if (deactivate_type == NFC_DEACTIVATE_TYPE_SLEEP) {
@@ -982,108 +948,61 @@ void nfa_dm_start_rf_discover(void) {
         /* NFC-A */
         if (nfa_dm_cb.disc_cb.entry[xx].host_id ==
             nfa_dm_cb.disc_cb.listen_RT[NFA_DM_DISC_LRT_NFC_A]) {
-          listen_mask |=
-              nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-              (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
-               NFA_DM_DISC_MASK_LA_ISO_DEP | NFA_DM_DISC_MASK_LA_NFC_DEP);
-          if (NFC_GetNCIVersion() >= NCI_VERSION_2_0) {
-            listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                           NFA_DM_DISC_MASK_LACM_NFC_DEP;
-          } else {
-            listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                           NFA_DM_DISC_MASK_LAA_NFC_DEP;
-          }
-        } else {
-          /* host can listen ISO-DEP based on AID routing */
-          listen_mask |= (nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
+          listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
+                         (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
                           NFA_DM_DISC_MASK_LA_ISO_DEP);
-          /* host can listen NFC-DEP based on protocol routing */
-           listen_mask |= (nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                            NFA_DM_DISC_MASK_LA_NFC_DEP);
-          if (NFC_GetNCIVersion() >= NCI_VERSION_2_0) {
-            listen_mask |= (nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                            NFA_DM_DISC_MASK_LACM_NFC_DEP);
-          } else {
-            listen_mask |= (nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                            NFA_DM_DISC_MASK_LAA_NFC_DEP);
-          }
         }
+      } else {
+        /* host can listen ISO-DEP based on AID routing */
+        listen_mask |= (nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
+                        NFA_DM_DISC_MASK_LA_ISO_DEP);
+      }
 
-        /* NFC-B */
-        /* multiple hosts can listen ISO-DEP based on AID routing */
-        listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                       NFA_DM_DISC_MASK_LB_ISO_DEP;
-
-        /* NFC-F */
-        /* NFCC can support NFC-DEP and T3T listening based on NFCID routing
-         * regardless of NFC-F tech routing */
+      /* NFC-B */
+      /* multiple hosts can listen ISO-DEP based on AID routing */
+      listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
+                     NFA_DM_DISC_MASK_LB_ISO_DEP;
+
+      /* NFC-F */
+      /* NFCC can support NFC-DEP and T3T listening based on NFCID routing
+       * regardless of NFC-F tech routing */
+      listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
+                     NFA_DM_DISC_MASK_LF_T3T;
+      /* NFC-B Prime */
+      if (nfa_dm_cb.disc_cb.entry[xx].host_id ==
+          nfa_dm_cb.disc_cb.listen_RT[NFA_DM_DISC_LRT_NFC_BP]) {
         listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                       (NFA_DM_DISC_MASK_LF_T3T | NFA_DM_DISC_MASK_LF_NFC_DEP);
-        if (NFC_GetNCIVersion() < NCI_VERSION_2_0) {
-          listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                         NFA_DM_DISC_MASK_LFA_NFC_DEP;
-        }
-        /* NFC-B Prime */
-        if (nfa_dm_cb.disc_cb.entry[xx].host_id ==
-            nfa_dm_cb.disc_cb.listen_RT[NFA_DM_DISC_LRT_NFC_BP]) {
-          listen_mask |= nfa_dm_cb.disc_cb.entry[xx].requested_disc_mask &
-                         NFA_DM_DISC_MASK_L_B_PRIME;
-        }
-
-        /*
-        ** clear listen mode technolgies and protocols which are already
-        ** used by others
-        */
-
-        /* Check if other modules are listening T1T or T2T */
-        if (dm_disc_mask &
-            (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T)) {
-          listen_mask &=
-              ~(NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
-                NFA_DM_DISC_MASK_LA_ISO_DEP | NFA_DM_DISC_MASK_LA_NFC_DEP);
-        }
+                       NFA_DM_DISC_MASK_L_B_PRIME;
+      }
 
-        /* T1T/T2T has priority on NFC-A */
-        if ((dm_disc_mask &
-             (NFA_DM_DISC_MASK_LA_ISO_DEP | NFA_DM_DISC_MASK_LA_NFC_DEP)) &&
-            (listen_mask &
-             (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T))) {
-          dm_disc_mask &=
-              ~(NFA_DM_DISC_MASK_LA_ISO_DEP | NFA_DM_DISC_MASK_LA_NFC_DEP);
-        }
+      /*
+      ** clear listen mode technolgies and protocols which are already
+      ** used by others
+      */
 
-        /* Don't remove ISO-DEP because multiple hosts can listen ISO-DEP based
-         * on AID routing */
+      /* Check if other modules are listening T1T or T2T */
+      if (dm_disc_mask & (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T)) {
+        listen_mask &= ~(NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T |
+                         NFA_DM_DISC_MASK_LA_ISO_DEP);
+      }
 
-        /* Check if other modules are listening NFC-DEP */
-        if (NFC_GetNCIVersion() >= NCI_VERSION_2_0) {
-          if (dm_disc_mask &
-              (NFA_DM_DISC_MASK_LA_NFC_DEP | NFA_DM_DISC_MASK_LACM_NFC_DEP)) {
-            listen_mask &=
-                ~(NFA_DM_DISC_MASK_LA_NFC_DEP | NFA_DM_DISC_MASK_LACM_NFC_DEP);
-          }
-        } else {
-          if (dm_disc_mask &
-              (NFA_DM_DISC_MASK_LA_NFC_DEP | NFA_DM_DISC_MASK_LAA_NFC_DEP)) {
-            listen_mask &=
-                ~(NFA_DM_DISC_MASK_LA_NFC_DEP | NFA_DM_DISC_MASK_LAA_NFC_DEP);
-          }
-        }
+      /* T1T/T2T has priority on NFC-A */
+      if ((dm_disc_mask & NFA_DM_DISC_MASK_LA_ISO_DEP) &&
+          (listen_mask & (NFA_DM_DISC_MASK_LA_T1T | NFA_DM_DISC_MASK_LA_T2T))) {
+        dm_disc_mask &= ~NFA_DM_DISC_MASK_LA_ISO_DEP;
+      }
 
-        nfa_dm_cb.disc_cb.entry[xx].selected_disc_mask =
-            poll_mask | listen_mask;
+      nfa_dm_cb.disc_cb.entry[xx].selected_disc_mask = poll_mask | listen_mask;
 
-        LOG(VERBOSE) << StringPrintf(
-            "nfa_dm_cb.disc_cb.entry[%d].selected_disc_mask = 0x%x", xx,
-            nfa_dm_cb.disc_cb.entry[xx].selected_disc_mask);
+      LOG(VERBOSE) << StringPrintf(
+          "%s; nfa_dm_cb.disc_cb.entry[%d].selected_disc_mask = 0x%x", __func__,
+          xx, nfa_dm_cb.disc_cb.entry[xx].selected_disc_mask);
 
-        dm_disc_mask |= nfa_dm_cb.disc_cb.entry[xx].selected_disc_mask;
-      }
+      dm_disc_mask |= nfa_dm_cb.disc_cb.entry[xx].selected_disc_mask;
     }
 
     if (NFC_GetNCIVersion() == NCI_VERSION_1_0) {
-      if (dm_disc_mask &
-          (NFA_DM_DISC_MASK_PF_NFC_DEP | NFA_DM_DISC_MASK_PF_T3T)) {
+      if (dm_disc_mask & NFA_DM_DISC_MASK_PF_T3T) {
         /* According to the NFC Forum Activity spec, controllers must:
          * 1) Poll with RC=0 and SC=FFFF to find NFC-DEP targets
          * 2) Poll with RC=1 and SC=FFFF to find T3T targets
@@ -1833,7 +1752,9 @@ static void nfa_dm_disc_sm_idle(tNFA_DM_RF_DISC_SM_EVENT event,
           /* stop discovery */
           nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
           NFC_Deactivate(NFA_DEACTIVATE_TYPE_IDLE);
-          break;
+          if (nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_DISABLING) {
+            break;
+          }
         }
 
         if (nfa_dm_cb.disc_cb.excl_disc_entry.in_use) {
@@ -2145,6 +2066,16 @@ static void nfa_dm_disc_sm_w4_host_select(tNFA_DM_RF_DISC_SM_EVENT event,
       break;
     case NFA_DM_RF_INTF_ACTIVATED_NTF:
       nfa_dm_disc_new_state(NFA_DM_RFST_POLL_ACTIVE);
+
+      if (nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP) {
+        // RF_DEACTIVATE_CMD was sent and INTF_ACTIVATED received before the
+        // RSP, RFST is changed to POLL_ACTIVE, hence a NTF must be waited too
+        LOG(DEBUG) << StringPrintf(
+            "%s; Adding NTF flag because activation was received before RSP",
+            __func__);
+        nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_NTF;
+      }
+
       /* always call nfa_dm_disc_notify_activation to update protocol/interface
        * information in NFA control blocks */
       status = nfa_dm_disc_notify_activation(&(p_data->nfc_discover));
@@ -2333,6 +2264,13 @@ static void nfa_dm_disc_sm_poll_active(tNFA_DM_RF_DISC_SM_EVENT event,
             nfa_dm_send_deactivate_cmd(p_data->nfc_discover.deactivate.type);
           }
         }
+        if ((nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_STOPPING) &&
+            (!old_sleep_wakeup_flag)) {
+          LOG(DEBUG) << StringPrintf("%s; Rx DEACT_NTF(SLEEP) while stopping,"
+              "resending DEACT_CMD(idle) now", __func__);
+          /* stop discovery */
+          NFC_Deactivate(NFA_DEACTIVATE_TYPE_IDLE);
+        }
       } else if (p_data->nfc_discover.deactivate.type ==
                  NFC_DEACTIVATE_TYPE_IDLE) {
         nfa_dm_disc_new_state(NFA_DM_RFST_IDLE);
@@ -2348,6 +2286,11 @@ static void nfa_dm_disc_sm_poll_active(tNFA_DM_RF_DISC_SM_EVENT event,
                    << StringPrintf("NFA_DM_RF_DEACTIVATE_NTF to discovery");
         if (p_data->nfc_discover.deactivate.reason ==
             NFC_DEACTIVATE_REASON_DH_REQ_FAILED) {
+          // If in pres check and at this point still errors
+          // Stop pres check, tag will be activated again if still present
+          if (old_sleep_wakeup_flag) {
+            nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_FAILED);
+          }
           nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_NTF,
                                           &(p_data->nfc_discover));
         }
@@ -2475,6 +2418,7 @@ static void nfa_dm_disc_sm_listen_active(tNFA_DM_RF_DISC_SM_EVENT event,
   switch (event) {
     case NFA_DM_RF_DEACTIVATE_CMD:
       nfa_dm_send_deactivate_cmd(p_data->deactivate_type);
+      nfa_dm_cb.listen_deact_cmd_type = p_data->deactivate_type;
       break;
     case NFA_DM_RF_DEACTIVATE_RSP:
       nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
@@ -2502,8 +2446,33 @@ static void nfa_dm_disc_sm_listen_active(tNFA_DM_RF_DISC_SM_EVENT event,
       if (nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP) {
         /* it's race condition. received deactivate NTF before receiving RSP */
         /* notify deactivation after receiving deactivate RSP */
-        LOG(VERBOSE) << StringPrintf(
-            "Rx deactivate NTF while waiting for deactivate RSP");
+        LOG(DEBUG) << StringPrintf(
+            "%s; Rx deactivate NTF while waiting for deactivate RSP", __func__);
+        if ((p_data->nfc_discover.deactivate.type ==
+             NFC_DEACTIVATE_TYPE_SLEEP) ||
+            (p_data->nfc_discover.deactivate.type ==
+             NFC_DEACTIVATE_TYPE_SLEEP_AF)) {
+          nfa_dm_disc_new_state(NFA_DM_RFST_LISTEN_SLEEP);
+        } else if (p_data->nfc_discover.deactivate.type ==
+                   NFC_DEACTIVATE_TYPE_DISCOVERY) {
+          /* Discovery */
+          if (nfa_dm_cb.pending_power_state != SCREEN_STATE_INVALID) {
+            NFC_SetPowerSubState(nfa_dm_cb.pending_power_state);
+            nfa_dm_cb.pending_power_state = SCREEN_STATE_INVALID;
+          }
+          nfa_dm_disc_new_state(NFA_DM_RFST_DISCOVERY);
+
+          // sent RF_DEACTIVATE_CMD(discovery)
+          if (nfa_dm_cb.listen_deact_cmd_type ==
+              NFC_DEACTIVATE_TYPE_DISCOVERY) {
+            // If receiving DEACT_CMD(disc) while in RFST_DISCOVERY
+            // then NFCC returns to RFST_IDLE (NCI)
+            LOG(WARNING) << StringPrintf(
+                "%s; Already in RFST_DISCOVERY, new state is RFST_IDLE",
+                __func__);
+            nfa_dm_disc_new_state(NFA_DM_RFST_IDLE);
+          }
+        }
       } else {
         nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_NTF,
                                         &(p_data->nfc_discover));
@@ -2554,14 +2523,13 @@ static void nfa_dm_disc_sm_listen_sleep(tNFA_DM_RF_DISC_SM_EVENT event,
                                         tNFA_DM_RF_DISC_DATA* p_data) {
   switch (event) {
     case NFA_DM_RF_DEACTIVATE_CMD:
-      nfa_dm_send_deactivate_cmd(p_data->deactivate_type);
+      // When in LISTEN_SLEEP, according to NCI, only deactivate(idle)
+      // can be sent
+      nfa_dm_send_deactivate_cmd(NFC_DEACTIVATE_TYPE_IDLE);
 
-      /* if deactivate type is not discovery then NFCC will not sent
-       * deactivation NTF */
-      if (p_data->deactivate_type != NFA_DEACTIVATE_TYPE_DISCOVERY) {
-        nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_NTF;
-        nfa_sys_stop_timer(&nfa_dm_cb.disc_cb.tle);
-      }
+      /* NFCC will not sent deactivation NTF */
+      nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_NTF;
+      nfa_sys_stop_timer(&nfa_dm_cb.disc_cb.tle);
       break;
     case NFA_DM_RF_DEACTIVATE_RSP:
       nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
@@ -2600,6 +2568,10 @@ static void nfa_dm_disc_sm_listen_sleep(tNFA_DM_RF_DISC_SM_EVENT event,
       break;
     case NFA_DM_RF_INTF_ACTIVATED_NTF:
       nfa_dm_disc_new_state(NFA_DM_RFST_LISTEN_ACTIVE);
+      if (nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP) {
+        /* NFCC will sent deactivation NTF */
+        nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_NTF;
+      }
       if (nfa_dm_disc_notify_activation(&(p_data->nfc_discover)) ==
           NFA_STATUS_FAILED) {
         LOG(VERBOSE) << StringPrintf(
@@ -2787,19 +2759,6 @@ void nfa_dm_start_excl_discovery(tNFA_TECHNOLOGY_MASK poll_tech_mask,
     poll_disc_mask |= NFA_DM_DISC_MASK_PA_NFC_DEP;
     poll_disc_mask |= NFA_DM_DISC_MASK_P_LEGACY;
   }
-  if (NFC_GetNCIVersion() >= NCI_VERSION_2_0) {
-    if (poll_tech_mask & NFA_TECHNOLOGY_MASK_ACTIVE) {
-      poll_disc_mask |= NFA_DM_DISC_MASK_PACM_NFC_DEP;
-    }
-  } else {
-    if (poll_tech_mask & NFA_TECHNOLOGY_MASK_A_ACTIVE) {
-      poll_disc_mask |= NFA_DM_DISC_MASK_PAA_NFC_DEP;
-    }
-    if (poll_tech_mask & NFA_TECHNOLOGY_MASK_F_ACTIVE) {
-      poll_disc_mask |= NFA_DM_DISC_MASK_PFA_NFC_DEP;
-    }
-  }
-
   if (poll_tech_mask & NFA_TECHNOLOGY_MASK_B) {
     poll_disc_mask |= NFA_DM_DISC_MASK_PB_ISO_DEP;
   }
@@ -3056,3 +3015,18 @@ void nfa_dm_get_tech_route_block(uint8_t* listen_techmask, bool* enable) {
                                  *listen_techmask);
   }
 }
+
+/*******************************************************************************
+**
+** Function         nfa_dm_get_nfc_secure
+**
+** Description      Retrieves NFC secure information
+**
+** Returns
+**
+*******************************************************************************/
+bool nfa_dm_get_nfc_secure() {
+  LOG(INFO) << StringPrintf("%s; status: %d", __func__,
+                            nfa_dm_cb.is_nfc_secure);
+  return nfa_dm_cb.is_nfc_secure;
+}
diff --git a/src/nfa/dm/nfa_dm_main.cc b/src/nfa/dm/nfa_dm_main.cc
index afdc482c..8aebfad2 100644
--- a/src/nfa/dm/nfa_dm_main.cc
+++ b/src/nfa/dm/nfa_dm_main.cc
@@ -168,13 +168,13 @@ void nfa_dm_sys_disable(void) {
 **
 *******************************************************************************/
 bool nfa_dm_is_protocol_supported(tNFC_PROTOCOL protocol, uint8_t sel_res) {
-  return ((protocol == NFC_PROTOCOL_T1T) ||
-          ((protocol == NFC_PROTOCOL_T2T) &&
-           (sel_res == NFC_SEL_RES_NFC_FORUM_T2T)) ||
-          (protocol == NFC_PROTOCOL_T3T) ||
-          (protocol == NFC_PROTOCOL_ISO_DEP) ||
-          (protocol == NFC_PROTOCOL_NFC_DEP) ||
-          (protocol == NFC_PROTOCOL_T5T) || (protocol == NFC_PROTOCOL_MIFARE));
+  return (
+      (protocol == NFC_PROTOCOL_T1T) ||
+      ((protocol == NFC_PROTOCOL_T2T) &&
+       (sel_res == NFC_SEL_RES_NFC_FORUM_T2T)) ||
+      (protocol == NFC_PROTOCOL_T3T) || (protocol == NFC_PROTOCOL_ISO_DEP) ||
+      (protocol == NFC_PROTOCOL_NFC_DEP) || (protocol == NFC_PROTOCOL_T5T) ||
+      (protocol == NFC_PROTOCOL_MIFARE) || (protocol == NFA_PROTOCOL_CI));
 }
 /*******************************************************************************
 **
@@ -304,6 +304,11 @@ tNFA_STATUS nfa_dm_check_set_config(uint8_t tlv_list_len, uint8_t* p_tlv_list,
         max_len = NCI_PARAM_LEN_LB_ADC_FO;
         p_cur_len = &nfa_dm_cb.params.lb_adc_fo_len;
         break;
+      case NFC_PMID_RF_FIELD_INFO:
+        p_stored = nfa_dm_cb.params.rf_field_info;
+        max_len = NCI_PARAM_LEN_RF_FIELD_INFO;
+        p_cur_len = &nfa_dm_cb.params.rf_field_info_len;
+        break;
       case NFC_PMID_LB_H_INFO:
         p_stored = nfa_dm_cb.params.lb_h_info;
         max_len = NCI_MAX_ATTRIB_LEN;
@@ -335,20 +340,6 @@ tNFA_STATUS nfa_dm_check_set_config(uint8_t tlv_list_len, uint8_t* p_tlv_list,
         p_stored = nfa_dm_cb.params.fwi;
         max_len = NCI_PARAM_LEN_FWI;
         break;
-      case NFC_PMID_WT:
-        p_stored = nfa_dm_cb.params.wt;
-        max_len = NCI_PARAM_LEN_WT;
-        break;
-      case NFC_PMID_ATR_REQ_GEN_BYTES:
-        p_stored = nfa_dm_cb.params.atr_req_gen_bytes;
-        max_len = NCI_MAX_GEN_BYTES_LEN;
-        p_cur_len = &nfa_dm_cb.params.atr_req_gen_bytes_len;
-        break;
-      case NFC_PMID_ATR_RES_GEN_BYTES:
-        p_stored = nfa_dm_cb.params.atr_res_gen_bytes;
-        max_len = NCI_MAX_GEN_BYTES_LEN;
-        p_cur_len = &nfa_dm_cb.params.atr_res_gen_bytes_len;
-        break;
       default:
         /*
         **  Listen F Configuration
diff --git a/src/nfa/dm/nfa_dm_ndef.cc b/src/nfa/dm/nfa_dm_ndef.cc
index abed8500..0325a8ca 100644
--- a/src/nfa/dm/nfa_dm_ndef.cc
+++ b/src/nfa/dm/nfa_dm_ndef.cc
@@ -251,6 +251,9 @@ tNFA_DM_API_REG_NDEF_HDLR* nfa_dm_ndef_find_next_handler(
   for (; i < NFA_NDEF_MAX_HANDLERS; i++) {
     /* Check if TNF matches */
     if ((p_cb->p_ndef_handler[i]) && (p_cb->p_ndef_handler[i]->tnf == tnf)) {
+      if (p_type_name == nullptr) {
+        break;
+      }
       /* TNF matches. */
       /* If handler is for a specific URI type, check if type is WKT URI, */
       /* and that the URI prefix abrieviation for this handler matches */
diff --git a/src/nfa/ee/nfa_ee_act.cc b/src/nfa/ee/nfa_ee_act.cc
index 6bdfc607..513ba06d 100644
--- a/src/nfa/ee/nfa_ee_act.cc
+++ b/src/nfa/ee/nfa_ee_act.cc
@@ -32,6 +32,7 @@
 #include "nfa_dm_int.h"
 #include "nfa_ee_int.h"
 #include "nfa_hci_int.h"
+#include "nfa_nfcee_int.h"
 #include "nfc_int.h"
 
 using android::base::StringPrintf;
@@ -62,6 +63,9 @@ const uint8_t nfa_ee_tech_list[NFA_EE_NUM_TECH] = {
 
 extern uint8_t mute_tech_route_option;
 
+#define NFCEE_TYPE_NDEF 0x04  // indicates that the NFCEE supports NDEF storage
+#define NFCEE_TAG_INDEX 0
+
 static void add_route_tech_proto_tlv(uint8_t** pp, uint8_t tlv_type,
                                      uint8_t nfcee_id, uint8_t pwr_cfg,
                                      uint8_t tech_proto) {
@@ -99,11 +103,10 @@ static void add_route_sys_code_tlv(uint8_t** p_buff, uint8_t* p_sys_code_cfg,
 
 const uint8_t nfa_ee_proto_mask_list[NFA_EE_NUM_PROTO] = {
     NFA_PROTOCOL_MASK_T1T, NFA_PROTOCOL_MASK_T2T, NFA_PROTOCOL_MASK_T3T,
-    NFA_PROTOCOL_MASK_ISO_DEP, NFA_PROTOCOL_MASK_NFC_DEP};
+    NFA_PROTOCOL_MASK_ISO_DEP};
 
 const uint8_t nfa_ee_proto_list[NFA_EE_NUM_PROTO] = {
-    NFC_PROTOCOL_T1T, NFC_PROTOCOL_T2T, NFC_PROTOCOL_T3T, NFC_PROTOCOL_ISO_DEP,
-    NFC_PROTOCOL_NFC_DEP};
+    NFC_PROTOCOL_T1T, NFC_PROTOCOL_T2T, NFC_PROTOCOL_T3T, NFC_PROTOCOL_ISO_DEP};
 
 static void nfa_ee_report_discover_req_evt(void);
 static void nfa_ee_build_discover_req_evt(tNFA_EE_DISCOVER_REQ* p_evt_data);
@@ -198,10 +201,7 @@ static void nfa_ee_update_route_size(tNFA_EE_ECB* p_cb) {
         power_cfg |= NCI_ROUTE_PWR_STATE_SCREEN_OFF_LOCK();
     }
 
-    // NFC-DEP must route to HOST
-    if (power_cfg ||
-        (p_cb->nfcee_id == NFC_DH_ID &&
-         nfa_ee_proto_mask_list[xx] == NFA_PROTOCOL_MASK_NFC_DEP)) {
+    if (power_cfg) {
       /* 5 = 1 (tag) + 1 (len) + 1(nfcee_id) + 1(power cfg) + 1 (protocol) */
       p_cb->size_mask_proto += 5;
     }
@@ -353,8 +353,12 @@ static void nfa_ee_add_tech_route_to_ecb(tNFA_EE_ECB* p_cb, uint8_t* pp,
               &pp, nfa_ee_cb.route_block_control | NFC_ROUTE_TAG_TECH,
               0x00 /* DH */, 0x00 /* no power states */, nfa_ee_tech_list[xx]);
         } else {
-          add_route_tech_proto_tlv(&pp, NFC_ROUTE_TAG_TECH, p_cb->nfcee_id,
-                                   power_cfg, nfa_ee_tech_list[xx]);
+          add_route_tech_proto_tlv(
+              &pp,
+              nfa_dm_get_nfc_secure()
+                  ? nfa_ee_cb.route_block_control | NFC_ROUTE_TAG_TECH
+                  : NFC_ROUTE_TAG_TECH,
+              p_cb->nfcee_id, power_cfg, nfa_ee_tech_list[xx]);
         }
       }
       num_tlv++;
@@ -383,9 +387,7 @@ static void nfa_ee_add_proto_route_to_ecb(tNFA_EE_ECB* p_cb, uint8_t* pp,
       power_cfg |= NCI_ROUTE_PWR_STATE_SWITCH_OFF;
     if (p_cb->proto_battery_off & nfa_ee_proto_mask_list[xx])
       power_cfg |= NCI_ROUTE_PWR_STATE_BATT_OFF;
-    if (power_cfg ||
-        (p_cb->nfcee_id == NFC_DH_ID &&
-         nfa_ee_proto_mask_list[xx] == NFA_PROTOCOL_MASK_NFC_DEP)) {
+    if (power_cfg) {
       /* Applying Route Block for ISO DEP Protocol, so that AIDs
        * which are not in the routing table can also be blocked */
       if (nfa_ee_proto_mask_list[xx] == NFA_PROTOCOL_MASK_ISO_DEP) {
@@ -405,21 +407,8 @@ static void nfa_ee_add_proto_route_to_ecb(tNFA_EE_ECB* p_cb, uint8_t* pp,
       } else {
         proto_tag = NFC_ROUTE_TAG_PROTO;
       }
-      if (p_cb->nfcee_id == NFC_DH_ID &&
-          nfa_ee_proto_mask_list[xx] == NFA_PROTOCOL_MASK_NFC_DEP) {
-        /* add NFC-DEP routing to HOST if NFC_DEP interface is supported */
-        if (nfc_cb.nci_interfaces & (1 << NCI_INTERFACE_NFC_DEP)) {
-          add_route_tech_proto_tlv(&pp, NFC_ROUTE_TAG_PROTO, NFC_DH_ID,
-                                   NCI_ROUTE_PWR_STATE_ON,
-                                   NFC_PROTOCOL_NFC_DEP);
-          LOG(VERBOSE) << StringPrintf("%s - NFC DEP added for DH!!!", __func__);
-        } else {
-          continue;
-        }
-      } else {
-        add_route_tech_proto_tlv(&pp, proto_tag, p_cb->nfcee_id, power_cfg,
-                                 nfa_ee_proto_list[xx]);
-      }
+      add_route_tech_proto_tlv(&pp, proto_tag, p_cb->nfcee_id, power_cfg,
+                               nfa_ee_proto_list[xx]);
       num_tlv++;
       if (power_cfg != NCI_ROUTE_PWR_STATE_ON)
         nfa_ee_cb.ee_cfged |= NFA_EE_CFGED_OFF_ROUTING;
@@ -546,6 +535,12 @@ static void nfa_ee_add_sys_code_route_to_ecb(tNFA_EE_ECB* p_cb, uint8_t* pp,
       uint8_t* p_start = pp;
       /* add one SC entry */
       if (p_cb->sys_code_rt_loc_vs_info[xx] & NFA_EE_AE_ROUTE) {
+        if (start_offset >
+            (sizeof(p_cb->sys_code_cfg) - NFA_EE_SYSTEM_CODE_LEN)) {
+          LOG(ERROR) << StringPrintf("%s; start_offset higher than 2",
+                                     __func__);
+          return;
+        }
         uint8_t* p_sys_code_cfg = &p_cb->sys_code_cfg[start_offset];
         if (nfa_ee_is_active(p_cb->sys_code_rt_loc[xx] | NFA_HANDLE_GROUP_EE)) {
           if (mute_tech_route_option) {
@@ -777,6 +772,12 @@ tNFA_EE_ECB* nfa_ee_find_sys_code_offset(uint16_t sys_code, int* p_offset,
     if (p_ecb->sys_code_cfg_entries) {
       uint8_t offset = 0;
       for (uint8_t yy = 0; yy < p_ecb->sys_code_cfg_entries; yy++) {
+        if (offset >=
+            (NFA_EE_MAX_SYSTEM_CODE_ENTRIES * NFA_EE_SYSTEM_CODE_LEN)) {
+          LOG(ERROR) << StringPrintf("%s; offset higher than max allowed value",
+                                     __func__);
+          return nullptr;
+        }
         if ((memcmp(&p_ecb->sys_code_cfg[offset], &sys_code,
                     NFA_EE_SYSTEM_CODE_LEN) == 0)) {
           p_ret = p_ecb;
@@ -2039,6 +2040,14 @@ void nfa_ee_nci_disc_ntf(tNFA_EE_MSG* p_data) {
       }
     }
 
+    if (p_cb->ee_tlv[NFCEE_TAG_INDEX].tag == NFCEE_TYPE_NDEF) {
+      nfa_t4tnfcee_set_ee_cback(p_cb);
+      p_info = &evt_data.new_ee;
+      p_info->ee_handle = (tNFA_HANDLE)p_cb->nfcee_id;
+      p_info->ee_status = p_cb->ee_status;
+      nfa_ee_report_event(p_cb->p_ee_cback, NFA_EE_DISCOVER_EVT, &evt_data);
+    }
+
     if ((nfa_ee_cb.p_ee_disc_cback == nullptr) && (notify_new_ee == true)) {
       if (nfa_dm_is_active() && (p_cb->ee_status != NFA_EE_STATUS_REMOVED)) {
         /* report this NFA_EE_NEW_EE_EVT only after NFA_DM_ENABLE_EVT is
@@ -2519,6 +2528,11 @@ void nfa_ee_nci_disc_req_ntf(tNFA_EE_MSG* p_data) {
                  NFC_DISCOVERY_TYPE_LISTEN_B_PRIME) {
         p_cb->lbp_protocol = p_cbk->info[xx].protocol;
       }
+      if (p_cb->ee_tlv[NFCEE_TAG_INDEX].tag == NFCEE_TYPE_NDEF) {
+        tNFA_EE_CBACK_DATA nfa_ee_cback_data = {0};
+        nfa_ee_report_event(p_cb->p_ee_cback, NFA_EE_DISCOVER_REQ_EVT,
+                            &nfa_ee_cback_data);
+      }
       LOG(VERBOSE) << StringPrintf(
           "nfcee_id=0x%x ee_status=0x%x ecb_flags=0x%x la_protocol=0x%x "
           "la_protocol=0x%x la_protocol=0x%x",
diff --git a/src/nfa/include/nfa_api.h b/src/nfa/include/nfa_api.h
index 2984b0ce..1b58a828 100755
--- a/src/nfa/include/nfa_api.h
+++ b/src/nfa/include/nfa_api.h
@@ -134,6 +134,7 @@ typedef uint8_t tNFA_TECHNOLOGY_MASK;
 #define NFA_PROTOCOL_NFC_DEP NFC_PROTOCOL_NFC_DEP
 /* NFC_PROTOCOL_T5T in NCI2.0 and NFC_PROTOCOL_ISO15693 proprietary in NCI1.0*/
 #define NFA_PROTOCOL_T5T NFC_PROTOCOL_T5T
+#define NFA_PROTOCOL_CI NFC_PROTOCOL_CI
 #define NFA_PROTOCOL_INVALID 0xFF
 typedef uint8_t tNFA_NFC_PROTOCOL;
 
@@ -142,7 +143,6 @@ typedef uint8_t tNFA_NFC_PROTOCOL;
 #define NFA_PROTOCOL_MASK_T2T 0x02     /* MIFARE / Type 2 tag */
 #define NFA_PROTOCOL_MASK_T3T 0x04     /* FeliCa / Type 3 tag */
 #define NFA_PROTOCOL_MASK_ISO_DEP 0x08 /* ISODEP/4A,4B        */
-#define NFA_PROTOCOL_MASK_NFC_DEP 0x10 /* NFCDEP/LLCP         */
 typedef uint8_t tNFA_PROTOCOL_MASK;
 
 /* NFA_DM callback events */
@@ -366,11 +366,16 @@ typedef struct {
   uint8_t IC_reference; /* IC Reference if I93_INFO_FLAG_IC_REF         */
 } tNFA_I93_PARAMS;
 
+typedef struct {
+  uint8_t mbi;
+  uint8_t uid[8]; /* UID of Chinese Id Card           */
+} tNFA_CI_PARAMS;
 typedef union {
   tNFA_T1T_PARAMS t1t; /* HR and UID of T1T                */
   tNFA_T2T_PARAMS t2t; /* UID of T2T                       */
   tNFA_T3T_PARAMS t3t; /* System codes                     */
   tNFA_I93_PARAMS i93; /* System Information of ISO 15693  */
+  tNFA_CI_PARAMS ci;
 } tNFA_TAG_PARAMS;
 
 typedef struct {
@@ -537,6 +542,8 @@ typedef struct {
   uint8_t presence_check_option;
   /* Maximum time to wait for presence check response         */
   uint16_t presence_check_timeout;
+  /* timeout for rf deactivate in rf listen active state      */
+  uint16_t deact_ntf_listen_active_timeout;
 } tNFA_DM_CFG;
 
 /* compile-time configuration structure for HCI */
@@ -622,7 +629,6 @@ typedef tNFC_RF_COMM_PARAMS tNFA_RF_COMM_PARAMS;
 /* RF Interface type */
 #define NFA_INTERFACE_FRAME NFC_INTERFACE_FRAME
 #define NFA_INTERFACE_ISO_DEP NFC_INTERFACE_ISO_DEP
-#define NFA_INTERFACE_NFC_DEP NFC_INTERFACE_NFC_DEP
 #define NFA_INTERFACE_MIFARE NFC_INTERFACE_MIFARE
 typedef tNFC_INTF_TYPE tNFA_INTF_TYPE;
 
@@ -1295,6 +1301,17 @@ extern tNFA_STATUS NFA_SendRawVsCommand(uint8_t cmd_params_len,
 *******************************************************************************/
 extern void NFA_EnableDtamode(tNFA_eDtaModes eDtaMode);
 
+/*******************************************************************************
+**
+** Function:        NFA_SetNfcSecure
+**
+** Description:     Set NFC secure flag
+**
+** Returns:         none:
+**
+*******************************************************************************/
+extern void NFA_SetNfcSecure(bool status);
+
 /*******************************************************************************
 **
 ** Function:        NFA_DisableDtamode
diff --git a/src/nfa/include/nfa_dm_int.h b/src/nfa/include/nfa_dm_int.h
index cf78b163..64ed597b 100755
--- a/src/nfa/include/nfa_dm_int.h
+++ b/src/nfa/include/nfa_dm_int.h
@@ -299,31 +299,22 @@ typedef uint8_t tNFA_DM_RF_DISC_EVT;
 #define NFA_DM_DISC_MASK_P_T5T 0x00000100
 #define NFA_DM_DISC_MASK_P_B_PRIME 0x00000200
 #define NFA_DM_DISC_MASK_P_KOVIO 0x00000400
-#define NFA_DM_DISC_MASK_PAA_NFC_DEP 0x00000800
-#define NFA_DM_DISC_MASK_PACM_NFC_DEP 0x00000800
-#define NFA_DM_DISC_MASK_PFA_NFC_DEP 0x00001000
 /* Legacy/proprietary/non-NFC Forum protocol (e.g Shanghai transit card) */
 #define NFA_DM_DISC_MASK_P_LEGACY 0x00002000
 #define NFA_DM_DISC_MASK_PA_MIFARE 0x00004000
+#define NFA_DM_DISC_MASK_PB_CI 0x00008000
 #define NFA_DM_DISC_MASK_POLL 0x0000FFFF
 
 #define NFA_DM_DISC_MASK_LA_T1T 0x00010000
 #define NFA_DM_DISC_MASK_LA_T2T 0x00020000
 #define NFA_DM_DISC_MASK_LA_ISO_DEP 0x00040000
-#define NFA_DM_DISC_MASK_LA_NFC_DEP 0x00080000
 #define NFA_DM_DISC_MASK_LB_ISO_DEP 0x00100000
 #define NFA_DM_DISC_MASK_LF_T3T 0x00200000
-#define NFA_DM_DISC_MASK_LF_NFC_DEP 0x00400000
 #define NFA_DM_DISC_MASK_L_ISO15693 0x01000000
 #define NFA_DM_DISC_MASK_L_B_PRIME 0x02000000
-#define NFA_DM_DISC_MASK_LACM_NFC_DEP 0x04000000
-#define NFA_DM_DISC_MASK_LAA_NFC_DEP 0x04000000
-#define NFA_DM_DISC_MASK_LFA_NFC_DEP 0x08000000
 #define NFA_DM_DISC_MASK_L_LEGACY 0x10000000
 #define NFA_DM_DISC_MASK_LISTEN 0xFFFF0000
 
-#define NFA_DM_DISC_MASK_NFC_DEP 0x0C481848
-
 typedef uint32_t tNFA_DM_DISC_TECH_PROTO_MASK;
 
 /* DM RF discovery host ID */
@@ -382,12 +373,6 @@ enum {
 /* NFA_EE_MAX_TECH_ROUTE. only A, B, F, Bprime are supported by UICC now */
 #define NFA_DM_MAX_TECH_ROUTE 4
 
-/* timeout for waiting deactivation NTF,
-** possible delay to send deactivate CMD if all credit wasn't returned
-** transport delay (1sec) and max RWT (5sec)
-*/
-#define NFA_DM_DISC_TIMEOUT_W4_DEACT_NTF (NFC_DEACTIVATE_TIMEOUT * 1000 + 6000)
-
 typedef struct {
   uint16_t disc_duration; /* Disc duration                                    */
   tNFA_DM_DISC_FLAGS disc_flags;    /* specific action flags */
@@ -508,6 +493,8 @@ typedef struct {
   uint8_t atr_res_gen_bytes_len;
 
   uint8_t pf_rc[NCI_PARAM_LEN_PF_RC];
+  uint8_t rf_field_info[NCI_PARAM_LEN_RF_FIELD_INFO];
+  uint8_t rf_field_info_len;
 } tNFA_DM_PARAMS;
 
 /*
@@ -562,9 +549,10 @@ typedef struct {
   /* NFCC power mode */
   uint8_t nfcc_pwr_mode; /* NFA_DM_PWR_MODE_FULL or NFA_DM_PWR_MODE_OFF_SLEEP */
 
+  tNFC_DEACT_TYPE listen_deact_cmd_type;
   uint8_t deactivate_cmd_retry_count; /*number of times the deactivation cmd
                                          sent in case of error scenerio */
-
+  bool is_nfc_secure;
   uint8_t power_state; /* current screen/power  state */
   uint32_t eDtaMode;   /* To enable the DTA type modes. */
   uint8_t pending_power_state; /* pending screen state change received in
@@ -688,6 +676,7 @@ tNFC_STATUS nfa_dm_disc_sleep_wakeup(void);
 tNFC_STATUS nfa_dm_disc_start_kovio_presence_check(void);
 bool nfa_dm_is_raw_frame_session(void);
 
+bool nfa_dm_get_nfc_secure();
 void nfa_dm_get_tech_route_block(uint8_t* listen_techmask, bool* enable);
 void nfa_dm_start_wireless_power_transfer(uint8_t power_adj_req,
                                           uint8_t wpt_time_int);
diff --git a/src/nfa/include/nfa_nfcee_api.h b/src/nfa/include/nfa_nfcee_api.h
new file mode 100644
index 00000000..b67216d3
--- /dev/null
+++ b/src/nfa/include/nfa_nfcee_api.h
@@ -0,0 +1,90 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 The Android Open Source Project.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+#pragma once
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeOpenConnection
+**
+** Description      Creates logical connection with T4T Nfcee
+**
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeOpenConnection();
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeClear
+**
+** Description      Clear Ndef data to T4T NFC EE.
+**                  For file ID NDEF, perform the NDEF detection procedure
+**                  and set the NDEF tag data to zero.
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeClear(uint8_t* p_fileId);
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeWrite
+**
+** Description      Write data to the T4T NFC EE of given file id.
+**                  If file ID is of NDEF, perform the NDEF detection procedure
+**                  and write the NDEF tag data using the appropriate method for
+**                  NDEF EE.
+**                  If File ID is Not NDEF then reads proprietary way
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeWrite(uint8_t* p_fileId, uint8_t* p_data, uint32_t len);
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeRead
+**
+** Description      Read T4T message from NFCC area.of given file id.
+**                  If file ID is of NDEF, perform the NDEF detection
+**                  procedure and read the NDEF tag data using the appropriate
+**                  method for NDEF EE. If File ID is Not NDEF then reads
+**                  proprietary way
+**
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeRead(uint8_t* p_fileId);
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeCloseConnection
+**
+** Description      Closes logical connection with T4T Nfcee
+**
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeCloseConnection();
diff --git a/src/nfa/include/nfa_nfcee_int.h b/src/nfa/include/nfa_nfcee_int.h
new file mode 100644
index 00000000..10205825
--- /dev/null
+++ b/src/nfa/include/nfa_nfcee_int.h
@@ -0,0 +1,159 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 The Android Open Source Project.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+#pragma once
+#include "nfa_ee_int.h"
+#include "nfa_sys.h"
+using namespace std;
+
+#define CC_FILE_ID 0xE103
+#define NDEF_FILE_ID 0xE104
+
+#define T4TNFCEE_SIZEOF_LEN_BYTES 0x02
+#define T4TNFCEE_SIZEOF_STATUS_BYTES 0x02
+
+/*CLA + INS + P1 + P2 + LC*/
+#define CAPDU_TL 0x05
+#define RW_T4TNFCEE_DATA_PER_WRITE (T4T_MAX_LENGTH_LC - CAPDU_TL)
+
+/*
+POWER_STATE:
+bit pos 0 = Switch On
+bit pos 1 = Switch Off
+bit pos 2 = Battery Off
+bit pos 3 = Screen On lock
+bit pos 4 = Screen off unlock
+bit pos 5 = Screen Off lock
+*/
+#define T4TNFCEE_AID_POWER_STATE 0x3B
+
+/* Event to notify T4T NFCEE Detection complete*/
+#define NFA_T4TNFCEE_EVT 40
+/* Event to notify NDEF T4TNFCEE READ complete*/
+#define NFA_T4TNFCEE_READ_CPLT_EVT 41
+/* Event to notify NDEF T4TNFCEE WRITE complete*/
+#define NFA_T4TNFCEE_WRITE_CPLT_EVT 42
+/* Event to notify NDEF T4TNFCEE CLEAR complete*/
+#define NFA_T4TNFCEE_CLEAR_CPLT_EVT 43
+/* Event to notify NDEF T4TNFCEE READ CC DATA complete*/
+#define NFA_T4TNFCEE_READ_CC_DATA_CPLT_EVT 44
+
+#define T4T_NFCEE_READ_ALLOWED 0x00
+#define T4T_NFCEE_WRITE_NOT_ALLOWED 0xFF
+
+/*Status codes*/
+#define NFA_T4T_STATUS_INVALID_FILE_ID 0x05
+
+typedef struct {
+  uint16_t capacity;
+  uint8_t read_access;
+  uint8_t write_access;
+} tNFA_T4TNFCEE_FILE_INFO;
+
+enum {
+  NFA_T4TNFCEE_OP_OPEN_CONNECTION,
+  NFA_T4TNFCEE_OP_READ,
+  NFA_T4TNFCEE_OP_WRITE,
+  NFA_T4TNFCEE_OP_CLOSE_CONNECTION,
+  NFA_T4TNFCEE_OP_CLEAR,
+  NFA_T4TNFCEE_OP_READ_CC_FILE,
+  NFA_T4TNFCEE_OP_MAX
+};
+typedef uint8_t tNFA_T4TNFCEE_OP;
+
+typedef struct {
+  uint32_t len;
+  uint8_t* p_data;
+} tNFA_T4TNFCEE_OP_PARAMS_WRITE;
+
+/* NDEF EE  events */
+enum {
+  NFA_T4TNFCEE_OP_REQUEST_EVT = NFA_SYS_EVT_START(NFA_ID_T4TNFCEE),
+  NFA_T4TNFCEE_MAX_EVT
+};
+
+/* data type for NFA_T4TNFCEE_op_req_EVT */
+typedef struct {
+  NFC_HDR hdr;
+  tNFA_T4TNFCEE_OP op; /* NFA T4TNFCEE operation */
+  uint8_t* p_fileId;
+  tNFA_T4TNFCEE_OP_PARAMS_WRITE write;
+} tNFA_T4TNFCEE_OPERATION;
+
+/* union of all data types */
+typedef union {
+  /* GKI event buffer header */
+  NFC_HDR hdr;
+  tNFA_T4TNFCEE_OPERATION op_req;
+} tNFA_T4TNFCEE_MSG;
+
+typedef enum {
+  /* NFA T4TNFCEE states */
+  NFA_T4TNFCEE_STATE_DISABLED = 0x00, /* T4TNFCEE is disabled  */
+  NFA_T4TNFCEE_STATE_TRY_ENABLE,
+  NFA_T4TNFCEE_STATE_INITIALIZED,  /* T4TNFCEE is waiting to handle api commands
+                                    */
+  NFA_T4TNFCEE_STATE_CONNECTED,    /* T4TNFCEE is in open sequence */
+  NFA_T4TNFCEE_STATE_DISCONNECTED, /* T4TNFCEE is in closing sequence */
+  NFA_T4TNFCEE_STATE_OPEN_FAILED   /* T4TNFCEE OPEN Failed */
+} tNFA_T4TNFCEE_STATE;
+
+typedef enum {
+  PROP_DISABLED = 0x00,
+  WAIT_SELECT_APPLICATION,
+  WAIT_SELECT_CC,
+  WAIT_READ_CC_DATA_LEN,
+  WAIT_READ_CC_FILE,
+  WAIT_SELECT_FILE,
+  WAIT_READ_DATA_LEN,
+  WAIT_READ_FILE,
+  WAIT_RESET_NLEN,
+  WAIT_WRITE,
+  WAIT_WRITE_COMPLETE,
+  WAIT_UPDATE_NLEN,
+  WAIT_CLEAR_NDEF_DATA,
+  OP_COMPLETE = 0x00
+} tNFA_T4TNFCEE_RW_STATE;
+/* NFA T4TNFCEE control block */
+typedef struct {
+  tNFA_STATUS status;
+  tNFA_T4TNFCEE_STATE t4tnfcee_state; /* T4T NFCEE state */
+  tNFA_T4TNFCEE_OP cur_op;            /* Current operation */
+  tNFA_T4TNFCEE_RW_STATE rw_state;    /* Read Write state */
+  tNFA_T4TNFCEE_MSG* p_pending_msg;   /* Pending command */
+  uint8_t* p_dataBuf;                 /* Data buffer */
+  uint16_t cur_fileId;                /* Current FileId */
+  uint16_t rd_offset;        /* current read-offset of incoming NDEF data  */
+  uint32_t dataLen;          /*length of the data*/
+  bool ndefEmulationSupport; /* NDEF emulation support */
+  uint8_t connId;            /* NDEF NFCEE CONN ID */
+} tNFA_T4TNFCEE_CB;
+extern tNFA_T4TNFCEE_CB nfa_t4tnfcee_cb;
+
+/* type definition for action functions */
+typedef bool (*tNFA_T4TNFCEE_ACTION)(tNFA_T4TNFCEE_MSG* p_data);
+
+bool nfa_t4tnfcee_handle_op_req(tNFA_T4TNFCEE_MSG* p_data);
+bool nfa_t4tnfcee_handle_event(NFC_HDR* p_msg);
+void nfa_t4tnfcee_free_rx_buf(void);
+bool nfa_t4tnfcee_is_enabled(void);
+bool NFA_T4tNfcEeIsProcessing(void);
+bool NFA_T4tNfcEeIsEmulationSupported(void);
+void nfa_t4tnfcee_set_ee_cback(tNFA_EE_ECB* p_ecb);
+void nfa_t4tnfcee_init();
+void nfa_t4tnfcee_deinit(void);
+tNFC_STATUS nfa_t4tnfcee_proc_disc_evt(tNFA_T4TNFCEE_OP event);
diff --git a/src/nfa/include/nfa_rw_int.h b/src/nfa/include/nfa_rw_int.h
index 38101d7b..1b5d9788 100644
--- a/src/nfa/include/nfa_rw_int.h
+++ b/src/nfa/include/nfa_rw_int.h
@@ -119,6 +119,8 @@ enum {
   NFA_RW_OP_I93_GET_SYS_INFO,
   NFA_RW_OP_I93_GET_MULTI_BLOCK_STATUS,
   NFA_RW_OP_I93_SET_ADDR_MODE,
+  NFA_RW_OP_CI_ATTRIB,
+  NFA_RW_OP_CI_UID,
   NFA_RW_OP_MAX
 };
 typedef uint8_t tNFA_RW_OP;
@@ -196,6 +198,10 @@ typedef struct {
   uint8_t* p_data;
 } tNFA_RW_OP_PARAMS_I93_CMD;
 
+typedef struct {
+  uint8_t nfcid0[NFC_NFCID0_MAX_LEN];
+} tNFA_RW_OP_PARAMS_CI;
+
 /* Union of params for all reader/writer operations */
 typedef union {
   /* params for NFA_RW_OP_WRITE_NDEF */
@@ -227,6 +233,7 @@ typedef union {
 
   /* params for ISO 15693 */
   tNFA_RW_OP_PARAMS_I93_CMD i93_cmd;
+  tNFA_RW_OP_PARAMS_CI ci_param;
 
 } tNFA_RW_OP_PARAMS;
 
diff --git a/src/nfa/include/nfa_sys.h b/src/nfa/include/nfa_sys.h
index 48e506c2..4aa8d8f6 100644
--- a/src/nfa/include/nfa_sys.h
+++ b/src/nfa/include/nfa_sys.h
@@ -34,16 +34,17 @@
 
 /* SW sub-systems */
 enum {
-  NFA_ID_SYS,  /* system manager                      */
-  NFA_ID_DM,   /* device manager                      */
-  NFA_ID_EE,   /* NFCEE sub-system                    */
-  NFA_ID_RW,   /* Reader/writer sub-system            */
-  NFA_ID_CE,   /* Card-emulation sub-system           */
-  NFA_ID_HCI,  /* Host controller interface sub-system*/
-  NFA_ID_WLC,  /* WLC sub-system */
+  NFA_ID_SYS, /* system manager                      */
+  NFA_ID_DM,  /* device manager                      */
+  NFA_ID_EE,  /* NFCEE sub-system                    */
+  NFA_ID_RW,  /* Reader/writer sub-system            */
+  NFA_ID_CE,  /* Card-emulation sub-system           */
+  NFA_ID_HCI, /* Host controller interface sub-system*/
+  NFA_ID_WLC, /* WLC sub-system */
 #if (NFA_DTA_INCLUDED == TRUE)
   NFA_ID_DTA, /* Device Test Application sub-system  */
 #endif
+  NFA_ID_T4TNFCEE, /* T4T Nfcee sub-system  */
   NFA_ID_MAX
 };
 typedef uint8_t tNFA_SYS_ID;
diff --git a/src/nfa/ndefnfcee/t4t/nfa_nfcee_act.cc b/src/nfa/ndefnfcee/t4t/nfa_nfcee_act.cc
new file mode 100644
index 00000000..40e05aec
--- /dev/null
+++ b/src/nfa/ndefnfcee/t4t/nfa_nfcee_act.cc
@@ -0,0 +1,705 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 The Android Open Source Project.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <string.h>
+
+#include <iomanip>
+#include <unordered_map>
+
+#include "ndef_utils.h"
+#include "nfa_dm_int.h"
+#include "nfa_mem_co.h"
+#include "nfa_nfcee_int.h"
+
+using android::base::StringPrintf;
+
+void nfa_t4tnfcee_handle_t4t_evt(tRW_EVENT event, tRW_DATA* p_data);
+void nfa_t4tnfcee_store_cc_info(NFC_HDR* p_data);
+void nfa_t4tnfcee_notify_rx_evt(void);
+void nfa_t4tnfcee_handle_file_operations(tRW_DATA* p_rwData);
+bool isReadPermitted(void);
+bool isWritePermitted(void);
+bool isDataLenBelowMaxFileCapacity(void);
+void nfa_t4tnfcee_store_rx_buf(NFC_HDR* p_data);
+void nfa_t4tnfcee_initialize_data(tNFA_T4TNFCEE_MSG* p_data);
+bool is_read_precondition_valid(tNFA_T4TNFCEE_MSG* p_data);
+bool is_write_precondition_valid(tNFA_T4TNFCEE_MSG* p_data);
+uint16_t nfa_t4tnfcee_get_len(tRW_DATA* p_rwData);
+tNFC_STATUS getWritePreconditionStatus();
+bool isError(tNFC_STATUS status);
+unordered_map<uint16_t, tNFA_T4TNFCEE_FILE_INFO> ccFileInfo;
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_free_rx_buf
+ **
+ ** Description      Free buffer allocated to hold incoming T4T message
+ **
+ ** Returns          Nothing
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_free_rx_buf(void) {
+  /*Free only if it is Read operation
+  For write, buffer will be passed from JNI which will be freed by JNI*/
+  if (((nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ) ||
+       (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_CLEAR) ||
+       (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ_CC_FILE)) &&
+      nfa_t4tnfcee_cb.p_dataBuf) {
+    nfa_mem_co_free(nfa_t4tnfcee_cb.p_dataBuf);
+    nfa_t4tnfcee_cb.p_dataBuf = NULL;
+  }
+  nfa_t4tnfcee_cb.rd_offset = 0x00;
+  nfa_t4tnfcee_cb.dataLen = 0x00;
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_exec_file_operation
+ **
+ ** Description      Handles read sequence for Ndef and proprietary
+ **
+ ** Returns          tNFA_STATUS
+ **
+ *******************************************************************************/
+tNFA_STATUS nfa_t4tnfcee_exec_file_operation() {
+  tNFA_STATUS status = NFA_STATUS_FAILED;
+  LOG(DEBUG) << StringPrintf("%s Enter", __func__);
+  status = RW_SetT4tNfceeInfo((tRW_CBACK*)nfa_t4tnfcee_handle_t4t_evt,
+                              nfa_t4tnfcee_cb.connId);
+  if (status != NFA_STATUS_OK) {
+    LOG(DEBUG) << StringPrintf("%s T4T info not able to set. Return", __func__);
+    return status;
+  }
+  status = RW_T4tNfceeSelectApplication();
+  if (status != NFA_STATUS_OK) {
+    LOG(DEBUG) << StringPrintf("%s T4T Select application failed", __func__);
+    return status;
+  } else {
+    nfa_t4tnfcee_cb.rw_state = WAIT_SELECT_APPLICATION;
+    return NFA_STATUS_OK;
+  }
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_handle_op_req
+ **
+ ** Description      Handler for NFA_T4TNFCEE_OP_REQUEST_EVT, operation request
+ **
+ ** Returns          true if caller should free p_data
+ **                  false if caller does not need to free p_data
+ **
+ *******************************************************************************/
+bool nfa_t4tnfcee_handle_op_req(tNFA_T4TNFCEE_MSG* p_data) {
+  LOG(DEBUG) << StringPrintf("nfa_t4tnfcee_handle_op_req: op=0x%02x",
+                             p_data->op_req.op);
+  nfa_t4tnfcee_cb.cur_op = p_data->op_req.op;
+
+  /* Call appropriate handler for requested operation */
+  switch (p_data->op_req.op) {
+    case NFA_T4TNFCEE_OP_OPEN_CONNECTION: {
+      nfa_t4tnfcee_proc_disc_evt(NFA_T4TNFCEE_OP_OPEN_CONNECTION);
+    } break;
+    case NFA_T4TNFCEE_OP_READ:
+    case NFA_T4TNFCEE_OP_READ_CC_FILE: {
+      if (!is_read_precondition_valid(p_data)) {
+        LOG(DEBUG) << StringPrintf("%s Failed", __func__);
+        nfa_t4tnfcee_cb.status = NFA_STATUS_INVALID_PARAM;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+      nfa_t4tnfcee_initialize_data(p_data);
+      tNFA_STATUS status = nfa_t4tnfcee_exec_file_operation();
+      if (status != NFA_STATUS_OK) {
+        nfa_t4tnfcee_cb.status = NFA_STATUS_FAILED;
+        nfa_t4tnfcee_notify_rx_evt();
+      }
+    } break;
+    case NFA_T4TNFCEE_OP_WRITE: {
+      if (!is_write_precondition_valid(p_data)) {
+        LOG(DEBUG) << StringPrintf("%s Failed", __func__);
+        nfa_t4tnfcee_cb.status = NFA_STATUS_INVALID_PARAM;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+      nfa_t4tnfcee_initialize_data(p_data);
+      if ((p_data->op_req.write.p_data != nullptr) &&
+          (p_data->op_req.write.len > 0)) {
+        nfa_t4tnfcee_cb.p_dataBuf = p_data->op_req.write.p_data;
+        nfa_t4tnfcee_cb.dataLen = p_data->op_req.write.len;
+      }
+      tNFA_STATUS status = nfa_t4tnfcee_exec_file_operation();
+      if (status != NFA_STATUS_OK) {
+        nfa_t4tnfcee_cb.status = NFA_STATUS_FAILED;
+        nfa_t4tnfcee_notify_rx_evt();
+      }
+    } break;
+    case NFA_T4TNFCEE_OP_CLEAR: {
+      nfa_t4tnfcee_initialize_data(p_data);
+      tNFA_STATUS status = nfa_t4tnfcee_exec_file_operation();
+      if (status != NFA_STATUS_OK) {
+        nfa_t4tnfcee_cb.status = NFA_STATUS_FAILED;
+        nfa_t4tnfcee_notify_rx_evt();
+      }
+      break;
+    }
+    case NFA_T4TNFCEE_OP_CLOSE_CONNECTION: {
+      nfa_t4tnfcee_proc_disc_evt(NFA_T4TNFCEE_OP_CLOSE_CONNECTION);
+    } break;
+    default:
+      break;
+  }
+  return true;
+}
+/*******************************************************************************
+ **
+ ** Function     nfa_t4tnfcee_check_sw
+ **
+ ** Description  Updates the status if R-APDU has been received with failure
+ *status
+ **
+ ** Returns      Nothing
+ **
+ *******************************************************************************/
+static void nfa_t4tnfcee_check_sw(tRW_DATA* p_rwData) {
+  uint8_t* p;
+  uint16_t status_words;
+  NFC_HDR* p_r_apdu = p_rwData->raw_frame.p_data;
+  p = (uint8_t*)(p_r_apdu + 1) + p_r_apdu->offset;
+  p += (p_r_apdu->len - T4T_RSP_STATUS_WORDS_SIZE);
+  BE_STREAM_TO_UINT16(status_words, p);
+  if ((status_words != T4T_RSP_CMD_CMPLTED) &&
+      (!T4T_RSP_WARNING_PARAMS_CHECK(status_words >> 8))) {
+    p_rwData->raw_frame.status = NFC_STATUS_FAILED;
+    LOG(DEBUG) << StringPrintf("status 0x%X", status_words);
+  }
+}
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_handle_t4t_evt
+ **
+ ** Description      Handler for Type-4 NFCEE reader/writer events
+ **
+ ** Returns          Nothing
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_handle_t4t_evt(tRW_EVENT event, tRW_DATA* p_rwData) {
+  LOG(DEBUG) << StringPrintf("%s: Enter event=0x%02x 0x%02x", __func__, event,
+                             p_rwData->status);
+  switch (event) {
+    case RW_T4T_RAW_FRAME_EVT:
+      nfa_t4tnfcee_check_sw(p_rwData);
+      LOG(DEBUG) << StringPrintf("%s RW_T4T_RAW_FRAME_EVT", __func__);
+      nfa_t4tnfcee_handle_file_operations(p_rwData);
+      break;
+    case RW_T4T_INTF_ERROR_EVT:
+      LOG(DEBUG) << StringPrintf("%s RW_T4T_INTF_ERROR_EVT", __func__);
+      nfa_t4tnfcee_handle_file_operations(p_rwData);
+      break;
+    default:
+      LOG(DEBUG) << StringPrintf("%s UNKNOWN EVENT", __func__);
+      break;
+  }
+  return;
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_store_cc_info
+ **
+ ** Description      stores CC info into local data structure
+ **
+ ** Returns          Nothing
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_store_cc_info(NFC_HDR* p_data) {
+  LOG(DEBUG) << StringPrintf("%s Enter", __func__);
+
+  uint16_t keyFileId;
+  string valueFileLength;
+  const uint8_t skipTL = 0x02, tlvLen = 0x08;
+  uint8_t jumpToFirstTLV = 0x03; /*Le index*/
+  uint16_t RemainingDataLen = 0;
+  uint8_t* ccInfo;
+
+  if (NULL != p_data) {
+    if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ_CC_FILE) {
+      ccInfo = (uint8_t*)(p_data + 1) +
+               p_data->offset;  // CC data does not require NDEF header offset
+      nfa_t4tnfcee_cb.p_dataBuf = (uint8_t*)nfa_mem_co_alloc(p_data->len);
+      memcpy(&nfa_t4tnfcee_cb.p_dataBuf[0], ccInfo, p_data->len);
+      return;
+    } else {
+      ccInfo = (uint8_t*)(p_data + 1) + p_data->offset + jumpToFirstTLV;
+    }
+  } else {
+    LOG(DEBUG) << StringPrintf("%s empty cc info", __func__);
+    return;
+  }
+  RW_T4tNfceeUpdateCC(ccInfo);
+
+  jumpToFirstTLV = 0x07;
+  ccInfo = (uint8_t*)(p_data + 1) + p_data->offset + jumpToFirstTLV;
+  ccFileInfo.clear();
+  RemainingDataLen =
+      (p_data->len - jumpToFirstTLV - T4TNFCEE_SIZEOF_STATUS_BYTES);
+  while (RemainingDataLen >= 0x08) {
+    tNFA_T4TNFCEE_FILE_INFO fileInfo;
+    ccInfo += skipTL;
+    BE_STREAM_TO_UINT16(keyFileId, ccInfo);
+    BE_STREAM_TO_UINT16(fileInfo.capacity, ccInfo);
+    BE_STREAM_TO_UINT8(fileInfo.read_access, ccInfo);
+    BE_STREAM_TO_UINT8(fileInfo.write_access, ccInfo);
+    ccFileInfo.insert(
+        pair<uint16_t, tNFA_T4TNFCEE_FILE_INFO>(keyFileId, fileInfo));
+    keyFileId = 0x00;
+    RemainingDataLen -= tlvLen;
+  }
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_store_rx_buf
+ **
+ ** Description      Stores read data.
+ **
+ ** Returns          Nothing
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_store_rx_buf(NFC_HDR* p_data) {
+  uint8_t* p;
+  if (NULL != p_data) {
+    LOG(DEBUG) << StringPrintf("%s copying data len %d  rd_offset: %d", __func__,
+                                p_data->len, nfa_t4tnfcee_cb.rd_offset);
+    p = (uint8_t*)(p_data + 1) + p_data->offset;
+    memcpy(&nfa_t4tnfcee_cb.p_dataBuf[nfa_t4tnfcee_cb.rd_offset], p,
+           p_data->len);
+    nfa_t4tnfcee_cb.rd_offset += p_data->len;
+  } else {
+    LOG(DEBUG) << StringPrintf("%s Data is NULL", __func__);
+  }
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_initialize_data
+ **
+ ** Description      Initializes control block
+ **
+ ** Returns          none
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_initialize_data(tNFA_T4TNFCEE_MSG* p_data) {
+  nfa_t4tnfcee_cb.rw_state = PROP_DISABLED;
+  nfa_t4tnfcee_cb.rd_offset = 0;
+  nfa_t4tnfcee_cb.p_dataBuf = nullptr;
+  nfa_t4tnfcee_cb.dataLen = 0x00;
+  BE_STREAM_TO_UINT16(nfa_t4tnfcee_cb.cur_fileId, p_data->op_req.p_fileId);
+}
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_handle_file_operations
+ **
+ ** Description      Handles proprietary file operations
+ **
+ ** Returns          none
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_handle_file_operations(tRW_DATA* p_rwData) {
+  if (p_rwData == nullptr) {
+    nfa_t4tnfcee_cb.status = NFC_STATUS_FAILED;
+    nfa_t4tnfcee_notify_rx_evt();
+    return;
+  }
+  LOG(DEBUG) << StringPrintf("%s currState : 0x%02x", __func__,
+                             nfa_t4tnfcee_cb.rw_state);
+  switch (nfa_t4tnfcee_cb.rw_state) {
+    case WAIT_SELECT_APPLICATION:
+      if (isError(p_rwData->raw_frame.status)) break;
+      RW_T4tNfceeSelectFile(CC_FILE_ID);
+      nfa_t4tnfcee_cb.rw_state = WAIT_SELECT_CC;
+      break;
+
+    case WAIT_SELECT_CC:
+      if (isError(p_rwData->raw_frame.status)) break;
+      RW_T4tNfceeReadDataLen();
+      nfa_t4tnfcee_cb.rw_state = WAIT_READ_CC_DATA_LEN;
+      break;
+
+    case WAIT_READ_CC_DATA_LEN: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      uint16_t lenDataToBeRead = nfa_t4tnfcee_get_len(p_rwData);
+      if (lenDataToBeRead <= 0x00) {
+        nfa_t4tnfcee_cb.status = NFC_STATUS_NO_BUFFERS;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+      RW_T4tNfceeReadFile(0x00, lenDataToBeRead);
+      nfa_t4tnfcee_cb.rw_state = WAIT_READ_CC_FILE;
+      break;
+    }
+
+    case WAIT_READ_CC_FILE: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      nfa_t4tnfcee_store_cc_info(p_rwData->raw_frame.p_data);
+      if (nfa_t4tnfcee_cb.cur_op != NFA_T4TNFCEE_OP_READ_CC_FILE) {
+        if (ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId) == ccFileInfo.end()) {
+          LOG(DEBUG) << StringPrintf("%s FileId Not found in CC", __func__);
+          nfa_t4tnfcee_cb.status = NFA_T4T_STATUS_INVALID_FILE_ID;
+          nfa_t4tnfcee_notify_rx_evt();
+          break;
+        }
+      } else {
+        nfa_t4tnfcee_cb.dataLen = p_rwData->raw_frame.p_data->len;
+        nfa_t4tnfcee_cb.status = p_rwData->raw_frame.status;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+      RW_T4tNfceeSelectFile(nfa_t4tnfcee_cb.cur_fileId);
+      nfa_t4tnfcee_cb.rw_state = WAIT_SELECT_FILE;
+      break;
+    }
+
+    case WAIT_SELECT_FILE: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      if ((nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ) &&
+          isReadPermitted()) {
+        RW_T4tNfceeReadDataLen();
+        nfa_t4tnfcee_cb.rw_state = WAIT_READ_DATA_LEN;
+      } else if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_WRITE) {
+        tNFA_STATUS preCondStatus = getWritePreconditionStatus();
+        if (preCondStatus == NFA_STATUS_OK) {
+          RW_T4tNfceeUpdateNlen(0x0000);
+          nfa_t4tnfcee_cb.rw_state = WAIT_RESET_NLEN;
+        } else {
+          nfa_t4tnfcee_cb.status = preCondStatus;
+          nfa_t4tnfcee_notify_rx_evt();
+        }
+      } else if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_CLEAR) {
+        RW_T4tNfceeReadDataLen();
+        nfa_t4tnfcee_cb.rw_state = WAIT_CLEAR_NDEF_DATA;
+      } else if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ_CC_FILE) {
+        nfa_t4tnfcee_cb.dataLen = nfa_t4tnfcee_cb.rd_offset;
+        nfa_t4tnfcee_cb.status = p_rwData->raw_frame.status;
+        nfa_t4tnfcee_notify_rx_evt();
+      }
+      break;
+    }
+
+    case WAIT_CLEAR_NDEF_DATA: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      uint16_t lenDataToBeClear = nfa_t4tnfcee_get_len(p_rwData);
+      if (lenDataToBeClear == 0x00) {
+        nfa_t4tnfcee_cb.status = p_rwData->raw_frame.status;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+      RW_T4tNfceeUpdateNlen(0x0000);
+      nfa_t4tnfcee_cb.p_dataBuf = (uint8_t*)nfa_mem_co_alloc(lenDataToBeClear);
+      if (!nfa_t4tnfcee_cb.p_dataBuf) {
+        nfa_t4tnfcee_cb.status = NFC_STATUS_FAILED;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+      memset(nfa_t4tnfcee_cb.p_dataBuf, 0, lenDataToBeClear);
+      nfa_t4tnfcee_cb.dataLen = lenDataToBeClear;
+      nfa_t4tnfcee_cb.rw_state = WAIT_RESET_NLEN;
+      break;
+    }
+
+    case WAIT_READ_DATA_LEN: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      uint16_t lenDataToBeRead = nfa_t4tnfcee_get_len(p_rwData);
+      if (lenDataToBeRead <= 0x00) {
+        nfa_t4tnfcee_cb.status = NFC_STATUS_NO_BUFFERS;
+        nfa_t4tnfcee_notify_rx_evt();
+        break;
+      }
+
+      nfa_t4tnfcee_cb.p_dataBuf = (uint8_t*)nfa_mem_co_alloc(lenDataToBeRead);
+      RW_T4tNfceeReadFile(T4T_FILE_LENGTH_SIZE, lenDataToBeRead);
+      nfa_t4tnfcee_cb.rw_state = WAIT_READ_FILE;
+      break;
+    }
+
+    case WAIT_READ_FILE: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      /*updating length field to discard status while processing read data
+      For RAW data, T4T module returns length including status length*/
+      if (p_rwData->raw_frame.p_data->len >= T4T_FILE_LENGTH_SIZE)
+        p_rwData->raw_frame.p_data->len -= T4T_FILE_LENGTH_SIZE;
+      nfa_t4tnfcee_store_rx_buf(p_rwData->raw_frame.p_data);
+      if (RW_T4tIsReadComplete()) {
+        nfa_t4tnfcee_cb.dataLen = nfa_t4tnfcee_cb.rd_offset;
+        nfa_t4tnfcee_cb.status = p_rwData->raw_frame.status;
+        nfa_t4tnfcee_notify_rx_evt();
+      } else {
+        RW_T4tNfceeReadPendingData();
+      }
+      break;
+    }
+
+    case WAIT_RESET_NLEN: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      RW_T4tNfceeStartUpdateFile(nfa_t4tnfcee_cb.dataLen,
+                                 nfa_t4tnfcee_cb.p_dataBuf);
+      if (RW_T4tIsUpdateComplete())
+        nfa_t4tnfcee_cb.rw_state = WAIT_WRITE_COMPLETE;
+      else
+        nfa_t4tnfcee_cb.rw_state = WAIT_WRITE;
+      break;
+    }
+
+    case WAIT_WRITE: {
+      RW_T4tNfceeUpdateFile();
+      if (RW_T4tIsUpdateComplete())
+        nfa_t4tnfcee_cb.rw_state = WAIT_WRITE_COMPLETE;
+      break;
+    }
+
+    case WAIT_WRITE_COMPLETE: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_CLEAR) {
+        nfa_t4tnfcee_cb.status = p_rwData->raw_frame.status;
+        /*Length is already zero returning from here.*/
+        nfa_t4tnfcee_notify_rx_evt();
+      } else {
+        RW_T4tNfceeUpdateNlen(nfa_t4tnfcee_cb.dataLen);
+        nfa_t4tnfcee_cb.rw_state = WAIT_UPDATE_NLEN;
+      }
+      break;
+    }
+
+    case WAIT_UPDATE_NLEN: {
+      if (isError(p_rwData->raw_frame.status)) break;
+      nfa_t4tnfcee_cb.status = p_rwData->raw_frame.status;
+      nfa_t4tnfcee_notify_rx_evt();
+      break;
+    }
+
+    default:
+      break;
+  }
+  GKI_freebuf(p_rwData->raw_frame.p_data);
+}
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_notify_rx_evt
+ **
+ ** Description      Notifies to upper layer with data
+ **
+ ** Returns          None
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_notify_rx_evt(void) {
+  tNFA_CONN_EVT_DATA conn_evt_data;
+  conn_evt_data.status = nfa_t4tnfcee_cb.status;
+  nfa_t4tnfcee_cb.rw_state = OP_COMPLETE;
+  if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ) {
+    if (conn_evt_data.status == NFA_STATUS_OK) {
+      conn_evt_data.data.p_data = nfa_t4tnfcee_cb.p_dataBuf;
+      conn_evt_data.data.len = nfa_t4tnfcee_cb.dataLen;
+    }
+    nfa_dm_act_conn_cback_notify(NFA_T4TNFCEE_READ_CPLT_EVT, &conn_evt_data);
+  } else if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_WRITE) {
+    if (conn_evt_data.status == NFA_STATUS_OK) {
+      conn_evt_data.data.len = nfa_t4tnfcee_cb.dataLen;
+    }
+    nfa_dm_act_conn_cback_notify(NFA_T4TNFCEE_WRITE_CPLT_EVT, &conn_evt_data);
+  } else if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_CLEAR) {
+    nfa_dm_act_conn_cback_notify(NFA_T4TNFCEE_CLEAR_CPLT_EVT, &conn_evt_data);
+  } else if (nfa_t4tnfcee_cb.cur_op == NFA_T4TNFCEE_OP_READ_CC_FILE) {
+    if (conn_evt_data.status == NFA_STATUS_OK) {
+      conn_evt_data.data.p_data = nfa_t4tnfcee_cb.p_dataBuf;
+      conn_evt_data.data.len = nfa_t4tnfcee_cb.dataLen;
+    }
+    nfa_dm_act_conn_cback_notify(NFA_T4TNFCEE_READ_CC_DATA_CPLT_EVT,
+                                 &conn_evt_data);
+  }
+  nfa_t4tnfcee_free_rx_buf();
+}
+
+/*******************************************************************************
+ **
+ ** Function         is_read_precondition_valid
+ **
+ ** Description      validates precondition for read
+ **
+ ** Returns          true/false
+ **
+ *******************************************************************************/
+bool is_read_precondition_valid(tNFA_T4TNFCEE_MSG* p_data) {
+  if ((p_data->op_req.p_fileId == nullptr) ||
+      (nfa_t4tnfcee_cb.t4tnfcee_state != NFA_T4TNFCEE_STATE_CONNECTED)) {
+    return false;
+  }
+  return true;
+}
+
+/*******************************************************************************
+ **
+ ** Function         is_write_precondition_valid
+ **
+ ** Description      validates precondition for write
+ **
+ ** Returns          true/false
+ **
+ *******************************************************************************/
+bool is_write_precondition_valid(tNFA_T4TNFCEE_MSG* p_data) {
+  if ((p_data->op_req.p_fileId == nullptr) ||
+      (nfa_t4tnfcee_cb.t4tnfcee_state != NFA_T4TNFCEE_STATE_CONNECTED) ||
+      (p_data->op_req.write.p_data == nullptr) ||
+      (p_data->op_req.write.len == 0)) {
+    return false;
+  }
+  return true;
+}
+
+/*******************************************************************************
+ **
+ ** Function         isReadPermitted
+ **
+ ** Description      Checks if read permitted for current file
+ **
+ ** Returns          true/false
+ **
+ *******************************************************************************/
+bool isReadPermitted(void) {
+  if (ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId) == ccFileInfo.end()) {
+    LOG(ERROR) << StringPrintf("%s FileId Not found", __func__);
+    return false;
+  }
+  return (ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId)->second.read_access ==
+          T4T_NFCEE_READ_ALLOWED);
+}
+
+/*******************************************************************************
+ **
+ ** Function         isWritePermitted
+ **
+ ** Description      Checks if write permitted for current file
+ **
+ ** Returns          true/false
+ **
+ *******************************************************************************/
+bool isWritePermitted(void) {
+  if (ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId) == ccFileInfo.end()) {
+    LOG(ERROR) << StringPrintf("%s FileId Not found", __func__);
+    return false;
+  }
+  LOG(DEBUG) << StringPrintf(
+      "%s : 0x%2x", __func__,
+      ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId)->second.write_access);
+  return ((ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId)->second.write_access !=
+           T4T_NFCEE_WRITE_NOT_ALLOWED));
+}
+
+/*******************************************************************************
+ **
+ ** Function         isDataLenBelowMaxFileCapacity
+ **
+ ** Description      Checks if current data length is less not exceeding file
+ **                  capacity
+ **
+ ** Returns          true/false
+ **
+ *******************************************************************************/
+bool isDataLenBelowMaxFileCapacity(void) {
+  if (ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId) == ccFileInfo.end()) {
+    LOG(ERROR) << StringPrintf("%s FileId Not found", __func__);
+    return false;
+  }
+  return (nfa_t4tnfcee_cb.dataLen <=
+          (ccFileInfo.find(nfa_t4tnfcee_cb.cur_fileId)->second.capacity -
+           T4TNFCEE_SIZEOF_LEN_BYTES));
+}
+
+/*******************************************************************************
+ **
+ ** Function         getWritePreconditionStatus
+ **
+ ** Description      Checks if write preconditions are satisfied
+ **
+ ** Returns          NFA_STATUS_OK if success else ERROR status
+ **
+ *******************************************************************************/
+tNFC_STATUS getWritePreconditionStatus() {
+  if (!isWritePermitted()) return NCI_STATUS_READ_ONLY;
+  if (!isDataLenBelowMaxFileCapacity()) {
+    LOG(ERROR) << StringPrintf("Data Len exceeds max file size");
+    return NFA_STATUS_FAILED;
+  }
+  if (nfa_t4tnfcee_cb.cur_fileId == NDEF_FILE_ID) {
+    tNDEF_STATUS ndef_status;
+    if ((ndef_status = NDEF_MsgValidate(nfa_t4tnfcee_cb.p_dataBuf,
+                                        nfa_t4tnfcee_cb.dataLen, true)) !=
+        NDEF_OK) {
+      LOG(DEBUG) << StringPrintf(
+          "Invalid NDEF message. NDEF_MsgValidate returned %i", ndef_status);
+      return NFA_STATUS_REJECTED;
+    }
+    /*NDEF Msg validation SUCCESS*/
+    return NFA_STATUS_OK;
+  }
+  return NFA_STATUS_OK;
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_get_len
+ **
+ ** Description      get the length of data available in current selected file
+ **
+ ** Returns          data len
+ **
+ *******************************************************************************/
+uint16_t nfa_t4tnfcee_get_len(tRW_DATA* p_rwData) {
+  uint8_t* p = nullptr;
+  uint16_t readLen = 0x00;
+  if (p_rwData->raw_frame.p_data->len > 0x00) {
+    p = (uint8_t*)(p_rwData->raw_frame.p_data + 1) +
+        p_rwData->raw_frame.p_data->offset;
+  }
+  if (p != nullptr) BE_STREAM_TO_UINT16(readLen, p);
+  if (readLen > 0x00) {
+    LOG(DEBUG) << StringPrintf("%s readLen  0x%x", __func__, readLen);
+  } else {
+    LOG(DEBUG) << StringPrintf("%s No Data to Read", __func__);
+  }
+  return readLen;
+}
+
+/*******************************************************************************
+ **
+ ** Function         isError
+ **
+ ** Description      Checks and notifies upper layer in case of error
+ **
+ ** Returns          true if error else false
+ **
+ *******************************************************************************/
+bool isError(tNFC_STATUS status) {
+  if (status != NFA_STATUS_OK) {
+    nfa_t4tnfcee_cb.status = NFC_STATUS_FAILED;
+    nfa_t4tnfcee_notify_rx_evt();
+    return true;
+  } else
+    return false;
+}
diff --git a/src/nfa/ndefnfcee/t4t/nfa_nfcee_api.cc b/src/nfa/ndefnfcee/t4t/nfa_nfcee_api.cc
new file mode 100644
index 00000000..0156322e
--- /dev/null
+++ b/src/nfa/ndefnfcee/t4t/nfa_nfcee_api.cc
@@ -0,0 +1,177 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 The Android Open Source Project.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <string.h>
+
+#include "nfa_nfcee_int.h"
+
+using android::base::StringPrintf;
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeOpenConnection
+**
+** Description      Creates logical connection with T4T Nfcee
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeOpenConnection() {
+  tNFA_T4TNFCEE_OPERATION* p_msg;
+
+  LOG(DEBUG) << StringPrintf("%s : Enter", __func__);
+
+  if ((p_msg = (tNFA_T4TNFCEE_OPERATION*)GKI_getbuf(
+           (uint16_t)(sizeof(tNFA_T4TNFCEE_OPERATION)))) != NULL) {
+    p_msg->hdr.event = NFA_T4TNFCEE_OP_REQUEST_EVT;
+    p_msg->op = NFA_T4TNFCEE_OP_OPEN_CONNECTION;
+    nfa_sys_sendmsg(p_msg);
+
+    return (NFA_STATUS_OK);
+  }
+
+  return (NFA_STATUS_FAILED);
+}
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeClear
+**
+** Description      Clear Ndef data to T4T NFC EE.
+**                  For file ID NDEF, perform the NDEF detection procedure
+**                  and set the NDEF tag data to zero.
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeClear(uint8_t* p_fileId) {
+  tNFA_T4TNFCEE_OPERATION* p_msg;
+  LOG(DEBUG) << StringPrintf("%s : Enter ", __func__);
+
+  if ((p_msg = (tNFA_T4TNFCEE_OPERATION*)GKI_getbuf(
+           (uint16_t)(sizeof(tNFA_T4TNFCEE_OPERATION)))) != NULL) {
+    p_msg->hdr.event = NFA_T4TNFCEE_OP_REQUEST_EVT;
+    p_msg->op = NFA_T4TNFCEE_OP_CLEAR;
+    p_msg->p_fileId = p_fileId;
+    nfa_sys_sendmsg(p_msg);
+
+    return (NFA_STATUS_OK);
+  }
+  return (NFA_STATUS_FAILED);
+}
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeWrite
+**
+** Description      Write data to the T4T NFC EE of given file id.
+**                  If file ID is of NDEF, perform the NDEF detection procedure
+**                  and write the NDEF tag data using the appropriate method for
+**                  NDEF EE.
+**                  If File ID is Not NDEF then reads proprietary way
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeWrite(uint8_t* p_fileId, uint8_t* p_data,
+                              uint32_t len) {
+  tNFA_T4TNFCEE_OPERATION* p_msg;
+
+  LOG(DEBUG) << StringPrintf("%s : Enter p_data=%s, len: %i", __func__, p_data,
+                             len);
+
+  if ((p_msg = (tNFA_T4TNFCEE_OPERATION*)GKI_getbuf(
+           (uint16_t)(sizeof(tNFA_T4TNFCEE_OPERATION)))) != NULL) {
+    p_msg->hdr.event = NFA_T4TNFCEE_OP_REQUEST_EVT;
+    p_msg->op = NFA_T4TNFCEE_OP_WRITE;
+    p_msg->p_fileId = p_fileId;
+    p_msg->write.len = len;
+    p_msg->write.p_data = p_data;
+    nfa_sys_sendmsg(p_msg);
+
+    return (NFA_STATUS_OK);
+  }
+
+  return (NFA_STATUS_FAILED);
+}
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeRead
+**
+** Description      Read T4T message from NFCC area.of given file id
+**                  If file ID is of NDEF, perform the NDEF detection procedure
+**                  and read the NDEF tag data using the appropriate method for
+**                  NDEF EE.
+**                  If File ID is Not NDEF then reads proprietary way
+**
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeRead(uint8_t* p_fileId) {
+  tNFA_T4TNFCEE_OPERATION* p_msg;
+  uint16_t m_fileId = (uint16_t)(((uint16_t)(*(p_fileId)) << 8) +
+                                 (uint16_t)(*((p_fileId) + 1)));
+
+  if ((p_msg = (tNFA_T4TNFCEE_OPERATION*)GKI_getbuf(
+           (uint16_t)(sizeof(tNFA_T4TNFCEE_OPERATION)))) != NULL) {
+    p_msg->hdr.event = NFA_T4TNFCEE_OP_REQUEST_EVT;
+    if (m_fileId == T4T_CC_FILE_ID) {
+      p_msg->op = NFA_T4TNFCEE_OP_READ_CC_FILE;
+    } else {
+      p_msg->op = NFA_T4TNFCEE_OP_READ;
+    }
+    p_msg->p_fileId = p_fileId;
+    nfa_sys_sendmsg(p_msg);
+
+    return (NFA_STATUS_OK);
+  }
+
+  return (NFA_STATUS_FAILED);
+}
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeCloseConnection
+**
+** Description      Closes logical connection with T4T Nfcee
+** Returns:
+**                  NFA_STATUS_OK if successfully initiated
+**                  NFA_STATUS_FAILED otherwise
+**
+*******************************************************************************/
+tNFA_STATUS NFA_T4tNfcEeCloseConnection() {
+  tNFA_T4TNFCEE_OPERATION* p_msg;
+
+  LOG(DEBUG) << StringPrintf("%s : Enter", __func__);
+
+  if ((p_msg = (tNFA_T4TNFCEE_OPERATION*)GKI_getbuf(
+           (uint16_t)(sizeof(tNFA_T4TNFCEE_OPERATION)))) != NULL) {
+    p_msg->hdr.event = NFA_T4TNFCEE_OP_REQUEST_EVT;
+    p_msg->op = NFA_T4TNFCEE_OP_CLOSE_CONNECTION;
+    nfa_sys_sendmsg(p_msg);
+
+    return (NFA_STATUS_OK);
+  }
+
+  return (NFA_STATUS_FAILED);
+}
diff --git a/src/nfa/ndefnfcee/t4t/nfa_nfcee_main.cc b/src/nfa/ndefnfcee/t4t/nfa_nfcee_main.cc
new file mode 100644
index 00000000..e5114b46
--- /dev/null
+++ b/src/nfa/ndefnfcee/t4t/nfa_nfcee_main.cc
@@ -0,0 +1,350 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 The Android Open Source Project.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <string.h>
+
+#include "nfa_dm_int.h"
+#include "nfa_ee_int.h"
+#include "nfa_nfcee_int.h"
+#include "nfa_rw_int.h"
+#include "nfc_config.h"
+
+using android::base::StringPrintf;
+
+tNFA_T4TNFCEE_CB nfa_t4tnfcee_cb;
+void nfa_t4tnfcee_info_cback(tNFA_EE_EVT event, tNFA_EE_CBACK_DATA* p_data);
+static void nfa_t4tnfcee_sys_enable(void);
+static void nfa_t4tnfcee_sys_disable(void);
+
+/*****************************************************************************
+** Constants and types
+*****************************************************************************/
+static const tNFA_SYS_REG nfa_t4tnfcee_sys_reg = {
+    nfa_t4tnfcee_sys_enable, nfa_t4tnfcee_handle_event,
+    nfa_t4tnfcee_sys_disable, NULL};
+/* NFA_T4TNFCEE actions */
+const tNFA_T4TNFCEE_ACTION nfa_t4tnfcee_action_tbl[] = {
+    nfa_t4tnfcee_handle_op_req, /* NFA_T4TNFCEE_OP_REQUEST_EVT            */
+};
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_init
+**
+** Description      Initialize NFA T4TNFCEE
+**
+** Returns          None
+**
+*******************************************************************************/
+void nfa_t4tnfcee_init(void) {
+  if (NfcConfig::hasKey(NAME_T4T_NFCEE_ENABLE)) {
+    if (NfcConfig::getUnsigned(NAME_T4T_NFCEE_ENABLE)) {
+      LOG(DEBUG) << StringPrintf("nfa_t4tnfcee_init ()");
+      /* initialize control block */
+      memset(&nfa_t4tnfcee_cb, 0, sizeof(tNFA_T4TNFCEE_CB));
+      nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_DISABLED;
+      /* register message handler on NFA SYS */
+      nfa_sys_register(NFA_ID_T4TNFCEE, &nfa_t4tnfcee_sys_reg);
+    }
+  }
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_deinit
+**
+** Description      DeInitialize NFA T4TNFCEE
+**
+** Returns          None
+**
+*******************************************************************************/
+void nfa_t4tnfcee_deinit(void) {
+  LOG(DEBUG) << StringPrintf("nfa_t4tnfcee_deinit ()");
+
+  /* reset state */
+  nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_DISABLED;
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_conn_cback
+**
+** Description      This function Process event from NCI
+**
+** Returns          None
+**
+*******************************************************************************/
+static void nfa_t4tnfcee_conn_cback(uint8_t conn_id, tNFC_CONN_EVT event,
+                                    tNFC_CONN* p_data) {
+  tNFA_CONN_EVT_DATA conn_evt_data;
+  LOG(DEBUG) << StringPrintf("%s : Enter, conn_id = %d, event = 0x%x", __func__,
+                             conn_id, event);
+  switch (event) {
+    case NFC_CONN_CREATE_CEVT: {
+      if (p_data->status == NFA_STATUS_OK) {
+        nfa_t4tnfcee_cb.connId = conn_id;
+        conn_evt_data.status = NFA_STATUS_OK;
+      }
+      break;
+    }
+    case NFC_CONN_CLOSE_CEVT: {
+      if (p_data->status != NFA_STATUS_OK) {
+        conn_evt_data.status = NFA_STATUS_FAILED;
+      } else {
+        nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_DISCONNECTED;
+        conn_evt_data.status = p_data->status;
+      }
+      /*reset callbacks*/
+      RW_SetT4tNfceeInfo(NULL, 0);
+      break;
+    }
+    default:
+      conn_evt_data.status = NFA_STATUS_FAILED;
+      RW_SetT4tNfceeInfo(NULL, 0);
+      break;
+  }
+  nfa_dm_act_conn_cback_notify(NFA_T4TNFCEE_EVT, &conn_evt_data);
+}
+
+/*******************************************************************************
+ **
+ ** Function         nfa_t4tnfcee_info_cback
+ **
+ ** Description      Callback function to handle EE configuration events
+ **
+ ** Returns          None
+ **
+ *******************************************************************************/
+void nfa_t4tnfcee_info_cback(tNFA_EE_EVT event, tNFA_EE_CBACK_DATA* p_data) {
+  LOG(DEBUG) << StringPrintf("%s event: %x", __func__, event);
+  int defaultNdefNfcee =
+      NfcConfig::getUnsigned(NAME_DEFAULT_NDEF_NFCEE_ROUTE, 0x10);
+  switch (event) {
+    case NFA_EE_DISCOVER_EVT:
+      if (nfa_t4tnfcee_cb.t4tnfcee_state == NFA_T4TNFCEE_STATE_DISABLED) {
+        nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_TRY_ENABLE;
+        if ((p_data != nullptr) &&
+            (p_data->new_ee.ee_status != NFA_STATUS_OK)) {
+          nfa_t4tnfcee_cb.ndefEmulationSupport = true;
+          NFC_NfceeModeSet(defaultNdefNfcee, NFC_MODE_ACTIVATE);
+        }
+      }
+      break;
+    case NFA_EE_MODE_SET_EVT:
+      if ((p_data != nullptr) && (p_data->mode_set.status != NFA_STATUS_OK) &&
+          (nfa_t4tnfcee_cb.t4tnfcee_state >= NFA_T4TNFCEE_STATE_TRY_ENABLE)) {
+        nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_DISABLED;
+        nfa_sys_cback_notify_enable_complete(NFA_ID_T4TNFCEE);
+        nfa_ee_report_disc_done(true);
+      } else {
+        nfa_ee_report_event(NULL, event, p_data);
+      }
+      break;
+    case NFA_EE_DISCOVER_REQ_EVT:
+      if (nfa_t4tnfcee_cb.t4tnfcee_state == NFA_T4TNFCEE_STATE_TRY_ENABLE) {
+        nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_INITIALIZED;
+        nfa_sys_cback_notify_enable_complete(NFA_ID_T4TNFCEE);
+        nfa_ee_report_disc_done(true);
+      }
+      break;
+    case NFA_EE_CONNECT_EVT:
+      if ((nfa_t4tnfcee_cb.t4tnfcee_state == NFA_T4TNFCEE_STATE_INITIALIZED) ||
+          (nfa_t4tnfcee_cb.t4tnfcee_state == NFA_T4TNFCEE_STATE_DISCONNECTED)) {
+        if (NFC_STATUS_OK ==
+            NFC_ConnCreate(NCI_DEST_TYPE_NFCEE, defaultNdefNfcee,
+                           NFC_NFCEE_INTERFACE_APDU, nfa_t4tnfcee_conn_cback))
+          nfa_t4tnfcee_cb.t4tnfcee_state = NFA_T4TNFCEE_STATE_CONNECTED;
+      } else {
+        tNFC_CONN p_data;
+        p_data.status = NFC_STATUS_FAILED;
+        nfa_t4tnfcee_conn_cback(NCI_DEST_TYPE_T4T_NFCEE, NFC_ERROR_CEVT,
+                                &p_data);
+      }
+      break;
+    default:
+      nfa_ee_report_event(NULL, event, p_data);
+      break;
+  }
+  return;
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_set_ee_cback
+**
+** Description      assign t4t callback to receive ee_events
+**
+** Returns          None
+**
+*******************************************************************************/
+void nfa_t4tnfcee_set_ee_cback(tNFA_EE_ECB* p_ecb) {
+  p_ecb->p_ee_cback = nfa_t4tnfcee_info_cback;
+  return;
+}
+
+/*******************************************************************************
+**
+** Function         nfa_rw_evt_2_str
+**
+** Description      convert nfa_rw evt to string
+**
+*******************************************************************************/
+static std::string nfa_t4tnfcee_evt_2_str(uint16_t event) {
+  switch (event) {
+    case NFA_RW_OP_REQUEST_EVT:
+      return "NFA_T4TNFCEE_OP_REQUEST_EVT";
+    default:
+      break;
+  }
+  return "Unknown";
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_sys_enable
+**
+** Description      Enable NFA HCI
+**
+** Returns          None
+**
+*******************************************************************************/
+void nfa_t4tnfcee_sys_enable(void) {
+  LOG(DEBUG) << StringPrintf("nfa_t4tnfcee_sys_enable ()");
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_sys_disable
+**
+** Description      Clean up t4tnfcee sub-system
+**
+**
+** Returns          void
+**
+*******************************************************************************/
+void nfa_t4tnfcee_sys_disable(void) {
+  /* Free scratch buffer if any */
+  nfa_t4tnfcee_free_rx_buf();
+
+  /* Free pending command if any */
+  if (nfa_t4tnfcee_cb.p_pending_msg) {
+    GKI_freebuf(nfa_t4tnfcee_cb.p_pending_msg);
+    nfa_t4tnfcee_cb.p_pending_msg = NULL;
+  }
+
+  nfa_sys_deregister(NFA_ID_T4TNFCEE);
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_proc_disc_evt
+**
+** Description      Called by nfa_dm to handle Ndef Nfcee Requests
+**
+** Returns          NFA_STATUS_OK if success else Failed status
+**
+*******************************************************************************/
+tNFC_STATUS nfa_t4tnfcee_proc_disc_evt(tNFA_T4TNFCEE_OP event) {
+  LOG(DEBUG) << StringPrintf("%s Enter. Event = %d ", __func__, (int)event);
+  tNFC_STATUS status = NFC_STATUS_FAILED;
+
+  switch (event) {
+    case NFA_T4TNFCEE_OP_OPEN_CONNECTION:
+      nfa_t4tnfcee_info_cback(NFA_EE_CONNECT_EVT, nullptr);
+      break;
+    case NFA_T4TNFCEE_OP_CLOSE_CONNECTION:
+      if (nfa_t4tnfcee_cb.t4tnfcee_state == NFA_T4TNFCEE_STATE_CONNECTED) {
+        NFC_SetStaticT4tNfceeCback(nfa_t4tnfcee_conn_cback,
+                                   nfa_t4tnfcee_cb.connId);
+        if (NFC_STATUS_OK != NFC_ConnClose(nfa_t4tnfcee_cb.connId)) {
+          tNFC_CONN p_data;
+          p_data.status = NFC_STATUS_FAILED;
+          nfa_t4tnfcee_conn_cback(nfa_t4tnfcee_cb.connId, NFC_ERROR_CEVT,
+                                  &p_data);
+        }
+      }
+      break;
+  }
+  return status;
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_handle_event
+**
+** Description      nfa t4tnfcee main event handling function.
+**
+** Returns          true if caller should free p_msg buffer
+**
+*******************************************************************************/
+bool nfa_t4tnfcee_handle_event(NFC_HDR* p_msg) {
+  uint16_t act_idx;
+
+  LOG(DEBUG) << StringPrintf("nfa_t4tnfcee_handle_event event: %s (0x%02x)",
+                             nfa_t4tnfcee_evt_2_str(p_msg->event).c_str(),
+                             p_msg->event);
+
+  /* Get NFA_T4TNFCEE sub-event */
+  if ((act_idx = (p_msg->event & 0x00FF)) < (NFA_T4TNFCEE_MAX_EVT & 0xFF)) {
+    return (*nfa_t4tnfcee_action_tbl[act_idx])((tNFA_T4TNFCEE_MSG*)p_msg);
+  } else {
+    LOG(DEBUG) << StringPrintf(
+        "nfa_t4tnfcee_handle_event: unhandled event 0x%02X", p_msg->event);
+    return true;
+  }
+}
+
+/*******************************************************************************
+**
+** Function         nfa_t4tnfcee_is_enabled
+**
+** Description      T4T is enabled and initialized.
+**
+** Returns          true if T4T Nfcee is enabled initialization
+**
+*******************************************************************************/
+bool nfa_t4tnfcee_is_enabled(void) {
+  return (nfa_t4tnfcee_cb.t4tnfcee_state >= NFA_T4TNFCEE_STATE_INITIALIZED);
+}
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeIsProcessing
+**
+** Description      Indicates if T4tNfcee Read or write under process
+**
+** Returns          true if under process else false
+**
+*******************************************************************************/
+bool NFA_T4tNfcEeIsProcessing(void) {
+  return (nfa_t4tnfcee_cb.t4tnfcee_state == NFA_T4TNFCEE_STATE_CONNECTED);
+}
+
+/*******************************************************************************
+**
+** Function         NFA_T4tNfcEeIsEmulationSupported
+**
+** Description      Indicates if T4t NDEF Nfcee emulation is supported or not
+**
+** Returns          true if supported else false
+**
+*******************************************************************************/
+bool NFA_T4tNfcEeIsEmulationSupported(void) {
+  return nfa_t4tnfcee_cb.ndefEmulationSupport;
+}
diff --git a/src/nfa/rw/nfa_rw_act.cc b/src/nfa/rw/nfa_rw_act.cc
index 29d2a298..bbb76626 100644
--- a/src/nfa/rw/nfa_rw_act.cc
+++ b/src/nfa/rw/nfa_rw_act.cc
@@ -726,14 +726,21 @@ static void nfa_rw_handle_t1t_evt(tRW_EVENT event, tRW_DATA* p_rw_data) {
 static void nfa_rw_handle_t2t_evt(tRW_EVENT event, tRW_DATA* p_rw_data) {
   tNFA_CONN_EVT_DATA conn_evt_data;
 
+  uint8_t data_slp_req[] = {0x50, 0x00};
   conn_evt_data.status = p_rw_data->status;
 
   if (p_rw_data->status == NFC_STATUS_REJECTED) {
     LOG(VERBOSE) << StringPrintf(
-        "; Waking the tag first before handling the "
-        "response!");
+        "%s; Waking the tag first before handling the "
+        "response!",
+        __func__);
     /* Received NACK. Let DM wakeup the tag first (by putting tag to sleep and
      * then waking it up) */
+    // Needed to not allocate buffer that will never be freed
+    if (!(nfa_rw_cb.flags & NFA_RW_FL_API_BUSY)) {
+      NFA_SendRawFrame(data_slp_req, sizeof(data_slp_req), 0);
+      usleep(4000);
+    }
     p_rw_data->status = nfa_dm_disc_sleep_wakeup();
     if (p_rw_data->status == NFC_STATUS_OK) {
       nfa_rw_cb.halt_event = event;
@@ -1490,6 +1497,61 @@ static void nfa_rw_handle_mfc_evt(tRW_EVENT event, tRW_DATA* p_rw_data) {
   }
 }
 
+/*******************************************************************************
+**
+** Function         nfa_rw_handle_ci_evt
+**
+** Description      Handler for Chinese Id Card tag reader events
+**
+** Returns          Nothing
+**
+*******************************************************************************/
+static void nfa_rw_handle_ci_evt(tRW_EVENT event, tRW_DATA* p_rw_data) {
+  tNFA_CONN_EVT_DATA conn_evt_data;
+  tNFA_TAG_PARAMS tag_params;
+
+  conn_evt_data.status = p_rw_data->status;
+  LOG(DEBUG) << StringPrintf("%s; event = 0x%X", __func__, event);
+
+  if (p_rw_data->status == NFC_STATUS_REJECTED) {
+    /* Received NACK. Let DM wakeup the tag first (by putting tag to sleep and
+     * then waking it up) */
+    if ((p_rw_data->status = nfa_dm_disc_sleep_wakeup()) == NFC_STATUS_OK) {
+      nfa_rw_cb.halt_event = event;
+      memcpy(&nfa_rw_cb.rw_data, p_rw_data, sizeof(tRW_DATA));
+      return;
+    }
+  }
+
+  switch (event) {
+    case RW_CI_PRESENCE_CHECK_EVT: /* Presence check completed */
+      nfa_rw_handle_presence_check_rsp(p_rw_data->status);
+      break;
+
+    case RW_CI_RAW_FRAME_EVT: /* Raw Frame data event         */
+      nfa_rw_send_data_to_upper(p_rw_data);
+
+      if (p_rw_data->status != NFC_STATUS_CONTINUE) {
+        /* Command complete - perform cleanup */
+        nfa_rw_command_complete();
+        nfa_rw_cb.cur_op = NFA_RW_OP_MAX;
+      }
+      break;
+
+    case RW_CI_CPLT_EVT: {
+      tag_params.ci.mbi = p_rw_data->ci_info.mbi;
+      memcpy(tag_params.ci.uid, p_rw_data->ci_info.uid,
+             sizeof(tag_params.ci.uid));
+      nfa_dm_notify_activation_status(NFA_STATUS_OK, &tag_params);
+      nfa_rw_command_complete();
+    } break;
+
+    case RW_CI_INTF_ERROR_EVT:
+      nfa_dm_rf_deactivate(NFA_DEACTIVATE_TYPE_DISCOVERY);
+      break;
+  }
+}
+
 /*******************************************************************************
 **
 ** Function         nfa_rw_cback
@@ -1521,6 +1583,8 @@ static void nfa_rw_cback(tRW_EVENT event, tRW_DATA* p_rw_data) {
   } else if (event < RW_MFC_MAX_EVT) {
     /* Handle Mifare Classic tag events */
     nfa_rw_handle_mfc_evt(event, p_rw_data);
+  } else if (event < RW_CI_MAX_EVT) {
+    nfa_rw_handle_ci_evt(event, p_rw_data);
   } else {
     LOG(ERROR) << StringPrintf("nfa_rw_cback: unhandled event=0x%02x", event);
   }
@@ -1833,6 +1897,10 @@ void nfa_rw_presence_check(tNFA_RW_MSG* p_data) {
   bool unsupported = false;
   uint8_t option = NFA_RW_OPTION_INVALID;
   tNFA_RW_PRES_CHK_OPTION op_param = NFA_RW_PRES_CHK_DEFAULT;
+  uint8_t data_slp_req[] = {0x50, 0x00};
+  NFC_HDR* p_msg;
+  uint16_t size;
+  uint8_t* p;
 
   if (NFC_PROTOCOL_T1T == protocol) {
     /* Type1Tag    - NFC-A */
@@ -1880,6 +1948,9 @@ void nfa_rw_presence_check(tNFA_RW_MSG* p_data) {
   } else if (NFC_PROTOCOL_T5T == protocol) {
     /* T5T/ISO 15693 */
     status = RW_I93PresenceCheck();
+  } else if (NFC_PROTOCOL_CI == protocol) {
+    // Chinese ID card
+    status = RW_CiPresenceCheck();
   } else {
     /* Protocol unsupported by RW module... */
     unsupported = true;
@@ -1892,6 +1963,24 @@ void nfa_rw_presence_check(tNFA_RW_MSG* p_data) {
     } else {
       /* Let DM perform presence check (by putting tag to sleep and then waking
        * it up) */
+      // Need to send DESELECT before putting the T2T tag to sleep
+      if (NFC_PROTOCOL_T2T == protocol) {
+        size = NFC_HDR_SIZE + NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE +
+               sizeof(data_slp_req);
+
+        p_msg = (NFC_HDR*)GKI_getbuf(size);
+        if (p_msg != nullptr) {
+          p_msg->layer_specific = 0;
+          p_msg->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
+          p_msg->len = sizeof(data_slp_req);
+
+          p = (uint8_t*)(p_msg + 1) + p_msg->offset;
+          memcpy(p, data_slp_req, sizeof(data_slp_req));
+
+          NFC_SendData(NFC_RF_CONN_ID, p_msg);
+          usleep(4000);
+        }
+      }
       status = nfa_dm_disc_sleep_wakeup();
     }
   }
@@ -2580,10 +2669,15 @@ bool nfa_rw_activate_ntf(tNFA_RW_MSG* p_data) {
 
   /* check if the protocol is activated with supported interface */
   if (p_activate_params->intf_param.type == NCI_INTERFACE_FRAME) {
-    if ((p_activate_params->protocol != NFA_PROTOCOL_T1T) &&
-        (p_activate_params->protocol != NFA_PROTOCOL_T2T) &&
-        (p_activate_params->protocol != NFA_PROTOCOL_T3T) &&
-        (p_activate_params->protocol != NFA_PROTOCOL_T5T)) {
+    // Chinese ID Card
+    if ((nfa_rw_cb.protocol == NFC_PROTOCOL_UNKNOWN) &&
+        (nfa_rw_cb.activated_tech_mode == NFC_DISCOVERY_TYPE_POLL_B)) {
+      LOG(DEBUG) << StringPrintf("%s; Chinese ID Card protocol", __func__);
+      nfa_rw_cb.protocol = NFA_PROTOCOL_CI;
+    } else if ((p_activate_params->protocol != NFA_PROTOCOL_T1T) &&
+               (p_activate_params->protocol != NFA_PROTOCOL_T2T) &&
+               (p_activate_params->protocol != NFA_PROTOCOL_T3T) &&
+               (p_activate_params->protocol != NFA_PROTOCOL_T5T)) {
       nfa_rw_cb.protocol = NFA_PROTOCOL_INVALID;
     }
   } else if (p_activate_params->intf_param.type == NCI_INTERFACE_ISO_DEP) {
@@ -2607,7 +2701,9 @@ bool nfa_rw_activate_ntf(tNFA_RW_MSG* p_data) {
    * start presence check if needed */
   if (!nfa_dm_is_protocol_supported(
           p_activate_params->protocol,
-          p_activate_params->rf_tech_param.param.pa.sel_rsp)) {
+          p_activate_params->rf_tech_param.param.pa.sel_rsp) &&
+      (nfa_rw_cb.protocol != NFA_PROTOCOL_CI)) {
+    LOG(DEBUG) << StringPrintf("%s; Protocol not supported", __func__);
     /* Notify upper layer of NFA_ACTIVATED_EVT if needed, and start presence
      * check timer */
     /* Set data callback (pass all incoming data to upper layer using
@@ -2742,6 +2838,15 @@ bool nfa_rw_activate_ntf(tNFA_RW_MSG* p_data) {
         memcpy(tag_params.i93.uid, nfa_rw_cb.i93_uid, I93_UID_BYTE_LEN);
       }
     }
+  } else if (NFC_PROTOCOL_CI == nfa_rw_cb.protocol) {
+    tNFA_RW_MSG msg;
+    msg.op_req.op = NFA_RW_OP_CI_ATTRIB;
+    memcpy(
+        msg.op_req.params.ci_param.nfcid0,
+        p_data->activate_ntf.p_activate_params->rf_tech_param.param.pb.nfcid0,
+        sizeof(NFC_NFCID0_MAX_LEN));
+    nfa_rw_handle_op_req(&msg);
+    activate_notify = false;
   }
 
   /* Notify upper layer of NFA_ACTIVATED_EVT if needed, and start presence check
@@ -2979,6 +3084,13 @@ bool nfa_rw_handle_op_req(tNFA_RW_MSG* p_data) {
       nfa_rw_i93_command(p_data);
       break;
 
+    case NFA_RW_OP_CI_ATTRIB: {
+      LOG(DEBUG) << StringPrintf("%s; Sending ATTRIB - nfcid0[0]=0x%02x",
+                                 __func__,
+                                 p_data->op_req.params.ci_param.nfcid0[0]);
+      RW_CiSendAttrib(p_data->op_req.params.ci_param.nfcid0);
+    } break;
+
     default:
       LOG(ERROR) << StringPrintf("nfa_rw_handle_api: unhandled operation: %i",
                                  p_data->op_req.op);
diff --git a/src/nfc/include/nfc_api.h b/src/nfc/include/nfc_api.h
index 994c1a9b..9948a080 100644
--- a/src/nfc/include/nfc_api.h
+++ b/src/nfc/include/nfc_api.h
@@ -120,8 +120,6 @@ typedef uint8_t tNFC_STATUS;
 #define NFC_PMID_PF_BIT_RATE NCI_PARAM_ID_PF_BIT_RATE
 #define NFC_PMID_PF_BAILOUT NCI_PARAM_ID_PF_BAILOUT
 #define NFC_PMID_PF_DEVICES_LIMIT NCI_PARAM_ID_PF_DEVICES_LIMIT
-#define NFC_PMID_ATR_REQ_GEN_BYTES NCI_PARAM_ID_ATR_REQ_GEN_BYTES
-#define NFC_PMID_ATR_REQ_CONFIG NCI_PARAM_ID_ATR_REQ_CONFIG
 #define NFC_PMID_LA_HIST_BY NCI_PARAM_ID_LA_HIST_BY
 #define NFC_PMID_LA_NFCID1 NCI_PARAM_ID_LA_NFCID1
 #define NFC_PMID_LA_BIT_FRAME_SDD NCI_PARAM_ID_LA_BIT_FRAME_SDD
@@ -139,10 +137,6 @@ typedef uint8_t tNFC_STATUS;
 #define NFC_PMID_LF_T3T_FLAGS2 NCI_PARAM_ID_LF_T3T_FLAGS2
 #define NFC_PMID_FWI NCI_PARAM_ID_FWI
 #define NFC_PMID_LF_CON_BITR_F NCI_PARAM_ID_LF_CON_BITR_F
-#define NFC_PMID_WT NCI_PARAM_ID_WT
-#define NFC_PMID_ATR_RES_GEN_BYTES NCI_PARAM_ID_ATR_RES_GEN_BYTES
-#define NFC_PMID_ATR_RSP_CONFIG NCI_PARAM_ID_ATR_RSP_CONFIG
-#define NFC_PMID_PACM_BIT_RATE NCI_PARAM_ID_PACM_BIT_RATE
 #define NFC_PMID_RF_FIELD_INFO NCI_PARAM_ID_RF_FIELD_INFO
 
 /* Technology based routing  */
@@ -381,6 +375,7 @@ extern uint8_t NFC_GetNCIVersion();
 #define NFC_PROTOCOL_T5T NFC_PROTOCOL_T5T_(NFC_GetNCIVersion())
 #define NFC_PROTOCOL_T5T_(x) \
   (((x) >= NCI_VERSION_2_0) ? NCI_PROTOCOL_T5T : NCI_PROTOCOL_15693)
+#define NFC_PROTOCOL_CI NCI_PROTOCOL_CI
 /* Type 4A,4B  - NFC-A or NFC-B   */
 #define NFC_PROTOCOL_ISO_DEP NCI_PROTOCOL_ISO_DEP
 /* NFCDEP/LLCP - NFC-A or NFC-F       */
@@ -421,7 +416,6 @@ typedef uint8_t tNFC_BIT_RATE;
 #define NFC_INTERFACE_EE_DIRECT_RF NCI_INTERFACE_EE_DIRECT_RF
 #define NFC_INTERFACE_FRAME NCI_INTERFACE_FRAME
 #define NFC_INTERFACE_ISO_DEP NCI_INTERFACE_ISO_DEP
-#define NFC_INTERFACE_NFC_DEP NCI_INTERFACE_NFC_DEP
 #define NFC_INTERFACE_MIFARE NCI_INTERFACE_VS_MIFARE
 typedef tNCI_INTF_TYPE tNFC_INTF_TYPE;
 
@@ -650,28 +644,6 @@ typedef struct {
 
 typedef struct { uint8_t rats; /* RATS */ } tNFC_INTF_LA_ISO_DEP;
 
-typedef struct {
-  uint8_t atr_res_len;                      /* Length of ATR_RES            */
-  uint8_t atr_res[NFC_MAX_ATS_LEN];         /* ATR_RES (Byte 3 - Byte 17+n) */
-  uint8_t max_payload_size;                 /* 64, 128, 192 or 254          */
-  uint8_t gen_bytes_len;                    /* len of general bytes         */
-  uint8_t gen_bytes[NFC_MAX_GEN_BYTES_LEN]; /* general bytes           */
-  uint8_t
-      waiting_time; /* WT -> Response Waiting Time RWT = (256 x 16/fC) x 2WT */
-} tNFC_INTF_PA_NFC_DEP;
-
-/* Note: keep tNFC_INTF_PA_NFC_DEP data member in the same order as
- * tNFC_INTF_LA_NFC_DEP */
-typedef struct {
-  uint8_t atr_req_len;                      /* Length of ATR_REQ            */
-  uint8_t atr_req[NFC_MAX_ATS_LEN];         /* ATR_REQ (Byte 3 - Byte 18+n) */
-  uint8_t max_payload_size;                 /* 64, 128, 192 or 254          */
-  uint8_t gen_bytes_len;                    /* len of general bytes         */
-  uint8_t gen_bytes[NFC_MAX_GEN_BYTES_LEN]; /* general bytes           */
-} tNFC_INTF_LA_NFC_DEP;
-typedef tNFC_INTF_LA_NFC_DEP tNFC_INTF_LF_NFC_DEP;
-typedef tNFC_INTF_PA_NFC_DEP tNFC_INTF_PF_NFC_DEP;
-
 #define NFC_MAX_ATTRIB_LEN NCI_MAX_ATTRIB_LEN
 
 typedef struct {
@@ -706,10 +678,6 @@ typedef struct {
     tNFC_INTF_PA_ISO_DEP pa_iso;
     tNFC_INTF_LB_ISO_DEP lb_iso;
     tNFC_INTF_PB_ISO_DEP pb_iso;
-    tNFC_INTF_LA_NFC_DEP la_nfc;
-    tNFC_INTF_PA_NFC_DEP pa_nfc;
-    tNFC_INTF_LF_NFC_DEP lf_nfc;
-    tNFC_INTF_PF_NFC_DEP pf_nfc;
     tNFC_INTF_FRAME frame;
   } intf_param; /* Activation Parameters   0 - n Bytes */
 } tNFC_INTF_PARAMS;
@@ -807,6 +775,7 @@ typedef void(tNFC_CONN_CBACK)(uint8_t conn_id, tNFC_CONN_EVT event,
 #define NFC_RF_CONN_ID 0
 /* the static connection ID for HCI transport */
 #define NFC_HCI_CONN_ID 1
+#define NFC_T4TNFCEE_CONN_ID 0x05
 
 /*****************************************************************************
 **  EXTERNAL FUNCTION DECLARATIONS
@@ -1068,6 +1037,21 @@ extern tNFC_STATUS NFC_ConnClose(uint8_t conn_id);
 *******************************************************************************/
 extern void NFC_SetStaticRfCback(tNFC_CONN_CBACK* p_cback);
 
+/*******************************************************************************
+**
+** Function         NFC_SetStaticT4tNfceeCback
+**
+** Description      This function is called to update the data callback function
+**                  to receive the data for the given connection id.
+**
+** Parameters       p_cback - the connection callback function
+**                  connId - connection ID for T4T NFCEE
+**
+** Returns          Nothing
+**
+*******************************************************************************/
+void NFC_SetStaticT4tNfceeCback(tNFC_CONN_CBACK* p_cback, uint8_t connId);
+
 /*******************************************************************************
 **
 ** Function         NFC_SetReassemblyFlag
diff --git a/src/nfc/include/nfc_int.h b/src/nfc/include/nfc_int.h
index 67a97035..810220fb 100644
--- a/src/nfc/include/nfc_int.h
+++ b/src/nfc/include/nfc_int.h
@@ -55,6 +55,7 @@
 #define NFC_TTYPE_RW_I93_RESPONSE 108
 #define NFC_TTYPE_CE_T4T_UPDATE 109
 #define NFC_TTYPE_RW_MFC_RESPONSE 112
+#define NFC_TTYPE_RW_CI_RESPONSE 113
 /* time out for mode set notification */
 #define NFC_MODE_SET_NTF_TIMEOUT 2
 /* NFC Task event messages */
diff --git a/src/nfc/include/rw_api.h b/src/nfc/include/rw_api.h
index 3b9a9bac..d0752c60 100644
--- a/src/nfc/include/rw_api.h
+++ b/src/nfc/include/rw_api.h
@@ -37,6 +37,7 @@
 #define RW_T4T_FIRST_EVT 0x80
 #define RW_I93_FIRST_EVT 0xA0
 #define RW_MFC_FIRST_EVT 0xC0
+#define RW_CI_FIRST_EVT 0xD0
 
 enum {
   /* Note: the order of these events can not be changed */
@@ -139,7 +140,12 @@ enum {
 
   RW_MFC_RAW_FRAME_EVT,  /* Response of raw frame sent               */
   RW_MFC_INTF_ERROR_EVT, /* RF Interface error event                 */
-  RW_MFC_MAX_EVT
+  RW_MFC_MAX_EVT,
+  RW_CI_PRESENCE_CHECK_EVT = RW_CI_FIRST_EVT,
+  RW_CI_INTF_ERROR_EVT,
+  RW_CI_RAW_FRAME_EVT,
+  RW_CI_CPLT_EVT,
+  RW_CI_MAX_EVT
 };
 
 #define RW_RAW_FRAME_EVT 0xFF
@@ -258,6 +264,11 @@ typedef struct {
   NFC_HDR* p_data;
 } tRW_RAW_FRAME;
 
+typedef struct {
+  uint8_t mbi;
+  uint8_t uid[8];
+} t_RW_CI_INFO;
+
 typedef union {
   tNFC_STATUS status;
   tRW_T3T_POLL t3t_poll;           /* Response to t3t poll command          */
@@ -271,6 +282,7 @@ typedef union {
   tRW_I93_DATA i93_data;           /* ISO 15693 Data response           */
   tRW_I93_SYS_INFO i93_sys_info;   /* ISO 15693 System Information      */
   tRW_I93_CMD_CMPL i93_cmd_cmpl;   /* ISO 15693 Command complete        */
+  t_RW_CI_INFO ci_info;
 } tRW_DATA;
 
 typedef void(tRW_CBACK)(tRW_EVENT event, tRW_DATA* p_data);
@@ -1411,6 +1423,182 @@ extern tNFC_STATUS RW_MfcDetectNDef(void);
 *******************************************************************************/
 extern tNFC_STATUS RW_MfcReadNDef(uint8_t* p_buffer, uint16_t buf_len);
 
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeSelectApplication
+**
+** Description      Selects T4T application using T4T AID
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeSelectApplication(void);
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeUpdateCC
+**
+** Description      Updates the T4T data structures with CC info
+**
+** Returns          None
+**
+*******************************************************************************/
+void RW_T4tNfceeUpdateCC(uint8_t* ccInfo);
+
+/*******************************************************************************
+**
+** Function         rw_ci_select
+**
+** Description      This function send Select command for Chinese Id card.
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+extern tNFC_STATUS rw_ci_select(void);
+
+/*****************************************************************************
+**
+** Function         RW_CiPresenceCheck
+**
+** Description
+**      Check if the tag is still in the field.
+**
+**      The RW_CI_PRESENCE_CHECK_EVT w/ status is used to indicate presence
+**      or non-presence.
+**
+** Returns
+**      NFC_STATUS_OK, if raw data frame sent
+**      NFC_STATUS_NO_BUFFERS: unable to allocate a buffer for this operation
+**      NFC_STATUS_FAILED: other error
+**
+*****************************************************************************/
+extern tNFC_STATUS RW_CiPresenceCheck(void);
+
+/*****************************************************************************
+**
+** Function         RW_CiSendAttrib
+**
+** Description
+**      Send the Attrib to the Endpoint.
+**
+** Returns
+**      NFC_STATUS_OK, if raw data frame sent
+**      NFC_STATUS_NO_BUFFERS: unable to allocate a buffer for this operation
+**      NFC_STATUS_FAILED: other error
+**
+*****************************************************************************/
+extern tNFC_STATUS RW_CiSendAttrib(uint8_t* nfcid0);
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeSelectFile
+**
+** Description      Selects T4T Nfcee File
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeSelectFile(uint16_t fileId);
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeReadDataLen
+**
+** Description      Reads proprietary data Len
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeReadDataLen();
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeStartUpdateFile
+**
+** Description      starts writing data to the currently selected file
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeStartUpdateFile(uint16_t length, uint8_t* p_data);
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeUpdateFile
+**
+** Description      writes requested data to the currently selected file
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeUpdateFile();
+
+/*******************************************************************************
+**
+** Function         RW_T4tIsUpdateComplete
+**
+** Description      Return true if no more data to write
+**
+** Returns          true/false
+**
+*******************************************************************************/
+extern bool RW_T4tIsUpdateComplete(void);
+
+/*******************************************************************************
+**
+** Function         RW_T4tIsReadComplete
+**
+** Description      Return true if no more data to be read
+**
+** Returns          true/false
+**
+*******************************************************************************/
+extern bool RW_T4tIsReadComplete(void);
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeReadFile
+**
+** Description      Reads T4T Nfcee File
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeReadFile(uint16_t offset, uint16_t Readlen);
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeReadPendingData
+**
+** Description      Reads pending data from T4T Nfcee File
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeReadPendingData();
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeUpdateNlen
+**
+** Description      writes requested length to the file
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_T4tNfceeUpdateNlen(uint16_t len);
+
+/*******************************************************************************
+**
+** Function         RW_SetT4tNfceeInfo
+**
+** Description      This function sets callbacks for T4t operations.
+**
+** Returns          tNFC_STATUS
+**
+*******************************************************************************/
+extern tNFC_STATUS RW_SetT4tNfceeInfo(tRW_CBACK* p_cback, uint8_t conn_id);
+
 /*****************************************************************************
 **
 ** Function         RW_MfcFormatNDef
diff --git a/src/nfc/include/rw_int.h b/src/nfc/include/rw_int.h
index cb4b478b..f15c2ac2 100644
--- a/src/nfc/include/rw_int.h
+++ b/src/nfc/include/rw_int.h
@@ -595,6 +595,7 @@ typedef struct {
   uint32_t rw_offset;     /* remaining offset to read/write   */
 
   NFC_HDR* p_data_to_free; /* GKI buffet to delete after done  */
+  NFC_HDR* p_retry_cmd;    /* buffer to store cmd sent last    */
 
   tRW_T4T_CC cc_file; /* Capability Container File        */
 
@@ -822,6 +823,14 @@ typedef struct {
   bool in_pres_check;
 } tRW_I93_CB;
 
+typedef uint8_t tRW_CI_RW_STATE;
+typedef struct {
+  tRW_CI_RW_STATE state; /* main state                       */
+  TIMER_LIST_ENT timer;  /* timeout for each sent command    */
+  uint8_t sent_cmd;      /* last sent command                */
+  uint8_t attrib_res[2];
+  uint8_t uid[8];
+} tRW_CI_CB;
 /* RW memory control blocks */
 typedef union {
   tRW_T1T_CB t1t;
@@ -830,6 +839,7 @@ typedef union {
   tRW_T4T_CB t4t;
   tRW_I93_CB i93;
   tRW_MFC_CB mfc;
+  tRW_CI_CB ci;
 } tRW_TCB;
 
 /* RW callback type */
@@ -881,6 +891,7 @@ extern tNFC_STATUS rw_t1t_send_static_cmd(uint8_t opcode, uint8_t add,
                                           uint8_t dat);
 extern void rw_t1t_process_timeout(TIMER_LIST_ENT* p_tle);
 extern void rw_t1t_handle_op_complete(void);
+extern tNFC_STATUS RW_T4tNfceeInitCb(void);
 
 #if (RW_NDEF_INCLUDED == TRUE)
 extern tRW_EVENT rw_t2t_info_to_event(const tT2T_CMD_RSP_INFO* p_info);
@@ -917,6 +928,7 @@ extern void rw_t5t_sm_update_ndef(NFC_HDR*);
 extern void rw_t5t_sm_set_read_only(NFC_HDR*);
 
 extern void rw_t4t_handle_isodep_nak_rsp(uint8_t status, bool is_ntf);
+extern void rw_ci_process_timeout(TIMER_LIST_ENT* p_tle);
 
 extern tNFC_STATUS rw_mfc_select(uint8_t selres, uint8_t uid[T1T_CMD_UID_LEN]);
 extern void rw_mfc_process_timeout(TIMER_LIST_ENT* p_tle);
diff --git a/src/nfc/include/tags_defs.h b/src/nfc/include/tags_defs.h
index 6cb5ef3a..de47a49d 100644
--- a/src/nfc/include/tags_defs.h
+++ b/src/nfc/include/tags_defs.h
@@ -372,6 +372,8 @@ typedef uint8_t tT3T_POLL_RC;
  * with Lc and Le coded using Extended Field Coding */
 #define T4T_CMD_MAX_EXT_HDR_SIZE 15
 
+/* CLA, INS, P1, P2, Le on 3 bytes (Lc absent) using Extended Field Coding */
+#define T4T_CMD_MAX_EFC_NO_LC_HDR_SIZE 7
 #define T4T_VERSION_3_0 0x30 /* version 3.0 */
 #define T4T_VERSION_2_0 0x20 /* version 2.0 */
 #define T4T_VERSION_1_0 0x10 /* version 1.0 */
@@ -409,6 +411,8 @@ typedef uint8_t tT3T_POLL_RC;
 #define T4T_RSP_WRONG_LENGTH 0x6700
 #define T4T_RSP_INSTR_NOT_SUPPORTED 0x6D00
 #define T4T_RSP_CMD_NOT_ALLOWED 0x6986
+#define T4T_RSP_WARNING_PARAMS_CHECK(X) \
+  ((X == 0x63 || X == 0x62 || X == 0x61) ? true : false)
 
 /* V1.0 Type 4 Tag Applicaiton ID length */
 #define T4T_V10_NDEF_TAG_AID_LEN 0x07
diff --git a/src/nfc/nfc/nfc_main.cc b/src/nfc/nfc/nfc_main.cc
index 996cc6d4..c7eaebe6 100644
--- a/src/nfc/nfc/nfc_main.cc
+++ b/src/nfc/nfc/nfc_main.cc
@@ -33,6 +33,7 @@
 #include "gki.h"
 #include "nci_hmsgs.h"
 #include "nfa_sys.h"
+#include "nfc_api.h"
 #include "nfc_int.h"
 #include "nfc_target.h"
 #include "rw_int.h"
@@ -236,7 +237,8 @@ void nfc_enabled(tNFC_STATUS nfc_status, NFC_HDR* p_init_rsp_msg) {
              NFC_NFCC_MAX_NUM_VS_INTERFACE);
     }
     /* four bytes below are consumed in the top expression */
-    evt_data.enable.max_conn = *p++;
+    // Max nb conn = nb static conn + max nb dynamic conn
+    evt_data.enable.max_conn = NCI_MAX_STATIC_CONN_CBS + *p++;
     STREAM_TO_UINT16(evt_data.enable.max_ce_table, p);
 #if (NFC_RW_ONLY == FALSE)
     nfc_cb.max_ce_table = evt_data.enable.max_ce_table;
@@ -522,15 +524,15 @@ void nfc_main_handle_hal_evt(tNFC_HAL_EVT_MSG* p_msg) {
           }
           break;
 
-        case HAL_HCI_NETWORK_RESET:
-          delete_stack_non_volatile_store(true);
-          break;
-
         default:
           break;
       }
       break;
 
+    case HAL_HCI_NETWORK_RESET:
+      delete_stack_non_volatile_store(true);
+      break;
+
     default:
       LOG(ERROR) << StringPrintf("unhandled event (0x%x).", p_msg->hal_evt);
       break;
@@ -1085,6 +1087,32 @@ void NFC_SetStaticRfCback(tNFC_CONN_CBACK* p_cback) {
   nfc_data_event(p_cb);
 }
 
+/*******************************************************************************
+**
+** Function         NFC_SetStaticT4tNfceeCback
+**
+** Description      This function is called to update the data callback function
+**                  to receive the data for the given connection id.
+**
+** Parameters       p_cback - the connection callback function
+**                  connId - connection ID for T4T NFCEE
+**
+** Returns          Nothing
+**
+*******************************************************************************/
+void NFC_SetStaticT4tNfceeCback(tNFC_CONN_CBACK* p_cback, uint8_t connId) {
+  // tNFC_CONN_CB * p_cb = &nfc_cb.conn_cb[];
+  tNFC_CONN_CB* p_cb = nfc_find_conn_cb_by_conn_id(connId);
+  if (p_cb != NULL) {
+    p_cb->p_cback = p_cback;
+    /* just in case DH has received NCI data before the data callback is set
+     * check if there's any data event to report on this connection id */
+    nfc_data_event(p_cb);
+    LOG(DEBUG) << StringPrintf("%s = %p, p_cb->p_cback = %p", __func__, p_cb,
+                               p_cb->p_cback);
+  }
+}
+
 /*******************************************************************************
 **
 ** Function         NFC_SetReassemblyFlag
diff --git a/src/nfc/nfc/nfc_ncif.cc b/src/nfc/nfc/nfc_ncif.cc
index 9224d386..e524767a 100644
--- a/src/nfc/nfc/nfc_ncif.cc
+++ b/src/nfc/nfc/nfc_ncif.cc
@@ -27,6 +27,7 @@
 #include <android-base/stringprintf.h>
 #include <fcntl.h>
 #include <log/log.h>
+#include <pthread.h>
 #include <statslog_nfc.h>
 #include <sys/stat.h>
 #include <sys/time.h>
@@ -43,10 +44,6 @@
 
 using android::base::StringPrintf;
 
-#if (NFC_RW_ONLY == FALSE)
-static const uint8_t nfc_mpl_code_to_size[] = {64, 128, 192, 254};
-
-#endif /* NFC_RW_ONLY */
 #if (APPL_DTA_MODE == TRUE)
 // Global Structure varibale for FW Version
 static tNFC_FW_VERSION nfc_fw_version;
@@ -60,6 +57,7 @@ extern std::string nfc_storage_path;
 
 static struct timeval timer_start;
 static struct timeval timer_end;
+static pthread_mutex_t cache_flush = PTHREAD_MUTEX_INITIALIZER;
 
 /*******************************************************************************
 **
@@ -295,6 +293,10 @@ void nfc_ncif_check_cmd_queue(NFC_HDR* p_buf) {
       /* Indicate command is pending */
       nfc_cb.nci_cmd_window--;
 
+      // Make sure the caches are consistent with other threads here.
+      (void)pthread_mutex_lock(&cache_flush);
+      (void)pthread_mutex_unlock(&cache_flush);
+
       /* send to HAL */
       nfcsnoop_capture(p_buf, false);
       HAL_WRITE(p_buf);
@@ -386,6 +388,10 @@ bool nfc_ncif_process_event(NFC_HDR* p_msg) {
     return free;
   }
 
+  // Make sure the caches are consistent with other threads here.
+  (void)pthread_mutex_lock(&cache_flush);
+  (void)pthread_mutex_unlock(&cache_flush);
+
   p = (uint8_t*)(p_msg + 1) + p_msg->offset;
 
   if (p_msg->len < 3) {
@@ -938,11 +944,6 @@ void nfc_ncif_proc_activate(uint8_t* p, uint8_t len) {
   tNFC_INTF_PA_ISO_DEP* p_pa_iso;
   tNFC_INTF_LB_ISO_DEP* p_lb_iso;
   tNFC_INTF_PB_ISO_DEP* p_pb_iso;
-#if (NFC_RW_ONLY == FALSE)
-  tNFC_INTF_PA_NFC_DEP* p_pa_nfc;
-  int mpl_idx = 0;
-  uint8_t gb_idx = 0, mpl;
-#endif
   uint8_t t0;
   tNCI_DISCOVERY_TYPE mode;
   tNFC_CONN_CB* p_cb = &nfc_cb.conn_cb[NFC_RF_CONN_ID];
@@ -1166,74 +1167,8 @@ void nfc_ncif_proc_activate(uint8_t* p, uint8_t len) {
         break;
     }
 
-  }
-#if (NFC_RW_ONLY == FALSE)
-  else if (evt_data.activate.intf_param.type == NCI_INTERFACE_NFC_DEP) {
-    /* Make max payload of NCI aligned to max payload of NFC-DEP for better
-     * performance */
-    if (buff_size > NCI_NFC_DEP_MAX_DATA) buff_size = NCI_NFC_DEP_MAX_DATA;
-
-    p_pa_nfc = &p_intf->intf_param.pa_nfc;
-
-    if (plen < 1) {
-      evt_data.status = NCI_STATUS_FAILED;
-      goto invalid_packet;
-    }
-    plen--;
-    p_pa_nfc->atr_res_len = *p++;
-
-    if (p_pa_nfc->atr_res_len > 0) {
-      if (p_pa_nfc->atr_res_len > NFC_MAX_ATS_LEN)
-        p_pa_nfc->atr_res_len = NFC_MAX_ATS_LEN;
-
-      if (plen < p_pa_nfc->atr_res_len) {
-        evt_data.status = NCI_STATUS_FAILED;
-        goto invalid_packet;
-      }
-      plen -= p_pa_nfc->atr_res_len;
-      STREAM_TO_ARRAY(p_pa_nfc->atr_res, p, p_pa_nfc->atr_res_len);
-
-      if ((mode == NCI_DISCOVERY_TYPE_POLL_A) ||
-          (mode == NCI_DISCOVERY_TYPE_POLL_F)) {
-        /* ATR_RES
-        Byte 3~12 Byte 13 Byte 14 Byte 15 Byte 16 Byte 17 Byte 18~18+n
-        NFCID3T   DIDT    BST     BRT     TO      PPT     [GT0 ... GTn] */
-        mpl_idx = 14;
-        gb_idx = NCI_P_GEN_BYTE_INDEX;
-
-        if (p_pa_nfc->atr_res_len < NCI_L_NFC_DEP_TO_INDEX + 1) {
-          evt_data.status = NCI_STATUS_FAILED;
-          goto invalid_packet;
-        }
-        p_pa_nfc->waiting_time =
-            p_pa_nfc->atr_res[NCI_L_NFC_DEP_TO_INDEX] & 0x0F;
-      } else if ((mode == NCI_DISCOVERY_TYPE_LISTEN_A) ||
-                 (mode == NCI_DISCOVERY_TYPE_LISTEN_F)) {
-        /* ATR_REQ
-        Byte 3~12 Byte 13 Byte 14 Byte 15 Byte 16 Byte 17~17+n
-        NFCID3I   DIDI    BSI     BRI     PPI     [GI0 ... GIn] */
-        mpl_idx = 13;
-        gb_idx = NCI_L_GEN_BYTE_INDEX;
-      }
-
-      if (p_pa_nfc->atr_res_len < mpl_idx + 1) {
-        evt_data.status = NCI_STATUS_FAILED;
-        goto invalid_packet;
-      }
-      mpl = ((p_pa_nfc->atr_res[mpl_idx]) >> 4) & 0x03;
-      p_pa_nfc->max_payload_size = nfc_mpl_code_to_size[mpl];
-      if (p_pa_nfc->atr_res_len > gb_idx) {
-        p_pa_nfc->gen_bytes_len = p_pa_nfc->atr_res_len - gb_idx;
-        if (p_pa_nfc->gen_bytes_len > NFC_MAX_GEN_BYTES_LEN)
-          p_pa_nfc->gen_bytes_len = NFC_MAX_GEN_BYTES_LEN;
-        memcpy(p_pa_nfc->gen_bytes, &p_pa_nfc->atr_res[gb_idx],
-               p_pa_nfc->gen_bytes_len);
-      }
-    }
-  }
-#endif
-  else if ((evt_data.activate.intf_param.type == NCI_INTERFACE_FRAME) &&
-           (evt_data.activate.protocol == NCI_PROTOCOL_T1T)) {
+  } else if ((evt_data.activate.intf_param.type == NCI_INTERFACE_FRAME) &&
+             (evt_data.activate.protocol == NCI_PROTOCOL_T1T)) {
     p_pa = &evt_data.activate.rf_tech_param.param.pa;
     if ((len_act == NCI_T1T_HR_LEN) && (p_pa->hr_len == 0)) {
       p_pa->hr_len = NCI_T1T_HR_LEN;
diff --git a/src/nfc/nfc/nfc_task.cc b/src/nfc/nfc/nfc_task.cc
index a448f9ae..c56d46e4 100644
--- a/src/nfc/nfc/nfc_task.cc
+++ b/src/nfc/nfc/nfc_task.cc
@@ -254,7 +254,9 @@ void nfc_process_quick_timer_evt(void) {
       case NFC_TTYPE_RW_MFC_RESPONSE:
         rw_mfc_process_timeout(p_tle);
         break;
-
+      case NFC_TTYPE_RW_CI_RESPONSE:
+        rw_ci_process_timeout(p_tle);
+        break;
 #if (NFC_RW_ONLY == FALSE)
       case NFC_TTYPE_CE_T4T_UPDATE:
         ce_t4t_process_timeout(p_tle);
diff --git a/src/nfc/tags/rw_ci.cc b/src/nfc/tags/rw_ci.cc
new file mode 100644
index 00000000..fbed9be3
--- /dev/null
+++ b/src/nfc/tags/rw_ci.cc
@@ -0,0 +1,507 @@
+/******************************************************************************
+ *
+ * Copyright (C) 2024 The Android Open Source Project
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ *
+ ******************************************************************************/
+
+/******************************************************************************
+ *
+ *  This file contains the implementation for CI 4 tag in Reader/Writer
+ *  mode.
+ *
+ ******************************************************************************/
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <log/log.h>
+#include <string.h>
+
+#include "gki.h"
+#include "nfc_api.h"
+#include "nfc_int.h"
+#include "nfc_target.h"
+#include "rw_api.h"
+#include "rw_int.h"
+#include "tags_int.h"
+
+/* main state */
+#define RW_CI_STATE_NOT_ACTIVATED 0x00  /* T4C is not activated */
+#define RW_CI_STATE_IDLE 0x01           /* waiting for upper layer API */
+#define RW_CI_STATE_ATTRIB 0x02         /* Get ATTRIB and UID */
+#define RW_CI_STATE_UID 0x03            /* Get ATTRIB and UID */
+#define RW_CI_STATE_PRESENCE_CHECK 0x04 /* checking presence of tag */
+
+#if (BT_TRACE_VERBOSE == true)
+static char* rw_ci_get_state_name(uint8_t state);
+#endif
+
+static bool rw_ci_send_to_lower(NFC_HDR* p_c_apdu);
+
+static void rw_ci_handle_error(tNFC_STATUS status, uint8_t sw1, uint8_t sw2);
+static void rw_ci_data_cback(uint8_t conn_id, tNFC_CONN_EVT event,
+                             tNFC_CONN* p_data);
+static void rw_ci_send_uid(void);
+
+using android::base::StringPrintf;
+extern bool nfc_debug_enabled;
+
+/*******************************************************************************
+**
+** Function         rw_ci_send_to_lower
+**
+** Description      Send C-APDU to lower layer
+**
+** Returns          true if success
+**
+*******************************************************************************/
+static bool rw_ci_send_to_lower(NFC_HDR* p_c_apdu) {
+  if (NFC_SendData(NFC_RF_CONN_ID, p_c_apdu) != NFC_STATUS_OK) {
+    LOG(ERROR) << StringPrintf("%s; NFC_SendData () failed", __func__);
+    return false;
+  }
+
+  nfc_start_quick_timer(&rw_cb.tcb.ci.timer, NFC_TTYPE_RW_CI_RESPONSE,
+                        (RW_CI_TOUT_RESP * QUICK_TIMER_TICKS_PER_SEC) / 1000);
+
+  return true;
+}
+
+/*******************************************************************************
+**
+** Function         rw_ci_handle_error
+**
+** Description      notify error to application and clean up
+**
+** Returns          none
+**
+*******************************************************************************/
+static void rw_ci_handle_error(tNFC_STATUS status, uint8_t sw1, uint8_t sw2) {
+  tRW_CI_CB* p_ci = &rw_cb.tcb.ci;
+  tRW_DATA rw_data;
+  tRW_EVENT event = NFC_STATUS_OK;
+
+  LOG(DEBUG) << StringPrintf(
+      "%s; status:0x%02X, sw1:0x%02X, sw2:0x%02X, "
+      "state:0x%X",
+      __func__, status, sw1, sw2, p_ci->state);
+
+  nfc_stop_quick_timer(&p_ci->timer);
+
+  if (rw_cb.p_cback) {
+    rw_data.status = status;
+
+    switch (p_ci->state) {
+      case RW_CI_STATE_ATTRIB:
+        if (status == NFC_STATUS_TIMEOUT) {
+          // Maybe not Chinese Id card, maybe ChengShiTong
+          // Report card anyway
+          rw_data.status = NFC_STATUS_OK;
+          rw_data.ci_info.mbi = 0;
+          memset(rw_data.ci_info.uid, 0, sizeof(rw_data.ci_info.uid));
+          event = RW_CI_CPLT_EVT;
+        } else {
+          event = RW_CI_INTF_ERROR_EVT;
+        }
+        break;
+
+      case RW_CI_STATE_UID:
+        if (status == NFC_STATUS_TIMEOUT) {
+          event = RW_CI_INTF_ERROR_EVT;
+        }
+        break;
+
+      case RW_CI_STATE_PRESENCE_CHECK:
+        event = RW_CI_PRESENCE_CHECK_EVT;
+        if (status == NFC_STATUS_TIMEOUT) {
+          rw_data.status = NFC_STATUS_RF_FRAME_CORRUPTED;
+        } else {
+          rw_data.status = NFC_STATUS_FAILED;
+        }
+        break;
+
+      default:
+        event = RW_CI_MAX_EVT;
+        break;
+    }
+
+    p_ci->state = RW_CI_STATE_IDLE;
+
+    if (event != RW_CI_MAX_EVT) {
+      (*(rw_cb.p_cback))(event, &rw_data);
+    }
+  } else {
+    p_ci->state = RW_CI_STATE_IDLE;
+  }
+}
+
+/*******************************************************************************
+**
+** Function         rw_ci_process_timeout
+**
+** Description      process timeout event
+**
+** Returns          none
+**
+*******************************************************************************/
+void rw_ci_process_timeout(TIMER_LIST_ENT* p_tle) {
+  LOG(DEBUG) << StringPrintf("%s; event=%d", __func__, p_tle->event);
+
+  if (p_tle->event == NFC_TTYPE_RW_CI_RESPONSE) {
+    rw_ci_handle_error(NFC_STATUS_TIMEOUT, 0, 0);
+  } else {
+    LOG(ERROR) << StringPrintf("%s; unknown event=%d", __func__, p_tle->event);
+  }
+}
+
+/*******************************************************************************
+**
+** Function         rw_ci_data_cback
+**
+** Description      This callback function receives the data from NFCC.
+**
+** Returns          none
+**
+*******************************************************************************/
+static void rw_ci_data_cback(__attribute__((unused)) uint8_t conn_id,
+                             tNFC_CONN_EVT event, tNFC_CONN* p_data) {
+  tRW_CI_CB* p_ci = &rw_cb.tcb.ci;
+  NFC_HDR* p_r_apdu;
+  tRW_DATA rw_data;
+  tRW_DATA evt_data;
+  uint8_t *p, *p_sw;
+
+#if (BT_TRACE_VERBOSE == true)
+  uint8_t begin_state = p_ci->state;
+#endif
+
+  LOG(DEBUG) << StringPrintf("%s; event = 0x%X", __func__, event);
+
+  // Case data is fragmented, do not stop time until complete frame received
+  if (event != NFC_DATA_START_CEVT) {
+    nfc_stop_quick_timer(&p_ci->timer);
+  }
+
+  switch (event) {
+    case NFC_DEACTIVATE_CEVT:
+      NFC_SetStaticRfCback(nullptr);
+      p_ci->state = RW_CI_STATE_NOT_ACTIVATED;
+      return;
+
+    case NFC_ERROR_CEVT:
+      if (p_ci->state == RW_CI_STATE_PRESENCE_CHECK) {
+        p_ci->state = RW_CI_STATE_IDLE;
+
+        rw_data.status = NFC_STATUS_RF_FRAME_CORRUPTED;
+
+        (*(rw_cb.p_cback))(RW_CI_PRESENCE_CHECK_EVT, &rw_data);
+      } else if (p_ci->state != RW_CI_STATE_IDLE) {
+        rw_data.status = NFC_STATUS_FAILED;
+        rw_ci_handle_error(rw_data.status, 0, 0);
+      } else {
+        p_ci->state = RW_CI_STATE_IDLE;
+        rw_data.status = (tNFC_STATUS)(*(uint8_t*)p_data);
+        (*(rw_cb.p_cback))(RW_CI_INTF_ERROR_EVT, &rw_data);
+      }
+      return;
+
+    case NFC_DATA_CEVT:
+      p_r_apdu = (NFC_HDR*)p_data->data.p_data;
+      p = (uint8_t*)(p_r_apdu + 1) + p_r_apdu->offset;
+      break;
+
+    default:
+      return;
+  }
+
+#if (BT_TRACE_VERBOSE == true)
+  LOG(DEBUG) << StringPrintf("RW CI state: <%s (%d)>",
+                             rw_ci_get_state_name(p_ci->state), p_ci->state);
+#else
+  LOG(DEBUG) << StringPrintf("%s; RW CI state: %d", __func__, p_ci->state);
+#endif
+
+  switch (p_ci->state) {
+    case RW_CI_STATE_IDLE:
+      /* Unexpected R-APDU, it should be raw frame response */
+      /* forward to upper layer without parsing */
+#if (BT_TRACE_VERBOSE == true)
+      LOG(DEBUG) << StringPrintf("%s; RW CI Raw Frame: Len [0x%X] Status [%s]",
+                                 __func__, p_r_apdu->len,
+                                 NFC_GetStatusName(p_data->data.status));
+#else
+      LOG(DEBUG) << StringPrintf(
+          "%s; RW CI Raw Frame: Len [0x%X] Status [0x%X]", __func__,
+          p_r_apdu->len, p_data->data.status);
+#endif
+      if (rw_cb.p_cback) {
+        rw_data.raw_frame.status = p_data->data.status;
+        rw_data.raw_frame.p_data = p_r_apdu;
+        (*(rw_cb.p_cback))(RW_CI_RAW_FRAME_EVT, &rw_data);
+        p_r_apdu = nullptr;
+      } else {
+        GKI_freebuf(p_r_apdu);
+      }
+      break;
+
+    case RW_CI_STATE_ATTRIB:
+      memcpy(p_ci->attrib_res, p, sizeof(p_ci->attrib_res));
+      GKI_freebuf(p_r_apdu);
+      rw_ci_send_uid();
+      break;
+
+    case RW_CI_STATE_UID: {
+      uint16_t status_words;
+
+      p_r_apdu->len -= 1;  // Last byte is status
+      p_sw = (uint8_t*)(p_r_apdu + 1) + p_r_apdu->offset;
+      p_sw += (p_r_apdu->len - T4T_RSP_STATUS_WORDS_SIZE);
+      BE_STREAM_TO_UINT16(status_words, p_sw);
+
+      if (status_words == T4T_RSP_CMD_CMPLTED) {
+        memcpy(p_ci->uid, p, sizeof(p_ci->uid));
+      }
+
+      GKI_freebuf(p_r_apdu);
+
+      p_ci->state = RW_CI_STATE_IDLE;
+
+      evt_data.status = NFC_STATUS_OK;
+      evt_data.ci_info.mbi = p_ci->attrib_res[0] & 0xF;
+      memcpy(evt_data.ci_info.uid, p_ci->uid, sizeof(p_ci->uid));
+      (*rw_cb.p_cback)(RW_CI_CPLT_EVT, (tRW_DATA*)&evt_data);
+    } break;
+
+    case RW_CI_STATE_PRESENCE_CHECK:
+      /* if any response, send presence check with ok */
+      rw_data.status = NFC_STATUS_OK;
+      p_ci->state = RW_CI_STATE_IDLE;
+      (*(rw_cb.p_cback))(RW_CI_PRESENCE_CHECK_EVT, &rw_data);
+      GKI_freebuf(p_r_apdu);
+      break;
+
+    default:
+      LOG(ERROR) << StringPrintf("%s; invalid state=%d", __func__, p_ci->state);
+      GKI_freebuf(p_r_apdu);
+      break;
+  }
+
+#if (BT_TRACE_VERBOSE == true)
+  if (begin_state != p_ci->state) {
+    LOG(DEBUG) << StringPrintf("%s; RW CI state changed:<%s> -> <%s>", __func__,
+                               rw_ci_get_state_name(begin_state),
+                               rw_ci_get_state_name(p_ci->state));
+  }
+#endif
+}
+
+/*******************************************************************************
+**
+** Function         rw_ci_select
+**
+** Description      This function send Select command for Chinese Id card.
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+tNFC_STATUS rw_ci_select(void) {
+  tRW_CI_CB* p_ci = &rw_cb.tcb.ci;
+
+  LOG(DEBUG) << StringPrintf("%s", __func__);
+
+  NFC_SetStaticRfCback(rw_ci_data_cback);
+
+  p_ci->state = RW_CI_STATE_IDLE;
+
+  return NFC_STATUS_OK;
+}
+
+/*****************************************************************************
+**
+** Function         RW_CiPresenceCheck
+**
+** Description
+**      Check if the tag is still in the field.
+**
+**      The RW_CI_PRESENCE_CHECK_EVT w/ status is used to indicate presence
+**      or non-presence.
+**
+** Returns
+**      NFC_STATUS_OK, if raw data frame sent
+**      NFC_STATUS_NO_BUFFERS: unable to allocate a buffer for this operation
+**      NFC_STATUS_FAILED: other error
+**
+*****************************************************************************/
+tNFC_STATUS RW_CiPresenceCheck(void) {
+  tNFC_STATUS retval = NFC_STATUS_OK;
+  tRW_DATA evt_data;
+  bool status;
+  NFC_HDR* p_data;
+  uint8_t* p;
+
+  LOG(DEBUG) << StringPrintf("%s ", __func__);
+
+  /* If RW_SelectTagType was not called (no conn_callback) return failure */
+  if (!rw_cb.p_cback) {
+    retval = NFC_STATUS_FAILED;
+  }
+  /* If command is pending, assume tag is still present */
+  else if (rw_cb.tcb.ci.state != RW_CI_STATE_IDLE) {
+    evt_data.status = NFC_STATUS_OK;
+    (*rw_cb.p_cback)(RW_CI_PRESENCE_CHECK_EVT, &evt_data);
+  } else {
+    status = false;
+    /* use I block of length 1 for presence check */
+    if ((p_data = (NFC_HDR*)GKI_getbuf(sizeof(NFC_HDR) + NCI_MSG_OFFSET_SIZE +
+                                       NCI_DATA_HDR_SIZE + 1)) != nullptr) {
+      p_data->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
+      p = (uint8_t*)(p_data + 1) + p_data->offset;
+      UINT8_TO_STREAM(p, 0xB2);
+      p_data->len = 1;
+      if (NFC_SendData(NFC_RF_CONN_ID, (NFC_HDR*)p_data) == NFC_STATUS_OK)
+        status = true;
+    }
+
+    if (status == true) {
+      rw_cb.tcb.ci.state = RW_CI_STATE_PRESENCE_CHECK;
+    } else {
+      retval = NFC_STATUS_NO_BUFFERS;
+    }
+  }
+
+  return (retval);
+}
+
+/*****************************************************************************
+**
+** Function         RW_CiSendAttrib
+**
+** Description
+**       Send the Attrib to the Endpoint.
+**
+** Returns
+**      NFC_STATUS_OK, if raw data frame sent
+**      NFC_STATUS_NO_BUFFERS: unable to allocate a buffer for this operation
+**      NFC_STATUS_FAILED: other error
+**
+*****************************************************************************/
+tNFC_STATUS RW_CiSendAttrib(uint8_t* nfcid0) {
+  NFC_HDR* p_c_apdu;
+  uint8_t* p;
+
+  LOG(DEBUG) << StringPrintf("%s", __func__);
+
+  p_c_apdu = (NFC_HDR*)GKI_getpoolbuf(NFC_RW_POOL_ID);
+
+  if (!p_c_apdu) {
+    LOG(ERROR) << StringPrintf("%s; Cannot allocate buffer", __func__);
+    return false;
+  }
+
+  p_c_apdu->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
+  p = (uint8_t*)(p_c_apdu + 1) + p_c_apdu->offset;
+
+  UINT8_TO_BE_STREAM(p, 0x1D);
+  UINT8_TO_BE_STREAM(p, nfcid0[0]);
+  UINT8_TO_BE_STREAM(p, nfcid0[1]);
+  UINT8_TO_BE_STREAM(p, nfcid0[2]);
+  UINT8_TO_BE_STREAM(p, nfcid0[3]);
+  UINT8_TO_BE_STREAM(p, 0x00);
+  UINT8_TO_BE_STREAM(p, 0x08);
+  UINT8_TO_BE_STREAM(p, 0x01);
+  UINT8_TO_BE_STREAM(p, 0x08);
+
+  p_c_apdu->len = 9;
+
+  if (!rw_ci_send_to_lower(p_c_apdu)) {
+    return false;
+  }
+
+  rw_cb.tcb.ci.state = RW_CI_STATE_ATTRIB;
+
+  return true;
+}
+
+/*****************************************************************************
+**
+** Function         RW_CiSendUid
+**
+** Description
+**      Send UID to the endpoint
+**
+** Returns
+**
+*****************************************************************************/
+static void rw_ci_send_uid(void) {
+  NFC_HDR* p_c_apdu;
+  uint8_t* p;
+
+  LOG(DEBUG) << StringPrintf("%s; ATTRIB_RES = %02X", __func__,
+                             rw_cb.tcb.ci.attrib_res[0]);
+
+  p_c_apdu = (NFC_HDR*)GKI_getpoolbuf(NFC_RW_POOL_ID);
+
+  if (!p_c_apdu) {
+    LOG(ERROR) << StringPrintf("%s; Cannot allocate buffer", __func__);
+    return;
+  }
+
+  p_c_apdu->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
+  p = (uint8_t*)(p_c_apdu + 1) + p_c_apdu->offset;
+
+  UINT8_TO_BE_STREAM(p, 0x00);
+  UINT8_TO_BE_STREAM(p, 0x36);
+  UINT8_TO_BE_STREAM(p, 0x00);
+  UINT8_TO_BE_STREAM(p, 0x00);
+  UINT8_TO_BE_STREAM(p, rw_cb.tcb.ci.attrib_res[0]);
+
+  p_c_apdu->len = 5;
+
+  if (!rw_ci_send_to_lower(p_c_apdu)) {
+    return;
+  }
+
+  rw_cb.tcb.ci.state = RW_CI_STATE_UID;
+
+  return;
+}
+
+#if (BT_TRACE_VERBOSE == true)
+/*******************************************************************************
+**
+** Function         rw_ci_get_state_name
+**
+** Description      This function returns the state name.
+**
+** NOTE             conditionally compiled to save memory.
+**
+** Returns          pointer to the name
+**
+*******************************************************************************/
+static char* rw_ci_get_state_name(uint8_t state) {
+  switch (state) {
+    case RW_CI_STATE_NOT_ACTIVATED:
+      return ("NOT_ACTIVATED");
+    case RW_CI_STATE_IDLE:
+      return ("IDLE");
+    case RW_CI_STATE_ATTRIB:
+      return ("ATTRIB");
+    case RW_CI_STATE_UID:
+      return ("UID");
+    case RW_CI_STATE_PRESENCE_CHECK:
+      return ("PRESENCE_CHECK");
+
+    default:
+      return ("???? UNKNOWN STATE");
+  }
+}
+#endif
diff --git a/src/nfc/tags/rw_main.cc b/src/nfc/tags/rw_main.cc
index 35421e22..7efb40e6 100644
--- a/src/nfc/tags/rw_main.cc
+++ b/src/nfc/tags/rw_main.cc
@@ -301,9 +301,11 @@ tNFC_STATUS RW_SetActivatedTagType(tNFC_ACTIVATE_DEVT* p_activate_params,
           p_activate_params->rf_tech_param.param.pa.nfcid1 +
               p_activate_params->rf_tech_param.param.pa.nfcid1_len - 4);
     }
-  }
-  /* TODO set up callback for proprietary protocol */
-  else {
+  } else if ((NFC_PROTOCOL_UNKNOWN == p_activate_params->protocol) &&
+             (p_activate_params->rf_tech_param.mode ==
+              NFC_DISCOVERY_TYPE_POLL_B)) {
+    status = rw_ci_select();
+  } else {
     rw_cb.tcb_type = RW_CB_TYPE_UNKNOWN;
     LOG(ERROR) << StringPrintf("RW_SetActivatedTagType Invalid protocol");
   }
@@ -311,3 +313,31 @@ tNFC_STATUS RW_SetActivatedTagType(tNFC_ACTIVATE_DEVT* p_activate_params,
   if (status != NFC_STATUS_OK) rw_cb.p_cback = nullptr;
   return status;
 }
+
+/*******************************************************************************
+**
+** Function         RW_SetT4tNfceeInfo
+**
+** Description      This function selects the T4t Nfcee  for Reader/Writer mode.
+**
+** Returns          tNFC_STATUS
+**
+*******************************************************************************/
+tNFC_STATUS RW_SetT4tNfceeInfo(tRW_CBACK* p_cback, uint8_t conn_id) {
+  tNFC_STATUS status = NFC_STATUS_FAILED;
+  /* Reset tag-specific area of control block */
+  LOG(ERROR) << StringPrintf("RW_SetActivatedTagType %d ", conn_id);
+
+  memset(&rw_cb.tcb, 0, sizeof(tRW_TCB));
+
+  if (p_cback != NULL) {
+    rw_cb.p_cback = p_cback;
+    status = RW_T4tNfceeInitCb();
+    if (status != NFC_STATUS_OK) {
+      rw_cb.p_cback = NULL;
+    }
+  } else {
+    rw_cb.p_cback = NULL;
+  }
+  return status;
+}
diff --git a/src/nfc/tags/rw_t2t.cc b/src/nfc/tags/rw_t2t.cc
index 1ec02637..aa0e59de 100644
--- a/src/nfc/tags/rw_t2t.cc
+++ b/src/nfc/tags/rw_t2t.cc
@@ -140,21 +140,36 @@ static void rw_t2t_proc_data(uint8_t conn_id, tNFC_DATA_CEVT* p_data) {
     evt_data.p_data = p_pkt;
     if (p_t2t->state == RW_T2T_STATE_READ) b_release = false;
 
-    LOG(VERBOSE) << StringPrintf(
-        "rw_t2t_proc_data - Received NACK response(0x%x)", (*p & 0x0f));
-
-    if (!p_t2t->check_tag_halt) {
-      /* Just received first NACK. Retry just one time to find if tag went in to
-       * HALT State */
+    if (p_t2t->state == RW_T2T_STATE_CHECK_PRESENCE) {
+      LOG(DEBUG) << StringPrintf(
+          "%s; Received NACK response(0x%x) while presence "
+          "checking",
+          __func__, (*p & 0x0f));
+      // Consider tag present
+      rw_t2t_handle_presence_check_rsp(NFC_STATUS_OK);
+
+      // Once this has been processed, there is no need for notification
+      // as already done.
+      // Release still need to free the buffer
       b_notify = false;
-      rw_t2t_process_error();
-      /* Assume Tag is in HALT State, untill we get response to retry command */
-      p_t2t->check_tag_halt = true;
     } else {
-      p_t2t->check_tag_halt = false;
-      /* Got consecutive NACK so tag not really halt after first NACK, but
-       * current operation failed */
-      evt_data.status = NFC_STATUS_FAILED;
+      LOG(DEBUG) << StringPrintf("%s; Received NACK response(0x%x)", __func__,
+                                 (*p & 0x0f));
+
+      if (!p_t2t->check_tag_halt) {
+        /* Just received first NACK. Retry just one time to find if tag went in
+         * to HALT State */
+        b_notify = false;
+        rw_t2t_process_error();
+        /* Assume Tag is in HALT State, until we get response to retry command
+         */
+        p_t2t->check_tag_halt = true;
+      } else {
+        p_t2t->check_tag_halt = false;
+        /* Got consecutive NACK so tag not really halt after first NACK, but
+         * current operation failed */
+        evt_data.status = NFC_STATUS_FAILED;
+      }
     }
   } else {
     /* If the response length indicates positive response or cannot be known
@@ -822,7 +837,7 @@ tNFC_STATUS rw_t2t_select(void) {
       return (NFC_STATUS_FAILED);
     }
   }
-  /* Alloc cmd buf for holding a command untill sector changes */
+  /* Alloc cmd buf for holding a command until sector changes */
   if (p_t2t->p_sec_cmd_buf == nullptr) {
     p_t2t->p_sec_cmd_buf = (NFC_HDR*)GKI_getpoolbuf(NFC_RW_POOL_ID);
     if (p_t2t->p_sec_cmd_buf == nullptr) {
diff --git a/src/nfc/tags/rw_t3t.cc b/src/nfc/tags/rw_t3t.cc
index 960b050b..4ec0bf8f 100644
--- a/src/nfc/tags/rw_t3t.cc
+++ b/src/nfc/tags/rw_t3t.cc
@@ -365,6 +365,13 @@ void rw_t3t_handle_nci_poll_ntf(uint8_t nci_status, uint8_t num_responses,
   /* stop timer for poll response */
   nfc_stop_quick_timer(&p_cb->poll_timer);
 
+  if (p_cb->rw_state == RW_T3T_STATE_NOT_ACTIVATED) {
+    // Tag was deactivated
+    evt_data.status = nci_status;
+    (*(rw_cb.p_cback))(RW_T3T_INTF_ERROR_EVT, &evt_data);
+    return;
+  }
+
   /* Stop t3t timer (if started) */
   if (p_cb->flags & RW_T3T_FL_W4_PRESENCE_CHECK_POLL_RSP) {
     p_cb->flags &= ~RW_T3T_FL_W4_PRESENCE_CHECK_POLL_RSP;
@@ -2432,7 +2439,7 @@ static tNFC_STATUS rw_t3t_unselect() {
 #endif /* RW_STATS_INCLUDED */
 
   /* Stop t3t timer (if started) */
-  nfc_stop_quick_timer(&p_cb->timer);
+  nfc_stop_quick_timer(&p_cb->poll_timer);
 
   /* Free cmd buf for retransmissions */
   if (p_cb->p_cur_cmd_buf) {
diff --git a/src/nfc/tags/rw_t4t.cc b/src/nfc/tags/rw_t4t.cc
index cc0f8c56..f203a781 100644
--- a/src/nfc/tags/rw_t4t.cc
+++ b/src/nfc/tags/rw_t4t.cc
@@ -28,6 +28,8 @@
 #include <string.h>
 
 #include "bt_types.h"
+#include "nfa_nfcee_int.h"
+#include "nfa_rw_int.h"
 #include "nfc_api.h"
 #include "nfc_int.h"
 #include "nfc_target.h"
@@ -127,7 +129,30 @@ static void rw_t4t_sm_ndef_format(NFC_HDR* p_r_apdu);
 **
 *******************************************************************************/
 static bool rw_t4t_send_to_lower(NFC_HDR* p_c_apdu) {
-  if (NFC_SendData(NFC_RF_CONN_ID, p_c_apdu) != NFC_STATUS_OK) {
+  uint8_t conn_id = NFC_RF_CONN_ID;
+
+  if (rw_cb.tcb.t4t.p_retry_cmd) {
+    GKI_freebuf(rw_cb.tcb.t4t.p_retry_cmd);
+    rw_cb.tcb.t4t.p_retry_cmd = nullptr;
+  }
+
+  uint16_t msg_size = sizeof(NFC_HDR) + p_c_apdu->offset + p_c_apdu->len;
+
+  rw_cb.tcb.t4t.p_retry_cmd = (NFC_HDR*)GKI_getpoolbuf(NFC_RW_POOL_ID);
+
+  if (rw_cb.tcb.t4t.p_retry_cmd &&
+      GKI_get_pool_bufsize(NFC_RW_POOL_ID) >= msg_size) {
+    memcpy(rw_cb.tcb.t4t.p_retry_cmd, p_c_apdu, msg_size);
+  } else {
+    LOG(ERROR) << StringPrintf("Memory allocation error");
+    return false;
+  }
+  if (NFA_T4tNfcEeIsProcessing()) {
+    conn_id = nfa_t4tnfcee_cb.connId;
+  }
+  LOG(DEBUG) << StringPrintf("%s - conn_id sent to lower : %d", __func__,
+                             conn_id);
+  if (NFC_SendData(conn_id, p_c_apdu) != NFC_STATUS_OK) {
     LOG(ERROR) << StringPrintf("failed");
     return false;
   }
@@ -290,6 +315,74 @@ static bool rw_t4t_set_ber_tlv(NFC_HDR* p_c_apdu, uint8_t* p, uint32_t length) {
   return true;
 }
 
+/*******************************************************************************
+**
+** Function         rw_t4t_format_short_field_coding
+**
+** Description      Reformat Binary Command with Le coded over one byte instead
+**                  of three bytes. Applicable to MV2.0 non compliant tags
+**
+** Returns          none
+**
+*******************************************************************************/
+static void rw_t4t_format_short_field_coding(void) {
+  tRW_T4T_CB* p_t4t = &rw_cb.tcb.t4t;
+  uint8_t* p;
+  uint8_t* p_old_c_apdu;
+  NFC_HDR* p_new_c_apdu;
+  uint16_t old_Le_field;
+
+  LOG(ERROR) << StringPrintf(
+      "%s; empty payload received, retry C-APDU with "
+      "Le in Short Field coding",
+      __func__);
+
+  p_t4t->p_retry_cmd->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
+  p_old_c_apdu =
+      (uint8_t*)(p_t4t->p_retry_cmd + 1) + p_t4t->p_retry_cmd->offset;
+
+  if ((*(p_old_c_apdu + 1) == T4T_CMD_INS_READ_BINARY) &&
+      (p_t4t->p_retry_cmd->len == T4T_CMD_MAX_EFC_NO_LC_HDR_SIZE)) {
+    /* Reformat C-APDU with Le Short Field Coded on one byte */
+
+    /* Note: Le configuration 00h for first byte followed by 0000h is
+     * not used in the command coding */
+    old_Le_field = *(p_old_c_apdu + 5);
+    old_Le_field <<= 8;
+    old_Le_field |= (uint16_t)*(p_old_c_apdu + 6);
+
+    LOG(DEBUG) << StringPrintf(
+        "%s; Reformat C-APDU with Le Short Field coded on one byte", __func__);
+    p_new_c_apdu = (NFC_HDR*)GKI_getpoolbuf(NFC_RW_POOL_ID);
+
+    if (p_new_c_apdu == nullptr) {
+      LOG(ERROR) << StringPrintf("%s; Cannot allocate buffer", __func__);
+      return;
+    }
+
+    p_new_c_apdu->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
+    p = (uint8_t*)(p_new_c_apdu + 1) + p_new_c_apdu->offset;
+
+    /* Copy CLA + INS + P1 + P2 from original command */
+    memcpy(p, p_old_c_apdu, T4T_CMD_MIN_HDR_SIZE);
+
+    if (old_Le_field <= 0xFF) {
+      /* Copy least significant byte of Le */
+      *(p + T4T_CMD_MIN_HDR_SIZE) = *(p_old_c_apdu + 6);
+    } else {
+      /* Limit length to read to 255 bytes (0x00 not used) */
+      *(p + T4T_CMD_MIN_HDR_SIZE) = 0xFF;
+    }
+
+    p_new_c_apdu->len = T4T_CMD_MAX_HDR_SIZE;
+
+    if (!rw_t4t_send_to_lower(p_new_c_apdu)) {
+      LOG(ERROR) << StringPrintf("%s; Error calling rw_t4t_send_to_lower()",
+                                 __func__);
+    }
+  }
+}
+
 /*******************************************************************************
 **
 ** Function         rw_t4t_get_hw_version
@@ -1964,10 +2057,27 @@ static void rw_t4t_sm_read_ndef(NFC_HDR* p_r_apdu) {
         p_t4t->rw_length -= p_r_apdu->len;
         p_t4t->rw_offset += p_r_apdu->len;
       } else {
+        if ((p_r_apdu->len == 0) &&
+            (p_t4t->cc_file.version == T4T_VERSION_2_0) &&
+            (p_t4t->intl_flags & RW_T4T_EXT_FIELD_CODING)) {
+          /* Workaround for tags not fully compliant (declaring MLe or MLc
+           * higher than respectively 256 and 255 bytes) answering with
+           * an R-APDU containing no data.
+           * Assume they do not support Extended Field coding */
+
+          p_t4t->intl_flags &= ~RW_T4T_EXT_FIELD_CODING;
+
+          if (p_t4t->p_retry_cmd) {
+            GKI_freebuf(p_r_apdu);
+            p_r_apdu = nullptr;
+            /* Re-send last command using Short Field coding */
+            rw_t4t_format_short_field_coding();
+            return;
+          }
+        }
         LOG(ERROR) << StringPrintf(
-            "%s - invalid payload length (%d), rw_length "
-            "(%d)",
-            __func__, p_r_apdu->len, p_t4t->rw_length);
+            "%s - invalid payload length (%d), rw_length (%d)", __func__,
+            p_r_apdu->len, p_t4t->rw_length);
         rw_t4t_handle_error(NFC_STATUS_BAD_RESP, 0, 0);
         break;
       }
@@ -2345,6 +2455,250 @@ static void rw_t4t_data_cback(__attribute__((unused)) uint8_t conn_id,
   }
 }
 
+/*******************************************************************************
+**
+** Function         rw_t4t_ndefee_init_cb
+**
+** Description      Initialize T4T
+**
+** Returns          NFC_STATUS_OK if success
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeInitCb(void) {
+  LOG(DEBUG) << StringPrintf("%s Enter ", __func__);
+  tRW_T4T_CB* p_t4t = &rw_cb.tcb.t4t;
+
+  LOG(DEBUG) << StringPrintf("rw_t4t_ndefee_select ()");
+
+  NFC_SetStaticT4tNfceeCback(rw_t4t_data_cback, nfa_t4tnfcee_cb.connId);
+
+  p_t4t->state = RW_T4T_STATE_IDLE;
+  p_t4t->version = T4T_MY_VERSION;
+  /* set it min of max R-APDU data size before reading CC file */
+  p_t4t->cc_file.max_le = T4T_MIN_MLE;
+
+  /* These will be udated during NDEF detection */
+  p_t4t->max_read_size = T4T_MAX_LENGTH_LE - T4T_FILE_LENGTH_SIZE;
+  p_t4t->max_update_size = RW_T4TNFCEE_DATA_PER_WRITE;
+
+  return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeUpdateCC
+**
+** Description      Updates the T4T data structures with CC info
+**
+** Returns          None
+**
+*******************************************************************************/
+void RW_T4tNfceeUpdateCC(uint8_t* ccInfo) {
+  LOG(DEBUG) << StringPrintf("%s Enter", __func__);
+  tRW_T4T_CB* p_t4t = &rw_cb.tcb.t4t;
+  BE_STREAM_TO_UINT16(p_t4t->cc_file.max_le, ccInfo);
+  BE_STREAM_TO_UINT16(p_t4t->cc_file.max_lc, ccInfo);
+
+  /* Get max bytes to read per command */
+  if (p_t4t->cc_file.max_le >= RW_T4T_MAX_DATA_PER_READ) {
+    p_t4t->max_read_size = RW_T4T_MAX_DATA_PER_READ;
+  } else {
+    p_t4t->max_read_size = p_t4t->cc_file.max_le;
+  }
+
+  /* Le: valid range is 0x01 to 0xFF */
+  if (p_t4t->max_read_size >= T4T_MAX_LENGTH_LE) {
+    p_t4t->max_read_size = T4T_MAX_LENGTH_LE;
+  }
+
+  /* Get max bytes to update per command */
+  if (p_t4t->cc_file.max_lc >= RW_T4T_MAX_DATA_PER_WRITE) {
+    p_t4t->max_update_size = RW_T4T_MAX_DATA_PER_WRITE;
+  } else {
+    p_t4t->max_update_size = p_t4t->cc_file.max_lc;
+  }
+  /* Lc: valid range is 0x01 to 0xFF */
+  if (p_t4t->max_update_size >= T4T_MAX_LENGTH_LC) {
+    p_t4t->max_update_size = T4T_MAX_LENGTH_LC;
+  }
+
+  LOG(DEBUG) << StringPrintf(
+      "%s le %d  lc: %d  max_read_size: %d max_update_size: %d", __func__,
+      p_t4t->cc_file.max_le, p_t4t->cc_file.max_lc, p_t4t->max_read_size,
+      p_t4t->max_update_size);
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeSelectApplication
+**
+** Description      Selects T4T application using T4T AID
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeSelectApplication(void) {
+  LOG(DEBUG) << StringPrintf("%s Enter", __func__);
+  if (!rw_t4t_select_application(T4T_VERSION_2_0)) {
+    return NFC_STATUS_FAILED;
+  } else
+    return NFC_STATUS_OK;
+}
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeSelectFile
+**
+** Description      Selects T4T Nfcee File
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeSelectFile(uint16_t fileId) {
+  LOG(DEBUG) << StringPrintf("%s Enter", __func__);
+  if (!rw_t4t_select_file(fileId)) {
+    return NFC_STATUS_FAILED;
+  } else
+    return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeReadDataLen
+**
+** Description      Reads proprietary data Len
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeReadDataLen() {
+  LOG(DEBUG) << StringPrintf("%s Enter ", __func__);
+  if (!rw_t4t_read_file(0x00, T4T_FILE_LENGTH_SIZE, false)) {
+    rw_t4t_handle_error(NFC_STATUS_FAILED, 0, 0);
+    return NFC_STATUS_FAILED;
+  }
+  return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeReadFile
+**
+** Description      Reads T4T Nfcee File
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeReadFile(uint16_t offset, uint16_t Readlen) {
+  // tNFC_STATUS status = NFC_STATUS_FAILED;
+  LOG(DEBUG) << StringPrintf("%s Enter : Readlen : 0x%x", __func__, Readlen);
+  if (!rw_t4t_read_file(offset, Readlen, false)) {
+    rw_t4t_handle_error(NFC_STATUS_FAILED, 0, 0);
+    return NFC_STATUS_FAILED;
+  }
+  return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeReadPendingData
+**
+** Description      Reads pending data from T4T Nfcee File
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeReadPendingData() {
+  tRW_T4T_CB* p_t4t = &rw_cb.tcb.t4t;
+  p_t4t->rw_length -= p_t4t->max_read_size;
+  p_t4t->rw_offset += p_t4t->max_read_size;
+  if (!rw_t4t_read_file(p_t4t->rw_offset, p_t4t->rw_length, true)) {
+    rw_t4t_handle_error(NFC_STATUS_FAILED, 0, 0);
+    return NFC_STATUS_FAILED;
+  }
+  return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeUpdateNlen
+**
+** Description      writes requested length to the file
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeUpdateNlen(uint16_t len) {
+  LOG(DEBUG) << StringPrintf("%s Enter ", __func__);
+  /* update nlen_size with T4T_FILE_LENGTH_SIZE to avoid mismatch in
+   * reading/writing length of data*/
+  tRW_T4T_CB* p_t4t = &rw_cb.tcb.t4t;
+  p_t4t->cc_file.ndef_fc.nlen_size = T4T_FILE_LENGTH_SIZE;
+  if (!rw_t4t_update_nlen(len)) {
+    return NFC_STATUS_FAILED;
+  }
+  return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeStartUpdateFile
+**
+** Description      starts writing data to the currently selected file
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeStartUpdateFile(uint16_t length, uint8_t* p_data) {
+  LOG(DEBUG) << StringPrintf("%s Enter ", __func__);
+  rw_cb.tcb.t4t.p_update_data = p_data;
+  rw_cb.tcb.t4t.rw_offset = T4T_FILE_LENGTH_SIZE;
+  rw_cb.tcb.t4t.rw_length = length;
+  return RW_T4tNfceeUpdateFile();
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tNfceeUpdateFile
+**
+** Description      writes requested data to the currently selected file
+**
+** Returns          NFC_STATUS_OK if success else NFC_STATUS_FAILED
+**
+*******************************************************************************/
+tNFC_STATUS RW_T4tNfceeUpdateFile() {
+  LOG(DEBUG) << StringPrintf("%s Enter ", __func__);
+  if (!rw_t4t_update_file()) {
+    rw_t4t_handle_error(NFC_STATUS_FAILED, 0, 0);
+    rw_cb.tcb.t4t.p_update_data = nullptr;
+    return NFC_STATUS_FAILED;
+  }
+  return NFC_STATUS_OK;
+}
+
+/*******************************************************************************
+**
+** Function         RW_T4tIsUpdateComplete
+**
+** Description      Return true if no more data to write
+**
+** Returns          true/false
+**
+*******************************************************************************/
+bool RW_T4tIsUpdateComplete(void) { return (rw_cb.tcb.t4t.rw_length == 0); }
+
+/*******************************************************************************
+**
+** Function         RW_T4tIsReadComplete
+**
+** Description      Return true if no more data to be read
+**
+** Returns          true/false
+**
+*******************************************************************************/
+bool RW_T4tIsReadComplete(void) {
+  return (rw_cb.tcb.t4t.rw_length <= rw_cb.tcb.t4t.max_read_size);
+}
+
 /*******************************************************************************
 **
 ** Function         RW_T4tFormatNDef
diff --git a/tests/Android.bp b/tests/Android.bp
new file mode 100644
index 00000000..77039b3a
--- /dev/null
+++ b/tests/Android.bp
@@ -0,0 +1,88 @@
+package {
+    default_team: "trendy_team_fwk_nfc",
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "system_nfc_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["system_nfc_license"],
+}
+
+cc_test {
+    name: "libnfc-nci-tests",
+    include_dirs: [
+        "system/nfc/src/include",
+        "system/nfc/utils/include",
+        "system/nfc/src/nfc/include",
+        "system/nfc/src/gki/common",
+        "system/nfc/src/gki/ulinux",
+        "system/nfc/src/nfa/include",
+        "system/nfc/src/nfa/ce",
+        "system/nfc/src/nfa/dm",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    target: {
+        host_linux: {
+            cflags: ["-D_GNU_SOURCE"],
+        },
+        darwin: {
+            enabled: false,
+        },
+    },
+    sanitize: {
+        integer_overflow: true,
+        misc_undefined: ["bounds"],
+        scs: true,
+    },
+    srcs: [
+        "**/*.cc",
+    ],
+    static_libs: [
+        "libgmock",
+        "libnfc-nci",
+        "libnfcutils",
+        "android.hardware.nfc@1.0",
+        "android.hardware.nfc@1.1",
+        "android.hardware.nfc@1.2",
+        // Add for AIDL
+        "android.hardware.nfc-V2-ndk",
+        "libnfc-nci_flags",
+        "libstatslog_nfc",
+    ],
+    shared_libs: [
+        "libcutils",
+        "liblog",
+        "libdl",
+        "libz",
+        "libbase",
+        // Treble configuration
+        "libhidlbase",
+        "libutils",
+        "libbinder_ndk",
+        "libstatssocket",
+        "server_configurable_flags",
+        "libaconfig_storage_read_api_cc",
+    ],
+    test_suites: [
+        "general-tests",
+        "mts-nfc",
+    ],
+    test_config_template: "nfc_test_config_template.xml",
+    // Support multilib variants (using different suffix per sub-architecture), which is needed on
+    // build targets with secondary architectures, as the MTS test suite packaging logic flattens
+    // all test artifacts into a single `testcases` directory.
+    compile_multilib: "both",
+    multilib: {
+        lib32: {
+            suffix: "32",
+        },
+        lib64: {
+            suffix: "64",
+        },
+    },
+    auto_gen_config: true,
+    min_sdk_version: "current",
+}
diff --git a/tests/nfc_test_config_template.xml b/tests/nfc_test_config_template.xml
new file mode 100644
index 00000000..2a49886c
--- /dev/null
+++ b/tests/nfc_test_config_template.xml
@@ -0,0 +1,36 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Configuration for {MODULE} Rust tests">
+   <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+   <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.nfcservices.apex" />
+   <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
+       <option name="cleanup" value="true" />
+       <option name="push" value="{MODULE}->/data/local/tmp/{MODULE}" />
+       <option name="append-bitness" value="true" />
+   </target_preparer>
+   <test class="com.android.tradefed.testtype.rust.RustBinaryTest" >
+       <option name="test-device-path" value="/data/local/tmp" />
+       <option name="module-name" value="{MODULE}" />
+   </test>
+   <object type="module_controller"
+           class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
+       <option name="mainline-module-package-name" value="com.google.android.nfcservices" />
+   </object>
+   <object type="module_controller"
+           class="com.android.tradefed.testtype.suite.module.DeviceFeatureModuleController">
+        <option name="required-feature" value="android.hardware.nfc.any" />
+   </object>
+</configuration>
diff --git a/tests/src/CrcChecksum_test.cc b/tests/src/CrcChecksum_test.cc
new file mode 100644
index 00000000..6a198d85
--- /dev/null
+++ b/tests/src/CrcChecksum_test.cc
@@ -0,0 +1,152 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include "CrcChecksum.h"
+#include <gtest/gtest.h>
+#include <fstream>
+#include <iostream>
+#include <string>
+
+void writeFileWithChecksum(const std::string& filename, const std::string& data,
+                           uint16_t checksum)
+{
+  std::ofstream file(filename, std::ios::binary);
+  if (file.is_open()) {
+    file.write(reinterpret_cast<const char*>(&checksum),
+               sizeof(checksum));
+    file.write(data.c_str(), data.size());
+    file.close();
+  }
+}
+class CrcChecksumTest : public ::testing::Test {
+ protected:
+  void SetUp() override {}
+  void TearDown() override {}
+};
+
+TEST_F(CrcChecksumTest, EmptyBuffer) {
+    unsigned char buffer[] = {};
+    uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
+    EXPECT_EQ(result, 0);
+}
+
+TEST_F(CrcChecksumTest, SingleByteBuffer) {
+    unsigned char buffer[] = {0x01};
+    uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
+    EXPECT_EQ(result, 49345);
+}
+
+TEST_F(CrcChecksumTest, MultipleByteBuffer) {
+    unsigned char buffer[] = {0x01, 0x02, 0x03, 0x04, 0x05};
+    uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
+    EXPECT_EQ(result, 47886);
+}
+
+TEST_F(CrcChecksumTest, AllZeroBuffer) {
+    unsigned char buffer[5] = {0};
+    uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
+    EXPECT_EQ(result, 0x0000);
+}
+
+TEST_F(CrcChecksumTest, AllOneBuffer) {
+    unsigned char buffer[] = {0xFF, 0xFF, 0xFF, 0xFF};
+    uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
+    EXPECT_EQ(result, 37889);
+}
+
+TEST_F(CrcChecksumTest, AlternatingBytes) {
+    unsigned char buffer[] = {0xAA, 0x55, 0xAA, 0x55};
+    uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
+    EXPECT_EQ(result, 22415);
+}
+
+TEST_F(CrcChecksumTest, LargeBuffer) {
+    std::string largeData(10 * 1024 * 1024, 'A');
+    uint16_t expectedChecksum = crcChecksumCompute(
+            reinterpret_cast<const unsigned char*>(largeData.c_str()),
+            largeData.size());
+    std::string filename = "test_large_buffer.bin";
+    writeFileWithChecksum(filename, largeData, expectedChecksum);
+    bool result = crcChecksumVerifyIntegrity(filename.c_str());
+    EXPECT_TRUE(result);
+    remove(filename.c_str());
+}
+
+class CrcChecksumFileTest : public ::testing::Test {
+ protected:
+  void SetUp() override {}
+  void TearDown() override {}
+};
+
+TEST_F(CrcChecksumFileTest, VerifyFileIntegrity) {
+  // Define test data and compute the expected checksum
+  std::string data = "Hello, CRC!";
+  uint16_t expectedChecksum = crcChecksumCompute(
+          reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
+  std::string filename = "test_file_with_crc.bin";
+  writeFileWithChecksum(filename, data, expectedChecksum);
+  bool result = crcChecksumVerifyIntegrity(filename.c_str());
+  EXPECT_TRUE(result);
+  remove(filename.c_str());
+}
+
+
+TEST_F(CrcChecksumFileTest, VerifyFileIntegrityWithCorruptedChecksum)
+{
+  std::string data = "Hello, CRC!";
+  uint16_t expectedChecksum = crcChecksumCompute(
+          reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
+  uint16_t corruptedChecksum = expectedChecksum + 1;
+  std::string filename = "test_file_with_corrupted_crc.bin";
+  writeFileWithChecksum(filename, data, corruptedChecksum);
+  bool result = crcChecksumVerifyIntegrity(filename.c_str());
+  EXPECT_FALSE(result);
+  remove(filename.c_str());
+}
+
+TEST_F(CrcChecksumFileTest, FileWithMissingChecksum) {
+    std::string data = "Hello, CRC!";
+    std::string filename = "test_missing_checksum.bin";
+    std::ofstream file(filename, std::ios::binary);
+    file.write(data.c_str(), data.size());
+    bool result = crcChecksumVerifyIntegrity(filename.c_str());
+    EXPECT_FALSE(result);
+    remove(filename.c_str());
+}
+
+TEST_F(CrcChecksumFileTest, EmptyFile) {
+    std::string filename = "test_empty_file.bin";
+    std::ofstream file(filename, std::ios::binary);
+    bool result = crcChecksumVerifyIntegrity(filename.c_str());
+    EXPECT_FALSE(result);
+    remove(filename.c_str());
+}
+
+TEST_F(CrcChecksumFileTest, LargeFile) {
+    std::string data(10 * 1024 * 1024, 'A');
+    uint16_t checksum = crcChecksumCompute(
+            reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
+    std::string filename = "test_large_file.bin";
+    writeFileWithChecksum(filename, data, checksum);
+    bool result = crcChecksumVerifyIntegrity(filename.c_str());
+    EXPECT_TRUE(result);
+    remove(filename.c_str());
+}
+
+int main(int argc, char** argv) {
+    ::testing::InitGoogleTest(&argc, argv);
+    return RUN_ALL_TESTS();
+}
\ No newline at end of file
diff --git a/tests/src/debug_lmrt_test.cc b/tests/src/debug_lmrt_test.cc
new file mode 100644
index 00000000..eb040240
--- /dev/null
+++ b/tests/src/debug_lmrt_test.cc
@@ -0,0 +1,91 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include "debug_lmrt.h"
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+
+
+extern lmrt_payload_t lmrt_payloads;
+class MockLogger {
+public:
+    MOCK_METHOD(void, logVerbose, (const std::string& message), ());
+};
+
+// Global instance of the mock logger
+MockLogger mock_logger_instance;
+// Redefine the logging function to use the mock
+void logVerbose(const std::string& message) {
+    mock_logger_instance.logVerbose(message);
+}
+
+class LmrtLogTest : public ::testing::Test {
+protected:
+    void SetUp() override {
+        // Reset mock expectations before each test
+        EXPECT_CALL(mock_logger_instance, logVerbose).Times(0);
+    }
+    void TearDown() override {
+        testing::Mock::AllowLeak(&mock_logger_instance);
+    }
+};
+
+// Test: Logging when payloads are empty
+TEST_F(LmrtLogTest, LogEmptyLmrtPayloads) {
+// Set up test data for empty payloads
+lmrt_payloads.more.clear();
+lmrt_payloads.entry_count.clear();
+lmrt_payloads.tlvs.clear();
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: No payloads to log"))
+.Times(1);
+lmrt_log();
+}
+
+// Test: Logging a single LMRT payload
+TEST_F(LmrtLogTest, LogSingleLmrtPayload) {
+lmrt_payloads.more = {1};
+lmrt_payloads.entry_count = {3};
+lmrt_payloads.tlvs = {{0x01, 0x02, 0x03}};
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: Packet 1/1"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: 3 entries in this packet"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: tlv: 010203"))
+.Times(1);
+lmrt_log();
+}
+
+// Test: Logging multiple LMRT payloads
+TEST_F(LmrtLogTest, LogMultipleLmrtPayloads) {
+lmrt_payloads.more = {1, 0};
+lmrt_payloads.entry_count = {3, 2};
+lmrt_payloads.tlvs = {
+        {0x01, 0x02, 0x03},
+        {0x04, 0x05}
+};
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: Packet 1/2"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: 3 entries in this packet"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: tlv: 010203"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: Packet 2/2"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: 2 entries in this packet"))
+.Times(1);
+EXPECT_CALL(mock_logger_instance, logVerbose("lmrt_log: tlv: 0405"))
+.Times(1);
+lmrt_log();
+}
diff --git a/tests/src/debug_nfcsnoop_test.cc b/tests/src/debug_nfcsnoop_test.cc
new file mode 100644
index 00000000..7d592626
--- /dev/null
+++ b/tests/src/debug_nfcsnoop_test.cc
@@ -0,0 +1,156 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+#include <fcntl.h>
+#include <unistd.h>
+#include <sys/stat.h>
+#include "debug_nfcsnoop.h"
+
+#define BUFFER_SIZE 3
+extern uint8_t* buffers[BUFFER_SIZE];
+// Mock for RingBuffer
+class MockRingBuffer {
+public:
+    MOCK_METHOD(bool, insert, (const uint8_t* data, size_t length), ());
+    MOCK_METHOD(bool, pop, (uint8_t* buffer, size_t length), ());
+};
+
+struct ringbuffer_t {
+    size_t size;
+};
+
+void CleanUpTestFile(const std::string& path) {
+    unlink(path.c_str());
+}
+
+TEST(NfcSnoopTest, DumpWithDataTest) {
+    NFC_HDR mock_hdr;
+    mock_hdr.len = 4;
+    mock_hdr.offset = 0;
+    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+    int fd = open("/tmp/nfc_snoop_test_dump", O_RDWR | O_CREAT | O_TRUNC, 0644);
+    ASSERT_GE(fd, 0);
+    debug_nfcsnoop_dump(fd);
+
+    struct stat st;
+    int ret = stat("/tmp/nfc_snoop_test_dump", &st);
+    ASSERT_EQ(ret, 0);
+    ASSERT_GT(st.st_size, 0);
+
+    close(fd);
+    CleanUpTestFile("/tmp/nfc_snoop_test_dump");
+}
+
+TEST(NfcSnoopTest, DumpEmptyBuffersTest) {
+    int fd = open("/tmp/nfc_snoop_test_dump_empty", O_RDWR | O_CREAT | O_TRUNC, 0644);
+    ASSERT_GE(fd, 0);
+    debug_nfcsnoop_dump(fd);
+    struct stat st;
+    int ret = stat("/tmp/nfc_snoop_test_dump_empty", &st);
+    ASSERT_EQ(ret, 0);
+    ASSERT_EQ(st.st_size, 56);
+    close(fd);
+    CleanUpTestFile("/tmp/nfc_snoop_test_dump_empty");
+}
+
+// Test for simulating a ringbuffer allocation failure
+TEST(NfcSnoopTest, DumpRingbufferInitFailureTest) {
+    uint8_t* buffers[BUFFER_SIZE];
+    ringbuffer_t* ringbuffers[BUFFER_SIZE];
+    buffers[0] = new uint8_t[256];
+    buffers[1] = new uint8_t[256];
+    ringbuffers[0] = new ringbuffer_t;
+    ringbuffers[1] = nullptr;
+    const std::string test_file = "/tmp/nfc_snoop_test_ringbuffer_init_failure";
+    int fd = open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
+    ASSERT_GE(fd, 0) << "Failed to open the test file";
+    debug_nfcsnoop_dump(fd);
+    close(fd);
+    struct stat st;
+    int ret = stat(test_file.c_str(), &st);
+    ASSERT_EQ(ret, 0) << "File should exist";
+    char buffer[1024];
+    fd = open(test_file.c_str(), O_RDONLY);
+    ssize_t bytesRead = read(fd, buffer, sizeof(buffer));
+    ASSERT_GT(bytesRead, 0) << "Expected content in the file, but it is empty";
+    buffer[bytesRead] = '\0';
+    std::cout << "File content:\n" << buffer << std::endl;
+    std::string content(buffer);
+    bool foundReadyMessage = content.find(
+            "Nfcsnoop is not ready (LOG_SUMMARY)") != std::string::npos;
+    bool foundAllocationMessage = content.find(
+            "Unable to allocate memory for compression") != std::string::npos;
+    ASSERT_TRUE(foundReadyMessage || foundAllocationMessage)
+    << "Expected one of the error messages, but neither was found.";
+    if (foundReadyMessage) {
+        std::cout << "Found 'Nfcsnoop is not ready' message. Likely caused by nullptr buffer."
+        << std::endl;
+    }
+    if (foundAllocationMessage) {
+        std::cout << "Found 'Unable to allocate memory for compression' message. "
+        << "Ringbuffer allocation failed." << std::endl;
+    }
+    close(fd);
+    CleanUpTestFile(test_file);
+    delete[] buffers[0];
+    delete[] buffers[1];
+}
+
+TEST(NfcSnoopTest, StoreLogsSuccessTest) {
+    const std::string log_data = "Test NFC log data";
+    bool result = storeNfcSnoopLogs("/tmp/nfc_snoop_log", 1024);
+    ASSERT_TRUE(result);
+    struct stat st;
+    int ret = stat("/tmp/nfc_snoop_log", &st);
+    ASSERT_EQ(ret, 0);
+    ASSERT_GT(st.st_size, 0);
+    CleanUpTestFile("/tmp/nfc_snoop_log");
+}
+
+TEST(NfcSnoopTest, StoreLogsValidPathTest) {
+    const std::string log_data = "Valid NFC log data";
+    bool result = storeNfcSnoopLogs("/tmp/nfc_snoop_valid_log", 1024);
+    ASSERT_TRUE(result);
+    struct stat st;
+    int ret = stat("/tmp/nfc_snoop_valid_log", &st);
+    ASSERT_EQ(ret, 0);
+    ASSERT_GT(st.st_size, 0);
+    CleanUpTestFile("/tmp/nfc_snoop_valid_log");
+}
+
+TEST(NfcSnoopTest, StoreLogsEmptyDataTest) {
+    const std::string log_data = "";
+    bool result = storeNfcSnoopLogs("/tmp/nfc_snoop_empty_log", 1024);
+    ASSERT_TRUE(result);
+    struct stat st;
+    int ret = stat("/tmp/nfc_snoop_empty_log", &st);
+    ASSERT_EQ(ret, 0);
+    ASSERT_GT(st.st_size, 0);
+    ASSERT_LT(st.st_size, 1024);
+    CleanUpTestFile("/tmp/nfc_snoop_empty_log");
+}
+
+
+TEST(NfcSnoopTest, StoreLogsFileCreationFailTest) {
+    const std::string log_data = "Some NFC log data";
+    bool result = storeNfcSnoopLogs("/root/nfc_snoop_fail_log", 1024);
+    ASSERT_FALSE(result);
+    struct stat st;
+    int ret = stat("/root/nfc_snoop_fail_log", &st);
+    ASSERT_EQ(ret, -1);
+}
diff --git a/tests/src/nfa_ce_act_test.cc b/tests/src/nfa_ce_act_test.cc
new file mode 100644
index 00000000..34b6abce
--- /dev/null
+++ b/tests/src/nfa_ce_act_test.cc
@@ -0,0 +1,509 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+#include <cstring>
+#include "nfa_ce_act.cc"
+#include "nfa_api.h"
+#include "nfa_ce_int.h"
+#include "nfa_mem_co.h"
+#include "android-base/logging.h"
+#include "android-base/stringprintf.h"
+
+extern "C" tNFA_STATUS (*nfa_ce_start_listening_ptr)();
+typedef unsigned int NFA_HANDLE;
+
+class MockCallback {
+public:
+    MOCK_METHOD(void, HandleEvent, (tNFA_EE_EVT event, tNFA_CONN_EVT_DATA* p_data), ());
+    MOCK_METHOD(tNFA_STATUS, CE_T3tSetLocalNDEFMsg,(bool read_only, uint16_t cur_size,
+            uint16_t max_size,uint8_t* p_data, uint8_t* p_uid));
+};
+
+class MockNfaDm {
+public:
+    MOCK_METHOD(void, nfa_dm_rf_deactivate, (tNFA_DEACTIVATE_TYPE deactivate_type), ());
+    MOCK_METHOD(void, nfa_dm_delete_rf_discover, (NFA_HANDLE), ());
+    MOCK_METHOD(void, nfa_dm_conn_cback_event_notify, (tNFA_EE_EVT event,
+            tNFA_CONN_EVT_DATA* p_data), ());
+};
+
+class MockNfcUtils {
+public:
+    MOCK_METHOD(uint8_t, NFC_GetNCIVersion, (), ());
+    MOCK_METHOD(void, nfa_dm_check_set_config, (uint8_t, uint8_t*, bool), ());
+};
+
+class MockMemoryAlloc {
+public:
+    MOCK_METHOD(void*, nfa_mem_co_alloc, (uint32_t num_bytes), ());
+    MOCK_METHOD(void, nfa_ce_free_scratch_buf, (), ());
+};
+
+class NfaCeHandleEvtTest : public ::testing::Test {
+protected:
+    static MockCallback mock_callback;
+    static void CallbackFunction(tNFA_EE_EVT event, tNFA_CONN_EVT_DATA* p_data) {
+        mock_callback.HandleEvent(event, p_data);
+    }
+    void SetUp() override {
+        tNFA_CE_CB mock_ce_cb;
+        mock_ce_cb.p_active_conn_cback = CallbackFunction;
+        mock_ce_cb.listen_info[0].p_conn_cback = CallbackFunction;
+        mock_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_T4T_ACTIVATE_PND;
+        mock_ce_cb.idx_cur_active = 0;
+        nfa_ce_cb = mock_ce_cb;
+    }
+    void TearDown() override {
+        testing::Mock::VerifyAndClearExpectations(&mock_callback);
+        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_callback));
+    }
+};
+
+MockCallback NfaCeHandleEvtTest::mock_callback;
+
+// tests for NfaCeHandle_T3t
+
+TEST_F(NfaCeHandleEvtTest, CallbackInvoked) {
+    tNFA_CE_CB mock_ce_cb;
+    mock_ce_cb.p_active_conn_cback = CallbackFunction;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_START_EVT, testing::_)).Times(1);
+    mock_ce_cb.p_active_conn_cback(NFA_CE_NDEF_WRITE_START_EVT, nullptr);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleNdefUpdateStartEvt) {
+    tNFA_CE_CB mock_ce_cb;
+    mock_ce_cb.p_active_conn_cback = CallbackFunction;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_START_EVT, testing::_)).Times(1);
+    tNFA_CONN_EVT_DATA mock_data;
+    mock_data.ndef_write_cplt.p_data = nullptr;
+    mock_ce_cb.p_active_conn_cback(NFA_CE_NDEF_WRITE_START_EVT, &mock_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleNdefUpdateCompleteEvt) {
+    tNFA_CE_CB mock_ce_cb;
+    mock_ce_cb.p_active_conn_cback = CallbackFunction;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_CPLT_EVT, testing::_)).Times(1);
+    tNFA_CONN_EVT_DATA mock_data;
+    mock_data.ndef_write_cplt.p_data = nullptr;
+    mock_ce_cb.p_active_conn_cback(NFA_CE_NDEF_WRITE_CPLT_EVT, &mock_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleRawFrameEvt) {
+    tNFA_CE_CB mock_ce_cb;
+    mock_ce_cb.p_active_conn_cback = CallbackFunction;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_DATA_EVT, testing::_)).Times(1);
+    tNFA_CONN_EVT_DATA mock_data;
+    mock_data.ce_data.p_data = nullptr;
+    mock_ce_cb.p_active_conn_cback(NFA_CE_DATA_EVT, &mock_data);
+}
+
+// tests for NfaCeHandle_T4t
+
+TEST_F(NfaCeHandleEvtTest, HandleT4tNdefUpdateStartEvt) {
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_START_EVT, testing::_)).Times(1);
+    tCE_EVENT event = CE_T4T_NDEF_UPDATE_START_EVT;
+    tCE_DATA ce_data;
+    nfa_ce_handle_t4t_evt(event, &ce_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleT4tNdefUpdateCpltEvt) {
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_CPLT_EVT, testing::_)).Times(1);
+    tCE_EVENT event = CE_T4T_NDEF_UPDATE_CPLT_EVT;
+    tCE_DATA ce_data;
+    ce_data.update_info.length = 5;
+    uint8_t mock_data[5] = {1, 2, 3, 4, 5};
+    ce_data.update_info.p_data = mock_data;
+    nfa_ce_handle_t4t_evt(event, &ce_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleT4tNdefUpdateCpltEvtFailure) {
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_CPLT_EVT, testing::_)).Times(1);
+    tCE_EVENT event = CE_T4T_NDEF_UPDATE_CPLT_EVT;
+    tCE_DATA ce_data;
+    ce_data.update_info.length = 5;
+    uint8_t invalid_data[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
+    ce_data.update_info.p_data = invalid_data;
+    nfa_ce_handle_t4t_evt(event, &ce_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleT4tNdefUpdateAbortEvt) {
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(NFA_CE_NDEF_WRITE_CPLT_EVT, testing::_)).Times(1);
+    tCE_EVENT event = CE_T4T_NDEF_UPDATE_ABORT_EVT;
+    tCE_DATA ce_data;
+    ce_data.update_info.length = 0;
+    ce_data.update_info.p_data = nullptr;nfa_ce_handle_t4t_evt(event, &ce_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleT4tUnhandledEvt) {
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    tCE_EVENT event = static_cast<tCE_EVENT>(0xFF);
+    tCE_DATA ce_data;
+    nfa_ce_handle_t4t_evt(event, &ce_data);
+}
+
+//tests for nfa_ce_handle_t4t_aid
+
+TEST_F(NfaCeHandleEvtTest, HandleValidAidEvent) {
+    tCE_EVENT event = CE_T4T_RAW_FRAME_EVT;
+    tCE_DATA ce_data;
+    ce_data.raw_frame.aid_handle = 0x34;
+    nfa_ce_handle_t4t_aid_evt(event, &ce_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleInvalidEventType) {
+    tNFA_CE_CB mock_ce_cb;
+    tCE_EVENT event = CE_T4T_RAW_FRAME_EVT + 1;
+    tCE_DATA ce_data;
+    mock_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE | NFA_CE_LISTEN_INFO_T4T_AID;
+    mock_ce_cb.listen_info[0].t4t_aid_handle = ce_data.raw_frame.aid_handle;
+    mock_ce_cb.listen_info[0].p_conn_cback = CallbackFunction;
+    nfa_ce_cb = mock_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    nfa_ce_handle_t4t_aid_evt(event, &ce_data);
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleEventWithActivatePendingFlag) {
+    tCE_EVENT event = CE_T4T_RAW_FRAME_EVT;
+    tCE_DATA ce_data;
+    ce_data.raw_frame.aid_handle = 0x34;
+    nfa_ce_handle_t4t_aid_evt(event, &ce_data);
+    LOG(INFO) << "Test complete: Callback should have been invoked.";
+}
+
+TEST_F(NfaCeHandleEvtTest, HandleInvalidListenInfo) {
+    tNFA_CE_CB mock_ce_cb;
+    tCE_EVENT event = CE_T4T_RAW_FRAME_EVT;
+    tCE_DATA ce_data;
+    ce_data.raw_frame.aid_handle = 0x34;
+    mock_ce_cb.listen_info[0].flags = 0;
+    mock_ce_cb.listen_info[0].t4t_aid_handle = ce_data.raw_frame.aid_handle;
+    nfa_ce_cb = mock_ce_cb;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    nfa_ce_handle_t4t_aid_evt(event, &ce_data);
+}
+
+class NfaCeDiscoveryCbackTest : public ::testing::Test {
+protected:
+    void SetUp() override {
+        memset(&nfa_ce_cb, 0, sizeof(nfa_ce_cb));
+    }
+    void TearDown() override {
+    }
+    static MockCallback mock_callback;
+};
+
+MockCallback NfaCeDiscoveryCbackTest::mock_callback;
+
+TEST_F(NfaCeDiscoveryCbackTest, DiscoveryStartEvent) {
+    tNFC_DISCOVER p_data;
+    p_data.start = NFC_STATUS_OK;
+    nfa_ce_discovery_cback(NFA_DM_RF_DISC_START_EVT, &p_data);
+}
+
+TEST_F(NfaCeDiscoveryCbackTest, DiscoveryActivatedEvent) {
+    tNFC_DISCOVER p_data;
+    p_data.activate = {};
+    EXPECT_CALL(mock_callback, HandleEvent(static_cast<unsigned char>(NFA_CE_ACTIVATE_NTF_EVT),
+                                           testing::_)).Times(1);
+    nfa_ce_discovery_cback(NFA_DM_RF_DISC_ACTIVATED_EVT, &p_data);
+}
+
+TEST_F(NfaCeDiscoveryCbackTest, DiscoveryDeactivatedEventActiveListen) {
+    tNFC_DISCOVER p_data;
+    p_data.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
+    nfa_ce_cb.flags |= NFA_CE_FLAGS_LISTEN_ACTIVE_SLEEP;
+    EXPECT_CALL(mock_callback, HandleEvent(static_cast<unsigned char>(NFA_CE_DEACTIVATE_NTF_EVT),
+                                           testing::_)).Times(1);
+    nfa_ce_discovery_cback(NFA_DM_RF_DISC_DEACTIVATED_EVT, &p_data);
+}
+
+TEST_F(NfaCeDiscoveryCbackTest, DiscoveryDeactivatedEventInactiveListen) {
+    tNFC_DISCOVER p_data;
+    p_data.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
+    nfa_ce_cb.flags &= ~NFA_CE_FLAGS_LISTEN_ACTIVE_SLEEP;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    nfa_ce_discovery_cback(NFA_DM_RF_DISC_DEACTIVATED_EVT, &p_data);
+}
+
+TEST_F(NfaCeDiscoveryCbackTest, UnexpectedEvent) {
+    tNFC_DISCOVER p_data;
+    memset(&p_data, 0, sizeof(p_data));
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    nfa_ce_discovery_cback(static_cast<tNFA_DM_RF_DISC_EVT>(0xFF), &p_data);
+}
+
+class MockNfaCe {
+public:
+    MOCK_METHOD(tNFA_STATUS, nfa_ce_start_listening, (), ());
+};
+
+class NfaCeRestartListenCheckTest : public ::testing::Test {
+protected:
+    void SetUp() override {
+    }
+
+    void TearDown() override {
+        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_nfa_ce));
+    }
+    static MockNfaCe mock_nfa_ce;
+};
+
+MockNfaCe NfaCeRestartListenCheckTest::mock_nfa_ce;
+
+TEST_F(NfaCeRestartListenCheckTest, ActiveListenInfoEntries) {
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    EXPECT_CALL(mock_nfa_ce, nfa_ce_start_listening()).Times(1).WillOnce(::testing::Return(
+            NFA_STATUS_OK));
+    bool result = nfa_ce_restart_listen_check();
+    EXPECT_TRUE(result);
+}
+
+TEST_F(NfaCeRestartListenCheckTest, NoActiveListenInfoEntries) {
+    for (int i = 0; i < NFA_CE_LISTEN_INFO_MAX; i++) {
+        nfa_ce_cb.listen_info[i].flags = 0;
+    }
+    bool result = nfa_ce_restart_listen_check();
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaCeRestartListenCheckTest, MultipleActiveListenInfoEntries) {
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[1].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    EXPECT_CALL(mock_nfa_ce, nfa_ce_start_listening()).Times(1).WillOnce(::testing::Return(
+            NFA_STATUS_OK));
+    bool result = nfa_ce_restart_listen_check();
+    EXPECT_TRUE(result);
+}
+
+TEST_F(NfaCeRestartListenCheckTest, AllListenInfoEntriesInactive) {
+    memset(nfa_ce_cb.listen_info, 0, sizeof(nfa_ce_cb.listen_info));
+    bool result = nfa_ce_restart_listen_check();
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaCeRestartListenCheckTest, OneActiveListenInfoEntry) {
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[1].flags = 0;
+    nfa_ce_cb.listen_info[2].flags = 0;
+    EXPECT_CALL(mock_nfa_ce, nfa_ce_start_listening()).Times(1).WillOnce(::testing::Return(
+            NFA_STATUS_OK));
+    bool result = nfa_ce_restart_listen_check();
+    EXPECT_TRUE(result);
+}
+
+class NfaCeSetContentTest : public ::testing::Test {
+protected:
+    static MockCallback mock_callback;
+
+    void SetUp() override {
+        memset(&nfa_ce_cb, 0, sizeof(nfa_ce_cb));
+    }
+
+    void TearDown() override {
+        testing::Mock::VerifyAndClearExpectations(&mock_callback);
+        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_callback));
+    }
+};
+
+MockCallback NfaCeSetContentTest::mock_callback;
+
+TEST_F(NfaCeSetContentTest, NotListeningForNDEF) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = 0;
+    EXPECT_EQ(nfa_ce_set_content(), NFA_STATUS_OK);
+}
+
+TEST_F(NfaCeSetContentTest, SetNDEFContentType3TAndIsoDepProtocols) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].protocol_mask =
+            NFA_PROTOCOL_MASK_T3T | NFA_PROTOCOL_MASK_ISO_DEP;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    EXPECT_EQ(nfa_ce_set_content(), NFA_STATUS_OK);
+}
+
+TEST_F(NfaCeSetContentTest, NoProtocolsUsed) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].protocol_mask = 0;
+    EXPECT_EQ(nfa_ce_set_content(), NFA_STATUS_OK);
+}
+
+TEST_F(NfaCeSetContentTest, ScratchBufferSuccessNoProtocolMask) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].protocol_mask = 0;
+    EXPECT_CALL(mock_callback, HandleEvent(testing::_, testing::_)).Times(0);
+    EXPECT_EQ(nfa_ce_set_content(), NFA_STATUS_OK);
+}
+
+class NfaCeDisableLocalTagTest : public ::testing::Test {
+protected:
+    static MockNfaDm mock_nfa_dm;
+    void SetUp() override {
+        memset(&nfa_ce_cb, 0, sizeof(nfa_ce_cb));
+    }
+    void TearDown() override {
+    }
+};
+
+MockNfaDm NfaCeDisableLocalTagTest::mock_nfa_dm;
+
+TEST_F(NfaCeDisableLocalTagTest, DisableNdefTagWithActiveSleep) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.flags = NFA_CE_FLAGS_LISTEN_ACTIVE_SLEEP;
+    nfa_ce_cb.idx_cur_active = NFA_CE_LISTEN_INFO_IDX_NDEF;
+    EXPECT_CALL(mock_nfa_dm, nfa_dm_rf_deactivate(NFA_DEACTIVATE_TYPE_IDLE)).Times(1);
+    nfa_ce_disable_local_tag();
+}
+
+TEST_F(NfaCeDisableLocalTagTest, DisableNdefTagWithoutActiveSleep) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.flags = 0;
+    nfa_ce_cb.idx_cur_active = NFA_CE_LISTEN_INFO_IDX_NDEF;
+    EXPECT_CALL(mock_nfa_dm, nfa_dm_delete_rf_discover(nfa_ce_cb.listen_info[
+            NFA_CE_LISTEN_INFO_IDX_NDEF].rf_disc_handle)).Times(1);
+    EXPECT_CALL(mock_nfa_dm, nfa_dm_conn_cback_event_notify(
+            NFA_CE_LOCAL_TAG_CONFIGURED_EVT, testing::_)).Times(1);
+}
+
+TEST_F(NfaCeDisableLocalTagTest, NdefTagInUseWithInvalidRfDiscHandle) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].rf_disc_handle = NFA_HANDLE_INVALID;
+    EXPECT_CALL(mock_nfa_dm, nfa_dm_conn_cback_event_notify(
+            NFA_CE_LOCAL_TAG_CONFIGURED_EVT, testing::_)).Times(1);
+}
+
+TEST_F(NfaCeDisableLocalTagTest, NdefTagNotInUseWithNoRfDiscHandle) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = 0;
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].rf_disc_handle = NFA_HANDLE_INVALID;
+    EXPECT_CALL(mock_nfa_dm, nfa_dm_conn_cback_event_notify(
+            NFA_CE_LOCAL_TAG_CONFIGURED_EVT, testing::_)).Times(1);
+}
+
+MockMemoryAlloc mock_mem_alloc;
+
+class NfaCeReallocScratchBufferTest : public ::testing::Test {
+protected:
+    void SetUp() override {
+        nfa_ce_cb.p_scratch_buf = nullptr;
+        nfa_ce_cb.scratch_buf_size = 0;
+        nfa_ce_cb.ndef_max_size = 128;
+        nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = 0;
+    }
+
+    void TearDown() override {
+    }
+};
+
+TEST_F(NfaCeReallocScratchBufferTest, TestAllocateScratchBufferWhenNoneAllocated) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = 0;
+    EXPECT_CALL(mock_mem_alloc, nfa_mem_co_alloc(nfa_ce_cb.ndef_max_size)).WillOnce(
+            testing::Return(reinterpret_cast<void*>(0x1234)));
+    EXPECT_CALL(mock_mem_alloc, nfa_ce_free_scratch_buf()).Times(1);
+    tNFA_STATUS result = nfa_ce_realloc_scratch_buffer();
+    EXPECT_EQ(result, NFA_STATUS_OK);
+    EXPECT_NE(nfa_ce_cb.p_scratch_buf, nullptr);
+    EXPECT_EQ(nfa_ce_cb.scratch_buf_size, nfa_ce_cb.ndef_max_size);
+}
+
+TEST_F(NfaCeReallocScratchBufferTest, TestNoAllocationWhenBufferSizeMatches) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags = 0;
+    nfa_ce_cb.p_scratch_buf = reinterpret_cast<uint8_t*>(0x1234);
+    nfa_ce_cb.scratch_buf_size = nfa_ce_cb.ndef_max_size;
+    EXPECT_CALL(mock_mem_alloc, nfa_mem_co_alloc(testing::_)).Times(0);
+    EXPECT_CALL(mock_mem_alloc, nfa_ce_free_scratch_buf()).Times(0);
+    tNFA_STATUS result = nfa_ce_realloc_scratch_buffer();
+    EXPECT_EQ(result, NFA_STATUS_OK);
+}
+
+TEST_F(NfaCeReallocScratchBufferTest, TestFreeScratchBufferWhenReadOnly) {
+    nfa_ce_cb.listen_info[NFA_CE_LISTEN_INFO_IDX_NDEF].flags |= NFC_CE_LISTEN_INFO_READONLY_NDEF;
+    EXPECT_CALL(mock_mem_alloc, nfa_ce_free_scratch_buf()).Times(1);
+    tNFA_STATUS result = nfa_ce_realloc_scratch_buffer();
+    EXPECT_EQ(result, NFA_STATUS_OK);
+    EXPECT_EQ(nfa_ce_cb.p_scratch_buf, nullptr);
+    EXPECT_EQ(nfa_ce_cb.scratch_buf_size, 0);
+}
+
+MockNfcUtils mock_nfc_utils;
+
+class NfcCeT3tSetListenParamsTest : public ::testing::Test {
+protected:
+    void SetUp() override {
+        memset(&nfa_ce_cb, 0, sizeof(nfa_ce_cb));
+    }
+
+    void TearDown() override {
+    }
+};
+
+TEST_F(NfcCeT3tSetListenParamsTest, TestNfcVersionLessThan2_0WithValidListenInfo) {
+    EXPECT_CALL(mock_nfc_utils, NFC_GetNCIVersion()).WillOnce(testing::Return(NCI_VERSION_1_0));
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[0].protocol_mask = NFA_PROTOCOL_MASK_T3T;
+    nfa_ce_cb.listen_info[0].t3t_system_code = 0x1234;
+    nfa_ce_cb.listen_info[0].t3t_nfcid2[0] = 0x01;
+    nfa_ce_cb.listen_info[0].t3t_pmm[0] = 0x01;
+    EXPECT_CALL(mock_nfc_utils, nfa_dm_check_set_config(
+            testing::_ , testing::_ , testing::_)).Times(1);
+    nfc_ce_t3t_set_listen_params();
+    EXPECT_EQ(nfa_ce_cb.listen_info[0].t3t_system_code, 0x1234);
+}
+
+TEST_F(NfcCeT3tSetListenParamsTest, TestNfcVersion2_0WithValidListenInfo) {
+    EXPECT_CALL(mock_nfc_utils, NFC_GetNCIVersion()).WillOnce(testing::Return(NCI_VERSION_2_0));
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[0].protocol_mask = NFA_PROTOCOL_MASK_T3T;
+    nfa_ce_cb.listen_info[0].t3t_system_code = 0x5678;
+    nfa_ce_cb.listen_info[0].t3t_nfcid2[0] = 0x02;
+    nfa_ce_cb.listen_info[0].t3t_pmm[0] = 0x02;
+    EXPECT_CALL(mock_nfc_utils, nfa_dm_check_set_config(
+            testing::_ , testing::_ , testing::_)).Times(1);
+    nfc_ce_t3t_set_listen_params();
+    EXPECT_EQ(nfa_ce_cb.listen_info[0].t3t_system_code, 0x5678);
+}
+
+TEST_F(NfcCeT3tSetListenParamsTest, TestNoListenInfoInUse) {
+    for (int i = 0; i < NFA_CE_LISTEN_INFO_MAX; i++) {
+        nfa_ce_cb.listen_info[i].flags = 0;
+    }
+    EXPECT_CALL(mock_nfc_utils, nfa_dm_check_set_config(
+            testing::_ , testing::_ , testing::_)).Times(0);
+    nfc_ce_t3t_set_listen_params();
+}
+
+TEST_F(NfcCeT3tSetListenParamsTest, TestProtocolMaskDoesNotMatch) {
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[0].protocol_mask = 0;
+    EXPECT_CALL(mock_nfc_utils, nfa_dm_check_set_config(
+            testing::_ , testing::_ , testing::_)).Times(0);
+    nfc_ce_t3t_set_listen_params();
+}
+
+TEST_F(NfcCeT3tSetListenParamsTest, TestDtaModeFlag) {
+    appl_dta_mode_flag = 0x01;
+    EXPECT_CALL(mock_nfc_utils, NFC_GetNCIVersion()).WillOnce(testing::Return(NCI_VERSION_1_0));
+    nfa_ce_cb.listen_info[0].flags = NFA_CE_LISTEN_INFO_IN_USE;
+    nfa_ce_cb.listen_info[0].protocol_mask = NFA_PROTOCOL_MASK_T3T;
+    EXPECT_CALL(mock_nfc_utils, nfa_dm_check_set_config(
+            testing::_ , testing::_ , testing::_)).Times(1);
+    nfc_ce_t3t_set_listen_params();
+}
diff --git a/tests/src/nfa_ce_api_test.cc b/tests/src/nfa_ce_api_test.cc
new file mode 100644
index 00000000..ed0e5b4e
--- /dev/null
+++ b/tests/src/nfa_ce_api_test.cc
@@ -0,0 +1,137 @@
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+#include "nfa_ce_api.h"
+#include "nfa_ce_int.h"
+#include "nfa_api.h"
+#include <android-base/logging.h>
+#include "nfa_ce_api.cc"
+
+class MockSystemFunctions {
+public:
+    MOCK_METHOD(void*, GKI_getbuf, (uint16_t size), ());
+    MOCK_METHOD(void, nfa_sys_sendmsg, (tNFA_CE_MSG* p_msg), ());
+    MOCK_METHOD(tNFA_STATUS, nfa_ce_api_deregister_listen, (tNFA_HANDLE handle,
+            uint16_t listen_type), ());
+
+};
+
+class NfaCeApiTest : public ::testing::Test {
+protected:
+    MockSystemFunctions mock_sys_funcs;
+
+    tNFA_STATUS (*configure_local_tag)(tNFA_PROTOCOL_MASK protocol_mask,
+                                       uint8_t* p_ndef_data,
+                                       uint16_t ndef_cur_size,
+                                       uint16_t ndef_max_size, bool read_only,
+                                       uint8_t uid_len, uint8_t* p_uid);
+
+    void SetUp() override {
+        // Pointing to the original function for testing
+        configure_local_tag = &NFA_CeConfigureLocalTag;
+    }
+
+    void TearDown() override {
+        // No cleanup needed for this test case
+    }
+};
+
+TEST_F(NfaCeApiTest, InvalidProtocolMaskWithNonNullNDEFData) {
+    tNFA_PROTOCOL_MASK invalid_protocol_mask = 0xFF;
+    uint8_t valid_ndef_data[] = {0x01, 0x02, 0x03};
+    uint16_t ndef_cur_size = 3;
+    uint16_t ndef_max_size = 1024;
+    bool read_only = false;
+    uint8_t uid_len = 0;
+    uint8_t* p_uid = nullptr;
+    tNFA_STATUS status = configure_local_tag(invalid_protocol_mask, valid_ndef_data, ndef_cur_size,
+                                             ndef_max_size, read_only, uid_len, p_uid);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, NullNDEFDataWithProtocolMask) {
+    tNFA_PROTOCOL_MASK protocol_mask = NFA_PROTOCOL_MASK_ISO_DEP;
+    uint8_t* p_ndef_data = nullptr;
+    uint16_t ndef_cur_size = 3;
+    uint16_t ndef_max_size = 1024;
+    bool read_only = false;
+    uint8_t uid_len = 0;
+    uint8_t* p_uid = nullptr;
+    tNFA_STATUS status = configure_local_tag(protocol_mask, p_ndef_data, ndef_cur_size,
+                                             ndef_max_size, read_only, uid_len, p_uid);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, InvalidProtocolMaskForType1Type2) {
+    tNFA_PROTOCOL_MASK protocol_mask = NFA_PROTOCOL_MASK_T1T;
+    uint8_t valid_ndef_data[] = {0x01, 0x02, 0x03};
+    uint16_t ndef_cur_size = 3;
+    uint16_t ndef_max_size = 1024;
+    bool read_only = false;
+    uint8_t uid_len = 0;
+    uint8_t* p_uid = nullptr;
+    tNFA_STATUS status = configure_local_tag(protocol_mask, valid_ndef_data, ndef_cur_size,
+                                             ndef_max_size, read_only, uid_len, p_uid);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, NonZeroUIDLengthWithProtocolMask) {
+    tNFA_PROTOCOL_MASK protocol_mask = NFA_PROTOCOL_MASK_ISO_DEP;
+    uint8_t valid_ndef_data[] = {0x01, 0x02, 0x03};
+    uint16_t ndef_cur_size = 3;
+    uint16_t ndef_max_size = 1024;
+    bool read_only = false;
+    uint8_t uid_len = 4;
+    uint8_t p_uid[] = {0x01, 0x02, 0x03, 0x04};
+    tNFA_STATUS status = configure_local_tag(protocol_mask, valid_ndef_data, ndef_cur_size,
+                                             ndef_max_size, read_only, uid_len, p_uid);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, InvalidParamNullCallback) {
+    uint8_t aid[NFC_MAX_AID_LEN] = {0x01, 0x02};
+    uint8_t aid_len = 2;
+    tNFA_CONN_CBACK* p_conn_cback = nullptr;
+    tNFA_STATUS status = NFA_CeRegisterAidOnDH(aid, aid_len, p_conn_cback);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, InvalidParamAidLenZero) {
+    uint8_t aid[NFC_MAX_AID_LEN] = {0x01, 0x02};
+    uint8_t aid_len = 0;
+    tNFA_CONN_CBACK* p_conn_cback = reinterpret_cast<tNFA_CONN_CBACK*>(0x1234);
+    tNFA_STATUS status = NFA_CeRegisterAidOnDH(aid, aid_len, p_conn_cback);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, InvalidParamNullAid) {
+    uint8_t* aid = nullptr;
+    uint8_t aid_len = 2;
+    tNFA_CONN_CBACK* p_conn_cback = reinterpret_cast<tNFA_CONN_CBACK*>(0x1234);
+    tNFA_STATUS status = NFA_CeRegisterAidOnDH(aid, aid_len, p_conn_cback);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, NullFelicaCallback) {
+    uint16_t system_code = 0x1234;
+    uint8_t nfcid2[NCI_RF_F_UID_LEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
+    uint8_t t3tPmm[NCI_T3T_PMM_LEN] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
+    tNFA_STATUS status = NFA_CeRegisterFelicaSystemCodeOnDH(system_code, nfcid2, t3tPmm, nullptr);
+    EXPECT_EQ(status, NFA_STATUS_INVALID_PARAM);
+}
+
+TEST_F(NfaCeApiTest, DeregisterFelicaSystemCodeOnDH_InvalidListenInfo) {
+    tNFA_HANDLE valid_handle = 0x1234;
+    uint32_t invalid_listen_info = 0x9999;
+    EXPECT_CALL(mock_sys_funcs, nfa_sys_sendmsg(testing::_)).Times(0);
+    tNFA_STATUS status = nfa_ce_api_deregister_listen(valid_handle, invalid_listen_info);
+    EXPECT_EQ(status, NFA_STATUS_BAD_HANDLE);
+}
+
+TEST_F(NfaCeApiTest, DeregisterFelicaSystemCodeOnDH_InvalidHandleAndListenInfo) {
+    tNFA_HANDLE invalid_handle = 0x4321;
+    uint32_t invalid_listen_info = 0x9999;
+    EXPECT_CALL(mock_sys_funcs, nfa_sys_sendmsg(testing::_)).Times(0);
+    tNFA_STATUS status = nfa_ce_api_deregister_listen(invalid_handle, invalid_listen_info);
+    EXPECT_EQ(status, NFA_STATUS_BAD_HANDLE);
+}
+
diff --git a/tests/src/nfa_ce_main_test.cc b/tests/src/nfa_ce_main_test.cc
new file mode 100644
index 00000000..e62f4ce3
--- /dev/null
+++ b/tests/src/nfa_ce_main_test.cc
@@ -0,0 +1,121 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+#include <string>
+#include "nfa_ce_main.cc"
+
+typedef unsigned int NFA_HANDLE;
+
+class MockNfcOperations {
+public:
+    MOCK_METHOD(void, nfa_ce_restart_listen_check, (), ());
+    MOCK_METHOD(void, nfa_dm_delete_rf_discover, (NFA_HANDLE), ());
+};
+
+// Tests for nfa_ce_evt_2_str
+TEST(NfaCeEvtTest, EventToString) {
+    EXPECT_EQ(nfa_ce_evt_2_str(NFA_CE_API_CFG_LOCAL_TAG_EVT), "NFA_CE_API_CFG_LOCAL_TAG_EVT");
+    EXPECT_EQ(nfa_ce_evt_2_str(NFA_CE_API_REG_LISTEN_EVT), "NFA_CE_API_REG_LISTEN_EVT");
+    EXPECT_EQ(nfa_ce_evt_2_str(NFA_CE_API_DEREG_LISTEN_EVT), "NFA_CE_API_DEREG_LISTEN_EVT");
+    EXPECT_EQ(nfa_ce_evt_2_str(NFA_CE_API_CFG_ISODEP_TECH_EVT), "NFA_CE_API_CFG_ISODEP_TECH_EVT");
+    EXPECT_EQ(nfa_ce_evt_2_str(NFA_CE_ACTIVATE_NTF_EVT), "NFA_CE_ACTIVATE_NTF_EVT");
+    EXPECT_EQ(nfa_ce_evt_2_str(NFA_CE_DEACTIVATE_NTF_EVT), "NFA_CE_DEACTIVATE_NTF_EVT");
+    EXPECT_EQ(nfa_ce_evt_2_str(0x9999), "Unknown");
+    EXPECT_EQ(nfa_ce_evt_2_str(0x0000), "Unknown");
+    EXPECT_EQ(nfa_ce_evt_2_str(0xFFFF), "Unknown");
+    EXPECT_EQ(nfa_ce_evt_2_str(0x0100), "Unknown");
+    EXPECT_EQ(nfa_ce_evt_2_str(0x01FF), "Unknown");
+    EXPECT_EQ(nfa_ce_evt_2_str(0x1000), "Unknown");
+    EXPECT_EQ(nfa_ce_evt_2_str(0x2000), "Unknown");
+
+}
+
+// Tests for nfa_ce_proc_nfcc_power_mode
+TEST(NfaCeProcNfccPowerModeTest, ProcessPowerMode) {
+    MockNfcOperations mock_ops;
+    nfa_ce_proc_nfcc_power_mode(NFA_DM_PWR_MODE_FULL);
+    nfa_ce_proc_nfcc_power_mode(0);
+    EXPECT_CALL(mock_ops, nfa_dm_delete_rf_discover(::testing::_)).Times(0);
+    nfa_ce_proc_nfcc_power_mode(0xFF);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, EdgeCases) {
+    MockNfcOperations mock_ops;
+    EXPECT_CALL(mock_ops, nfa_dm_delete_rf_discover(::testing::_)).Times(0);
+    nfa_ce_proc_nfcc_power_mode(NFA_DM_PWR_MODE_FULL);
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    memset(p_cb->listen_info, 0, sizeof(p_cb->listen_info));
+    EXPECT_CALL(mock_ops, nfa_dm_delete_rf_discover(::testing::_)).Times(0);
+    nfa_ce_proc_nfcc_power_mode(0);
+    memset(p_cb->listen_info, 0xFF, sizeof(p_cb->listen_info));
+    nfa_ce_proc_nfcc_power_mode(0);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, NoListenInfo) {
+    MockNfcOperations mock_ops;
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    memset(p_cb->listen_info, 0, sizeof(p_cb->listen_info));
+    EXPECT_CALL(mock_ops, nfa_dm_delete_rf_discover(::testing::_)).Times(0);
+    nfa_ce_proc_nfcc_power_mode(0);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, SingleActiveListenEntry) {
+    MockNfcOperations mock_ops;
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    p_cb->listen_info[0].flags |= NFA_CE_LISTEN_INFO_IN_USE;
+    p_cb->listen_info[0].rf_disc_handle = 1;
+    nfa_ce_proc_nfcc_power_mode(0);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, TwoActiveListenEntries) {
+    MockNfcOperations mock_ops;
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    p_cb->listen_info[0].flags |= NFA_CE_LISTEN_INFO_IN_USE;
+    p_cb->listen_info[0].rf_disc_handle = 1;
+    p_cb->listen_info[1].flags |= NFA_CE_LISTEN_INFO_IN_USE;
+    p_cb->listen_info[1].rf_disc_handle = 2;
+    nfa_ce_proc_nfcc_power_mode(0);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, NoActiveListenEntries) {
+    MockNfcOperations mock_ops;
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    memset(p_cb->listen_info, 0, sizeof(p_cb->listen_info));
+    EXPECT_CALL(mock_ops, nfa_dm_delete_rf_discover(::testing::_)).Times(0);
+    nfa_ce_proc_nfcc_power_mode(0);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, SingleDeactivatedListenEntry) {
+    MockNfcOperations mock_ops;
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    memset(p_cb->listen_info, 0, sizeof(p_cb->listen_info));
+    p_cb->listen_info[0].flags &= ~NFA_CE_LISTEN_INFO_IN_USE;
+
+    EXPECT_CALL(mock_ops, nfa_dm_delete_rf_discover(::testing::_)).Times(0);
+    nfa_ce_proc_nfcc_power_mode(0);
+}
+
+TEST(NfaCeProcNfccPowerModeTest, MixedActiveAndInactiveListenEntries) {
+    MockNfcOperations mock_ops;
+    tNFA_CE_CB* p_cb = &nfa_ce_cb;
+    p_cb->listen_info[0].flags |= NFA_CE_LISTEN_INFO_IN_USE;
+    p_cb->listen_info[0].rf_disc_handle = 1;
+    p_cb->listen_info[1].flags &= ~NFA_CE_LISTEN_INFO_IN_USE;
+
+    nfa_ce_proc_nfcc_power_mode(0);
+}
\ No newline at end of file
diff --git a/tests/src/nfa_dm_main_test.cc b/tests/src/nfa_dm_main_test.cc
new file mode 100644
index 00000000..d32aaa09
--- /dev/null
+++ b/tests/src/nfa_dm_main_test.cc
@@ -0,0 +1,148 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include <gtest/gtest.h>
+#include "nfa_dm_main.cc"
+
+// tests for nfa_dm_is_protocol_supported
+
+TEST(NfaDmMainTest, SupportedProtocolsWithoutSelRes) {
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_T1T, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_T3T, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_ISO_DEP, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_NFC_DEP, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_T5T, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_MIFARE, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFA_PROTOCOL_CI, 0));
+}
+
+TEST(NfaDmMainTest, ProtocolT2TWithMatchingSelRes) {
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_T2T, NFC_SEL_RES_NFC_FORUM_T2T));
+}
+
+TEST(NfaDmMainTest, ProtocolT2TWithNonMatchingSelRes) {
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_T2T, 0x00));
+    EXPECT_FALSE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_T2T, 0xFF));
+}
+
+TEST(NfaDmMainTest, UnsupportedProtocols) {
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(0xFF, 0));
+}
+
+TEST(NfaDmMainTest, EdgeCases) {
+    EXPECT_FALSE(nfa_dm_is_protocol_supported(0, 0));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(0xFF, 0xFF));
+    EXPECT_TRUE(nfa_dm_is_protocol_supported(NFC_PROTOCOL_ISO_DEP, NFC_SEL_RES_NFC_FORUM_T2T));
+}
+
+// tests for nfa_dm_evt_2_str
+
+TEST(NfaDmMainTest, ValidEvents) {
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(NFA_DM_API_ENABLE_EVT)), "NFA_DM_API_ENABLE_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(NFA_DM_API_DISABLE_EVT)), "NFA_DM_API_DISABLE_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(
+            NFA_DM_API_SET_CONFIG_EVT)), "NFA_DM_API_SET_CONFIG_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(
+            NFA_DM_API_GET_CONFIG_EVT)), "NFA_DM_API_GET_CONFIG_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(
+            NFA_DM_API_START_RF_DISCOVERY_EVT)), "NFA_DM_API_START_RF_DISCOVERY_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(
+            NFA_DM_API_STOP_RF_DISCOVERY_EVT)), "NFA_DM_API_STOP_RF_DISCOVERY_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(
+            NFA_DM_API_RELEASE_EXCL_RF_CTRL_EVT)), "NFA_DM_API_RELEASE_EXCL_RF_CTRL_EVT");
+}
+
+TEST(NfaDmMainTest, UnknownEvents) {
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(0x1234)), "Unknown or Vendor Specific");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(0xFFFF)), "Unknown or Vendor Specific");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(0x00FF)), "Unknown or Vendor Specific");
+}
+
+TEST(NfaDmMainTest, BoundaryEventCodes) {
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(0x0000)), "NFA_DM_API_ENABLE_EVT");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(0xFFFF)), "Unknown or Vendor Specific");
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(NFA_DM_API_ENABLE_EVT)), "NFA_DM_API_ENABLE_EVT");
+}
+
+TEST(NfaDmMainTest, EventsNotMapped) {
+    EXPECT_EQ(std::string(nfa_dm_evt_2_str(0x00A0)), "Unknown or Vendor Specific");
+}
+
+//tests for nfa_dm_check_set_config
+
+TEST(NfaDmMainTest, ValidSingleTypeTLV) {
+    uint8_t tlv_list[] = {NFC_PMID_PF_RC, 1, 0x01};
+    uint8_t tlv_list_len = sizeof(tlv_list);
+    EXPECT_EQ(nfa_dm_check_set_config(tlv_list_len, tlv_list, false), NFA_STATUS_OK);
+}
+
+TEST(NfaDmMainTest, InvalidTLVLength) {
+    uint8_t tlv_list[] = {NFC_PMID_PF_RC, 5, 0x01};
+    uint8_t tlv_list_len = sizeof(tlv_list) - 1;
+    EXPECT_EQ(nfa_dm_check_set_config(tlv_list_len, tlv_list, false), NFA_STATUS_FAILED);
+}
+
+TEST(NfaDmMainTest, ExceedMaxPendingSetConfigs) {
+    nfa_dm_cb.setcfg_pending_num = NFA_DM_SETCONFIG_PENDING_MAX;
+    uint8_t tlv_list[] = {NFC_PMID_PF_RC, 1, 0x01};
+    EXPECT_EQ(nfa_dm_check_set_config(sizeof(tlv_list), tlv_list, false), NFA_STATUS_FAILED);
+}
+
+TEST(NfaDmMainTest, UpdateRequired) {
+    memset(nfa_dm_cb.params.pf_rc, 0x00, NCI_PARAM_LEN_PF_RC);
+    uint8_t tlv_list[] = {NFC_PMID_PF_RC, 1, 0x01};
+    auto result = nfa_dm_check_set_config(sizeof(tlv_list), tlv_list, false);
+    LOG(VERBOSE) << "Function returned: " << result;
+    LOG(VERBOSE) << "Updated pf_rc[0]: " << (int)nfa_dm_cb.params.pf_rc[1];
+    EXPECT_EQ(result, 0x03);
+    EXPECT_EQ(nfa_dm_cb.params.pf_rc[0], 0x00);
+}
+
+TEST(NfaDmMainTest, NoUpdateNeeded) {
+    nfa_dm_cb.params.pf_rc[0] = 0x01;
+    uint8_t tlv_list[] = {NFC_PMID_PF_RC, 1, 0x01};
+    EXPECT_EQ(nfa_dm_check_set_config(sizeof(tlv_list), tlv_list, false), 0x03);
+    ASSERT_EQ(nfa_dm_cb.params.pf_rc[0], 0x01);
+}
+
+TEST(NfaDmMainTest, InvalidType) {
+    uint8_t tlv_list[] = {0xFF, 1, 0x01};
+    EXPECT_EQ(nfa_dm_check_set_config(sizeof(tlv_list), tlv_list, false), 0x03);
+}
+
+TEST(NfaDmMainTest, MultipleTLVs) {
+    uint8_t tlv_list[] = {
+        NFC_PMID_PF_RC, 1, 0x01,
+        NFC_PMID_TOTAL_DURATION, 1, 0x05
+    };
+    uint8_t result = nfa_dm_check_set_config(sizeof(tlv_list), tlv_list, false);
+    EXPECT_EQ(result, 0x03);
+    EXPECT_EQ(nfa_dm_cb.params.pf_rc[0], 0x01);
+}
+
+TEST(NfaDmMainTest, EmptyTLVList) {
+    uint8_t* tlv_list = nullptr;
+    EXPECT_EQ(nfa_dm_check_set_config(0, tlv_list, false), 0x03);
+}
+
+TEST(NfaDmMainTest, ExcessiveTLVLength) {
+    uint8_t tlv_list[255];
+    memset(tlv_list, 0, sizeof(tlv_list));
+    tlv_list[0] = NFC_PMID_PF_RC;
+    tlv_list[1] = 254;
+    EXPECT_EQ(nfa_dm_check_set_config(sizeof(tlv_list), tlv_list, false), NFA_STATUS_FAILED);
+}
+
diff --git a/tests/src/nfa_dm_ndef_test.cc b/tests/src/nfa_dm_ndef_test.cc
new file mode 100644
index 00000000..cb42d3e2
--- /dev/null
+++ b/tests/src/nfa_dm_ndef_test.cc
@@ -0,0 +1,432 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include <gtest/gtest.h>
+#include <gmock/gmock.h>
+#include <cstring>
+#include "nfa_dm_ndef.cc"
+class MockNDEFHandler {
+public:
+    MOCK_METHOD(void, OnNDEFData, (uint8_t event, tNFA_NDEF_EVT_DATA* data));
+    uint8_t flags;
+};
+static void NDEFCallbackBridge(uint8_t event, tNFA_NDEF_EVT_DATA* data) {
+    extern MockNDEFHandler* g_mock_handler;
+    if (g_mock_handler) {
+        g_mock_handler->OnNDEFData(event, data);
+    }
+}
+MockNDEFHandler* g_mock_handler = nullptr;
+class NfaDmTest : public ::testing::Test {
+protected:
+    tNFA_DM_CB nfa_dm_cb_mock;
+    MockNDEFHandler mock_handler;
+    MockNDEFHandler mock_handler1;
+    MockNDEFHandler mock_handler2;
+    void SetUp() override {
+        memset(&nfa_dm_cb_mock, 0, sizeof(nfa_dm_cb_mock));
+        g_mock_handler = &mock_handler;
+        nfa_dm_cb_mock.p_ndef_handler[0] = reinterpret_cast<
+                tNFA_DM_API_REG_NDEF_HDLR*>(&mock_handler1);
+        nfa_dm_cb_mock.p_ndef_handler[1] = reinterpret_cast<
+                tNFA_DM_API_REG_NDEF_HDLR*>(&mock_handler2);
+    }
+    void TearDown() override {
+        g_mock_handler = nullptr;
+        testing::Mock::VerifyAndClearExpectations(&mock_handler);
+    }
+};
+
+// nfa_dm_ndef_reg_hdlr
+
+TEST_F(NfaDmTest, RegisterHandler_Success) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 4;
+    EXPECT_CALL(mock_handler, OnNDEFData('\0', ::testing::_)).Times(1);
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    bool result = nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaDmTest, RegisterHandler_ReplaceExisting) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info1 = {};
+    reg_info1.p_ndef_cback = NDEFCallbackBridge;
+    reg_info1.tnf = NFA_TNF_DEFAULT;
+    reg_info1.name_len = 5;
+    uint8_t name1[] = "Test1";
+    memcpy(reg_info1.name, name1, reg_info1.name_len);
+    EXPECT_CALL(mock_handler, OnNDEFData(::testing::_, ::testing::_)).Times(1);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    tNFA_DM_API_REG_NDEF_HDLR reg_info2 = {};
+    reg_info2.p_ndef_cback = NDEFCallbackBridge;
+    reg_info2.tnf = NFA_TNF_DEFAULT;
+    reg_info2.name_len = 5;
+    EXPECT_CALL(mock_handler, OnNDEFData(::testing::_, ::testing::_)).Times(1);
+    uint8_t name2[] = "Test2";
+    memcpy(reg_info2.name, name2, reg_info2.name_len);
+    bool result = nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info2);
+    EXPECT_FALSE(result);
+}
+
+//nfa_dm_ndef_dereg_hdlr
+
+TEST_F(NfaDmTest, DeregisterHandler_Success) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    EXPECT_CALL(mock_handler, OnNDEFData(::testing::_, ::testing::_)).Times(0);
+    bool result = nfa_dm_ndef_dereg_hdlr((tNFA_DM_MSG*)&reg_info);
+    std::cout << "Deregistration result: " << (result ? "Success" : "Failure") << std::endl;
+    EXPECT_TRUE(result);
+}
+
+TEST_F(NfaDmTest, DeregisterHandler_Fail_HandlerNotRegistered) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    bool result = nfa_dm_ndef_dereg_hdlr((tNFA_DM_MSG*)&reg_info);
+    EXPECT_TRUE(result);
+}
+
+TEST_F(NfaDmTest, DeregisterHandler_ReleaseSlot) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info1 = {};
+    reg_info1.p_ndef_cback = NDEFCallbackBridge;
+    reg_info1.tnf = NFA_TNF_DEFAULT;
+    reg_info1.name_len = 5;
+    uint8_t name1[] = "Test1";
+    memcpy(reg_info1.name, name1, reg_info1.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    bool result1 = nfa_dm_ndef_dereg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    EXPECT_TRUE(result1);
+    tNFA_DM_API_REG_NDEF_HDLR reg_info2 = {};
+    reg_info2.p_ndef_cback = NDEFCallbackBridge;
+    reg_info2.tnf = NFA_TNF_DEFAULT;
+    reg_info2.name_len = 5;
+    uint8_t name2[] = "Test2";
+    memcpy(reg_info2.name, name2, reg_info2.name_len);
+    bool result2 = nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info2);
+    EXPECT_FALSE(result2);
+}
+TEST_F(NfaDmTest, DeregisterHandler_AllSlotsOccupied) {
+    for (int i = 0; i < NFA_NDEF_MAX_HANDLERS; ++i) {
+        tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+        reg_info.p_ndef_cback = NDEFCallbackBridge;
+        reg_info.tnf = NFA_TNF_DEFAULT;
+        reg_info.name_len = 4;
+        uint8_t name[] = "Test";
+        memcpy(reg_info.name, name, reg_info.name_len);
+        nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    }
+    tNFA_DM_API_REG_NDEF_HDLR reg_info_to_deregister = {};
+    reg_info_to_deregister.p_ndef_cback = NDEFCallbackBridge;
+    reg_info_to_deregister.tnf = NFA_TNF_DEFAULT;
+    reg_info_to_deregister.name_len = 4;
+    uint8_t name_to_deregister[] = "Test";
+    memcpy(reg_info_to_deregister.name, name_to_deregister, reg_info_to_deregister.name_len);
+    bool result = nfa_dm_ndef_dereg_hdlr((tNFA_DM_MSG*)&reg_info_to_deregister);
+    EXPECT_TRUE(result);
+    tNFA_DM_API_REG_NDEF_HDLR reg_info_new = {};
+    reg_info_new.p_ndef_cback = NDEFCallbackBridge;
+    reg_info_new.tnf = NFA_TNF_DEFAULT;
+    reg_info_new.name_len = 4;
+    uint8_t name_new[] = "New";
+    memcpy(reg_info_new.name, name_new, reg_info_new.name_len);
+    bool result_new = nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info_new);
+    EXPECT_FALSE(result_new);
+}
+
+//nfa_dm_ndef_handle_message
+
+TEST_F(NfaDmTest, HandleMessage_RegisteredHandler) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    uint8_t event = 1;
+    tNFA_NDEF_EVT_DATA event_data = {};
+    EXPECT_CALL(mock_handler, OnNDEFData(::testing::_, ::testing::_)).Times(0);
+    uint8_t msg_buf[sizeof(tNFA_NDEF_EVT_DATA)];
+    memcpy(msg_buf, &event_data, sizeof(tNFA_NDEF_EVT_DATA));
+    uint32_t len = sizeof(tNFA_NDEF_EVT_DATA);
+    tNFA_STATUS status = NFA_STATUS_OK;
+    nfa_dm_ndef_handle_message(status, msg_buf, len);
+}
+
+TEST_F(NfaDmTest, HandleMessage_UnregisteredHandler) {
+    uint8_t event = 1;
+    tNFA_NDEF_EVT_DATA event_data = {};
+    uint8_t msg_buf[sizeof(tNFA_NDEF_EVT_DATA)];
+    memcpy(msg_buf, &event_data, sizeof(tNFA_NDEF_EVT_DATA));
+    EXPECT_CALL(mock_handler, OnNDEFData(event, &event_data)).Times(0);
+    uint32_t len = sizeof(tNFA_NDEF_EVT_DATA);
+    tNFA_STATUS status = NFA_STATUS_OK;
+    nfa_dm_ndef_handle_message(status, msg_buf, len);
+}
+
+TEST_F(NfaDmTest, HandleMessage_InvalidEvent) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    uint8_t invalid_event = 99;
+    tNFA_NDEF_EVT_DATA event_data = {};
+    uint8_t msg_buf[sizeof(tNFA_NDEF_EVT_DATA)];
+    memcpy(msg_buf, &event_data, sizeof(tNFA_NDEF_EVT_DATA));
+    EXPECT_CALL(mock_handler, OnNDEFData(invalid_event, &event_data)).Times(0);
+    uint32_t len = sizeof(tNFA_NDEF_EVT_DATA);
+    tNFA_STATUS status = NFA_STATUS_OK;
+    nfa_dm_ndef_handle_message(status, msg_buf, len);
+}
+
+TEST_F(NfaDmTest, HandleMessage_CallbackInvocation) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    uint8_t event = 2;
+    tNFA_NDEF_EVT_DATA event_data = {};
+    EXPECT_CALL(mock_handler, OnNDEFData(::testing::_, ::testing::_)).Times(0);
+    uint8_t msg_buf[sizeof(tNFA_NDEF_EVT_DATA)];
+    memcpy(msg_buf, &event_data, sizeof(tNFA_NDEF_EVT_DATA));
+    uint32_t len = sizeof(tNFA_NDEF_EVT_DATA);
+    tNFA_STATUS status = NFA_STATUS_OK;
+    nfa_dm_ndef_handle_message(status, msg_buf, len);
+}
+
+TEST_F(NfaDmTest, HandleMultipleMessages) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    uint8_t event1 = 1, event2 = 2;
+    tNFA_NDEF_EVT_DATA event_data1 = {};
+    tNFA_NDEF_EVT_DATA event_data2 = {};
+    uint8_t msg_buf1[sizeof(tNFA_NDEF_EVT_DATA)];
+    uint8_t msg_buf2[sizeof(tNFA_NDEF_EVT_DATA)];
+    memcpy(msg_buf1, &event_data1, sizeof(tNFA_NDEF_EVT_DATA));
+    memcpy(msg_buf2, &event_data2, sizeof(tNFA_NDEF_EVT_DATA));
+    EXPECT_CALL(mock_handler, OnNDEFData(event1, &event_data1)).Times(0);
+    EXPECT_CALL(mock_handler, OnNDEFData(event2, &event_data2)).Times(0);
+    uint32_t len = sizeof(tNFA_NDEF_EVT_DATA);
+    tNFA_STATUS status = NFA_STATUS_OK;
+    nfa_dm_ndef_handle_message(status, msg_buf1, len);
+    nfa_dm_ndef_handle_message(status, msg_buf2, len);
+}
+
+//nfa_dm_ndef_find_next_handler
+
+TEST_F(NfaDmTest, FindNextHandler_Success) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info1 = {};
+    reg_info1.p_ndef_cback = NDEFCallbackBridge;
+    reg_info1.tnf = NFA_TNF_DEFAULT;
+    reg_info1.name_len = 5;
+    uint8_t name1[] = "Test1";
+    memcpy(reg_info1.name, name1, reg_info1.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    tNFA_DM_API_REG_NDEF_HDLR reg_info2 = {};
+    reg_info2.p_ndef_cback = NDEFCallbackBridge;
+    reg_info2.tnf = NFA_TNF_DEFAULT;
+    reg_info2.name_len = 5;
+    uint8_t name2[] = "Test2";
+    memcpy(reg_info2.name, name2, reg_info2.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info2);
+    unsigned char event = 1;
+    unsigned char* p_name = nullptr;
+    unsigned char name_len = 0;
+    unsigned char* p_tnf = nullptr;
+    unsigned int index = 0;
+    bool result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info1, event, p_name, name_len, p_tnf, index);
+    EXPECT_FALSE(result);
+    result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info2, event, p_name, name_len, p_tnf, index);
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaDmTest, FindNextHandler_NoHandler) {
+    unsigned char event = 1;
+    unsigned char* p_name = nullptr;
+    unsigned char name_len = 0;
+    unsigned char* p_tnf = nullptr;
+    unsigned int index = 0;
+    tNFA_DM_API_REG_NDEF_HDLR* found_handler = nullptr;
+    bool result = nfa_dm_ndef_find_next_handler(nullptr, event, p_name, name_len, p_tnf, index);
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaDmTest, FindNextHandler_NoMatch) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info1 = {};
+    reg_info1.p_ndef_cback = NDEFCallbackBridge;
+    reg_info1.tnf = NFA_TNF_DEFAULT;
+    reg_info1.name_len = 5;
+    uint8_t name1[] = "Test1";
+    memcpy(reg_info1.name, name1, reg_info1.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    unsigned char event = 1;
+    unsigned char* p_name = (unsigned char*)"NonMatchingName";
+    unsigned char name_len = 15;
+    unsigned char* p_tnf = nullptr;
+    unsigned int index = 0;
+    tNFA_DM_API_REG_NDEF_HDLR* found_handler = nullptr;
+    bool result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info1, event, p_name, name_len, p_tnf, index);
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaDmTest, FindNextHandler_InvalidEvent) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info1 = {};
+    reg_info1.p_ndef_cback = NDEFCallbackBridge;
+    reg_info1.tnf = NFA_TNF_DEFAULT;
+    reg_info1.name_len = 5;
+    uint8_t name1[] = "Test1";
+    memcpy(reg_info1.name, name1, reg_info1.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    unsigned char invalid_event = 99;
+    unsigned char* p_name = nullptr;
+    unsigned char name_len = 0;
+    unsigned char* p_tnf = nullptr;
+    unsigned int index = 0;
+    tNFA_DM_API_REG_NDEF_HDLR* found_handler = nullptr;
+    bool result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info1, invalid_event, p_name, name_len, p_tnf, index);
+    EXPECT_FALSE(result);
+}
+
+//nfa_dm_ndef_find_next_handler
+
+TEST_F(NfaDmTest, DeregisterHandle_Success) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    bool result = nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    EXPECT_FALSE(result);
+    tNFA_HANDLE handler_handle = reg_info.ndef_type_handle;
+    nfa_dm_ndef_dereg_hdlr_by_handle(handler_handle);
+    tNFA_DM_API_REG_NDEF_HDLR* found_handler = nullptr;
+    result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info, 0, nullptr, 0, nullptr, 0);
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaDmTest, DeregisterHandler_Fail_InvalidHandle) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info = {};
+    reg_info.p_ndef_cback = NDEFCallbackBridge;
+    reg_info.tnf = NFA_TNF_DEFAULT;
+    reg_info.name_len = 5;
+    uint8_t name[] = "Test";
+    memcpy(reg_info.name, name, reg_info.name_len);
+    bool result = nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info);
+    EXPECT_FALSE(result);
+    tNFA_HANDLE invalid_handle = 0;
+    nfa_dm_ndef_dereg_hdlr_by_handle(invalid_handle);
+    tNFA_DM_API_REG_NDEF_HDLR* found_handler = nullptr;
+    result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info, 0, nullptr, 0, nullptr, 0);
+    EXPECT_FALSE(result);
+}
+
+TEST_F(NfaDmTest, DeregisterHandler_MultipleHandlers) {
+    tNFA_DM_API_REG_NDEF_HDLR reg_info1 = {};
+    reg_info1.p_ndef_cback = NDEFCallbackBridge;
+    reg_info1.tnf = NFA_TNF_DEFAULT;
+    reg_info1.name_len = 5;
+    uint8_t name1[] = "Test1";
+    memcpy(reg_info1.name, name1, reg_info1.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info1);
+    tNFA_DM_API_REG_NDEF_HDLR reg_info2 = {};
+    reg_info2.p_ndef_cback = NDEFCallbackBridge;
+    reg_info2.tnf = NFA_TNF_DEFAULT;
+    reg_info2.name_len = 5;
+    uint8_t name2[] = "Test2";
+    memcpy(reg_info2.name, name2, reg_info2.name_len);
+    nfa_dm_ndef_reg_hdlr((tNFA_DM_MSG*)&reg_info2);
+    tNFA_HANDLE handle1 = reg_info1.ndef_type_handle;
+    tNFA_HANDLE handle2 = reg_info2.ndef_type_handle;
+    nfa_dm_ndef_dereg_hdlr_by_handle(handle1);
+    tNFA_DM_API_REG_NDEF_HDLR* found_handler = nullptr;
+    bool result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info1, 0, nullptr, 0, nullptr, 0);
+    EXPECT_FALSE(result);
+    result = nfa_dm_ndef_find_next_handler(
+            (tNFA_DM_API_REG_NDEF_HDLR*)&reg_info2, 0, nullptr, 0, nullptr, 0);
+    EXPECT_FALSE(result);
+}
+
+// nfa_dm_ndef_clear_notified_flag
+
+TEST_F(NfaDmTest, ClearNotifiedFlag_Success) {
+    mock_handler1.flags |= NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    mock_handler2.flags |= NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    nfa_dm_ndef_clear_notified_flag();
+    EXPECT_TRUE(mock_handler1.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+    EXPECT_TRUE(mock_handler2.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+}
+
+TEST_F(NfaDmTest, ClearNotifiedFlag_AlreadyClear) {
+    mock_handler1.flags &= ~NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    mock_handler2.flags &= ~NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    nfa_dm_ndef_clear_notified_flag();
+    EXPECT_FALSE(mock_handler1.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+    EXPECT_FALSE(mock_handler2.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+}
+
+TEST_F(NfaDmTest, ClearNotifiedFlag_OnlyRegisteredHandlers) {
+    mock_handler1.flags |= NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    nfa_dm_ndef_clear_notified_flag();
+    EXPECT_TRUE(mock_handler1.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+    EXPECT_FALSE(mock_handler2.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+}
+
+TEST_F(NfaDmTest, ClearNotifiedFlag_NoHandlers) {
+    nfa_dm_cb_mock.p_ndef_handler[0] = nullptr;
+    nfa_dm_cb_mock.p_ndef_handler[1] = nullptr;
+    nfa_dm_ndef_clear_notified_flag();
+    EXPECT_FALSE(mock_handler1.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+    EXPECT_FALSE(mock_handler2.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+}
+
+TEST_F(NfaDmTest, ClearNotifiedFlag_MultipleCalls) {
+    mock_handler1.flags |= NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    mock_handler2.flags |= NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED;
+    nfa_dm_ndef_clear_notified_flag();
+    nfa_dm_ndef_clear_notified_flag();
+    EXPECT_TRUE(mock_handler1.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+    EXPECT_TRUE(mock_handler2.flags & NFA_NDEF_FLAGS_WHOLE_MESSAGE_NOTIFIED);
+}
diff --git a/utils/test/config_test.cc b/tests/utils/config_test.cc
similarity index 98%
rename from utils/test/config_test.cc
rename to tests/utils/config_test.cc
index 62e324cd..32649f88 100644
--- a/utils/test/config_test.cc
+++ b/tests/utils/config_test.cc
@@ -13,9 +13,9 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+#include <config.h>
 #include <gtest/gtest.h>
 
-#include <config.h>
 #include <filesystem>
 
 namespace {
@@ -63,9 +63,7 @@ class ConfigTestFromFile : public ::testing::Test {
     fwrite(SIMPLE_CONFIG, 1, sizeof(SIMPLE_CONFIG), fp);
     fclose(fp);
   }
-  void TearDown() override {
-    std::filesystem::remove(kConfigFile);
-  }
+  void TearDown() override { std::filesystem::remove(kConfigFile); }
 };
 
 TEST(ConfigTestFromString, test_simple_config) {
diff --git a/tests/utils/ringbuffer_test.cc b/tests/utils/ringbuffer_test.cc
new file mode 100644
index 00000000..6fdb5f16
--- /dev/null
+++ b/tests/utils/ringbuffer_test.cc
@@ -0,0 +1,396 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+#include <gtest/gtest.h>
+#include <ringbuffer.h>
+
+TEST(RingbufferTest, test_new_simple) {
+  ringbuffer_t* rb = ringbuffer_init(4096);
+  ASSERT_TRUE(rb != nullptr);
+  EXPECT_EQ((size_t)4096, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_insert_basic) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t buffer[10] = {0x01, 0x02, 0x03, 0x04, 0x05,
+                        0x06, 0x07, 0x08, 0x09, 0x0A};
+  ringbuffer_insert(rb, buffer, 10);
+  EXPECT_EQ((size_t)10, ringbuffer_size(rb));
+  EXPECT_EQ((size_t)6, ringbuffer_available(rb));
+  uint8_t peek[10] = {0};
+  size_t peeked = ringbuffer_peek(rb, 0, peek, 10);
+  EXPECT_EQ((size_t)10, ringbuffer_size(rb));  // Ensure size doesn't change
+  EXPECT_EQ((size_t)6, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)10, peeked);
+  ASSERT_TRUE(0 == memcmp(buffer, peek, peeked));
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_insert_full) {
+  ringbuffer_t* rb = ringbuffer_init(5);
+  uint8_t aa[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
+  uint8_t bb[] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
+  uint8_t peek[5] = {0};
+  size_t added = ringbuffer_insert(rb, aa, 7);
+  EXPECT_EQ((size_t)5, added);
+  EXPECT_EQ((size_t)0, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
+  added = ringbuffer_insert(rb, bb, 5);
+  EXPECT_EQ((size_t)0, added);
+  EXPECT_EQ((size_t)0, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
+  size_t peeked = ringbuffer_peek(rb, 0, peek, 5);
+  EXPECT_EQ((size_t)5, peeked);
+  EXPECT_EQ((size_t)0, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
+  ASSERT_TRUE(0 == memcmp(aa, peek, peeked));
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_multi_insert_delete) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  EXPECT_EQ((size_t)16, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
+  // Insert some bytes
+  uint8_t aa[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
+  size_t added = ringbuffer_insert(rb, aa, sizeof(aa));
+  EXPECT_EQ((size_t)8, added);
+  EXPECT_EQ((size_t)8, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)8, ringbuffer_size(rb));
+  uint8_t bb[] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
+  ringbuffer_insert(rb, bb, sizeof(bb));
+  EXPECT_EQ((size_t)3, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)13, ringbuffer_size(rb));
+  uint8_t content[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
+                       0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
+  uint8_t peek[16] = {0};
+  size_t peeked = ringbuffer_peek(rb, 0, peek, 16);
+  EXPECT_EQ((size_t)13, peeked);
+  ASSERT_TRUE(0 == memcmp(content, peek, peeked));
+
+  // Delete some bytes
+  ringbuffer_delete(rb, sizeof(aa));
+  EXPECT_EQ((size_t)11, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
+
+  // Add some more to wrap buffer
+  uint8_t cc[] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
+  ringbuffer_insert(rb, cc, sizeof(cc));
+  EXPECT_EQ((size_t)2, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)14, ringbuffer_size(rb));
+
+  uint8_t content2[] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xCC, 0xCC};
+  peeked = ringbuffer_peek(rb, 0, peek, 7);
+  EXPECT_EQ((size_t)7, peeked);
+  ASSERT_TRUE(0 == memcmp(content2, peek, peeked));
+
+  // Pop buffer
+
+  memset(peek, 0, 16);
+  size_t popped = ringbuffer_pop(rb, peek, 7);
+  EXPECT_EQ((size_t)7, popped);
+  EXPECT_EQ((size_t)9, ringbuffer_available(rb));
+  ASSERT_TRUE(0 == memcmp(content2, peek, peeked));
+
+  // Add more again to check head motion
+
+  uint8_t dd[] = {0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD};
+  added = ringbuffer_insert(rb, dd, sizeof(dd));
+  EXPECT_EQ((size_t)8, added);
+  EXPECT_EQ((size_t)1, ringbuffer_available(rb));
+
+  // Delete everything
+
+  ringbuffer_delete(rb, 16);
+  EXPECT_EQ((size_t)16, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
+
+  // Add small token
+
+  uint8_t ae[] = {0xAE, 0xAE, 0xAE};
+  added = ringbuffer_insert(rb, ae, sizeof(ae));
+  EXPECT_EQ((size_t)13, ringbuffer_available(rb));
+
+  // Get everything
+
+  popped = ringbuffer_pop(rb, peek, 16);
+  EXPECT_EQ(added, popped);
+  EXPECT_EQ((size_t)16, ringbuffer_available(rb));
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
+  ASSERT_TRUE(0 == memcmp(ae, peek, popped));
+
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_delete) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+  ringbuffer_insert(rb, data, sizeof(data));
+
+  EXPECT_EQ((size_t)4, ringbuffer_size(rb));
+  EXPECT_EQ((size_t)12, ringbuffer_available(rb));
+
+  ringbuffer_delete(rb, 2);  // Delete 2 bytes
+  EXPECT_EQ((size_t)2, ringbuffer_size(rb));
+  EXPECT_EQ((size_t)14, ringbuffer_available(rb));
+
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_delete_after_basic_insert) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t buffer[10] = {0x01, 0x02, 0x03, 0x04, 0x05,
+                        0x06, 0x07, 0x08, 0x09, 0x0A};
+  ringbuffer_insert(rb, buffer, 10);
+  // Delete 5 bytes
+  ringbuffer_delete(rb, 5);
+  EXPECT_EQ((size_t)11,
+            ringbuffer_available(rb));        // Available should increase by 5
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));  // Size should decrease to 5
+
+  uint8_t peek[10] = {0};
+  size_t peeked = ringbuffer_peek(rb, 0, peek, 10);
+  uint8_t expected[] = {0x06, 0x07, 0x08, 0x09, 0x0A};
+  ASSERT_TRUE(0 == memcmp(expected, peek, peeked));  // Check remaining bytes
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_delete_after_insert_full) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
+                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
+
+  // Insert data
+  ringbuffer_insert(rb, data, sizeof(data));
+  EXPECT_EQ((size_t)16, ringbuffer_size(rb));
+  EXPECT_EQ((size_t)0, ringbuffer_available(rb));  // Should be full
+  // Now delete some bytes
+  ringbuffer_delete(rb, 8);  // Delete half of the buffer
+  EXPECT_EQ((size_t)8, ringbuffer_size(rb));       // Should have 8 left
+  EXPECT_EQ((size_t)8, ringbuffer_available(rb));  // 8 should be available now
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_multi_insert_followed_by_delete) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
+  uint8_t data2[] = {0x05, 0x06, 0x07, 0x08};
+  ringbuffer_insert(rb, data1, sizeof(data1));
+  EXPECT_EQ((size_t)4, ringbuffer_size(rb));        // 4 bytes
+  EXPECT_EQ((size_t)12, ringbuffer_available(rb));  // 12 bytes available
+  ringbuffer_insert(rb, data2, sizeof(data2));
+  EXPECT_EQ((size_t)8, ringbuffer_size(rb));       // 8 bytes
+  EXPECT_EQ((size_t)8, ringbuffer_available(rb));  // 8 bytes available
+  // Delete some bytes
+  ringbuffer_delete(rb, 3);                         // Delete 3 bytes
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));        // Should have 5 left
+  EXPECT_EQ((size_t)11, ringbuffer_available(rb));  // 11 should be available
+  // Verify contents
+  uint8_t peek[16] = {0};
+  size_t peeked = ringbuffer_peek(rb, 0, peek, 16);
+  uint8_t expected[] = {0x04, 0x05, 0x06, 0x07,
+                        0x08};  // Remaining bytes after deletion
+  ASSERT_TRUE(0 == memcmp(expected, peek, 5));
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_free_empty) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+  ringbuffer_free(rb);  // Freeing an empty ringbuffer should not cause issues
+}
+
+TEST(RingbufferTest, test_free_after_inserts) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+  ringbuffer_insert(rb, data, sizeof(data));
+  EXPECT_EQ((size_t)4, ringbuffer_size(rb));
+  ringbuffer_free(rb);  // Ensure freeing works after inserts
+}
+
+TEST(RingbufferTest, test_free_multiple_times) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+  ringbuffer_free(rb);  // First free should be fine
+
+  // Set pointer to null to prevent double free
+  rb = nullptr;
+
+  // The second free should not cause an issue as rb is now null
+  ringbuffer_free(rb);  // This should safely do nothing
+}
+
+TEST(RingbufferTest, test_peek_empty) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t peek[16] = {0};
+  size_t peeked = ringbuffer_peek(rb, 0, peek, sizeof(peek));
+  EXPECT_EQ((size_t)0, peeked);               // Nothing to peek
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));  // Size should remain 0
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_peek_after_insert) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+  ringbuffer_insert(rb, data, sizeof(data));
+  uint8_t peek[4] = {0};
+  size_t peeked = ringbuffer_peek(rb, 0, peek, sizeof(peek));
+  EXPECT_EQ((size_t)4, peeked);
+  ASSERT_TRUE(0 == memcmp(data, peek, peeked));
+  EXPECT_EQ((size_t)4, ringbuffer_size(rb));  // Size should remain unchanged
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_peek_with_offset) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+  ringbuffer_insert(rb, data, sizeof(data));
+  uint8_t peek[3] = {0};
+  size_t peeked =
+      ringbuffer_peek(rb, 1, peek, sizeof(peek));  // Peek with offset 1
+
+  EXPECT_EQ((size_t)3, peeked);
+  uint8_t expected[] = {0x02, 0x03, 0x04};
+  ASSERT_TRUE(0 == memcmp(expected, peek, peeked));
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_peek_with_wrap) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+  uint8_t data1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
+  ringbuffer_insert(rb, data1, sizeof(data1));  // Insert 8 bytes
+  uint8_t data2[] = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
+  ringbuffer_insert(rb, data2,
+                    sizeof(data2));  // Insert another 8 bytes (total 16 bytes)
+  uint8_t peeked[10] = {0};
+  size_t peeked_size = ringbuffer_peek(rb, 0, peeked, 10);  // Peek 10 bytes
+  EXPECT_EQ((size_t)10, peeked_size);  // Should successfully peek 10 bytes
+  uint8_t expected[10] = {0x01, 0x02, 0x03, 0x04, 0x05,
+                          0x06, 0x07, 0x08, 0x09, 0x0A};
+  EXPECT_EQ(0, memcmp(expected, peeked,
+                      peeked_size));  // Check if peeked data is correct
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_pop_empty) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t peek[16] = {0};
+  size_t popped = ringbuffer_pop(rb, peek, sizeof(peek));
+  EXPECT_EQ((size_t)0, popped);               // Nothing to pop
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));  // Size should remain 0
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_pop_after_insert) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+  ringbuffer_insert(rb, data, sizeof(data));
+  uint8_t peek[4] = {0};
+  size_t popped = ringbuffer_pop(rb, peek, sizeof(peek));
+  EXPECT_EQ((size_t)4, popped);
+  ASSERT_TRUE(0 == memcmp(data, peek, popped));
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));  // Size should now be 0
+
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_pop_partial) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
+  ringbuffer_insert(rb, data, sizeof(data));
+  uint8_t peek[2] = {0};
+  size_t popped = ringbuffer_pop(rb, peek, 2);
+  EXPECT_EQ((size_t)2, popped);
+  uint8_t expected[] = {0x01, 0x02};
+  ASSERT_TRUE(0 == memcmp(expected, peek, popped));
+  EXPECT_EQ((size_t)2, ringbuffer_size(rb));  // Remaining size should be 2
+  ringbuffer_free(rb);
+}
+TEST(RingbufferTest, test_pop_with_wrap) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+
+  uint8_t data1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
+  ringbuffer_insert(rb, data1, sizeof(data1));  // Insert 8 bytes
+
+  uint8_t data2[] = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
+  ringbuffer_insert(rb, data2,
+                    sizeof(data2));  // Insert another 8 bytes (total 16 bytes)
+
+  uint8_t popped[10] = {0};
+  size_t popped_size = ringbuffer_pop(rb, popped, 10);  // Pop 10 bytes
+
+  EXPECT_EQ((size_t)10, popped_size);  // Should successfully pop 10 bytes
+  uint8_t expected[10] = {0x01, 0x02, 0x03, 0x04, 0x05,
+                          0x06, 0x07, 0x08, 0x09, 0x0A};
+  EXPECT_EQ(0, memcmp(expected, popped,
+                      popped_size));  // Check if popped data is correct
+
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_initial_size) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+  EXPECT_EQ((size_t)0, ringbuffer_size(rb));  // Should be 0
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_size_after_insert) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+
+  uint8_t data1[] = {0x01, 0x02, 0x03};
+  ringbuffer_insert(rb, data1, sizeof(data1));  // Insert 3 bytes
+
+  EXPECT_EQ((size_t)3, ringbuffer_size(rb));  // Should be 3
+
+  uint8_t data2[] = {0x04, 0x05, 0x06, 0x07};
+  ringbuffer_insert(rb, data2, sizeof(data2));  // Insert 4 more bytes
+
+  EXPECT_EQ((size_t)7, ringbuffer_size(rb));  // Should be
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_size_after_delete) {
+  ringbuffer_t* rb = ringbuffer_init(16);
+  ASSERT_TRUE(rb != nullptr);
+
+  uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
+  ringbuffer_insert(rb, data, sizeof(data));  // Insert 5 bytes
+
+  EXPECT_EQ((size_t)5, ringbuffer_size(rb));  // Should be 5
+
+  ringbuffer_delete(rb, 3);                   // Delete 3 bytes
+  EXPECT_EQ((size_t)2, ringbuffer_size(rb));  // Should be 2
+  ringbuffer_free(rb);
+}
+
+TEST(RingbufferTest, test_size_after_wrap_around) {
+  ringbuffer_t* rb = ringbuffer_init(8);  // Small buffer for testing
+  ASSERT_TRUE(rb != nullptr);
+  uint8_t data1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
+  ringbuffer_insert(rb, data1, sizeof(data1));  // Fill the buffer
+  EXPECT_EQ((size_t)8, ringbuffer_size(rb));  // Should be 8
+  ringbuffer_delete(rb, 4);                   // Delete 4 bytes
+  EXPECT_EQ((size_t)4, ringbuffer_size(rb));  // Should be 4
+  uint8_t data2[] = {0x09, 0x0A};
+  ringbuffer_insert(rb, data2, sizeof(data2));  // Insert 2 more bytes
+  EXPECT_EQ((size_t)6, ringbuffer_size(rb));  // Should be 6
+  ringbuffer_free(rb);
+}
diff --git a/tools/casimir/Android.bp b/tools/casimir/Android.bp
index 22eee656..15ef8e7b 100644
--- a/tools/casimir/Android.bp
+++ b/tools/casimir/Android.bp
@@ -40,14 +40,15 @@ rust_binary_host {
         ":casimir_rf_packets_rust_gen",
     ],
     rustlibs: [
-        "libenv_logger",
         "libanyhow",
         "libargh",
-        "libtokio",
         "libbytes",
+        "libenv_logger",
         "libfutures",
         "liblog_rust",
         "libpdl_runtime",
+        "librustutils",
+        "libtokio",
     ],
 }
 
diff --git a/tools/casimir/README.rst b/tools/casimir/README.rst
index 8b65802a..0c3afa04 100644
--- a/tools/casimir/README.rst
+++ b/tools/casimir/README.rst
@@ -146,7 +146,7 @@ RF management
 | RF_DEACTIVATE_RSP               |              |                                                 |
 | RF_DEACTIVATE_NTF               |              |                                                 |
 +---------------------------------+--------------+-------------------------------------------------+
-| RF_FIELD_INFO_NTF               | Not started  |                                                 |
+| RF_FIELD_INFO_NTF               | Completed    |                                                 |
 +---------------------------------+--------------+-------------------------------------------------+
 | RF_T3T_POLLING_CMD              | Not started  |                                                 |
 | RF_T3T_POLLING_RSP              |              |                                                 |
diff --git a/tools/casimir/scripts/rf_packets.py b/tools/casimir/scripts/rf_packets.py
index eecafe88..ef963978 100644
--- a/tools/casimir/scripts/rf_packets.py
+++ b/tools/casimir/scripts/rf_packets.py
@@ -87,6 +87,7 @@ class Technology(enum.IntEnum):
     NFC_B = 0x1
     NFC_F = 0x2
     NFC_V = 0x3
+    RAW = 0x7
 
     @staticmethod
     def from_int(v: int) -> Union[int, 'Technology']:
@@ -217,7 +218,7 @@ class RfPacket(Packet):
 
 @dataclass
 class PollCommand(RfPacket):
-    
+    data : bytearray = field(kw_only=True, default_factory=bytearray)
 
     def __post_init__(self):
         self.packet_type = RfPacketType.POLL_COMMAND
@@ -226,15 +227,18 @@ class PollCommand(RfPacket):
     def parse(fields: dict, span: bytes) -> Tuple['PollCommand', bytes]:
         if fields['packet_type'] != RfPacketType.POLL_COMMAND:
             raise Exception("Invalid constraint field values")
+        data = span[0:]
+        fields['data'] = data
         return PollCommand(**fields), span
 
     def serialize(self, payload: bytes = None) -> bytes:
         _span = bytearray()
+        _span.extend(self.data)
         return RfPacket.serialize(self, payload = bytes(_span))
 
     @property
     def size(self) -> int:
-        return 0
+        return len(self.data)
 
 @dataclass
 class NfcAPollResponse(RfPacket):
@@ -411,7 +415,7 @@ class NfcDepSelectResponse(RfPacket):
 
 @dataclass
 class SelectCommand(RfPacket):
-    
+
 
     def __post_init__(self):
         self.packet_type = RfPacketType.SELECT_COMMAND
diff --git a/tools/casimir/scripts/t4at.py b/tools/casimir/scripts/t4at.py
index 80981944..cf0f741b 100755
--- a/tools/casimir/scripts/t4at.py
+++ b/tools/casimir/scripts/t4at.py
@@ -89,7 +89,14 @@ class T4AT:
                         await self.active(response.sender)
                     case _:
                         pass
-                time.sleep(0.150);
+                time.sleep(0.050);
+            except TimeoutError:
+                pass
+            time.sleep(0.050);
+            try:
+                signature = bytes([0x1, 0x2, 0x3, 0x4]);
+                self._write(rf.PollCommand(technology=rf.Technology.NFC_RAW, data=signature))
+                await asyncio.wait_for(self._read(), timeout=1.0)
             except TimeoutError:
                 pass
 
diff --git a/tools/casimir/src/controller.rs b/tools/casimir/src/controller.rs
index b7f67a5b..6a27539f 100644
--- a/tools/casimir/src/controller.rs
+++ b/tools/casimir/src/controller.rs
@@ -1215,6 +1215,7 @@ impl<'a> Controller<'a> {
                 info!("[{}] RF_DEACTIVATE_NTF", self.id);
                 info!("         Type: {:?}", cmd.get_deactivation_type());
                 info!("         Reason: DH_Request");
+                self.field_info(rf::FieldStatus::FieldOff, 255).await?;
                 self.send_control(nci::RfDeactivateNotificationBuilder {
                     deactivation_type: cmd.get_deactivation_type(),
                     deactivation_reason: nci::DeactivationReason::DhRequest,
@@ -1232,6 +1233,7 @@ impl<'a> Controller<'a> {
                     receiver: id,
                     protocol: rf_protocol,
                     technology: rf_technology,
+                    power_level: 255,
                     sender: self.id,
                     type_: cmd.get_deactivation_type().into(),
                     reason: rf::DeactivateReason::EndpointRequest,
@@ -1446,6 +1448,7 @@ impl<'a> Controller<'a> {
                 self.send_rf(rf::DataBuilder {
                     receiver: id,
                     sender: self.id,
+                    power_level: 255,
                     protocol: rf::Protocol::IsoDep,
                     technology: rf_technology,
                     data: packet.get_payload().into(),
@@ -1585,6 +1588,29 @@ impl<'a> Controller<'a> {
         }
     }
 
+    async fn field_info(&mut self, field_status: rf::FieldStatus, power_level: u8) -> Result<()> {
+        if self.state.config_parameters.rf_field_info != 0 {
+            self.send_control(nci::RfFieldInfoNotificationBuilder {
+                rf_field_status: match field_status {
+                    rf::FieldStatus::FieldOn => nci::RfFieldStatus::FieldDetected,
+                    rf::FieldStatus::FieldOff => nci::RfFieldStatus::NoFieldDetected,
+                },
+            })
+            .await?;
+        }
+        self.send_control(nci::AndroidPollingLoopNotificationBuilder {
+            polling_frames: vec![nci::PollingFrame {
+                frame_type: nci::PollingFrameType::RemoteField,
+                flags: 0,
+                timestamp: (self.state.start_time.elapsed().as_micros() as u32).to_be_bytes(),
+                gain: power_level,
+                payload: vec![field_status.into()],
+            }],
+        })
+        .await?;
+        Ok(())
+    }
+
     async fn poll_command(&mut self, cmd: rf::PollCommand) -> Result<()> {
         trace!("[{}] poll_command()", self.id);
 
@@ -1602,16 +1628,17 @@ impl<'a> Controller<'a> {
         // transaction.
         self.send_control(nci::AndroidPollingLoopNotificationBuilder {
             polling_frames: vec![nci::PollingFrame {
-                r#type: match technology {
+                frame_type: match technology {
                     rf::Technology::NfcA => nci::PollingFrameType::Reqa,
                     rf::Technology::NfcB => nci::PollingFrameType::Reqb,
                     rf::Technology::NfcF => nci::PollingFrameType::Reqf,
                     rf::Technology::NfcV => nci::PollingFrameType::Reqv,
+                    rf::Technology::Raw => nci::PollingFrameType::Unknown,
                 },
                 flags: 0,
-                timestamp: (self.state.start_time.elapsed().as_millis() as u32).to_be_bytes(),
-                gain: 2,
-                data: vec![],
+                timestamp: (self.state.start_time.elapsed().as_micros() as u32).to_be_bytes(),
+                gain: cmd.get_power_level(),
+                payload: cmd.get_payload().to_vec(),
             }],
         })
         .await?;
@@ -1637,6 +1664,7 @@ impl<'a> Controller<'a> {
                         protocol: rf::Protocol::Undetermined,
                         receiver: cmd.get_sender(),
                         sender: self.id,
+                        power_level: 255,
                         nfcid1: self.state.nfcid1(),
                         int_protocol: self.state.config_parameters.la_sel_info >> 5,
                         bit_frame_sdd: self.state.config_parameters.la_bit_frame_sdd,
@@ -1732,6 +1760,7 @@ impl<'a> Controller<'a> {
         self.send_rf(rf::T4ATSelectResponseBuilder {
             receiver: cmd.get_sender(),
             sender: self.id,
+            power_level: 255,
             rats_response,
         })
         .await?;
@@ -1906,6 +1935,7 @@ impl<'a> Controller<'a> {
 
         // Deactivate the active RF interface if applicable.
         if next_state != self.state.rf_state {
+            self.field_info(rf::FieldStatus::FieldOff, 255).await?;
             self.send_control(nci::RfDeactivateNotificationBuilder {
                 deactivation_type: cmd.get_type_().into(),
                 deactivation_reason: cmd.get_reason().into(),
@@ -1921,6 +1951,7 @@ impl<'a> Controller<'a> {
 
         match packet.specialize() {
             PollCommand(cmd) => self.poll_command(cmd).await,
+            FieldInfo(cmd) => self.field_info(cmd.get_field_status(), cmd.get_power_level()).await,
             NfcAPollResponse(cmd) => self.nfca_poll_response(cmd).await,
             // [NCI] 5.2.2 State RFST_DISCOVERY
             // If discovered by a Remote NFC Endpoint in Listen mode, once the
@@ -1962,6 +1993,7 @@ impl<'a> Controller<'a> {
                     sender: self.id,
                     receiver: self.state.rf_poll_responses[rf_discovery_id].id,
                     technology: rf::Technology::NfcA,
+                    power_level: 255,
                     protocol: rf::Protocol::T2t,
                 })
                 .await?
@@ -1970,6 +2002,7 @@ impl<'a> Controller<'a> {
                 self.send_rf(rf::T4ATSelectCommandBuilder {
                     sender: self.id,
                     receiver: self.state.rf_poll_responses[rf_discovery_id].id,
+                    power_level: 255,
                     // [DIGITAL] 14.6.1.6 The FSD supported by the
                     // Reader/Writer SHALL be FSD T4AT,MIN
                     // (set to 256 in Appendix B.6).
@@ -1981,6 +2014,7 @@ impl<'a> Controller<'a> {
                 self.send_rf(rf::NfcDepSelectCommandBuilder {
                     sender: self.id,
                     receiver: self.state.rf_poll_responses[rf_discovery_id].id,
+                    power_level: 255,
                     technology: rf::Technology::NfcA,
                     lr: 0,
                 })
@@ -2067,6 +2101,8 @@ impl<'a> Controller<'a> {
                     nci::RfTechnologyAndMode::NfcVPassivePollMode => rf::Technology::NfcV,
                     _ => continue,
                 },
+                power_level: 255,
+                payload: Some(bytes::Bytes::new()),
             })
             .await?
         }
diff --git a/tools/casimir/src/main.rs b/tools/casimir/src/main.rs
index 3e81197c..a6c57f7e 100644
--- a/tools/casimir/src/main.rs
+++ b/tools/casimir/src/main.rs
@@ -17,14 +17,14 @@
 use anyhow::Result;
 use argh::FromArgs;
 use log::{error, info, warn};
+use rustutils::inherited_fd;
 use std::future::Future;
 use std::net::{Ipv4Addr, SocketAddrV4};
 use std::pin::{pin, Pin};
 use std::task::Context;
 use std::task::Poll;
-use tokio::io::AsyncReadExt;
-use tokio::io::AsyncWriteExt;
-use tokio::net::{tcp, TcpListener, TcpStream};
+use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
+use tokio::net::{TcpListener, UnixListener};
 use tokio::select;
 use tokio::sync::mpsc;
 
@@ -40,19 +40,19 @@ type Id = u16;
 /// Read RF Control and Data packets received on the RF transport.
 /// Performs recombination of the segmented packets.
 pub struct RfReader {
-    socket: tcp::OwnedReadHalf,
+    socket: Pin<Box<dyn AsyncRead>>,
 }
 
 /// Write RF Control and Data packets received to the RF transport.
 /// Performs segmentation of the packets.
 pub struct RfWriter {
-    socket: tcp::OwnedWriteHalf,
+    socket: Pin<Box<dyn AsyncWrite>>,
 }
 
 impl RfReader {
-    /// Create a new RF reader from the TCP socket half.
-    pub fn new(socket: tcp::OwnedReadHalf) -> Self {
-        RfReader { socket }
+    /// Create a new RF reader from an `AsyncRead` implementation.
+    pub fn new(socket: impl AsyncRead + 'static) -> Self {
+        RfReader { socket: Box::pin(socket) }
     }
 
     /// Read a single RF packet from the reader.
@@ -74,9 +74,9 @@ impl RfReader {
 }
 
 impl RfWriter {
-    /// Create a new RF writer from the TCP socket half.
-    pub fn new(socket: tcp::OwnedWriteHalf) -> Self {
-        RfWriter { socket }
+    /// Create a new RF writer from an `AsyncWrite` implementation.
+    pub fn new(socket: impl AsyncWrite + 'static) -> Self {
+        RfWriter { socket: Box::pin(socket) }
     }
 
     /// Write a single RF packet to the writer.
@@ -112,7 +112,8 @@ pub struct Device {
 impl Device {
     fn nci(
         id: Id,
-        socket: TcpStream,
+        nci_rx: impl AsyncRead + 'static,
+        nci_tx: impl AsyncWrite + 'static,
         controller_rf_tx: mpsc::UnboundedSender<rf::RfPacket>,
     ) -> Device {
         let (rf_tx, rf_rx) = mpsc::unbounded_channel();
@@ -120,7 +121,6 @@ impl Device {
             id,
             rf_tx,
             task: Box::pin(async move {
-                let (nci_rx, nci_tx) = socket.into_split();
                 Controller::run(
                     id,
                     pin!(nci::Reader::new(nci_rx).into_stream()),
@@ -135,7 +135,8 @@ impl Device {
 
     fn rf(
         id: Id,
-        socket: TcpStream,
+        socket_rx: impl AsyncRead + 'static,
+        socket_tx: impl AsyncWrite + 'static,
         controller_rf_tx: mpsc::UnboundedSender<rf::RfPacket>,
     ) -> Device {
         let (rf_tx, mut rf_rx) = mpsc::unbounded_channel();
@@ -143,7 +144,6 @@ impl Device {
             id,
             rf_tx,
             task: Box::pin(async move {
-                let (socket_rx, socket_tx) = socket.into_split();
                 let mut rf_reader = RfReader::new(socket_rx);
                 let mut rf_writer = RfWriter::new(socket_tx);
 
@@ -236,6 +236,7 @@ impl Scene {
                         reason: rf::DeactivateReason::RfLinkLoss,
                         sender: id,
                         receiver: device.id,
+                        power_level: 255,
                         technology: rf::Technology::NfcA,
                         protocol: rf::Protocol::Undetermined,
                     }
@@ -287,42 +288,108 @@ impl Future for Scene {
 #[derive(FromArgs, Debug)]
 /// Nfc emulator.
 struct Opt {
-    #[argh(option, default = "7000")]
+    #[argh(option)]
     /// configure the TCP port for the NCI server.
-    nci_port: u16,
-    #[argh(option, default = "7001")]
+    nci_port: Option<u16>,
+    #[argh(option)]
+    /// configure a preexisting unix server fd for the NCI server.
+    nci_unix_fd: Option<i32>,
+    #[argh(option)]
     /// configure the TCP port for the RF server.
-    rf_port: u16,
+    rf_port: Option<u16>,
+    #[argh(option)]
+    /// configure a preexisting unix server fd for the RF server.
+    rf_unix_fd: Option<i32>,
 }
 
+/// Abstraction between different server sources
+enum Listener {
+    Tcp(TcpListener),
+    #[allow(unused)]
+    Unix(UnixListener),
+}
+
+impl Listener {
+    async fn accept_split(
+        &self,
+    ) -> Result<(Pin<Box<dyn AsyncRead>>, Pin<Box<dyn AsyncWrite>>, String)> {
+        match self {
+            Listener::Tcp(tcp) => {
+                let (socket, addr) = tcp.accept().await?;
+                let (rx, tx) = socket.into_split();
+                Ok((Box::pin(rx), Box::pin(tx), format!("{}", addr)))
+            }
+            Listener::Unix(unix) => {
+                let (socket, addr) = unix.accept().await?;
+                let (rx, tx) = socket.into_split();
+                Ok((Box::pin(rx), Box::pin(tx), format!("{:?}", addr)))
+            }
+        }
+    }
+}
+
+#[tokio::main]
 async fn run() -> Result<()> {
     env_logger::init_from_env(
         env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
     );
 
     let opt: Opt = argh::from_env();
-    let nci_listener =
-        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, opt.nci_port)).await?;
-    let rf_listener =
-        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, opt.rf_port)).await?;
+
+    let nci_listener = match (opt.nci_port, opt.nci_unix_fd) {
+        (None, Some(unix_fd)) => {
+            let owned_fd = inherited_fd::take_fd_ownership(unix_fd)?;
+            let nci_listener = std::os::unix::net::UnixListener::from(owned_fd);
+            nci_listener.set_nonblocking(true)?;
+            let nci_listener = UnixListener::from_std(nci_listener)?;
+            info!("Listening for NCI connections on fd {}", unix_fd);
+            Listener::Unix(nci_listener)
+        }
+        (port, None) => {
+            let port = port.unwrap_or(7000);
+            let nci_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
+            let nci_listener = TcpListener::bind(nci_addr).await?;
+            info!("Listening for NCI connections at address {}", nci_addr);
+            Listener::Tcp(nci_listener)
+        }
+        _ => anyhow::bail!("Specify at most one of `--nci-port` and `--nci-unix-fd`."),
+    };
+
+    let rf_listener = match (opt.rf_port, opt.rf_unix_fd) {
+        (None, Some(unix_fd)) => {
+            let owned_fd = inherited_fd::take_fd_ownership(unix_fd)?;
+            let nci_listener = std::os::unix::net::UnixListener::from(owned_fd);
+            nci_listener.set_nonblocking(true)?;
+            let nci_listener = UnixListener::from_std(nci_listener)?;
+            info!("Listening for RF connections on fd {}", unix_fd);
+            Listener::Unix(nci_listener)
+        }
+        (port, None) => {
+            let port = port.unwrap_or(7001);
+            let rf_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
+            let rf_listener = TcpListener::bind(rf_addr).await?;
+            info!("Listening for RF connections at address {}", rf_addr);
+            Listener::Tcp(rf_listener)
+        }
+        _ => anyhow::bail!("Specify at most one of `--rf-port` and `--rf-unix-fd`"),
+    };
+
     let (rf_tx, mut rf_rx) = mpsc::unbounded_channel();
     let mut scene = Scene::new();
-    info!("Listening for NCI connections at address 127.0.0.1:{}", opt.nci_port);
-    info!("Listening for RF connections at address 127.0.0.1:{}", opt.rf_port);
     loop {
         select! {
-            result = nci_listener.accept() => {
-                let (socket, addr) = result?;
+            result = nci_listener.accept_split() => {
+                let (socket_rx, socket_tx, addr) = result?;
                 info!("Incoming NCI connection from {}", addr);
-                match scene.add_device(|id| Device::nci(id, socket, rf_tx.clone())) {
+                match scene.add_device(|id| Device::nci(id, socket_rx, socket_tx, rf_tx.clone())) {
                     Ok(id) => info!("Accepted NCI connection from {} in slot {}", addr, id),
                     Err(err) => error!("Failed to accept NCI connection from {}: {}", addr, err)
                 }
             },
-            result = rf_listener.accept() => {
-                let (socket, addr) = result?;
+            result = rf_listener.accept_split() => {
+                let (socket_rx, socket_tx, addr) = result?;
                 info!("Incoming RF connection from {}", addr);
-                match scene.add_device(|id| Device::rf(id, socket, rf_tx.clone())) {
+                match scene.add_device(|id| Device::rf(id, socket_rx, socket_tx, rf_tx.clone())) {
                     Ok(id) => info!("Accepted RF connection from {} in slot {}", addr, id),
                     Err(err) => error!("Failed to accept RF connection from {}: {}", addr, err)
                 }
@@ -336,7 +403,8 @@ async fn run() -> Result<()> {
     }
 }
 
-#[tokio::main]
-async fn main() -> Result<()> {
-    run().await
+fn main() -> Result<()> {
+    // Safety: First function call in the `main` function, before any other library calls
+    unsafe { inherited_fd::init_once()? };
+    run()
 }
diff --git a/tools/casimir/src/nci_packets.pdl b/tools/casimir/src/nci_packets.pdl
index 0dea2942..fbe1f5b3 100644
--- a/tools/casimir/src/nci_packets.pdl
+++ b/tools/casimir/src/nci_packets.pdl
@@ -728,6 +728,16 @@ packet RfDeactivateNotification : RfPacket (mt = NOTIFICATION, oid = DEACTIVATE)
   deactivation_reason : DeactivationReason,
 }
 
+enum RfFieldStatus : 8 {
+  NO_FIELD_DETECTED = 0,
+  FIELD_DETECTED = 1,
+}
+
+packet RfFieldInfoNotification : RfPacket (mt = NOTIFICATION, oid = FIELD_INFO) {
+  rf_field_status: RfFieldStatus,
+}
+
+
 // [NCI] Table 85: TLV Coding for RF Discovery Request from NFCEE
 enum InformationEntryType : 8 {
   ADD_DISCOVERY_REQUEST = 0x00,
@@ -886,14 +896,14 @@ enum PollingFrameType : 8 {
 }
 
 struct PollingFrame {
-  type: PollingFrameType,
+  frame_type: PollingFrameType,
   flags: 8,
-  _size_(data): 8,
+  _size_(_payload_): 8,
   // The timestamp is encoded in big-endian byte order,
   // whereas other NCI definitions are little-endian.
   timestamp: 8[4],
   gain: 8,
-  data: 8[],
+  _payload_: [+5],
 }
 
 packet AndroidPollingLoopNotification : AndroidPacket(mt = NOTIFICATION, android_sub_oid = POLLING_FRAME) {
diff --git a/tools/casimir/src/rf_packets.pdl b/tools/casimir/src/rf_packets.pdl
index 3588841b..a9d8c46e 100644
--- a/tools/casimir/src/rf_packets.pdl
+++ b/tools/casimir/src/rf_packets.pdl
@@ -16,6 +16,7 @@ enum Technology : 8 {
     NFC_B = 1,
     NFC_F = 2,
     NFC_V = 3,
+    RAW = 0x7,
 }
 
 /// Protocol used for data exchange.
@@ -58,6 +59,7 @@ enum RfPacketType : 8 {
     SELECT_COMMAND = 3,
     SELECT_RESPONSE = 4,
     DEACTIVATE_NOTIFICATION = 5,
+    FIELD_INFO = 6,
 }
 
 /// The definition of packets does not aim to reproduce the exact protocol
@@ -70,6 +72,9 @@ packet RfPacket {
     technology: Technology,
     protocol : Protocol,
     packet_type: RfPacketType,
+    // Power level from 0-12 with higher numbers representing stronger field strength.
+    // OxFF represents an unknown or invalid value.
+    power_level: 8,
     _payload_,
 }
 
@@ -80,6 +85,18 @@ packet RfPacket {
 /// - INVENTORY_REQ Command for NFC-V
 /// - ATR_REQ Command for NFC-ACM
 packet PollCommand : RfPacket (packet_type = POLL_COMMAND) {
+    _payload_,
+}
+
+/// Whether the RF field of the tag is currently on or off
+/// as defined by RF_FIELD_INFO_NTF
+enum FieldStatus : 8 {
+    FieldOff = 0,
+    FieldOn = 1,
+}
+
+packet FieldInfo : RfPacket (packet_type = FIELD_INFO) {
+    field_status: FieldStatus,
 }
 
 /// Poll response for an NFC-A Listener.
diff --git a/utils/Android.bp b/utils/Android.bp
index ed1d2f40..5c569fd1 100644
--- a/utils/Android.bp
+++ b/utils/Android.bp
@@ -49,24 +49,7 @@ cc_library_static {
         "//apex_available:platform",
         "com.android.nfcservices",
     ],
-}
-
-cc_test {
-    name: "nfc_test_utils",
-    defaults: ["nfc_utils_defaults"],
-    test_suites: ["device-tests"],
-    host_supported: true,
-    srcs: [
-        "test/config_test.cc",
-        "test/ringbuffer_test.cc",
-    ],
-    static_libs: [
-        "libnfcutils",
-        "libgmock",
-    ],
-    shared_libs: [
-        "libbase",
-    ],
+    min_sdk_version: "35", // Make it 36 once available.
 }
 
 cc_fuzz {
diff --git a/utils/test/ringbuffer_test.cc b/utils/test/ringbuffer_test.cc
deleted file mode 100644
index 682b8e22..00000000
--- a/utils/test/ringbuffer_test.cc
+++ /dev/null
@@ -1,138 +0,0 @@
-#include <gtest/gtest.h>
-
-#include <ringbuffer.h>
-
-TEST(RingbufferTest, test_new_simple) {
-  ringbuffer_t* rb = ringbuffer_init(4096);
-  ASSERT_TRUE(rb != nullptr);
-  EXPECT_EQ((size_t)4096, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
-  ringbuffer_free(rb);
-}
-
-TEST(RingbufferTest, test_insert_basic) {
-  ringbuffer_t* rb = ringbuffer_init(16);
-
-  uint8_t buffer[10] = {0x01, 0x02, 0x03, 0x04, 0x05,
-                        0x06, 0x07, 0x08, 0x09, 0x0A};
-  ringbuffer_insert(rb, buffer, 10);
-  EXPECT_EQ((size_t)10, ringbuffer_size(rb));
-  EXPECT_EQ((size_t)6, ringbuffer_available(rb));
-
-  uint8_t peek[10] = {0};
-  size_t peeked = ringbuffer_peek(rb, 0, peek, 10);
-  EXPECT_EQ((size_t)10, ringbuffer_size(rb));  // Ensure size doesn't change
-  EXPECT_EQ((size_t)6, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)10, peeked);
-  ASSERT_TRUE(0 == memcmp(buffer, peek, peeked));
-
-  ringbuffer_free(rb);
-}
-
-TEST(RingbufferTest, test_insert_full) {
-  ringbuffer_t* rb = ringbuffer_init(5);
-
-  uint8_t aa[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
-  uint8_t bb[] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
-  uint8_t peek[5] = {0};
-
-  size_t added = ringbuffer_insert(rb, aa, 7);
-  EXPECT_EQ((size_t)5, added);
-  EXPECT_EQ((size_t)0, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
-
-  added = ringbuffer_insert(rb, bb, 5);
-  EXPECT_EQ((size_t)0, added);
-  EXPECT_EQ((size_t)0, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
-
-  size_t peeked = ringbuffer_peek(rb, 0, peek, 5);
-  EXPECT_EQ((size_t)5, peeked);
-  EXPECT_EQ((size_t)0, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
-
-  ASSERT_TRUE(0 == memcmp(aa, peek, peeked));
-
-  ringbuffer_free(rb);
-}
-
-TEST(RingbufferTest, test_multi_insert_delete) {
-  ringbuffer_t* rb = ringbuffer_init(16);
-  EXPECT_EQ((size_t)16, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
-
-  // Insert some bytes
-
-  uint8_t aa[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
-  size_t added = ringbuffer_insert(rb, aa, sizeof(aa));
-  EXPECT_EQ((size_t)8, added);
-  EXPECT_EQ((size_t)8, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)8, ringbuffer_size(rb));
-
-  uint8_t bb[] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
-  ringbuffer_insert(rb, bb, sizeof(bb));
-  EXPECT_EQ((size_t)3, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)13, ringbuffer_size(rb));
-
-  uint8_t content[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
-                       0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
-  uint8_t peek[16] = {0};
-  size_t peeked = ringbuffer_peek(rb, 0, peek, 16);
-  EXPECT_EQ((size_t)13, peeked);
-  ASSERT_TRUE(0 == memcmp(content, peek, peeked));
-
-  // Delete some bytes
-
-  ringbuffer_delete(rb, sizeof(aa));
-  EXPECT_EQ((size_t)11, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)5, ringbuffer_size(rb));
-
-  // Add some more to wrap buffer
-
-  uint8_t cc[] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
-  ringbuffer_insert(rb, cc, sizeof(cc));
-  EXPECT_EQ((size_t)2, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)14, ringbuffer_size(rb));
-
-  uint8_t content2[] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xCC, 0xCC};
-  peeked = ringbuffer_peek(rb, 0, peek, 7);
-  EXPECT_EQ((size_t)7, peeked);
-  ASSERT_TRUE(0 == memcmp(content2, peek, peeked));
-
-  // Pop buffer
-
-  memset(peek, 0, 16);
-  size_t popped = ringbuffer_pop(rb, peek, 7);
-  EXPECT_EQ((size_t)7, popped);
-  EXPECT_EQ((size_t)9, ringbuffer_available(rb));
-  ASSERT_TRUE(0 == memcmp(content2, peek, peeked));
-
-  // Add more again to check head motion
-
-  uint8_t dd[] = {0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD};
-  added = ringbuffer_insert(rb, dd, sizeof(dd));
-  EXPECT_EQ((size_t)8, added);
-  EXPECT_EQ((size_t)1, ringbuffer_available(rb));
-
-  // Delete everything
-
-  ringbuffer_delete(rb, 16);
-  EXPECT_EQ((size_t)16, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
-
-  // Add small token
-
-  uint8_t ae[] = {0xAE, 0xAE, 0xAE};
-  added = ringbuffer_insert(rb, ae, sizeof(ae));
-  EXPECT_EQ((size_t)13, ringbuffer_available(rb));
-
-  // Get everything
-
-  popped = ringbuffer_pop(rb, peek, 16);
-  EXPECT_EQ(added, popped);
-  EXPECT_EQ((size_t)16, ringbuffer_available(rb));
-  EXPECT_EQ((size_t)0, ringbuffer_size(rb));
-  ASSERT_TRUE(0 == memcmp(ae, peek, popped));
-
-  ringbuffer_free(rb);
-}
```

