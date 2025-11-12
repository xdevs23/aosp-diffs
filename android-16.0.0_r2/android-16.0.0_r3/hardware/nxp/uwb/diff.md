```diff
diff --git a/extns/inc/uci_defs.h b/extns/inc/uci_defs.h
index 7ce7c16..a5c28fa 100644
--- a/extns/inc/uci_defs.h
+++ b/extns/inc/uci_defs.h
@@ -197,4 +197,6 @@ constexpr uint8_t kSessionType_AliroRanging = 0xA2;
 #define UCI_STATUS_COUNTRY_CODE_BLOCKED_CHANNEL 0x56
 #define UCI_STATUS_CODE_ANDROID_REGULATION_UWB_OFF 0x53
 
+#define UCI_MSG_SESSION_DATA_CREDIT_NTF 4
+
 #endif /* UWB_UCI_DEFS_H */
diff --git a/halimpl/hal/phNxpUciHal.cc b/halimpl/hal/phNxpUciHal.cc
index a38c395..504e1ce 100644
--- a/halimpl/hal/phNxpUciHal.cc
+++ b/halimpl/hal/phNxpUciHal.cc
@@ -534,6 +534,12 @@ static void handle_rx_packet(uint8_t *buffer, size_t length)
         // TODO: Why should we wake up the user thread here?
         nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_FAILED);
       }
+    } else if (nxpucihal_ctrl.isLastDataMsgSnd) {
+      if (gid == UCI_GID_SESSION_CONTROL && oid == UCI_MSG_SESSION_DATA_CREDIT_NTF) {
+        usleep(20); /* credit ntf received before wait is started */
+        nxpucihal_ctrl.cmdrsp.Wakeup(gid, oid);
+        nxpucihal_ctrl.isLastDataMsgSnd = false;
+      }
     }
     // End of UCI_MT_NTF
   } else if (mt == UCI_MT_RSP) {
@@ -988,6 +994,11 @@ tHAL_UWB_STATUS phNxpUciHal_hw_init()
 
   phNxpUciHal_getVersionInfo();
 
+  status = nxpucihal_ctrl.uwb_chip->core_init_post();
+  if (status != UWBSTATUS_SUCCESS) {
+    return status;
+  }
+
   return UWBSTATUS_SUCCESS;
 }
 
diff --git a/halimpl/hal/phNxpUciHal.h b/halimpl/hal/phNxpUciHal.h
index e16f668..d424941 100644
--- a/halimpl/hal/phNxpUciHal.h
+++ b/halimpl/hal/phNxpUciHal.h
@@ -281,6 +281,7 @@ typedef struct phNxpUciHal_Control {
 
   // Current country code
   uint8_t country_code[2];
+  uint8_t isLastDataMsgSnd;
 } phNxpUciHal_Control_t;
 
 // RX packet handler
diff --git a/halimpl/hal/phNxpUciHal_ext.cc b/halimpl/hal/phNxpUciHal_ext.cc
index 3cb0502..2b93ca4 100644
--- a/halimpl/hal/phNxpUciHal_ext.cc
+++ b/halimpl/hal/phNxpUciHal_ext.cc
@@ -79,8 +79,8 @@ tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(size_t cmd_len,
   }
 
   const uint8_t mt = (p_cmd[0] & UCI_MT_MASK) >> UCI_MT_SHIFT;
-  const uint8_t gid = p_cmd[0] & UCI_GID_MASK;
-  const uint8_t oid = p_cmd[1] & UCI_OID_MASK;
+  uint8_t gid = p_cmd[0] & UCI_GID_MASK;
+  uint8_t oid = p_cmd[1] & UCI_OID_MASK;
 
   // Create local copy of cmd_data
   uint8_t cmd[UCI_MAX_DATA_LEN];
@@ -94,7 +94,11 @@ tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(size_t cmd_len,
   tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
   int nr_retries = 0;
   int nr_timedout = 0;
-
+  if (mt == UCI_MT_DATA) {
+    nxpucihal_ctrl.isLastDataMsgSnd = true;
+    gid = UCI_GID_SESSION_CONTROL;
+    oid = UCI_MSG_SESSION_DATA_CREDIT_NTF;
+  }
   while(nr_retries < MAX_COMMAND_RETRY_COUNT) {
     nxpucihal_ctrl.cmdrsp.StartCmd(gid, oid);
     status = phNxpUciHal_write_unlocked(cmd_len, cmd);
@@ -330,11 +334,10 @@ static void phNxpUciHal_applyCountryCaps(const char country_code[2],
  *
  *******************************************************************************/
 static bool phNxpUciHal_is_retry_not_required(uint8_t uci_octet0) {
-  bool isRetryRequired = false, isChained_cmd = false, isData_Msg = false;
+  bool isRetryNotRequired = false, isChained_cmd = false;
   isChained_cmd = (bool)((uci_octet0 & UCI_PBF_ST_CONT) >> UCI_PBF_SHIFT);
-  isData_Msg = ((uci_octet0 & UCI_MT_MASK) >> UCI_MT_SHIFT) == UCI_MT_DATA;
-  isRetryRequired = isChained_cmd | isData_Msg;
-  return isRetryRequired;
+  isRetryNotRequired = isChained_cmd;
+  return isRetryNotRequired;
 }
 
 // TODO: remove this out
diff --git a/halimpl/inc/NxpUwbChip.h b/halimpl/inc/NxpUwbChip.h
index f6d950e..6e1ea4f 100644
--- a/halimpl/inc/NxpUwbChip.h
+++ b/halimpl/inc/NxpUwbChip.h
@@ -4,8 +4,7 @@
 #include <cstddef>
 #include <cstdint>
 
-#include <memory>
-
+#include "phUwbStatus.h"
 #include "phUwbTypes.h"
 
 // Chip type
@@ -54,9 +53,12 @@ public:
   virtual tHAL_UWB_STATUS chip_init() = 0;
 
   // Per-chip device configurations
-  // Binding check, life cycle check.
+  // Binding check, life cycle check, etc.
   virtual tHAL_UWB_STATUS core_init() = 0;
 
+  // Called right before coreInit completed.
+  virtual tHAL_UWB_STATUS core_init_post() { return UWBSTATUS_SUCCESS; }
+
   // Determine device_type_t from DEVICE_INFO_RSP::UWB_CHIP_ID
   virtual device_type_t get_device_type(const uint8_t* param, size_t param_len) = 0;
 
@@ -64,7 +66,7 @@ public:
   virtual tHAL_UWB_STATUS read_otp(extcal_param_id_t id,
                                    uint8_t *data,
                                    size_t data_len,
-                                   size_t *retlen);
+                                   size_t *retlen) { return UWBSTATUS_NOT_ALLOWED; }
 
   // Apply device calibration
   virtual tHAL_UWB_STATUS apply_calibration(extcal_param_id_t id,
```

