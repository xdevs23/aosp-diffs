```diff
diff --git a/1.0/hal/halcore.c b/1.0/hal/halcore.c
index da5a90a..ba7e875 100644
--- a/1.0/hal/halcore.c
+++ b/1.0/hal/halcore.c
@@ -277,8 +277,8 @@ void HalDestroy(HALHANDLE hHAL) {
  * @param hHAL HAL handle
  * @param data Data message
  * @param size Message size
- */ bool HalSendDownstream(HALHANDLE hHAL, const uint8_t* data, size_t size)
-{
+ */
+bool HalSendDownstream(HALHANDLE hHAL, const uint8_t* data, size_t size) {
   // Send an NCI frame downstream. will
   HalInstance* inst = (HalInstance*)hHAL;
 
@@ -316,9 +316,9 @@ void HalDestroy(HALHANDLE hHAL) {
  * @param hHAL HAL handle
  * @param data Data message
  * @param size Message size
- */ bool HalSendDownstreamTimer(HALHANDLE hHAL, const uint8_t* data,
-                                size_t size, uint8_t duration)
-{
+ */
+bool HalSendDownstreamTimer(HALHANDLE hHAL, const uint8_t* data, size_t size,
+                            uint8_t duration) {
   // Send an NCI frame downstream. will
   HalInstance* inst = (HalInstance*)hHAL;
 
diff --git a/aidl/Android.bp b/aidl/Android.bp
index 3d44275..1227573 100644
--- a/aidl/Android.bp
+++ b/aidl/Android.bp
@@ -37,7 +37,7 @@ cc_binary {
     defaults: ["android.hardware.nfc-service.st_default"],
     relative_install_path: "hw",
     init_rc: ["nfc-service-default.rc"],
-    vintf_fragments: ["nfc-service-default.xml"],
+    vintf_fragment_modules: ["nfc-service-default.xml"],
     vendor: true,
     cflags: [
         "-Wall",
@@ -61,6 +61,12 @@ cc_binary {
     },
 }
 
+vintf_fragment {
+    name: "nfc-service-default.xml",
+    src: "nfc-service-default.xml",
+    vendor: true,
+}
+
 cc_fuzz {
     name: "nfc_service_fuzzer",
     defaults: [
@@ -73,13 +79,6 @@ cc_fuzz {
     vendor: true,
 }
 
-prebuilt_etc {
-    name: "nfc-service-default.xml",
-    src: "nfc-service-default.xml",
-    sub_dir: "vintf",
-    installable: false,
-}
-
 genrule {
     name: "com.google.android.hardware.nfc.st.rc-gen",
     srcs: ["nfc-service-default.rc"],
@@ -105,7 +104,6 @@ apex {
     binaries: ["android.hardware.nfc-service.st"],
     prebuilts: [
         "com.google.android.hardware.nfc.st.rc",
-        "nfc-service-default.xml",
         "android.hardware.nfc.prebuilt.xml",
         "android.hardware.nfc.hce.prebuilt.xml",
         "android.hardware.nfc.hcef.prebuilt.xml",
diff --git a/aidl/StNfc_hal_api.h b/aidl/StNfc_hal_api.h
index 1df55b6..0e172a8 100644
--- a/aidl/StNfc_hal_api.h
+++ b/aidl/StNfc_hal_api.h
@@ -66,7 +66,6 @@ void StNfc_hal_setLogging(bool enable);
 bool StNfc_hal_isLoggingEnabled();
 
 void StNfc_hal_dump(int fd);
-uint16_t
-iso14443_crc(const uint8_t *data, size_t szLen, int type);
+uint16_t iso14443_crc(const uint8_t* data, size_t szLen, int type);
 
 #endif /* _STNFC_HAL_API_H_ */
diff --git a/aidl/hal_st21nfc.cc b/aidl/hal_st21nfc.cc
index fddbfa3..0fd5553 100644
--- a/aidl/hal_st21nfc.cc
+++ b/aidl/hal_st21nfc.cc
@@ -39,13 +39,11 @@
 #endif
 #define VENDOR_LIB_EXT ".so"
 
-
 #define CRC_PRESET_A 0x6363
 #define CRC_PRESET_B 0xFFFF
 #define Type_A 0
 #define Type_B 1
 
-
 bool dbg_logging = false;
 
 extern void HalCoreCallback(void* context, uint32_t event, const void* d,
@@ -403,7 +401,7 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
              p_data[3] == 0x6) {
     DispHal("TX DATA", (p_data), data_len);
 
-    memcpy(nci_cmd+3, p_data+4, 4);
+    memcpy(nci_cmd + 3, p_data + 4, 4);
     nci_cmd[0] = 0x2f;
     nci_cmd[1] = 0x19;
 
@@ -448,8 +446,8 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
       memcpy(nci_cmd + ll_index, p_data + index, (tlv_len - 1) / 2);
       for (int i = 0; i < (tlv_len - 1) / 2; ++i) {
         if (p_data[index + i] != 0xFF) {
-            exact_match = false;
-            break;
+          exact_match = false;
+          break;
         }
       }
       ll_index += (tlv_len - 1) / 2;
@@ -460,14 +458,13 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
         nci_cmd[ll_index++] = crc_mask;
 
         if (!exact_match) {
-        nci_cmd[crc_index] = crc_mask;
-        nci_cmd[crc_index +1] = crc_mask;
+          nci_cmd[crc_index] = crc_mask;
+          nci_cmd[crc_index + 1] = crc_mask;
         }
-
       }
     }
     nci_length = ll_index;
-    nci_cmd[2] = ll_index -3;
+    nci_cmd[2] = ll_index - 3;
 
     if (!HalSendDownstream(dev.hHAL, nci_cmd, nci_length)) {
       STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
@@ -477,18 +474,29 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
   } else if (!memcmp(p_data, NCI_ANDROID_PREFIX, sizeof(NCI_ANDROID_PREFIX)) &&
              p_data[3] == 0x9) {
     DispHal("TX DATA", (p_data), data_len);
+    if (data_len < 5) {
+      STLOG_HAL_E("HAL st21nfc %s  data_len is too short", __func__);
+      (void)pthread_mutex_unlock(&hal_mtx);
+      return 0;
+    }
     memcpy(nci_cmd + 3, p_data + 4, data_len - 4);
-
-    uint16_t crc = iso14443_crc(nci_cmd + 7, nci_cmd[5] - 1, Type_A);
-
-    uint8_t len = p_data[2];
     nci_cmd[0] = 0x2f;
     nci_cmd[1] = 0x1d;
-    nci_cmd[5] = nci_cmd[5] + 2;
-    nci_cmd[data_len - 1] = (uint8_t)crc;
-    nci_cmd[data_len] = (uint8_t)(crc >> 8);
+    if (p_data[2] == 0x2 && p_data[4] == 0x0) {
+      nci_cmd[2] = 0x1;
+    } else {
+      uint16_t crc = 0;
+      if (nci_cmd[5] > 0) {
+        crc = iso14443_crc(nci_cmd + 7, nci_cmd[5] - 1, Type_A);
+      }
+
+      uint8_t len = p_data[2];
+      nci_cmd[5] = nci_cmd[5] + 2;
+      nci_cmd[data_len - 1] = (uint8_t)crc;
+      nci_cmd[data_len] = (uint8_t)(crc >> 8);
 
-    nci_cmd[2] = p_data[2] + 1;
+      nci_cmd[2] = p_data[2] + 1;
+    }
     if (!HalSendDownstream(dev.hHAL, nci_cmd, nci_cmd[2] + 3)) {
       STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
       (void)pthread_mutex_unlock(&hal_mtx);
diff --git a/st21nfc/adaptation/i2clayer.cc b/st21nfc/adaptation/i2clayer.cc
index 54589cc..1e00c97 100644
--- a/st21nfc/adaptation/i2clayer.cc
+++ b/st21nfc/adaptation/i2clayer.cc
@@ -33,6 +33,7 @@
 
 #include "android_logmsg.h"
 #include "hal_config.h"
+#include "hal_event_logger.h"
 #include "halcore.h"
 #include "halcore_private.h"
 
@@ -50,11 +51,13 @@
 #define ST21NFC_CLK_STATE _IOR(ST21NFC_MAGIC, 0x13, unsigned int)
 
 #define LINUX_DBGBUFFER_SIZE 300
+#define I2C_ERROR_COUNT_MAX 50
 
 static int fidI2c = 0;
 static int cmdPipe[2] = {0, 0};
 static int notifyResetRequest = 0;
 static bool recovery_mode = false;
+static uint16_t i2c_error_count = 0;
 
 static struct pollfd event_table[3];
 static pthread_t threadHandle = (pthread_t)NULL;
@@ -93,7 +96,7 @@ static void* I2cWorkerThread(void* arg) {
   STLOG_HAL_D("echo thread started...\n");
   bool readOk = false;
   int eventNum = (notifyResetRequest <= 0) ? 2 : 3;
-  bool resetting= false;
+  bool resetting = false;
 
   do {
     event_table[0].fd = fidI2c;
@@ -169,7 +172,11 @@ static void* I2cWorkerThread(void* arg) {
               bytesRead = i2cRead(fidI2c, buffer + 3, remaining);
             }
             if (bytesRead == remaining) {
-              DispHal("RX DATA", buffer, 3 + bytesRead);
+              if ((buffer[0] == 0x6f) && (buffer[1] == 0x02)) {
+                if (mDisplayFwLog) DispHal("RX DATA", buffer, 3 + bytesRead);
+              } else {
+                DispHal("RX DATA", buffer, 3 + bytesRead);
+              }
               HalSendUpstream(hHAL, buffer, 3 + bytesRead);
             } else {
               readOk = false;
@@ -177,8 +184,16 @@ static void* I2cWorkerThread(void* arg) {
             }
           }
 
+          i2c_error_count = 0;
         } else {
           STLOG_HAL_E("! didn't read 3 requested bytes from i2c\n");
+          if (i2c_error_count < I2C_ERROR_COUNT_MAX) {
+            HalEventLogger::getInstance().log()
+                << "! didn't read 3 requested bytes from i2c, bytesRead:"
+                << bytesRead << " errno " << errno
+                << " count:" << i2c_error_count << std::endl;
+            i2c_error_count++;
+          }
         }
 
         readOk = false;
@@ -232,9 +247,9 @@ static void* I2cWorkerThread(void* arg) {
       if (byte < 10) {
         reset[byte] = '\0';
       }
-      if (byte > 0 && reset[0] == '1' && resetting== false) {
+      if (byte > 0 && reset[0] == '1' && resetting == false) {
         STLOG_HAL_E("trigger NFCC reset.. \n");
-        resetting= true;
+        resetting = true;
         i2cResetPulse(fidI2c);
       }
     }
diff --git a/st21nfc/hal/hal_fwlog.cc b/st21nfc/hal/hal_fwlog.cc
index 6aee8b1..2cbfbba 100644
--- a/st21nfc/hal/hal_fwlog.cc
+++ b/st21nfc/hal/hal_fwlog.cc
@@ -78,12 +78,16 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
       }
 
       // work-around type-A short frame notification bug
-      if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54J &&
-          (tlvBuffer[2] & 0xF) == 0x01 &&  // short frame
-          tlvBuffer[5] == 0x00 &&          // no error
-          tlvBuffer[6] == 0x0F             // incorrect real size
-      ) {
-        tlv_size = 9;
+      if (hal_fd_getFwInfo() != NULL) {
+        if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54J &&
+            (tlvBuffer[2] & 0xF) == 0x01 &&  // short frame
+            tlvBuffer[5] == 0x00 &&          // no error
+            tlvBuffer[6] == 0x0F             // incorrect real size
+        ) {
+          tlv_size = 9;
+        }
+      } else {
+        return 0;
       }
 
       value_len = tlv_size - 3;
diff --git a/st21nfc/hal/hal_fwlog.h b/st21nfc/hal/hal_fwlog.h
index 193def3..c7d17a7 100644
--- a/st21nfc/hal/hal_fwlog.h
+++ b/st21nfc/hal/hal_fwlog.h
@@ -45,9 +45,9 @@ typedef union timestamp_bytes {
   uint8_t ts4;
 } timestamp_bytes;
 
-int notifyPollingLoopFrames(uint8_t *p_data, uint16_t data_len,
-                            uint8_t *bufferToSend);
-uint8_t handlePollingLoopData(uint8_t *tlvBuffer, uint16_t data_len,
-                              uint8_t **NewTlv);
+int notifyPollingLoopFrames(uint8_t* p_data, uint16_t data_len,
+                            uint8_t* bufferToSend);
+uint8_t handlePollingLoopData(uint8_t* tlvBuffer, uint16_t data_len,
+                              uint8_t** NewTlv);
 
 #endif
diff --git a/st21nfc/hal/halcore.cc b/st21nfc/hal/halcore.cc
index da5d043..599e298 100644
--- a/st21nfc/hal/halcore.cc
+++ b/st21nfc/hal/halcore.cc
@@ -43,14 +43,14 @@ struct timespec start_tx_data;
 uint8_t NCI_ANDROID_GET_CAPS[] = {0x2f, 0x0c, 0x01, 0x0};
 uint8_t NCI_ANDROID_GET_CAPS_RSP[] = {
     0x4f, 0x0c,
-    0x14,                          // Command length
+    0x14,  // Command length
     0x00, 0x00, 0x00, 0x00,
-    0x05,                          // Nb of capabilities
-    0x00, 0x01, 0x01,              // Passive Observe mode
-    0x01, 0x01, 0x01,              // Polling frame ntf
-    0x03, 0x01, 0x00,              // Autotransact polling loop filter
-    0x04, 0x01, 0x05,              // Nb of max exit frame entries
-    0x05, 0x01, 0x01               // Polling loop annotations
+    0x05,              // Nb of capabilities
+    0x00, 0x01, 0x01,  // Passive Observe mode
+    0x01, 0x01, 0x01,  // Polling frame ntf
+    0x03, 0x01, 0x00,  // Autotransact polling loop filter
+    0x04, 0x01, 0x05,  // Nb of max exit frame entries
+    0x05, 0x01, 0x01   // Polling loop annotations
 };
 
 /**************************************************************************************************
@@ -122,15 +122,17 @@ void HalCoreCallback(void* context, uint32_t event, const void* d,
         NCI_ANDROID_GET_CAPS_RSP[2] = sizeof(NCI_ANDROID_GET_CAPS_RSP) - 3;
         NCI_ANDROID_GET_CAPS_RSP[10] = hal_fd_getFwCap()->ObserveMode;
         NCI_ANDROID_GET_CAPS_RSP[16] = hal_fd_getFwCap()->ExitFrameSupport;
-        uint8_t FWVersionMajor = (uint8_t)(hal_fd_getFwInfo()->chipFwVersion >> 24);
+        uint8_t FWVersionMajor =
+            (uint8_t)(hal_fd_getFwInfo()->chipFwVersion >> 24);
         uint8_t FWVersionMinor =
-          (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
-        // Declare support for reader mode annotation only if fw version >= 2.06.
+            (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
+        // Declare support for reader mode annotation only if fw version
+        // >= 2.06.
         if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54L &&
-          (FWVersionMajor >= 0x2) && (FWVersionMinor >= 0x6)) {
-            NCI_ANDROID_GET_CAPS_RSP[22] = 1;
+            (FWVersionMajor >= 0x2) && (FWVersionMinor >= 0x6)) {
+          NCI_ANDROID_GET_CAPS_RSP[22] = 1;
         } else {
-            NCI_ANDROID_GET_CAPS_RSP[22] = 0;
+          NCI_ANDROID_GET_CAPS_RSP[22] = 0;
         }
 
         dev->p_data_cback(sizeof(NCI_ANDROID_GET_CAPS_RSP),
diff --git a/st21nfc/hal_wrapper.cc b/st21nfc/hal_wrapper.cc
index c86238d..a1f0443 100644
--- a/st21nfc/hal_wrapper.cc
+++ b/st21nfc/hal_wrapper.cc
@@ -30,6 +30,7 @@
 #include "hal_fwlog.h"
 #include "halcore.h"
 #include "st21nfc_dev.h"
+#define OPEN_TIMEOUT_MAX_COUNT 5
 
 extern void HalCoreCallback(void* context, uint32_t event, const void* d,
                             size_t length);
@@ -40,6 +41,7 @@ extern void I2cRecovery();
 static void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data);
 static void halWrapperCallback(uint8_t event, uint8_t event_status);
 static std::string hal_wrapper_state_to_str(uint16_t event);
+static void hal_wrapper_store_timeout_log();
 
 nfc_stack_callback_t* mHalWrapperCallback = NULL;
 nfc_stack_data_callback_t* mHalWrapperDataCallback = NULL;
@@ -84,6 +86,9 @@ bool mObserverRsp = false;
 bool mPerTechCmdRsp = false;
 bool storedLog = false;
 bool mObserveModeSuspended = false;
+static uint16_t OpenTimeoutCount = 0;
+
+bool mDisplayFwLog = false;
 
 void wait_ready() {
   pthread_mutex_lock(&mutex);
@@ -119,6 +124,7 @@ bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
   mObserverMode = 0;
   mObserverRsp = false;
   mObserveModeSuspended = false;
+  mDisplayFwLog = false;
 
   mHalWrapperCallback = p_cback;
   mHalWrapperDataCallback = p_data_cback;
@@ -137,6 +143,7 @@ bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
 
   HalEventLogger::getInstance().initialize();
   HalEventLogger::getInstance().log() << __func__ << std::endl;
+
   HalSendDownstreamTimer(mHalHandle, 10000);
 
   return 1;
@@ -450,10 +457,13 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
               if (firmware_debug_enabled || sEnableFwLog) {
                 num = 1;
                 swp_log = 30;
+                mDisplayFwLog = true;
               } else if (isDebuggable) {
                 swp_log = 30;
+                mDisplayFwLog = true;
               } else {
                 swp_log = 8;
+                mDisplayFwLog = false;
               }
               rf_log = 15;
 
@@ -563,9 +573,9 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
               mObserverMode = p_data[4];
             }
             if (!mObserveModeSuspended) {
-            p_data[5] = p_data[4];
+              p_data[5] = p_data[4];
             } else {
-              p_data[5] =  0x00;
+              p_data[5] = 0x00;
             }
           } else {
             if (p_data[7] != mObserverMode) {
@@ -845,17 +855,26 @@ static void halWrapperCallback(uint8_t event,
 
     case HAL_WRAPPER_STATE_OPEN:
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
-        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout accessing the CLF.", __func__);
+        OpenTimeoutCount++;
+        STLOG_HAL_E(
+            "NFC-NCI HAL: %s  Timeout accessing the CLF. OpenTimeoutCount:d",
+            __func__, OpenTimeoutCount);
         HalSendDownstreamStopTimer(mHalHandle);
-        I2cRecovery();
-        HalEventLogger::getInstance().log()
-            << __func__ << " Timeout accessing the CLF."
-            << " mHalWrapperState="
-            << hal_wrapper_state_to_str(mHalWrapperState)
-            << " mIsActiveRW=" << mIsActiveRW
-            << " mTimerStarted=" << mTimerStarted << std::endl;
-        HalEventLogger::getInstance().store_log();
-        abort();  // TODO: fix it when we have a better recovery method.
+        hal_wrapper_store_timeout_log();
+        if (OpenTimeoutCount > OPEN_TIMEOUT_MAX_COUNT) {
+          mHalWrapperState = HAL_WRAPPER_STATE_CLOSED;
+          OpenTimeoutCount = 0;
+          return;
+        }
+        p_data[0] = 0x60;
+        p_data[1] = 0x00;
+        p_data[2] = 0x03;
+        p_data[3] = 0xAF;
+        p_data[4] = 0x00;
+        p_data[5] = 0x00;
+        data_len = 0x6;
+        mHalWrapperDataCallback(data_len, p_data);
+        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
         return;
       }
       break;
@@ -872,18 +891,17 @@ static void halWrapperCallback(uint8_t event,
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         STLOG_HAL_E("%s - Timer for FW update procedure timeout, retry",
                     __func__);
-        HalEventLogger::getInstance().log()
-            << __func__ << " Timer for FW update procedure timeout, retry"
-            << " mHalWrapperState="
-            << hal_wrapper_state_to_str(mHalWrapperState)
-            << " mIsActiveRW=" << mIsActiveRW
-            << " mTimerStarted=" << mTimerStarted << std::endl;
-        HalEventLogger::getInstance().store_log();
-        abort();  // TODO: fix it when we have a better recovery method.
-        HalSendDownstreamStopTimer(mHalHandle);
-        resetHandlerState();
-        I2cResetPulse();
+        hal_wrapper_store_timeout_log();
+        p_data[0] = 0x60;
+        p_data[1] = 0x00;
+        p_data[2] = 0x03;
+        p_data[3] = 0xAE;
+        p_data[4] = 0x00;
+        p_data[5] = 0x00;
+        data_len = 0x6;
+        mHalWrapperDataCallback(data_len, p_data);
         mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
+        return;
       }
       break;
 
@@ -901,13 +919,7 @@ static void halWrapperCallback(uint8_t event,
     case HAL_WRAPPER_STATE_PROP_CONFIG:
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         STLOG_HAL_E("%s - Timer when sending conf parameters, retry", __func__);
-        HalEventLogger::getInstance().log()
-            << __func__ << " Timer when sending conf parameters, retry"
-            << " mHalWrapperState="
-            << hal_wrapper_state_to_str(mHalWrapperState)
-            << " mIsActiveRW=" << mIsActiveRW
-            << " mTimerStarted=" << mTimerStarted << std::endl;
-        HalEventLogger::getInstance().store_log();
+        hal_wrapper_store_timeout_log();
         abort();  // TODO: fix it when we have a better recovery method.
         HalSendDownstreamStopTimer(mHalHandle);
         resetHandlerState();
@@ -951,13 +963,7 @@ static void halWrapperCallback(uint8_t event,
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
                     hal_wrapper_state_to_str(mHalWrapperState).c_str());
-        HalEventLogger::getInstance().log()
-            << __func__ << " Timer when sending conf parameters, retry"
-            << " mHalWrapperState="
-            << hal_wrapper_state_to_str(mHalWrapperState)
-            << " mIsActiveRW=" << mIsActiveRW
-            << " mTimerStarted=" << mTimerStarted << std::endl;
-        HalEventLogger::getInstance().store_log();
+        hal_wrapper_store_timeout_log();
         HalSendDownstreamStopTimer(mHalHandle);
         p_data[0] = 0x60;
         p_data[1] = 0x00;
@@ -972,17 +978,69 @@ static void halWrapperCallback(uint8_t event,
       }
       break;
 
+    case HAL_WRAPPER_STATE_OPEN_CPLT:
+      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
+        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
+                    hal_wrapper_state_to_str(mHalWrapperState).c_str());
+        hal_wrapper_store_timeout_log();
+        HalSendDownstreamStopTimer(mHalHandle);
+        p_data[0] = 0x60;
+        p_data[1] = 0x00;
+        p_data[2] = 0x03;
+        p_data[3] = 0xAC;
+        p_data[4] = 0x00;
+        p_data[5] = 0x00;
+        data_len = 0x6;
+        mHalWrapperDataCallback(data_len, p_data);
+        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
+        return;
+      }
+      break;
+
+    case HAL_WRAPPER_STATE_APPLY_CUSTOM_PARAM:
+      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
+        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
+                    hal_wrapper_state_to_str(mHalWrapperState).c_str());
+        hal_wrapper_store_timeout_log();
+        HalSendDownstreamStopTimer(mHalHandle);
+        p_data[0] = 0x60;
+        p_data[1] = 0x00;
+        p_data[2] = 0x03;
+        p_data[3] = 0xAD;
+        p_data[4] = 0x00;
+        p_data[5] = 0x00;
+        data_len = 0x6;
+        mHalWrapperDataCallback(data_len, p_data);
+        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
+        return;
+      }
+      break;
+
+    case HAL_WRAPPER_STATE_RECOVERY:
+      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
+        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
+                    hal_wrapper_state_to_str(mHalWrapperState).c_str());
+        hal_wrapper_store_timeout_log();
+        HalSendDownstreamStopTimer(mHalHandle);
+        p_data[0] = 0x60;
+        p_data[1] = 0x00;
+        p_data[2] = 0x03;
+        p_data[3] = 0xBA;
+        p_data[4] = 0x00;
+        p_data[5] = 0x00;
+        data_len = 0x6;
+        mHalWrapperDataCallback(data_len, p_data);
+        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
+        return;
+      }
+      break;
+
     default:
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
                     hal_wrapper_state_to_str(mHalWrapperState).c_str());
         if (!storedLog) {
-          HalEventLogger::getInstance().log()
-              << __func__ << " Timeout at state: "
-              << hal_wrapper_state_to_str(mHalWrapperState)
-              << " mIsActiveRW=" << mIsActiveRW
-              << " mTimerStarted=" << mTimerStarted << std::endl;
-          HalEventLogger::getInstance().store_log();
+          hal_wrapper_store_timeout_log();
           storedLog = true;
         }
       }
@@ -1079,4 +1137,20 @@ static std::string hal_wrapper_state_to_str(uint16_t event) {
     default:
       return "Unknown";
   }
+}
+
+/*******************************************************************************
+**
+** Function         hal_wrapper_store_timeout_log
+**
+** Description      Store timeout event logs.
+**
+** Returns          void
+*******************************************************************************/
+static void hal_wrapper_store_timeout_log() {
+  HalEventLogger::getInstance().log()
+      << " Timeout at state: " << hal_wrapper_state_to_str(mHalWrapperState)
+      << " mIsActiveRW=" << mIsActiveRW << " mTimerStarted=" << mTimerStarted
+      << std::endl;
+  HalEventLogger::getInstance().store_log();
 }
\ No newline at end of file
diff --git a/st21nfc/include/android_logmsg.h b/st21nfc/include/android_logmsg.h
index 5766239..fe1d827 100644
--- a/st21nfc/include/android_logmsg.h
+++ b/st21nfc/include/android_logmsg.h
@@ -40,6 +40,8 @@ extern int GetByteArrayValue(const char* name, char* pValue, long bufflen,
                              long* len);
 extern int GetStrValue(const char* name, char* pValue, unsigned long l);
 
+extern bool mDisplayFwLog;
+
 /* #######################
  * Set the log module name in .conf file
  * ########################## */
```

