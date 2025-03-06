```diff
diff --git a/1.0/adaptation/i2clayer.c b/1.0/adaptation/i2clayer.c
index 7cabc7a..35a96ac 100644
--- a/1.0/adaptation/i2clayer.c
+++ b/1.0/adaptation/i2clayer.c
@@ -98,7 +98,7 @@ static void* I2cWorkerThread(void* arg)
 
         if (-1 == poll_status) {
             STLOG_HAL_E("error in poll call\n");
-            return false;
+            return 0;
         }
 
         if (event_table[0].revents & POLLIN) {
diff --git a/aidl/hal_st21nfc.cc b/aidl/hal_st21nfc.cc
index 5a56b6c..e46c080 100644
--- a/aidl/hal_st21nfc.cc
+++ b/aidl/hal_st21nfc.cc
@@ -30,6 +30,7 @@
 #include "hal_config.h"
 #include "halcore.h"
 #include "st21nfc_dev.h"
+#include "hal_fd.h"
 
 #if defined(ST_LIB_32)
 #define VENDOR_LIB_PATH "/vendor/lib/"
@@ -312,6 +313,18 @@ int StNfc_hal_open(nfc_stack_callback_t* p_cback,
 int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
   STLOG_HAL_D("HAL st21nfc: %s", __func__);
 
+  uint8_t NCI_ANDROID_PASSIVE_OBSERVER_PREFIX[] = {0x2f, 0x0c, 0x02, 0x02};
+  uint8_t NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX[] = {0x2f, 0x0c, 0x01, 0x4};
+  uint8_t RF_GET_LISTEN_OBSERVE_MODE_STATE[5] = {0x21, 0x17, 0x00};
+  uint8_t RF_SET_LISTEN_OBSERVE_MODE_STATE[4] = {0x21, 0x16, 0x01, 0x0};
+  uint8_t CORE_GET_CONFIG_OBSERVER[5] = {0x20, 0x03, 0x02, 0x01, 0xa3};
+  uint8_t CORE_SET_CONFIG_OBSERVER[7] = {0x20, 0x02, 0x04, 0x01,
+                                         0xa3, 0x01, 0x00};
+  uint8_t* mGetObserve = CORE_GET_CONFIG_OBSERVER;
+  uint8_t mGetObserve_size = 5;
+  uint8_t* mSetObserve = CORE_SET_CONFIG_OBSERVER;
+  uint8_t mSetObserve_size = 7;
+  uint8_t mTechObserved = 0x0;
   /* check if HAL is closed */
   int ret = (int)data_len;
   (void)pthread_mutex_lock(&hal_mtx);
@@ -324,26 +337,38 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
     return ret;
   }
 
-  uint8_t NCI_ANDROID_PASSIVE_OBSERVER_PREFIX[] = {0x2f, 0x0c, 0x02, 0x02};
-  uint8_t NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX[] = {0x2f, 0x0c, 0x01, 0x4};
-  if (data_len == 4 && !memcmp(p_data, NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX,
-                               sizeof(NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX))) {
-    uint8_t CORE_GET_CONFIG_OBSERVER[5] = {0x20, 0x03, 0x02, 0x01, 0xa3};
+  if (data_len == 4 &&
+      !memcmp(p_data, NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX,
+              sizeof(NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX))) {
     hal_wrapper_get_observer_mode();
-    if (!HalSendDownstream(dev.hHAL, CORE_GET_CONFIG_OBSERVER, 5)) {
+    if (hal_fd_getFwCap()->ObserveMode == 2) {
+      mGetObserve = RF_GET_LISTEN_OBSERVE_MODE_STATE;
+      mGetObserve_size = 3;
+    }
+    if (!HalSendDownstream(dev.hHAL, mGetObserve, mGetObserve_size)) {
       STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
       (void)pthread_mutex_unlock(&hal_mtx);
       return 0;
     }
   }
 
-  else if (data_len == 5 && !memcmp(p_data, NCI_ANDROID_PASSIVE_OBSERVER_PREFIX,
-                               sizeof(NCI_ANDROID_PASSIVE_OBSERVER_PREFIX))) {
-    uint8_t CORE_SET_CONFIG_OBSERVER[7] = {0x20, 0x02, 0x04, 0x01,
-                                           0xa3, 0x01, p_data[4]};
+  else if (data_len == 5 &&
+           !memcmp(p_data, NCI_ANDROID_PASSIVE_OBSERVER_PREFIX,
+                   sizeof(NCI_ANDROID_PASSIVE_OBSERVER_PREFIX))) {
+    if (hal_fd_getFwCap()->ObserveMode == 2) {
+      mSetObserve = RF_SET_LISTEN_OBSERVE_MODE_STATE;
+      mSetObserve_size = 4;
+      if (p_data[4]) {
+        mTechObserved = 0x7;
+      }
+      mSetObserve[3] = mTechObserved;
+      hal_wrapper_set_observer_mode(mTechObserved);
+    } else {
+      mSetObserve[6] = p_data[4];
+      hal_wrapper_set_observer_mode(p_data[4]);
+    }
 
-    hal_wrapper_set_observer_mode(p_data[4]);
-    if (!HalSendDownstream(dev.hHAL, CORE_SET_CONFIG_OBSERVER, 7)) {
+    if (!HalSendDownstream(dev.hHAL, mSetObserve, mSetObserve_size)) {
       STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
       (void)pthread_mutex_unlock(&hal_mtx);
       return 0;
diff --git a/st21nfc/hal/hal_fd.cc b/st21nfc/hal/hal_fd.cc
index d9bbe5b..3cf002f 100644
--- a/st21nfc/hal/hal_fd.cc
+++ b/st21nfc/hal/hal_fd.cc
@@ -27,6 +27,9 @@
 #include "halcore.h"
 /* Initialize fw info structure pointer used to access fw info structure */
 FWInfo *mFWInfo = NULL;
+
+FWCap *mFWCap = NULL;
+
 FILE *mFwFileBin;
 FILE *mCustomFileBin;
 fpos_t mPos;
@@ -211,6 +214,15 @@ int hal_fd_init() {
 
   memset(mFWInfo, 0, sizeof(FWInfo));
 
+  // Initializing structure holding FW Capabilities
+  mFWCap = (FWCap *)malloc(sizeof(FWCap));
+
+  if (mFWCap == NULL) {
+    result = 0;
+  }
+
+  memset(mFWCap, 0, sizeof(FWCap));
+
   mFwFileBin = NULL;
   mCustomFileBin = NULL;
 
@@ -312,6 +324,11 @@ FWInfo* hal_fd_getFwInfo() {
    return mFWInfo;
 }
 
+FWCap* hal_fd_getFwCap() {
+  STLOG_HAL_D("  %s -enter", __func__);
+   return mFWCap;
+}
+
 /**
  * Send a HW reset and decode NCI_CORE_RESET_NTF information
  * @param pHwVersion is used to return HW version, part of NCI_CORE_RESET_NTF
@@ -342,7 +359,9 @@ uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
     mFWInfo->chipFwVersion =
         (pdata[10] << 24) | (pdata[11] << 16) | (pdata[12] << 8) | pdata[13];
     STLOG_HAL_D("   FwVersion = 0x%08X", mFWInfo->chipFwVersion);
-
+    uint8_t FWVersionMajor = (uint8_t)(hal_fd_getFwInfo()->chipFwVersion >> 24);
+    uint8_t FWVersionMinor =
+        (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
     /* retrieve Loader Version from NCI_CORE_RESET_NTF */
     mFWInfo->chipLoaderVersion =
         (pdata[14] << 16) | (pdata[15] << 8) | pdata[16];
@@ -434,6 +453,16 @@ uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
     mUwbConfigNeeded = true;
   }
 
+  uint8_t FWVersionMajor = (uint8_t)(hal_fd_getFwInfo()->chipFwVersion >> 24);
+  uint8_t FWVersionMinor =
+        (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
+
+  if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54L &&
+      (FWVersionMajor >= 0x2) && (FWVersionMinor >= 0x5)) {
+    mFWCap->ObserveMode = 0x2;
+  } else {
+    mFWCap->ObserveMode = 0x1;
+  }
   return result;
 } /* ft_cmd_HwReset */
 
diff --git a/st21nfc/hal/hal_fwlog.cc b/st21nfc/hal/hal_fwlog.cc
index cd75907..615c366 100644
--- a/st21nfc/hal/hal_fwlog.cc
+++ b/st21nfc/hal/hal_fwlog.cc
@@ -120,7 +120,11 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
           type = TYPE_UNKNOWN;
           break;
       }
-      if (tlvBuffer[5] != 0) {
+      if ((tlvBuffer[5] != 0) ||
+          ((type == TYPE_A) &&
+           (tlvBuffer[8] != 0x26 && tlvBuffer[8] != 0x52)) ||
+          ((type == TYPE_B) && (tlvBuffer[8] != 0x05) &&
+           (length_value == 0x3))) {
         // if error flag is set, consider the frame as unknown.
         type = TYPE_UNKNOWN;
       }
diff --git a/st21nfc/hal/halcore.cc b/st21nfc/hal/halcore.cc
index dcbbb1d..da1bae7 100644
--- a/st21nfc/hal/halcore.cc
+++ b/st21nfc/hal/halcore.cc
@@ -114,6 +114,8 @@ void HalCoreCallback(void* context, uint32_t event, const void* d,
       DispHal("TX DATA", (data), length);
       if (length == 4 && !memcmp(data, NCI_ANDROID_GET_CAPS,
            sizeof(NCI_ANDROID_GET_CAPS))) {
+          NCI_ANDROID_GET_CAPS_RSP[10] = hal_fd_getFwCap()->ObserveMode;
+
         dev->p_data_cback(NCI_ANDROID_GET_CAPS_RSP[2]+3, NCI_ANDROID_GET_CAPS_RSP);
       } else {
         // Send write command to IO thread
diff --git a/st21nfc/hal_wrapper.cc b/st21nfc/hal_wrapper.cc
index c3bb0c0..381a94f 100644
--- a/st21nfc/hal_wrapper.cc
+++ b/st21nfc/hal_wrapper.cc
@@ -205,9 +205,8 @@ void hal_wrapper_set_observer_mode(uint8_t enable) {
   mObserverMode = enable;
   mObserverRsp = true;
 }
-void hal_wrapper_get_observer_mode() {
-  mObserverRsp = true;
-}
+void hal_wrapper_get_observer_mode() { mObserverRsp = true; }
+
 void hal_wrapper_update_complete() {
   STLOG_HAL_V("%s ", __func__);
   mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_OK);
@@ -523,7 +522,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
     case HAL_WRAPPER_STATE_READY:  // 5
       STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_READY", __func__);
       if (mObserverRsp) {
-        if ((p_data[0] == 0x40) && (p_data[1] == 0x02)) {
+        if (((p_data[0] == 0x41) && (p_data[1] == 0x16)) ||
+            ((p_data[0] == 0x40) && (p_data[1] == 0x02))) {
           uint8_t rsp_status = p_data[3];
           mObserverRsp = false;
           p_data[0] = 0x4f;
@@ -532,21 +532,32 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
           p_data[3] = 0x02;
           p_data[4] = rsp_status;
           data_len = 0x5;
-        } else if ((p_data[0] == 0x40) && (p_data[1] == 0x03) && (data_len > 7)) {
-            uint8_t rsp_status = p_data[3];
-            mObserverRsp = false;
+        } else if (((p_data[0] == 0x41) && (p_data[1] == 0x17) &&
+                    (data_len > 4)) ||
+                   ((p_data[0] == 0x40) && (p_data[1] == 0x03) &&
+                    (data_len > 7))) {
+          uint8_t rsp_status = p_data[3];
+          mObserverRsp = false;
+          if (hal_fd_getFwCap()->ObserveMode == 2) {
+            if (p_data[4] != mObserverMode) {
+              STLOG_HAL_E("mObserverMode got out of sync");
+              mObserverMode = p_data[4];
+            }
+            p_data[5] = p_data[4];
+          } else {
             if (p_data[7] != mObserverMode) {
-                STLOG_HAL_E("mObserverMode got out of sync");
-                mObserverMode = p_data[7];
+              STLOG_HAL_E("mObserverMode got out of sync");
+              mObserverMode = p_data[7];
             }
-            p_data[0] = 0x4f;
-            p_data[1] = 0x0c;
-            p_data[2] = 0x03;
-            p_data[3] = 0x04;
-            p_data[4] = rsp_status;
-            p_data[5] =  p_data[7];
-            data_len = 0x6;
+            p_data[5] = p_data[7];
           }
+          p_data[0] = 0x4f;
+          p_data[1] = 0x0c;
+          p_data[2] = 0x03;
+          p_data[3] = 0x04;
+          p_data[4] = rsp_status;
+          data_len = 0x6;
+        }
       }
       if (!((p_data[0] == 0x60) && (p_data[3] == 0xa0))) {
         if (mHciCreditLent && (p_data[0] == 0x60) && (p_data[1] == 0x06)) {
@@ -617,9 +628,10 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             mTimerStarted = false;
           }
         } else if (p_data[0] == 0x60 && p_data[1] == 0x00) {
+          STLOG_HAL_E("%s - Reset trigger from 0x%x to 0x0", __func__, p_data[3]);
           p_data[3] = 0x0;  // Only reset trigger that should be received in
                             // HAL_WRAPPER_STATE_READY is unreocoverable error.
-
+          mHalWrapperState = HAL_WRAPPER_STATE_RECOVERY;
         } else if (data_len >= 4 && p_data[0] == 0x60 && p_data[1] == 0x07) {
           if (p_data[3] == 0xE1) {
             // Core Generic Error - Buffer Overflow Ntf - Restart all
@@ -631,6 +643,7 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             p_data[4] = 0x00;
             p_data[5] = 0x00;
             data_len = 0x6;
+            mHalWrapperState = HAL_WRAPPER_STATE_RECOVERY;
           } else if (p_data[3] == 0xE6) {
             unsigned long hal_ctrl_clk = 0;
             GetNumValue(NAME_STNFC_CONTROL_CLK, &hal_ctrl_clk,
@@ -645,6 +658,7 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
               p_data[4] = 0x00;
               p_data[5] = 0x00;
               data_len = 0x6;
+              mHalWrapperState = HAL_WRAPPER_STATE_RECOVERY;
             }
           } else if (p_data[3] == 0xA1) {
             if (mFieldInfoTimerStarted) {
@@ -752,7 +766,7 @@ static void halWrapperCallback(uint8_t event, __attribute__((unused))uint8_t eve
 
     case HAL_WRAPPER_STATE_OPEN:
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
-        STLOG_HAL_D("NFC-NCI HAL: %s  Timeout accessing the CLF.", __func__);
+        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout accessing the CLF.", __func__);
         HalSendDownstreamStopTimer(mHalHandle);
         I2cRecovery();
         abort(); // TODO: fix it when we have a better recovery method.
diff --git a/st21nfc/include/android_logmsg.h b/st21nfc/include/android_logmsg.h
index 666c2b9..6769c05 100644
--- a/st21nfc/include/android_logmsg.h
+++ b/st21nfc/include/android_logmsg.h
@@ -72,7 +72,7 @@ extern int GetStrValue(const char* name, char* pValue, unsigned long l);
   {                                                         \
     if ((hal_trace_level & STNFC_TRACE_LEVEL_MASK) >=       \
         STNFC_TRACE_LEVEL_VERBOSE)                          \
-      LOG_PRI(ANDROID_LOG_DEBUG, HAL_LOG_TAG, __VA_ARGS__); \
+      LOG_PRI(ANDROID_LOG_VERBOSE, HAL_LOG_TAG, __VA_ARGS__); \
   }
 #define STLOG_HAL_D(...)                                                       \
   {                                                                            \
diff --git a/st21nfc/hal/hal_fd.h b/st21nfc/include/hal_fd.h
similarity index 95%
rename from st21nfc/hal/hal_fd.h
rename to st21nfc/include/hal_fd.h
index 9016d75..3b2af48 100644
--- a/st21nfc/hal/hal_fd.h
+++ b/st21nfc/include/hal_fd.h
@@ -42,6 +42,15 @@ typedef struct FWInfo {
   uint8_t chipProdType;
 } FWInfo;
 
+
+/*
+ *Structure containing capabilities
+ */
+typedef struct FWCap {
+  uint8_t ObserveMode;
+
+} FWCap;
+
 typedef enum {
   //  HAL_FD_STATE_GET_ATR,
   HAL_FD_STATE_AUTHENTICATE,
@@ -93,4 +102,5 @@ void ApplyUwbParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
 void resetHandlerState();
 bool ft_CheckUWBConf() ;
 FWInfo* hal_fd_getFwInfo();
+FWCap* hal_fd_getFwCap();
 #endif /* HAL_FD_H_ */
```

