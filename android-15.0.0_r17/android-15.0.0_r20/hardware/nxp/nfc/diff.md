```diff
diff --git a/Android.bp b/Android.bp
index d68c500..da9eb5d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -33,5 +33,7 @@ license {
 }
 
 subdirs = [
-    "snxxx","intf", "power-tracker", "pn8x",
+    "snxxx",
+    "intf",
+    "power-tracker",
 ]
diff --git a/snxxx/1.1/Nfc.cpp b/snxxx/1.1/Nfc.cpp
index dd591fc..35c89a8 100644
--- a/snxxx/1.1/Nfc.cpp
+++ b/snxxx/1.1/Nfc.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2018, 2023 NXP
+ *  Copyright 2018, 2023-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -54,10 +54,6 @@ Return<V1_0::NfcStatus> Nfc::open_1_1(
 // Methods from ::android::hardware::nfc::V1_0::INfc follow.
 Return<V1_0::NfcStatus> Nfc::open(
     const sp<V1_0::INfcClientCallback>& clientCallback) {
-  if (mIsServiceStarted) {
-    ALOGD_IF(nfc_debug_enabled, "Nfc::open service is already started");
-    return V1_0::NfcStatus::OK;
-  }
   ALOGD_IF(nfc_debug_enabled, "Nfc::open Enter");
   if (clientCallback == nullptr) {
     ALOGD_IF(nfc_debug_enabled, "Nfc::open null callback");
@@ -68,7 +64,6 @@ Return<V1_0::NfcStatus> Nfc::open(
   }
 
   NFCSTATUS status = phNxpNciHal_open(eventCallback, dataCallback);
-  mIsServiceStarted = true;
   ALOGD_IF(nfc_debug_enabled, "Nfc::open Exit");
   return CHK_STATUS(status);
 }
@@ -91,7 +86,6 @@ Return<V1_0::NfcStatus> Nfc::close() {
     return V1_0::NfcStatus::FAILED;
   }
   NFCSTATUS status = phNxpNciHal_close(false);
-  mIsServiceStarted = false;
 
   if (mCallbackV1_1 != nullptr) {
     mCallbackV1_1->unlinkToDeath(this);
@@ -125,7 +119,6 @@ Return<V1_0::NfcStatus> Nfc::closeForPowerOffCase() {
     return V1_0::NfcStatus::FAILED;
   }
   NFCSTATUS status = phNxpNciHal_configDiscShutdown();
-  mIsServiceStarted = false;
 
   if (mCallbackV1_1 != nullptr) {
     mCallbackV1_1->unlinkToDeath(this);
diff --git a/snxxx/1.1/Nfc.h b/snxxx/1.1/Nfc.h
index fb4248c..ef467de 100644
--- a/snxxx/1.1/Nfc.h
+++ b/snxxx/1.1/Nfc.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2018,2023 NXP
+ *  Copyright 2018 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -99,7 +99,6 @@ struct Nfc : public V1_1::INfc, public hidl_death_recipient {
   }
 
  private:
-  bool mIsServiceStarted;
   static sp<V1_1::INfcClientCallback> mCallbackV1_1;
   static sp<V1_0::INfcClientCallback> mCallbackV1_0;
 };
diff --git a/snxxx/1.2/Nfc.cpp b/snxxx/1.2/Nfc.cpp
index bf1dc2a..f929621 100755
--- a/snxxx/1.2/Nfc.cpp
+++ b/snxxx/1.2/Nfc.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2019-2023 NXP
+ *  Copyright 2019-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -56,10 +56,6 @@ Return<V1_0::NfcStatus> Nfc::open_1_1(
 // Methods from ::android::hardware::nfc::V1_0::INfc follow.
 Return<V1_0::NfcStatus> Nfc::open(
     const sp<V1_0::INfcClientCallback>& clientCallback) {
-  if (mIsServiceStarted) {
-    ALOGD_IF(nfc_debug_enabled, "Nfc::open service is already started");
-    return V1_0::NfcStatus::OK;
-  }
   ALOGD_IF(nfc_debug_enabled, "Nfc::open Enter");
   if (clientCallback == nullptr) {
     ALOGD_IF(nfc_debug_enabled, "Nfc::open null callback");
@@ -70,7 +66,6 @@ Return<V1_0::NfcStatus> Nfc::open(
   }
   printNfcMwVersion();
   NFCSTATUS status = phNxpNciHal_open(eventCallback, dataCallback);
-  mIsServiceStarted = true;
   ALOGD_IF(nfc_debug_enabled, "Nfc::open Exit");
   return CHK_STATUS(status);
 }
@@ -93,7 +88,6 @@ Return<V1_0::NfcStatus> Nfc::close() {
     return V1_0::NfcStatus::FAILED;
   }
   NFCSTATUS status = phNxpNciHal_close(false);
-  mIsServiceStarted = false;
 
   if (mCallbackV1_1 != nullptr) {
     mCallbackV1_1->unlinkToDeath(this);
@@ -127,7 +121,7 @@ Return<V1_0::NfcStatus> Nfc::closeForPowerOffCase() {
     return V1_0::NfcStatus::FAILED;
   }
   NFCSTATUS status = phNxpNciHal_configDiscShutdown();
-  mIsServiceStarted = false;
+
   if (mCallbackV1_1 != nullptr) {
     mCallbackV1_1->unlinkToDeath(this);
     mCallbackV1_1 = nullptr;
@@ -160,7 +154,6 @@ void Nfc::serviceDied(uint64_t /*cookie*/, const wp<IBase>& /*who*/) {
     return;
   }
   phNxpNciHal_close(true);
-  mIsServiceStarted = false;
 
   if (mCallbackV1_1 != nullptr) {
     mCallbackV1_1->unlinkToDeath(this);
diff --git a/snxxx/1.2/Nfc.h b/snxxx/1.2/Nfc.h
index 1bb29b8..1af7a14 100755
--- a/snxxx/1.2/Nfc.h
+++ b/snxxx/1.2/Nfc.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2019-2023 NXP
+ *  Copyright 2019-2022 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -101,7 +101,6 @@ struct Nfc : public V1_2::INfc, public hidl_death_recipient {
   virtual void serviceDied(uint64_t /*cookie*/, const wp<IBase>& /*who*/);
 
  private:
-  bool mIsServiceStarted;
   static sp<V1_1::INfcClientCallback> mCallbackV1_1;
   static sp<V1_0::INfcClientCallback> mCallbackV1_0;
 };
diff --git a/snxxx/Android.bp b/snxxx/Android.bp
index 01105a6..5fd9544 100644
--- a/snxxx/Android.bp
+++ b/snxxx/Android.bp
@@ -88,6 +88,7 @@ cc_library_shared {
         "halimpl/mifare/NxpMfcReader.cc",
         "halimpl/recovery/phNxpNciHal_Recovery.cc",
         "halimpl/hal/phNxpNciHal_PowerTrackerIface.cc",
+        "halimpl/hal/phNxpNciHal_WiredSeIface.cc",
     ],
 
     local_include_dirs: [
@@ -144,6 +145,7 @@ cc_library_headers {
         "halimpl/mifare",
         "extns/impl/nxpnfc/2.0",
         "halimpl/recovery",
+        "halimpl/observe_mode",
     ],
 }
 
diff --git a/snxxx/aidl/1.0/main.cpp b/snxxx/aidl/1.0/main.cpp
index d219cd9..ce2e9e8 100644
--- a/snxxx/aidl/1.0/main.cpp
+++ b/snxxx/aidl/1.0/main.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2022 NXP
+ *  Copyright 2022, 2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -26,12 +26,15 @@
 #include "NxpNfc.h"
 #include "phNxpNciHal_Adaptation.h"
 #include "phNxpNciHal_Recovery.h"
+#include "phNxpNciHal_WiredSeIface.h"
 
 using ::aidl::android::hardware::nfc::Nfc;
 using ::aidl::vendor::nxp::nxpnfc_aidl::INxpNfc;
 using ::aidl::vendor::nxp::nxpnfc_aidl::NxpNfc;
 using namespace std;
 
+extern WiredSeHandle gWiredSeHandle;
+
 void startNxpNfcAidlService() {
   ALOGI("NXP NFC Extn Service is starting.");
   std::shared_ptr<NxpNfc> nxp_nfc_service = ndk::SharedRefBase::make<NxpNfc>();
@@ -62,6 +65,10 @@ int main() {
   phNxpNciHal_RecoverFWTearDown();
 #endif
   thread t1(startNxpNfcAidlService);
+  // Starts Wired SE HAL instance if platform supports
+  if (phNxpNciHal_WiredSeStart(&gWiredSeHandle) != NFCSTATUS_SUCCESS) {
+    ALOGE("Wired Se HAL Disabled");
+  }
   ABinderProcess_joinThreadPool();
   return 0;
 }
diff --git a/snxxx/halimpl/common/Nxp_Features.h b/snxxx/halimpl/common/Nxp_Features.h
index 1c5f172..80a767c 100644
--- a/snxxx/halimpl/common/Nxp_Features.h
+++ b/snxxx/halimpl/common/Nxp_Features.h
@@ -19,6 +19,8 @@
 #include <stdint.h>
 
 #include <string>
+
+#include "phNxpConfig.h"
 #ifndef NXP_FEATURES_H
 #define NXP_FEATURES_H
 
@@ -128,6 +130,19 @@ typedef struct {
   uint8_t _NFCC_4K_FW_SUPPORT : 1;
 } tNfc_nfccFeatureList;
 
+typedef struct {
+  uint8_t id;
+  uint8_t len;
+  uint8_t val;
+} tNfc_capability;
+
+typedef struct {
+  tNfc_capability OBSERVE_MODE;
+  tNfc_capability POLLING_FRAME_NOTIFICATION;
+  tNfc_capability POWER_SAVING;
+  tNfc_capability AUTOTRANSACT_PLF;
+} tNfc_nfccCapabililty;
+
 typedef struct {
   uint8_t nfcNxpEse : 1;
   tNFC_chipType chipType;
@@ -137,6 +152,7 @@ typedef struct {
   uint16_t _PHDNLDNFC_USERDATA_EEPROM_LEN;
   uint8_t _FW_MOBILE_MAJOR_NUMBER;
   tNfc_nfccFeatureList nfccFL;
+  tNfc_nfccCapabililty nfccCap;
 } tNfc_featureList;
 
 extern tNfc_featureList nfcFL;
@@ -234,6 +250,7 @@ extern tNfc_featureList nfcFL;
     nfcFL._FW_MOBILE_MAJOR_NUMBER = FW_MOBILE_MAJOR_NUMBER_PN48AD;     \
     nfcFL.nfccFL._NFCC_DWNLD_MODE = NFCC_DWNLD_WITH_VEN_RESET;         \
     nfcFL.nfccFL._NFCC_4K_FW_SUPPORT = false;                          \
+    UPDATE_NFCC_CAPABILITY()                                           \
     switch (chipType) {                                                \
       case pn557:                                                      \
         nfcFL.nfccFL._NFCC_I2C_READ_WRITE_IMPROVEMENT = true;          \
@@ -296,4 +313,39 @@ extern tNfc_featureList nfcFL;
     nfcFL._FW_LIB_PATH.append(str1);             \
     nfcFL._FW_LIB_PATH.append(FW_LIB_EXTENSION); \
   }
+
+#define CAP_OBSERVE_MODE_ID 0x00
+#define CAP_POLL_FRAME_NTF_ID 0x01
+#define CAP_POWER_SAVING_MODE_ID 0x02
+#define CAP_AUTOTRANSACT_PLF_ID 0x03
+
+#define UPDATE_NFCC_CAPABILITY()                                             \
+  {                                                                          \
+    nfcFL.nfccCap.OBSERVE_MODE.id = CAP_OBSERVE_MODE_ID;                     \
+    nfcFL.nfccCap.OBSERVE_MODE.len = 0x01;                                   \
+    nfcFL.nfccCap.OBSERVE_MODE.val = 0x00;                                   \
+    nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.id = CAP_POLL_FRAME_NTF_ID;     \
+    nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.len = 0x01;                     \
+    nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.val = 0x00;                     \
+    nfcFL.nfccCap.POWER_SAVING.id = CAP_POWER_SAVING_MODE_ID;                \
+    nfcFL.nfccCap.POWER_SAVING.len = 0x01;                                   \
+    nfcFL.nfccCap.POWER_SAVING.val = 0x00;                                   \
+    nfcFL.nfccCap.AUTOTRANSACT_PLF.id = CAP_AUTOTRANSACT_PLF_ID;             \
+    nfcFL.nfccCap.AUTOTRANSACT_PLF.len = 0x01;                               \
+    nfcFL.nfccCap.AUTOTRANSACT_PLF.val = 0x00;                               \
+    uint8_t extended_field_mode = 0x00;                                      \
+    if (IS_CHIP_TYPE_GE(sn100u) &&                                           \
+        GetNxpNumValue(NAME_NXP_EXTENDED_FIELD_DETECT_MODE,                  \
+                       &extended_field_mode, sizeof(extended_field_mode))) { \
+      if (extended_field_mode == 0x03) {                                     \
+        nfcFL.nfccCap.OBSERVE_MODE.val = 0x01;                               \
+      }                                                                      \
+    }                                                                        \
+    unsigned long num = 0;                                                   \
+    if ((GetNxpNumValue(NAME_NXP_DEFAULT_ULPDET_MODE, &num, sizeof(num)))) { \
+      if ((uint8_t)num > 0) {                                                \
+        nfcFL.nfccCap.POWER_SAVING.val = 0x01;                               \
+      }                                                                      \
+    }                                                                        \
+  }
 #endif
diff --git a/snxxx/halimpl/common/phNfcNciConstants.h b/snxxx/halimpl/common/phNfcNciConstants.h
index e50760a..f9107aa 100644
--- a/snxxx/halimpl/common/phNfcNciConstants.h
+++ b/snxxx/halimpl/common/phNfcNciConstants.h
@@ -30,8 +30,10 @@
 #define RF_DISC_CMD_CONFIG_START_INDEX 4
 // RF tech mode and Disc Frequency values
 #define RF_DISC_CMD_EACH_CONFIG_LENGTH 2
+#define NFCEE_MODE_SET_CMD_MODE_INDEX 4
 
 /* Android Parameters */
+#define NCI_ANDROID_GET_CAPABILITY 0x00
 #define NCI_ANDROID_POWER_SAVING 0x01
 #define NCI_ANDROID_OBSERVER_MODE 0x02
 #define NCI_ANDROID_GET_OBSERVER_MODE_STATUS 0x04
@@ -55,7 +57,7 @@
 #define NFC_B_PASSIVE_LISTEN_MODE 0x81
 #define NFC_F_PASSIVE_LISTEN_MODE 0x82
 #define NFC_ACTIVE_LISTEN_MODE 0x83
-#define OBSERVE_MODE 0xFF
+#define OBSERVE_MODE_RF_TECH_AND_MODE 0xFF
 #define OBSERVE_MODE_DISCOVERY_CYCLE 0x01
 
 // Observe mode constants
@@ -103,3 +105,6 @@
 #define LX_LENGTH_MASK 0x0F
 #define LX_TAG_MASK 0xF0
 #define SHORT_FLAG 0x00
+#define TYPE_ALL_EVENTS 0x00
+#define TYPE_ONLY_MOD_EVENTS 0x01
+#define TYPE_ONLY_CMA_EVENTS 0x02
diff --git a/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf
index 98d04c6..a182fcf 100644
--- a/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf
@@ -109,6 +109,11 @@ OFFHOST_AID_ROUTE_PWR_STATE=0x3B
 #Set bit to 0,  to disable block list
 NFA_AID_BLOCK_ROUTE=0x00
 
+###############################################################################
+# Tech route options
+# 0x00, Route mute techs to DH, enable block bit and set power state to 0x00
+# 0x01, Remove mute techs from rf discover cmd
+MUTE_TECH_ROUTE_OPTION=0x01
 ###############################################################################
 # Set presence check retry count value. Value Range: 0 to 5
 # This value indicates the number of time presence check is repeated in case of
@@ -129,3 +134,7 @@ HOST_LISTEN_TECH_MASK=0x07
 # 1 to Enable this behaviour
 ISO15693_SKIP_GET_SYS_INFO_CMD=0
 ##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
+##############################################################################
diff --git a/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf
index 4f220a4..4fffa60 100644
--- a/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf
@@ -88,6 +88,11 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
+# Tech route options
+# 0x00, Route mute techs to DH, enable block bit and set power state to 0x00
+# 0x01, Remove mute techs from rf discover cmd
+MUTE_TECH_ROUTE_OPTION=0x01
+##############################################################################
 # Forcing HOST to listen for a selected protocol
 # 0x00 : Disable Host Listen
 # 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
@@ -102,3 +107,7 @@ HOST_LISTEN_TECH_MASK=0x07
 # 1 to Enable this behaviour
 ISO15693_SKIP_GET_SYS_INFO_CMD=0
 ##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf
index d8eb971..b288279 100644
--- a/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf
@@ -95,6 +95,11 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
+# Tech route options
+# 0x00, Route mute techs to DH, enable block bit and set power state to 0x00
+# 0x01, Remove mute techs from rf discover cmd
+MUTE_TECH_ROUTE_OPTION=0x01
+##############################################################################
 # Forcing HOST to listen for a selected protocol
 # 0x00 : Disable Host Listen
 # 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
@@ -109,3 +114,7 @@ HOST_LISTEN_TECH_MASK=0x07
 # 1 to Enable this behaviour
 ISO15693_SKIP_GET_SYS_INFO_CMD=0
 ##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf
index d8eb971..b288279 100644
--- a/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf
@@ -95,6 +95,11 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
+# Tech route options
+# 0x00, Route mute techs to DH, enable block bit and set power state to 0x00
+# 0x01, Remove mute techs from rf discover cmd
+MUTE_TECH_ROUTE_OPTION=0x01
+##############################################################################
 # Forcing HOST to listen for a selected protocol
 # 0x00 : Disable Host Listen
 # 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
@@ -109,3 +114,7 @@ HOST_LISTEN_TECH_MASK=0x07
 # 1 to Enable this behaviour
 ISO15693_SKIP_GET_SYS_INFO_CMD=0
 ##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf
index d2c3dd6..0ecdaf3 100644
--- a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf
@@ -96,6 +96,11 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
+# Tech route options
+# 0x00, Route mute techs to DH, enable block bit and set power state to 0x00
+# 0x01, Remove mute techs from rf discover cmd
+MUTE_TECH_ROUTE_OPTION=0x01
+##############################################################################
 # Forcing HOST to listen for a selected protocol
 # 0x00 : Disable Host Listen
 # 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
@@ -110,3 +115,7 @@ HOST_LISTEN_TECH_MASK=0x07
 # 1 to Enable this behaviour
 ISO15693_SKIP_GET_SYS_INFO_CMD=0
 ##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf
index 60df7c0..78644a2 100644
--- a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf
+++ b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf
@@ -12,6 +12,7 @@ NXPLOG_EXTNS_LOGLEVEL=0x04
 NXPLOG_NCIHAL_LOGLEVEL=0x04
 NXPLOG_NCIX_LOGLEVEL=0x04
 NXPLOG_NCIR_LOGLEVEL=0x04
+NXPLOG_AVCNCI_LOGLEVEL=0x04
 NXPLOG_FWDNLD_LOGLEVEL=0x04
 NXPLOG_TML_LOGLEVEL=0x04
 NFC_DEBUG_ENABLED=1
@@ -490,3 +491,9 @@ NXP_RESTART_RF_FOR_NFCEE_RECOVERY=1
 # It will lead to mismatch of event's for profiles
 NXP_EXTENDED_FIELD_DETECT_MODE=0x03
 ###############################################################################
+# Observe mode required notifications based on below type
+# All events CMA + Modulation Events       0x00
+# Only Modulation events                   0x01
+# Only CMA Events                          0x02
+NXP_OBSERVE_MODE_REQ_NOTIFICATION_TYPE=0x02
+###############################################################################
diff --git a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf
index 89a0879..8d37fa9 100644
--- a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf
@@ -102,6 +102,11 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
+# Tech route options
+# 0x00, Route mute techs to DH, enable block bit and set power state to 0x00
+# 0x01, Remove mute techs from rf discover cmd
+MUTE_TECH_ROUTE_OPTION=0x01
+##############################################################################
 # Forcing HOST to listen for a selected protocol
 # 0x00 : Disable Host Listen
 # 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
@@ -116,3 +121,7 @@ HOST_LISTEN_TECH_MASK=0x07
 # 1 to Enable this behaviour
 ISO15693_SKIP_GET_SYS_INFO_CMD=0
 ##############################################################################
+# Deactivate notification wait time out in seconds used in listen active state
+# Default is 8sec if not set or set as 0 (see nfc_target.h)
+NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT=3
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf
index db6ecde..29938be 100644
--- a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf
+++ b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf
@@ -12,6 +12,7 @@ NXPLOG_EXTNS_LOGLEVEL=0x04
 NXPLOG_NCIHAL_LOGLEVEL=0x04
 NXPLOG_NCIX_LOGLEVEL=0x04
 NXPLOG_NCIR_LOGLEVEL=0x04
+NXPLOG_AVCNCI_LOGLEVEL=0x04
 NXPLOG_FWDNLD_LOGLEVEL=0x04
 NXPLOG_TML_LOGLEVEL=0x04
 NFC_DEBUG_ENABLED=1
@@ -505,3 +506,9 @@ NXP_EXTENDED_FIELD_DETECT_MODE=0x03
 # 0x01 = Enabled
 NXP_4K_FWDNLD_SUPPORT=1
 ###############################################################################
+# Observe mode required notifications based on below type
+# All events CMA + Modulation Events       0x00
+# Only Modulation events                   0x01
+# Only CMA Events                          0x02
+NXP_OBSERVE_MODE_REQ_NOTIFICATION_TYPE=0x02
+#################################################################################
\ No newline at end of file
diff --git a/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc b/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc
index 6d51f89..e78c074 100644
--- a/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc
+++ b/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc
@@ -37,7 +37,7 @@
 #define PHLIBNFC_IOCTL_DNLD_SN300U_GETVERLEN MAX_GET_VER_RESP_LEN
 #define IS_EQUAL(ExpectedHwVer, HwVerFromChip) \
   (ExpectedHwVer == (HwVerFromChip & PHDNLDNFC_UPPER_NIBBLE_MASK))
-#define CRC_SN300 (0xCFFC001F)
+#define CRC_SN300 (0xCFF4001F)
 /* External global variable to get FW version */
 extern uint16_t wFwVer;
 extern uint16_t wMwVer;
@@ -1777,7 +1777,7 @@ static NFCSTATUS phLibNfc_VerifySNxxxU_CrcStatus(uint8_t* bCrcStatus) {
     acceptable_crc_values = CRC_SN300;
   } else if (IS_CHIP_TYPE_EQ(sn220u)) {
     /* Accepted CRC value according to SN220 integrity bit mapping */
-    acceptable_crc_values = 0xFBFFC00F;
+    acceptable_crc_values = 0xFBF7C00F;
   }
   NFCSTATUS wStatus = NFCSTATUS_SUCCESS;
   phDnldChkIntegrityRsp_Buff_t chkIntgRspBuf;
diff --git a/snxxx/halimpl/hal/WiredSeService.h b/snxxx/halimpl/hal/WiredSeService.h
new file mode 100755
index 0000000..8efce01
--- /dev/null
+++ b/snxxx/halimpl/hal/WiredSeService.h
@@ -0,0 +1,70 @@
+/******************************************************************************
+ *
+ *  Copyright 2024 NXP
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at
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
+
+#include <stdint.h>
+
+// Opaque WiredSe Service object.
+struct WiredSeService;
+
+typedef enum WiredSeEvtType {
+  NFC_STATE_CHANGE,
+  NFC_PKT_RECEIVED,
+  SENDING_HCI_PKT,
+  DISABLING_NFCEE,
+  NFC_EVT_UNKNOWN
+} WiredSeEvtType;
+
+typedef enum { NFC_ON, NFC_OFF, NFC_STATE_UNKNOWN } NfcState;
+
+typedef struct NfcPkt {
+  uint8_t* data;
+  uint16_t len;
+  NfcPkt() {
+    data = NULL;
+    len = 0;
+  }
+  // Constructor
+  NfcPkt(uint8_t* inData, uint16_t inLen) {
+    data = inData;
+    len = inLen;
+  }
+} NfcPkt;
+
+typedef union WiredSeEvtData {
+  NfcState nfcState;
+  NfcPkt nfcPkt;
+  // Default
+  WiredSeEvtData() {}
+  // For typecasting from NfcState to WiredSeEvtData
+  WiredSeEvtData(NfcState inNfcState) { nfcState = inNfcState; }
+  // For typecasting from NfcPkt to WiredSeEvtData
+  WiredSeEvtData(NfcPkt inNfcPkt) { nfcPkt = inNfcPkt; }
+
+} WiredSeEvtData;
+
+typedef struct WiredSeEvt {
+  WiredSeEvtType event;
+  WiredSeEvtData eventData;
+
+  WiredSeEvt() { event = NFC_EVT_UNKNOWN; }
+} WiredSeEvt;
+
+extern "C" int32_t WiredSeService_Start(WiredSeService** wiredSeService);
+extern "C" int32_t WiredSeService_DispatchEvent(WiredSeService* wiredSeService,
+                                                WiredSeEvt evt);
diff --git a/snxxx/halimpl/hal/phNxpNciHal.cc b/snxxx/halimpl/hal/phNxpNciHal.cc
index 10dc05b..f2ccce7 100644
--- a/snxxx/halimpl/hal/phNxpNciHal.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal.cc
@@ -43,6 +43,7 @@
 #include "phNxpNciHal_PowerTrackerIface.h"
 #include "phNxpNciHal_ULPDet.h"
 #include "phNxpNciHal_VendorProp.h"
+#include "phNxpNciHal_WiredSeIface.h"
 #include "phNxpNciHal_extOperations.h"
 
 using android::base::StringPrintf;
@@ -56,6 +57,13 @@ using android::base::WriteStringToFile;
 #define EOS_FW_SESSION_STATE_LOCKED 0x02
 #define NS_PER_S 1000000000
 #define MAX_WAIT_MS_FOR_RESET_NTF 1600
+#define INVALID_PARAM 0x09
+#define IS_HCI_PACKET(nciPkt) \
+  (nciPkt[NCI_GID_INDEX] == 0x01) && (nciPkt[NCI_OID_INDEX] == 0x00)
+#define IS_NFCEE_DISABLE(nciPkt)                                     \
+  (nciPkt[NCI_GID_INDEX] == 0x22 && nciPkt[NCI_OID_INDEX] == 0x01 && \
+   nciPkt[NCI_MSG_LEN_INDEX] == 0x02 &&                              \
+   nciPkt[NFCEE_MODE_SET_CMD_MODE_INDEX] == 0x00)
 
 bool bEnableMfcExtns = false;
 bool bEnableMfcReader = false;
@@ -119,6 +127,7 @@ uint8_t fw_dwnld_flag = false;
 #endif
 bool nfc_debug_enabled = true;
 PowerTrackerHandle gPowerTrackerHandle;
+WiredSeHandle gWiredSeHandle;
 sem_t sem_reset_ntf_received;
 /*  Used to send Callback Transceive data during Mifare Write.
  *  If this flag is enabled, no need to send response to Upper layer */
@@ -703,6 +712,7 @@ int phNxpNciHal_MinOpen() {
   NFCSTATUS status = NFCSTATUS_SUCCESS;
   int dnld_retry_cnt = 0;
   sIsHalOpenErrorRecovery = false;
+  setObserveModeFlag(false);
   NXPLOG_NCIHAL_D("phNxpNci_MinOpen(): enter");
 
   if (nxpncihal_ctrl.halStatus == HAL_STATUS_MIN_OPEN) {
@@ -1137,6 +1147,8 @@ int phNxpNciHal_write(uint16_t data_len, const uint8_t* p_data) {
   if (bEnableMfcExtns && p_data[NCI_GID_INDEX] == 0x00) {
     return NxpMfcReaderInstance.Write(data_len, p_data);
   } else if (phNxpNciHal_isVendorSpecificCommand(data_len, p_data)) {
+    phNxpNciHal_print_packet("SEND", p_data, data_len,
+                             RfFwRegionDnld_handle == NULL);
     return phNxpNciHal_handleVendorSpecificCommand(data_len, p_data);
   } else if (isObserveModeEnabled() &&
              p_data[NCI_GID_INDEX] == NCI_RF_DISC_COMMD_GID &&
@@ -1144,6 +1156,15 @@ int phNxpNciHal_write(uint16_t data_len, const uint8_t* p_data) {
     NciDiscoveryCommandBuilder builder;
     vector<uint8_t> v_data = builder.reConfigRFDiscCmd(data_len, p_data);
     return phNxpNciHal_write_internal(v_data.size(), v_data.data());
+  } else if (IS_HCI_PACKET(p_data)) {
+    // Inform WiredSe service that HCI Pkt is sending from libnfc layer
+    phNxpNciHal_WiredSeDispatchEvent(&gWiredSeHandle, SENDING_HCI_PKT);
+  } else if (IS_NFCEE_DISABLE(p_data)) {
+    // NFCEE_MODE_SET(DISABLE) is called. Dispatch event to WiredSe so
+    // that it can close if session is ongoing on same NFCEE
+    phNxpNciHal_WiredSeDispatchEvent(
+        &gWiredSeHandle, DISABLING_NFCEE,
+        (WiredSeEvtData)NfcPkt((uint8_t*)p_data, data_len));
   }
   long value = 0;
   /* NXP Removal Detection timeout Config */
@@ -1444,6 +1465,12 @@ static void phNxpNciHal_read_complete(void* pContext,
           nxpncihal_ctrl.p_rx_data, nxpncihal_ctrl.rx_data_len);
       NXPLOG_NCIHAL_D("Mfc Response Status = 0x%x", mfcRspStatus);
       SEM_POST(&(nxpncihal_ctrl.ext_cb_data));
+    } else if (phNxpNciHal_WiredSeDispatchEvent(
+                   &gWiredSeHandle, NFC_PKT_RECEIVED,
+                   (WiredSeEvtData)NfcPkt(nxpncihal_ctrl.p_rx_data,
+                                          nxpncihal_ctrl.rx_data_len)) ==
+               NFCSTATUS_SUCCESS) {
+      NXPLOG_NCIHAL_D("%s => %d, Processed WiredSe Packet", __func__, __LINE__);
     }
     /* Read successful send the event to higher layer */
     else if (status == NFCSTATUS_SUCCESS) {
@@ -1480,6 +1507,24 @@ static void phNxpNciHal_read_complete(void* pContext,
   return;
 }
 
+/******************************************************************************
+ * Function         phNxpNciHal_notifyPollingFrame
+ *
+ * Description      Send polling info notification to send to upper layer
+ *
+ * Parameters       p_data - Polling loop info notification
+ *
+ * Returns          void
+ *
+ ******************************************************************************/
+void phNxpNciHal_notifyPollingFrame(uint16_t data_len, uint8_t* p_data) {
+  phNxpNciHal_print_packet("RECV", p_data, data_len,
+                           RfFwRegionDnld_handle == NULL);
+  if (nxpncihal_ctrl.p_nfc_stack_data_cback != NULL) {
+    (*nxpncihal_ctrl.p_nfc_stack_data_cback)(data_len, p_data);
+  }
+}
+
 /******************************************************************************
  * Function         phNxpNciHal_client_data_callback
  *
@@ -1499,9 +1544,16 @@ void phNxpNciHal_client_data_callback() {
   if (isObserveModeEnabled() &&
       nxpncihal_ctrl.p_rx_data[NCI_GID_INDEX] == NCI_PROP_NTF_GID &&
       nxpncihal_ctrl.p_rx_data[NCI_OID_INDEX] == NCI_PROP_LX_NTF_OID) {
+    unsigned long notificationType = 0;
     ReaderPollConfigParser readerPollConfigParser;
+    int isFound = GetNxpNumValue(NAME_NXP_OBSERVE_MODE_REQ_NOTIFICATION_TYPE,
+                                 &notificationType, sizeof(notificationType));
+    if (isFound == 0) {
+      notificationType = 0;
+    }
+    readerPollConfigParser.setNotificationType(notificationType);
     readerPollConfigParser.setReaderPollCallBack(
-        nxpncihal_ctrl.p_nfc_stack_data_cback);
+        phNxpNciHal_notifyPollingFrame);
     readerPollConfigParser.parseAndSendReaderPollInfo(
         nxpncihal_ctrl.p_rx_data, nxpncihal_ctrl.rx_data_len);
   } else {
@@ -1723,6 +1775,12 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
   request_EEPROM(&mEEPROM_info);
 
   if (IS_CHIP_TYPE_GE(sn100u)) {
+    unsigned long num = 0;
+    if ((GetNxpNumValue(NAME_NXP_CE_SUPPORT_IN_NFC_OFF_PHONE_OFF, &num,
+                        sizeof(num))) &&
+        (IS_CHIP_TYPE_EQ(sn300u))) {
+      if (num == ENABLE_T4T_CE) enable_ce_in_phone_off = num;
+    }
     mEEPROM_info.buffer = &enable_ce_in_phone_off;
     mEEPROM_info.bufflen = sizeof(enable_ce_in_phone_off);
     mEEPROM_info.request_type = EEPROM_CE_PHONE_OFF_CFG;
@@ -1953,13 +2011,17 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
         if (status == NFCSTATUS_SUCCESS) {
           status = phNxpNciHal_CheckRFCmdRespStatus();
           /*STATUS INVALID PARAM 0x09*/
-          if (status == 0x09) {
+          if (status == INVALID_PARAM) {
             phNxpNciHalRFConfigCmdRecSequence();
             retry_core_init_cnt++;
             goto retry_core_init;
           }
         } else if (status != NFCSTATUS_SUCCESS) {
           NXPLOG_NCIHAL_E("RF Settings BLK %ld failed", loopcnt);
+          /*STATUS INVALID PARAM 0x09*/
+          if (status == INVALID_PARAM) {
+            phNxpNciHalRFConfigCmdRecSequence();
+          }
           retry_core_init_cnt++;
           goto retry_core_init;
         }
@@ -1989,13 +2051,16 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
     if (status == NFCSTATUS_SUCCESS) {
       status = phNxpNciHal_CheckRFCmdRespStatus();
       /*STATUS INVALID PARAM 0x09*/
-      if (status == 0x09) {
+      if (status == INVALID_PARAM) {
         phNxpNciHalRFConfigCmdRecSequence();
         retry_core_init_cnt++;
         goto retry_core_init;
       }
     } else if (status != NFCSTATUS_SUCCESS) {
       NXPLOG_NCIHAL_E("Setting NXP_CORE_RF_FIELD status failed");
+      if (status == INVALID_PARAM) {
+        phNxpNciHalRFConfigCmdRecSequence();
+      }
       retry_core_init_cnt++;
       goto retry_core_init;
     }
@@ -2173,7 +2238,6 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
  ******************************************************************************/
 NFCSTATUS phNxpNciHal_CheckRFCmdRespStatus() {
   NFCSTATUS status = NFCSTATUS_SUCCESS;
-  static uint16_t INVALID_PARAM = 0x09;
   if ((nxpncihal_ctrl.rx_data_len > 0) && (nxpncihal_ctrl.p_rx_data[2] > 0)) {
     if (nxpncihal_ctrl.p_rx_data[3] == 0x09) {
       status = INVALID_PARAM;
@@ -2261,6 +2325,17 @@ static void phNxpNciHal_core_initialized_complete(NFCSTATUS status) {
  *
  ******************************************************************************/
 int phNxpNciHal_pre_discover(void) {
+  if (nxpncihal_ctrl.halStatus != HAL_STATUS_CLOSE) {
+    // Flush SRAM content to flash
+    CONCURRENCY_LOCK();
+    if (phNxpNciHal_ext_send_sram_config_to_flash() != NFCSTATUS_SUCCESS) {
+      NXPLOG_NCIHAL_E("phNxpNciHal_ext_send_sram_config_to_flash: Failed");
+    }
+    CONCURRENCY_UNLOCK();
+    // Inform WireSe Service that NFC is ON
+    phNxpNciHal_WiredSeDispatchEvent(&gWiredSeHandle, NFC_STATE_CHANGE,
+                                     (WiredSeEvtData)NfcState::NFC_ON);
+  }
   /* Nothing to do here for initial version */
   // This is set to return Failed as no vendor specific pre-discovery action is
   // needed in case of HalPrediscover
@@ -2310,6 +2385,7 @@ int phNxpNciHal_close(bool bShutdown) {
   unsigned long uiccListenMask = 0x00;
   unsigned long eseListenMask = 0x00;
   uint8_t retry = 0;
+  uint8_t num = 0x00;
 
   phNxpNciHal_deinitializeRegRfFwDnld();
   NfcHalAutoThreadMutex a(sHalFnLock);
@@ -2320,6 +2396,8 @@ int phNxpNciHal_close(bool bShutdown) {
   if (gPowerTrackerHandle.stop != NULL) {
     gPowerTrackerHandle.stop();
   }
+  phNxpNciHal_WiredSeDispatchEvent(&gWiredSeHandle, NFC_STATE_CHANGE,
+                                   (WiredSeEvtData)NfcState::NFC_OFF);
   if (IS_CHIP_TYPE_L(sn100u)) {
     if (!(GetNxpNumValue(NAME_NXP_UICC_LISTEN_TECH_MASK, &uiccListenMask,
                          sizeof(uiccListenMask)))) {
@@ -2340,19 +2418,39 @@ int phNxpNciHal_close(bool bShutdown) {
   if (sem_val == 0) {
     sem_post(&(nxpncihal_ctrl.syncSpiNfc));
   }
+
+  /**
+   * @brief In Case of chipset greater than or equal to SN110,
+   * If Chipset is SN300 &
+   *    - NAME_NXP_CE_SUPPORT_IN_NFC_OFF_PHONE_OFF is 0x00,
+   *      then CE support in Phone off NFC off is not supported &
+   *      Autonomous mode is disabled.
+   *    - NAME_NXP_CE_SUPPORT_IN_NFC_OFF_PHONE_OFF is 0x03,
+   *      then CE support for T4T in Phone off NFC off is supported &
+   *      Autonomous mode is disabled.
+   * otherwise, CE support in Phone off NFC off is not supported &
+   * Autonomous mode is disabled.
+   */
   if (!bShutdown && phNxpNciHal_getULPDetFlag() == false) {
-    if (IS_CHIP_TYPE_GE(sn100u)) {
-      status = phNxpNciHal_send_ext_cmd(sizeof(cmd_ce_in_phone_off),
-                                        cmd_ce_in_phone_off);
-      if (status != NFCSTATUS_SUCCESS) {
-        NXPLOG_NCIHAL_E("CMD_CE_IN_PHONE_OFF: Failed");
+    if ((IS_CHIP_TYPE_GE(sn100u) && IS_CHIP_TYPE_L(sn300u)) ||
+        ((IS_CHIP_TYPE_EQ(sn300u)) &&
+         (GetNxpNumValue(NAME_NXP_CE_SUPPORT_IN_NFC_OFF_PHONE_OFF, &num,
+                         sizeof(num))) &&
+         ((num == NXP_PHONE_OFF_NFC_OFF_CE_NOT_SUPPORTED) ||
+          (num == NXP_PHONE_OFF_NFC_OFF_T4T_CE_SUPPORTED)))) {
+      if (num == NXP_PHONE_OFF_NFC_OFF_CE_NOT_SUPPORTED) {
+        status = phNxpNciHal_send_ext_cmd(sizeof(cmd_ce_in_phone_off),
+                                          cmd_ce_in_phone_off);
+        if (status != NFCSTATUS_SUCCESS) {
+          NXPLOG_NCIHAL_E("CMD_CE_IN_PHONE_OFF: Failed");
+        }
       }
       config_ext.autonomous_mode = 0x00;
       status = phNxpNciHal_setAutonomousMode();
       if (status != NFCSTATUS_SUCCESS) {
         NXPLOG_NCIHAL_E("Autonomous mode Disable: Failed");
       }
-    } else {
+    } else if (IS_CHIP_TYPE_EQ(pn557)) {
       status = phNxpNciHal_send_ext_cmd(sizeof(cmd_ce_in_phone_off_pn557),
                                         cmd_ce_in_phone_off_pn557);
       if (status != NFCSTATUS_SUCCESS) {
@@ -2429,14 +2527,14 @@ close_and_return:
       if (status == NFCSTATUS_SUCCESS) {
         break;
       } else {
-        NXPLOG_NCIHAL_E("NCI_CORE_RESET: Failed, perform retry after delay");
+        retry++;
+        NXPLOG_NCIHAL_E("NCI_CORE_RESET: Failed %x, perform retry after delay", retry);
         usleep(1000 * 1000);
         if (nxpncihal_ctrl.halStatus == HAL_STATUS_CLOSE) {
           // make sure read is pending
           NFCSTATUS readStatus = phNxpNciHal_enableTmlRead();
           NXPLOG_NCIHAL_D("read status = %x", readStatus);
         }
-        retry++;
         if (retry > 3) {
           NXPLOG_NCIHAL_E(
               "Maximum retries performed, shall restart HAL to recover");
@@ -2517,6 +2615,56 @@ void phNxpNciHal_close_complete(NFCSTATUS status) {
   return;
 }
 
+/******************************************************************************
+ * Function         phNxpNciHal_clean_resources
+ *
+ * Description      This function clean the resources.
+ *
+ * Returns          void.
+ *
+ ******************************************************************************/
+void phNxpNciHal_clean_resources() {
+  phNxpNciHal_deinitializeRegRfFwDnld();
+
+  if (gPowerTrackerHandle.stop != NULL) {
+    gPowerTrackerHandle.stop();
+  }
+  phNxpNciHal_WiredSeDispatchEvent(&gWiredSeHandle, NFC_STATE_CHANGE,
+                                   (WiredSeEvtData)NfcState::NFC_OFF);
+
+  sem_destroy(&sem_reset_ntf_received);
+  sem_destroy(&nxpncihal_ctrl.syncSpiNfc);
+
+  if (NULL != gpphTmlNfc_Context->pDevHandle) {
+    phNxpNciHal_close_complete(NFCSTATUS_SUCCESS);
+    /* Abort any pending read and write */
+    NFCSTATUS status = phTmlNfc_ReadAbort();
+    if (status != NFCSTATUS_SUCCESS) {
+      NXPLOG_TML_E("phTmlNfc_ReadAbort Failed");
+    }
+    phOsalNfc_Timer_Cleanup();
+
+    status = phTmlNfc_Shutdown();
+    if (status != NFCSTATUS_SUCCESS) {
+      NXPLOG_TML_E("phTmlNfc_Shutdown Failed");
+    }
+
+    PhNxpEventLogger::GetInstance().Finalize();
+    phNxpTempMgr::GetInstance().Reset();
+    phTmlNfc_CleanUp();
+
+    phDal4Nfc_msgrelease(nxpncihal_ctrl.gDrvCfg.nClientId);
+
+    memset(&nxpncihal_ctrl, 0x00, sizeof(nxpncihal_ctrl));
+  }
+
+  phNxpNciHal_cleanup_monitor();
+  write_unlocked_status = NFCSTATUS_SUCCESS;
+  phNxpNciHal_release_info();
+  /* reset config cache */
+  resetNxpConfig();
+}
+
 /******************************************************************************
  * Function         phNxpNciHal_configDiscShutdown
  *
@@ -2567,8 +2715,14 @@ int phNxpNciHal_configDiscShutdown(void) {
   if (IS_CHIP_TYPE_GE(sn220u)) {
     if (phNxpNciHal_isULPDetSupported() &&
         phNxpNciHal_getULPDetFlag() == false) {
+      if (nxpncihal_ctrl.halStatus == HAL_STATUS_CLOSE) {
+        NXPLOG_NCIHAL_D("phNxpNciHal_close is already closed, ignoring close");
+        return NFCSTATUS_FAILED;
+      }
       NXPLOG_NCIHAL_D("Ulpdet supported");
       status = phNxpNciHal_propConfULPDetMode(true);
+      phNxpNciHal_clean_resources();
+      CONCURRENCY_UNLOCK();
       return status;
     }
   }
@@ -3704,19 +3858,23 @@ static NFCSTATUS phNxpNciHal_do_swp_session_reset(void) {
  ******************************************************************************/
 void phNxpNciHal_do_factory_reset(void) {
   NFCSTATUS status = NFCSTATUS_FAILED;
+  bool isHalOpenRequested = false;
   // After factory reset phone will turnoff so mutex not required here.
   if (nxpncihal_ctrl.halStatus == HAL_STATUS_CLOSE) {
+    isHalOpenRequested = true;
     status = phNxpNciHal_MinOpen();
     if (status != NFCSTATUS_SUCCESS) {
       NXPLOG_NCIHAL_E("%s: NXP Nfc Open failed", __func__);
       return;
     }
-    phNxpNciHal_deinitializeRegRfFwDnld();
   }
   status = phNxpNciHal_do_swp_session_reset();
   if (status != NFCSTATUS_SUCCESS) {
     NXPLOG_NCIHAL_E("%s failed. status = %x ", __func__, status);
   }
+  if (nxpncihal_ctrl.halStatus == HAL_STATUS_MIN_OPEN && isHalOpenRequested) {
+    phNxpNciHal_close(false);
+  }
 }
 /******************************************************************************
  * Function         phNxpNciHal_hci_network_reset
@@ -4062,6 +4220,7 @@ void phNxpNciHal_deinitializeRegRfFwDnld() {
     fpPropConfCover = NULL;
     dlclose(RfFwRegionDnld_handle);
     RfFwRegionDnld_handle = NULL;
+    fpDoAntennaActivity = NULL;
   }
 }
 
diff --git a/snxxx/halimpl/hal/phNxpNciHal.h b/snxxx/halimpl/hal/phNxpNciHal.h
index 45a00af..c3bf837 100644
--- a/snxxx/halimpl/hal/phNxpNciHal.h
+++ b/snxxx/halimpl/hal/phNxpNciHal.h
@@ -55,6 +55,7 @@ typedef void(phNxpNciHal_control_granted_callback_t)();
 #define UICC1_ID 0x02
 #define UICC2_ID 0x04
 #define UICC3_ID 0x08
+#define ENABLE_T4T_CE 0x03
 /* NCI Data */
 
 //#define NCI_MT_CMD 0x20
@@ -83,6 +84,9 @@ typedef void(phNxpNciHal_control_granted_callback_t)();
 #define NXP_MAX_CONFIG_STRING_LEN 260
 #define NCI_HEADER_SIZE 3
 
+#define NXP_PHONE_OFF_NFC_OFF_CE_NOT_SUPPORTED 0x00
+#define NXP_PHONE_OFF_NFC_OFF_T4T_CE_SUPPORTED 0x03
+
 #define CORE_RESET_NTF_RECOVERY_REQ_COUNT 0x03
 
 typedef struct nci_data {
@@ -459,4 +463,16 @@ void phNxpNciHal_client_data_callback();
  ******************************************************************************/
 bool phNxpNciHal_UpdateRfMiscSettings();
 
+/******************************************************************************
+ * Function         phNxpNciHal_notifyPollingFrame
+ *
+ * Description      Send polling info notification to send to upper layer
+ *
+ * Parameters       p_data - Polling loop info notification
+ *
+ * Returns          void
+ *
+ ******************************************************************************/
+void phNxpNciHal_notifyPollingFrame(uint16_t data_len, uint8_t* p_data);
+
 #endif /* _PHNXPNCIHAL_H_ */
diff --git a/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc b/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc
index 90648dc..a77b572 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc
@@ -22,6 +22,8 @@
 
 #include <map>
 #include <set>
+#include <unordered_map>
+#include <vector>
 
 #include "EseAdaptation.h"
 #include "NfccTransport.h"
@@ -42,6 +44,54 @@ using namespace ::android::base;
 /* HAL_NFC_STATUS_REFUSED sent to restart NFC service */
 #define HAL_NFC_STATUS_RESTART HAL_NFC_STATUS_REFUSED
 
+#define GET_RES_STATUS_CHECK(len, data)                           \
+  (((len) < NCI_HEADER_SIZE) ||                                   \
+   ((len) != ((data[NCI_PACKET_LEN_INDEX]) + NCI_HEADER_SIZE)) || \
+   (NFCSTATUS_SUCCESS != (data[NCI_GET_RES_STATUS_INDEX])))
+
+typedef enum {
+  UPDATE_DLMA_ID_TX_ENTRY,
+  UPDATE_RF_CM_TX_UNDERSHOOT_CONFIG,
+  UPDATE_MIFARE_NACK_TO_RATS_ENABLE,
+  UPDATE_MIFARE_MUTE_TO_RATS_ENABLE,
+  UPDATE_CHINA_TIANJIN_RF_ENABLED,
+  UPDATE_CN_TRANSIT_CMA_BYPASSMODE_ENABLE,
+  UPDATE_CN_TRANSIT_BLK_NUM_CHECK_ENABLE,
+  UPDATE_ISO_DEP_MERGE_SAK,
+  UPDATE_PHONEOFF_TECH_DISABLE,
+  UPDATE_INITIAL_TX_PHASE,
+  UPDATE_GUARD_TIMEOUT_TX2RX,
+  UPDATE_LPDET_THRESHOLD,
+  UPDATE_NFCLD_THRESHOLD,
+  UPDATE_RF_PATTERN_CHK,
+  UPDATE_UNKNOWN = 0xFF
+} tNFC_setDynamicRfConfigType;
+static const std::unordered_map<std::string, uint8_t> tokenMap = {
+    {"UPDATE_DLMA_ID_TX_ENTRY", UPDATE_DLMA_ID_TX_ENTRY},
+    {"UPDATE_RF_CM_TX_UNDERSHOOT_CONFIG", UPDATE_RF_CM_TX_UNDERSHOOT_CONFIG},
+    {"UPDATE_MIFARE_NACK_TO_RATS_ENABLE", UPDATE_MIFARE_NACK_TO_RATS_ENABLE},
+    {"UPDATE_MIFARE_MUTE_TO_RATS_ENABLE", UPDATE_MIFARE_MUTE_TO_RATS_ENABLE},
+    {"UPDATE_CHINA_TIANJIN_RF_ENABLED", UPDATE_CHINA_TIANJIN_RF_ENABLED},
+    {"UPDATE_CN_TRANSIT_CMA_BYPASSMODE_ENABLE",
+     UPDATE_CN_TRANSIT_CMA_BYPASSMODE_ENABLE},
+    {"UPDATE_CN_TRANSIT_BLK_NUM_CHECK_ENABLE",
+     UPDATE_CN_TRANSIT_BLK_NUM_CHECK_ENABLE},
+    {"UPDATE_ISO_DEP_MERGE_SAK", UPDATE_ISO_DEP_MERGE_SAK},
+    {"UPDATE_PHONEOFF_TECH_DISABLE", UPDATE_PHONEOFF_TECH_DISABLE},
+    {"UPDATE_INITIAL_TX_PHASE", UPDATE_INITIAL_TX_PHASE},
+    {"UPDATE_GUARD_TIMEOUT_TX2RX", UPDATE_GUARD_TIMEOUT_TX2RX},
+    {"UPDATE_LPDET_THRESHOLD", UPDATE_LPDET_THRESHOLD},
+    {"UPDATE_NFCLD_THRESHOLD", UPDATE_NFCLD_THRESHOLD},
+    {"UPDATE_RF_PATTERN_CHK", UPDATE_RF_PATTERN_CHK}};
+
+static const std::unordered_map<uint8_t, uint8_t> rfReg_A085_Map = {
+    {UPDATE_MIFARE_NACK_TO_RATS_ENABLE, MIFARE_NACK_TO_RATS_ENABLE_BIT_POS},
+    {UPDATE_MIFARE_MUTE_TO_RATS_ENABLE, MIFARE_MUTE_TO_RATS_ENABLE_BIT_POS},
+    {UPDATE_CHINA_TIANJIN_RF_ENABLED, CHINA_TIANJIN_RF_ENABLE_BIT_POS},
+    {UPDATE_CN_TRANSIT_CMA_BYPASSMODE_ENABLE,
+     CN_TRANSIT_CMA_BYPASSMODE_ENABLE_BIT_POS},
+    {UPDATE_CN_TRANSIT_BLK_NUM_CHECK_ENABLE,
+     CN_TRANSIT_BLK_NUM_CHECK_ENABLE_BIT_POS}};
 /****************************************************************
  * Global Variables Declaration
  ***************************************************************/
@@ -122,7 +172,8 @@ int property_set_intf(const char* propName, const char* valueStr) {
 }
 
 extern size_t readConfigFile(const char* fileName, uint8_t** p_data);
-
+extern NFCSTATUS phNxpNciHal_ext_send_sram_config_to_flash();
+static bool phNxpNciHal_checkUpdateRfTransitConfig(const char* config);
 static string phNxpNciHal_parseBytesString(string in);
 static bool phNxpNciHal_parseValueFromString(string& in);
 static bool phNxpNciHal_CheckKeyNeeded(string key);
@@ -665,9 +716,19 @@ bool phNxpNciHal_setNxpTransitConfig(char* transitConfValue) {
   long transitConfValueLen = strlen(transitConfValue) + 1;
 
   if (transitConfValueLen > 1) {
-    if (!WriteStringToFile(transitConfValue, transitConfFileName)) {
-      NXPLOG_NCIHAL_E("WriteStringToFile: Failed");
-      status = false;
+    if (strncmp(transitConfValue, "UPDATE_", 7) == 0) {
+      if (IS_CHIP_TYPE_GE(sn220u) &&
+          phNxpNciHal_checkUpdateRfTransitConfig(transitConfValue)) {
+        NXPLOG_NCIHAL_D("%s :RfTransit values updated", __func__);
+      } else {
+        NXPLOG_NCIHAL_E("Failed to update RfTransit values");
+        status = false;
+      }
+    } else {
+      if (!WriteStringToFile(transitConfValue, transitConfFileName)) {
+        NXPLOG_NCIHAL_E("WriteStringToFile: Failed");
+        status = false;
+      }
     }
   } else {
     if (!WriteStringToFile("", transitConfFileName)) {
@@ -904,3 +965,357 @@ void phNxpNciHal_txNfccClockSetCmd(void) {
   }
   return;
 }
+
+/*******************************************************************************
+**
+** Function         phNxpNciHal_updateRfSetConfig
+**
+** Description      Update the set RF settings.
+**
+** Parameters       setConfCmd - Update the set config buffer based on getConfig
+**                  getResData - Response data.
+** Returns          True/False
+*******************************************************************************/
+bool phNxpNciHal_updateRfSetConfig(vector<uint8_t>& setConfCmd,
+                                   vector<uint8_t>& getResData) {
+  uint8_t res_data_packet_len = 0;
+  if ((getResData.size() <= 5) ||
+      (getResData.size() !=
+       (getResData[NCI_PACKET_LEN_INDEX] + NCI_HEADER_SIZE))) {
+    NXPLOG_NCIHAL_E("%s : Invalid res data length", __FUNCTION__);
+    return false;
+  }
+  /*Updating the actual TLV packet length by excluding the status & tlv bytes */
+  res_data_packet_len = getResData[NCI_PACKET_LEN_INDEX] - 2;
+  /*Copying the TLV packet and excluding  NCI header, status & tlv bytes*/
+  setConfCmd.insert(setConfCmd.end(), getResData.begin() + 5, getResData.end());
+  if (setConfCmd.size() >= 0xFF) {
+    if (NFCSTATUS_SUCCESS !=
+        phNxpNciHal_send_ext_cmd((setConfCmd.size() - res_data_packet_len),
+                                 &setConfCmd[0])) {
+      NXPLOG_NCIHAL_E("%s : Set config failed", __FUNCTION__);
+      return false;
+    }
+    // Clear setConf Data expect the last command response.
+    setConfCmd.erase(setConfCmd.begin() + 4,
+                     setConfCmd.end() - res_data_packet_len);
+    // Clear the length and TLV after sending the packet.
+    setConfCmd[NCI_PACKET_LEN_INDEX] = 0x01;
+    setConfCmd[NCI_PACKET_TLV_INDEX] = 0x00;
+  }
+  setConfCmd[NCI_PACKET_LEN_INDEX] += res_data_packet_len;
+  setConfCmd[NCI_PACKET_TLV_INDEX] += getResData[NCI_GET_RES_TLV_INDEX];
+
+  return true;
+}
+/*******************************************************************************
+**
+** Function         phNxpNciHal_getUpdatePropRfSetConfig
+**
+** Description      Get and update the Prop RF settings.
+**
+** Parameters       IndexValue poniting to the vector
+**                  NewValue   - To be update at the index position
+**                  propCmdresData - Update the prop response buffer based on
+**                  prop getConfig response.
+** Returns          bool value true/false
+*******************************************************************************/
+bool phNxpNciHal_getUpdatePropRfSetConfig(unsigned newValue,
+                                          vector<uint8_t>& propCmdresData) {
+  vector<uint8_t> prop_cmd_get_rftxval{0x2F, 0x14, 0x02, 0x62, 0x32};
+  uint8_t getPropRfCount = 0;
+  uint8_t index = 10;  // Index for RF register 6232
+  do {
+    if (NFCSTATUS_SUCCESS !=
+        phNxpNciHal_send_ext_cmd(prop_cmd_get_rftxval.size(),
+                                 &prop_cmd_get_rftxval[0])) {
+      NXPLOG_NCIHAL_E("%s : Get config failed for A00D", __FUNCTION__);
+      return false;
+    }
+    if (GET_RES_STATUS_CHECK(nxpncihal_ctrl.rx_data_len,
+                             nxpncihal_ctrl.p_rx_data)) {
+      NXPLOG_NCIHAL_E("%s : Get response failed", __FUNCTION__);
+      return false;
+    }
+    if (nxpncihal_ctrl.p_rx_data[RF_CM_TX_UNDERSHOOT_INDEX] == newValue)
+      return true;
+
+    // Mapping Prop command response to NCI command response.
+    propCmdresData[index] = (uint8_t)(newValue & BYTE0_SHIFT_MASK);
+    propCmdresData[index + 1] =
+        nxpncihal_ctrl.p_rx_data[RF_CM_TX_UNDERSHOOT_INDEX + 1];
+    propCmdresData[index + 2] =
+        nxpncihal_ctrl.p_rx_data[RF_CM_TX_UNDERSHOOT_INDEX + 2];
+    propCmdresData[index + 3] =
+        nxpncihal_ctrl.p_rx_data[RF_CM_TX_UNDERSHOOT_INDEX + 3];
+
+    getPropRfCount++;
+    if (getPropRfCount == 1) {
+      index = 19;  // Index for RF register 6732
+      prop_cmd_get_rftxval[NCI_PACKET_TLV_INDEX] = 0x67;
+    }
+  } while (getPropRfCount < 2);
+
+  return true;
+}
+
+/*******************************************************************************
+**
+** Function         phNxpNciHal_checkUpdateRfTransitConfig
+**
+** Description      Check and update selected RF settings dynamically.
+**
+** Parameters       char config
+**
+** Returns          bool value true/false
+*******************************************************************************/
+bool phNxpNciHal_checkUpdateRfTransitConfig(const char* config) {
+  vector<uint8_t> cmd_get_rfconfval{0x20, 0x03, 0x03, 0x01, 0xA0, 0x85};
+  vector<uint8_t> cmd_response{};
+  vector<uint8_t> lpdet_cmd_response{};
+  vector<uint8_t> get_cmd_response{};
+  vector<uint8_t> cmd_set_rfconfval{0x20, 0x02, 0x01, 0x00};
+  vector<uint8_t> prop_Cmd_Response{
+      /*Preset get config response for A00D register*/
+      0x40, 0x03, 0x14, 0x00, 0x02, 0xA0, 0x0D, 0x06, 0x62, 0x32, 0xAE, 0x00,
+      0x7F, 0x00, 0xA0, 0x0D, 0x06, 0x67, 0x32, 0xAE, 0x00, 0x1F, 0x00};
+  bool is_feature_update_required = false;
+  bool is_lpdet_threshold_required = false;
+  uint8_t index_to_value = 0;
+  uint8_t update_mode = BITWISE;
+  uint8_t condition = 0;
+  stringstream key_value_pairs(config);
+  string single_key_value;
+  unsigned b_position = 0;
+  unsigned new_value = 0;
+  unsigned read_value = 0;
+  unsigned rf_reg_A085_value = 0;
+
+  NXPLOG_NCIHAL_D("%s : Enter", __FUNCTION__);
+
+  if (NFCSTATUS_SUCCESS != phNxpNciHal_send_ext_cmd(cmd_get_rfconfval.size(),
+                                                    &cmd_get_rfconfval[0])) {
+    NXPLOG_NCIHAL_E("%s : Get config failed for A085", __FUNCTION__);
+    return false;
+  }
+  if (GET_RES_STATUS_CHECK(nxpncihal_ctrl.rx_data_len,
+                           nxpncihal_ctrl.p_rx_data)) {
+    NXPLOG_NCIHAL_E("%s : Get config failed", __FUNCTION__);
+    return false;
+  }
+  // Updating the A085 get config command response to vector.
+  cmd_response.insert(
+      cmd_response.end(), &nxpncihal_ctrl.p_rx_data[0],
+      (&nxpncihal_ctrl.p_rx_data[0] +
+       (nxpncihal_ctrl.p_rx_data[NCI_PACKET_LEN_INDEX] + NCI_HEADER_SIZE)));
+  rf_reg_A085_value = (unsigned)((cmd_response[REG_A085_DATA_INDEX + 3] << 24) |
+                                 (cmd_response[REG_A085_DATA_INDEX + 2] << 16) |
+                                 (cmd_response[REG_A085_DATA_INDEX + 1] << 8) |
+                                 (cmd_response[REG_A085_DATA_INDEX]));
+
+  cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x9E;
+  if (NFCSTATUS_SUCCESS != phNxpNciHal_send_ext_cmd(cmd_get_rfconfval.size(),
+                                                    &cmd_get_rfconfval[0])) {
+    NXPLOG_NCIHAL_E("%s : Get config failed for A09E", __FUNCTION__);
+    return false;
+  }
+  if (GET_RES_STATUS_CHECK(nxpncihal_ctrl.rx_data_len,
+                           nxpncihal_ctrl.p_rx_data)) {
+    NXPLOG_NCIHAL_E("%s : Get config failed", __FUNCTION__);
+    return false;
+  }
+  // Updating the A09E get config command response to vector.
+  lpdet_cmd_response.insert(
+      lpdet_cmd_response.end(), &nxpncihal_ctrl.p_rx_data[0],
+      (&nxpncihal_ctrl.p_rx_data[0] +
+       (nxpncihal_ctrl.p_rx_data[NCI_PACKET_LEN_INDEX] + NCI_HEADER_SIZE)));
+
+  while (getline(key_value_pairs, single_key_value)) {
+    auto search = single_key_value.find('=');
+    if (search == string::npos) continue;
+
+    string key(Trim(single_key_value.substr(0, search)));
+    string value(Trim(single_key_value.substr(search + 1, string::npos)));
+    ParseUint(value.c_str(), &new_value);
+    update_mode = BITWISE;
+    NXPLOG_NCIHAL_D("%s : Update Key = %s Value: %02x", __FUNCTION__,
+                    key.c_str(), new_value);
+    auto it = tokenMap.find(key);
+    if (it != tokenMap.end()) {
+      condition = it->second;
+    } else
+      condition = UPDATE_UNKNOWN;
+
+    switch (condition) {
+      case UPDATE_DLMA_ID_TX_ENTRY:
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX1] = 0xA0;
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x34;
+        index_to_value = DLMA_ID_TX_ENTRY_INDEX;
+        break;
+      case UPDATE_RF_CM_TX_UNDERSHOOT_CONFIG:
+        if (!phNxpNciHal_getUpdatePropRfSetConfig(new_value, prop_Cmd_Response))
+          return false;
+
+        if ((nxpncihal_ctrl.rx_data_len > RF_CM_TX_UNDERSHOOT_INDEX) &&
+            (nxpncihal_ctrl.p_rx_data[RF_CM_TX_UNDERSHOOT_INDEX] !=
+             new_value)) {
+          if (!phNxpNciHal_updateRfSetConfig(cmd_set_rfconfval,
+                                             prop_Cmd_Response))
+            return false;
+        }
+        break;
+      case UPDATE_INITIAL_TX_PHASE:
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX1] = 0xA0;
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x6A;
+        index_to_value = INITIAL_TX_PHASE_INDEX;
+        update_mode = BYTEWISE;
+        break;
+      case UPDATE_LPDET_THRESHOLD:
+        read_value = 0;
+        read_value = lpdet_cmd_response[LPDET_THRESHOLD_INDEX];
+        read_value |= (lpdet_cmd_response[LPDET_THRESHOLD_INDEX + 1] << 8);
+        NXPLOG_NCIHAL_D("%s : read_value = %02x Value: %02x", __FUNCTION__,
+                        read_value, new_value);
+        if (read_value != new_value) {
+          lpdet_cmd_response[LPDET_THRESHOLD_INDEX] =
+              (uint8_t)(new_value & BYTE0_SHIFT_MASK);
+          lpdet_cmd_response[LPDET_THRESHOLD_INDEX + 1] =
+              (uint8_t)((new_value & BYTE1_SHIFT_MASK) >> 8);
+          is_lpdet_threshold_required = true;
+        }
+        break;
+      case UPDATE_NFCLD_THRESHOLD:
+        read_value = 0;
+        read_value = lpdet_cmd_response[NFCLD_THRESHOLD_INDEX];
+        read_value |= (lpdet_cmd_response[NFCLD_THRESHOLD_INDEX + 1] << 8);
+        NXPLOG_NCIHAL_D("%s : read_value = %02x Value: %02x", __FUNCTION__,
+                        read_value, new_value);
+        if (read_value != new_value) {
+          lpdet_cmd_response[NFCLD_THRESHOLD_INDEX] =
+              (uint8_t)(new_value & BYTE0_SHIFT_MASK);
+          lpdet_cmd_response[NFCLD_THRESHOLD_INDEX + 1] =
+              (uint8_t)((new_value & BYTE1_SHIFT_MASK) >> 8);
+          is_lpdet_threshold_required = true;
+        }
+        break;
+      case UPDATE_GUARD_TIMEOUT_TX2RX:
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX1] = 0xA1;
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x0E;
+        index_to_value = GUARD_TIMEOUT_TX2RX_INDEX;
+        break;
+      case UPDATE_RF_PATTERN_CHK:
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX1] = 0xA1;
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x48;
+        index_to_value = RF_PATTERN_CHK_INDEX;
+        break;
+      case UPDATE_MIFARE_NACK_TO_RATS_ENABLE:
+      case UPDATE_MIFARE_MUTE_TO_RATS_ENABLE:
+      case UPDATE_CHINA_TIANJIN_RF_ENABLED:
+      case UPDATE_CN_TRANSIT_CMA_BYPASSMODE_ENABLE:
+      case UPDATE_CN_TRANSIT_BLK_NUM_CHECK_ENABLE: {
+        auto itReg = rfReg_A085_Map.find(condition);
+        if (itReg == rfReg_A085_Map.end()) continue;
+
+        NXPLOG_NCIHAL_D("%s : Reg A085 Update Key = %s and Bit Position: %d",
+                        __FUNCTION__, key.c_str(), itReg->second);
+        b_position = (unsigned)(0x01 << itReg->second);
+        if ((rf_reg_A085_value & b_position) !=
+            ((new_value & 0x01) << itReg->second)) {
+          rf_reg_A085_value ^= (1 << itReg->second);
+          is_feature_update_required = true;
+        }
+      } break;
+      case UPDATE_PHONEOFF_TECH_DISABLE:
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX1] = 0xA1;
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x1A;
+        index_to_value = PHONEOFF_TECH_DISABLE_INDEX;
+        break;
+      case UPDATE_ISO_DEP_MERGE_SAK:
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX1] = 0xA1;
+        cmd_get_rfconfval[NCI_GET_CMD_TLV_INDEX2] = 0x1B;
+        index_to_value = ISO_DEP_MERGE_SAK_INDEX;
+        break;
+      default:
+        NXPLOG_NCIHAL_D("%s : default = %x", __FUNCTION__, new_value);
+        break;
+    }
+    if (index_to_value) {
+      if (NFCSTATUS_SUCCESS !=
+          phNxpNciHal_send_ext_cmd(cmd_get_rfconfval.size(),
+                                   &cmd_get_rfconfval[0])) {
+        NXPLOG_NCIHAL_E("%s : Get config failed for %s", __FUNCTION__,
+                        key.c_str());
+        return false;
+      }
+      if (GET_RES_STATUS_CHECK(nxpncihal_ctrl.rx_data_len,
+                               nxpncihal_ctrl.p_rx_data)) {
+        NXPLOG_NCIHAL_E("%s : Get config response failed ", __FUNCTION__);
+        return false;
+      }
+      read_value = 0;
+      read_value = nxpncihal_ctrl.p_rx_data[index_to_value];
+      if (update_mode == BYTEWISE)
+        read_value |= (nxpncihal_ctrl.p_rx_data[index_to_value + 1] << 8);
+      if (read_value == new_value) {
+        index_to_value = 0;
+        continue;
+      }
+      nxpncihal_ctrl.p_rx_data[index_to_value] =
+          (uint8_t)(new_value & BYTE0_SHIFT_MASK);
+      if (update_mode == BYTEWISE)
+        nxpncihal_ctrl.p_rx_data[index_to_value + 1] =
+            (uint8_t)((new_value & BYTE1_SHIFT_MASK) >> 8);
+
+      // Updating the get config command response to vector.
+      get_cmd_response.insert(
+          get_cmd_response.end(), &nxpncihal_ctrl.p_rx_data[0],
+          (&nxpncihal_ctrl.p_rx_data[0] +
+           (nxpncihal_ctrl.p_rx_data[NCI_PACKET_LEN_INDEX] + NCI_HEADER_SIZE)));
+      if (!phNxpNciHal_updateRfSetConfig(cmd_set_rfconfval, get_cmd_response))
+        return false;
+
+      get_cmd_response.clear();
+      index_to_value = 0;
+    }
+  }
+  if (is_feature_update_required) {
+    // Updating the A085 response to set config command.
+    cmd_response[REG_A085_DATA_INDEX + 3] =
+        (uint8_t)((rf_reg_A085_value & BYTE3_SHIFT_MASK) >> 24);
+    cmd_response[REG_A085_DATA_INDEX + 2] =
+        (uint8_t)((rf_reg_A085_value & BYTE2_SHIFT_MASK) >> 16);
+    cmd_response[REG_A085_DATA_INDEX + 1] =
+        (uint8_t)((rf_reg_A085_value & BYTE1_SHIFT_MASK) >> 8);
+    cmd_response[REG_A085_DATA_INDEX] =
+        (uint8_t)(rf_reg_A085_value & BYTE0_SHIFT_MASK);
+    if (!phNxpNciHal_updateRfSetConfig(cmd_set_rfconfval, cmd_response))
+      return false;
+  }
+  if (is_lpdet_threshold_required) {
+    // Updating the A09E response to set config command.
+    if (!phNxpNciHal_updateRfSetConfig(cmd_set_rfconfval, lpdet_cmd_response))
+      return false;
+  }
+  if (cmd_set_rfconfval.size() <= NCI_HEADER_SIZE) {
+    NXPLOG_NCIHAL_E("%s : Invalid NCI Command length = %zu", __FUNCTION__,
+                    cmd_set_rfconfval.size());
+    return false;
+  }
+  if (cmd_set_rfconfval[NCI_PACKET_TLV_INDEX] != 0x00) {
+    /*If update require do set-config in NFCC otherwise skip */
+    if (NFCSTATUS_SUCCESS == phNxpNciHal_send_ext_cmd(cmd_set_rfconfval.size(),
+                                                      &cmd_set_rfconfval[0])) {
+      if (is_feature_update_required) {
+        if (NFCSTATUS_SUCCESS != phNxpNciHal_ext_send_sram_config_to_flash()) {
+          NXPLOG_NCIHAL_E("%s :Updation of the SRAM contents failed",
+                          __FUNCTION__);
+          return false;
+        }
+      }
+    } else {
+      NXPLOG_NCIHAL_D("Set RF update cmd  is failed..");
+      return false;
+    }
+  }
+  return true;
+}
diff --git a/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.h b/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.h
index d5a743c..47ec81b 100755
--- a/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.h
+++ b/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2019-2023 NXP
+ * Copyright 2019-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -20,6 +20,37 @@
 #include "phNxpConfig.h"
 #include "phNxpLog.h"
 
+#define NCI_PACKET_LEN_INDEX 2
+#define NCI_PACKET_TLV_INDEX 3
+/*Below are NCI get config response index values for each RF register*/
+#define DLMA_ID_TX_ENTRY_INDEX 12
+#define RF_CM_TX_UNDERSHOOT_INDEX 5
+#define PHONEOFF_TECH_DISABLE_INDEX 8
+#define ISO_DEP_MERGE_SAK_INDEX 8
+#define INITIAL_TX_PHASE_INDEX 8
+#define LPDET_THRESHOLD_INDEX 11
+#define NFCLD_THRESHOLD_INDEX 13
+#define RF_PATTERN_CHK_INDEX 8
+#define GUARD_TIMEOUT_TX2RX_INDEX 8
+#define REG_A085_DATA_INDEX 8
+
+/*Below are A085 RF register bitpostions*/
+#define CN_TRANSIT_BLK_NUM_CHECK_ENABLE_BIT_POS 6
+#define MIFARE_NACK_TO_RATS_ENABLE_BIT_POS 13
+#define MIFARE_MUTE_TO_RATS_ENABLE_BIT_POS 9
+#define CN_TRANSIT_CMA_BYPASSMODE_ENABLE_BIT_POS 23
+#define CHINA_TIANJIN_RF_ENABLE_BIT_POS 28
+
+#define NCI_GET_CMD_TLV_INDEX1 4
+#define NCI_GET_CMD_TLV_INDEX2 5
+#define NCI_GET_RES_STATUS_INDEX 3
+#define NCI_GET_RES_TLV_INDEX 4
+
+#define BYTE0_SHIFT_MASK 0x000000FF
+#define BYTE1_SHIFT_MASK 0x0000FF00
+#define BYTE2_SHIFT_MASK 0x00FF0000
+#define BYTE3_SHIFT_MASK 0xFF000000
+
 /******************************************************************************
  ** Function         phNxpNciHal_ioctlIf
  **
diff --git a/snxxx/halimpl/hal/phNxpNciHal_LxDebug.h b/snxxx/halimpl/hal/phNxpNciHal_LxDebug.h
index fc515f6..69f7d80 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_LxDebug.h
+++ b/snxxx/halimpl/hal/phNxpNciHal_LxDebug.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2023 NXP
+ * Copyright 2023-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -30,7 +30,7 @@
 #define LX_DEBUG_CFG_ENABLE_L1_EVENT 0x0010
 #define LX_DEBUG_CFG_ENABLE_MOD_DETECTED_EVENT 0x0020
 #define LX_DEBUG_CFG_ENABLE_CMA_EVENTS 0x2000
-#define LX_DEBUG_CFG_MASK_RFU 0xDFC0
-#define LX_DEBUG_CFG_MASK 0x20FF
+#define LX_DEBUG_CFG_MASK_RFU 0x9FC0
+#define LX_DEBUG_CFG_MASK 0x60FF
 
 #endif /* _PHNXPNCIHAL_LXDEBUG_H_ */
diff --git a/snxxx/halimpl/hal/phNxpNciHal_WiredSeIface.cc b/snxxx/halimpl/hal/phNxpNciHal_WiredSeIface.cc
new file mode 100755
index 0000000..41d0c33
--- /dev/null
+++ b/snxxx/halimpl/hal/phNxpNciHal_WiredSeIface.cc
@@ -0,0 +1,93 @@
+/*
+ * Copyright 2024 NXP
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "phNxpNciHal_WiredSeIface.h"
+
+#include <dlfcn.h>
+#include <phNxpNciHal.h>
+
+#define TERMINAL_TYPE_ESE 0x01
+#define TERMINAL_TYPE_EUICC 0x05
+#define TERMINAL_TYPE_EUICC2 0x06
+
+/*******************************************************************************
+**
+** Function         phNxpNciHal_WiredSeStart()
+**
+** Description      Starts wired-se HAL. This is the first Api to be invoked.
+**                  Once it is started it will run throughout the process
+*lifecycle.
+**                  It is recommended to call from main() of service.
+**
+** Parameters       outHandle - Handle to the Wired SE subsystem.
+** Returns          NFCSTATUS_SUCCESS if WiredSe HAL is started.
+**                  NFCSTATUS_FAILURE otherwise
+*******************************************************************************/
+
+NFCSTATUS phNxpNciHal_WiredSeStart(WiredSeHandle* outHandle) {
+  if (outHandle == NULL) {
+    return NFCSTATUS_FAILED;
+  }
+  // Open WiredSe shared library
+  NXPLOG_NCIHAL_D("Opening (/vendor/lib64/WiredSe.so)");
+  outHandle->dlHandle = dlopen("/vendor/lib64/WiredSe.so", RTLD_NOW);
+  if (outHandle->dlHandle == NULL) {
+    NXPLOG_NCIHAL_E("Error : opening (/vendor/lib64/WiredSe.so) %s!!",
+                    dlerror());
+    return NFCSTATUS_FAILED;
+  }
+  outHandle->start =
+      (WiredSeStartFunc_t)dlsym(outHandle->dlHandle, "WiredSeService_Start");
+  if (outHandle->start == NULL) {
+    NXPLOG_NCIHAL_E("Error : Failed to find symbol WiredSeService_Start %s!!",
+                    dlerror());
+    return NFCSTATUS_FAILED;
+  }
+  outHandle->dispatchEvent = (WiredSeDispatchEventFunc_t)dlsym(
+      outHandle->dlHandle, "WiredSeService_DispatchEvent");
+  if (outHandle->dispatchEvent == NULL) {
+    NXPLOG_NCIHAL_E(
+        "Error : Failed to find symbol WiredSeService_DispatchEvent "
+        "%s!!",
+        dlerror());
+    return NFCSTATUS_FAILED;
+  }
+  NXPLOG_NCIHAL_D("Opened (/vendor/lib64/WiredSe.so)");
+  return outHandle->start(&outHandle->pWiredSeService);
+}
+
+/*******************************************************************************
+**
+** Function         phNxpNciHal_WiredSeDispatchEvent()
+**
+** Description      Dispatch events to wired-se subsystem.
+**
+** Parameters       outHandle - WiredSe Handle
+** Returns          NFCSTATUS_SUCCESS if success.
+**                  NFCSTATUS_FAILURE otherwise
+*******************************************************************************/
+NFCSTATUS phNxpNciHal_WiredSeDispatchEvent(WiredSeHandle* inHandle,
+                                           WiredSeEvtType evtType,
+                                           WiredSeEvtData evtData) {
+  if (inHandle == NULL || inHandle->dispatchEvent == NULL ||
+      inHandle->pWiredSeService == NULL) {
+    return NFCSTATUS_FAILED;
+  }
+  WiredSeEvt event;
+  event.eventData = evtData;
+  event.event = evtType;
+  return inHandle->dispatchEvent(inHandle->pWiredSeService, event);
+}
diff --git a/snxxx/halimpl/hal/phNxpNciHal_WiredSeIface.h b/snxxx/halimpl/hal/phNxpNciHal_WiredSeIface.h
new file mode 100755
index 0000000..8307b63
--- /dev/null
+++ b/snxxx/halimpl/hal/phNxpNciHal_WiredSeIface.h
@@ -0,0 +1,71 @@
+/*
+ * Copyright 2024 NXP
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#pragma once
+
+#include "WiredSeService.h"
+#include "phNfcStatus.h"
+
+#define NFCEE_ESE_ID 0xC0
+#define NFCEE_EUICC_ID 0xC1
+#define NFCEE_EUICC2_ID 0xC2
+#define NFCEE_INVALID_ID 0x00
+
+typedef int32_t (*WiredSeStartFunc_t)(WiredSeService** pWiredSeService);
+typedef int32_t (*WiredSeDispatchEventFunc_t)(WiredSeService* pWiredSeService,
+                                              WiredSeEvt event);
+
+/**
+ * Handle to the Power Tracker stack implementation.
+ */
+typedef struct {
+  // Function to start wired-se.
+  WiredSeStartFunc_t start;
+  // Function to dispatch events to wired-se subsystem.
+  WiredSeDispatchEventFunc_t dispatchEvent;
+  // WiredSeService instance
+  WiredSeService* pWiredSeService;
+  // WiredSe.so dynamic library handle.
+  void* dlHandle;
+} WiredSeHandle;
+
+/*******************************************************************************
+**
+** Function         phNxpNciHal_WiredSeStart()
+**
+** Description      Starts wired-se HAL. This is the first Api to be invoked.
+**                  Once it is started it will run throughout the process
+*lifecycle.
+**                  It is recommended to call from main() of service.
+**
+** Parameters       outHandle - Handle to the Wired SE subsystem.
+** Returns          NFCSTATUS_SUCCESS if WiredSe HAL is started.
+**                  NFCSTATUS_FAILURE otherwise
+*******************************************************************************/
+NFCSTATUS phNxpNciHal_WiredSeStart(WiredSeHandle* outHandle);
+
+/*******************************************************************************
+**
+** Function         phNxpNciHal_WiredSeDispatchEvent()
+**
+** Description      Dispatch events to wired-se subsystem.
+**
+** Parameters       inHandle - WiredSe Handle
+** Returns          NFCSTATUS_SUCCESS if success.
+**                  NFCSTATUS_FAILURE otherwise
+*******************************************************************************/
+NFCSTATUS phNxpNciHal_WiredSeDispatchEvent(
+    WiredSeHandle* inHandle, WiredSeEvtType evtType,
+    WiredSeEvtData evtData = WiredSeEvtData());
diff --git a/snxxx/halimpl/hal/phNxpNciHal_ext.cc b/snxxx/halimpl/hal/phNxpNciHal_ext.cc
index 9f735cd..842920b 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_ext.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_ext.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2023 NXP
+ * Copyright 2012-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -41,7 +41,7 @@
 #define NXP_EN_SN300U 1
 #define NXP_EN_SN330U 1
 #define NFC_NXP_MW_ANDROID_VER (15U)  /* Android version used by NFC MW */
-#define NFC_NXP_MW_VERSION_MAJ (0x08) /* MW Major Version */
+#define NFC_NXP_MW_VERSION_MAJ (0x0C) /* MW Major Version */
 #define NFC_NXP_MW_VERSION_MIN (0x00) /* MW Minor Version */
 #define NFC_NXP_MW_CUSTOMER_ID (0x00) /* MW Customer Id */
 #define NFC_NXP_MW_RC_VERSION (0x00)  /* MW RC Version */
diff --git a/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc b/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
index cabcdd3..4dd0376 100755
--- a/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
@@ -34,6 +34,7 @@ static vector<uint8_t> uicc2HciParams(0);
 static vector<uint8_t> uiccHciCeParams(0);
 extern phNxpNciHal_Control_t nxpncihal_ctrl;
 extern phTmlNfc_Context_t* gpphTmlNfc_Context;
+extern void* RfFwRegionDnld_handle;
 extern NFCSTATUS phNxpNciHal_ext_send_sram_config_to_flash();
 
 /*******************************************************************************
@@ -799,6 +800,10 @@ int phNxpNciHal_handleVendorSpecificCommand(uint16_t data_len,
                                   NCI_ANDROID_GET_OBSERVER_MODE_STATUS) {
     // 2F 0C 01 04 => ObserveMode Status Command length is 4 Bytes
     return handleGetObserveModeStatus(data_len, p_data);
+  } else if (data_len >= 4 &&
+             p_data[NCI_MSG_INDEX_FOR_FEATURE] == NCI_ANDROID_GET_CAPABILITY) {
+    // 2F 0C 01 00 => GetCapability Command length is 4 Bytes
+    return handleGetCapability(data_len, p_data);
   } else {
     return phNxpNciHal_write_internal(data_len, p_data);
   }
@@ -829,6 +834,9 @@ void phNxpNciHal_vendorSpecificCallback(int oid, int opcode,
   msg.eMsgType = NCI_HAL_VENDOR_MSG;
   msg.pMsgData = NULL;
   msg.Size = 0;
+  phNxpNciHal_print_packet("RECV", nxpncihal_ctrl.vendor_msg,
+                           nxpncihal_ctrl.vendor_msg_len,
+                           RfFwRegionDnld_handle == NULL);
   phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId,
                         (phLibNfc_Message_t*)&msg);
 }
@@ -857,3 +865,49 @@ bool phNxpNciHal_isObserveModeSupported() {
   }
   return false;
 }
+
+/*******************************************************************************
+ *
+ * Function         handleGetCapability()
+ *
+ * Description      It frames the capability for the below features
+ *                  1. Observe mode
+ *                  2. Polling frame notification
+ *                  3. Power saving mode
+ *                  4. Auotransact polling loop filter
+ *
+ * Returns          It returns number of bytes received.
+ *
+ ******************************************************************************/
+int handleGetCapability(uint16_t data_len, const uint8_t* p_data) {
+  // 2F 0C 01 00 => GetCapability Command length is 4 Bytes
+  if (data_len < 4) {
+    return 0;
+  }
+
+  // First byte is status is ok
+  // next 2 bytes is version for Android requirements
+  vector<uint8_t> capability = {0x00, 0x00, 0x00};
+  capability.push_back(4);  // 4 capability event's
+  // Observe mode
+  capability.push_back(nfcFL.nfccCap.OBSERVE_MODE.id);
+  capability.push_back(nfcFL.nfccCap.OBSERVE_MODE.len);
+  capability.push_back(nfcFL.nfccCap.OBSERVE_MODE.val);
+  // Polling frame notification
+  capability.push_back(nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.id);
+  capability.push_back(nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.len);
+  capability.push_back(nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.val);
+  // Power saving mode
+  capability.push_back(nfcFL.nfccCap.POWER_SAVING.id);
+  capability.push_back(nfcFL.nfccCap.POWER_SAVING.len);
+  capability.push_back(nfcFL.nfccCap.POWER_SAVING.val);
+  // Auotransact polling loop filter
+  capability.push_back(nfcFL.nfccCap.AUTOTRANSACT_PLF.id);
+  capability.push_back(nfcFL.nfccCap.AUTOTRANSACT_PLF.len);
+  capability.push_back(nfcFL.nfccCap.AUTOTRANSACT_PLF.val);
+
+  phNxpNciHal_vendorSpecificCallback(p_data[NCI_OID_INDEX],
+                                     p_data[NCI_MSG_INDEX_FOR_FEATURE],
+                                     std::move(capability));
+  return p_data[NCI_MSG_LEN_INDEX];
+}
diff --git a/snxxx/halimpl/hal/phNxpNciHal_extOperations.h b/snxxx/halimpl/hal/phNxpNciHal_extOperations.h
index eb5e91c..959ef62 100755
--- a/snxxx/halimpl/hal/phNxpNciHal_extOperations.h
+++ b/snxxx/halimpl/hal/phNxpNciHal_extOperations.h
@@ -26,6 +26,10 @@
 #define SWITCH_OFF_MASK 0x02
 #define NCI_GET_CONFI_MIN_LEN 0x04
 #define NXP_MAX_RETRY_COUNT 0x03
+typedef enum {
+  CONFIG,
+  API,
+} tNFC_requestedBy;
 typedef struct {
   uint8_t autonomous_mode;
   uint8_t guard_timer_value;
@@ -246,3 +250,15 @@ void phNxpNciHal_vendorSpecificCallback(int oid, int opcode,
 ** Returns          bool: true if supported, otherwise false
 *******************************************************************************/
 bool phNxpNciHal_isObserveModeSupported();
+
+/*******************************************************************************
+ *
+ * Function         handleGetCapability()
+ *
+ * Description      Get Capability command is not supported, hence returning
+ *                  failure
+ *
+ * Returns          It returns number of bytes received.
+ *
+ ******************************************************************************/
+int handleGetCapability(uint16_t data_len, const uint8_t* p_data);
diff --git a/snxxx/halimpl/log/phNxpLog.cc b/snxxx/halimpl/log/phNxpLog.cc
index 7608c26..c43f59c 100644
--- a/snxxx/halimpl/log/phNxpLog.cc
+++ b/snxxx/halimpl/log/phNxpLog.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2010-2019, 2022-2023 NXP
+ * Copyright 2010-2019, 2022-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -27,6 +27,8 @@ const char* NXPLOG_ITEM_EXTNS = "NxpExtns";
 const char* NXPLOG_ITEM_NCIHAL = "NxpHal";
 const char* NXPLOG_ITEM_NCIX = "NxpNciX";
 const char* NXPLOG_ITEM_NCIR = "NxpNciR";
+const char* NXPAVCLOG_ITEM_NCIX = "NxpAvcNciX";
+const char* NXPAVCLOG_ITEM_NCIR = "NxpAvcNciR";
 const char* NXPLOG_ITEM_FWDNLD = "NxpFwDnld";
 const char* NXPLOG_ITEM_TML = "NxpTml";
 const char* NXPLOG_ITEM_ONEBIN = "NxpOneBinary";
@@ -85,7 +87,6 @@ static void phNxpLog_SetHALLogLevel(uint8_t level) {
   if (GetNxpNumValue(NAME_NXPLOG_NCIHAL_LOGLEVEL, &num, sizeof(num))) {
     gLog_level.hal_log_level =
         (level > (unsigned char)num) ? level : (unsigned char)num;
-    ;
   }
 
   len = property_get(PROP_NAME_NXPLOG_NCIHAL_LOGLEVEL, valueStr, "");
@@ -96,6 +97,26 @@ static void phNxpLog_SetHALLogLevel(uint8_t level) {
   }
 }
 
+/*******************************************************************************
+ *
+ * Function         phNxpLog_SetAvcLogLevel
+ *
+ * Description      Sets the Android Vendor GID OID log level.
+ *
+ * Returns          void
+ *
+ ******************************************************************************/
+static void phNxpLog_SetAvcLogLevel(uint8_t level) {
+  unsigned long num = 0;
+  int len;
+  char valueStr[PROPERTY_VALUE_MAX] = {0};
+
+  if (GetNxpNumValue(NAME_NXPLOG_AVCNCI_LOGLEVEL, &num, sizeof(num))) {
+    gLog_level.avc_log_level =
+        (level > (unsigned char)num) ? level : (unsigned char)num;
+  }
+}
+
 /*******************************************************************************
  *
  * Function         phNxpLog_SetExtnsLogLevel
@@ -247,6 +268,7 @@ static void phNxpLog_SetNciTxLogLevel(uint8_t level) {
 void phNxpLog_InitializeLogLevel(void) {
   uint8_t level = phNxpLog_SetGlobalLogLevel();
   phNxpLog_SetHALLogLevel(level);
+  phNxpLog_SetAvcLogLevel(level);
   phNxpLog_SetExtnsLogLevel(level);
   phNxpLog_SetTmlLogLevel(level);
   phNxpLog_SetDnldLogLevel(level);
@@ -255,11 +277,11 @@ void phNxpLog_InitializeLogLevel(void) {
   ALOGD_IF(nfc_debug_enabled,
            "%s: global =%u, Fwdnld =%u, extns =%u, \
                 hal =%u, tml =%u, ncir =%u, \
-                ncix =%u",
+                ncix =%u, avc = %u",
            __func__, gLog_level.global_log_level, gLog_level.dnld_log_level,
            gLog_level.extns_log_level, gLog_level.hal_log_level,
            gLog_level.tml_log_level, gLog_level.ncir_log_level,
-           gLog_level.ncix_log_level);
+           gLog_level.ncix_log_level, gLog_level.avc_log_level);
 }
 /******************************************************************************
  * Function         phNxpLog_EnableDisableLogLevel
diff --git a/snxxx/halimpl/log/phNxpLog.h b/snxxx/halimpl/log/phNxpLog.h
index 26f4670..7438d4c 100644
--- a/snxxx/halimpl/log/phNxpLog.h
+++ b/snxxx/halimpl/log/phNxpLog.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2010-2014, 2022-2023 NXP
+ * Copyright 2010-2014, 2022-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -23,6 +23,7 @@ typedef struct nci_log_level {
   uint8_t global_log_level;
   uint8_t extns_log_level;
   uint8_t hal_log_level;
+  uint8_t avc_log_level;
   uint8_t dnld_log_level;
   uint8_t tml_log_level;
   uint8_t ncix_log_level;
@@ -47,6 +48,7 @@ extern bool nfc_debug_enabled;
  * ########################## */
 #define NAME_NXPLOG_EXTNS_LOGLEVEL "NXPLOG_EXTNS_LOGLEVEL"
 #define NAME_NXPLOG_NCIHAL_LOGLEVEL "NXPLOG_NCIHAL_LOGLEVEL"
+#define NAME_NXPLOG_AVCNCI_LOGLEVEL "NXPLOG_AVCNCI_LOGLEVEL"
 #define NAME_NXPLOG_NCIX_LOGLEVEL "NXPLOG_NCIX_LOGLEVEL"
 #define NAME_NXPLOG_NCIR_LOGLEVEL "NXPLOG_NCIR_LOGLEVEL"
 #define NAME_NXPLOG_FWDNLD_LOGLEVEL "NXPLOG_FWDNLD_LOGLEVEL"
@@ -87,6 +89,8 @@ extern const char* NXPLOG_ITEM_EXTNS;  /* Android logging tag for NxpExtns  */
 extern const char* NXPLOG_ITEM_NCIHAL; /* Android logging tag for NxpNciHal */
 extern const char* NXPLOG_ITEM_NCIX;   /* Android logging tag for NxpNciX   */
 extern const char* NXPLOG_ITEM_NCIR;   /* Android logging tag for NxpNciR   */
+extern const char* NXPAVCLOG_ITEM_NCIX; /* Android logging tag for NxpAvcNciX */
+extern const char* NXPAVCLOG_ITEM_NCIR; /* Android logging tag for NxpAvcNciR */
 extern const char* NXPLOG_ITEM_FWDNLD; /* Android logging tag for NxpFwDnld */
 extern const char* NXPLOG_ITEM_TML;    /* Android logging tag for NxpTml    */
 
@@ -238,6 +242,30 @@ extern const char* NXPLOG_ITEM_HCPR; /* Android logging tag for NxpHcpR   */
 #define NXPLOG_NCIR_E(...)
 #endif /* Logging APIs used by NCIR module */
 
+/* Logging APIs used by NxpAvcNciX module */
+#if (ENABLE_NCIX_TRACES == TRUE)
+#define NXPAVCLOG_NCIX_I(...)                                      \
+  {                                                                \
+    if ((nfc_debug_enabled) ||                                     \
+        (gLog_level.avc_log_level >= NXPLOG_LOG_INFO_LOGLEVEL))    \
+      LOG_PRI(ANDROID_LOG_INFO, NXPAVCLOG_ITEM_NCIX, __VA_ARGS__); \
+  }
+#else
+#define NXPAVCLOG_NCIX_I(...)
+#endif /* Logging APIs used by AVC Command module */
+
+/* Logging APIs used by NxpAVCNciR module */
+#if (ENABLE_NCIR_TRACES == TRUE)
+#define NXPAVCLOG_NCIR_I(...)                                      \
+  {                                                                \
+    if ((nfc_debug_enabled) ||                                     \
+        (gLog_level.avc_log_level >= NXPLOG_LOG_INFO_LOGLEVEL))    \
+      LOG_PRI(ANDROID_LOG_INFO, NXPAVCLOG_ITEM_NCIR, __VA_ARGS__); \
+  }
+#else
+#define NXPAVCLOG_NCIR_I(...)
+#endif /* Logging APIs used by AVC R module */
+
 /* Logging APIs used by NxpFwDnld module */
 #if (ENABLE_FWDNLD_TRACES == TRUE)
 #define NXPLOG_FWDNLD_D(...)                                       \
diff --git a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
index 4b217d5..13235ba 100644
--- a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
+++ b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
@@ -108,8 +108,8 @@ void NciDiscoveryCommandBuilder::removeListenParams() {
  *
  ****************************************************************************/
 void NciDiscoveryCommandBuilder::addObserveModeParams() {
-  mRfDiscoverConfiguration.push_back(
-      DiscoveryConfiguration(OBSERVE_MODE, OBSERVE_MODE_DISCOVERY_CYCLE));
+  mRfDiscoverConfiguration.push_back(DiscoveryConfiguration(
+      OBSERVE_MODE_RF_TECH_AND_MODE, OBSERVE_MODE_DISCOVERY_CYCLE));
 }
 
 /*****************************************************************************
diff --git a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc
index 7558ba6..bbbf18e 100644
--- a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc
+++ b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc
@@ -118,22 +118,60 @@ vector<uint8_t> ReaderPollConfigParser::parseCmaEvent(vector<uint8_t> p_event) {
   vector<uint8_t> event_data = vector<uint8_t>();
   if (lastKnownModEvent == EVENT_MOD_B && p_event.size() > 0 &&
       p_event[0] == TYPE_B_APF) {  // Type B Apf value is 0x05
-    event_data =
-        getWellKnownModEventData(TYPE_MOD_B, std::move(unknownEventTimeStamp),
-                                 lastKnownGain, std::move(p_event));
+    if (this->notificationType != TYPE_ONLY_MOD_EVENTS) {
+      event_data =
+          getWellKnownModEventData(TYPE_MOD_B, std::move(unknownEventTimeStamp),
+                                   lastKnownGain, std::move(p_event));
+    }
   } else if (lastKnownModEvent == EVENT_MOD_F &&
              p_event[0] == TYPE_F_CMD_LENGH && p_event[2] == TYPE_F_ID &&
              p_event[3] == TYPE_F_ID) {
-    event_data =
-        getWellKnownModEventData(TYPE_MOD_F, std::move(unknownEventTimeStamp),
-                                 lastKnownGain, std::move(p_event));
+    if (this->notificationType != TYPE_ONLY_MOD_EVENTS) {
+      event_data =
+          getWellKnownModEventData(TYPE_MOD_F, std::move(unknownEventTimeStamp),
+                                   lastKnownGain, std::move(p_event));
+    }
   } else {
-    event_data = getUnknownEvent(
-        std::move(p_event), std::move(unknownEventTimeStamp), lastKnownGain);
+    bool invalidData = std::all_of(p_event.begin(), p_event.end(),
+                                   [](int i) { return i == 0; });
+    if (!invalidData) {
+      event_data = getUnknownEvent(
+          std::move(p_event), std::move(unknownEventTimeStamp), lastKnownGain);
+    }
   }
   return event_data;
 }
 
+/*****************************************************************************
+ *
+ * Function         getTimestampInMicroSeconds
+ *
+ * Description      Function to convert Timestamp in microseconds and gives it
+ *                  in Big endian format
+ *
+ * Parameters       rawFrame
+ *
+ * Returns          vector<uint8_t>
+ *
+ ****************************************************************************/
+vector<uint8_t> ReaderPollConfigParser::getTimestampInMicroSeconds(
+    vector<uint8_t> rawFrame) {
+  if (rawFrame.size() < 4) {
+    return vector<uint8_t>{0x00, 0x00, 0x00, 0x00};
+  }
+  uint32_t timeStampInMicroSeconds =
+      ((rawFrame.at(1) << 8) + rawFrame.at(0)) * 1000 +
+      ((rawFrame.at(3) << 8) + rawFrame.at(2));
+
+  vector<uint8_t> timeStamp;
+  timeStamp.push_back((timeStampInMicroSeconds >> 24) & 0xFF);
+  timeStamp.push_back((timeStampInMicroSeconds >> 16) & 0xFF);
+  timeStamp.push_back((timeStampInMicroSeconds >> 8) & 0xFF);
+  timeStamp.push_back((timeStampInMicroSeconds) & 0xFF);
+
+  return timeStamp;
+}
+
 /*****************************************************************************
  *
  * Function         getEvent
@@ -161,12 +199,9 @@ vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
 
   if (cmaEventType == L2_EVT_TAG) {
     // Timestamp should be in Big Endian format
-    int idx = 3;
-    vector<uint8_t> timestamp;
-    timestamp.push_back(p_event[idx--]);
-    timestamp.push_back(p_event[idx--]);
-    timestamp.push_back(p_event[idx--]);
-    timestamp.push_back(p_event[idx]);
+
+    vector<uint8_t> timestamp = getTimestampInMicroSeconds(p_event);
+
     lastKnownGain = p_event[INDEX_OF_L2_EVT_GAIN];
     switch (p_event[INDEX_OF_L2_EVT_TYPE] & LX_TYPE_MASK) {
       // Trigger Type
@@ -175,27 +210,30 @@ vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
         switch ((p_event[INDEX_OF_L2_EVT_TYPE] & LX_EVENT_MASK) >> 4) {
           case EVENT_MOD_A:
             lastKnownModEvent = EVENT_MOD_A;
-            event_data = getWellKnownModEventData(
-                TYPE_MOD_A, std::move(timestamp), lastKnownGain);
+            if (this->notificationType != TYPE_ONLY_CMA_EVENTS) {
+              event_data = getWellKnownModEventData(
+                  TYPE_MOD_A, std::move(timestamp), lastKnownGain);
+            }
             break;
 
           case EVENT_MOD_B:
             lastKnownModEvent = EVENT_MOD_B;
-            event_data = getWellKnownModEventData(
-                TYPE_MOD_B, std::move(timestamp), lastKnownGain);
+            if (this->notificationType != TYPE_ONLY_CMA_EVENTS) {
+              event_data = getWellKnownModEventData(
+                  TYPE_MOD_B, std::move(timestamp), lastKnownGain);
+            }
             break;
 
           case EVENT_MOD_F:
             lastKnownModEvent = EVENT_MOD_F;
-            event_data = getWellKnownModEventData(
-                TYPE_MOD_F, std::move(timestamp), lastKnownGain);
+            if (this->notificationType != TYPE_ONLY_CMA_EVENTS) {
+              event_data = getWellKnownModEventData(
+                  TYPE_MOD_F, std::move(timestamp), lastKnownGain);
+            }
             break;
 
           default:
-            event_data = getUnknownEvent(
-                vector<uint8_t>(p_event.begin() + INDEX_OF_L2_EVT_TYPE,
-                                p_event.end()),
-                std::move(timestamp), lastKnownGain);
+            break;
         }
         break;
 
@@ -209,39 +247,31 @@ vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
         break;
 
       default:
-        event_data = getUnknownEvent(
-            vector<uint8_t>(p_event.begin() + INDEX_OF_L2_EVT_TYPE,
-                            p_event.end()),
-            std::move(timestamp), lastKnownGain);
         break;
     }
 
   } else if (cmaEventType == CMA_EVT_TAG) {
     // Timestamp should be in Big Endian format
-    int idx = 3;
-    vector<uint8_t> timestamp;
-    timestamp.push_back(p_event[idx--]);
-    timestamp.push_back(p_event[idx--]);
-    timestamp.push_back(p_event[idx--]);
-    timestamp.push_back(p_event[idx]);
+    vector<uint8_t> timestamp = getTimestampInMicroSeconds(p_event);
     switch (p_event[INDEX_OF_CMA_EVT_TYPE]) {
       // Trigger Type
       case CMA_EVENT_TRIGGER_TYPE:
         switch (p_event[INDEX_OF_CMA_EVT_DATA]) {
           case REQ_A:
-            event_data = getWellKnownModEventData(
-                TYPE_MOD_A, std::move(timestamp), lastKnownGain, {REQ_A});
+            if (this->notificationType != TYPE_ONLY_MOD_EVENTS) {
+              event_data = getWellKnownModEventData(
+                  TYPE_MOD_A, std::move(timestamp), lastKnownGain, {REQ_A});
+            }
             break;
 
           case WUP_A:
-            event_data = getWellKnownModEventData(
-                TYPE_MOD_A, std::move(timestamp), lastKnownGain, {WUP_A});
+            if (this->notificationType != TYPE_ONLY_MOD_EVENTS) {
+              event_data = getWellKnownModEventData(
+                  TYPE_MOD_A, std::move(timestamp), lastKnownGain, {WUP_A});
+            }
             break;
           default:
-            event_data = getUnknownEvent(
-                vector<uint8_t>(p_event.begin() + INDEX_OF_CMA_EVT_DATA,
-                                p_event.end()),
-                std::move(timestamp), lastKnownGain);
+            break;
         }
         break;
       case CMA_DATA_TRIGGER_TYPE: {
@@ -250,12 +280,8 @@ vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
         unknownEventTimeStamp = timestamp;
         break;
       }
-      default: {
-        vector<uint8_t> payloadData = vector<uint8_t>(
-            p_event.begin() + INDEX_OF_CMA_EVT_TYPE, p_event.end());
-        event_data = getUnknownEvent(std::move(payloadData),
-                                     std::move(timestamp), lastKnownGain);
-      }
+      default:
+        break;
     }
   } else if (cmaEventType == CMA_EVT_EXTRA_DATA_TAG &&
              readExtraBytesForUnknownEvent) {
@@ -417,3 +443,19 @@ void ReaderPollConfigParser::resetExtraBytesInfo() {
   extraBytes = vector<uint8_t>();
   unknownEventTimeStamp = vector<uint8_t>();
 }
+
+/*****************************************************************************
+ *
+ * Function         setNotificationType
+ *
+ * Description      Function to select the Notification type for Observe mode
+ *                  By default all type of notification enabled if not set
+ *
+ * Parameters       None
+ *
+ * Returns          void
+ *
+ ****************************************************************************/
+void ReaderPollConfigParser::setNotificationType(uint8_t notificationType) {
+  this->notificationType = notificationType;
+}
diff --git a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h
index 75e4538..87966fc 100644
--- a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h
+++ b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h
@@ -136,6 +136,7 @@ class ReaderPollConfigParser {
  public:
   bool readExtraBytesForUnknownEvent = false;
   uint8_t extraByteLength = 0;
+  uint8_t notificationType = 0;
   vector<uint8_t> unknownEventTimeStamp;
   vector<uint8_t> extraBytes = vector<uint8_t>();
   /*****************************************************************************
@@ -194,4 +195,32 @@ class ReaderPollConfigParser {
    *
    ****************************************************************************/
   void resetExtraBytesInfo();
+
+  /*****************************************************************************
+   *
+   * Function         setNotificationType
+   *
+   * Description      Function to select the Notification type for Observe mode
+   *                  By default all type of notification enabled if not set
+   *
+   * Parameters       None
+   *
+   * Returns          void
+   *
+   ****************************************************************************/
+  void setNotificationType(uint8_t notificationType);
+
+  /*****************************************************************************
+   *
+   * Function         getTimestampInMicroSeconds
+   *
+   * Description      Function to convert Timestamp in microseconds and gives it
+   *                  in Big endian format
+   *
+   * Parameters       rawFrame
+   *
+   * Returns          vector<uint8_t>
+   *
+   ****************************************************************************/
+  vector<uint8_t> getTimestampInMicroSeconds(vector<uint8_t> rawFrame);
 };
diff --git a/snxxx/halimpl/utils/phNxpConfig.h b/snxxx/halimpl/utils/phNxpConfig.h
index 7a2d630..31fa2a5 100644
--- a/snxxx/halimpl/utils/phNxpConfig.h
+++ b/snxxx/halimpl/utils/phNxpConfig.h
@@ -177,6 +177,8 @@ extern char Fw_Lib_Path[256];
 #define NAME_NXP_PROP_CE_ACTION_NTF "NXP_PROP_CE_ACTION_NTF"
 #define NAME_NXP_AGC_DEBUG_ENABLE "NXP_AGC_DEBUG_ENABLE"
 #define NAME_NXP_EXTENDED_FIELD_DETECT_MODE "NXP_EXTENDED_FIELD_DETECT_MODE"
+#define NAME_NXP_OBSERVE_MODE_REQ_NOTIFICATION_TYPE \
+  "NXP_OBSERVE_MODE_REQ_NOTIFICATION_TYPE"
 #define NAME_NXP_MIFARE_NACK_TO_RATS_ENABLE "NXP_MIFARE_NACK_TO_RATS_ENABLE"
 #define NAME_CONF_GPIO_CONTROL "CONF_GPIO_CONTROL"
 #define NAME_NXP_DEFAULT_ULPDET_MODE "NXP_DEFAULT_ULPDET_MODE"
@@ -189,4 +191,6 @@ extern char Fw_Lib_Path[256];
 #define NAME_NXP_AUTH_TIMEOUT_CFG "NXP_AUTH_TIMEOUT_CFG"
 #define NAME_NXP_REMOVAL_DETECTION_TIMEOUT "NXP_REMOVAL_DETECTION_TIMEOUT"
 #define NAME_NXP_4K_FWDNLD_SUPPORT "NXP_4K_FWDNLD_SUPPORT"
+#define NAME_NXP_CE_SUPPORT_IN_NFC_OFF_PHONE_OFF \
+  "NXP_CE_SUPPORT_IN_NFC_OFF_PHONE_OFF"
 #endif
diff --git a/snxxx/halimpl/utils/phNxpNciHal_utils.cc b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
index 3f6c7b3..54d3757 100644
--- a/snxxx/halimpl/utils/phNxpNciHal_utils.cc
+++ b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
@@ -1,6 +1,6 @@
 /*
  *
- *  Copyright 2013-2023 NXP
+ *  Copyright 2013-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -431,7 +431,7 @@ void phNxpNciHal_releaseall_cb_data(void) {
 **
 *******************************************************************************/
 void phNxpNciHal_print_packet(const char* pString, const uint8_t* p_data,
-                              uint16_t len) {
+                              uint16_t len, bool isNxpAvcNciPrint) {
   tNFC_printType printType = getPrintType(pString);
   if (printType == PRINT_UNKNOWN) return;  // logging is disabled
   uint32_t i;
@@ -441,12 +441,22 @@ void phNxpNciHal_print_packet(const char* pString, const uint8_t* p_data,
       snprintf(&print_buffer[i * 2], 3, "%02X", p_data[i]);
     }
     switch (printType) {
-      case PRINT_SEND:
-        NXPLOG_NCIX_I("len = %3d > %s", len, print_buffer);
+      case PRINT_SEND: {
+        if (isNxpAvcNciPrint) {
+          NXPAVCLOG_NCIX_I("len = %3d > %s", len, print_buffer);
+        } else {
+          NXPLOG_NCIX_I("len = %3d > %s", len, print_buffer);
+        }
         break;
-      case PRINT_RECV:
-        NXPLOG_NCIR_I("len = %3d > %s", len, print_buffer);
+      }
+      case PRINT_RECV: {
+        if (isNxpAvcNciPrint) {
+          NXPAVCLOG_NCIR_I("len = %3d > %s", len, print_buffer);
+        } else {
+          NXPLOG_NCIR_I("len = %3d > %s", len, print_buffer);
+        }
         break;
+      }
       case PRINT_DEBUG:
         NXPLOG_NCIHAL_D(" Debug Info > len = %3d > %s", len, print_buffer);
         break;
diff --git a/snxxx/halimpl/utils/phNxpNciHal_utils.h b/snxxx/halimpl/utils/phNxpNciHal_utils.h
index e7d42ef..4dcf725 100644
--- a/snxxx/halimpl/utils/phNxpNciHal_utils.h
+++ b/snxxx/halimpl/utils/phNxpNciHal_utils.h
@@ -1,6 +1,6 @@
 /*
  *
- *  Copyright (C) 2013-2018, 2021-2022 NXP
+ *  Copyright (C) 2013-2018, 2021-2022, 2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -97,7 +97,7 @@ NFCSTATUS phNxpNciHal_init_cb_data(phNxpNciHal_Sem_t* pCallbackData,
 void phNxpNciHal_cleanup_cb_data(phNxpNciHal_Sem_t* pCallbackData);
 void phNxpNciHal_releaseall_cb_data(void);
 void phNxpNciHal_print_packet(const char* pString, const uint8_t* p_data,
-                              uint16_t len);
+                              uint16_t len, bool isNxpAvcNciPrint = false);
 void phNxpNciHal_emergency_recovery(uint8_t status);
 tNFC_printType getPrintType(const char* pString);
 
```

