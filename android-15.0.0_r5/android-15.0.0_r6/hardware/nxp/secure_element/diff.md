```diff
diff --git a/snxxx/1.1/NxpEseService.cpp b/snxxx/1.1/NxpEseService.cpp
old mode 100755
new mode 100644
diff --git a/snxxx/1.1/SecureElement.h b/snxxx/1.1/SecureElement.h
old mode 100755
new mode 100644
diff --git a/snxxx/1.1/VirtualISO.h b/snxxx/1.1/VirtualISO.h
old mode 100755
new mode 100644
diff --git a/snxxx/1.2/Android.bp b/snxxx/1.2/Android.bp
index aedd554..919797c 100644
--- a/snxxx/1.2/Android.bp
+++ b/snxxx/1.2/Android.bp
@@ -41,7 +41,7 @@ cc_binary {
         "android.hardware.secure_element@1.0",
         "android.hardware.secure_element@1.1",
         "android.hardware.secure_element@1.2",
-        "ese_spi_nxp_snxxx",
+        "ese_teq1_nxp_snxxx",
         "libbase",
         "libbinder",
         "libbinder_ndk",
@@ -64,15 +64,15 @@ cc_binary {
 
     include_dirs: [
         "hardware/nxp/secure_element/snxxx/extns/impl",
-        "hardware/nxp/secure_element/snxxx/libese-spi/common/include",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/common",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/inc",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/lib",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/pal",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/pal/spi",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/utils",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/spm",
-        "hardware/nxp/secure_element/snxxx/libese-spi/src/include",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/common/include",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/common",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/inc",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/lib",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/pal",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/pal/spi",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/utils",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/spm",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/src/include",
         "hardware/nxp/secure_element/snxxx/ese-clients/inc",
         "hardware/nxp/secure_element/snxxx/OsuHal/inc",
     ],
diff --git a/snxxx/1.2/NxpEseService.cpp b/snxxx/1.2/NxpEseService.cpp
old mode 100755
new mode 100644
diff --git a/snxxx/1.2/android.hardware.secure_element_snxxx@1.2-service.rc b/snxxx/1.2/android.hardware.secure_element_snxxx@1.2-service.rc
index 3625cce..1ae9978 100755
--- a/snxxx/1.2/android.hardware.secure_element_snxxx@1.2-service.rc
+++ b/snxxx/1.2/android.hardware.secure_element_snxxx@1.2-service.rc
@@ -1,4 +1,4 @@
 service vendor.secure_element_hal_service /vendor/bin/hw/android.hardware.secure_element_snxxx@1.2-service
-    class hal
+    class early_hal
     user secure_element
     group secure_element
diff --git a/snxxx/Android.bp b/snxxx/Android.bp
old mode 100755
new mode 100644
index 17877d0..09ec862
--- a/snxxx/Android.bp
+++ b/snxxx/Android.bp
@@ -23,15 +23,17 @@ package {
 }
 
 subdirs = [
-    "aidl","1.2",
+    "aidl",
+    "1.2",
 ]
 filegroup {
     name: "OsuHalCommonFile",
     srcs: ["OsuHal/src/OsuHalExtn.cpp"],
 }
+
 filegroup {
     name: "ExtnsFile",
-     srcs: [
-         "extns/impl/NxpEse.cpp",
+    srcs: [
+        "extns/impl/NxpEse.cpp",
     ],
 }
diff --git a/snxxx/aidl/Android.bp b/snxxx/aidl/Android.bp
index 61eca51..fa1c5ca 100644
--- a/snxxx/aidl/Android.bp
+++ b/snxxx/aidl/Android.bp
@@ -45,7 +45,7 @@ cc_binary {
         "liblog",
         "libmemunreachable",
         "libutils",
-        "ese_spi_nxp_snxxx",
+        "ese_teq1_nxp_snxxx",
         "nfc_nci_nxp_snxxx",
         "android.hardware.nfc@1.2",
         "android.hardware.nfc-V1-ndk",
@@ -54,15 +54,15 @@ cc_binary {
 
     include_dirs: [
         "hardware/nxp/secure_element/snxxx/extns/impl",
-        "hardware/nxp/secure_element/snxxx/libese-spi/common/include",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/common",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/inc",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/lib",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/pal",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/pal/spi",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/utils",
-        "hardware/nxp/secure_element/snxxx/libese-spi/p73/spm",
-        "hardware/nxp/secure_element/snxxx/libese-spi/src/include",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/common/include",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/common",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/inc",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/lib",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/pal",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/pal/spi",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/utils",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/nxp-ese/spm",
+        "hardware/nxp/secure_element/snxxx/libese-teq1/src/include",
         "hardware/nxp/secure_element/snxxx/OsuHal/inc",
         "hardware/nxp/secure_element/snxxx/ese-clients/inc",
         "hardware/nxp/nfc/snxxx/halimpl/common",
diff --git a/snxxx/aidl/NxpEseService.cpp b/snxxx/aidl/NxpEseService.cpp
index d8e868b..780100a 100644
--- a/snxxx/aidl/NxpEseService.cpp
+++ b/snxxx/aidl/NxpEseService.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2023 NXP
+ *  Copyright 2023-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -76,11 +76,11 @@ int main() {
   bool ret = false;
 
   ALOGI("Secure Element AIDL HAL Service starting up");
-  if (!ABinderProcess_setThreadPoolMaxThreadCount(1)) {
+  if (!ABinderProcess_setThreadPoolMaxThreadCount(0)) {
     ALOGE("failed to set thread pool max thread count");
     return EXIT_FAILURE;
   }
-
+  ABinderProcess_startThreadPool();
   waitForNFCHAL();
   ALOGI("Secure Element AIDL HAL Service starting up");
   std::shared_ptr<SecureElement> se_service =
@@ -137,4 +137,4 @@ shutdown:
   // In normal operation, we don't expect the thread pool to exit
   ALOGE("Secure Element Service is shutting down");
   return EXIT_FAILURE;
-}
\ No newline at end of file
+}
diff --git a/snxxx/aidl/SecureElement.cpp b/snxxx/aidl/SecureElement.cpp
index 432a2ef..4ad9388 100644
--- a/snxxx/aidl/SecureElement.cpp
+++ b/snxxx/aidl/SecureElement.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2023 NXP
+ *  Copyright 2023-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -36,6 +36,8 @@ namespace secure_element {
 #define SW1_BYTES_REMAINING 0x61
 #define NUM_OF_CH4 0x04
 #define NUM_OF_CH5 0x05
+#define AID_SECURE_ELEMENT 1068
+#define AID_ROOT 0
 
 typedef struct gsTransceiveBuffer {
   phNxpEse_data cmdData;
@@ -48,6 +50,7 @@ static int getResponseInternal(uint8_t cla, phNxpEse_7816_rpdu_t& rpdu,
 static sTransceiveBuffer_t gsTxRxBuffer;
 static std::vector<uint8_t> gsRspDataBuff(256);
 std::shared_ptr<ISecureElementCallback> SecureElement::mCb = nullptr;
+uid_t SecureElement::mCbClientUid = 0;
 AIBinder_DeathRecipient* clientDeathRecipient = nullptr;
 std::vector<bool> SecureElement::mOpenedChannels;
 static const std::vector<std::vector<uint8_t>> kWeaverAIDs = {
@@ -65,7 +68,10 @@ static bool isWeaverApplet(std::vector<uint8_t> aid) {
 }
 
 SecureElement::SecureElement()
-    : mMaxChannelCount(0), mOpenedchannelCount(0), mIsEseInitialized(false) {}
+    : mMaxChannelCount(0),
+      mOpenedchannelCount(0),
+      mIsEseInitialized(false),
+      isOmapi(false) {}
 
 void SecureElement::updateSeHalInitState(bool mstate) {
   mIsEseInitialized = mstate;
@@ -78,6 +84,7 @@ void OnDeath(void* cookie) {
   if (se->seHalDeInit() != SESTATUS_SUCCESS) {
     LOG(ERROR) << "SE Deinit not successful";
   }
+  se->handleStateOnDeath();
 }
 
 void SecureElement::NotifySeWaitExtension(phNxpEse_wtxState state) {
@@ -94,8 +101,14 @@ ScopedAStatus SecureElement::init(
   if (!clientCallback) {
     return ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
   }
-
+  uid_t clientUid = AIBinder_getCallingUid();
+  // Allow VTS tests even if omapi acquires the lock.
+  if (!isClientVts(clientUid) && !handleClientCallback(clientCallback)) {
+    LOG(INFO) << __func__ << " client not allowed";
+    return ScopedAStatus::fromServiceSpecificError(IOERROR);
+  }
   mCb = clientCallback;
+  mCbClientUid = clientUid;
   ESESTATUS status = ESESTATUS_SUCCESS;
   bool mIsInitDone = false;
   phNxpEse_initParams initParams;
@@ -106,6 +119,7 @@ ScopedAStatus SecureElement::init(
   initParams.fPtr_WtxNtf = SecureElement::NotifySeWaitExtension;
 
   if (clientCallback == nullptr) {
+    handleClientCbCleanup();
     return ScopedAStatus::ok();
   } else {
     clientDeathRecipient = AIBinder_DeathRecipient_new(OnDeath);
@@ -162,6 +176,7 @@ ScopedAStatus SecureElement::init(
     mCb->onStateChange(true, "NXP SE HAL init ok");
   } else {
     LOG(ERROR) << "eSE-Hal Init failed";
+    handleClientCbCleanup();
     mCb->onStateChange(false, "NXP SE HAL init failed");
   }
   return ScopedAStatus::ok();
@@ -329,6 +344,7 @@ ScopedAStatus SecureElement::openLogicalChannel(
   if (aid.size() > MAX_AID_LENGTH) {
     LOG(ERROR) << "%s: AID out of range!!!" << __func__;
     *_aidl_return = resApduBuff;
+    handleClientCbCleanup();
     return ScopedAStatus::fromServiceSpecificError(FAILED);
   }
 
@@ -346,6 +362,7 @@ ScopedAStatus SecureElement::openLogicalChannel(
     ALOGE("%s: Reached Max supported(%d) Logical Channel", __func__,
           openedLogicalChannelCount);
     *_aidl_return = resApduBuff;
+    handleClientCbCleanup();
     return ScopedAStatus::fromServiceSpecificError(CHANNEL_NOT_AVAILABLE);
   }
 
@@ -356,12 +373,14 @@ ScopedAStatus SecureElement::openLogicalChannel(
       (IS_OSU_MODE(OsuHalExtn::getInstance().OPENLOGICAL))) {
     LOG(ERROR) << "%s: Not allowed in dedicated mode!!!" << __func__;
     *_aidl_return = resApduBuff;
+    handleClientCbCleanup();
     return ScopedAStatus::fromServiceSpecificError(IOERROR);
   }
   if (!mIsEseInitialized) {
     ESESTATUS status = seHalInit();
     if (status != ESESTATUS_SUCCESS) {
       LOG(ERROR) << "%s: seHalInit Failed!!!" << __func__;
+      handleClientCbCleanup();
       *_aidl_return = resApduBuff;
       return ScopedAStatus::fromServiceSpecificError(IOERROR);
     }
@@ -426,6 +445,7 @@ ScopedAStatus SecureElement::openLogicalChannel(
       LOG(ERROR) << "phNxpEse_ResetEndPoint_Cntxt failed!!!";
     }
     *_aidl_return = resApduBuff;
+    handleClientCbCleanup();
     return ScopedAStatus::fromServiceSpecificError(sestatus);
   }
   LOG(INFO) << "openLogicalChannel Sending selectApdu";
@@ -450,6 +470,7 @@ ScopedAStatus SecureElement::openLogicalChannel(
     ALOGE("%s: Invalid Channel no: %02x", __func__, resApduBuff.channelNumber);
     resApduBuff.channelNumber = 0xff;
     *_aidl_return = resApduBuff;
+    handleClientCbCleanup();
     return ScopedAStatus::fromServiceSpecificError(IOERROR);
   }
   cpdu.ins = 0xA4; /* Instruction code */
@@ -508,6 +529,7 @@ ScopedAStatus SecureElement::openLogicalChannel(
     }
   }
   if (sestatus != SESTATUS_SUCCESS) {
+    handleClientCbCleanup();
     int closeChannelStatus = internalCloseChannel(resApduBuff.channelNumber);
     if (closeChannelStatus != SESTATUS_SUCCESS) {
       LOG(ERROR) << "%s: closeChannel Failed" << __func__;
@@ -790,6 +812,7 @@ ScopedAStatus SecureElement::closeChannel(int8_t channelNumber) {
     }
     sestatus = SESTATUS_SUCCESS;
   }
+  handleClientCbCleanup();
   return sestatus == SESTATUS_SUCCESS
              ? ndk::ScopedAStatus::ok()
              : ndk::ScopedAStatus::fromServiceSpecificError(sestatus);
@@ -984,6 +1007,46 @@ uint8_t SecureElement::getMaxChannelCnt() {
   return cnt;
 }
 
+void SecureElement::handleStateOnDeath() {
+  if (!isClientVts(mCbClientUid)) {
+    seHalClientLock.unlock();
+  }
+}
+void SecureElement::handleClientCbCleanup() {
+  if (!isClientVts(mCbClientUid) && !isOmapi) {
+    seHalClientLock.unlock();
+  }
+}
+
+bool SecureElement::handleClientCallback(
+    const std::shared_ptr<ISecureElementCallback>& clientCallback) {
+  AutoMutex guard(initLock);
+  LOG(INFO) << "isOmapi : " << isOmapi;
+  uid_t currentClientUid = AIBinder_getCallingUid();
+  if (isOmapi && (currentClientUid != AID_SECURE_ELEMENT)) {
+    return false;
+  }
+  // Lock the mutex until the acquired client either closes the channel or
+  // killed.
+  seHalClientLock.lock();
+  // Check if the client exists before registering the callback.
+  if (!ndk::ScopedAStatus::fromStatus(
+           AIBinder_ping(clientCallback->asBinder().get()))
+           .isOk()) {
+    LOG(INFO) << "currentClientUid: " << currentClientUid
+              << "died, so release the mutex.";
+    seHalClientLock.unlock();
+    return false;
+  }
+  isOmapi = (currentClientUid == AID_SECURE_ELEMENT);
+
+  return true;
+}
+
+bool SecureElement::isClientVts(uid_t clientUid) {
+  return (AID_ROOT == clientUid);
+}
+
 }  // namespace secure_element
 }  // namespace hardware
 }  // namespace android
diff --git a/snxxx/aidl/SecureElement.h b/snxxx/aidl/SecureElement.h
index 98e8901..582266d 100644
--- a/snxxx/aidl/SecureElement.h
+++ b/snxxx/aidl/SecureElement.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2023 NXP
+ *  Copyright 2023-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -93,6 +93,7 @@ struct SecureElement : public BnSecureElement {
   static void NotifySeWaitExtension(phNxpEse_wtxState state);
   void updateSeHalInitState(bool);
   int seHalDeInit();
+  void handleStateOnDeath();
 
  private:
   uint8_t mMaxChannelCount;
@@ -100,17 +101,25 @@ struct SecureElement : public BnSecureElement {
   Mutex seHalLock;
   bool mIsEseInitialized = false;
   static std::vector<bool> mOpenedChannels;
+  Mutex seHalClientLock;
+  Mutex initLock;
 
   static std::shared_ptr<ISecureElementCallback> mCb;
+  static uid_t mCbClientUid;
   bool mHasPriorityAccess = false;
+  bool isOmapi;
 
   ESESTATUS seHalInit();
   int internalCloseChannel(uint8_t channelNumber);
   uint8_t getReserveChannelCnt(const std::vector<uint8_t>& aid);
   uint8_t getMaxChannelCnt();
+  bool isClientVts(uid_t clientUid);
+  void handleClientCbCleanup();
+  bool handleClientCallback(
+      const std::shared_ptr<ISecureElementCallback>& clientCallback);
 };
 
 }  // namespace secure_element
 }  // namespace hardware
 }  // namespace android
-}  // namespace aidl
\ No newline at end of file
+}  // namespace aidl
diff --git a/snxxx/aidl/VirtualISO.h b/snxxx/aidl/VirtualISO.h
index fc8140a..3b5360f 100644
--- a/snxxx/aidl/VirtualISO.h
+++ b/snxxx/aidl/VirtualISO.h
@@ -83,4 +83,4 @@ struct VirtualISO
 }  // namespace virtual_iso
 }  // namespace nxp
 }  // namespace vendor
-}  // namespace aidl
\ No newline at end of file
+}  // namespace aidl
diff --git a/snxxx/aidl/secure_element-service-nxp.rc b/snxxx/aidl/secure_element-service-nxp.rc
index 0a64d39..4e9cf1f 100644
--- a/snxxx/aidl/secure_element-service-nxp.rc
+++ b/snxxx/aidl/secure_element-service-nxp.rc
@@ -1,4 +1,4 @@
 service vendor.secure_element_hal_service /vendor/bin/hw/android.hardware.secure_element-service.nxp
-    class hal
+    class early_hal
     user secure_element
     group secure_element
diff --git a/snxxx/extns/impl/hal_nxpese.h b/snxxx/extns/impl/hal_nxpese.h
old mode 100755
new mode 100644
diff --git a/snxxx/libese-spi/Android.bp b/snxxx/libese-teq1/Android.bp
old mode 100755
new mode 100644
similarity index 68%
rename from snxxx/libese-spi/Android.bp
rename to snxxx/libese-teq1/Android.bp
index c45dd01..b221a8f
--- a/snxxx/libese-spi/Android.bp
+++ b/snxxx/libese-teq1/Android.bp
@@ -9,46 +9,46 @@ package {
 
 cc_library_shared {
 
-    name: "ese_spi_nxp_snxxx",
+    name: "ese_teq1_nxp_snxxx",
     defaults: ["hidl_defaults"],
     proprietary: true,
 
     srcs: [
-        "p73/lib/phNxpEseDataMgr.cpp",
-        "p73/lib/phNxpEseProto7816_3.cpp",
-        "p73/lib/phNxpEse_Apdu_Api.cpp",
-        "p73/lib/phNxpEse_Api.cpp",
-        "p73/pal/phNxpEsePal.cpp",
-        "p73/pal/EseTransportFactory.cpp",
-        "p73/pal/spi/EseSpiTransport.cpp",
-        "p73/pal/NxpTimer.cpp",
-        "p73/spm/phNxpEse_Spm.cpp",
-        "p73/utils/ese_config.cpp",
-        "p73/utils/config.cpp",
-        "p73/utils/ringbuffer.cpp",
+        "nxp-ese/lib/phNxpEseDataMgr.cpp",
+        "nxp-ese/lib/phNxpEseProto7816_3.cpp",
+        "nxp-ese/lib/phNxpEse_Apdu_Api.cpp",
+        "nxp-ese/lib/phNxpEse_Api.cpp",
+        "nxp-ese/pal/phNxpEsePal.cpp",
+        "nxp-ese/pal/EseTransportFactory.cpp",
+        "nxp-ese/pal/spi/EseSpiTransport.cpp",
+        "nxp-ese/pal/NxpTimer.cpp",
+        "nxp-ese/spm/phNxpEse_Spm.cpp",
+        "nxp-ese/utils/ese_config.cpp",
+        "nxp-ese/utils/config.cpp",
+        "nxp-ese/utils/ringbuffer.cpp",
         "src/adaptation/NfcAdaptation.cpp",
         "src/adaptation/CondVar.cpp",
         "src/adaptation/Mutex.cpp",
     ],
 
     local_include_dirs: [
-        "p73/lib",
-        "p73/pal/spi",
-        "p73/utils",
+        "nxp-ese/lib",
+        "nxp-ese/pal/spi",
+        "nxp-ese/utils",
     ],
     export_include_dirs: [
         "common/include",
-        "p73/common",
-        "p73/inc",
-        "p73/pal",
+        "nxp-ese/common",
+        "nxp-ese/inc",
+        "nxp-ese/pal",
         "src/include",
     ],
     include_dirs: [
         "hardware/nxp/nfc/snxxx/extns/impl/nxpnfc/aidl",
         "hardware/nxp/nfc/snxxx/extns/impl/nxpnfc/2.0",
         "hardware/nxp/secure_element/snxxx/extns/impl",
-        "hardware/nxp/secure_element/snxxx/ese-clients/inc"
-],
+        "hardware/nxp/secure_element/snxxx/ese-clients/inc",
+    ],
 
     cflags: [
         "-DANDROID",
@@ -76,7 +76,6 @@ cc_library_shared {
         "libbinder_ndk",
         "liblog",
         "libbase",
-        "libchrome",
         "vendor.nxp.nxpese@1.0",
         "vendor.nxp.nxpnfc@2.0",
         "vendor.nxp.nxpnfc_aidl-V1-ndk",
@@ -85,7 +84,7 @@ cc_library_shared {
     product_variables: {
         debuggable: {
             cflags: [
-                "-DDCHECK_ALWAYS_ON"
+                "-DDCHECK_ALWAYS_ON",
             ],
         },
     },
diff --git a/snxxx/libese-spi/common/include/phNxpEseFeatures.h b/snxxx/libese-teq1/common/include/phNxpEseFeatures.h
similarity index 100%
rename from snxxx/libese-spi/common/include/phNxpEseFeatures.h
rename to snxxx/libese-teq1/common/include/phNxpEseFeatures.h
diff --git a/snxxx/libese-spi/p73/common/phEseStatus.h b/snxxx/libese-teq1/nxp-ese/common/phEseStatus.h
similarity index 98%
rename from snxxx/libese-spi/p73/common/phEseStatus.h
rename to snxxx/libese-teq1/nxp-ese/common/phEseStatus.h
index 80db0b5..7dac337 100644
--- a/snxxx/libese-spi/p73/common/phEseStatus.h
+++ b/snxxx/libese-teq1/nxp-ese/common/phEseStatus.h
@@ -54,7 +54,7 @@
  * PHESESTATUS
  * Get grp_retval from Status Code
  */
-#define PHESESTATUS(phEseStatus) ((phEseStatus)&0x00FFU)
+#define PHESESTATUS(phEseStatus) ((phEseStatus) & 0x00FFU)
 
 /**
  * \ingroup ISO7816-3_protocol_lib_common
diff --git a/snxxx/libese-spi/p73/inc/phNxpEse_Apdu_Api.h b/snxxx/libese-teq1/nxp-ese/inc/phNxpEse_Apdu_Api.h
similarity index 100%
rename from snxxx/libese-spi/p73/inc/phNxpEse_Apdu_Api.h
rename to snxxx/libese-teq1/nxp-ese/inc/phNxpEse_Apdu_Api.h
diff --git a/snxxx/libese-spi/p73/inc/phNxpEse_Api.h b/snxxx/libese-teq1/nxp-ese/inc/phNxpEse_Api.h
similarity index 100%
rename from snxxx/libese-spi/p73/inc/phNxpEse_Api.h
rename to snxxx/libese-teq1/nxp-ese/inc/phNxpEse_Api.h
diff --git a/snxxx/libese-spi/p73/lib/phNxpEseDataMgr.cpp b/snxxx/libese-teq1/nxp-ese/lib/phNxpEseDataMgr.cpp
old mode 100755
new mode 100644
similarity index 100%
rename from snxxx/libese-spi/p73/lib/phNxpEseDataMgr.cpp
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEseDataMgr.cpp
diff --git a/snxxx/libese-spi/p73/lib/phNxpEseDataMgr.h b/snxxx/libese-teq1/nxp-ese/lib/phNxpEseDataMgr.h
similarity index 100%
rename from snxxx/libese-spi/p73/lib/phNxpEseDataMgr.h
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEseDataMgr.h
diff --git a/snxxx/libese-spi/p73/lib/phNxpEseProto7816_3.cpp b/snxxx/libese-teq1/nxp-ese/lib/phNxpEseProto7816_3.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/lib/phNxpEseProto7816_3.cpp
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEseProto7816_3.cpp
diff --git a/snxxx/libese-spi/p73/lib/phNxpEseProto7816_3.h b/snxxx/libese-teq1/nxp-ese/lib/phNxpEseProto7816_3.h
similarity index 100%
rename from snxxx/libese-spi/p73/lib/phNxpEseProto7816_3.h
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEseProto7816_3.h
diff --git a/snxxx/libese-spi/p73/lib/phNxpEse_Apdu_Api.cpp b/snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Apdu_Api.cpp
old mode 100755
new mode 100644
similarity index 100%
rename from snxxx/libese-spi/p73/lib/phNxpEse_Apdu_Api.cpp
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Apdu_Api.cpp
diff --git a/snxxx/libese-spi/p73/lib/phNxpEse_Api.cpp b/snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Api.cpp
similarity index 99%
rename from snxxx/libese-spi/p73/lib/phNxpEse_Api.cpp
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Api.cpp
index 7c0e254..bf6f664 100644
--- a/snxxx/libese-spi/p73/lib/phNxpEse_Api.cpp
+++ b/snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Api.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2018-2023 NXP
+ *  Copyright 2018-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -1111,8 +1111,7 @@ static int phNxpEse_readPacket(void* pDevHandle, uint8_t* pBuffer,
                       GET_WAKE_UP_DELAY() * CHAINED_PKT_SCALER);
         phPalEse_BusyWait(GET_WAKE_UP_DELAY() * CHAINED_PKT_SCALER);
       } else {
-        /*DLOG_IF(INFO, ese_log_level)
-         << StringPrintf("%s Normal Pkt, delay read %dus", __FUNCTION__,
+        /*NXP_LOG_ESE_D("%s Normal Pkt, delay read %dus", __FUNCTION__,
          WAKE_UP_DELAY_SN1xx * NAD_POLLING_SCALER_SN1xx);*/
         phPalEse_BusyWait(nxpese_ctxt.nadPollingRetryTime *
                           GET_WAKE_UP_DELAY() * NAD_POLLING_SCALER);
diff --git a/snxxx/libese-spi/p73/lib/phNxpEse_Internal.h b/snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Internal.h
similarity index 99%
rename from snxxx/libese-spi/p73/lib/phNxpEse_Internal.h
rename to snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Internal.h
index 83e5667..a5fb29f 100644
--- a/snxxx/libese-spi/p73/lib/phNxpEse_Internal.h
+++ b/snxxx/libese-teq1/nxp-ese/lib/phNxpEse_Internal.h
@@ -22,7 +22,7 @@
 
 /* Macro to enable SPM Module */
 #define SPM_INTEGRATED
-//#undef SPM_INTEGRATED
+// #undef SPM_INTEGRATED
 #ifdef SPM_INTEGRATED
 #include "../spm/phNxpEse_Spm.h"
 #endif
diff --git a/snxxx/libese-spi/p73/pal/EseTransport.h b/snxxx/libese-teq1/nxp-ese/pal/EseTransport.h
similarity index 100%
rename from snxxx/libese-spi/p73/pal/EseTransport.h
rename to snxxx/libese-teq1/nxp-ese/pal/EseTransport.h
diff --git a/snxxx/libese-spi/p73/pal/EseTransportFactory.cpp b/snxxx/libese-teq1/nxp-ese/pal/EseTransportFactory.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/pal/EseTransportFactory.cpp
rename to snxxx/libese-teq1/nxp-ese/pal/EseTransportFactory.cpp
diff --git a/snxxx/libese-spi/p73/pal/EseTransportFactory.h b/snxxx/libese-teq1/nxp-ese/pal/EseTransportFactory.h
similarity index 99%
rename from snxxx/libese-spi/p73/pal/EseTransportFactory.h
rename to snxxx/libese-teq1/nxp-ese/pal/EseTransportFactory.h
index 0a9a876..042bc05 100644
--- a/snxxx/libese-spi/p73/pal/EseTransportFactory.h
+++ b/snxxx/libese-teq1/nxp-ese/pal/EseTransportFactory.h
@@ -18,6 +18,7 @@
 
 #pragma once
 #include <EseTransport.h>
+
 #include <memory>
 
 #define transportFactory (EseTransportFactory::getInstance())
diff --git a/snxxx/libese-spi/p73/pal/NxpTimer.cpp b/snxxx/libese-teq1/nxp-ese/pal/NxpTimer.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/pal/NxpTimer.cpp
rename to snxxx/libese-teq1/nxp-ese/pal/NxpTimer.cpp
diff --git a/snxxx/libese-spi/p73/pal/NxpTimer.h b/snxxx/libese-teq1/nxp-ese/pal/NxpTimer.h
similarity index 100%
rename from snxxx/libese-spi/p73/pal/NxpTimer.h
rename to snxxx/libese-teq1/nxp-ese/pal/NxpTimer.h
diff --git a/snxxx/libese-spi/p73/pal/phNxpEsePal.cpp b/snxxx/libese-teq1/nxp-ese/pal/phNxpEsePal.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/pal/phNxpEsePal.cpp
rename to snxxx/libese-teq1/nxp-ese/pal/phNxpEsePal.cpp
diff --git a/snxxx/libese-spi/p73/pal/phNxpEsePal.h b/snxxx/libese-teq1/nxp-ese/pal/phNxpEsePal.h
similarity index 100%
rename from snxxx/libese-spi/p73/pal/phNxpEsePal.h
rename to snxxx/libese-teq1/nxp-ese/pal/phNxpEsePal.h
diff --git a/snxxx/libese-spi/p73/pal/spi/EseSpiTransport.cpp b/snxxx/libese-teq1/nxp-ese/pal/spi/EseSpiTransport.cpp
similarity index 99%
rename from snxxx/libese-spi/p73/pal/spi/EseSpiTransport.cpp
rename to snxxx/libese-teq1/nxp-ese/pal/spi/EseSpiTransport.cpp
index fa29656..22e451a 100644
--- a/snxxx/libese-spi/p73/pal/spi/EseSpiTransport.cpp
+++ b/snxxx/libese-teq1/nxp-ese/pal/spi/EseSpiTransport.cpp
@@ -395,8 +395,8 @@ ESESTATUS EseSpiTransport::Ioctl(phPalEse_ControlCode_t eControlCode,
       break;
     case phPalEse_e_ChipRst:
       if (GET_CHIP_OS_VERSION() != OS_VERSION_4_0) {
-        if (level == 5) {              // SPI driver communication part
-          if (!mConfigColdResetIntf) { // Call the driver IOCTL
+        if (level == 5) {               // SPI driver communication part
+          if (!mConfigColdResetIntf) {  // Call the driver IOCTL
             unsigned int cmd = ESE_PERFORM_COLD_RESET;
             if ((mConfigGpioReset == 0x01) &&
                 ((GET_CHIP_OS_VERSION() == OS_VERSION_8_9))) {
diff --git a/snxxx/libese-spi/p73/pal/spi/EseSpiTransport.h b/snxxx/libese-teq1/nxp-ese/pal/spi/EseSpiTransport.h
similarity index 100%
rename from snxxx/libese-spi/p73/pal/spi/EseSpiTransport.h
rename to snxxx/libese-teq1/nxp-ese/pal/spi/EseSpiTransport.h
diff --git a/snxxx/libese-spi/p73/spm/phNxpEse_Spm.cpp b/snxxx/libese-teq1/nxp-ese/spm/phNxpEse_Spm.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/spm/phNxpEse_Spm.cpp
rename to snxxx/libese-teq1/nxp-ese/spm/phNxpEse_Spm.cpp
diff --git a/snxxx/libese-spi/p73/spm/phNxpEse_Spm.h b/snxxx/libese-teq1/nxp-ese/spm/phNxpEse_Spm.h
similarity index 100%
rename from snxxx/libese-spi/p73/spm/phNxpEse_Spm.h
rename to snxxx/libese-teq1/nxp-ese/spm/phNxpEse_Spm.h
diff --git a/snxxx/libese-spi/p73/utils/config.cpp b/snxxx/libese-teq1/nxp-ese/utils/config.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/utils/config.cpp
rename to snxxx/libese-teq1/nxp-ese/utils/config.cpp
diff --git a/snxxx/libese-spi/p73/utils/config.h b/snxxx/libese-teq1/nxp-ese/utils/config.h
similarity index 100%
rename from snxxx/libese-spi/p73/utils/config.h
rename to snxxx/libese-teq1/nxp-ese/utils/config.h
diff --git a/snxxx/libese-spi/p73/utils/ese_config.cpp b/snxxx/libese-teq1/nxp-ese/utils/ese_config.cpp
similarity index 99%
rename from snxxx/libese-spi/p73/utils/ese_config.cpp
rename to snxxx/libese-teq1/nxp-ese/utils/ese_config.cpp
index e90db57..16b2e23 100644
--- a/snxxx/libese-spi/p73/utils/ese_config.cpp
+++ b/snxxx/libese-teq1/nxp-ese/utils/ese_config.cpp
@@ -22,7 +22,6 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/strings.h>
-
 #include <config.h>
 
 using namespace ::std;
diff --git a/snxxx/libese-spi/p73/utils/ese_config.h b/snxxx/libese-teq1/nxp-ese/utils/ese_config.h
similarity index 100%
rename from snxxx/libese-spi/p73/utils/ese_config.h
rename to snxxx/libese-teq1/nxp-ese/utils/ese_config.h
index e3d5c77..f26e129 100644
--- a/snxxx/libese-spi/p73/utils/ese_config.h
+++ b/snxxx/libese-teq1/nxp-ese/utils/ese_config.h
@@ -18,11 +18,11 @@
 
 #pragma once
 
+#include <config.h>
+
 #include <string>
 #include <vector>
 
-#include <config.h>
-
 #ifndef __CONFIG_H
 #define __CONFIG_H
 
diff --git a/snxxx/libese-spi/p73/utils/ese_logs.h b/snxxx/libese-teq1/nxp-ese/utils/ese_logs.h
similarity index 100%
rename from snxxx/libese-spi/p73/utils/ese_logs.h
rename to snxxx/libese-teq1/nxp-ese/utils/ese_logs.h
diff --git a/snxxx/libese-spi/p73/utils/ringbuffer.cpp b/snxxx/libese-teq1/nxp-ese/utils/ringbuffer.cpp
similarity index 100%
rename from snxxx/libese-spi/p73/utils/ringbuffer.cpp
rename to snxxx/libese-teq1/nxp-ese/utils/ringbuffer.cpp
diff --git a/snxxx/libese-spi/p73/utils/ringbuffer.h b/snxxx/libese-teq1/nxp-ese/utils/ringbuffer.h
similarity index 100%
rename from snxxx/libese-spi/p73/utils/ringbuffer.h
rename to snxxx/libese-teq1/nxp-ese/utils/ringbuffer.h
diff --git a/snxxx/libese-spi/src/adaptation/CondVar.cpp b/snxxx/libese-teq1/src/adaptation/CondVar.cpp
old mode 100755
new mode 100644
similarity index 83%
rename from snxxx/libese-spi/src/adaptation/CondVar.cpp
rename to snxxx/libese-teq1/src/adaptation/CondVar.cpp
index ad69973..a6309f2
--- a/snxxx/libese-spi/src/adaptation/CondVar.cpp
+++ b/snxxx/libese-teq1/src/adaptation/CondVar.cpp
@@ -14,18 +14,37 @@
  * limitations under the License.
  */
 
+/******************************************************************************
+ *
+ *  The original Work has been changed by NXP.
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
+ *  Copyright 2024 NXP
+ *
+ ******************************************************************************/
+
 /*
  *  Encapsulate a condition variable for thread synchronization.
  */
 
 #include "CondVar.h"
 
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
 #include <errno.h>
 #include <string.h>
 
-#include <android-base/stringprintf.h>
-#include <base/logging.h>
-
 using android::base::StringPrintf;
 
 /*******************************************************************************
diff --git a/snxxx/libese-spi/src/adaptation/Mutex.cpp b/snxxx/libese-teq1/src/adaptation/Mutex.cpp
old mode 100755
new mode 100644
similarity index 80%
rename from snxxx/libese-spi/src/adaptation/Mutex.cpp
rename to snxxx/libese-teq1/src/adaptation/Mutex.cpp
index ef4d5e5..33f9667
--- a/snxxx/libese-spi/src/adaptation/Mutex.cpp
+++ b/snxxx/libese-teq1/src/adaptation/Mutex.cpp
@@ -14,18 +14,37 @@
  * limitations under the License.
  */
 
+/******************************************************************************
+ *
+ *  The original Work has been changed by NXP.
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
+ *  Copyright 2024 NXP
+ *
+ ******************************************************************************/
+
 /*
  *  Encapsulate a mutex for thread synchronization.
  */
 
 #include "Mutex.h"
 
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
 #include <errno.h>
 #include <string.h>
 
-#include <android-base/stringprintf.h>
-#include <base/logging.h>
-
 using android::base::StringPrintf;
 
 /*******************************************************************************
diff --git a/snxxx/libese-spi/src/adaptation/NfcAdaptation.cpp b/snxxx/libese-teq1/src/adaptation/NfcAdaptation.cpp
similarity index 100%
rename from snxxx/libese-spi/src/adaptation/NfcAdaptation.cpp
rename to snxxx/libese-teq1/src/adaptation/NfcAdaptation.cpp
diff --git a/snxxx/libese-spi/src/include/CondVar.h b/snxxx/libese-teq1/src/include/CondVar.h
similarity index 99%
rename from snxxx/libese-spi/src/include/CondVar.h
rename to snxxx/libese-teq1/src/include/CondVar.h
index a2be51f..dfb0505 100644
--- a/snxxx/libese-spi/src/include/CondVar.h
+++ b/snxxx/libese-teq1/src/include/CondVar.h
@@ -20,6 +20,7 @@
 
 #pragma once
 #include <pthread.h>
+
 #include "Mutex.h"
 
 class CondVar {
diff --git a/snxxx/libese-spi/src/include/Mutex.h b/snxxx/libese-teq1/src/include/Mutex.h
similarity index 100%
rename from snxxx/libese-spi/src/include/Mutex.h
rename to snxxx/libese-teq1/src/include/Mutex.h
diff --git a/snxxx/libese-spi/src/include/NfcAdaptation.h b/snxxx/libese-teq1/src/include/NfcAdaptation.h
similarity index 100%
rename from snxxx/libese-spi/src/include/NfcAdaptation.h
rename to snxxx/libese-teq1/src/include/NfcAdaptation.h
diff --git a/snxxx/libese-spi/src/include/SyncEvent.h b/snxxx/libese-teq1/src/include/SyncEvent.h
similarity index 100%
rename from snxxx/libese-spi/src/include/SyncEvent.h
rename to snxxx/libese-teq1/src/include/SyncEvent.h
```

