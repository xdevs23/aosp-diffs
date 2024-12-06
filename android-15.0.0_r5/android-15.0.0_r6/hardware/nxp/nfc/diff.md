```diff
diff --git a/OWNERS b/OWNERS
index 45e7662..f46dccd 100755
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,2 @@
-zachoverflow@google.com
-jackcwyu@google.com
-georgekgchang@google.com
-alisher@google.com
+# Bug component: 48448
+include platform/packages/apps/Nfc:/OWNERS
\ No newline at end of file
diff --git a/intf/nxpnfc/aidl/Android.bp b/intf/nxpnfc/aidl/Android.bp
index feec593..e20b471 100644
--- a/intf/nxpnfc/aidl/Android.bp
+++ b/intf/nxpnfc/aidl/Android.bp
@@ -15,6 +15,7 @@ aidl_interface {
     srcs: ["vendor/nxp/nxpnfc_aidl/*.aidl"],
     stability: "vintf",
     frozen: true,
+    owner: "nxp",
     backend: {
         cpp: {
             enabled: false,
diff --git a/snxxx/Android.bp b/snxxx/Android.bp
index 524c167..01105a6 100644
--- a/snxxx/Android.bp
+++ b/snxxx/Android.bp
@@ -13,9 +13,23 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//
-//  The original Work has been changed by NXP.
-//  Copyright (C) 2021-2024 NXP
+/******************************************************************************
+ *
+ *  Copyright 2021-2024 NXP
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
 
 package {
     // See: http://go/android-license-faq
@@ -47,6 +61,7 @@ cc_library_shared {
         "halimpl/dnld/phDnldNfc_Utils.cc",
         "halimpl/dnld/phNxpNciHal_Dnld.cc",
         "halimpl/hal/phNxpNciHal.cc",
+        "halimpl/hal/phNxpNciHal_VendorProp.cc",
         "halimpl/hal/phNxpNciHal_ext.cc",
         "halimpl/log/phNxpLog.cc",
         "halimpl/src/adaptation/EseAdaptation.cc",
@@ -108,7 +123,7 @@ cc_library_shared {
         "vendor.nxp.nxpese@1.0",
     ],
     header_libs: [
-      "power_tracker_headers",
+        "power_tracker_headers",
     ],
 }
 
@@ -132,11 +147,53 @@ cc_library_headers {
     ],
 }
 
+cc_binary {
+    name: "android.hardware.nfc2-service.nxp",
+    relative_install_path: "hw",
+    init_rc: ["aidl/2.0/nfc2-service-nxp.rc"],
+    vintf_fragments: ["aidl/2.0/nfc2-service-nxp.xml"],
+    vendor: true,
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Wextra",
+        "-DNXP_NFC_RECOVERY=TRUE",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libutils",
+        "libbinder_ndk",
+        "android.hardware.nfc-V2-ndk",
+        "nfc_nci_nxp_snxxx",
+        "libhardware",
+        "vendor.nxp.nxpnfc_aidl-V1-ndk",
+    ],
+    srcs: [
+        "aidl/2.0/main.cpp",
+        "aidl/2.0/Nfc.cpp",
+        "aidl/2.0/NfcExtns.cpp",
+        "extns/impl/nxpnfc/aidl/NxpNfc.cpp",
+    ],
+    local_include_dirs: [
+        "halimpl/common",
+        "halimpl/dnld",
+        "halimpl/hal",
+        "halimpl/inc",
+        "halimpl/log",
+        "halimpl/utils",
+        "halimpl/mifare",
+        "halimpl/recovery",
+        "halimpl/eseclients_extns/inc/",
+        "extns/impl/nxpnfc/aidl",
+    ],
+}
+
 cc_binary {
     name: "android.hardware.nfc-service.nxp",
     relative_install_path: "hw",
-    init_rc: ["aidl/nfc-service-nxp.rc"],
-    vintf_fragments: ["aidl/nfc-service-nxp.xml"],
+    init_rc: ["aidl/1.0/nfc-service-nxp.rc"],
+    vintf_fragments: ["aidl/1.0/nfc-service-nxp.xml"],
     vendor: true,
     cflags: [
         "-Wall",
@@ -155,9 +212,9 @@ cc_binary {
         "vendor.nxp.nxpnfc_aidl-V1-ndk",
     ],
     srcs: [
-        "aidl/main.cpp",
-        "aidl/Nfc.cpp",
-        "aidl/NfcExtns.cpp",
+        "aidl/1.0/main.cpp",
+        "aidl/1.0/Nfc.cpp",
+        "aidl/1.0/NfcExtns.cpp",
         "extns/impl/nxpnfc/aidl/NxpNfc.cpp",
     ],
     local_include_dirs: [
@@ -173,3 +230,27 @@ cc_binary {
         "extns/impl/nxpnfc/aidl",
     ],
 }
+
+filegroup {
+    name: "nxp_gtest_filegroup",
+
+    srcs: [
+        "halimpl/observe_mode/NciDiscoveryCommandBuilder.cc",
+        "halimpl/observe_mode/ReaderPollConfigParser.cc",
+    ],
+    visibility: [
+        "//hardware/nxp/nfc/snxxx/tests/gtest",
+    ],
+}
+
+cc_library_headers {
+    name: "nxp_gtest_headers",
+    host_supported: true,
+    export_include_dirs: [
+        "halimpl/common",
+        "halimpl/observe_mode",
+    ],
+    visibility: [
+        "//hardware/nxp/nfc/snxxx/tests/gtest",
+    ],
+}
diff --git a/snxxx/aidl/Nfc.cpp b/snxxx/aidl/1.0/Nfc.cpp
similarity index 96%
rename from snxxx/aidl/Nfc.cpp
rename to snxxx/aidl/1.0/Nfc.cpp
index f49fec6..d4aac73 100644
--- a/snxxx/aidl/Nfc.cpp
+++ b/snxxx/aidl/1.0/Nfc.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2022-2023 NXP
+ *  Copyright 2022-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -33,13 +33,16 @@ namespace nfc {
 
 std::shared_ptr<INfcClientCallback> Nfc::mCallback = nullptr;
 AIBinder_DeathRecipient* clientDeathRecipient = nullptr;
+std::mutex syncNfcOpenClose;
 
 void OnDeath(void* cookie) {
   if (Nfc::mCallback != nullptr &&
       !AIBinder_isAlive(Nfc::mCallback->asBinder().get())) {
+    std::lock_guard<std::mutex> lk(syncNfcOpenClose);
     LOG(INFO) << __func__ << " Nfc service has died";
     Nfc* nfc = static_cast<Nfc*>(cookie);
     nfc->close(NfcCloseType::DISABLE);
+    LOG(INFO) << __func__ << " death NTF completed";
   }
 }
 
@@ -51,6 +54,7 @@ void OnDeath(void* cookie) {
     return ndk::ScopedAStatus::fromServiceSpecificError(
         static_cast<int32_t>(NfcStatus::FAILED));
   }
+  std::lock_guard<std::mutex> lk(syncNfcOpenClose);
   Nfc::mCallback = clientCallback;
 
   clientDeathRecipient = AIBinder_DeathRecipient_new(OnDeath);
@@ -83,7 +87,6 @@ void OnDeath(void* cookie) {
   } else {
     ret = phNxpNciHal_close(false);
   }
-  Nfc::mCallback = nullptr;
   AIBinder_DeathRecipient_delete(clientDeathRecipient);
   clientDeathRecipient = nullptr;
   return ret == NFCSTATUS_SUCCESS
diff --git a/snxxx/aidl/Nfc.h b/snxxx/aidl/1.0/Nfc.h
similarity index 100%
rename from snxxx/aidl/Nfc.h
rename to snxxx/aidl/1.0/Nfc.h
diff --git a/snxxx/aidl/NfcExtns.cpp b/snxxx/aidl/1.0/NfcExtns.cpp
similarity index 100%
rename from snxxx/aidl/NfcExtns.cpp
rename to snxxx/aidl/1.0/NfcExtns.cpp
diff --git a/snxxx/aidl/NfcExtns.h b/snxxx/aidl/1.0/NfcExtns.h
similarity index 100%
rename from snxxx/aidl/NfcExtns.h
rename to snxxx/aidl/1.0/NfcExtns.h
diff --git a/snxxx/aidl/hardware_nfc.h b/snxxx/aidl/1.0/hardware_nfc.h
similarity index 100%
rename from snxxx/aidl/hardware_nfc.h
rename to snxxx/aidl/1.0/hardware_nfc.h
diff --git a/snxxx/aidl/main.cpp b/snxxx/aidl/1.0/main.cpp
similarity index 100%
rename from snxxx/aidl/main.cpp
rename to snxxx/aidl/1.0/main.cpp
diff --git a/snxxx/aidl/nfc-service-nxp.rc b/snxxx/aidl/1.0/nfc-service-nxp.rc
similarity index 100%
rename from snxxx/aidl/nfc-service-nxp.rc
rename to snxxx/aidl/1.0/nfc-service-nxp.rc
diff --git a/snxxx/aidl/nfc-service-nxp.xml b/snxxx/aidl/1.0/nfc-service-nxp.xml
similarity index 90%
rename from snxxx/aidl/nfc-service-nxp.xml
rename to snxxx/aidl/1.0/nfc-service-nxp.xml
index a1a97e0..9ee49de 100644
--- a/snxxx/aidl/nfc-service-nxp.xml
+++ b/snxxx/aidl/1.0/nfc-service-nxp.xml
@@ -1,6 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.nfc</name>
+        <version>1</version>
         <fqname>INfc/default</fqname>
     </hal>
     <hal format="aidl">
diff --git a/snxxx/aidl/2.0/Nfc.cpp b/snxxx/aidl/2.0/Nfc.cpp
new file mode 100644
index 0000000..03a5c76
--- /dev/null
+++ b/snxxx/aidl/2.0/Nfc.cpp
@@ -0,0 +1,191 @@
+/******************************************************************************
+ *
+ *  Copyright 2022-2024 NXP
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
+
+#include "Nfc.h"
+
+#include <android-base/logging.h>
+
+#include "NfcExtns.h"
+#include "phNfcStatus.h"
+#include "phNxpConfig.h"
+#include "phNxpNciHal_Adaptation.h"
+#include "phNxpNciHal_ext.h"
+
+#define CHK_STATUS(x) \
+  ((x) == NFCSTATUS_SUCCESS) ? (NfcStatus::OK) : (NfcStatus::FAILED)
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace nfc {
+
+std::shared_ptr<INfcClientCallback> Nfc::mCallback = nullptr;
+AIBinder_DeathRecipient* clientDeathRecipient = nullptr;
+std::mutex syncNfcOpenClose;
+
+void OnDeath(void* cookie) {
+  if (Nfc::mCallback != nullptr &&
+      !AIBinder_isAlive(Nfc::mCallback->asBinder().get())) {
+    std::lock_guard<std::mutex> lk(syncNfcOpenClose);
+    LOG(INFO) << __func__ << " Nfc service has died";
+    Nfc* nfc = static_cast<Nfc*>(cookie);
+    nfc->close(NfcCloseType::DISABLE);
+    LOG(INFO) << __func__ << " death NTF completed";
+  }
+}
+
+::ndk::ScopedAStatus Nfc::open(
+    const std::shared_ptr<INfcClientCallback>& clientCallback) {
+  LOG(INFO) << "Nfc::open";
+  if (clientCallback == nullptr) {
+    LOG(INFO) << "Nfc::open null callback";
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(NfcStatus::FAILED));
+  }
+  std::lock_guard<std::mutex> lk(syncNfcOpenClose);
+  Nfc::mCallback = clientCallback;
+
+  clientDeathRecipient = AIBinder_DeathRecipient_new(OnDeath);
+  auto linkRet = AIBinder_linkToDeath(clientCallback->asBinder().get(),
+                                      clientDeathRecipient, this /* cookie */);
+  if (linkRet != STATUS_OK) {
+    LOG(ERROR) << __func__ << ": linkToDeath failed: " << linkRet;
+    // Just ignore the error.
+  }
+
+  printNfcMwVersion();
+  int ret = phNxpNciHal_open(eventCallback, dataCallback);
+  LOG(INFO) << "Nfc::open Exit";
+  return ret == NFCSTATUS_SUCCESS
+             ? ndk::ScopedAStatus::ok()
+             : ndk::ScopedAStatus::fromServiceSpecificError(
+                   static_cast<int32_t>(NfcStatus::FAILED));
+}
+
+::ndk::ScopedAStatus Nfc::close(NfcCloseType type) {
+  LOG(INFO) << "Nfc::close";
+  if (Nfc::mCallback == nullptr) {
+    LOG(ERROR) << __func__ << "mCallback null";
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(NfcStatus::FAILED));
+  }
+  int ret = 0;
+  if (type == NfcCloseType::HOST_SWITCHED_OFF) {
+    ret = phNxpNciHal_configDiscShutdown();
+  } else {
+    ret = phNxpNciHal_close(false);
+  }
+  AIBinder_DeathRecipient_delete(clientDeathRecipient);
+  clientDeathRecipient = nullptr;
+  return ret == NFCSTATUS_SUCCESS
+             ? ndk::ScopedAStatus::ok()
+             : ndk::ScopedAStatus::fromServiceSpecificError(
+                   static_cast<int32_t>(NfcStatus::FAILED));
+}
+
+::ndk::ScopedAStatus Nfc::coreInitialized() {
+  LOG(INFO) << "Nfc::coreInitialized";
+  if (Nfc::mCallback == nullptr) {
+    LOG(ERROR) << __func__ << "mCallback null";
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(NfcStatus::FAILED));
+  }
+  int ret = phNxpNciHal_core_initialized();
+
+  return ret == NFCSTATUS_SUCCESS
+             ? ndk::ScopedAStatus::ok()
+             : ndk::ScopedAStatus::fromServiceSpecificError(
+                   static_cast<int32_t>(NfcStatus::FAILED));
+}
+
+::ndk::ScopedAStatus Nfc::factoryReset() {
+  LOG(INFO) << "Nfc::factoryReset";
+  phNxpNciHal_do_factory_reset();
+  return ndk::ScopedAStatus::ok();
+}
+
+::ndk::ScopedAStatus Nfc::getConfig(NfcConfig* _aidl_return) {
+  LOG(INFO) << "Nfc::getConfig";
+  NfcConfig config;
+  NfcExtns nfcExtns;
+  nfcExtns.getConfig(config);
+  *_aidl_return = std::move(config);
+  return ndk::ScopedAStatus::ok();
+}
+
+::ndk::ScopedAStatus Nfc::powerCycle() {
+  LOG(INFO) << "powerCycle";
+  if (Nfc::mCallback == nullptr) {
+    LOG(ERROR) << __func__ << "mCallback null";
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(NfcStatus::FAILED));
+  }
+  int ret = phNxpNciHal_power_cycle();
+  return ret == NFCSTATUS_SUCCESS
+             ? ndk::ScopedAStatus::ok()
+             : ndk::ScopedAStatus::fromServiceSpecificError(
+                   static_cast<int32_t>(NfcStatus::FAILED));
+}
+
+::ndk::ScopedAStatus Nfc::preDiscover() {
+  LOG(INFO) << "preDiscover";
+  if (Nfc::mCallback == nullptr) {
+    LOG(ERROR) << __func__ << "mCallback null";
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(NfcStatus::FAILED));
+  }
+  int ret = phNxpNciHal_pre_discover();
+  return ret == NFCSTATUS_SUCCESS
+             ? ndk::ScopedAStatus::ok()
+             : ndk::ScopedAStatus::fromServiceSpecificError(
+                   static_cast<int32_t>(NfcStatus::FAILED));
+}
+
+::ndk::ScopedAStatus Nfc::write(const std::vector<uint8_t>& data,
+                                int32_t* _aidl_return) {
+  LOG(INFO) << "write";
+  if (Nfc::mCallback == nullptr) {
+    LOG(ERROR) << __func__ << "mCallback null";
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(NfcStatus::FAILED));
+  }
+  *_aidl_return = phNxpNciHal_write(data.size(), &data[0]);
+  return ndk::ScopedAStatus::ok();
+}
+::ndk::ScopedAStatus Nfc::setEnableVerboseLogging(bool enable) {
+  LOG(INFO) << "setVerboseLogging";
+  phNxpNciHal_setVerboseLogging(enable);
+  return ndk::ScopedAStatus::ok();
+}
+
+::ndk::ScopedAStatus Nfc::isVerboseLoggingEnabled(bool* _aidl_return) {
+  *_aidl_return = phNxpNciHal_getVerboseLogging();
+  return ndk::ScopedAStatus::ok();
+}
+
+::ndk::ScopedAStatus Nfc::controlGranted(NfcStatus* _aidl_return) {
+  LOG(INFO) << "controlGranted";
+  int status = phNxpNciHal_control_granted();
+  *_aidl_return = CHK_STATUS(status);
+  return ndk::ScopedAStatus::ok();
+}
+
+}  // namespace nfc
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/snxxx/aidl/2.0/Nfc.h b/snxxx/aidl/2.0/Nfc.h
new file mode 100644
index 0000000..303aa82
--- /dev/null
+++ b/snxxx/aidl/2.0/Nfc.h
@@ -0,0 +1,108 @@
+
+/******************************************************************************
+ *
+ *  Copyright 2022-2023 NXP
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
+
+#pragma once
+
+#include <aidl/android/hardware/nfc/BnNfc.h>
+#include <aidl/android/hardware/nfc/INfc.h>
+#include <aidl/android/hardware/nfc/INfcClientCallback.h>
+#include <aidl/android/hardware/nfc/NfcConfig.h>
+#include <aidl/android/hardware/nfc/NfcEvent.h>
+#include <aidl/android/hardware/nfc/NfcStatus.h>
+#include <aidl/android/hardware/nfc/PresenceCheckAlgorithm.h>
+#include <aidl/android/hardware/nfc/ProtocolDiscoveryConfig.h>
+#include <android-base/logging.h>
+#include <log/log.h>
+
+#include "phNxpNciHal_ext.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace nfc {
+
+using ::aidl::android::hardware::nfc::NfcCloseType;
+using ::aidl::android::hardware::nfc::NfcConfig;
+using ::aidl::android::hardware::nfc::NfcStatus;
+using NfcConfig = aidl::android::hardware::nfc::NfcConfig;
+using ::aidl::android::hardware::nfc::NfcEvent;
+
+// Default implementation that reports no support NFC.
+struct Nfc : public BnNfc {
+ public:
+  Nfc() = default;
+
+  ::ndk::ScopedAStatus open(
+      const std::shared_ptr<INfcClientCallback>& clientCallback) override;
+  ::ndk::ScopedAStatus close(NfcCloseType type) override;
+  ::ndk::ScopedAStatus coreInitialized() override;
+  ::ndk::ScopedAStatus factoryReset() override;
+  ::ndk::ScopedAStatus getConfig(NfcConfig* _aidl_return) override;
+  ::ndk::ScopedAStatus powerCycle() override;
+  ::ndk::ScopedAStatus preDiscover() override;
+  ::ndk::ScopedAStatus write(const std::vector<uint8_t>& data,
+                             int32_t* _aidl_return) override;
+  ::ndk::ScopedAStatus setEnableVerboseLogging(bool enable) override;
+  ::ndk::ScopedAStatus isVerboseLoggingEnabled(bool* _aidl_return) override;
+  ::ndk::ScopedAStatus controlGranted(NfcStatus* _aidl_return_) override;
+
+  static uint8_t mapToAidlIfRequired(uint8_t event) {
+    switch (event) {
+      case HAL_HCI_NETWORK_RESET_EVT:
+        event = (uint8_t)NfcEvent::HCI_NETWORK_RESET;
+        break;
+      case HAL_NFC_REQUEST_CONTROL_EVT:
+        event = (uint8_t)NfcEvent::REQUEST_CONTROL;
+        break;
+      case HAL_NFC_RELEASE_CONTROL_EVT:
+        event = (uint8_t)NfcEvent::RELEASE_CONTROL;
+        break;
+      default:
+        break;
+    }
+    return event;
+  }
+
+  static void eventCallback(uint8_t event, uint8_t status) {
+    if (mCallback != nullptr) {
+      event = mapToAidlIfRequired(event);
+      auto ret = mCallback->sendEvent((NfcEvent)event, (NfcStatus)status);
+      if (!ret.isOk()) {
+        LOG(ERROR) << "Failed to send event!";
+      }
+    }
+  }
+
+  static void dataCallback(uint16_t data_len, uint8_t* p_data) {
+    std::vector<uint8_t> data(p_data, p_data + data_len);
+    if (mCallback != nullptr) {
+      auto ret = mCallback->sendData(data);
+      if (!ret.isOk()) {
+        LOG(ERROR) << "Failed to send data!";
+      }
+    }
+  }
+
+  static std::shared_ptr<INfcClientCallback> mCallback;
+};
+
+}  // namespace nfc
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/snxxx/aidl/2.0/NfcExtns.cpp b/snxxx/aidl/2.0/NfcExtns.cpp
new file mode 100644
index 0000000..a8cd850
--- /dev/null
+++ b/snxxx/aidl/2.0/NfcExtns.cpp
@@ -0,0 +1,111 @@
+/******************************************************************************
+ *
+ *  Copyright 2023-2024 NXP
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
+#include "NfcExtns.h"
+
+#include "phNfcStatus.h"
+#include "phNxpConfig.h"
+#include "phNxpNciHal_extOperations.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace nfc {
+
+void NfcExtns::getConfig(NfcConfig& config) {
+  unsigned long num = 0;
+  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
+  buffer.fill(0);
+  long retlen = 0;
+  memset(&config, 0x00, sizeof(NfcConfig));
+
+  phNxpNciHal_getExtVendorConfig();
+
+  if (GetNxpNumValue(NAME_NFA_POLL_BAIL_OUT_MODE, &num, sizeof(num))) {
+    config.nfaPollBailOutMode = (bool)num;
+  }
+  if (GetNxpNumValue(NAME_ISO_DEP_MAX_TRANSCEIVE, &num, sizeof(num))) {
+    config.maxIsoDepTransceiveLength = (uint32_t)num;
+  }
+  if (GetNxpNumValue(NAME_DEFAULT_OFFHOST_ROUTE, &num, sizeof(num))) {
+    config.defaultOffHostRoute = (uint8_t)num;
+  }
+  if (GetNxpNumValue(NAME_DEFAULT_NFCF_ROUTE, &num, sizeof(num))) {
+    config.defaultOffHostRouteFelica = (uint8_t)num;
+  }
+  if (GetNxpNumValue(NAME_DEFAULT_SYS_CODE_ROUTE, &num, sizeof(num))) {
+    config.defaultSystemCodeRoute = (uint8_t)num;
+  }
+  if (GetNxpNumValue(NAME_DEFAULT_SYS_CODE_PWR_STATE, &num, sizeof(num))) {
+    config.defaultSystemCodePowerState =
+        phNxpNciHal_updateAutonomousPwrState((uint8_t)num);
+  }
+  if (GetNxpNumValue(NAME_DEFAULT_ROUTE, &num, sizeof(num))) {
+    config.defaultRoute = (uint8_t)num;
+  }
+  if (GetNxpByteArrayValue(NAME_DEVICE_HOST_ALLOW_LIST, (char*)buffer.data(),
+                           buffer.size(), &retlen)) {
+    config.hostAllowlist.resize(retlen);
+    for (long i = 0; i < retlen; i++) config.hostAllowlist[i] = buffer[i];
+  }
+  if (GetNxpNumValue(NAME_OFF_HOST_ESE_PIPE_ID, &num, sizeof(num))) {
+    config.offHostESEPipeId = (uint8_t)num;
+  }
+  if (GetNxpByteArrayValue(NAME_OFF_HOST_SIM_PIPE_IDS, (char*)buffer.data(),
+                           buffer.size(), &retlen)) {
+    config.offHostSimPipeIds.resize(retlen);
+    for (long i = 0; i < retlen; i++) config.offHostSimPipeIds[i] = buffer[i];
+  }
+  if (GetNxpNumValue(NAME_DEFAULT_ISODEP_ROUTE, &num, sizeof(num))) {
+    config.defaultIsoDepRoute = (uint8_t)num;
+  }
+  if (GetNxpByteArrayValue(NAME_OFFHOST_ROUTE_UICC, (char*)buffer.data(),
+                           buffer.size(), &retlen)) {
+    config.offHostRouteUicc.resize(retlen);
+    for (long i = 0; i < retlen; i++) config.offHostRouteUicc[i] = buffer[i];
+  }
+
+  if (GetNxpByteArrayValue(NAME_OFFHOST_ROUTE_ESE, (char*)buffer.data(),
+                           buffer.size(), &retlen)) {
+    config.offHostRouteEse.resize(retlen);
+    for (long i = 0; i < retlen; i++) config.offHostRouteEse[i] = buffer[i];
+  }
+  if ((GetNxpByteArrayValue(NAME_NFA_PROPRIETARY_CFG, (char*)buffer.data(),
+                            buffer.size(), &retlen)) &&
+      (retlen == 9)) {
+    config.nfaProprietaryCfg.protocol18092Active = (uint8_t)buffer[0];
+    config.nfaProprietaryCfg.protocolBPrime = (uint8_t)buffer[1];
+    config.nfaProprietaryCfg.protocolDual = (uint8_t)buffer[2];
+    config.nfaProprietaryCfg.protocol15693 = (uint8_t)buffer[3];
+    config.nfaProprietaryCfg.protocolKovio = (uint8_t)buffer[4];
+    config.nfaProprietaryCfg.protocolMifare = (uint8_t)buffer[5];
+    config.nfaProprietaryCfg.discoveryPollKovio = (uint8_t)buffer[6];
+    config.nfaProprietaryCfg.discoveryPollBPrime = (uint8_t)buffer[7];
+    config.nfaProprietaryCfg.discoveryListenBPrime = (uint8_t)buffer[8];
+  } else {
+    memset(&config.nfaProprietaryCfg, 0xFF, sizeof(ProtocolDiscoveryConfig));
+  }
+  if ((GetNxpNumValue(NAME_PRESENCE_CHECK_ALGORITHM, &num, sizeof(num))) &&
+      (num <= 2)) {
+    config.presenceCheckAlgorithm = (PresenceCheckAlgorithm)num;
+  }
+}
+
+}  // namespace nfc
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
\ No newline at end of file
diff --git a/snxxx/aidl/2.0/NfcExtns.h b/snxxx/aidl/2.0/NfcExtns.h
new file mode 100644
index 0000000..c8ac27d
--- /dev/null
+++ b/snxxx/aidl/2.0/NfcExtns.h
@@ -0,0 +1,48 @@
+/******************************************************************************
+ *
+ *  Copyright 2023 NXP
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
+
+#pragma once
+#include <aidl/android/hardware/nfc/NfcConfig.h>
+#include <aidl/android/hardware/nfc/PresenceCheckAlgorithm.h>
+#include <aidl/android/hardware/nfc/ProtocolDiscoveryConfig.h>
+#include <android-base/logging.h>
+#include <log/log.h>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace nfc {
+
+#define NXP_MAX_CONFIG_STRING_LEN 260
+using ::aidl::android::hardware::nfc::NfcConfig;
+using NfcConfig = aidl::android::hardware::nfc::NfcConfig;
+using PresenceCheckAlgorithm =
+    aidl::android::hardware::nfc::PresenceCheckAlgorithm;
+using ProtocolDiscoveryConfig =
+    aidl::android::hardware::nfc::ProtocolDiscoveryConfig;
+
+struct NfcExtns {
+ public:
+  NfcExtns() = default;
+  void getConfig(NfcConfig& config);
+};
+
+}  // namespace nfc
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/snxxx/aidl/2.0/hardware_nfc.h b/snxxx/aidl/2.0/hardware_nfc.h
new file mode 100644
index 0000000..a11cf59
--- /dev/null
+++ b/snxxx/aidl/2.0/hardware_nfc.h
@@ -0,0 +1,34 @@
+/******************************************************************************
+ *
+ *  Copyright 2022 NXP
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
+typedef uint8_t nfc_event_t;
+typedef uint8_t nfc_status_t;
+
+/*
+ * The callback passed in from the NFC stack that the HAL
+ * can use to pass events back to the stack.
+ */
+typedef void(nfc_stack_callback_t)(nfc_event_t event,
+                                   nfc_status_t event_status);
+
+/*
+ * The callback passed in from the NFC stack that the HAL
+ * can use to pass incoming data to the stack.
+ */
+typedef void(nfc_stack_data_callback_t)(uint16_t data_len, uint8_t* p_data);
diff --git a/snxxx/aidl/2.0/main.cpp b/snxxx/aidl/2.0/main.cpp
new file mode 100644
index 0000000..d219cd9
--- /dev/null
+++ b/snxxx/aidl/2.0/main.cpp
@@ -0,0 +1,67 @@
+/******************************************************************************
+ *
+ *  Copyright 2022 NXP
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
+
+#include <android-base/logging.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+
+#include <thread>
+
+#include "Nfc.h"
+#include "NxpNfc.h"
+#include "phNxpNciHal_Adaptation.h"
+#include "phNxpNciHal_Recovery.h"
+
+using ::aidl::android::hardware::nfc::Nfc;
+using ::aidl::vendor::nxp::nxpnfc_aidl::INxpNfc;
+using ::aidl::vendor::nxp::nxpnfc_aidl::NxpNfc;
+using namespace std;
+
+void startNxpNfcAidlService() {
+  ALOGI("NXP NFC Extn Service is starting.");
+  std::shared_ptr<NxpNfc> nxp_nfc_service = ndk::SharedRefBase::make<NxpNfc>();
+  const std::string nxpNfcInstName =
+      std::string() + NxpNfc::descriptor + "/default";
+  ALOGI("NxpNfc Registering service: %s", nxpNfcInstName.c_str());
+  binder_status_t status = AServiceManager_addService(
+      nxp_nfc_service->asBinder().get(), nxpNfcInstName.c_str());
+  ALOGI("NxpNfc Registered INxpNfc service status: %d", status);
+  CHECK(status == STATUS_OK);
+  ABinderProcess_joinThreadPool();
+}
+
+int main() {
+  ALOGI("NFC AIDL HAL starting up");
+  if (!ABinderProcess_setThreadPoolMaxThreadCount(1)) {
+    ALOGE("failed to set thread pool max thread count");
+    return 1;
+  }
+  std::shared_ptr<Nfc> nfc_service = ndk::SharedRefBase::make<Nfc>();
+
+  const std::string nfcInstName = std::string() + Nfc::descriptor + "/default";
+  binder_status_t status = AServiceManager_addService(
+      nfc_service->asBinder().get(), nfcInstName.c_str());
+  CHECK(status == STATUS_OK);
+
+#if (NXP_NFC_RECOVERY == TRUE)
+  phNxpNciHal_RecoverFWTearDown();
+#endif
+  thread t1(startNxpNfcAidlService);
+  ABinderProcess_joinThreadPool();
+  return 0;
+}
diff --git a/snxxx/aidl/2.0/nfc2-service-nxp.rc b/snxxx/aidl/2.0/nfc2-service-nxp.rc
new file mode 100644
index 0000000..6acec04
--- /dev/null
+++ b/snxxx/aidl/2.0/nfc2-service-nxp.rc
@@ -0,0 +1,4 @@
+service vendor.nfc_hal_service /vendor/bin/hw/android.hardware.nfc2-service.nxp
+    class early_hal
+    user nfc
+    group nfc drmrpc system
diff --git a/snxxx/aidl/2.0/nfc2-service-nxp.xml b/snxxx/aidl/2.0/nfc2-service-nxp.xml
new file mode 100644
index 0000000..5d71582
--- /dev/null
+++ b/snxxx/aidl/2.0/nfc2-service-nxp.xml
@@ -0,0 +1,11 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl">
+        <name>android.hardware.nfc</name>
+        <version>2</version>
+        <fqname>INfc/default</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>vendor.nxp.nxpnfc_aidl</name>
+        <fqname>INxpNfc/default</fqname>
+    </hal>
+</manifest>
diff --git a/snxxx/halimpl/common/Nxp_Features.h b/snxxx/halimpl/common/Nxp_Features.h
index 80cca0a..1c5f172 100644
--- a/snxxx/halimpl/common/Nxp_Features.h
+++ b/snxxx/halimpl/common/Nxp_Features.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2022,2023 NXP
+ *  Copyright 2022-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -124,8 +124,8 @@ typedef struct {
   uint8_t _NFCC_SPI_FW_DOWNLOAD_SYNC : 1;
   uint8_t _NFCEE_REMOVED_NTF_RECOVERY : 1;
   uint8_t _NFCC_FORCE_FW_DOWNLOAD : 1;
-  uint8_t _NFA_EE_MAX_EE_SUPPORTED : 3;
   uint8_t _NFCC_DWNLD_MODE : 1;
+  uint8_t _NFCC_4K_FW_SUPPORT : 1;
 } tNfc_nfccFeatureList;
 
 typedef struct {
@@ -148,6 +148,10 @@ extern tNfc_featureList nfcFL;
 #define IS_CHIP_TYPE_LE(cType) (nfcFL.chipType <= cType)
 #define IS_CHIP_TYPE_L(cType) (nfcFL.chipType < cType)
 #define IS_CHIP_TYPE_NE(cType) (nfcFL.chipType != cType)
+#define IS_4K_SUPPORT (nfcFL.nfccFL._NFCC_4K_FW_SUPPORT == true)
+
+#define CONFIGURE_4K_SUPPORT(value) \
+  { nfcFL.nfccFL._NFCC_4K_FW_SUPPORT = value; }
 
 #define CONFIGURE_FEATURELIST(chipType)               \
   {                                                   \
@@ -199,40 +203,28 @@ extern tNfc_featureList nfcFL;
     }                                                 \
   }
 
-#define CONFIGURE_FEATURELIST_NFCC_WITH_ESE(chipType)                     \
-  {                                                                       \
-    switch (chipType) {                                                   \
-      case pn81T:                                                         \
-        CONFIGURE_FEATURELIST_NFCC(pn557)                                 \
-        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true;                   \
-        nfcFL.nfccFL._NFA_EE_MAX_EE_SUPPORTED =                           \
-            EE_T4T_SUPPORTED + EE_UICC1_SUPPORTED + EE_UICC2_SUPPORTED +  \
-            EE_ESE_SUPPORTED;                                             \
-        break;                                                            \
-      case sn100u:                                                        \
-        CONFIGURE_FEATURELIST_NFCC(sn100u)                                \
-        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true;                   \
-        nfcFL.nfccFL._NFA_EE_MAX_EE_SUPPORTED =                           \
-            EE_T4T_SUPPORTED + EE_UICC1_SUPPORTED + EE_UICC2_SUPPORTED +  \
-            EE_UICC3_SUPPORTED + EE_ESE_SUPPORTED;                        \
-        break;                                                            \
-      case sn220u:                                                        \
-        CONFIGURE_FEATURELIST_NFCC(sn220u)                                \
-        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true;                   \
-        nfcFL.nfccFL._NFA_EE_MAX_EE_SUPPORTED =                           \
-            EE_T4T_SUPPORTED + EE_UICC1_SUPPORTED + EE_UICC2_SUPPORTED +  \
-            EE_ESE_SUPPORTED;                                             \
-        break;                                                            \
-      case sn300u:                                                        \
-        CONFIGURE_FEATURELIST_NFCC(sn300u)                                \
-        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true;                   \
-        nfcFL.nfccFL._NFA_EE_MAX_EE_SUPPORTED =                           \
-            EE_T4T_SUPPORTED + EE_UICC1_SUPPORTED + EE_UICC2_SUPPORTED +  \
-            EE_ESE_SUPPORTED + EE_EUICC1_SUPPORTED + EE_EUICC2_SUPPORTED; \
-        break;                                                            \
-      default:                                                            \
-        break;                                                            \
-    }                                                                     \
+#define CONFIGURE_FEATURELIST_NFCC_WITH_ESE(chipType)   \
+  {                                                     \
+    switch (chipType) {                                 \
+      case pn81T:                                       \
+        CONFIGURE_FEATURELIST_NFCC(pn557)               \
+        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true; \
+        break;                                          \
+      case sn100u:                                      \
+        CONFIGURE_FEATURELIST_NFCC(sn100u)              \
+        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true; \
+        break;                                          \
+      case sn220u:                                      \
+        CONFIGURE_FEATURELIST_NFCC(sn220u)              \
+        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true; \
+        break;                                          \
+      case sn300u:                                      \
+        CONFIGURE_FEATURELIST_NFCC(sn300u)              \
+        nfcFL.nfccFL._NFCC_SPI_FW_DOWNLOAD_SYNC = true; \
+        break;                                          \
+      default:                                          \
+        break;                                          \
+    }                                                   \
   }
 
 #define CONFIGURE_FEATURELIST_NFCC(chipType)                           \
@@ -241,6 +233,7 @@ extern tNfc_featureList nfcFL;
     nfcFL._PHDNLDNFC_USERDATA_EEPROM_LEN = 0x0C80U;                    \
     nfcFL._FW_MOBILE_MAJOR_NUMBER = FW_MOBILE_MAJOR_NUMBER_PN48AD;     \
     nfcFL.nfccFL._NFCC_DWNLD_MODE = NFCC_DWNLD_WITH_VEN_RESET;         \
+    nfcFL.nfccFL._NFCC_4K_FW_SUPPORT = false;                          \
     switch (chipType) {                                                \
       case pn557:                                                      \
         nfcFL.nfccFL._NFCC_I2C_READ_WRITE_IMPROVEMENT = true;          \
diff --git a/snxxx/halimpl/common/phNfcCommon.h b/snxxx/halimpl/common/phNfcCommon.h
index 90ca880..62be7fd 100644
--- a/snxxx/halimpl/common/phNfcCommon.h
+++ b/snxxx/halimpl/common/phNfcCommon.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2010-2018, 2021-2022 NXP
+ *  Copyright 2010-2018, 2021-2022, 2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -92,6 +92,7 @@
 #define CLK_FREQ_52MHZ 6
 #define CLK_FREQ_32MHZ 7
 #define CLK_FREQ_48MHZ 8
+#define CLK_FREQ_76_8MHZ 9
 
 static const uint8_t PN557_SET_CONFIG_CMD_PLL_13MHZ[] = {
     0x20, 0x02, 0x0C, 0x01, 0xA0, 0x20, 0x08, 0x08,
diff --git a/snxxx/halimpl/common/phNfcNciConstants.h b/snxxx/halimpl/common/phNfcNciConstants.h
index 7182d3e..e50760a 100644
--- a/snxxx/halimpl/common/phNfcNciConstants.h
+++ b/snxxx/halimpl/common/phNfcNciConstants.h
@@ -61,6 +61,7 @@
 // Observe mode constants
 #define L2_EVT_TAG 0x01
 #define CMA_EVT_TAG 0x0A
+#define CMA_EVT_EXTRA_DATA_TAG 0x07
 #define MIN_LEN_NON_CMA_EVT 7
 #define MIN_LEN_CMA_EVT 6
 #define INDEX_OF_L2_EVT_TYPE 6
@@ -70,9 +71,10 @@
 #define INDEX_OF_CMA_DATA 7
 #define MIN_LEN_NON_CMA_EVT 7
 #define MIN_LEN_CMA_EVT 6
+#define MIN_LEN_CMA_EXTRA_DATA_EVT 1
 #define L2_EVENT_TRIGGER_TYPE 0x1
 #define CMA_EVENT_TRIGGER_TYPE 0x02
-#define CMA_DATA_TRIGGER_TYPE 0x0C
+#define CMA_DATA_TRIGGER_TYPE 0x0E
 // Event types to send upper layer
 #define TYPE_RF_FLAG 0x00
 #define TYPE_MOD_A 0x01
diff --git a/snxxx/halimpl/common/phNfcTypes.h b/snxxx/halimpl/common/phNfcTypes.h
index 31be23c..1a8e612 100644
--- a/snxxx/halimpl/common/phNfcTypes.h
+++ b/snxxx/halimpl/common/phNfcTypes.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2010-2020, 2023 NXP
+ * Copyright 2010-2020, 2023-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -50,7 +50,7 @@ typedef uint16_t NFCSTATUS; /* Return values */
 
 /*
  * Possible Hardware Configuration exposed to upper layer.
- * Typically this should be port name (Ex:"COM1","COM2") to which PN54X is
+ * Typically this should be port name (Ex:"COM1","COM2") to which NFCC is
  * connected.
  */
 typedef enum {
diff --git a/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf
index cc42665..98d04c6 100644
--- a/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nci.conf
@@ -114,5 +114,18 @@ NFA_AID_BLOCK_ROUTE=0x00
 # This value indicates the number of time presence check is repeated in case of
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
-
 ###############################################################################
+# Forcing HOST to listen for a selected protocol
+# 0x00 : Disable Host Listen
+# 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
+# 0x02 : Enable Host to Listen (B)  for ISO-DEP tech B
+# 0x04 : Enable Host to Listen (F)  for T3T Tag Type Protocol tech F
+# 0x07 : Enable Host to Listen (ABF)for ISO-DEP tech AB & T3T Tag Type Protocol tech F
+HOST_LISTEN_TECH_MASK=0x07
+###############################################################################
+# Config option to skip ISO15693 GET_SYS_INFO command as NFC forum tool does
+# not support this command
+# 0 to Disable this behaviour
+# 1 to Enable this behaviour
+ISO15693_SKIP_GET_SYS_INFO_CMD=0
+##############################################################################
diff --git a/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nxp-PN557_example.conf b/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nxp-PN557_example.conf
index f47b6b6..d33ab21 100644
--- a/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nxp-PN557_example.conf
+++ b/snxxx/halimpl/conf/PN557/gen-config-files/libnfc-nxp-PN557_example.conf
@@ -182,8 +182,8 @@ DEFAULT_SYS_CODE_ROUTE=0x00
 # bit pos 0 = Switch On
 # bit pos 1 = Switch Off
 # bit pos 2 = Battery Off
-# bit pos 3 = Screen On lock
-# bit pos 4 = Screen off unlock
+# bit pos 3 = Screen off unlock
+# bit pos 4 = Screen On lock
 # bit pos 5 = Screen Off lock
 DEFAULT_AID_PWR_STATE=0x3B
 
@@ -234,10 +234,16 @@ DEFAULT_SYS_CODE_PWR_STATE=0x00
 ###############################################################################
 # Configure the NFC Extras to open and use a static pipe.  If the value is
 # not set or set to 0, then the default is use a dynamic pipe based on a
-# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
-# for each UICC (where F3="UICC0" and F4="UICC1")
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE). Note there is a value
+# for each EE.
 OFF_HOST_ESE_PIPE_ID=0x19
-OFF_HOST_SIM_PIPE_ID=0x0A
+
+###############################################################################
+# Configure the NFC Extras to open and use a static pipe.  If the value is
+# not set or set to 0, then the default is use a dynamic pipe based on a
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
+# for each SIM1, SIM2 etc based on the number of SIM's supported.
+OFF_HOST_SIM_PIPE_IDS={0A}
 
 ###############################################################################
 # Bail out mode
diff --git a/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf
index 21603b2..4f220a4 100644
--- a/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/PN560/gen-config-files/libnfc-nci.conf
@@ -47,11 +47,10 @@ PRESERVE_STORAGE=0x01
 # so that the stack will not wait any longer than necessary.
 
 # Maximum EE supported number
-# NXP PN547C2 0x02
-# NXP PN65T 0x03
-# NXP PN548C2 0x02
-# NXP PN66T 0x03
-NFA_MAX_EE_SUPPORTED=0x03
+# NXP PN557 0x04
+# NXP SN1xx 0x06
+# NXP PN560 0x04
+NFA_MAX_EE_SUPPORTED=0x04
 ##############################################################################
 # Deactivate notification wait time out in seconds used in ETSI Reader mode
 # 0 - Infinite wait
@@ -89,4 +88,17 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
-
+# Forcing HOST to listen for a selected protocol
+# 0x00 : Disable Host Listen
+# 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
+# 0x02 : Enable Host to Listen (B)  for ISO-DEP tech B
+# 0x04 : Enable Host to Listen (F)  for T3T Tag Type Protocol tech F
+# 0x07 : Enable Host to Listen (ABF)for ISO-DEP tech AB & T3T Tag Type Protocol tech F
+HOST_LISTEN_TECH_MASK=0x07
+##############################################################################
+# Config option to skip ISO15693 GET_SYS_INFO command as NFC forum tool does
+# not support this command
+# 0 to Disable this behaviour
+# 1 to Enable this behaviour
+ISO15693_SKIP_GET_SYS_INFO_CMD=0
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf
index 9e3e717..d8eb971 100644
--- a/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nci.conf
@@ -47,11 +47,9 @@ PRESERVE_STORAGE=0x01
 # so that the stack will not wait any longer than necessary.
 
 # Maximum EE supported number
-# NXP PN547C2 0x02
-# NXP PN65T 0x03
-# NXP PN548C2 0x02
-# NXP PN66T 0x03
-NFA_MAX_EE_SUPPORTED=0x03
+# NXP PN557 0x04
+# NXP SN1xx 0x06
+NFA_MAX_EE_SUPPORTED=0x06
 ##############################################################################
 # Deactivate notification wait time out in seconds used in ETSI Reader mode
 # 0 - Infinite wait
@@ -97,4 +95,17 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
-
+# Forcing HOST to listen for a selected protocol
+# 0x00 : Disable Host Listen
+# 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
+# 0x02 : Enable Host to Listen (B)  for ISO-DEP tech B
+# 0x04 : Enable Host to Listen (F)  for T3T Tag Type Protocol tech F
+# 0x07 : Enable Host to Listen (ABF)for ISO-DEP tech AB & T3T Tag Type Protocol tech F
+HOST_LISTEN_TECH_MASK=0x07
+##############################################################################
+# Config option to skip ISO15693 GET_SYS_INFO command as NFC forum tool does
+# not support this command
+# 0 to Disable this behaviour
+# 1 to Enable this behaviour
+ISO15693_SKIP_GET_SYS_INFO_CMD=0
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nxp_AndroidOne.conf b/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nxp_AndroidOne.conf
index 8f8d90a..b6369ca 100644
--- a/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nxp_AndroidOne.conf
+++ b/snxxx/halimpl/conf/SN1xx/sn100/gen-config-files/libnfc-nxp_AndroidOne.conf
@@ -264,11 +264,16 @@ FORWARD_FUNCTIONALITY_ENABLE=0x01
 ###############################################################################
 # Configure the NFC Extras to open and use a static pipe.  If the value is
 # not set or set to 0, then the default is use a dynamic pipe based on a
-# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
-# for each EE (ESE/SIM1/SIM2)
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE). Note there is a value
+# for each EE.
 OFF_HOST_ESE_PIPE_ID=0x16
-OFF_HOST_SIM_PIPE_ID=0x0A
-OFF_HOST_SIM2_PIPE_ID=0x23
+
+###############################################################################
+# Configure the NFC Extras to open and use a static pipe.  If the value is
+# not set or set to 0, then the default is use a dynamic pipe based on a
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
+# for each SIM1, SIM2 etc based on the number of SIM's supported.
+OFF_HOST_SIM_PIPE_IDS={0A:23}
 
 ###############################################################################
 #Set the Felica T3T System Code Power state :
diff --git a/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf
index 9e3e717..d8eb971 100644
--- a/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nci.conf
@@ -47,11 +47,9 @@ PRESERVE_STORAGE=0x01
 # so that the stack will not wait any longer than necessary.
 
 # Maximum EE supported number
-# NXP PN547C2 0x02
-# NXP PN65T 0x03
-# NXP PN548C2 0x02
-# NXP PN66T 0x03
-NFA_MAX_EE_SUPPORTED=0x03
+# NXP PN557 0x04
+# NXP SN1xx 0x06
+NFA_MAX_EE_SUPPORTED=0x06
 ##############################################################################
 # Deactivate notification wait time out in seconds used in ETSI Reader mode
 # 0 - Infinite wait
@@ -97,4 +95,17 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
-
+# Forcing HOST to listen for a selected protocol
+# 0x00 : Disable Host Listen
+# 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
+# 0x02 : Enable Host to Listen (B)  for ISO-DEP tech B
+# 0x04 : Enable Host to Listen (F)  for T3T Tag Type Protocol tech F
+# 0x07 : Enable Host to Listen (ABF)for ISO-DEP tech AB & T3T Tag Type Protocol tech F
+HOST_LISTEN_TECH_MASK=0x07
+##############################################################################
+# Config option to skip ISO15693 GET_SYS_INFO command as NFC forum tool does
+# not support this command
+# 0 to Disable this behaviour
+# 1 to Enable this behaviour
+ISO15693_SKIP_GET_SYS_INFO_CMD=0
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nxp_AndroidOne.conf b/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nxp_AndroidOne.conf
index 8f8d90a..b6369ca 100644
--- a/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nxp_AndroidOne.conf
+++ b/snxxx/halimpl/conf/SN1xx/sn110/gen-config-files/libnfc-nxp_AndroidOne.conf
@@ -264,11 +264,16 @@ FORWARD_FUNCTIONALITY_ENABLE=0x01
 ###############################################################################
 # Configure the NFC Extras to open and use a static pipe.  If the value is
 # not set or set to 0, then the default is use a dynamic pipe based on a
-# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
-# for each EE (ESE/SIM1/SIM2)
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE). Note there is a value
+# for each EE.
 OFF_HOST_ESE_PIPE_ID=0x16
-OFF_HOST_SIM_PIPE_ID=0x0A
-OFF_HOST_SIM2_PIPE_ID=0x23
+
+###############################################################################
+# Configure the NFC Extras to open and use a static pipe.  If the value is
+# not set or set to 0, then the default is use a dynamic pipe based on a
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
+# for each SIM1, SIM2 etc based on the number of SIM's supported.
+OFF_HOST_SIM_PIPE_IDS={0A:23}
 
 ###############################################################################
 #Set the Felica T3T System Code Power state :
diff --git a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf
index 9e3e717..d2c3dd6 100644
--- a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nci.conf
@@ -47,11 +47,10 @@ PRESERVE_STORAGE=0x01
 # so that the stack will not wait any longer than necessary.
 
 # Maximum EE supported number
-# NXP PN547C2 0x02
-# NXP PN65T 0x03
-# NXP PN548C2 0x02
-# NXP PN66T 0x03
-NFA_MAX_EE_SUPPORTED=0x03
+# NXP PN557 0x04
+# NXP SN1xx 0x06
+# NXP SN2xx 0x06
+NFA_MAX_EE_SUPPORTED=0x06
 ##############################################################################
 # Deactivate notification wait time out in seconds used in ETSI Reader mode
 # 0 - Infinite wait
@@ -97,4 +96,17 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
-
+# Forcing HOST to listen for a selected protocol
+# 0x00 : Disable Host Listen
+# 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
+# 0x02 : Enable Host to Listen (B)  for ISO-DEP tech B
+# 0x04 : Enable Host to Listen (F)  for T3T Tag Type Protocol tech F
+# 0x07 : Enable Host to Listen (ABF)for ISO-DEP tech AB & T3T Tag Type Protocol tech F
+HOST_LISTEN_TECH_MASK=0x07
+##############################################################################
+# Config option to skip ISO15693 GET_SYS_INFO command as NFC forum tool does
+# not support this command
+# 0 to Disable this behaviour
+# 1 to Enable this behaviour
+ISO15693_SKIP_GET_SYS_INFO_CMD=0
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf
index c4c8fa8..60df7c0 100644
--- a/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf
+++ b/snxxx/halimpl/conf/SN220/gen-config-files/libnfc-nxp_AndroidOne.conf
@@ -238,6 +238,14 @@ NFA_PROPRIETARY_CFG={05, FF, FF, 06, 81, 80, FF, FF, FF}
 #Disable  0x00
 #NXP_CN_TRANSIT_BLK_NUM_CHECK_ENABLE=0x01
 
+###############################################################################
+#NXP_MIFARE_MUTE_TO_RATS_ENABLE
+#Enable/Disable Mute To RATS
+#Enable   0x01 NFCC stays mute on RATS command when configured with
+#              a non ISODEP SAK
+#Disable  0x00
+#NXP_MIFARE_MUTE_TO_RATS_ENABLE=0x01
+
 ################################################################################
 #This flags will enable different modes of Lx Debug based on bits of the Byte0
 #Byte 0:
@@ -264,11 +272,16 @@ FORWARD_FUNCTIONALITY_ENABLE=0x01
 ###############################################################################
 # Configure the NFC Extras to open and use a static pipe.  If the value is
 # not set or set to 0, then the default is use a dynamic pipe based on a
-# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
-# for each EE (ESE/SIM1/SIM2)
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE). Note there is a value
+# for each EE.
 OFF_HOST_ESE_PIPE_ID=0x16
-OFF_HOST_SIM_PIPE_ID=0x0A
-OFF_HOST_SIM2_PIPE_ID=0x23
+
+###############################################################################
+# Configure the NFC Extras to open and use a static pipe.  If the value is
+# not set or set to 0, then the default is use a dynamic pipe based on a
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
+# for each SIM1, SIM2 etc based on the number of SIM's supported.
+OFF_HOST_SIM_PIPE_IDS={0A:23}
 
 ###############################################################################
 #Set the Felica T3T System Code Power state :
diff --git a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf
index db08ed3..89a0879 100644
--- a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf
+++ b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nci.conf
@@ -52,11 +52,11 @@ PRESERVE_STORAGE=0x01
 # so that the stack will not wait any longer than necessary.
 
 # Maximum EE supported number
-# NXP PN547C2 0x02
-# NXP PN65T 0x03
-# NXP PN548C2 0x02
-# NXP PN66T 0x03
-NFA_MAX_EE_SUPPORTED=0x03
+# NXP PN557 0x04
+# NXP SN1xx 0x06
+# NXP SN2xx 0x06
+# NXP SN3xx 0x06
+NFA_MAX_EE_SUPPORTED=0x06
 ##############################################################################
 # Deactivate notification wait time out in seconds used in ETSI Reader mode
 # 0 - Infinite wait
@@ -102,4 +102,17 @@ NXP_NCI_CREDIT_NTF_TIMEOUT=2
 # failure
 PRESENCE_CHECK_RETRY_COUNT=0
 #########################################################################
-
+# Forcing HOST to listen for a selected protocol
+# 0x00 : Disable Host Listen
+# 0x01 : Enable Host to Listen (A)  for ISO-DEP tech A
+# 0x02 : Enable Host to Listen (B)  for ISO-DEP tech B
+# 0x04 : Enable Host to Listen (F)  for T3T Tag Type Protocol tech F
+# 0x07 : Enable Host to Listen (ABF)for ISO-DEP tech AB & T3T Tag Type Protocol tech F
+HOST_LISTEN_TECH_MASK=0x07
+##############################################################################
+# Config option to skip ISO15693 GET_SYS_INFO command as NFC forum tool does
+# not support this command
+# 0 to Disable this behaviour
+# 1 to Enable this behaviour
+ISO15693_SKIP_GET_SYS_INFO_CMD=0
+##############################################################################
diff --git a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf
index 44bf43e..db6ecde 100644
--- a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf
+++ b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_AndroidOne.conf
@@ -240,6 +240,14 @@ NFA_PROPRIETARY_CFG={05, FF, FF, 06, 81, 80, FF, FF, FF}
 #Disable  0x00
 #NXP_CN_TRANSIT_BLK_NUM_CHECK_ENABLE=0x01
 
+###############################################################################
+#NXP_MIFARE_MUTE_TO_RATS_ENABLE
+#Enable/Disable Mute To RATS
+#Enable   0x01 NFCC stays mute on RATS command when configured with
+#              a non ISODEP SAK
+#Disable  0x00
+#NXP_MIFARE_MUTE_TO_RATS_ENABLE=0x01
+
 ################################################################################
 #This flags will enable different modes of Lx Debug based on bits of the Byte0
 #Byte 0:
@@ -266,11 +274,16 @@ FORWARD_FUNCTIONALITY_ENABLE=0x01
 ###############################################################################
 # Configure the NFC Extras to open and use a static pipe.  If the value is
 # not set or set to 0, then the default is use a dynamic pipe based on a
-# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
-# for each EE (ESE/SIM1/SIM2)
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE). Note there is a value
+# for each EE.
 OFF_HOST_ESE_PIPE_ID=0x16
-OFF_HOST_SIM_PIPE_ID=0x0A
-OFF_HOST_SIM2_PIPE_ID=0x23
+
+###############################################################################
+# Configure the NFC Extras to open and use a static pipe.  If the value is
+# not set or set to 0, then the default is use a dynamic pipe based on a
+# destination gate (see NFA_HCI_DEFAULT_DEST_GATE).  Note there is a value
+# for each SIM1, SIM2 etc based on the number of SIM's supported.
+OFF_HOST_SIM_PIPE_IDS={0A:23}
 
 ###############################################################################
 #Set the Felica T3T System Code Power state :
@@ -487,3 +500,8 @@ NXP_ENABLE_DCDC_ON=1
 # It will lead to mismatch of event's for profiles
 NXP_EXTENDED_FIELD_DETECT_MODE=0x03
 #################################################################################
+# Enable disable support for 4K FW download
+# 0x00 = Disabled
+# 0x01 = Enabled
+NXP_4K_FWDNLD_SUPPORT=1
+###############################################################################
diff --git a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_RF-SN300U_example.conf b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_RF-SN300U_example.conf
index e851d48..3c0d06e 100644
--- a/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_RF-SN300U_example.conf
+++ b/snxxx/halimpl/conf/SN300/gen-config-files/libnfc-nxp_RF-SN300U_example.conf
@@ -14,6 +14,7 @@ NXP_SYS_CLK_SRC_SEL=0x02
 #define CLK_FREQ_52MHZ         6
 #define CLK_FREQ_32MHZ         7
 #define CLK_FREQ_48MHZ         8
+#define CLK_FREQ_76_8MHZ       9
 NXP_SYS_CLK_FREQ_SEL=0x02
 
 ###############################################################################
diff --git a/snxxx/halimpl/dnld/phDnldNfc.cc b/snxxx/halimpl/dnld/phDnldNfc.cc
index 6f98cfc..91a656d 100644
--- a/snxxx/halimpl/dnld/phDnldNfc.cc
+++ b/snxxx/halimpl/dnld/phDnldNfc.cc
@@ -1,5 +1,5 @@
 /*
- *  Copyright 2010-2023 NXP
+ *  Copyright 2010-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -578,6 +578,8 @@ NFCSTATUS phDnldNfc_Force(pphDnldNfc_Buff_t pInputs, pphDnldNfc_RspCb_t pNotify,
             bClkFreq = phDnldNfc_ClkFreq_32Mhz;
           } else if (CLK_FREQ_48MHZ == (pInputs->pBuff[1])) {
             bClkFreq = phDnldNfc_ClkFreq_48Mhz;
+          } else if (CLK_FREQ_76_8MHZ == (pInputs->pBuff[1])) {
+            bClkFreq = phDnldNfc_ClkFreq_76_8Mhz;
           } else {
             NXPLOG_FWDNLD_E(
                 "Invalid Clk Frequency !! Using default value of 19.2Mhz..");
@@ -1199,7 +1201,7 @@ void phDnldNfc_SetDlRspTimeout(uint16_t timeout) {
 *******************************************************************************/
 void phDnldNfc_SetI2CFragmentLength() {
   if (NULL != gpphDnldContext) {
-    if (IS_CHIP_TYPE_EQ(sn300u)) {
+    if (IS_CHIP_TYPE_EQ(sn300u) && IS_4K_SUPPORT) {
       gpphDnldContext->nxp_i2c_fragment_len = PH_TMLNFC_FRGMENT_SIZE_SN300;
     } else if (IS_CHIP_TYPE_GE(sn100u)) {
       gpphDnldContext->nxp_i2c_fragment_len = PH_TMLNFC_FRGMENT_SIZE_SNXXX;
diff --git a/snxxx/halimpl/dnld/phDnldNfc.h b/snxxx/halimpl/dnld/phDnldNfc.h
index d2f0472..9bf8356 100644
--- a/snxxx/halimpl/dnld/phDnldNfc.h
+++ b/snxxx/halimpl/dnld/phDnldNfc.h
@@ -1,5 +1,5 @@
 /*
- *  Copyright 2010-2023 NXP
+ *  Copyright 2010-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -24,7 +24,7 @@
 
 /*
  *
- * Callback for handling the received data/response from PN54X.
+ * Callback for handling the received data/response from NFCC.
  * Parameters to be passed/registered to download context during respective
  * download function call:
  *      pContext - Upper layer context
@@ -86,14 +86,15 @@ typedef enum phDnldNfc_ClkSrc {
  * Enum definition contains Clk Frequency value for Force command request
  */
 typedef enum phDnldNfc_ClkFreq {
-  phDnldNfc_ClkFreq_13Mhz = 0U,   /* 13Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_19_2Mhz = 1U, /* 19.2Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_24Mhz = 2U,   /* 24Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_26Mhz = 3U,   /* 26Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_38_4Mhz = 4U, /* 38.4Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_52Mhz = 5U,   /* 52Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_32Mhz = 6U,   /* 32Mhz Clk Frequency */
-  phDnldNfc_ClkFreq_48Mhz = 0x0AU /* 48Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_13Mhz = 0U,     /* 13Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_19_2Mhz = 1U,   /* 19.2Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_24Mhz = 2U,     /* 24Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_26Mhz = 3U,     /* 26Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_38_4Mhz = 4U,   /* 38.4Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_52Mhz = 5U,     /* 52Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_32Mhz = 6U,     /* 32Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_48Mhz = 0x0AU,  /* 48Mhz Clk Frequency */
+  phDnldNfc_ClkFreq_76_8Mhz = 0x0BU /* 76.8Mhz Clk Frequency */
 } phDnldNfc_ClkFreq_t;
 
 /*
diff --git a/snxxx/halimpl/dnld/phDnldNfc_Internal.cc b/snxxx/halimpl/dnld/phDnldNfc_Internal.cc
index afbd28e..01c28e2 100644
--- a/snxxx/halimpl/dnld/phDnldNfc_Internal.cc
+++ b/snxxx/halimpl/dnld/phDnldNfc_Internal.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2010-2023 NXP
+ * Copyright (C) 2010-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -982,6 +982,25 @@ static NFCSTATUS phDnldNfc_SetupResendTimer(pphDnldNfc_DlContext_t pDlContext) {
 #error PH_LIBNFC_VEN_RESET_ON_DOWNLOAD_TIMEOUT has to be defined
 #endif
 
+/*******************************************************************************
+**
+** Function         phDnldNfc_accessStatusWithLock
+**
+** Description      This function setting timer status after specific mutex lock
+**                  based on current event.
+**
+** Parameters       pDlContext - pointer to the download context structure
+**                  seqStateLock - Mutex to lock based on event.
+**
+** Returns          None
+**
+*******************************************************************************/
+static void phDnldNfc_accessStatusWithLock(pphDnldNfc_DlContext_t pDlCtxt,
+                                           NfcHalThreadMutex seqStateLock) {
+  NfcHalAutoThreadMutex a(seqStateLock);
+  (pDlCtxt->TimerInfo.wTimerExpStatus) = NFCSTATUS_RF_TIMEOUT;
+}
+
 /*******************************************************************************
 **
 ** Function         phDnldNfc_RspTimeOutCb
@@ -1016,12 +1035,12 @@ static void phDnldNfc_RspTimeOutCb(uint32_t TimerId, void* pContext) {
       }
 #endif
 
-      (pDlCtxt->TimerInfo.wTimerExpStatus) = NFCSTATUS_RF_TIMEOUT;
-
       if ((phDnldNfc_EventRead == pDlCtxt->tCurrEvent) ||
           (phDnldNfc_EventWrite == pDlCtxt->tCurrEvent)) {
+        phDnldNfc_accessStatusWithLock(pDlCtxt, sProcessRwSeqStateLock);
         phDnldNfc_ProcessRWSeqState(pDlCtxt, NULL);
       } else {
+        phDnldNfc_accessStatusWithLock(pDlCtxt, sProcessSeqStateLock);
         phDnldNfc_ProcessSeqState(pDlCtxt, NULL);
       }
     }
@@ -1052,10 +1071,12 @@ static void phDnldNfc_ResendTimeOutCb(uint32_t TimerId, void* pContext) {
     if (1 == pDlCtxt->TimerInfo.TimerStatus) {
       /* No response received and the timer expired */
       pDlCtxt->TimerInfo.TimerStatus = 0; /* Reset timer status flag */
+      {
+        NfcHalAutoThreadMutex a(sProcessRwSeqStateLock);
+        (pDlCtxt->TimerInfo.wTimerExpStatus) = 0;
 
-      (pDlCtxt->TimerInfo.wTimerExpStatus) = 0;
-
-      pDlCtxt->tCurrState = phDnldNfc_StateSend;
+        pDlCtxt->tCurrState = phDnldNfc_StateSend;
+      }
 
       /* set the flag to trigger last frame re-transmission */
       pDlCtxt->bResendLastFrame = true;
diff --git a/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc b/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc
index 771ce0e..6d51f89 100644
--- a/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc
+++ b/snxxx/halimpl/dnld/phNxpNciHal_Dnld.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2023 NXP
+ * Copyright 2012-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -1824,8 +1824,8 @@ static NFCSTATUS phNxpNciHal_releasePendingRead() {
                       sizeof(nfc_dev_node))) {
     NXPLOG_FWDNLD_D(
         "Invalid nfc device node name keeping the default device node "
-        "/dev/pn54x");
-    strlcpy(nfc_dev_node, "/dev/pn54x", (sizeof(nfc_dev_node)));
+        "/dev/nxp-nci");
+    strlcpy(nfc_dev_node, "/dev/nxp-nci", (sizeof(nfc_dev_node)));
   }
   tTmlConfig.pDevName = (int8_t*)nfc_dev_node;
   gpTransportObj->Close(gpphTmlNfc_Context->pDevHandle);
diff --git a/snxxx/halimpl/hal/phNxpNciHal.cc b/snxxx/halimpl/hal/phNxpNciHal.cc
index 3ac8ef6..10dc05b 100644
--- a/snxxx/halimpl/hal/phNxpNciHal.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2023 NXP
+ * Copyright 2012-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -42,6 +42,7 @@
 #include "phNxpNciHal_LxDebug.h"
 #include "phNxpNciHal_PowerTrackerIface.h"
 #include "phNxpNciHal_ULPDet.h"
+#include "phNxpNciHal_VendorProp.h"
 #include "phNxpNciHal_extOperations.h"
 
 using android::base::StringPrintf;
@@ -53,6 +54,8 @@ using android::base::WriteStringToFile;
 #define MAX_NXP_HAL_EXTN_BYTES 10
 #define DEFAULT_MINIMAL_FW_VERSION 0x0110DE
 #define EOS_FW_SESSION_STATE_LOCKED 0x02
+#define NS_PER_S 1000000000
+#define MAX_WAIT_MS_FOR_RESET_NTF 1600
 
 bool bEnableMfcExtns = false;
 bool bEnableMfcReader = false;
@@ -67,10 +70,12 @@ static const char* rf_block_num[] = {
     "23", "24", "25", "26", "27", "28", "29", "30", NULL};
 const char* rf_block_name = "NXP_RF_CONF_BLK_";
 static uint8_t read_failed_disable_nfc = false;
+const char* core_reset_ntf_count_prop_name = "nfc.core_reset_ntf_count";
 /* FW download success flag */
 static uint8_t fw_download_success = 0;
 static uint8_t config_access = false;
 static uint8_t config_success = true;
+static bool sIsHalOpenErrorRecovery = false;
 NfcHalThreadMutex sHalFnLock;
 
 /* NCI HAL Control structure */
@@ -114,7 +119,7 @@ uint8_t fw_dwnld_flag = false;
 #endif
 bool nfc_debug_enabled = true;
 PowerTrackerHandle gPowerTrackerHandle;
-
+sem_t sem_reset_ntf_received;
 /*  Used to send Callback Transceive data during Mifare Write.
  *  If this flag is enabled, no need to send response to Upper layer */
 bool sendRspToUpperLayer = true;
@@ -123,7 +128,7 @@ phNxpNciHal_Sem_t config_data;
 
 phNxpNciClock_t phNxpNciClock = {0, {0}, false};
 
-phNxpNciRfSetting_t phNxpNciRfSet = {false, {0}};
+phNxpNciRfSetting_t phNxpNciRfSet = {false, vector<uint8_t>{}};
 
 phNxpNciMwEepromArea_t phNxpNciMwEepromArea = {false, {0}};
 
@@ -175,6 +180,7 @@ static NFCSTATUS phNxpNciHal_getChipInfoInFwDnldMode(
 static uint8_t phNxpNciHal_getSessionInfoInFwDnldMode();
 static NFCSTATUS phNxpNciHal_dlResetInFwDnldMode();
 static NFCSTATUS phNxpNciHal_enableTmlRead();
+static void phNxpNciHal_check_and_recover_fw();
 
 /******************************************************************************
  * Function         onLoadLibrary
@@ -353,6 +359,15 @@ void* phNxpNciHal_client_thread(void* arg) {
         REENTRANCE_UNLOCK();
         break;
       }
+      case NCI_HAL_VENDOR_MSG: {
+        REENTRANCE_LOCK();
+        if (nxpncihal_ctrl.p_nfc_stack_data_cback != NULL) {
+          (*nxpncihal_ctrl.p_nfc_stack_data_cback)(
+              nxpncihal_ctrl.vendor_msg_len, nxpncihal_ctrl.vendor_msg);
+        }
+        REENTRANCE_UNLOCK();
+        break;
+      }
       case HAL_NFC_FW_UPDATE_STATUS_EVT: {
         REENTRANCE_LOCK();
         if (nxpncihal_ctrl.p_nfc_stack_cback != NULL) {
@@ -486,7 +501,7 @@ static NFCSTATUS phNxpNciHal_force_fw_download(uint8_t seq_handler_offset,
 /******************************************************************************
  * Function         phNxpNciHal_fw_download
  *
- * Description      This function download the PN54X secure firmware to IC. If
+ * Description      This function download the NFCC secure firmware to IC. If
  *                  firmware version in Android filesystem and firmware in the
  *                  IC is same then firmware download will return with success
  *                  without downloading the firmware.
@@ -687,6 +702,7 @@ int phNxpNciHal_MinOpen() {
   NFCSTATUS wConfigStatus = NFCSTATUS_SUCCESS;
   NFCSTATUS status = NFCSTATUS_SUCCESS;
   int dnld_retry_cnt = 0;
+  sIsHalOpenErrorRecovery = false;
   NXPLOG_NCIHAL_D("phNxpNci_MinOpen(): enter");
 
   if (nxpncihal_ctrl.halStatus == HAL_STATUS_MIN_OPEN) {
@@ -738,12 +754,12 @@ int phNxpNciHal_MinOpen() {
   } else if (!GetNxpStrValue(NAME_NXP_NFC_DEV_NODE, nfc_dev_node, max_len)) {
     NXPLOG_NCIHAL_D(
         "Invalid nfc device node name keeping the default device node "
-        "/dev/pn54x");
-    strlcpy(nfc_dev_node, "/dev/pn54x", (max_len * sizeof(char)));
+        "/dev/nxp-nci");
+    strlcpy(nfc_dev_node, "/dev/nxp-nci", (max_len * sizeof(char)));
   }
   /* Configure hardware link */
   nxpncihal_ctrl.gDrvCfg.nClientId = phDal4Nfc_msgget(0, 0600);
-  nxpncihal_ctrl.gDrvCfg.nLinkType = ENUM_LINK_TYPE_I2C; /* For PN54X */
+  nxpncihal_ctrl.gDrvCfg.nLinkType = ENUM_LINK_TYPE_I2C; /* For NFCC */
   tTmlConfig.pDevName = (int8_t*)nfc_dev_node;
   tOsalConfig.dwCallbackThreadId = (uintptr_t)nxpncihal_ctrl.gDrvCfg.nClientId;
   tOsalConfig.pLogFile = NULL;
@@ -781,6 +797,10 @@ int phNxpNciHal_MinOpen() {
   }
 
   CONCURRENCY_UNLOCK();
+  if (sem_init(&sem_reset_ntf_received, 0, 0) != 0) {
+    NXPLOG_NCIHAL_E("%s : sem_init for sem_reset_ntf_received failed",
+                    __func__);
+  }
   /* call read pending */
   status = phTmlNfc_Read(
       nxpncihal_ctrl.p_rsp_data, NCI_MAX_DATA_LEN,
@@ -798,7 +818,7 @@ int phNxpNciHal_MinOpen() {
   if (GetNxpNumValue(NAME_NXP_NFC_CHIP, &chipInfo, sizeof(chipInfo))) {
     NXPLOG_NCIHAL_D("The chip type is %lx", chipInfo);
   }
-
+  phNxpNciHal_check_and_recover_fw();
   if (gsIsFirstHalMinOpen) {
     /*Skip get version command for pn557*/
     if (chipInfo != pn557) phNxpNciHal_CheckAndHandleFwTearDown();
@@ -857,9 +877,13 @@ int phNxpNciHal_MinOpen() {
         phDnldNfc_ReSetHwDevHandle();
       }
     }
-  } else if (bVenResetRequired) {
-    if (NFCSTATUS_SUCCESS == phNxpNciHal_getChipInfoInFwDnldMode(true))
-      bIsNfccDlState = true;
+  } else {
+    NXPLOG_NCIHAL_E("Communication error, Need FW Recovery and Config Update");
+    sIsHalOpenErrorRecovery = true;
+    if (bVenResetRequired) {
+      if (NFCSTATUS_SUCCESS == phNxpNciHal_getChipInfoInFwDnldMode(true))
+        bIsNfccDlState = true;
+    }
   }
 
   if (gsIsFirstHalMinOpen && gsIsFwRecoveryRequired) {
@@ -892,6 +916,12 @@ int phNxpNciHal_MinOpen() {
     } else if (status != NFCSTATUS_SUCCESS) {
       return phNxpNciHal_MinOpen_Clean(nfc_dev_node);
     } else {
+      if (sIsHalOpenErrorRecovery) {
+        NXPLOG_NCIHAL_D(
+            "Applying config settings as FW download recovery done");
+        phNxpNciHal_core_initialized();
+        sIsHalOpenErrorRecovery = false;
+      }
       break;
     }
 
@@ -906,6 +936,11 @@ int phNxpNciHal_MinOpen() {
       (gsIsFirstHalMinOpen || fw_download_success)) {
     fpDoAntennaActivity(ANTENNA_CHECK_STATUS);
   }
+  /* if MinOpen exit gracefully there is no core reset ntf issue */
+  if (NFCSTATUS_SUCCESS !=
+      phNxpNciHal_setVendorProp(core_reset_ntf_count_prop_name, "0")) {
+    NXPLOG_NCIHAL_E("setting core_reset_ntf_count_prop failed");
+  }
   /* Call open complete */
   phNxpNciHal_MinOpen_complete(wConfigStatus);
   NXPLOG_NCIHAL_D("phNxpNciHal_MinOpen(): exit");
@@ -917,7 +952,7 @@ int phNxpNciHal_MinOpen() {
  *
  * Description      This function is called by libnfc-nci during the
  *                  initialization of the NFCC. It opens the physical connection
- *                  with NFCC (PN54X) and creates required client thread for
+ *                  with NFCC and creates required client thread for
  *                  operation.
  *                  After open is complete, status is informed to libnfc-nci
  *                  through callback function.
@@ -1071,7 +1106,7 @@ static void phNxpNciHal_open_complete(NFCSTATUS status) {
 
   if (status == NFCSTATUS_SUCCESS) {
     msg.eMsgType = NCI_HAL_OPEN_CPLT_MSG;
-    nxpncihal_ctrl.hal_open_status = true;
+    nxpncihal_ctrl.hal_open_status = HAL_OPENED;
     nxpncihal_ctrl.halStatus = HAL_STATUS_OPEN;
   } else {
     msg.eMsgType = NCI_HAL_ERROR_MSG;
@@ -1090,7 +1125,7 @@ static void phNxpNciHal_open_complete(NFCSTATUS status) {
  * Function         phNxpNciHal_write
  *
  * Description      This function write the data to NFCC through physical
- *                  interface (e.g. I2C) using the PN54X driver interface.
+ *                  interface (e.g. I2C) using the NFCC driver interface.
  *                  Before sending the data to NFCC, phNxpNciHal_write_ext
  *                  is called to check if there is any extension processing
  *                  is required for the NCI packet being sent out.
@@ -1110,6 +1145,16 @@ int phNxpNciHal_write(uint16_t data_len, const uint8_t* p_data) {
     vector<uint8_t> v_data = builder.reConfigRFDiscCmd(data_len, p_data);
     return phNxpNciHal_write_internal(v_data.size(), v_data.data());
   }
+  long value = 0;
+  /* NXP Removal Detection timeout Config */
+  if (GetNxpNumValue(NAME_NXP_REMOVAL_DETECTION_TIMEOUT, (void*)&value,
+                     sizeof(value))) {
+    // Change the timeout value as per config file
+    uint8_t* wait_time = (uint8_t*)&p_data[3];
+    if ((data_len == 0x04) && (p_data[0] == 0x21 && p_data[1] == 0x12)) {
+      *wait_time = value;
+    }
+  }
   return phNxpNciHal_write_internal(data_len, p_data);
 }
 
@@ -1117,7 +1162,7 @@ int phNxpNciHal_write(uint16_t data_len, const uint8_t* p_data) {
  * Function         phNxpNciHal_write_internal
  *
  * Description      This function write the data to NFCC through physical
- *                  interface (e.g. I2C) using the PN54X driver interface.
+ *                  interface (e.g. I2C) using the NFCC driver interface.
  *                  Before sending the data to NFCC, phNxpNciHal_write_ext
  *                  is called to check if there is any extension processing
  *                  is required for the NCI packet being sent out.
@@ -1147,7 +1192,7 @@ int phNxpNciHal_write_internal(uint16_t data_len, const uint8_t* p_data) {
       phNxpNciHal_write_ext(&nxpncihal_ctrl.cmd_len, nxpncihal_ctrl.p_cmd_data,
                             &nxpncihal_ctrl.rsp_len, nxpncihal_ctrl.p_rsp_data);
   if (status != NFCSTATUS_SUCCESS) {
-    /* Do not send packet to PN54X, send response directly */
+    /* Do not send packet to NFCC, send response directly */
     msg.eMsgType = NCI_HAL_RX_MSG;
     msg.pMsgData = NULL;
     msg.Size = 0;
@@ -1243,25 +1288,25 @@ retry:
     data_len = 0;
     if (nxpncihal_ctrl.retry_cnt++ < MAX_RETRY_COUNT) {
       NXPLOG_NCIHAL_D(
-          "write_unlocked failed - PN54X Maybe in Standby Mode - Retry");
+          "write_unlocked failed - NFCC Maybe in Standby Mode - Retry");
       /* 10ms delay to give NFCC wake up delay */
       usleep(1000 * 10);
       goto retry;
     } else {
       NXPLOG_NCIHAL_E(
-          "write_unlocked failed - PN54X Maybe in Standby Mode (max count = "
+          "write_unlocked failed - NFCC Maybe in Standby Mode (max count = "
           "0x%x)",
           nxpncihal_ctrl.retry_cnt);
 
       status = phTmlNfc_IoCtl(phTmlNfc_e_ResetDevice);
 
       if (NFCSTATUS_SUCCESS == status) {
-        NXPLOG_NCIHAL_D("PN54X Reset - SUCCESS\n");
+        NXPLOG_NCIHAL_D("NFCC Reset - SUCCESS\n");
       } else {
-        NXPLOG_NCIHAL_D("PN54X Reset - FAILED\n");
+        NXPLOG_NCIHAL_D("NFCC Reset - FAILED\n");
       }
       if (nxpncihal_ctrl.p_nfc_stack_data_cback != NULL &&
-          nxpncihal_ctrl.hal_open_status == true) {
+          nxpncihal_ctrl.hal_open_status != HAL_CLOSED) {
         if (nxpncihal_ctrl.p_rx_data != NULL) {
           NXPLOG_NCIHAL_D(
               "Send the Core Reset NTF to upper layer, which will trigger the "
@@ -1504,7 +1549,7 @@ NFCSTATUS phNxpNciHal_enableTmlRead() {
  * Function         phNxpNciHal_core_initialized
  *
  * Description      This function is called by libnfc-nci after successful open
- *                  of NFCC. All proprietary setting for PN54X are done here.
+ *                  of NFCC. All proprietary setting for NFCC are done here.
  *                  After completion of proprietary settings notification is
  *                  provided to libnfc-nci through callback function.
  *
@@ -1551,6 +1596,7 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
   if (nxpncihal_ctrl.halStatus != HAL_STATUS_OPEN) {
     return NFCSTATUS_FAILED;
   }
+  nxpncihal_ctrl.hal_open_status = HAL_OPEN_CORE_INITIALIZING;
   if (core_init_rsp_params_len >= 1 && (*p_core_init_rsp_params > 0) &&
       (*p_core_init_rsp_params < 4))  // initializing for recovery.
   {
@@ -1564,14 +1610,15 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
       buffer = NULL;
     }
     if (retry_core_init_cnt > 3) {
+      nxpncihal_ctrl.hal_open_status = HAL_OPENED;
       return NFCSTATUS_FAILED;
     }
     if (IS_CHIP_TYPE_L(sn100u)) {
       status = phTmlNfc_IoCtl(phTmlNfc_e_ResetDevice);
       if (NFCSTATUS_SUCCESS == status) {
-        NXPLOG_NCIHAL_D("PN54X Reset - SUCCESS\n");
+        NXPLOG_NCIHAL_D("NFCC Reset - SUCCESS\n");
       } else {
-        NXPLOG_NCIHAL_D("PN54X Reset - FAILED\n");
+        NXPLOG_NCIHAL_D("NFCC Reset - FAILED\n");
       }
     }
 
@@ -1603,6 +1650,7 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
 
   buffer = (uint8_t*)malloc(bufflen * sizeof(uint8_t));
   if (NULL == buffer) {
+    nxpncihal_ctrl.hal_open_status = HAL_OPENED;
     return NFCSTATUS_FAILED;
   }
   config_access = true;
@@ -1664,6 +1712,9 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
   }
 
   if (IS_CHIP_TYPE_EQ(pn557)) enable_ven_cfg = PN557_VEN_CFG_DEFAULT;
+  if (IS_CHIP_TYPE_GE(sn220u) && phNxpNciHal_isULPDetSupported()) {
+    enable_ven_cfg = 0x00;
+  }
 
   mEEPROM_info.buffer = &enable_ven_cfg;
   mEEPROM_info.bufflen = sizeof(uint8_t);
@@ -2097,7 +2148,10 @@ int phNxpNciHal_core_initialized(uint16_t core_init_rsp_params_len,
   gRecFWDwnld = 0;
   gRecFwRetryCount = 0;
 
-  phNxpNciHal_core_initialized_complete(status);
+  // Callback not needed for config applying in error recovery
+  if (!sIsHalOpenErrorRecovery) {
+    phNxpNciHal_core_initialized_complete(status);
+  }
   if (isNxpConfigModified()) {
     updateNxpConfigTimestamp();
   }
@@ -2183,6 +2237,7 @@ NFCSTATUS phNxpNciHalRFConfigCmdRecSequence() {
 static void phNxpNciHal_core_initialized_complete(NFCSTATUS status) {
   static phLibNfc_Message_t msg;
 
+  nxpncihal_ctrl.hal_open_status = HAL_OPENED;
   if (status == NFCSTATUS_SUCCESS) {
     msg.eMsgType = NCI_HAL_POST_INIT_CPLT_MSG;
   } else {
@@ -2399,7 +2454,7 @@ close_and_return:
       }
     }
   }
-
+  sem_destroy(&sem_reset_ntf_received);
   sem_destroy(&nxpncihal_ctrl.syncSpiNfc);
 
   if (NULL != gpphTmlNfc_Context->pDevHandle) {
@@ -2456,7 +2511,7 @@ void phNxpNciHal_close_complete(NFCSTATUS status) {
   }
   msg.pMsgData = NULL;
   msg.Size = 0;
-  nxpncihal_ctrl.hal_open_status = false;
+  nxpncihal_ctrl.hal_open_status = HAL_CLOSED;
   phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId, &msg);
 
   return;
@@ -2509,6 +2564,14 @@ int phNxpNciHal_configDiscShutdown(void) {
       NXPLOG_NCIHAL_E("Updation of the SRAM contents failed");
     }
   }
+  if (IS_CHIP_TYPE_GE(sn220u)) {
+    if (phNxpNciHal_isULPDetSupported() &&
+        phNxpNciHal_getULPDetFlag() == false) {
+      NXPLOG_NCIHAL_D("Ulpdet supported");
+      status = phNxpNciHal_propConfULPDetMode(true);
+      return status;
+    }
+  }
   status = phNxpNciHal_send_ext_cmd(sizeof(cmd_ce_disc_nci), cmd_ce_disc_nci);
   if (status != NFCSTATUS_SUCCESS) {
     NXPLOG_NCIHAL_E("CMD_CE_DISC_NCI: Failed");
@@ -2625,9 +2688,9 @@ int phNxpNciHal_power_cycle(void) {
   status = phTmlNfc_IoCtl(phTmlNfc_e_PowerReset);
 
   if (NFCSTATUS_SUCCESS == status) {
-    NXPLOG_NCIHAL_D("PN54X Reset - SUCCESS\n");
+    NXPLOG_NCIHAL_D("NFCC Reset - SUCCESS\n");
   } else {
-    NXPLOG_NCIHAL_D("PN54X Reset - FAILED\n");
+    NXPLOG_NCIHAL_D("NFCC Reset - FAILED\n");
   }
 
   phNxpNciHal_power_cycle_complete(NFCSTATUS_SUCCESS);
@@ -2700,7 +2763,7 @@ int phNxpNciHal_check_ncicmd_write_window(uint16_t cmd_len, uint8_t* p_cmd) {
  * Function         phNxpNciHal_ioctl
  *
  * Description      This function is called by jni when wired mode is
- *                  performed.First Pn54x driver will give the access
+ *                  performed.First NFCC driver will give the access
  *                  permission whether wired mode is allowed or not
  *                  arg (0):
  * Returns          return 0 on success and -1 on fail, On success
@@ -2761,7 +2824,7 @@ static void phNxpNciHal_nfccClockCfgRead(void) {
     nxpprofile_ctrl.bClkSrcVal = NXP_SYS_CLK_SRC_SEL;
   }
   if ((nxpprofile_ctrl.bClkFreqVal < CLK_FREQ_13MHZ) ||
-      (nxpprofile_ctrl.bClkFreqVal > CLK_FREQ_48MHZ)) {
+      (nxpprofile_ctrl.bClkFreqVal > CLK_FREQ_76_8MHZ)) {
     NXPLOG_FWDNLD_E(
         "Clock frequency value is wrong in config file, setting it as default");
     nxpprofile_ctrl.bClkFreqVal = NXP_SYS_CLK_FREQ_SEL;
@@ -2808,6 +2871,8 @@ int phNxpNciHal_determineConfiguredClockSrc() {
       param_clock_src |= 0x06;
     } else if (nxpprofile_ctrl.bClkFreqVal == CLK_FREQ_48MHZ) {
       param_clock_src |= 0x0A;
+    } else if (nxpprofile_ctrl.bClkFreqVal == CLK_FREQ_76_8MHZ) {
+      param_clock_src |= 0x0B;
     } else {
       NXPLOG_NCIHAL_E("Wrong clock freq, send default PLL@19.2MHz");
       if (IS_CHIP_TYPE_L(sn100u))
@@ -3039,15 +3104,11 @@ retry_send_ext:
  ******************************************************************************/
 NFCSTATUS phNxpNciHal_china_tianjin_rf_setting(void) {
   NFCSTATUS status = NFCSTATUS_SUCCESS;
-  int isfound = 0;
-  unsigned long config_value = 0;
-  int rf_val = 0;
-  int flag_send_tianjin_config = true;
-  int flag_send_transit_config = true;
-  int flag_send_cmabypass_config = true;
-  int flag_send_mfc_rf_setting_config = true;
+  const int GET_CONFIG_STATUS_INDEX = 3;
+  const int GET_CONFIG_RF_MISC_TAG_START_INDEX = 5;
+  const int GET_CONFIG_RF_MISC_TAG_NUM_OF_BYTES = 7;
+
   uint8_t retry_cnt = 0;
-  int enable_bit = 0;
 
   static uint8_t get_rf_cmd[] = {0x20, 0x03, 0x03, 0x01, 0xA0, 0x85};
   NXPLOG_NCIHAL_D("phNxpNciHal_china_tianjin_rf_setting - Enter");
@@ -3066,108 +3127,29 @@ retry_send_ext:
     goto retry_send_ext;
   }
   phNxpNciRfSet.isGetRfSetting = false;
-  if (phNxpNciRfSet.p_rx_data[3] != 0x00) {
+  if ((int)phNxpNciRfSet.p_rx_data.size() <= GET_CONFIG_STATUS_INDEX ||
+      ((int)phNxpNciRfSet.p_rx_data.size() > GET_CONFIG_STATUS_INDEX &&
+       phNxpNciRfSet.p_rx_data[GET_CONFIG_STATUS_INDEX] != 0x00)) {
     NXPLOG_NCIHAL_E("GET_CONFIG_RSP is FAILED for CHINA TIANJIN");
     return status;
   }
 
-  /* check if tianjin_rf_setting is required */
-  rf_val = phNxpNciRfSet.p_rx_data[10];
-  isfound = (GetNxpNumValue(NAME_NXP_CHINA_TIANJIN_RF_ENABLED,
-                            (void*)&config_value, sizeof(config_value)));
-  if (isfound > 0) {
-    enable_bit = rf_val & 0x40;
-    if (nfcFL.nfccFL._NFCC_MIFARE_TIANJIN) {
-      if ((enable_bit != 0x40) && (config_value == 1)) {
-        phNxpNciRfSet.p_rx_data[10] |= 0x40;  // Enable if it is disabled
-      } else if ((enable_bit == 0x40) && (config_value == 0)) {
-        phNxpNciRfSet.p_rx_data[10] &= 0xBF;  // Disable if it is Enabled
-      } else {
-        flag_send_tianjin_config = false;  // No need to change in RF setting
-      }
-    } else {
-      enable_bit = phNxpNciRfSet.p_rx_data[11] & 0x10;
-      if ((config_value == 1) && (enable_bit != 0x10)) {
-        NXPLOG_NCIHAL_E("Setting Non-Mifare reader for china tianjin");
-        phNxpNciRfSet.p_rx_data[11] |= 0x10;
-      } else if ((config_value == 0) && (enable_bit == 0x10)) {
-        NXPLOG_NCIHAL_E("Setting Non-Mifare reader for china tianjin");
-        phNxpNciRfSet.p_rx_data[11] &= 0xEF;
-      } else {
-        flag_send_tianjin_config = false;
-      }
-    }
-  } else {
-    flag_send_tianjin_config = false;
-  }
-
-  config_value = 0;
-  /*check MFC NACK settings*/
-  rf_val = phNxpNciRfSet.p_rx_data[9];
-  isfound = (GetNxpNumValue(NAME_NXP_MIFARE_NACK_TO_RATS_ENABLE,
-                            (void*)&config_value, sizeof(config_value)));
-  if (isfound > 0) {
-    enable_bit = rf_val & 0x20;
-    if ((enable_bit != 0x20) && (config_value == 1)) {
-      phNxpNciRfSet.p_rx_data[9] |= 0x20;  // Enable if it is disabled
-    } else if ((enable_bit == 0x20) && (config_value == 0)) {
-      phNxpNciRfSet.p_rx_data[9] &= ~0x20;  // Disable if it is Enabled
-    } else {
-      flag_send_mfc_rf_setting_config =
-          false;  // No need to change in RF setting
-    }
-  } else {
-    flag_send_mfc_rf_setting_config = FALSE;  // No need to change in RF setting
-  }
-
-  config_value = 0;
-  /*check if china block number check is required*/
-  rf_val = phNxpNciRfSet.p_rx_data[8];
-  isfound = (GetNxpNumValue(NAME_NXP_CHINA_BLK_NUM_CHK_ENABLE,
-                            (void*)&config_value, sizeof(config_value)));
-  if (isfound > 0) {
-    enable_bit = rf_val & 0x40;
-    if ((enable_bit != 0x40) && (config_value == 1)) {
-      phNxpNciRfSet.p_rx_data[8] |= 0x40;  // Enable if it is disabled
-    } else if ((enable_bit == 0x40) && (config_value == 0)) {
-      phNxpNciRfSet.p_rx_data[8] &= ~0x40;  // Disable if it is Enabled
-    } else {
-      flag_send_transit_config = false;  // No need to change in RF setting
-    }
-  } else {
-    flag_send_transit_config = FALSE;  // No need to change in RF setting
-  }
+  bool isUpdateRequired = phNxpNciHal_UpdateRfMiscSettings();
 
-  config_value = 0;
-  isfound = (GetNxpNumValue(NAME_NXP_CN_TRANSIT_CMA_BYPASSMODE_ENABLE,
-                            (void*)&config_value, sizeof(config_value)));
-  if (isfound > 0) {
-    if (config_value == 0 && ((phNxpNciRfSet.p_rx_data[10] & 0x80) == 0x80)) {
-      NXPLOG_NCIHAL_D("Disable CMA_BYPASSMODE Supports EMVCo PICC Complaincy");
-      phNxpNciRfSet.p_rx_data[10] &=
-          ~0x80;  // set 24th bit of RF MISC SETTING to 0 for EMVCo PICC
-                  // Complaincy support
-    } else if (config_value == 1 &&
-               ((phNxpNciRfSet.p_rx_data[10] & 0x80) == 0)) {
-      NXPLOG_NCIHAL_D(
-          "Enable CMA_BYPASSMODE bypass the ISO14443-3A state machine from "
-          "READY to ACTIVE and backward compatibility with MIfrae Reader ");
-      phNxpNciRfSet.p_rx_data[10] |=
-          0x80;  // set 24th bit of RF MISC SETTING to 1 for backward
-                 // compatibility with MIfrae Reader
+  if (isUpdateRequired) {
+    vector<uint8_t> set_rf_cmd = {0x20, 0x02, 0x08, 0x01};
+    if ((int)phNxpNciRfSet.p_rx_data.size() >=
+        (GET_CONFIG_RF_MISC_TAG_START_INDEX +
+         GET_CONFIG_RF_MISC_TAG_NUM_OF_BYTES)) {
+      set_rf_cmd.insert(
+          set_rf_cmd.end(),
+          phNxpNciRfSet.p_rx_data.begin() + GET_CONFIG_RF_MISC_TAG_START_INDEX,
+          phNxpNciRfSet.p_rx_data.begin() + GET_CONFIG_RF_MISC_TAG_START_INDEX +
+              GET_CONFIG_RF_MISC_TAG_NUM_OF_BYTES);
+      status = phNxpNciHal_send_ext_cmd(set_rf_cmd.size(), set_rf_cmd.data());
     } else {
-      flag_send_cmabypass_config = FALSE;  // No need to change in RF setting
+      status = NFCSTATUS_FAILED;
     }
-  } else {
-    flag_send_cmabypass_config = FALSE;
-  }
-
-  if (flag_send_tianjin_config || flag_send_transit_config ||
-      flag_send_cmabypass_config || flag_send_mfc_rf_setting_config) {
-    static uint8_t set_rf_cmd[] = {0x20, 0x02, 0x08, 0x01, 0xA0, 0x85,
-                                   0x04, 0x50, 0x08, 0x68, 0x00};
-    memcpy(&set_rf_cmd[4], &phNxpNciRfSet.p_rx_data[5], 7);
-    status = phNxpNciHal_send_ext_cmd(sizeof(set_rf_cmd), set_rf_cmd);
     if (status != NFCSTATUS_SUCCESS) {
       NXPLOG_NCIHAL_E("unable to set the RF setting");
       retry_cnt++;
@@ -3178,6 +3160,86 @@ retry_send_ext:
   return status;
 }
 
+/******************************************************************************
+ * Function         phNxpNciHal_UpdateRfMiscSettings
+ *
+ * Description      This will look the configuration properties and
+ *                  update the RF misc settings
+ *
+ * Returns          bool - true if the RF Misc settings update required
+ *                      otherwise false
+ *
+ ******************************************************************************/
+bool phNxpNciHal_UpdateRfMiscSettings() {
+  vector<phRfMiscSettings> settings;
+
+  const int MISC_CHINA_BLK_INDEX = 8;
+  const int MISC_MIFARE_CONFIG_RATS_INDEX = 9;
+  const int MISC_TIANJIN_RF_INDEX = 11;
+  const int MISC_CN_TRANSIT_CMA_INDEX = 10;
+  const int MISC_TIANJIN_RF_INDEX_PN557 = 10;
+  const uint8_t MISC_TIANJIN_RF_BITMASK = 0x10;
+  const uint8_t MISC_TIANJIN_RF_BITMASK_PN557 = 0x40;
+  const uint8_t MISC_MIFARE_NACK_TO_RATS_BITMASK = 0x20;
+  const uint8_t MISC_MIFARE_MUTE_TO_RATS_BITMASK = 0x02;
+  const uint8_t MISC_CHINA_BLK_NUM_CHK_BITMASK = 0x40;
+  const uint8_t MISC_CN_TRANSIT_CMA_BYPASSMODE_BITMASK = 0x80;
+
+  bool isUpdaterequired = false;
+  if (nfcFL.nfccFL._NFCC_MIFARE_TIANJIN) {
+    settings.push_back({NAME_NXP_CHINA_TIANJIN_RF_ENABLED,
+                        MISC_TIANJIN_RF_INDEX_PN557,
+                        MISC_TIANJIN_RF_BITMASK_PN557});
+  } else {
+    settings.push_back({NAME_NXP_CHINA_TIANJIN_RF_ENABLED,
+                        MISC_TIANJIN_RF_INDEX, MISC_TIANJIN_RF_BITMASK});
+  }
+  settings.push_back({NAME_NXP_MIFARE_NACK_TO_RATS_ENABLE,
+                      MISC_MIFARE_CONFIG_RATS_INDEX,
+                      MISC_MIFARE_NACK_TO_RATS_BITMASK});
+  settings.push_back({NAME_NXP_MIFARE_MUTE_TO_RATS_ENABLE,
+                      MISC_MIFARE_CONFIG_RATS_INDEX,
+                      MISC_MIFARE_MUTE_TO_RATS_BITMASK});
+  settings.push_back({NAME_NXP_CHINA_BLK_NUM_CHK_ENABLE, MISC_CHINA_BLK_INDEX,
+                      MISC_CHINA_BLK_NUM_CHK_BITMASK});
+  settings.push_back({NAME_NXP_CN_TRANSIT_CMA_BYPASSMODE_ENABLE,
+                      MISC_CN_TRANSIT_CMA_INDEX,
+                      MISC_CN_TRANSIT_CMA_BYPASSMODE_BITMASK});
+
+  vector<phRfMiscSettings>::iterator it;
+  for (it = settings.begin(); it != settings.end(); it++) {
+    unsigned long config_value = 0;
+    int position = it->configPosition;
+    if ((int)phNxpNciRfSet.p_rx_data.size() <= position) {
+      NXPLOG_NCIHAL_E(
+          "Can't update the value due to the length issue, hence ignoring %s",
+          it->configName);
+      continue;
+    }
+    int rf_val = phNxpNciRfSet.p_rx_data[position];
+    int isfound = (GetNxpNumValue(it->configName, (void*)&config_value,
+                                  sizeof(config_value)));
+    if (isfound > 0) {
+      uint8_t configBitMask = it->configBitMask;
+      int enable_bit = rf_val & configBitMask;
+      if ((enable_bit != configBitMask) && (config_value == 1)) {
+        phNxpNciRfSet.p_rx_data[position] |=
+            configBitMask;  // Enable if it is disabled
+        isUpdaterequired = true;
+      } else if ((enable_bit == configBitMask) && (config_value == 0)) {
+        phNxpNciRfSet.p_rx_data[position] &=
+            ~configBitMask;  // Disable if it is Enabled
+        isUpdaterequired = true;
+      } else {
+        NXPLOG_NCIHAL_E("No change in value, hence ignoring %s",
+                        it->configName);
+      }
+    }
+  }
+
+  return isUpdaterequired;
+}
+
 /******************************************************************************
  * Function         phNxpNciHal_DownloadFw
  *
@@ -3724,16 +3786,7 @@ static void phNxpNciHal_print_res_status(uint8_t* p_rx_data, uint16_t* p_len) {
     }
 
     else if (phNxpNciRfSet.isGetRfSetting) {
-      int i, len = sizeof(phNxpNciRfSet.p_rx_data);
-      if (*p_len > len) {
-        android_errorWriteLog(0x534e4554, "169258733");
-      } else {
-        len = *p_len;
-      }
-      for (i = 0; i < len; i++) {
-        phNxpNciRfSet.p_rx_data[i] = p_rx_data[i];
-        // NXPLOG_NCIHAL_D("%s: response status =0x%x",__func__,p_rx_data[i]);
-      }
+      phNxpNciRfSet.p_rx_data = vector<uint8_t>(p_rx_data, p_rx_data + *p_len);
     } else if (phNxpNciMwEepromArea.isGetEepromArea) {
       int i, len = sizeof(phNxpNciMwEepromArea.p_rx_data) + 8;
       if (*p_len > len) {
@@ -3840,8 +3893,18 @@ NFCSTATUS phNxpNciHal_send_get_cfgs() {
 void phNxpNciHal_configFeatureList(uint8_t* init_rsp, uint16_t rsp_len) {
   nxpncihal_ctrl.chipType = pConfigFL->processChipType(init_rsp, rsp_len);
   tNFC_chipType chipType = nxpncihal_ctrl.chipType;
+  bool is4KFragementSupported = false;
   NXPLOG_NCIHAL_D("%s chipType = %s", __func__, pConfigFL->product[chipType]);
   CONFIGURE_FEATURELIST(chipType);
+  if (IS_CHIP_TYPE_EQ(sn300u)) {
+    if (!GetNxpNumValue(NAME_NXP_4K_FWDNLD_SUPPORT, &is4KFragementSupported,
+                        sizeof(is4KFragementSupported))) {
+      is4KFragementSupported = false;
+    }
+  }
+  NXPLOG_NCIHAL_D("%s 4K FW download support = %x", __func__,
+                  is4KFragementSupported);
+  CONFIGURE_4K_SUPPORT(is4KFragementSupported);
   /* update fragment len based on the chip type.*/
   phTmlNfc_IoCtl(phTmlNfc_e_setFragmentSize);
 }
@@ -4023,3 +4086,81 @@ void phNxpNciHal_setVerboseLogging(bool enable) { nfc_debug_enabled = enable; }
  *****************************************************************************/
 
 bool phNxpNciHal_getVerboseLogging() { return nfc_debug_enabled; }
+
+/******************************************************************************
+ * Function         phNxpNciHal_check_and_recover_fw
+ *
+ * Description      This function  performs fw recovery using force fw download
+ *                  followed by power reset if it requires.
+ *
+ * Returns          void
+ *
+ *****************************************************************************/
+
+static void phNxpNciHal_check_and_recover_fw() {
+  NXPLOG_NCIHAL_D("%s: Entry", __func__);
+  uint8_t cmd_reset_nci_rs[] = {0x20, 0x00, 0x01, 0x80};  // switch to DL mode
+  NFCSTATUS status = NFCSTATUS_FAILED;
+  int32_t core_reset_count =
+      phNxpNciHal_getVendorProp_int32(core_reset_ntf_count_prop_name, 0);
+  if (core_reset_count < CORE_RESET_NTF_RECOVERY_REQ_COUNT) {
+    return;
+  }
+  NXPLOG_NCIHAL_D("FW Recovery is required");
+  if (core_reset_count <= CORE_RESET_NTF_RECOVERY_REQ_COUNT + 1) {
+    // check if there is a new  reset NTF or time out after 1600ms
+    // as interval b/w 2 consecutive NTF is 1.4 secs
+    struct timespec ts;
+
+    clock_gettime(CLOCK_MONOTONIC, &ts);
+    // Normalize timespec
+    ts.tv_sec += MAX_WAIT_MS_FOR_RESET_NTF / 1000;
+    ts.tv_nsec += (MAX_WAIT_MS_FOR_RESET_NTF % 1000) * 1000000;
+    if (ts.tv_nsec >= NS_PER_S) {
+      ts.tv_sec++;
+      ts.tv_nsec -= NS_PER_S;
+    }
+
+    int s;
+    while ((s = sem_timedwait_monotonic_np(&sem_reset_ntf_received, &ts)) ==
+               -1 &&
+           errno == EINTR) {
+      continue; /* Restart if interrupted by handler */
+    }
+    if (s == -1) {
+      NXPLOG_NCIHAL_D("sem_timedwait failed. errno = %d", errno);
+    }
+    if (NFCSTATUS_SUCCESS !=
+        phNxpNciHal_send_ext_cmd(sizeof(cmd_reset_nci_rs), cmd_reset_nci_rs)) {
+      NXPLOG_NCIHAL_E(
+          "failed to switch in fw download mode through nci core reset");
+    }
+
+    status = phNxpNciHal_getChipInfoInFwDnldMode(false);
+    if (status != NFCSTATUS_SUCCESS) {
+      NXPLOG_NCIHAL_E("phNxpNciHal_getChipInfoInFwDnldMode Failed");
+      status = NFCSTATUS_FAILED;
+    }
+  }
+  if (status != NFCSTATUS_SUCCESS) {
+    if ((phTmlNfc_IoCtl(phTmlNfc_e_PullVenLow) != NFCSTATUS_SUCCESS) ||
+        (phTmlNfc_IoCtl(phTmlNfc_e_PullVenHigh) != NFCSTATUS_SUCCESS)) {
+      NXPLOG_NCIHAL_E("Power reset failed during fw recovery");
+      return;
+    }
+    if (phNxpNciHal_getChipInfoInFwDnldMode(false) != NFCSTATUS_SUCCESS) {
+      NXPLOG_NCIHAL_E("phNxpNciHal_getChipInfoInFwDnldMode Failed");
+      return;
+    }
+  }
+  /* entered in recovery mode now reset the counter */
+  if (NFCSTATUS_SUCCESS !=
+      phNxpNciHal_setVendorProp(core_reset_ntf_count_prop_name, "0")) {
+    NXPLOG_NCIHAL_E("setting core_reset_ntf_count_prop failed");
+  }
+  if (phNxpNciHal_force_fw_download(0x00, true) != NFCSTATUS_SUCCESS) {
+    NXPLOG_NCIHAL_D("FW Recovery Failed");
+  } else {
+    NXPLOG_NCIHAL_D("FW Recovery SUCCESS");
+  }
+}
diff --git a/snxxx/halimpl/hal/phNxpNciHal.h b/snxxx/halimpl/hal/phNxpNciHal.h
index 13adda2..45a00af 100644
--- a/snxxx/halimpl/hal/phNxpNciHal.h
+++ b/snxxx/halimpl/hal/phNxpNciHal.h
@@ -18,6 +18,9 @@
 
 #include <hardware/nfc.h>
 #include <phNxpNciHal_utils.h>
+
+#include <vector>
+
 #include "NxpMfcReader.h"
 #include "NxpNfcCapability.h"
 #ifdef NXP_BOOTTIME_UPDATE
@@ -80,6 +83,8 @@ typedef void(phNxpNciHal_control_granted_callback_t)();
 #define NXP_MAX_CONFIG_STRING_LEN 260
 #define NCI_HEADER_SIZE 3
 
+#define CORE_RESET_NTF_RECOVERY_REQ_COUNT 0x03
+
 typedef struct nci_data {
   uint16_t len;
   uint8_t p_data[NCI_MAX_DATA_LEN];
@@ -91,6 +96,13 @@ typedef enum {
   HAL_STATUS_MIN_OPEN
 } phNxpNci_HalStatus;
 
+typedef enum {
+  HAL_CLOSED, /* Either hal_close() done or hal_open() is on going */
+  HAL_OPENED, /* hal_open() is done */
+  HAL_OPEN_CORE_INITIALIZING /* core_initialized() ongoing. will be set back to
+                                HAL_OPENED once done. */
+} phNxpNci_HalOpenStatus;
+
 typedef enum {
   HAL_NFC_FW_UPDATE_INVALID = 0x00,
   HAL_NFC_FW_UPDATE_START,
@@ -145,7 +157,7 @@ typedef struct phNxpNciHal_Control {
   phNxpNciHal_control_granted_callback_t* p_control_granted_cback;
 
   /* HAL open status */
-  bool_t hal_open_status;
+  phNxpNci_HalOpenStatus hal_open_status;
 
   /* HAL extensions */
   uint8_t hal_ext_enabled;
@@ -159,6 +171,9 @@ typedef struct phNxpNciHal_Control {
   uint16_t rsp_len;
   uint8_t p_rsp_data[NCI_MAX_DATA_LEN];
 
+  uint16_t vendor_msg_len;
+  uint8_t vendor_msg[NCI_MAX_DATA_LEN];
+
   /* retry count used to force download */
   uint16_t retry_cnt;
   uint8_t read_retry_cnt;
@@ -185,7 +200,7 @@ typedef struct phNxpNciClock {
 
 typedef struct phNxpNciRfSetting {
   bool_t isGetRfSetting;
-  uint8_t p_rx_data[20];
+  vector<uint8_t> p_rx_data;
 } phNxpNciRfSetting_t;
 
 typedef struct phNxpNciMwEepromArea {
@@ -193,6 +208,12 @@ typedef struct phNxpNciMwEepromArea {
   uint8_t p_rx_data[32];
 } phNxpNciMwEepromArea_t;
 
+struct phRfMiscSettings {
+  const char* configName;
+  int configPosition;
+  uint8_t configBitMask;
+};
+
 enum { SE_TYPE_ESE, SE_TYPE_EUICC, SE_TYPE_UICC, SE_TYPE_UICC2, NUM_SE_TYPES };
 
 typedef enum {
@@ -306,6 +327,7 @@ typedef struct phNxpNciProfile_Control {
 #define NCI_HAL_ERROR_MSG 0x415
 #define NCI_HAL_HCI_NETWORK_RESET_MSG 0x416
 #define NCI_HAL_RX_MSG 0xF01
+#define NCI_HAL_VENDOR_MSG 0xF02
 #define HAL_NFC_FW_UPDATE_STATUS_EVT 0x0A
 
 #define NCIHAL_CMD_CODE_LEN_BYTE_OFFSET (2U)
@@ -425,4 +447,16 @@ NFCSTATUS phNxpNciHal_restore_uicc_params();
  ******************************************************************************/
 void phNxpNciHal_client_data_callback();
 
+/******************************************************************************
+ * Function         phNxpNciHal_UpdateRfMiscSettings
+ *
+ * Description      This will look the configuration properties and
+ *                  update the RF misc settings
+ *
+ * Returns          bool - true if the RF Misc settings update required
+ *                      otherwise false
+ *
+ ******************************************************************************/
+bool phNxpNciHal_UpdateRfMiscSettings();
+
 #endif /* _PHNXPNCIHAL_H_ */
diff --git a/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc b/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc
index 7ac79ac..90648dc 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_IoctlOperations.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2019-2023 NXP
+ * Copyright 2019-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -192,7 +192,6 @@ std::set<string> gNciConfigs = {"NXP_SE_COLD_TEMP_ERROR_DELAY",
                                 "NXP_DISCONNECT_TAG_IN_SCRN_OFF",
                                 "NXP_CE_PRIORITY_ENABLED",
                                 "NXP_RDR_REQ_GUARD_TIME",
-                                "OFF_HOST_SIM2_PIPE_ID",
                                 "NXP_ENABLE_DISABLE_LOGS",
                                 "NXP_RDR_DISABLE_ENABLE_LPCD",
                                 "NXP_SUPPORT_NON_STD_CARD",
@@ -207,9 +206,7 @@ std::set<string> gNciConfigs = {"NXP_SE_COLD_TEMP_ERROR_DELAY",
                                 "NXP_NFCC_RECOVERY_SUPPORT",
                                 "NXP_AGC_DEBUG_ENABLE",
                                 "NXP_EXTENDED_FIELD_DETECT_MODE",
-                                "NXP_SE_SMB_TERMINAL_TYPE",
-                                "OFF_HOST_ESIM_PIPE_ID",
-                                "OFF_HOST_ESIM2_PIPE_ID"};
+                                "NXP_SE_SMB_TERMINAL_TYPE"};
 
 /****************************************************************
  * Local Functions
@@ -339,14 +336,6 @@ bool phNxpNciHal_setSystemProperty(string key, string value) {
   } else if (strcmp(key.c_str(), "nfc.cmd_timeout") == 0) {
     NXPLOG_NCIHAL_E("%s : nci_timeout, sem post", __func__);
     sem_post(&(nxpncihal_ctrl.syncSpiNfc));
-  } else if (strcmp(key.c_str(), "nfc.ulpdet") == 0) {
-    NXPLOG_NCIHAL_E("%s : set ulpdet", __func__);
-    if (!phNxpNciHal_isULPDetSupported()) return false;
-    bool flag = false;
-    if (strcmp(value.c_str(), "1") == 0) {
-      flag = true;
-    }
-    phNxpNciHal_setULPDetFlag(flag);
   }
   gsystemProperty[key] = std::move(value);
   return stat;
diff --git a/snxxx/halimpl/hal/phNxpNciHal_VendorProp.cc b/snxxx/halimpl/hal/phNxpNciHal_VendorProp.cc
new file mode 100644
index 0000000..e3e8022
--- /dev/null
+++ b/snxxx/halimpl/hal/phNxpNciHal_VendorProp.cc
@@ -0,0 +1,54 @@
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
+#include "phNxpNciHal_VendorProp.h"
+#undef PROPERTY_VALUE_MAX
+#undef property_get
+#undef property_set
+#include <cutils/properties.h>
+
+/******************************************************************************
+ * Function         phNxpNciHal_getVendorProp_int32
+ *
+ * Description      This function will read and return property
+ *                  value of input key as integer.
+ * Parameters       key - property string for which value to be read.
+ *                  default_value - default value to be return if property not
+ *                  set.
+ *
+ * Returns          integer value of key from vendor properties if set else
+ *                  return the input default_value.
+ *
+ ******************************************************************************/
+int32_t phNxpNciHal_getVendorProp_int32(const char* key,
+                                        int32_t default_value) {
+  return property_get_int32(key, default_value);
+}
+
+/******************************************************************************
+ * Function         phNxpNciHal_setVendorProp
+ *
+ * Description      This function will set the value for input property.
+ *
+ * Parameters       key - property string for which value to be set.
+ *                  value - value of key property be set.
+ *
+ * Returns          returns 0 on success and, < 0 on failure
+ *
+ ******************************************************************************/
+int phNxpNciHal_setVendorProp(const char* key, const char* value) {
+  return property_set(key, value);
+}
diff --git a/snxxx/halimpl/hal/phNxpNciHal_VendorProp.h b/snxxx/halimpl/hal/phNxpNciHal_VendorProp.h
new file mode 100644
index 0000000..4bcc76e
--- /dev/null
+++ b/snxxx/halimpl/hal/phNxpNciHal_VendorProp.h
@@ -0,0 +1,45 @@
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
+#include <stdint.h>
+
+/******************************************************************************
+ * Function         phNxpNciHal_getVendorProp_int32
+ *
+ * Description      This function will read and return property
+ *                  value of input key as integer.
+ * Parameters       key - property string for which value to be read.
+ *                  default_value - default value to be return if property not
+ *                  set.
+ *
+ * Returns          integer value of key from vendor properties if set else
+ *                  return the input default_value.
+ *
+ ******************************************************************************/
+int32_t phNxpNciHal_getVendorProp_int32(const char* key, int32_t default_value);
+
+/******************************************************************************
+ * Function         phNxpNciHal_setVendorProp
+ *
+ * Description      This function will set the value for input property.
+ *
+ * Parameters       key - property string for which value to be set.
+ *                  value - value of key property be set.
+ *
+ * Returns          returns 0 on success and, < 0 on failure
+ *
+ ******************************************************************************/
+int phNxpNciHal_setVendorProp(const char* key, const char* value);
diff --git a/snxxx/halimpl/hal/phNxpNciHal_ext.cc b/snxxx/halimpl/hal/phNxpNciHal_ext.cc
index a8d9656..9f735cd 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_ext.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_ext.cc
@@ -31,6 +31,7 @@
 #include "phNxpNciHal_IoctlOperations.h"
 #include "phNxpNciHal_LxDebug.h"
 #include "phNxpNciHal_PowerTrackerIface.h"
+#include "phNxpNciHal_VendorProp.h"
 
 #define NXP_EN_SN110U 1
 #define NXP_EN_SN100U 1
@@ -38,8 +39,9 @@
 #define NXP_EN_PN557 1
 #define NXP_EN_PN560 1
 #define NXP_EN_SN300U 1
-#define NFC_NXP_MW_ANDROID_VER (14U)  /* Android version used by NFC MW */
-#define NFC_NXP_MW_VERSION_MAJ (0x0E) /* MW Major Version */
+#define NXP_EN_SN330U 1
+#define NFC_NXP_MW_ANDROID_VER (15U)  /* Android version used by NFC MW */
+#define NFC_NXP_MW_VERSION_MAJ (0x08) /* MW Major Version */
 #define NFC_NXP_MW_VERSION_MIN (0x00) /* MW Minor Version */
 #define NFC_NXP_MW_CUSTOMER_ID (0x00) /* MW Customer Id */
 #define NFC_NXP_MW_RC_VERSION (0x00)  /* MW RC Version */
@@ -59,6 +61,7 @@ extern PowerTrackerHandle gPowerTrackerHandle;
 extern bool_t gsIsFwRecoveryRequired;
 
 extern bool nfc_debug_enabled;
+extern const char* core_reset_ntf_count_prop_name;
 uint8_t icode_detected = 0x00;
 uint8_t icode_send_eof = 0x00;
 static uint8_t ee_disc_done = 0x00;
@@ -75,6 +78,7 @@ static uint32_t bCoreInitRsp[40];
 static uint32_t iCoreInitRspLen;
 
 extern uint32_t timeoutTimerId;
+extern sem_t sem_reset_ntf_received;
 
 /************** HAL extension functions ***************************************/
 static void hal_extns_write_rsp_timeout_cb(uint32_t TimerId, void* pContext);
@@ -99,12 +103,15 @@ static NFCSTATUS phNxpNciHal_process_screen_state_cmd(uint16_t* cmd_len,
                                                       uint8_t* p_cmd_data,
                                                       uint16_t* rsp_len,
                                                       uint8_t* p_rsp_data);
+static bool phNxpNciHal_update_core_reset_ntf_prop();
+
 void printNfcMwVersion() {
   uint32_t validation = (NXP_EN_SN100U << 13);
   validation |= (NXP_EN_SN110U << 14);
   validation |= (NXP_EN_SN220U << 15);
   validation |= (NXP_EN_PN560 << 16);
   validation |= (NXP_EN_SN300U << 17);
+  validation |= (NXP_EN_SN330U << 18);
   validation |= (NXP_EN_PN557 << 11);
 
   ALOGE("MW-HAL Version: NFC_AR_%02X_%05X_%02d.%02x.%02x",
@@ -397,7 +404,9 @@ NFCSTATUS phNxpNciHal_process_ext_rsp(uint8_t* p_ntf, uint16_t* p_len) {
     PhNxpEventLogger::GetInstance().Log(p_ntf, *p_len,
                                         LogEventType::kLogSMBEvent);
   } else if (*p_len >= 5 && p_ntf[0] == 0x01 &&
-             p_ntf[3] == ESE_CONNECTIVITY_PACKET && p_ntf[4] == ESE_DPD_EVENT) {
+             (p_ntf[3] == ESE_CONNECTIVITY_PACKET ||
+              p_ntf[3] == EUICC_CONNECTIVITY_PACKET) &&
+             p_ntf[4] == ESE_DPD_EVENT) {
     NXPLOG_NCIHAL_D(">  DPD monitor event received");
     PhNxpEventLogger::GetInstance().Log(p_ntf, *p_len,
                                         LogEventType::kLogDPDEvent);
@@ -478,7 +487,17 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
       NXPLOG_NCIHAL_D("NxpNci> FW Version: %x.%x.%x", p_ntf[len - 2],
                       p_ntf[len - 1], p_ntf[len]);
     } else {
-      phNxpNciHal_emergency_recovery(p_ntf[3]);
+      bool is_abort_req = true;
+      if ((p_ntf[3] == CORE_RESET_TRIGGER_TYPE_WATCHDOG_RESET ||
+           p_ntf[3] == CORE_RESET_TRIGGER_TYPE_FW_ASSERT) ||
+          ((p_ntf[3] == CORE_RESET_TRIGGER_TYPE_UNRECOVERABLE_ERROR) &&
+           (p_ntf[4] == CORE_RESET_TRIGGER_TYPE_WATCHDOG_RESET ||
+            p_ntf[4] == CORE_RESET_TRIGGER_TYPE_FW_ASSERT))) {
+        /* WA : In some cases for Watchdog reset FW sends reset reason code as
+         * unrecoverable error and config status as WATCHDOG_RESET */
+        is_abort_req = phNxpNciHal_update_core_reset_ntf_prop();
+      }
+      if (is_abort_req) phNxpNciHal_emergency_recovery(p_ntf[3]);
       status = NFCSTATUS_FAILED;
     } /* Parsing CORE_INIT_RSP*/
   } else if (p_ntf[0] == NCI_MT_RSP &&
@@ -632,7 +651,8 @@ static NFCSTATUS phNxpNciHal_process_ext_cmd_rsp(uint16_t cmd_len,
 
   /*Response check for Set config, Core Reset & Core init command sent part of
    * HAL_EXT*/
-  if (nxpncihal_ctrl.p_rx_data[0] == 0x40 &&
+  if (nxpncihal_ctrl.hal_open_status == HAL_OPEN_CORE_INITIALIZING &&
+      nxpncihal_ctrl.p_rx_data[0] == 0x40 &&
       nxpncihal_ctrl.p_rx_data[1] <= 0x02 &&
       nxpncihal_ctrl.p_rx_data[2] != 0x00) {
     status = nxpncihal_ctrl.p_rx_data[3];
@@ -1601,3 +1621,35 @@ static NFCSTATUS phNxpNciHal_process_screen_state_cmd(uint16_t* cmd_len,
   }
   return status;
 }
+
+/******************************************************************************
+ * Function         phNxpNciHal_update_core_reset_ntf_prop
+ *
+ * Description      This function updates the vendor property which keep track
+ *                  core reset ntf count for fw recovery.
+ *
+ * Returns          void
+ *
+ *****************************************************************************/
+
+static bool phNxpNciHal_update_core_reset_ntf_prop() {
+  NXPLOG_NCIHAL_D("%s: Entry", __func__);
+  bool is_abort_req = true;
+  int32_t core_reset_count =
+      phNxpNciHal_getVendorProp_int32(core_reset_ntf_count_prop_name, 0);
+  if (core_reset_count == CORE_RESET_NTF_RECOVERY_REQ_COUNT) {
+    NXPLOG_NCIHAL_D("%s: Notify main thread of fresh ntf received", __func__);
+    sem_post(&sem_reset_ntf_received);
+    is_abort_req = false;
+  }
+  ++core_reset_count;
+  std::string ntf_count_str = std::to_string(core_reset_count);
+  NXPLOG_NCIHAL_D("Core reset counter prop value  %d", core_reset_count);
+  if (NFCSTATUS_SUCCESS !=
+      phNxpNciHal_setVendorProp(core_reset_ntf_count_prop_name,
+                                ntf_count_str.c_str())) {
+    NXPLOG_NCIHAL_D("setting core_reset_ntf_count_prop failed");
+  }
+  NXPLOG_NCIHAL_D("%s: Exit", __func__);
+  return is_abort_req;
+}
diff --git a/snxxx/halimpl/hal/phNxpNciHal_ext.h b/snxxx/halimpl/hal/phNxpNciHal_ext.h
index 99c1d87..1d0a1d2 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_ext.h
+++ b/snxxx/halimpl/hal/phNxpNciHal_ext.h
@@ -23,6 +23,10 @@
 #define NCI_MT_NTF 0x60
 #define NCI_MSG_CORE_RESET 0x00
 #define NCI_MSG_CORE_INIT 0x01
+
+/* libnfc_nci -> AIDL Mapping Support */
+#define HAL_NFC_REQUEST_CONTROL_EVT 0x04
+#define HAL_NFC_RELEASE_CONTROL_EVT 0x05
 #define HAL_HCI_NETWORK_RESET_EVT 0x07
 
 #define NXP_NFC_SET_CONFIG_PARAM_EXT 0xA0
diff --git a/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc b/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
index 325af25..cabcdd3 100755
--- a/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
@@ -816,17 +816,17 @@ int phNxpNciHal_handleVendorSpecificCommand(uint16_t data_len,
 void phNxpNciHal_vendorSpecificCallback(int oid, int opcode,
                                         vector<uint8_t> data) {
   static phLibNfc_Message_t msg;
-  nxpncihal_ctrl.p_rsp_data[0] = (uint8_t)(NCI_GID_PROP | NCI_MT_RSP);
-  nxpncihal_ctrl.p_rsp_data[1] = oid;
-  nxpncihal_ctrl.p_rsp_data[2] = 1 + (int)data.size();
-  nxpncihal_ctrl.p_rsp_data[3] = opcode;
+  nxpncihal_ctrl.vendor_msg[0] = (uint8_t)(NCI_GID_PROP | NCI_MT_RSP);
+  nxpncihal_ctrl.vendor_msg[1] = oid;
+  nxpncihal_ctrl.vendor_msg[2] = 1 + (int)data.size();
+  nxpncihal_ctrl.vendor_msg[3] = opcode;
   if ((int)data.size() > 0) {
-    memcpy(&nxpncihal_ctrl.p_rsp_data[4], data.data(),
+    memcpy(&nxpncihal_ctrl.vendor_msg[4], data.data(),
            data.size() * sizeof(uint8_t));
   }
-  nxpncihal_ctrl.rsp_len = 4 + (int)data.size();
+  nxpncihal_ctrl.vendor_msg_len = 4 + (int)data.size();
 
-  msg.eMsgType = NCI_HAL_RX_MSG;
+  msg.eMsgType = NCI_HAL_VENDOR_MSG;
   msg.pMsgData = NULL;
   msg.Size = 0;
   phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId,
diff --git a/snxxx/halimpl/observe_mode/ObserveMode.cc b/snxxx/halimpl/observe_mode/ObserveMode.cc
index d855028..43315a3 100644
--- a/snxxx/halimpl/observe_mode/ObserveMode.cc
+++ b/snxxx/halimpl/observe_mode/ObserveMode.cc
@@ -93,8 +93,8 @@ int handleGetObserveModeStatus(uint16_t data_len, const uint8_t* p_data) {
     return 0;
   }
   vector<uint8_t> response;
-  response.push_back(0x00);
-  response.push_back(isObserveModeEnabled() ? 0x00 : 0x01);
+  response.push_back(NCI_RSP_OK);
+  response.push_back(isObserveModeEnabled() ? 0x01 : 0x00);
   phNxpNciHal_vendorSpecificCallback(p_data[NCI_OID_INDEX],
                                      p_data[NCI_MSG_INDEX_FOR_FEATURE],
                                      std::move(response));
diff --git a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc
index 653ce54..7558ba6 100644
--- a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc
+++ b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.cc
@@ -102,6 +102,38 @@ vector<uint8_t> ReaderPollConfigParser::getRFEventData(
   return eventData;
 }
 
+/*****************************************************************************
+ *
+ * Function         parseCmaEvent
+ *
+ * Description      This function parses the unknown frames
+ *
+ * Parameters       p_event - Data bytes of type Unknown event
+ *
+ * Returns          Filters Type-B/Type-F data frames
+ *                  and converts other frame to  unknown frame
+ *
+ ***************************************************************************/
+vector<uint8_t> ReaderPollConfigParser::parseCmaEvent(vector<uint8_t> p_event) {
+  vector<uint8_t> event_data = vector<uint8_t>();
+  if (lastKnownModEvent == EVENT_MOD_B && p_event.size() > 0 &&
+      p_event[0] == TYPE_B_APF) {  // Type B Apf value is 0x05
+    event_data =
+        getWellKnownModEventData(TYPE_MOD_B, std::move(unknownEventTimeStamp),
+                                 lastKnownGain, std::move(p_event));
+  } else if (lastKnownModEvent == EVENT_MOD_F &&
+             p_event[0] == TYPE_F_CMD_LENGH && p_event[2] == TYPE_F_ID &&
+             p_event[3] == TYPE_F_ID) {
+    event_data =
+        getWellKnownModEventData(TYPE_MOD_F, std::move(unknownEventTimeStamp),
+                                 lastKnownGain, std::move(p_event));
+  } else {
+    event_data = getUnknownEvent(
+        std::move(p_event), std::move(unknownEventTimeStamp), lastKnownGain);
+  }
+  return event_data;
+}
+
 /*****************************************************************************
  *
  * Function         getEvent
@@ -111,27 +143,30 @@ vector<uint8_t> ReaderPollConfigParser::getRFEventData(
  *                  notification
  *
  * Parameters       p_event - Vector Lx Notification
- *                  isCmaEvent - true if it CMA event otherwise false
+ *                  cmaEventType - CMA event type
  *
  * Returns          This function return reader poll info notification
  *
  ****************************************************************************/
 vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
-                                                 bool isCmaEvent) {
+                                                 uint8_t cmaEventType) {
   vector<uint8_t> event_data;
-  if ((!isCmaEvent && (int)p_event.size() < MIN_LEN_NON_CMA_EVT) ||
-      (isCmaEvent && (int)p_event.size() < MIN_LEN_CMA_EVT)) {
+  if ((cmaEventType == L2_EVT_TAG &&
+       (int)p_event.size() < MIN_LEN_NON_CMA_EVT) ||
+      (cmaEventType == CMA_EVT_TAG && (int)p_event.size() < MIN_LEN_CMA_EVT) ||
+      (cmaEventType == CMA_EVT_EXTRA_DATA_TAG &&
+       (int)p_event.size() < MIN_LEN_CMA_EXTRA_DATA_EVT)) {
     return event_data;
   }
 
-  // Timestamp should be in Big Endian format
-  int idx = 3;
-  vector<uint8_t> timestamp;
-  timestamp.push_back(p_event[idx--]);
-  timestamp.push_back(p_event[idx--]);
-  timestamp.push_back(p_event[idx--]);
-  timestamp.push_back(p_event[idx]);
-  if (!isCmaEvent) {
+  if (cmaEventType == L2_EVT_TAG) {
+    // Timestamp should be in Big Endian format
+    int idx = 3;
+    vector<uint8_t> timestamp;
+    timestamp.push_back(p_event[idx--]);
+    timestamp.push_back(p_event[idx--]);
+    timestamp.push_back(p_event[idx--]);
+    timestamp.push_back(p_event[idx]);
     lastKnownGain = p_event[INDEX_OF_L2_EVT_GAIN];
     switch (p_event[INDEX_OF_L2_EVT_TYPE] & LX_TYPE_MASK) {
       // Trigger Type
@@ -181,7 +216,14 @@ vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
         break;
     }
 
-  } else {
+  } else if (cmaEventType == CMA_EVT_TAG) {
+    // Timestamp should be in Big Endian format
+    int idx = 3;
+    vector<uint8_t> timestamp;
+    timestamp.push_back(p_event[idx--]);
+    timestamp.push_back(p_event[idx--]);
+    timestamp.push_back(p_event[idx--]);
+    timestamp.push_back(p_event[idx]);
     switch (p_event[INDEX_OF_CMA_EVT_TYPE]) {
       // Trigger Type
       case CMA_EVENT_TRIGGER_TYPE:
@@ -203,38 +245,28 @@ vector<uint8_t> ReaderPollConfigParser::getEvent(vector<uint8_t> p_event,
         }
         break;
       case CMA_DATA_TRIGGER_TYPE: {
-        uint8_t entryLength = p_event[INDEX_OF_CMA_EVT_DATA];
-        if (p_event.size() >= INDEX_OF_CMA_EVT_DATA + entryLength) {
-          vector<uint8_t> payloadData = vector<uint8_t>(
-              p_event.begin() + INDEX_OF_CMA_DATA, p_event.end());
-
-          if (lastKnownModEvent == EVENT_MOD_B &&
-              payloadData[0] == TYPE_B_APF) {  // Type B Apf value is 0x05
-            event_data =
-                getWellKnownModEventData(TYPE_MOD_B, std::move(timestamp),
-                                         lastKnownGain, std::move(payloadData));
-            break;
-          } else if (lastKnownModEvent == EVENT_MOD_F &&
-                     payloadData[0] == TYPE_F_CMD_LENGH &&
-                     payloadData[2] == TYPE_F_ID &&
-                     payloadData[3] == TYPE_F_ID) {
-            event_data =
-                getWellKnownModEventData(TYPE_MOD_F, std::move(timestamp),
-                                         lastKnownGain, std::move(payloadData));
-            break;
-          } else {
-            event_data = getUnknownEvent(std::move(payloadData),
-                                         std::move(timestamp), lastKnownGain);
-            break;
-          }
-        }
-        [[fallthrough]];
+        readExtraBytesForUnknownEvent = true;
+        extraByteLength = p_event[INDEX_OF_CMA_EVT_DATA];
+        unknownEventTimeStamp = timestamp;
+        break;
       }
-      default:
+      default: {
         vector<uint8_t> payloadData = vector<uint8_t>(
             p_event.begin() + INDEX_OF_CMA_EVT_TYPE, p_event.end());
         event_data = getUnknownEvent(std::move(payloadData),
                                      std::move(timestamp), lastKnownGain);
+      }
+    }
+  } else if (cmaEventType == CMA_EVT_EXTRA_DATA_TAG &&
+             readExtraBytesForUnknownEvent) {
+    extraBytes.insert(std::end(extraBytes), std::begin(p_event),
+                      std::end(p_event));
+
+    // If the required bytes received from Extra Data frames, process the
+    // unknown event and reset the extra data bytes
+    if (extraBytes.size() >= extraByteLength) {
+      event_data = parseCmaEvent(std::move(extraBytes));
+      resetExtraBytesInfo();
     }
   }
 
@@ -295,12 +327,22 @@ bool ReaderPollConfigParser::parseAndSendReaderPollInfo(uint8_t* p_ntf,
     uint8_t entryLength = (lxNotification[idx] & LX_LENGTH_MASK);
 
     idx++;
-    if ((entryTag == L2_EVT_TAG || entryTag == CMA_EVT_TAG) &&
+    if ((entryTag == L2_EVT_TAG || entryTag == CMA_EVT_TAG ||
+         entryTag == CMA_EVT_EXTRA_DATA_TAG) &&
         lxNotification.size() >= (idx + entryLength)) {
+      /*
+        Reset the extra data bytes, If it receives other events while reading
+        for unknown event chained frames
+      */
+      if (readExtraBytesForUnknownEvent &&
+          (entryTag == L2_EVT_TAG || entryTag == CMA_EVT_TAG)) {
+        resetExtraBytesInfo();
+      }
       vector<uint8_t> readerPollInfo =
           getEvent(vector<uint8_t>(lxNotification.begin() + idx,
                                    lxNotification.begin() + idx + entryLength),
-                   entryTag == CMA_EVT_TAG);
+                   entryTag);
+
       if ((int)(readerPollInfoNotifications.size() + readerPollInfo.size()) >=
           0xFF) {
         notifyPollingLoopInfoEvent(std::move(readerPollInfoNotifications));
@@ -357,3 +399,21 @@ void ReaderPollConfigParser::setReaderPollCallBack(
     reader_poll_info_callback_t* callback) {
   this->callback = callback;
 }
+
+/*****************************************************************************
+ *
+ * Function         resetExtraBytesInfo
+ *
+ * Description      Function to reset the extra bytes info of UnknownEvent
+ *
+ * Parameters       None
+ *
+ * Returns          void
+ *
+ ****************************************************************************/
+void ReaderPollConfigParser::resetExtraBytesInfo() {
+  readExtraBytesForUnknownEvent = false;
+  extraByteLength = 0;
+  extraBytes = vector<uint8_t>();
+  unknownEventTimeStamp = vector<uint8_t>();
+}
diff --git a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h
index 4587ea6..75e4538 100644
--- a/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h
+++ b/snxxx/halimpl/observe_mode/ReaderPollConfigParser.h
@@ -83,6 +83,20 @@ class ReaderPollConfigParser {
   vector<uint8_t> getUnknownEvent(vector<uint8_t> data,
                                   vector<uint8_t> timeStamp, uint8_t gain);
 
+  /*****************************************************************************
+   *
+   * Function         parseCmaEvent
+   *
+   * Description      This function parses the unknown frames
+   *
+   * Parameters       p_event - Data bytes of type Unknown event
+   *
+   * Returns          Filters Type-B/Type-F data frames
+   *                  and converts other frame to  unknown frame
+   *
+   ***************************************************************************/
+  vector<uint8_t> parseCmaEvent(vector<uint8_t> p_event);
+
   /*****************************************************************************
    *
    * Function         getEvent
@@ -92,12 +106,12 @@ class ReaderPollConfigParser {
    *                  notification
    *
    * Parameters       p_event - Vector Lx Notification
-   *                  isCmaEvent - true if it CMA event otherwise false
+   *                  cmaEventType - CMA event type
    *
    * Returns          This function return reader poll info notification
    *
    ****************************************************************************/
-  vector<uint8_t> getEvent(vector<uint8_t> p_event, bool isCmaEvent);
+  vector<uint8_t> getEvent(vector<uint8_t> p_event, uint8_t cmaEventType);
 
   /*****************************************************************************
    *
@@ -120,6 +134,10 @@ class ReaderPollConfigParser {
 #endif
 
  public:
+  bool readExtraBytesForUnknownEvent = false;
+  uint8_t extraByteLength = 0;
+  vector<uint8_t> unknownEventTimeStamp;
+  vector<uint8_t> extraBytes = vector<uint8_t>();
   /*****************************************************************************
    *
    * Function         parseAndSendReaderPollInfo
@@ -163,4 +181,17 @@ class ReaderPollConfigParser {
    *
    ****************************************************************************/
   void setReaderPollCallBack(reader_poll_info_callback_t* callback);
+
+  /*****************************************************************************
+   *
+   * Function         resetExtraBytesInfo
+   *
+   * Description      Function to reset the extra bytes info of UnknownEvent
+   *
+   * Parameters       None
+   *
+   * Returns          void
+   *
+   ****************************************************************************/
+  void resetExtraBytesInfo();
 };
diff --git a/snxxx/halimpl/power-tracker/src/phNxpNciHal_PowerTracker.cc b/snxxx/halimpl/power-tracker/src/phNxpNciHal_PowerTracker.cc
index cae7301..2de540f 100644
--- a/snxxx/halimpl/power-tracker/src/phNxpNciHal_PowerTracker.cc
+++ b/snxxx/halimpl/power-tracker/src/phNxpNciHal_PowerTracker.cc
@@ -141,6 +141,17 @@ NFCSTATUS phNxpNciHal_startPowerTracker(unsigned long pollDuration) {
         NfcProps::ulpdetStateEntryCount().value_or(0);
     gContext.stateData[ULPDET].stateTickCount =
         NfcProps::ulpdetStateTick().value_or(0);
+    NXPLOG_NCIHAL_D(
+        "Cached PowerTracker data "
+        "Active counter = %u, Active Tick = %u "
+        "Standby Counter = %u, Standby Tick = %u "
+        "ULPDET Counter = %u, ULPDET Tick = %u",
+        gContext.stateData[ACTIVE].stateEntryCount,
+        gContext.stateData[ACTIVE].stateTickCount,
+        gContext.stateData[STANDBY].stateEntryCount,
+        gContext.stateData[STANDBY].stateTickCount,
+        gContext.stateData[ULPDET].stateEntryCount,
+        gContext.stateData[ULPDET].stateTickCount);
 
     // Start polling Thread
     gContext.pollDurationMilliSec = pollDuration;
@@ -196,13 +207,9 @@ static void* phNxpNciHal_pollPowerTrackerData(void* pCtx) {
     pContext->event.unlock();
 
     // Sync and cache power tracker data.
-    if (pContext->isRefreshNfccStateOngoing) {
-      status = phNxpNciHal_syncPowerTrackerData();
-      if (NFCSTATUS_SUCCESS != status) {
-        NXPLOG_NCIHAL_E("Failed to fetch PowerTracker data. error = %d",
-                        status);
-        // break;
-      }
+    status = phNxpNciHal_syncPowerTrackerData();
+    if (NFCSTATUS_SUCCESS != status) {
+      NXPLOG_NCIHAL_E("Failed to fetch PowerTracker data. error = %d", status);
     }
   }
   NXPLOG_NCIHAL_D("Stopped polling for PowerTracker data");
@@ -397,16 +404,6 @@ NFCSTATUS phNxpNciHal_stopPowerTracker() {
   phNxpNci_EEPROM_info_t mEEPROM_info = {.request_mode = 0};
   uint8_t power_tracker_disable = 0x00;
 
-  mEEPROM_info.request_mode = SET_EEPROM_DATA;
-  mEEPROM_info.buffer = (uint8_t*)&power_tracker_disable;
-  mEEPROM_info.bufflen = sizeof(power_tracker_disable);
-  mEEPROM_info.request_type = EEPROM_POWER_TRACKER_ENABLE;
-
-  status = request_EEPROM(&mEEPROM_info);
-  if (status != NFCSTATUS_SUCCESS) {
-    NXPLOG_NCIHAL_E("%s Failed to disable PowerTracker, error = %d", __func__,
-                    status);
-  }
   if (gContext.isRefreshNfccStateOngoing) {
     // Stop Polling Thread
     gContext.isRefreshNfccStateOngoing = false;
@@ -417,6 +414,16 @@ NFCSTATUS phNxpNciHal_stopPowerTracker() {
   } else {
     NXPLOG_NCIHAL_E("PowerTracker is already disabled");
   }
+  mEEPROM_info.request_mode = SET_EEPROM_DATA;
+  mEEPROM_info.buffer = (uint8_t*)&power_tracker_disable;
+  mEEPROM_info.bufflen = sizeof(power_tracker_disable);
+  mEEPROM_info.request_type = EEPROM_POWER_TRACKER_ENABLE;
+
+  status = request_EEPROM(&mEEPROM_info);
+  if (status != NFCSTATUS_SUCCESS) {
+    NXPLOG_NCIHAL_E("%s Failed to disable PowerTracker, error = %d", __func__,
+                    status);
+  }
   if (!gContext.isUlpdetOn) {
     NXPLOG_NCIHAL_I("%s: Stopped PowerTracker", __func__);
     phNxpNciHal_unregisterPowerStats();
diff --git a/snxxx/halimpl/recovery/phNxpNciHal_Recovery.cc b/snxxx/halimpl/recovery/phNxpNciHal_Recovery.cc
index 829474b..bd98f63 100644
--- a/snxxx/halimpl/recovery/phNxpNciHal_Recovery.cc
+++ b/snxxx/halimpl/recovery/phNxpNciHal_Recovery.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2021-2023 NXP
+ * Copyright 2021-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -491,24 +491,27 @@ static NFCSTATUS phnxpNciHal_partialOpen(void) {
   phTmlNfc_Config_t tTmlConfig;
   char* nfc_dev_node = NULL;
 
+  CONCURRENCY_LOCK();
   NXPLOG_NCIHAL_D("phnxpNciHal_partialOpen(): enter");
   if (nxpncihal_ctrl.halStatus == HAL_STATUS_MIN_OPEN) {
     NXPLOG_NCIHAL_D("phNxpNciHal: already open");
+    CONCURRENCY_UNLOCK();
     return NFCSTATUS_SUCCESS;
   }
   /* initialize trace level */
   phNxpLog_InitializeLogLevel();
   if (phNxpNciHal_init_monitor() == NULL) {
     NXPLOG_NCIHAL_E("Init monitor failed");
+    CONCURRENCY_UNLOCK();
     return NFCSTATUS_FAILED;
   }
   /* Create the local semaphore */
   if (phNxpNciHal_init_cb_data(&nxpncihal_ctrl.ext_cb_data, NULL) !=
       NFCSTATUS_SUCCESS) {
     NXPLOG_NCIHAL_D("Create ext_cb_data failed");
+    CONCURRENCY_UNLOCK();
     return NFCSTATUS_FAILED;
   }
-  CONCURRENCY_LOCK();
   memset(&tOsalConfig, 0x00, sizeof(tOsalConfig));
   memset(&tTmlConfig, 0x00, sizeof(tTmlConfig));
   memset(&nxpprofile_ctrl, 0, sizeof(phNxpNciProfile_Control_t));
@@ -528,13 +531,13 @@ static NFCSTATUS phnxpNciHal_partialOpen(void) {
                              NXP_MAX_CONFIG_STRING_LEN)) {
     NXPLOG_NCIHAL_D(
         "Invalid nfc device node name keeping the default device node "
-        "/dev/pn54x");
-    strlcpy(nfc_dev_node, "/dev/pn54x",
+        "/dev/nxp-nci");
+    strlcpy(nfc_dev_node, "/dev/nxp-nci",
             (NXP_MAX_CONFIG_STRING_LEN * sizeof(char)));
   }
   /* Configure hardware link */
   nxpncihal_ctrl.gDrvCfg.nClientId = phDal4Nfc_msgget(0, 0600);
-  nxpncihal_ctrl.gDrvCfg.nLinkType = ENUM_LINK_TYPE_I2C; /* For PN54X */
+  nxpncihal_ctrl.gDrvCfg.nLinkType = ENUM_LINK_TYPE_I2C; /* For NFCC */
   tTmlConfig.pDevName = (int8_t*)nfc_dev_node;
   tOsalConfig.dwCallbackThreadId = (uintptr_t)nxpncihal_ctrl.gDrvCfg.nClientId;
   tOsalConfig.pLogFile = NULL;
diff --git a/snxxx/halimpl/tml/phTmlNfc.cc b/snxxx/halimpl/tml/phTmlNfc.cc
index 3dde64f..dbdec87 100644
--- a/snxxx/halimpl/tml/phTmlNfc.cc
+++ b/snxxx/halimpl/tml/phTmlNfc.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2010-2023 NXP
+ * Copyright 2010-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -290,7 +290,7 @@ static NFCSTATUS phTmlNfc_StartThread(void) {
 static void* phTmlNfc_TmlThread(void* pParam) {
   NFCSTATUS wStatus = NFCSTATUS_SUCCESS;
   int32_t dwNoBytesWrRd = PH_TMLNFC_RESET_VALUE;
-  uint8_t temp[260];
+  uint8_t temp[PH_TMLNFC_MAX_READ_NCI_BUFF_LEN];
   uint8_t readRetryDelay = 0;
   /* Transaction info buffer to be passed to Callback Thread */
   static phTmlNfc_TransactInfo_t tTransactionInfo;
@@ -300,7 +300,7 @@ static void* phTmlNfc_TmlThread(void* pParam) {
   /* Initialize Message structure to post message onto Callback Thread */
   static phLibNfc_Message_t tMsg;
   UNUSED_PROP(pParam);
-  NXPLOG_TML_D("PN54X - Tml Reader Thread Started................\n");
+  NXPLOG_TML_D("NFCC - Tml Reader Thread Started................\n");
 
   /* Reader thread loop shall be running till shutdown is invoked */
   while (gpphTmlNfc_Context->bThreadDone) {
@@ -313,7 +313,7 @@ static void* phTmlNfc_TmlThread(void* pParam) {
 
     /* If Tml read is requested */
     if (1 == gpphTmlNfc_Context->tReadInfo.bEnable) {
-      NXPLOG_TML_D("PN54X - Read requested.....\n");
+      NXPLOG_TML_D("NFCC - Read requested.....\n");
       /* Set the variable to success initially */
       wStatus = NFCSTATUS_SUCCESS;
 
@@ -322,12 +322,13 @@ static void* phTmlNfc_TmlThread(void* pParam) {
 
       /* Read the data from the file onto the buffer */
       if (NULL != gpphTmlNfc_Context->pDevHandle) {
-        NXPLOG_TML_D("PN54X - Invoking I2C Read.....\n");
+        NXPLOG_TML_D("NFCC - Invoking Read.....\n");
         dwNoBytesWrRd =
-            gpTransportObj->Read(gpphTmlNfc_Context->pDevHandle, temp, 260);
+            gpTransportObj->Read(gpphTmlNfc_Context->pDevHandle, temp,
+                                 PH_TMLNFC_MAX_READ_NCI_BUFF_LEN);
 
         if (-1 == dwNoBytesWrRd) {
-          NXPLOG_TML_E("PN54X - Error in I2C Read.....\n");
+          NXPLOG_TML_E("NFCC - Error in Read.....\n");
           if (readRetryDelay < MAX_READ_RETRY_DELAY_IN_MILLISEC) {
             /*sleep for 30/60/90/120/150 msec between each read trial incase of
              * read error*/
@@ -335,7 +336,13 @@ static void* phTmlNfc_TmlThread(void* pParam) {
           }
           usleep(readRetryDelay * 1000);
           sem_post(&gpphTmlNfc_Context->rxSemaphore);
-        } else if (dwNoBytesWrRd > 260) {
+        } else if (dwNoBytesWrRd == PH_TMNFC_VBAT_LOW_ERROR) {
+          NXPLOG_TML_E(
+              "Platform VBAT Error detected by NFCC "
+              "NFC restart... : %d\n",
+              dwNoBytesWrRd);
+          abort();
+        } else if (dwNoBytesWrRd > PH_TMLNFC_MAX_READ_NCI_BUFF_LEN) {
           NXPLOG_TML_E("Numer of bytes read exceeds the limit 260.....\n");
           readRetryDelay = 0;
           sem_post(&gpphTmlNfc_Context->rxSemaphore);
@@ -343,17 +350,17 @@ static void* phTmlNfc_TmlThread(void* pParam) {
           memcpy(gpphTmlNfc_Context->tReadInfo.pBuffer, temp, dwNoBytesWrRd);
           readRetryDelay = 0;
 
-          NXPLOG_TML_D("PN54X - I2C Read successful.....\n");
+          NXPLOG_TML_D("NFCC - Read successful.....\n");
           /* This has to be reset only after a successful read */
           gpphTmlNfc_Context->tReadInfo.bEnable = 0;
           if ((phTmlNfc_e_EnableRetrans == gpphTmlNfc_Context->eConfig) &&
               (0x00 != (gpphTmlNfc_Context->tReadInfo.pBuffer[0] & 0xE0))) {
-            NXPLOG_TML_D("PN54X - Retransmission timer stopped.....\n");
+            NXPLOG_TML_D("NFCC - Retransmission timer stopped.....\n");
             /* Stop Timer to prevent Retransmission */
             uint32_t timerStatus =
                 phOsalNfc_Timer_Stop(gpphTmlNfc_Context->dwTimerId);
             if (NFCSTATUS_SUCCESS != timerStatus) {
-              NXPLOG_TML_E("PN54X - timer stopped returned failure.....\n");
+              NXPLOG_TML_E("NFCC - timer stopped returned failure.....\n");
             } else {
               gpphTmlNfc_Context->bWriteCbInvoked = false;
             }
@@ -381,14 +388,14 @@ static void* phTmlNfc_TmlThread(void* pParam) {
           tMsg.eMsgType = PH_LIBNFC_DEFERREDCALL_MSG;
           tMsg.pMsgData = &tDeferredInfo;
           tMsg.Size = sizeof(tDeferredInfo);
-          NXPLOG_TML_D("PN54X - Posting read message.....\n");
+          NXPLOG_TML_D("NFCC - Posting read message.....\n");
           phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId, &tMsg);
         }
       } else {
-        NXPLOG_TML_D("PN54X -gpphTmlNfc_Context->pDevHandle is NULL");
+        NXPLOG_TML_D("NFCC -gpphTmlNfc_Context->pDevHandle is NULL");
       }
     } else {
-      NXPLOG_TML_D("PN54X - read request NOT enabled");
+      NXPLOG_TML_D("NFCC - read request NOT enabled");
       usleep(10 * 1000);
     }
   } /* End of While loop */
@@ -420,17 +427,17 @@ static void* phTmlNfc_TmlWriterThread(void* pParam) {
   /* In case of I2C Write Retry */
   static uint16_t retry_cnt;
   UNUSED_PROP(pParam);
-  NXPLOG_TML_D("PN54X - Tml Writer Thread Started................\n");
+  NXPLOG_TML_D("NFCC - Tml Writer Thread Started................\n");
 
   /* Writer thread loop shall be running till shutdown is invoked */
   while (gpphTmlNfc_Context->bThreadDone) {
-    NXPLOG_TML_D("PN54X - Tml Writer Thread Running................\n");
+    NXPLOG_TML_D("NFCC - Tml Writer Thread Running................\n");
     if (-1 == sem_wait(&gpphTmlNfc_Context->txSemaphore)) {
       NXPLOG_TML_E("sem_wait didn't return success \n");
     }
     /* If Tml write is requested */
     if (1 == gpphTmlNfc_Context->tWriteInfo.bEnable) {
-      NXPLOG_TML_D("PN54X - Write requested.....\n");
+      NXPLOG_TML_D("NFCC - Write requested.....\n");
       /* Set the variable to success initially */
       wStatus = NFCSTATUS_SUCCESS;
       if (NULL != gpphTmlNfc_Context->pDevHandle) {
@@ -439,7 +446,7 @@ static void* phTmlNfc_TmlWriterThread(void* pParam) {
         /* Variable to fetch the actual number of bytes written */
         dwNoBytesWrRd = PH_TMLNFC_RESET_VALUE;
         /* Write the data in the buffer onto the file */
-        NXPLOG_TML_D("PN54X - Invoking I2C Write.....\n");
+        NXPLOG_TML_D("NFCC - Invoking Write.....\n");
         /* TML reader writer callback synchronization mutex lock --- START */
         pthread_mutex_lock(&gpphTmlNfc_Context->wait_busy_lock);
         gpphTmlNfc_Context->gWriterCbflag = false;
@@ -450,18 +457,17 @@ static void* phTmlNfc_TmlWriterThread(void* pParam) {
         /* TML reader writer callback synchronization mutex lock --- END */
         pthread_mutex_unlock(&gpphTmlNfc_Context->wait_busy_lock);
 
-        /* Try I2C Write Five Times, if it fails : Raju */
+        /* Try NFCC Write Five Times, if it fails: */
         if (-1 == dwNoBytesWrRd) {
           if (gpTransportObj->IsFwDnldModeEnabled()) {
             if (retry_cnt++ < MAX_WRITE_RETRY_COUNT) {
-              NXPLOG_TML_D("PN54X - Error in I2C Write  - Retry 0x%x",
-                           retry_cnt);
+              NXPLOG_TML_D("NFCC - Error in Write  - Retry 0x%x", retry_cnt);
               // Add a 10 ms delay to ensure NFCC is not still in stand by mode.
               usleep(10 * 1000);
               goto retry;
             }
           }
-          NXPLOG_TML_D("PN54X - Error in I2C Write.....\n");
+          NXPLOG_TML_D("NFCC - Error in Write.....\n");
           wStatus = PHNFCSTVAL(CID_NFC_TML, NFCSTATUS_FAILED);
         } else {
           phNxpNciHal_print_packet("SEND",
@@ -470,7 +476,7 @@ static void* phTmlNfc_TmlWriterThread(void* pParam) {
         }
         retry_cnt = 0;
         if (NFCSTATUS_SUCCESS == wStatus) {
-          NXPLOG_TML_D("PN54X - I2C Write successful.....\n");
+          NXPLOG_TML_D("NFCC - Write successful.....\n");
           dwNoBytesWrRd = PH_TMLNFC_VALUE_ONE;
         }
         /* Fill the Transaction info structure to be passed to Callback Function
@@ -499,14 +505,14 @@ static void* phTmlNfc_TmlWriterThread(void* pParam) {
             (0x00 != (gpphTmlNfc_Context->tWriteInfo.pBuffer[0] & 0xE0))) {
           if (gpphTmlNfc_Context->bWriteCbInvoked == false) {
             if ((NFCSTATUS_SUCCESS == wStatus) || (bCurrentRetryCount == 0)) {
-              NXPLOG_TML_D("PN54X - Posting Write message.....\n");
+              NXPLOG_TML_D("NFCC - Posting Write message.....\n");
               phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId,
                                     &tMsg);
               gpphTmlNfc_Context->bWriteCbInvoked = true;
             }
           }
         } else {
-          NXPLOG_TML_D("PN54X - Posting Fresh Write message.....\n");
+          NXPLOG_TML_D("NFCC - Posting Fresh Write message.....\n");
           phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId, &tMsg);
           if (NFCSTATUS_SUCCESS == wStatus) {
             /*TML reader writer thread callback synchronization---START*/
@@ -518,10 +524,10 @@ static void* phTmlNfc_TmlWriterThread(void* pParam) {
           }
         }
       } else {
-        NXPLOG_TML_D("PN54X - gpphTmlNfc_Context->pDevHandle is NULL");
+        NXPLOG_TML_D("NFCC - gpphTmlNfc_Context->pDevHandle is NULL");
       }
     } else {
-      NXPLOG_TML_D("PN54X - Write request NOT enabled");
+      NXPLOG_TML_D("NFCC - Write request NOT enabled");
       usleep(10000);
     }
 
@@ -628,7 +634,7 @@ NFCSTATUS phTmlNfc_Shutdown(void) {
 **                  NOTE:
 **                  * it is important to post a message with id
 **                    PH_TMLNFC_WRITE_MESSAGE to IntegrationThread after data
-**                    has been written to PN54X
+**                    has been written to NFCC
 **                  * if CRC needs to be computed, then input buffer should be
 **                    capable to store two more bytes apart from length of
 **                    packet
@@ -880,7 +886,7 @@ NFCSTATUS phTmlNfc_IoCtl(phTmlNfc_ControlCode_t eControlCode) {
 
       {
         if (IS_CHIP_TYPE_L(sn100u)) {
-          /*Reset PN54X*/
+          /*Reset NFCC*/
           gpTransportObj->NfccReset(gpphTmlNfc_Context->pDevHandle,
                                     MODE_POWER_ON);
           usleep(100 * 1000);
@@ -893,7 +899,7 @@ NFCSTATUS phTmlNfc_IoCtl(phTmlNfc_ControlCode_t eControlCode) {
         break;
       }
       case phTmlNfc_e_EnableNormalMode: {
-        /*Reset PN54X*/
+        /*Reset NFCC*/
         gpphTmlNfc_Context->tReadInfo.bEnable = 0;
         if (nfcFL.nfccFL._NFCC_DWNLD_MODE == NFCC_DWNLD_WITH_VEN_RESET) {
           NXPLOG_TML_D(" phTmlNfc_e_EnableNormalMode complete with VEN RESET ");
@@ -947,7 +953,7 @@ NFCSTATUS phTmlNfc_IoCtl(phTmlNfc_ControlCode_t eControlCode) {
       }
       case phTmlNfc_e_setFragmentSize: {
         if (IS_CHIP_TYPE_EQ(sn300u)) {
-          if (phTmlNfc_IsFwDnldModeEnabled()) {
+          if (phTmlNfc_IsFwDnldModeEnabled() && IS_4K_SUPPORT) {
             gpphTmlNfc_Context->fragment_len = PH_TMLNFC_FRGMENT_SIZE_SN300;
           } else {
             gpphTmlNfc_Context->fragment_len = PH_TMLNFC_FRGMENT_SIZE_SNXXX;
diff --git a/snxxx/halimpl/tml/phTmlNfc.h b/snxxx/halimpl/tml/phTmlNfc.h
index 9467f02..b0a6165 100644
--- a/snxxx/halimpl/tml/phTmlNfc.h
+++ b/snxxx/halimpl/tml/phTmlNfc.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2010-2023 NXP
+ * Copyright 2010-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -28,6 +28,7 @@
 #ifndef PHTMLNFC_H
 #define PHTMLNFC_H
 
+#include <errno.h>
 #include <phNfcCommon.h>
 
 /*
@@ -47,21 +48,21 @@
  */
 #define PH_TMLNFC_RESETDEVICE (0x00008001)
 
-/*
- * The 4096 bytes fragment len is supported during SN300 FW DNLD.
- * If this macro is not defined, then the fragment len will fallback to 554.
- */
-#define PH_TMLNFC_HDLL_4K_WRITE_SUPPORTED
 /*
  * Fragment Length for SNXXX and PN547
  */
 #define PH_TMLNFC_FRGMENT_SIZE_PN557 (0x102)
 #define PH_TMLNFC_FRGMENT_SIZE_SNXXX (0x22A)
-#ifdef PH_TMLNFC_HDLL_4K_WRITE_SUPPORTED
 #define PH_TMLNFC_FRGMENT_SIZE_SN300 (0x1000)
-#else
-#define PH_TMLNFC_FRGMENT_SIZE_SN300 (0x22A)
-#endif
+
+/*
+ * Value indicates to NFCC Max read length.
+ */
+#define PH_TMLNFC_MAX_READ_NCI_BUFF_LEN (260)
+/*
+ * Value indicates to NFCC recovery from vbat low.
+ */
+#define PH_TMNFC_VBAT_LOW_ERROR (-ENOTCONN)
 /*
 ***************************Globals,Structure and Enumeration ******************
 */
@@ -197,11 +198,11 @@ typedef struct phTmlNfc_Context {
  * TML Configuration exposed to upper layer.
  */
 typedef struct phTmlNfc_Config {
-  /* Port name connected to PN54X
+  /* Port name connected to NFCC
    *
-   * Platform specific canonical device name to which PN54X is connected.
+   * Platform specific canonical device name to which NFCC is connected.
    *
-   * e.g. On Linux based systems this would be /dev/PN54X
+   * e.g. On Linux based systems this would be /dev/nxp-nci
    */
   int8_t* pDevName;
   /* Callback Thread ID
diff --git a/snxxx/halimpl/tml/transport/NfccI2cTransport.cc b/snxxx/halimpl/tml/transport/NfccI2cTransport.cc
index a568b95..b3f0b90 100644
--- a/snxxx/halimpl/tml/transport/NfccI2cTransport.cc
+++ b/snxxx/halimpl/tml/transport/NfccI2cTransport.cc
@@ -1,5 +1,5 @@
 /******************************************************************************
- *  Copyright 2020-2023 NXP
+ *  Copyright 2020-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -190,6 +190,9 @@ int NfccI2cTransport::Read(void* pDevHandle, uint8_t* pBuffer,
     } else if (ret_Read == 0) {
       NXPLOG_TML_E("%s [hdr]EOF", __func__);
       return -1;
+    } else if (errno == ENOTCONN) {
+      NXPLOG_TML_E("%s [hdr] errno : %x", __func__, errno);
+      return -ENOTCONN;
     } else {
       NXPLOG_TML_E("%s [hdr] errno : %x", __func__, errno);
       NXPLOG_TML_E(" %s pBuffer[0] = %x pBuffer[1]= %x", __func__, pBuffer[0],
diff --git a/snxxx/halimpl/utils/phNxpConfig.h b/snxxx/halimpl/utils/phNxpConfig.h
index 6071e14..7a2d630 100644
--- a/snxxx/halimpl/utils/phNxpConfig.h
+++ b/snxxx/halimpl/utils/phNxpConfig.h
@@ -20,7 +20,7 @@
  *
  *  The original Work has been changed by NXP.
  *
- *  Copyright 2013-2023 NXP
+ *  Copyright 2013-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -89,6 +89,7 @@ extern char Fw_Lib_Path[256];
 #define NAME_NXP_CHINA_BLK_NUM_CHK_ENABLE "NXP_CN_TRANSIT_BLK_NUM_CHECK_ENABLE"
 #define NAME_NXP_CN_TRANSIT_CMA_BYPASSMODE_ENABLE \
   "NXP_CN_TRANSIT_CMA_BYPASSMODE_ENABLE"
+#define NAME_NXP_MIFARE_MUTE_TO_RATS_ENABLE "NXP_MIFARE_MUTE_TO_RATS_ENABLE"
 #define NAME_NXP_SWP_SWITCH_TIMEOUT "NXP_SWP_SWITCH_TIMEOUT"
 #define NAME_NXP_SWP_FULL_PWR_ON "NXP_SWP_FULL_PWR_ON"
 #define NAME_NXP_CORE_RF_FIELD "NXP_CORE_RF_FIELD"
@@ -109,6 +110,7 @@ extern char Fw_Lib_Path[256];
 #define NAME_DEFAULT_SYS_CODE_PWR_STATE "DEFAULT_SYS_CODE_PWR_STATE"
 #define NAME_OFF_HOST_ESE_PIPE_ID "OFF_HOST_ESE_PIPE_ID"
 #define NAME_OFF_HOST_SIM_PIPE_ID "OFF_HOST_SIM_PIPE_ID"
+#define NAME_OFF_HOST_SIM_PIPE_IDS "OFF_HOST_SIM_PIPE_IDS"
 #define NAME_DEFAULT_OFFHOST_ROUTE "DEFAULT_OFFHOST_ROUTE"
 #define NAME_DEFAULT_NFCF_ROUTE "DEFAULT_NFCF_ROUTE"
 #define NAME_ISO_DEP_MAX_TRANSCEIVE "ISO_DEP_MAX_TRANSCEIVE"
@@ -185,4 +187,6 @@ extern char Fw_Lib_Path[256];
 /* default configuration */
 #define default_storage_location "/data/vendor/nfc"
 #define NAME_NXP_AUTH_TIMEOUT_CFG "NXP_AUTH_TIMEOUT_CFG"
+#define NAME_NXP_REMOVAL_DETECTION_TIMEOUT "NXP_REMOVAL_DETECTION_TIMEOUT"
+#define NAME_NXP_4K_FWDNLD_SUPPORT "NXP_4K_FWDNLD_SUPPORT"
 #endif
diff --git a/snxxx/halimpl/utils/phNxpEventLogger.h b/snxxx/halimpl/utils/phNxpEventLogger.h
index 03a333a..7edbdee 100644
--- a/snxxx/halimpl/utils/phNxpEventLogger.h
+++ b/snxxx/halimpl/utils/phNxpEventLogger.h
@@ -19,6 +19,7 @@
 #include <fstream>
 
 #define ESE_CONNECTIVITY_PACKET 0x96
+#define EUICC_CONNECTIVITY_PACKET 0xAB
 #define ESE_DPD_EVENT 0x70
 
 enum class LogEventType { kLogSMBEvent = 0, kLogDPDEvent };
diff --git a/snxxx/halimpl/utils/phNxpNciHal_utils.cc b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
index 58c5610..3f6c7b3 100644
--- a/snxxx/halimpl/utils/phNxpNciHal_utils.cc
+++ b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
@@ -513,7 +513,7 @@ void phNxpNciHal_emergency_recovery(uint8_t status) {
       abort();
     }
     case CORE_RESET_TRIGGER_TYPE_POWERED_ON: {
-      if (nxpncihal_ctrl.hal_open_status == true &&
+      if (nxpncihal_ctrl.hal_open_status != HAL_CLOSED &&
           nxpncihal_ctrl.power_reset_triggered == false) {
         phNxpNciHal_decodeGpioStatus();
         NXPLOG_NCIHAL_E("abort()");
```

