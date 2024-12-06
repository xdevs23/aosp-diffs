```diff
diff --git a/aidl/Android.bp b/aidl/Android.bp
index dc0c4f9..7cc07a0 100644
--- a/aidl/Android.bp
+++ b/aidl/Android.bp
@@ -7,8 +7,34 @@ package {
     default_applicable_licenses: ["hardware_st_nfc_license"],
 }
 
+cc_defaults {
+    name: "android.hardware.nfc-service.st_default",
+    cflags: [
+        "-Wall",
+        "-Wextra",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libutils",
+        "libbinder_ndk",
+        "android.hardware.nfc-V1-ndk",
+        "nfc_nci.st21nfc.default",
+    ],
+    srcs: [
+        "Nfc.cpp",
+        "hal_st21nfc.cc",
+    ],
+    arch: {
+        arm: {
+            cflags: ["-DST_LIB_32"],
+        },
+    },
+}
+
 cc_binary {
     name: "android.hardware.nfc-service.st",
+    defaults: ["android.hardware.nfc-service.st_default"],
     relative_install_path: "hw",
     init_rc: ["nfc-service-default.rc"],
     vintf_fragments: ["nfc-service-default.xml"],
@@ -27,10 +53,22 @@ cc_binary {
     ],
     srcs: [
         "main.cpp",
-        "Nfc.cpp",
-        "hal_st21nfc.cc",
     ],
     arch: {
-        arm: { cflags: ["-DST_LIB_32"] },
-    }
+        arm: {
+            cflags: ["-DST_LIB_32"],
+        },
+    },
+}
+
+cc_fuzz {
+    name: "nfc_service_fuzzer",
+    defaults: [
+        "android.hardware.nfc-service.st_default",
+        "service_fuzzer_defaults",
+    ],
+    srcs: [
+        "fuzzer/NfcServiceFuzzer.cpp",
+    ],
+    vendor: true,
 }
diff --git a/aidl/corpus/seed-2024-08-29-0 b/aidl/corpus/seed-2024-08-29-0
new file mode 100644
index 0000000..3e96f67
Binary files /dev/null and b/aidl/corpus/seed-2024-08-29-0 differ
diff --git a/aidl/corpus/seed-2024-08-29-1 b/aidl/corpus/seed-2024-08-29-1
new file mode 100644
index 0000000..f06504d
Binary files /dev/null and b/aidl/corpus/seed-2024-08-29-1 differ
diff --git a/aidl/corpus/seed-2024-08-29-2 b/aidl/corpus/seed-2024-08-29-2
new file mode 100644
index 0000000..21ba259
Binary files /dev/null and b/aidl/corpus/seed-2024-08-29-2 differ
diff --git a/aidl/corpus/seed-2024-08-29-3 b/aidl/corpus/seed-2024-08-29-3
new file mode 100644
index 0000000..9ee2684
Binary files /dev/null and b/aidl/corpus/seed-2024-08-29-3 differ
diff --git a/aidl/corpus/seed-2024-08-29-4 b/aidl/corpus/seed-2024-08-29-4
new file mode 100644
index 0000000..c53be3d
Binary files /dev/null and b/aidl/corpus/seed-2024-08-29-4 differ
diff --git a/aidl/corpus/seed-2024-08-29-5 b/aidl/corpus/seed-2024-08-29-5
new file mode 100644
index 0000000..b66a0c7
Binary files /dev/null and b/aidl/corpus/seed-2024-08-29-5 differ
diff --git a/aidl/fuzzer/NfcServiceFuzzer.cpp b/aidl/fuzzer/NfcServiceFuzzer.cpp
new file mode 100644
index 0000000..6cded0e
--- /dev/null
+++ b/aidl/fuzzer/NfcServiceFuzzer.cpp
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+#include <fuzzbinder/libbinder_ndk_driver.h>
+#include <fuzzer/FuzzedDataProvider.h>
+
+#include "Nfc.h"
+
+using android::fuzzService;
+using ndk::SharedRefBase;
+using ::aidl::android::hardware::nfc::Nfc;
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+  std::shared_ptr<Nfc> nfc_service = ndk::SharedRefBase::make<Nfc>();
+  fuzzService(nfc_service->asBinder().get(), FuzzedDataProvider(data, size));
+  return 0;
+}
\ No newline at end of file
diff --git a/aidl/hal_st21nfc.cc b/aidl/hal_st21nfc.cc
index 70b9371..5a56b6c 100644
--- a/aidl/hal_st21nfc.cc
+++ b/aidl/hal_st21nfc.cc
@@ -402,7 +402,8 @@ int StNfc_hal_close(int nfc_mode_value) {
 
   std::string valueStr =
       android::base::GetProperty("persist.vendor.nfc.streset", "");
-  if (valueStr.length() > 0) {
+  // do a cold_reset when nfc is off
+  if (valueStr.length() > 0 && nfc_mode_value == 0) {
     stdll = dlopen(valueStr.c_str(), RTLD_NOW);
     if (!stdll) {
       valueStr = VENDOR_LIB_PATH + valueStr + VENDOR_LIB_EXT;
diff --git a/st21nfc/hal/hal_fwlog.cc b/st21nfc/hal/hal_fwlog.cc
index 8704639..cd75907 100644
--- a/st21nfc/hal/hal_fwlog.cc
+++ b/st21nfc/hal/hal_fwlog.cc
@@ -55,7 +55,7 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
     case T_fieldOn:
     case T_fieldOff:
       STLOG_HAL_D("%s - FieldOn/Off", __func__);
-      *NewTlv = (uint8_t*)malloc(8 * sizeof(uint8_t));
+      *NewTlv = (uint8_t*)malloc(9 * sizeof(uint8_t));
       value_len = 0x06;
       (*NewTlv)[0] = TYPE_REMOTE_FIELD;
       (*NewTlv)[1] = flag;
diff --git a/st21nfc/hal/halcore.cc b/st21nfc/hal/halcore.cc
index eb696d2..dcbbb1d 100644
--- a/st21nfc/hal/halcore.cc
+++ b/st21nfc/hal/halcore.cc
@@ -307,6 +307,10 @@ void HalDestroy(HALHANDLE hHAL) {
 {
   // Send an NCI frame downstream. will
   HalInstance* inst = (HalInstance*)hHAL;
+  if(inst == nullptr) {
+    STLOG_HAL_E("HalInstance is null.");
+    return false;
+  }
 
   if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
     ThreadMesssage msg;
@@ -601,6 +605,10 @@ static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
  */
 static HalBuffer* HalAllocBuffer(HalInstance* inst) {
   HalBuffer* b;
+  if(inst == nullptr) {
+    STLOG_HAL_E("HalInstance is null.");
+    return nullptr;
+  }
 
   // Wait until we have a buffer resource
   sem_wait_nointr(&inst->bufferResourceSem);
diff --git a/st21nfc/hal_wrapper.cc b/st21nfc/hal_wrapper.cc
index 7d82ef7..c3bb0c0 100644
--- a/st21nfc/hal_wrapper.cc
+++ b/st21nfc/hal_wrapper.cc
@@ -168,7 +168,6 @@ void hal_wrapper_send_core_config_prop() {
       STLOG_HAL_V("%s - Enter", __func__);
       set_ready(0);
 
-      mHalWrapperState = HAL_WRAPPER_STATE_PROP_CONFIG;
       if (!HalSendDownstreamTimer(mHalHandle, ConfigBuffer, retlen, 1000)) {
         STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
       }
@@ -182,7 +181,7 @@ void hal_wrapper_send_core_config_prop() {
 void hal_wrapper_send_vs_config() {
   STLOG_HAL_V("%s - Enter", __func__);
   set_ready(0);
-
+  mHalWrapperState = HAL_WRAPPER_STATE_PROP_CONFIG;
   mReadFwConfigDone = true;
   if (!HalSendDownstreamTimer(mHalHandle, nciPropGetFwDbgTracesConfig,
                               sizeof(nciPropGetFwDbgTracesConfig), 1000)) {
@@ -192,9 +191,9 @@ void hal_wrapper_send_vs_config() {
 }
 
 void hal_wrapper_send_config() {
-  hal_wrapper_send_core_config_prop();
-  mHalWrapperState = HAL_WRAPPER_STATE_PROP_CONFIG;
   hal_wrapper_send_vs_config();
+  mHalWrapperState = HAL_WRAPPER_STATE_PROP_CONFIG;
+  hal_wrapper_send_core_config_prop();
 }
 
 void hal_wrapper_factoryReset() {
@@ -394,9 +393,13 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
       // CORE_SET_CONFIG_RSP
       if ((p_data[0] == 0x40) && (p_data[1] == 0x02)) {
         HalSendDownstreamStopTimer(mHalHandle);
+        GetNumValue(NAME_STNFC_REMOTE_FIELD_TIMER, &hal_field_timer,
+                    sizeof(hal_field_timer));
+        STLOG_HAL_D("%s - hal_field_timer = %lu", __func__, hal_field_timer);
         set_ready(1);
-
-        STLOG_HAL_V("%s - Received config RSP, read FW dDBG config", __func__);
+        // Exit state, all processing done
+        mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
+        mHalWrapperState = HAL_WRAPPER_STATE_READY;
       } else if (mHciCreditLent && (p_data[0] == 0x60) && (p_data[1] == 0x06)) {
         // CORE_CONN_CREDITS_NTF
         if (p_data[4] == 0x01) {  // HCI connection
@@ -418,7 +421,6 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
         if (mReadFwConfigDone == true) {
           mReadFwConfigDone = false;
           HalSendDownstreamStopTimer(mHalHandle);
-          set_ready(1);
           // NFC_STATUS_OK
           if (p_data[3] == 0x00) {
             bool confNeeded = false;
@@ -505,16 +507,16 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
                 }
                 mHalWrapperState = HAL_WRAPPER_STATE_APPLY_PROP_CONFIG;
                 break;
+              } else {
+                set_ready(1);
               }
             }
+          } else {
+            set_ready(1);
           }
+        } else {
+          set_ready(1);
         }
-        GetNumValue(NAME_STNFC_REMOTE_FIELD_TIMER, &hal_field_timer,
-                    sizeof(hal_field_timer));
-        STLOG_HAL_D("%s - hal_field_timer = %lu", __func__, hal_field_timer);
-        // Exit state, all processing done
-        mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
-        mHalWrapperState = HAL_WRAPPER_STATE_READY;
       }
       break;
 
@@ -723,9 +725,7 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
       }
       // CORE_INIT_RSP
       else if ((p_data[0] == 0x40) && (p_data[1] == 0x01)) {
-        // Exit state, all processing done
-        mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
-        mHalWrapperState = HAL_WRAPPER_STATE_READY;
+        set_ready(1);
       }
       break;
     case HAL_WRAPPER_STATE_RECOVERY:
```

