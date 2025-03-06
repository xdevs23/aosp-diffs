```diff
diff --git a/KM200/Android.bp b/KM200/Android.bp
index c8fedd8..75684c8 100644
--- a/KM200/Android.bp
+++ b/KM200/Android.bp
@@ -54,6 +54,7 @@ cc_library {
     cflags: [
         "-O0",
         "-DNXP_EXTNS",
+        "-Wno-enum-constexpr-conversion",
     ],
     shared_libs: [
         "android.hardware.security.secureclock-V1-ndk",
@@ -69,6 +70,7 @@ cc_library {
         "libcutils",
         "libjc_keymint_transport.nxp",
         "libbinder_ndk",
+        "libmemunreachable",
         "android.hardware.security.keymint-V2-ndk",
         "android.hardware.security.rkp-V2-ndk",
     ],
diff --git a/KM200/CborConverter.cpp b/KM200/CborConverter.cpp
index e34c651..b3a538c 100644
--- a/KM200/CborConverter.cpp
+++ b/KM200/CborConverter.cpp
@@ -14,6 +14,25 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
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
+ *  Copyright 2023 NXP
+ *
+ ******************************************************************************/
 
 #include "CborConverter.h"
 #include <JavacardKeyMintUtils.h>
@@ -25,10 +44,12 @@
 #include <vector>
 
 namespace keymint::javacard {
-using namespace cppbor;
-using namespace aidl::android::hardware::security::keymint;
-using namespace aidl::android::hardware::security::secureclock;
-using namespace aidl::android::hardware::security::sharedsecret;
+using ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType;
+using ::aidl::android::hardware::security::keymint::SecurityLevel;
+using ::aidl::android::hardware::security::keymint::km_utils::aidlKeyParams2Km;
+using ::aidl::android::hardware::security::keymint::km_utils::kmBlob2vector;
+using ::aidl::android::hardware::security::keymint::km_utils::kmParam2Aidl;
+using ::aidl::android::hardware::security::keymint::km_utils::typeFromTag;
 using std::string;
 using std::unique_ptr;
 using std::vector;
@@ -48,13 +69,13 @@ bool CborConverter::addAttestationKey(Array& array,
 }
 
 bool CborConverter::addKeyparameters(Array& array, const vector<KeyParameter>& keyParams) {
-    keymaster_key_param_set_t paramSet = km_utils::aidlKeyParams2Km(keyParams);
+    keymaster_key_param_set_t paramSet = aidlKeyParams2Km(keyParams);
     Map map;
     std::map<uint64_t, vector<uint8_t>> enum_repetition;
     std::map<uint64_t, Array> uint_repetition;
     for (size_t i = 0; i < paramSet.length; i++) {
         const auto& param = paramSet.params[i];
-        switch (km_utils::typeFromTag(param.tag)) {
+        switch (typeFromTag(param.tag)) {
         case KM_ENUM:
             map.add(static_cast<uint64_t>(param.tag), param.enumerated);
             break;
@@ -84,7 +105,7 @@ bool CborConverter::addKeyparameters(Array& array, const vector<KeyParameter>& k
         case KM_BIGNUM:
         case KM_BYTES:
             map.add(static_cast<uint64_t>(param.tag & 0x00000000ffffffff),
-                    km_utils::kmBlob2vector(param.blob));
+                    kmBlob2vector(param.blob));
             break;
         default:
             /* Invalid skip */
@@ -146,7 +167,7 @@ bool CborConverter::getKeyParameter(
             keymaster_key_param_t keyParam;
             keyParam.tag = static_cast<keymaster_tag_t>(key);
             keyParam.enumerated = bchar;
-            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+            keyParams.push_back(kmParam2Aidl(keyParam));
         }
     } break;
     case KM_ENUM: {
@@ -156,7 +177,7 @@ bool CborConverter::getKeyParameter(
             return false;
         }
         keyParam.enumerated = static_cast<uint32_t>(value);
-        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+        keyParams.push_back(kmParam2Aidl(keyParam));
     } break;
     case KM_UINT: {
         keymaster_key_param_t keyParam;
@@ -165,7 +186,7 @@ bool CborConverter::getKeyParameter(
             return false;
         }
         keyParam.integer = static_cast<uint32_t>(value);
-        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+        keyParams.push_back(kmParam2Aidl(keyParam));
     } break;
     case KM_ULONG: {
         keymaster_key_param_t keyParam;
@@ -174,7 +195,7 @@ bool CborConverter::getKeyParameter(
             return false;
         }
         keyParam.long_integer = value;
-        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+        keyParams.push_back(kmParam2Aidl(keyParam));
     } break;
     case KM_UINT_REP: {
         /* UINT_REP contains values encoded in a Array */
@@ -188,7 +209,7 @@ bool CborConverter::getKeyParameter(
                 return false;
             }
             keyParam.integer = static_cast<uint32_t>(value);
-            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+            keyParams.push_back(kmParam2Aidl(keyParam));
         }
     } break;
     case KM_ULONG_REP: {
@@ -202,7 +223,7 @@ bool CborConverter::getKeyParameter(
             if (!getUint64(item, keyParam.long_integer)) {
                 return false;
             }
-            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+            keyParams.push_back(kmParam2Aidl(keyParam));
         }
     } break;
     case KM_DATE: {
@@ -212,7 +233,7 @@ bool CborConverter::getKeyParameter(
             return false;
         }
         keyParam.date_time = value;
-        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+        keyParams.push_back(kmParam2Aidl(keyParam));
     } break;
     case KM_BOOL: {
         keymaster_key_param_t keyParam;
@@ -222,7 +243,7 @@ bool CborConverter::getKeyParameter(
         }
         // TODO re-check the logic below
         keyParam.boolean = static_cast<bool>(value);
-        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+        keyParams.push_back(kmParam2Aidl(keyParam));
     } break;
     case KM_BYTES: {
         keymaster_key_param_t keyParam;
@@ -231,7 +252,7 @@ bool CborConverter::getKeyParameter(
         if (bstr == nullptr) return false;
         keyParam.blob.data = bstr->value().data();
         keyParam.blob.data_length = bstr->value().size();
-        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
+        keyParams.push_back(kmParam2Aidl(keyParam));
     } break;
     default:
         /* Invalid - return error */
@@ -319,7 +340,7 @@ bool CborConverter::getSharedSecretParameters(const unique_ptr<Item>& item, cons
 bool CborConverter::addSharedSecretParameters(Array& array,
                                               const vector<SharedSecretParameters>& params) {
     Array cborParamsVec;
-    for (auto param : params) {
+    for (const auto &param : params) {
         Array cborParam;
         cborParam.add(Bstr(param.seed));
         cborParam.add(Bstr(param.nonce));
@@ -367,11 +388,11 @@ bool CborConverter::getHardwareAuthToken(const unique_ptr<Item>& item, const uin
         !getBinaryArray(item, pos + 5, token.mac)) {
         return false;
     }
-    token.challenge = static_cast<long>(challenge);
-    token.userId = static_cast<long>(userId);
-    token.authenticatorId = static_cast<long>(authenticatorId);
+    token.challenge = static_cast<int64_t>(challenge);
+    token.userId = static_cast<int64_t>(userId);
+    token.authenticatorId = static_cast<int64_t>(authenticatorId);
     token.authenticatorType = static_cast<HardwareAuthenticatorType>(authType);
-    token.timestamp.milliSeconds = static_cast<long>(timestampMillis);
+    token.timestamp.milliSeconds = static_cast<int64_t>(timestampMillis);
     return true;
 }
 
@@ -385,8 +406,8 @@ bool CborConverter::getTimeStampToken(const unique_ptr<Item>& item, const uint32
         !getBinaryArray(item, pos + 2, token.mac)) {
         return false;
     }
-    token.challenge = static_cast<long>(challenge);
-    token.timestamp.milliSeconds = static_cast<long>(timestampMillis);
+    token.challenge = static_cast<int64_t>(challenge);
+    token.timestamp.milliSeconds = static_cast<int64_t>(timestampMillis);
     return true;
 }
 
diff --git a/KM200/CborConverter.h b/KM200/CborConverter.h
index db1033b..a628210 100644
--- a/KM200/CborConverter.h
+++ b/KM200/CborConverter.h
@@ -14,6 +14,25 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
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
+ *  Copyright 2023 NXP
+ *
+ ******************************************************************************/
 #pragma once
 #include <aidl/android/hardware/security/keymint/Certificate.h>
 #include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
@@ -28,10 +47,21 @@
 #include <vector>
 
 namespace keymint::javacard {
-using namespace cppbor;
-using namespace aidl::android::hardware::security::keymint;
-using namespace aidl::android::hardware::security::secureclock;
-using namespace aidl::android::hardware::security::sharedsecret;
+using aidl::android::hardware::security::keymint::AttestationKey;
+using aidl::android::hardware::security::keymint::Certificate;
+using aidl::android::hardware::security::keymint::HardwareAuthToken;
+using aidl::android::hardware::security::keymint::KeyCharacteristics;
+using aidl::android::hardware::security::keymint::KeyParameter;
+using aidl::android::hardware::security::secureclock::TimeStampToken;
+using aidl::android::hardware::security::sharedsecret::SharedSecretParameters;
+using cppbor::Array;
+using cppbor::Bstr;
+using cppbor::Item;
+using cppbor::MajorType;
+using cppbor::Map;
+using cppbor::Nint;
+using cppbor::parse;
+using cppbor::Uint;
 using std::string;
 using std::unique_ptr;
 using std::vector;
diff --git a/KM200/JavacardKeyMintDevice.cpp b/KM200/JavacardKeyMintDevice.cpp
index 541cdbe..d447baa 100644
--- a/KM200/JavacardKeyMintDevice.cpp
+++ b/KM200/JavacardKeyMintDevice.cpp
@@ -14,24 +14,24 @@
  * limitations under the License.
  */
 /******************************************************************************
-*
-*  The original Work has been changed by NXP.
-*
-*  Licensed under the Apache License, Version 2.0 (the "License");
-*  you may not use this file except in compliance with the License.
-*  You may obtain a copy of the License at
-*
-*  http://www.apache.org/licenses/LICENSE-2.0
-*
-*  Unless required by applicable law or agreed to in writing, software
-*  distributed under the License is distributed on an "AS IS" BASIS,
-*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-*  See the License for the specific language governing permissions and
-*  limitations under the License.
-*
-*  Copyright 2022 NXP
-*
-******************************************************************************/
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
+ *  Copyright 2022-2023 NXP
+ *
+ ******************************************************************************/
 #define LOG_TAG "javacard.keymint.device.strongbox-impl"
 #include "JavacardKeyMintDevice.h"
 #include "JavacardKeyMintOperation.h"
@@ -46,14 +46,20 @@
 #include <keymaster/android_keymaster_messages.h>
 #include <keymaster/wrapped_key.h>
 #include <memory>
+#include <memunreachable/memunreachable.h>
 #include <regex.h>
 #include <string>
 #include <vector>
 
 namespace aidl::android::hardware::security::keymint {
-using km_utils::KmParamSet;
-using namespace ::keymaster;
-using namespace ::keymint::javacard;
+using cppbor::Array;
+using cppbor::Bstr;
+using cppbor::Uint;
+using ::keymaster::AuthorizationSet;
+using ::keymaster::dup_buffer;
+using ::keymaster::KeymasterBlob;
+using ::keymaster::KeymasterKeyBlob;
+using ::keymint::javacard::Instruction;
 
 ScopedAStatus JavacardKeyMintDevice::defaultHwInfo(KeyMintHardwareInfo* info) {
     info->versionNumber = 1;
@@ -90,7 +96,7 @@ ScopedAStatus JavacardKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info)
 ScopedAStatus JavacardKeyMintDevice::generateKey(const vector<KeyParameter>& keyParams,
                                                  const optional<AttestationKey>& attestationKey,
                                                  KeyCreationResult* creationResult) {
-    cppbor::Array array;
+    Array array;
     // add key params
     cbor_.addKeyparameters(array, keyParams);
     // add attestation key if any
@@ -110,7 +116,7 @@ ScopedAStatus JavacardKeyMintDevice::generateKey(const vector<KeyParameter>& key
 }
 
 ScopedAStatus JavacardKeyMintDevice::addRngEntropy(const vector<uint8_t>& data) {
-    cppbor::Array request;
+    Array request;
     // add key data
     request.add(Bstr(data));
     auto [item, err] = card_->sendRequest(Instruction::INS_ADD_RNG_ENTROPY_CMD, request);
@@ -126,7 +132,7 @@ ScopedAStatus JavacardKeyMintDevice::importKey(const vector<KeyParameter>& keyPa
                                                const optional<AttestationKey>& attestationKey,
                                                KeyCreationResult* creationResult) {
 
-    cppbor::Array request;
+    Array request;
     // add key params
     cbor_.addKeyparameters(request, keyParams);
     // add key format
@@ -157,7 +163,7 @@ ScopedAStatus JavacardKeyMintDevice::importWrappedKey(const vector<uint8_t>& wra
                                                       const vector<KeyParameter>& unwrappingParams,
                                                       int64_t passwordSid, int64_t biometricSid,
                                                       KeyCreationResult* creationResult) {
-    cppbor::Array request;
+    Array request;
     std::unique_ptr<Item> item;
     vector<uint8_t> keyBlob;
     std::vector<uint8_t> response;
@@ -233,7 +239,7 @@ JavacardKeyMintDevice::sendFinishImportWrappedKeyCmd(
 ScopedAStatus JavacardKeyMintDevice::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                 const vector<KeyParameter>& upgradeParams,
                                                 vector<uint8_t>* keyBlob) {
-    cppbor::Array request;
+    Array request;
     // add key blob
     request.add(Bstr(keyBlobToUpgrade));
     // add key params
@@ -284,7 +290,7 @@ ScopedAStatus JavacardKeyMintDevice::begin(KeyPurpose purpose, const std::vector
                                            const std::optional<HardwareAuthToken>& authToken,
                                            BeginResult* result) {
 
-    cppbor::Array array;
+    Array array;
     std::vector<uint8_t> response;
     // make request
     array.add(Uint(static_cast<uint64_t>(purpose)));
@@ -360,7 +366,7 @@ ScopedAStatus JavacardKeyMintDevice::earlyBootEnded() {
 ScopedAStatus JavacardKeyMintDevice::getKeyCharacteristics(
     const std::vector<uint8_t>& keyBlob, const std::vector<uint8_t>& appId,
     const std::vector<uint8_t>& appData, std::vector<KeyCharacteristics>* result) {
-    cppbor::Array request;
+    Array request;
     request.add(vector<uint8_t>(keyBlob));
     request.add(vector<uint8_t>(appId));
     request.add(vector<uint8_t>(appData));
@@ -446,4 +452,10 @@ ScopedAStatus JavacardKeyMintDevice::convertStorageKeyToEphemeral(
     std::vector<uint8_t>* /* ephemeralKeyBlob */) {
     return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
 }
+
+binder_status_t JavacardKeyMintDevice::dump(int /* fd */, const char** /* p */, uint32_t /* q */) {
+    LOG(INFO) << "\n KeyMint-JavacardKeyMintDevice HAL MemoryLeak Info = \n"
+              << ::android::GetUnreachableMemoryString(true, 10000).c_str();
+    return STATUS_OK;
+}
 }  // namespace aidl::android::hardware::security::keymint
diff --git a/KM200/JavacardKeyMintDevice.h b/KM200/JavacardKeyMintDevice.h
index 1afaf6e..8284800 100644
--- a/KM200/JavacardKeyMintDevice.h
+++ b/KM200/JavacardKeyMintDevice.h
@@ -14,24 +14,24 @@
  * limitations under the License.
  */
 /******************************************************************************
-*
-*  The original Work has been changed by NXP.
-*
-*  Licensed under the Apache License, Version 2.0 (the "License");
-*  you may not use this file except in compliance with the License.
-*  You may obtain a copy of the License at
-*
-*  http://www.apache.org/licenses/LICENSE-2.0
-*
-*  Unless required by applicable law or agreed to in writing, software
-*  distributed under the License is distributed on an "AS IS" BASIS,
-*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-*  See the License for the specific language governing permissions and
-*  limitations under the License.
-*
-*  Copyright 2022 NXP
-*
-******************************************************************************/
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
+ *  Copyright 2022-2023 NXP
+ *
+ ******************************************************************************/
 #pragma once
 
 #include "CborConverter.h"
@@ -42,10 +42,11 @@
 #include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>
 
 namespace aidl::android::hardware::security::keymint {
-using namespace ::keymint::javacard;
-using namespace aidl::android::hardware::security::sharedsecret;
-using namespace aidl::android::hardware::security::secureclock;
+using cppbor::Item;
+using ::keymint::javacard::CborConverter;
+using ::keymint::javacard::JavacardSecureElement;
 using ndk::ScopedAStatus;
+using secureclock::TimeStampToken;
 using std::optional;
 using std::shared_ptr;
 using std::vector;
@@ -53,12 +54,15 @@ using std::vector;
 class JavacardKeyMintDevice : public BnKeyMintDevice {
   public:
     explicit JavacardKeyMintDevice(shared_ptr<JavacardSecureElement> card)
-        : securitylevel_(SecurityLevel::STRONGBOX), card_(card),
+        : securitylevel_(SecurityLevel::STRONGBOX), card_(std::move(card)),
           isEarlyBootEventPending(true) {
         card_->initializeJavacard();
     }
     virtual ~JavacardKeyMintDevice() {}
 
+    // Methods from ::ndk::ICInterface follow.
+    binder_status_t dump(int fd, const char** args, uint32_t num_args) override;
+
     ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) override;
 
     ScopedAStatus addRngEntropy(const vector<uint8_t>& data) override;
diff --git a/KM200/JavacardKeyMintOperation.cpp b/KM200/JavacardKeyMintOperation.cpp
index 1f74d28..c291ae8 100644
--- a/KM200/JavacardKeyMintOperation.cpp
+++ b/KM200/JavacardKeyMintOperation.cpp
@@ -29,22 +29,28 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2022 NXP
+ ** Copyright 2022-2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.strongbox.keymint.operation-impl"
 
 #include "JavacardKeyMintOperation.h"
+#include "CborConverter.h"
 #include <JavacardKeyMintUtils.h>
 #include <aidl/android/hardware/security/keymint/ErrorCode.h>
 #include <aidl/android/hardware/security/secureclock/ISecureClock.h>
 #include <android-base/logging.h>
 
 namespace aidl::android::hardware::security::keymint {
-using namespace ::keymint::javacard;
+using cppbor::Bstr;
+using cppbor::Uint;
 using secureclock::TimeStampToken;
 
 JavacardKeyMintOperation::~JavacardKeyMintOperation() {
+#ifdef NXP_EXTNS
+    card_->setOperationState(::keymint::javacard::CryptoOperationState::FINISHED);
+#endif
+
     if (opHandle_ != 0) {
         abort();
     }
diff --git a/KM200/JavacardKeyMintOperation.h b/KM200/JavacardKeyMintOperation.h
index 5807fd5..6b1af88 100644
--- a/KM200/JavacardKeyMintOperation.h
+++ b/KM200/JavacardKeyMintOperation.h
@@ -13,6 +13,25 @@
  * See the License for the specific language governing permissions and
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
+ *  Copyright 2023-2024 NXP
+ *
+ ******************************************************************************/
 
 #pragma once
 
@@ -30,7 +49,11 @@
 #define EC_BUFFER_SIZE 32
 #define MAX_CHUNK_SIZE 256
 namespace aidl::android::hardware::security::keymint {
-using namespace ::keymint::javacard;
+using cppbor::Array;
+using cppbor::Item;
+using ::keymint::javacard::CborConverter;
+using ::keymint::javacard::Instruction;
+using ::keymint::javacard::JavacardSecureElement;
 using ::ndk::ScopedAStatus;
 using secureclock::TimeStampToken;
 using std::optional;
@@ -69,8 +92,13 @@ class JavacardKeyMintOperation : public BnKeyMintOperation {
                                       BufferingMode bufferingMode,
                                       uint16_t macLength,
                                       shared_ptr<JavacardSecureElement> card)
-        : buffer_(vector<uint8_t>()), bufferingMode_(bufferingMode), macLength_(macLength),
-          card_(card), opHandle_(opHandle)  {}
+        : buffer_(vector<uint8_t>()), bufferingMode_(bufferingMode),
+          macLength_(macLength), card_(std::move(card)), opHandle_(opHandle) {
+#ifdef NXP_EXTNS
+        card_->setOperationState(
+            ::keymint::javacard::CryptoOperationState::STARTED);
+#endif
+    }
     virtual ~JavacardKeyMintOperation();
 
     ScopedAStatus updateAad(const vector<uint8_t>& input,
diff --git a/KM200/JavacardKeyMintUtils.cpp b/KM200/JavacardKeyMintUtils.cpp
index 9860d40..5efc5f9 100644
--- a/KM200/JavacardKeyMintUtils.cpp
+++ b/KM200/JavacardKeyMintUtils.cpp
@@ -13,6 +13,25 @@
  * See the License for the specific language governing permissions and
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
+ *  Copyright 2023 NXP
+ *
+ ******************************************************************************/
 
 #include "JavacardKeyMintUtils.h"
 #include <android-base/logging.h>
@@ -36,6 +55,10 @@ KeyParameter kmEnumParam2Aidl(const keymaster_key_param_t& param) {
     case KM_TAG_DIGEST:
         return KeyParameter{Tag::DIGEST, KeyParameterValue::make<KeyParameterValue::digest>(
                                              static_cast<Digest>(param.enumerated))};
+    case KM_TAG_RSA_OAEP_MGF_DIGEST:
+        return KeyParameter{Tag::RSA_OAEP_MGF_DIGEST,
+                            KeyParameterValue::make<KeyParameterValue::digest>(
+                                static_cast<Digest>(param.enumerated))};
     case KM_TAG_PADDING:
         return KeyParameter{Tag::PADDING, KeyParameterValue::make<KeyParameterValue::paddingMode>(
                                               static_cast<PaddingMode>(param.enumerated))};
diff --git a/KM200/JavacardKeyMintUtils.h b/KM200/JavacardKeyMintUtils.h
index 9b103ff..9a23ed4 100644
--- a/KM200/JavacardKeyMintUtils.h
+++ b/KM200/JavacardKeyMintUtils.h
@@ -13,6 +13,25 @@
  * See the License for the specific language governing permissions and
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
+ *  Copyright 2023 NXP
+ *
+ ******************************************************************************/
 
 #pragma once
 #include <aidl/android/hardware/security/keymint/KeyParameter.h>
@@ -24,9 +43,9 @@
 #include <vector>
 
 namespace aidl::android::hardware::security::keymint::km_utils {
-using namespace ::keymaster;
-using secureclock::TimeStampToken;
+using keymaster::KeymasterBlob;
 using ::ndk::ScopedAStatus;
+using secureclock::TimeStampToken;
 using std::vector;
 using LegacyHardwareAuthToken = ::keymaster::HardwareAuthToken;
 
diff --git a/KM200/JavacardRemotelyProvisionedComponentDevice.cpp b/KM200/JavacardRemotelyProvisionedComponentDevice.cpp
index d0b45c2..090d567 100644
--- a/KM200/JavacardRemotelyProvisionedComponentDevice.cpp
+++ b/KM200/JavacardRemotelyProvisionedComponentDevice.cpp
@@ -29,33 +29,36 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2022 NXP
+ ** Copyright 2022-2024 NXP
  **
  *********************************************************************************/
 
 #define LOG_TAG "javacard.keymint.device.rkp.strongbox-impl"
-#include <JavacardRemotelyProvisionedComponentDevice.h>
-#include <android-base/logging.h>
 #include <JavacardKeyMintUtils.h>
+#include <JavacardRemotelyProvisionedComponentDevice.h>
 #include <aidl/android/hardware/security/keymint/MacedPublicKey.h>
+#include <android-base/logging.h>
 #include <keymaster/cppcose/cppcose.h>
 #include <keymaster/remote_provisioning_utils.h>
+#include <memunreachable/memunreachable.h>
 
 #ifdef NXP_EXTNS
 #define KM_RKP_VERSION_1 0x01
 #endif
 
 namespace aidl::android::hardware::security::keymint {
-using namespace cppcose;
-using namespace keymaster;
-using namespace cppbor;
+using cppbor::Array;
+using cppbor::EncodedItem;
+using cppcose::kCoseMac0EntryCount;
+using cppcose::kCoseMac0Payload;
+using ::keymint::javacard::Instruction;
 // RKP error codes defined in keymint applet.
-constexpr keymaster_error_t kStatusFailed = static_cast<keymaster_error_t>(32000);
-constexpr keymaster_error_t kStatusInvalidMac = static_cast<keymaster_error_t>(32001);
-constexpr keymaster_error_t kStatusProductionKeyInTestRequest = static_cast<keymaster_error_t>(32002);
-constexpr keymaster_error_t kStatusTestKeyInProductionRequest = static_cast<keymaster_error_t>(32003);
-constexpr keymaster_error_t kStatusInvalidEek = static_cast<keymaster_error_t>(32004);
-constexpr keymaster_error_t kStatusInvalidState = static_cast<keymaster_error_t>(32005);
+constexpr int32_t kStatusFailed = 32000;
+constexpr int32_t kStatusInvalidMac = 32001;
+constexpr int32_t kStatusProductionKeyInTestRequest = 32002;
+constexpr int32_t kStatusTestKeyInProductionRequest = 32003;
+constexpr int32_t kStatusInvalidEek = 32004;
+constexpr int32_t kStatusInvalidState = 32005;
 
 namespace {
 
@@ -295,4 +298,11 @@ JavacardRemotelyProvisionedComponentDevice::generateCertificateRequest(bool test
     return ScopedAStatus::ok();
 }
 
+binder_status_t JavacardRemotelyProvisionedComponentDevice::dump(int /* fd */, const char** /* p */,
+                                                                 uint32_t /* q */) {
+    LOG(INFO) << "\n KeyMint-JavacardRemotelyProvisionedComponentDevice Info = \n"
+              << ::android::GetUnreachableMemoryString(true, 10000).c_str();
+    return STATUS_OK;
+}
+
 } // namespace aidl::android::hardware::security::keymint
diff --git a/KM200/JavacardRemotelyProvisionedComponentDevice.h b/KM200/JavacardRemotelyProvisionedComponentDevice.h
index 6592d2e..abe7e4e 100644
--- a/KM200/JavacardRemotelyProvisionedComponentDevice.h
+++ b/KM200/JavacardRemotelyProvisionedComponentDevice.h
@@ -13,6 +13,25 @@
  * See the License for the specific language governing permissions and
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
+ *  Copyright 2022-2023 NXP
+ *
+ ******************************************************************************/
 
 #pragma once
 
@@ -27,30 +46,35 @@
 #include "JavacardSecureElement.h"
 
 namespace aidl::android::hardware::security::keymint {
-using namespace ::keymint::javacard;
+using ::keymint::javacard::CborConverter;
+using ::keymint::javacard::JavacardSecureElement;
 using ndk::ScopedAStatus;
+using std::shared_ptr;
 
 class JavacardRemotelyProvisionedComponentDevice
     : public BnRemotelyProvisionedComponent {
  public:
   explicit JavacardRemotelyProvisionedComponentDevice(
       shared_ptr<JavacardSecureElement> card)
-      : card_(card) {}
+      : card_(std::move(card)) {}
 
   virtual ~JavacardRemotelyProvisionedComponentDevice() = default;
 
-  ScopedAStatus getHardwareInfo(RpcHardwareInfo* info) override;
+  // Methods from ::ndk::ICInterface follow.
+  binder_status_t dump(int fd, const char **args, uint32_t num_args) override;
+
+  ScopedAStatus getHardwareInfo(RpcHardwareInfo *info) override;
 
-  ScopedAStatus generateEcdsaP256KeyPair(
-      bool testMode, MacedPublicKey* macedPublicKey,
-      std::vector<uint8_t>* privateKeyHandle) override;
+  ScopedAStatus
+  generateEcdsaP256KeyPair(bool testMode, MacedPublicKey *macedPublicKey,
+                            std::vector<uint8_t> *privateKeyHandle) override;
 
   ScopedAStatus generateCertificateRequest(
-      bool testMode, const std::vector<MacedPublicKey>& keysToSign,
-      const std::vector<uint8_t>& endpointEncCertChain,
-      const std::vector<uint8_t>& challenge, DeviceInfo* deviceInfo,
-      ProtectedData* protectedData,
-      std::vector<uint8_t>* keysToSignMac) override;
+      bool testMode, const std::vector<MacedPublicKey> &keysToSign,
+      const std::vector<uint8_t> &endpointEncCertChain,
+      const std::vector<uint8_t> &challenge, DeviceInfo *deviceInfo,
+      ProtectedData *protectedData,
+      std::vector<uint8_t> *keysToSignMac) override;
 
  private:
   ScopedAStatus beginSendData(bool testMode,
diff --git a/KM200/JavacardSecureElement.cpp b/KM200/JavacardSecureElement.cpp
index 57ec618..514d9c8 100644
--- a/KM200/JavacardSecureElement.cpp
+++ b/KM200/JavacardSecureElement.cpp
@@ -13,6 +13,25 @@
  * See the License for the specific language governing permissions and
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
+ *  Copyright 2023-2024 NXP
+ *
+ ******************************************************************************/
 
 #define LOG_TAG "javacard.keymint.device.strongbox-impl"
 #include "JavacardSecureElement.h"
@@ -31,14 +50,20 @@
 
 namespace keymint::javacard {
 
-using namespace ::keymaster;
 keymaster_error_t JavacardSecureElement::initializeJavacard() {
-    Array request;
-    request.add(Uint(getOsVersion()));
-    request.add(Uint(getOsPatchlevel()));
-    request.add(Uint(getVendorPatchlevel()));
-    auto [item, err] = sendRequest(Instruction::INS_SET_BOOT_PARAMS_CMD, request);
-    return err;
+    keymaster_error_t ret = KM_ERROR_OK;
+    if (!isCardInitialized_) {
+        Array request;
+        request.add(Uint(getOsVersion()));
+        request.add(Uint(getOsPatchlevel()));
+        request.add(Uint(getVendorPatchlevel()));
+        auto [item, err] = sendRequest(Instruction::INS_SET_BOOT_PARAMS_CMD, request);
+        if (err == KM_ERROR_OK) {
+            isCardInitialized_ = true;
+        }
+        ret = err;
+    }
+    return ret;
 }
 
 keymaster_error_t JavacardSecureElement::constructApduMessage(Instruction& ins,
@@ -83,16 +108,15 @@ keymaster_error_t JavacardSecureElement::sendData(Instruction ins, std::vector<u
         return ret;
     }
 
-    if (!transport_->sendData(apdu, response)) {
-        LOG(ERROR) << "Error in sending data in sendData.";
+    if (!transport_->sendData(apdu, response) && (response.size() < 2)) {
+        LOG(ERROR) << "Error in sending C-APDU";
         return (KM_ERROR_SECURE_HW_COMMUNICATION_FAILED);
     }
-
-    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU
-    // status.
-    if ((response.size() <= 2) || (getApduStatus(response) != APDU_RESP_STATUS_OK)) {
-        LOG(ERROR) << "Response of the sendData is wrong: response size = " << response.size()
-                   << " apdu status = " << getApduStatus(response);
+    // Response size should be greater than 2. Cbor output data followed by two
+    // bytes of APDU status.
+    if (getApduStatus(response) != APDU_RESP_STATUS_OK) {
+        LOG(ERROR) << "ERROR Response apdu status = " << std::uppercase << std::hex
+                   << getApduStatus(response);
         return (KM_ERROR_UNKNOWN_ERROR);
     }
     // remove the status bytes
@@ -137,4 +161,10 @@ JavacardSecureElement::sendRequest(Instruction ins) {
     return cbor_.decodeData(response);
 }
 
+#ifdef NXP_EXTNS
+void JavacardSecureElement::setOperationState(CryptoOperationState state) {
+    transport_->setCryptoOperationState(state);
+}
+#endif
+
 }  // namespace keymint::javacard
diff --git a/KM200/JavacardSecureElement.h b/KM200/JavacardSecureElement.h
index 60347b7..d2bc7ea 100644
--- a/KM200/JavacardSecureElement.h
+++ b/KM200/JavacardSecureElement.h
@@ -14,37 +14,39 @@
  * limitations under the License.
  */
 /******************************************************************************
-*
-*  The original Work has been changed by NXP.
-*
-*  Licensed under the Apache License, Version 2.0 (the "License");
-*  you may not use this file except in compliance with the License.
-*  You may obtain a copy of the License at
-*
-*  http://www.apache.org/licenses/LICENSE-2.0
-*
-*  Unless required by applicable law or agreed to in writing, software
-*  distributed under the License is distributed on an "AS IS" BASIS,
-*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-*  See the License for the specific language governing permissions and
-*  limitations under the License.
-*
-*  Copyright 2022 NXP
-*
-******************************************************************************/
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
+ *  Copyright 2022-2024 NXP
+ *
+ ******************************************************************************/
 #pragma once
 
 #include "CborConverter.h"
 #include <ITransport.h>
 
 #define APDU_CLS 0x80
-//#define APDU_P1 0x50
+// #define APDU_P1 0x50
 #define APDU_P1 0x40
 #define APDU_P2 0x00
 #define APDU_RESP_STATUS_OK 0x9000
 
 #define KEYMINT_CMD_APDU_START 0x20
 
+#define KEYMINT_VENDOR_CMD_APDU_START 0xD0
+
 namespace keymint::javacard {
 using ndk::ScopedAStatus;
 using std::optional;
@@ -79,7 +81,7 @@ enum class Instruction {
     INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24,
     INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25,
     //INS_SET_BOOT_PARAMS_CMD = KEYMINT_CMD_APDU_START + 26,
-    INS_SET_BOOT_PARAMS_CMD = 9,
+    INS_SET_BOOT_PARAMS_CMD = KEYMINT_VENDOR_CMD_APDU_START + 9,
     // RKP Commands
     INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27,
     INS_GENERATE_RKP_KEY_CMD = KEYMINT_CMD_APDU_START + 28,
@@ -94,12 +96,18 @@ enum class Instruction {
     INS_SEND_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 47,
 };
 
+#ifdef NXP_EXTNS
+enum CryptoOperationState { STARTED = 0, FINISHED };
+#endif
+
 class JavacardSecureElement {
   public:
-    explicit JavacardSecureElement(shared_ptr<ITransport> transport, uint32_t osVersion,
-                                   uint32_t osPatchLevel, uint32_t vendorPatchLevel)
-        : transport_(transport), osVersion_(osVersion), osPatchLevel_(osPatchLevel),
-          vendorPatchLevel_(vendorPatchLevel) {
+    explicit JavacardSecureElement(shared_ptr<ITransport> transport,
+                                   uint32_t osVersion, uint32_t osPatchLevel,
+                                   uint32_t vendorPatchLevel)
+        : transport_(std::move(transport)), osVersion_(osVersion),
+          osPatchLevel_(osPatchLevel), vendorPatchLevel_(vendorPatchLevel),
+          isCardInitialized_(false) {
         transport_->openConnection();
     }
     virtual ~JavacardSecureElement() { transport_->closeConnection(); }
@@ -122,10 +130,14 @@ class JavacardSecureElement {
         return (SW0 << 8 | SW1);
     }
 
+#ifdef NXP_EXTNS
+    void setOperationState(CryptoOperationState state);
+#endif
     shared_ptr<ITransport> transport_;
     uint32_t osVersion_;
     uint32_t osPatchLevel_;
     uint32_t vendorPatchLevel_;
+    bool isCardInitialized_;
     CborConverter cbor_;
 };
 }  // namespace keymint::javacard
diff --git a/KM200/JavacardSharedSecret.cpp b/KM200/JavacardSharedSecret.cpp
index 1992734..cc42e60 100644
--- a/KM200/JavacardSharedSecret.cpp
+++ b/KM200/JavacardSharedSecret.cpp
@@ -14,7 +14,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2021-2022 NXP
+ ** Copyright 2021-2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.strongbox.keymint.operation-impl"
@@ -22,6 +22,7 @@
 
 #include "JavacardSharedSecret.h"
 #include <JavacardKeyMintUtils.h>
+#include <memunreachable/memunreachable.h>
 
 /* 1 sec delay till OMAPI service initialized (~ 30 to 40 secs)
  * 20 retry as per transport layer retry logic.
@@ -30,10 +31,8 @@
 #define MAX_SHARED_SECRET_RETRY_COUNT 120
 
 namespace aidl::android::hardware::security::sharedsecret {
-using namespace ::keymint::javacard;
+using ::keymint::javacard::Instruction;
 using ndk::ScopedAStatus;
-using std::optional;
-using std::shared_ptr;
 using std::vector;
 
 static uint8_t getSharedSecretRetryCount = 0x00;
@@ -42,7 +41,8 @@ ScopedAStatus JavacardSharedSecret::getSharedSecretParameters(SharedSecretParame
     card_->initializeJavacard();
     auto [item, err] = card_->sendRequest(Instruction::INS_GET_SHARED_SECRET_PARAM_CMD);
 #ifdef NXP_EXTNS
-    if (err != KM_ERROR_OK && (getSharedSecretRetryCount < MAX_SHARED_SECRET_RETRY_COUNT)) {
+    if (err == KM_ERROR_SECURE_HW_COMMUNICATION_FAILED &&
+        (getSharedSecretRetryCount < MAX_SHARED_SECRET_RETRY_COUNT)) {
         getSharedSecretRetryCount++;
     } else if (err != KM_ERROR_OK) {
         std::vector<uint8_t> refNonceSeed = {
@@ -57,7 +57,7 @@ ScopedAStatus JavacardSharedSecret::getSharedSecretParameters(SharedSecretParame
 #endif
     if (err != KM_ERROR_OK || !cbor_.getSharedSecretParameters(item, 1, *params)) {
         LOG(ERROR) << "Error in sending in getSharedSecretParameters.";
-        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
+        return keymint::km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
     }
     return ScopedAStatus::ok();
 }
@@ -72,13 +72,19 @@ JavacardSharedSecret::computeSharedSecret(const std::vector<SharedSecretParamete
     auto [item, err] = card_->sendRequest(Instruction::INS_COMPUTE_SHARED_SECRET_CMD, request);
     if (err != KM_ERROR_OK) {
         LOG(ERROR) << "Error in sending in computeSharedSecret.";
-        return km_utils::kmError2ScopedAStatus(err);
+        return keymint::km_utils::kmError2ScopedAStatus(err);
     }
     if (!cbor_.getBinaryArray(item, 1, *secret)) {
         LOG(ERROR) << "Error in decoding the response in computeSharedSecret.";
-        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
+        return keymint::km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
     }
     return ScopedAStatus::ok();
 }
 
+binder_status_t JavacardSharedSecret::dump(int /* fd */, const char** /* p */, uint32_t /* q */) {
+    LOG(INFO) << "\n KeyMint-JavacardSharedSecret HAL MemoryLeak Info = \n"
+              << ::android::GetUnreachableMemoryString(true, 10000).c_str();
+    return STATUS_OK;
+}
+
 }  // namespace aidl::android::hardware::security::sharedsecret
diff --git a/KM200/JavacardSharedSecret.h b/KM200/JavacardSharedSecret.h
index 29b0e05..5aba93f 100644
--- a/KM200/JavacardSharedSecret.h
+++ b/KM200/JavacardSharedSecret.h
@@ -1,3 +1,22 @@
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
+ *  Copyright 2022-2023 NXP
+ *
+ ******************************************************************************/
 #pragma once
 
 #include "CborConverter.h"
@@ -9,7 +28,8 @@
 #include <vector>
 
 namespace aidl::android::hardware::security::sharedsecret {
-using namespace ::keymint::javacard;
+using ::keymint::javacard::CborConverter;
+using ::keymint::javacard::JavacardSecureElement;
 using ndk::ScopedAStatus;
 using std::optional;
 using std::shared_ptr;
@@ -17,9 +37,13 @@ using std::vector;
 
 class JavacardSharedSecret : public BnSharedSecret {
   public:
-    explicit JavacardSharedSecret(shared_ptr<JavacardSecureElement> card) : card_(card) {}
+    explicit JavacardSharedSecret(shared_ptr<JavacardSecureElement> card)
+        : card_(std::move(card)) {}
     virtual ~JavacardSharedSecret() {}
 
+    // Methods from ::ndk::ICInterface follow.
+    binder_status_t dump(int fd, const char** args, uint32_t num_args) override;
+
     ScopedAStatus getSharedSecretParameters(SharedSecretParameters* params) override;
 
     ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& params,
diff --git a/KM200/res/config.fs b/KM200/res/config.fs
index f1b7da3..52deba7 100644
--- a/KM200/res/config.fs
+++ b/KM200/res/config.fs
@@ -9,10 +9,10 @@ value:2902
 mode: 0755
 user: AID_VENDOR_NXP_STRONGBOX
 group: AID_SYSTEM
-caps: SYS_ADMIN SYS_NICE
+caps: SYS_ADMIN SYS_NICE WAKE_ALARM
 
 [vendor/bin/hw/android.hardware.weaver@1.0-service.nxp]
 mode: 0755
 user: AID_VENDOR_NXP_WEAVER
 group: AID_SYSTEM
-caps: SYS_ADMIN SYS_NICE
+caps: SYS_ADMIN SYS_NICE WAKE_ALARM
diff --git a/KM200/service.cpp b/KM200/service.cpp
index 09f956b..a0fbca8 100644
--- a/KM200/service.cpp
+++ b/KM200/service.cpp
@@ -29,7 +29,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2020-2022 NXP
+ ** Copyright 2020-2023 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.strongbox-service"
@@ -54,8 +54,10 @@
 #endif
 
 using aidl::android::hardware::security::keymint::JavacardKeyMintDevice;
-using aidl::android::hardware::security::keymint::JavacardSharedSecret;
+using aidl::android::hardware::security::keymint::
+    JavacardRemotelyProvisionedComponentDevice;
 using aidl::android::hardware::security::keymint::SecurityLevel;
+using aidl::android::hardware::security::sharedsecret::JavacardSharedSecret;
 using namespace keymint::javacard;
 
 const std::vector<uint8_t> gStrongBoxAppletAID = {0xA0, 0x00, 0x00, 0x00, 0x62};
diff --git a/KM300/Android.bp b/KM300/Android.bp
index 1c68b01..1bfbd27 100644
--- a/KM300/Android.bp
+++ b/KM300/Android.bp
@@ -27,7 +27,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 //
-// Copyright 2022-2023 NXP
+// Copyright 2022-2024 NXP
 //
 
 package {
@@ -53,12 +53,13 @@ cc_library {
     cflags: [
         "-O0",
         "-DNXP_EXTNS",
+        //"-DINIT_USING_SEHAL_TRANSPORT",
     ],
     shared_libs: [
         "android.hardware.security.rkp-V3-ndk",
         "android.hardware.security.secureclock-V1-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V3",
         "libbase",
         "libbinder",
         "libcppbor",
@@ -68,10 +69,12 @@ cc_library {
         "liblog",
         "libcrypto",
         "libcutils",
+        "libutils",
         "libjc_keymint_transport.nxp",
         "libbinder_ndk",
         "libmemunreachable",
         "android.hardware.security.keymint-V3-ndk",
+        "android.hardware.secure_element-V1-ndk",
     ],
     export_include_dirs: [
         ".",
@@ -102,7 +105,7 @@ cc_binary {
     shared_libs: [
         "android.hardware.security.rkp-V3-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V3",
         "android.se.omapi-V1-ndk",
         "libbase",
         "libbinder_ndk",
@@ -115,6 +118,7 @@ cc_binary {
         "libutils",
         "libhidlbase",
         "android.hardware.security.keymint-V3-ndk",
+        "android.hardware.secure_element-V1-ndk",
     ],
     srcs: [
         "service.cpp",
diff --git a/KM300/JavacardKeyMintDevice.cpp b/KM300/JavacardKeyMintDevice.cpp
index d45957d..544f02a 100644
--- a/KM300/JavacardKeyMintDevice.cpp
+++ b/KM300/JavacardKeyMintDevice.cpp
@@ -14,24 +14,24 @@
  * limitations under the License.
  */
 /******************************************************************************
-*
-*  The original Work has been changed by NXP.
-*
-*  Licensed under the Apache License, Version 2.0 (the "License");
-*  you may not use this file except in compliance with the License.
-*  You may obtain a copy of the License at
-*
-*  http://www.apache.org/licenses/LICENSE-2.0
-*
-*  Unless required by applicable law or agreed to in writing, software
-*  distributed under the License is distributed on an "AS IS" BASIS,
-*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-*  See the License for the specific language governing permissions and
-*  limitations under the License.
-*
-*  Copyright 2022 NXP
-*
-******************************************************************************/
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
+ *  Copyright 2022,2024 NXP
+ *
+ ******************************************************************************/
 #define LOG_TAG "javacard.keymint.device.strongbox-impl"
 #include "JavacardKeyMintDevice.h"
 
@@ -91,7 +91,6 @@ ScopedAStatus JavacardKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info)
         LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
         return defaultHwInfo(info);
     }
-    card_->initializeJavacard();
     info->keyMintName = std::move(optKeyMintName.value());
     info->keyMintAuthorName = std::move(optKeyMintAuthorName.value());
     info->timestampTokenRequired = (optTsRequired.value() == 1);
@@ -397,9 +396,16 @@ ScopedAStatus JavacardKeyMintDevice::getKeyCharacteristics(
 }
 
 ScopedAStatus JavacardKeyMintDevice::getRootOfTrustChallenge(std::array<uint8_t, 16>* challenge) {
+#ifdef INIT_USING_SEHAL_TRANSPORT
+    auto [item, err] = card_->sendRequestSeHal(Instruction::INS_GET_ROT_CHALLENGE_CMD);
+#else
     auto [item, err] = card_->sendRequest(Instruction::INS_GET_ROT_CHALLENGE_CMD);
+#endif
     if (err != KM_ERROR_OK) {
         LOG(ERROR) << "Error in sending in getRootOfTrustChallenge.";
+#ifdef INIT_USING_SEHAL_TRANSPORT
+        card_->closeSEHal();
+#endif
         return km_utils::kmError2ScopedAStatus(err);
     }
     auto optChallenge = cbor_.getByteArrayVec(item, 1);
@@ -418,8 +424,16 @@ ScopedAStatus JavacardKeyMintDevice::getRootOfTrust(const std::array<uint8_t, 16
 
 ScopedAStatus JavacardKeyMintDevice::sendRootOfTrust(const std::vector<uint8_t>& rootOfTrust) {
     cppbor::Array request;
+    std::unique_ptr<Item> item;
+    keymaster_error_t err;
     request.add(EncodedItem(rootOfTrust));  // taggedItem.
-    auto [item, err] = card_->sendRequest(Instruction::INS_SEND_ROT_DATA_CMD, request);
+#ifdef INIT_USING_SEHAL_TRANSPORT
+    std::tie(item, err) =
+        card_->sendRequestSeHal(Instruction::INS_SEND_ROT_DATA_CMD, request.encode());
+    card_->closeSEHal();
+#else
+    std::tie(item, err) = card_->sendRequest(Instruction::INS_SEND_ROT_DATA_CMD, request.encode());
+#endif
     if (err != KM_ERROR_OK) {
         LOG(ERROR) << "Error in sending in sendRootOfTrust.";
         return km_utils::kmError2ScopedAStatus(err);
diff --git a/KM300/JavacardKeyMintDevice.h b/KM300/JavacardKeyMintDevice.h
index 94378a1..a73dad3 100644
--- a/KM300/JavacardKeyMintDevice.h
+++ b/KM300/JavacardKeyMintDevice.h
@@ -14,24 +14,24 @@
  * limitations under the License.
  */
 /******************************************************************************
-*
-*  The original Work has been changed by NXP.
-*
-*  Licensed under the Apache License, Version 2.0 (the "License");
-*  you may not use this file except in compliance with the License.
-*  You may obtain a copy of the License at
-*
-*  http://www.apache.org/licenses/LICENSE-2.0
-*
-*  Unless required by applicable law or agreed to in writing, software
-*  distributed under the License is distributed on an "AS IS" BASIS,
-*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-*  See the License for the specific language governing permissions and
-*  limitations under the License.
-*
-*  Copyright 2022-2023 NXP
-*
-******************************************************************************/
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
+ *  Copyright 2022-2024 NXP
+ *
+ ******************************************************************************/
 #pragma once
 
 #include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
@@ -56,9 +56,7 @@ using std::vector;
 class JavacardKeyMintDevice : public BnKeyMintDevice {
   public:
     explicit JavacardKeyMintDevice(shared_ptr<JavacardSecureElement> card)
-        : securitylevel_(SecurityLevel::STRONGBOX), card_(std::move(card)) {
-        card_->initializeJavacard();
-    }
+        : securitylevel_(SecurityLevel::STRONGBOX), card_(std::move(card)) {}
     virtual ~JavacardKeyMintDevice() {}
 
     // Methods from ::ndk::ICInterface follow.
diff --git a/KM300/JavacardKeyMintOperation.cpp b/KM300/JavacardKeyMintOperation.cpp
index 0d8c9da..df57e09 100644
--- a/KM300/JavacardKeyMintOperation.cpp
+++ b/KM300/JavacardKeyMintOperation.cpp
@@ -29,7 +29,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2022 NXP
+ ** Copyright 2022,2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.strongbox.keymint.operation-impl"
@@ -49,6 +49,9 @@ using cppbor::Uint;
 using secureclock::TimeStampToken;
 
 JavacardKeyMintOperation::~JavacardKeyMintOperation() {
+#ifdef NXP_EXTNS
+    card_->setOperationState(::keymint::javacard::CryptoOperationState::FINISHED);
+#endif
     if (opHandle_ != 0) {
         JavacardKeyMintOperation::abort();
     }
diff --git a/KM300/JavacardKeyMintOperation.h b/KM300/JavacardKeyMintOperation.h
index 959fbd7..3472827 100644
--- a/KM300/JavacardKeyMintOperation.h
+++ b/KM300/JavacardKeyMintOperation.h
@@ -29,7 +29,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2023 NXP
+ ** Copyright 2023-2024 NXP
  **
  *********************************************************************************/
 
@@ -92,7 +92,11 @@ class JavacardKeyMintOperation : public BnKeyMintOperation {
                                       BufferingMode bufferingMode, uint16_t macLength,
                                       shared_ptr<JavacardSecureElement> card)
         : buffer_(vector<uint8_t>()), bufferingMode_(bufferingMode), macLength_(macLength),
-          card_(std::move(card)), opHandle_(opHandle) {}
+          card_(std::move(card)), opHandle_(opHandle) {
+#ifdef NXP_EXTNS
+            card_->setOperationState(::keymint::javacard::CryptoOperationState::STARTED);
+#endif
+    }
     virtual ~JavacardKeyMintOperation();
 
     ScopedAStatus updateAad(const vector<uint8_t>& input,
diff --git a/KM300/JavacardRemotelyProvisionedComponentDevice.cpp b/KM300/JavacardRemotelyProvisionedComponentDevice.cpp
index 880f316..ba38f21 100644
--- a/KM300/JavacardRemotelyProvisionedComponentDevice.cpp
+++ b/KM300/JavacardRemotelyProvisionedComponentDevice.cpp
@@ -29,7 +29,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2023 NXP
+ ** Copyright 2023,2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.keymint.device.rkp.strongbox-impl"
@@ -125,6 +125,7 @@ ScopedAStatus JavacardRemotelyProvisionedComponentDevice::getHardwareInfo(RpcHar
         LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
         return defaultHwInfo(info);
     }
+    card_->sendPendingEvents();
     info->rpcAuthorName = std::move(optRpcAuthorName.value());
     info->versionNumber = static_cast<int32_t>(std::move(optVersionNumber.value()));
     info->supportedEekCurve = static_cast<int32_t>(std::move(optSupportedEekCurve.value()));
@@ -138,6 +139,7 @@ ScopedAStatus JavacardRemotelyProvisionedComponentDevice::generateEcdsaP256KeyPa
     if (testMode) {
         return km_utils::kmError2ScopedAStatus(static_cast<keymaster_error_t>(STATUS_REMOVED));
     }
+    card_->sendPendingEvents();
     auto [item, err] = card_->sendRequest(Instruction::INS_GENERATE_RKP_KEY_CMD);
     if (err != KM_ERROR_OK) {
         LOG(ERROR) << "Error in sending generateEcdsaP256KeyPair.";
diff --git a/KM300/JavacardSecureElement.cpp b/KM300/JavacardSecureElement.cpp
index 51e047c..0937e2b 100644
--- a/KM300/JavacardSecureElement.cpp
+++ b/KM300/JavacardSecureElement.cpp
@@ -13,6 +13,25 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+/******************************************************************************
+*
+*  The original Work has been changed by NXP.
+*
+*  Licensed under the Apache License, Version 2.0 (the "License");
+*  you may not use this file except in compliance with the License.
+*  You may obtain a copy of the License at
+*
+*  http://www.apache.org/licenses/LICENSE-2.0
+*
+*  Unless required by applicable law or agreed to in writing, software
+*  distributed under the License is distributed on an "AS IS" BASIS,
+*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+*  See the License for the specific language governing permissions and
+*  limitations under the License.
+*
+*  Copyright 2024 NXP
+*
+******************************************************************************/
 
 #define LOG_TAG "javacard.keymint.device.strongbox-impl"
 #include "JavacardSecureElement.h"
@@ -25,6 +44,10 @@
 #include <string>
 #include <vector>
 
+#ifdef INIT_USING_SEHAL_TRANSPORT
+#include <HalToHalTransport.h>
+#endif
+#include <aidl/android/hardware/security/keymint/ErrorCode.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <keymaster/android_keymaster_messages.h>
@@ -32,6 +55,14 @@
 #include "keymint_utils.h"
 
 namespace keymint::javacard {
+using ::aidl::android::hardware::security::keymint::ErrorCode;
+const std::vector<uint8_t> gStrongBoxAppletAID = {0xA0, 0x00, 0x00, 0x00, 0x62};
+
+namespace {
+keymaster_error_t aidlEnumErrorCode2km(ErrorCode err) {
+    return static_cast<keymaster_error_t>(err);
+}
+}  // namespace
 
 keymaster_error_t JavacardSecureElement::initializeJavacard() {
     Array request;
@@ -49,26 +80,34 @@ void JavacardSecureElement::setEarlyBootEndedPending() {
     isEarlyBootEndedPending = true;
 }
 void JavacardSecureElement::sendPendingEvents() {
+    if (isCardInitPending) {
+        if (KM_ERROR_OK == initializeJavacard()) {
+            isCardInitPending = false;
+        } else {
+            LOG(ERROR) << "Error in sending system properties(OS_VERSION, OS_PATCH, VENDOR_PATCH).";
+        }
+    }
+
     if (isDeleteAllKeysPending) {
-      auto [_, err] = sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
-      if (err == KM_ERROR_OK) {
-        isDeleteAllKeysPending = false;
-      } else {
-        LOG(ERROR) << "Error in sending deleteAllKeys.";
-      }
+        auto [_, err] = sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
+        if (err == KM_ERROR_OK) {
+            isDeleteAllKeysPending = false;
+        } else {
+            LOG(ERROR) << "Error in sending deleteAllKeys.";
+        }
     }
     if (isEarlyBootEndedPending) {
-      auto [_, err] = sendRequest(Instruction::INS_EARLY_BOOT_ENDED_CMD);
-      if (err == KM_ERROR_OK) {
-        isEarlyBootEndedPending = false;
-      } else {
-        LOG(ERROR) << "Error in sending earlyBootEnded.";
-      }
+        auto [_, err] = sendRequest(Instruction::INS_EARLY_BOOT_ENDED_CMD);
+        if (err == KM_ERROR_OK) {
+            isEarlyBootEndedPending = false;
+        } else {
+            LOG(ERROR) << "Error in sending earlyBootEnded.";
+        }
     }
 }
 
 keymaster_error_t JavacardSecureElement::constructApduMessage(Instruction& ins,
-                                                              std::vector<uint8_t>& inputData,
+                                                              const std::vector<uint8_t>& inputData,
                                                               std::vector<uint8_t>& apduOut) {
     apduOut.push_back(static_cast<uint8_t>(APDU_CLS));  // CLS
     apduOut.push_back(static_cast<uint8_t>(ins));       // INS
@@ -98,7 +137,9 @@ keymaster_error_t JavacardSecureElement::constructApduMessage(Instruction& ins,
     return (KM_ERROR_OK);  // success
 }
 
-keymaster_error_t JavacardSecureElement::sendData(Instruction ins, std::vector<uint8_t>& inData,
+keymaster_error_t JavacardSecureElement::sendData(const std::shared_ptr<ITransport>& transport,
+                                                  Instruction ins,
+                                                  const std::vector<uint8_t>& inData,
                                                   std::vector<uint8_t>& response) {
     keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
     std::vector<uint8_t> apdu;
@@ -109,16 +150,15 @@ keymaster_error_t JavacardSecureElement::sendData(Instruction ins, std::vector<u
         return ret;
     }
 
-    if (!transport_->sendData(apdu, response)) {
-        LOG(ERROR) << "Error in sending data in sendData.";
+    if (!transport->sendData(apdu, response) && (response.size() < 2)) {
+        LOG(ERROR) << "Error in sending C-APDU";
         return (KM_ERROR_SECURE_HW_COMMUNICATION_FAILED);
     }
-
     // Response size should be greater than 2. Cbor output data followed by two
     // bytes of APDU status.
-    if ((response.size() <= 2) || (getApduStatus(response) != APDU_RESP_STATUS_OK)) {
-        LOG(ERROR) << "Response of the sendData is wrong: response size = " << response.size()
-                   << " apdu status = " << getApduStatus(response);
+    if (getApduStatus(response) != APDU_RESP_STATUS_OK) {
+        LOG(ERROR) << "ERROR Response apdu status = " << std::uppercase << std::hex
+                   << getApduStatus(response);
         return (KM_ERROR_UNKNOWN_ERROR);
     }
     // remove the status bytes
@@ -127,40 +167,87 @@ keymaster_error_t JavacardSecureElement::sendData(Instruction ins, std::vector<u
     return (KM_ERROR_OK);  // success
 }
 
-std::tuple<std::unique_ptr<Item>, keymaster_error_t>
-JavacardSecureElement::sendRequest(Instruction ins, Array& request) {
-    vector<uint8_t> response;
-    // encode request
-    std::vector<uint8_t> command = request.encode();
-    auto sendError = sendData(ins, command, response);
-    if (sendError != KM_ERROR_OK) {
-        return {unique_ptr<Item>(nullptr), sendError};
+keymaster_error_t JavacardSecureElement::sendData(Instruction ins,
+                                                  const std::vector<uint8_t>& inData,
+                                                  std::vector<uint8_t>& response) {
+    return sendData(transport_, ins, inData, response);
+}
+
+std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
+    Instruction ins, const Array& request) {
+    return sendRequest(transport_, ins, request.encode());
+}
+
+std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
+    Instruction ins, const std::vector<uint8_t>& command) {
+    return sendRequest(transport_, ins, command);
+}
+
+std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
+    Instruction ins) {
+    return sendRequest(transport_, ins, std::vector<uint8_t>());
+}
+#ifdef INIT_USING_SEHAL_TRANSPORT
+bool JavacardSecureElement::initSEHal() {
+    if (seHalTransport == nullptr) {
+        seHalTransport = std::make_shared<HalToHalTransport>(gStrongBoxAppletAID);
     }
-    // decode the response and send that back
-    return cbor_.decodeData(response);
+    return seHalTransport->openConnection();
 }
 
-std::tuple<std::unique_ptr<Item>, keymaster_error_t>
-JavacardSecureElement::sendRequest(Instruction ins, std::vector<uint8_t>& command) {
-    vector<uint8_t> response;
-    auto sendError = sendData(ins, command, response);
-    if (sendError != KM_ERROR_OK) {
-        return {unique_ptr<Item>(nullptr), sendError};
+bool JavacardSecureElement::closeSEHal() {
+    bool ret = true;
+    if (seHalTransport != nullptr) {
+        ret = seHalTransport->closeConnection();
+        if (!ret) {
+            LOG(INFO) << "Failed to close SE Hal.";
+        }
+        seHalTransport = nullptr;
+    }
+    return ret;
+}
+#endif
+std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequestSeHal(
+    Instruction ins, const std::vector<uint8_t>& command) {
+    if (seHalTransport != nullptr) {
+        return sendRequest(seHalTransport, ins, command);
+    } else {
+        auto [item, err] = sendRequest(ins, command);
+        if (err != KM_ERROR_OK) {
+#ifdef INIT_USING_SEHAL_TRANSPORT
+            if (err == aidlEnumErrorCode2km(ErrorCode::SECURE_HW_COMMUNICATION_FAILED)) {
+                LOG(DEBUG) << "OMAPI is not yet available. Send INS: " << static_cast<int>(ins)
+                           << " via SE Hal.";
+                if (initSEHal()) {
+                    return sendRequest(seHalTransport, ins, command);
+                }
+                LOG(ERROR) << "Failed to initialize SE HAL";
+            }
+#endif
+        }
+        return {std::move(item), std::move(err)};
     }
-    // decode the response and send that back
-    return cbor_.decodeData(response);
 }
 
-std::tuple<std::unique_ptr<Item>, keymaster_error_t>
-JavacardSecureElement::sendRequest(Instruction ins) {
+std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequestSeHal(
+    Instruction ins) {
+    return sendRequestSeHal(ins, std::vector<uint8_t>());
+}
+
+std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
+    const std::shared_ptr<ITransport>& transport, Instruction ins,
+    const std::vector<uint8_t>& command) {
     vector<uint8_t> response;
-    vector<uint8_t> emptyRequest;
-    auto sendError = sendData(ins, emptyRequest, response);
+    auto sendError = sendData(transport, ins, command, response);
     if (sendError != KM_ERROR_OK) {
         return {unique_ptr<Item>(nullptr), sendError};
     }
     // decode the response and send that back
     return cbor_.decodeData(response);
 }
-
+#ifdef NXP_EXTNS
+void JavacardSecureElement::setOperationState(CryptoOperationState state) {
+    transport_->setCryptoOperationState(state);
+}
+#endif
 }  // namespace keymint::javacard
diff --git a/KM300/JavacardSecureElement.h b/KM300/JavacardSecureElement.h
index b3fb67e..63975a1 100644
--- a/KM300/JavacardSecureElement.h
+++ b/KM300/JavacardSecureElement.h
@@ -29,7 +29,7 @@
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
-*  Copyright 2022-2023 NXP
+*  Copyright 2022-2024 NXP
 *
 ******************************************************************************/
 #pragma once
@@ -78,7 +78,7 @@ enum class Instruction {
     INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23,
     INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24,
     INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25,
-    //INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26,
+    // INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26,
     INS_INIT_STRONGBOX_CMD = KEYMINT_VENDOR_CMD_APDU_START + 9,
     // RKP Commands
     INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27,
@@ -96,32 +96,44 @@ enum class Instruction {
     INS_GET_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 46,
     INS_SEND_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 47,
 };
+#ifdef NXP_EXTNS
+enum CryptoOperationState { STARTED = 0, FINISHED };
+#endif
 
 class JavacardSecureElement {
   public:
     explicit JavacardSecureElement(shared_ptr<ITransport> transport)
-        : transport_(std::move(transport)), isEarlyBootEndedPending(false),
-          isDeleteAllKeysPending(false) {
-      transport_->openConnection();
+        : transport_(std::move(transport)),
+          isEarlyBootEndedPending(false),
+          isDeleteAllKeysPending(false),
+          isCardInitPending(true) {
+        transport_->openConnection();
     }
     virtual ~JavacardSecureElement() { transport_->closeConnection(); }
 
     std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
-                                                                     Array& request);
+                                                                     const Array& request);
     std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins);
-    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
-                                                                     std::vector<uint8_t>& command);
+    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(
+        Instruction ins, const std::vector<uint8_t>& command);
 
-    keymaster_error_t sendData(Instruction ins, std::vector<uint8_t>& inData,
-                               std::vector<uint8_t>& response);
+    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequestSeHal(
+        Instruction ins, const std::vector<uint8_t>& command);
+    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequestSeHal(Instruction ins);
+
+    bool closeSEHal();
 
-    keymaster_error_t constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData,
+    keymaster_error_t sendData(Instruction ins, const std::vector<uint8_t>& inData,
+                               std::vector<uint8_t>& response);
+    keymaster_error_t constructApduMessage(Instruction& ins, const std::vector<uint8_t>& inputData,
                                            std::vector<uint8_t>& apduOut);
     keymaster_error_t initializeJavacard();
     void sendPendingEvents();
     void setEarlyBootEndedPending();
     void setDeleteAllKeysPending();
-
+#ifdef NXP_EXTNS
+    void setOperationState(CryptoOperationState state);
+#endif
     inline uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
         // Last two bytes are the status SW0SW1
         uint8_t SW0 = inputData.at(inputData.size() - 2);
@@ -130,9 +142,17 @@ class JavacardSecureElement {
     }
 
   private:
+    bool initSEHal();
+    keymaster_error_t sendData(const std::shared_ptr<ITransport>& transport, Instruction ins,
+                               const std::vector<uint8_t>& inData, std::vector<uint8_t>& response);
+    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(
+        const std::shared_ptr<ITransport>& transport, Instruction ins,
+        const std::vector<uint8_t>& command);
     shared_ptr<ITransport> transport_;
+    shared_ptr<ITransport> seHalTransport;
     bool isEarlyBootEndedPending;
     bool isDeleteAllKeysPending;
+    bool isCardInitPending;
     CborConverter cbor_;
 };
 }  // namespace keymint::javacard
diff --git a/KM300/JavacardSharedSecret.cpp b/KM300/JavacardSharedSecret.cpp
index 5c70445..4473d2a 100644
--- a/KM300/JavacardSharedSecret.cpp
+++ b/KM300/JavacardSharedSecret.cpp
@@ -14,7 +14,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2021-2022 NXP
+ ** Copyright 2021-2022, 2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.strongbox.keymint.operation-impl"
@@ -36,13 +36,14 @@ using ::keymint::javacard::Instruction;
 static uint8_t getSharedSecretRetryCount = 0x00;
 
 ScopedAStatus JavacardSharedSecret::getSharedSecretParameters(SharedSecretParameters* params) {
-    auto error = card_->initializeJavacard();
-    if (error != KM_ERROR_OK) {
-        LOG(ERROR) << "Error in initializing javacard.";
-    }
+#ifdef INIT_USING_SEHAL_TRANSPORT
+    auto [item, err] = card_->sendRequestSeHal(Instruction::INS_GET_SHARED_SECRET_PARAM_CMD);
+#else
     auto [item, err] = card_->sendRequest(Instruction::INS_GET_SHARED_SECRET_PARAM_CMD);
+#endif
 #ifdef NXP_EXTNS
-    if (err != KM_ERROR_OK && (getSharedSecretRetryCount < MAX_SHARED_SECRET_RETRY_COUNT)) {
+    if (err == KM_ERROR_SECURE_HW_COMMUNICATION_FAILED &&
+        (getSharedSecretRetryCount < MAX_SHARED_SECRET_RETRY_COUNT)) {
         getSharedSecretRetryCount++;
     } else if (err != KM_ERROR_OK) {
         std::vector<uint8_t> refNonceSeed = {
@@ -68,17 +69,17 @@ ScopedAStatus JavacardSharedSecret::getSharedSecretParameters(SharedSecretParame
     return ScopedAStatus::ok();
 }
 
-ScopedAStatus
-JavacardSharedSecret::computeSharedSecret(const std::vector<SharedSecretParameters>& params,
-                                          std::vector<uint8_t>* secret) {
-    card_->sendPendingEvents();
-    auto error = card_->initializeJavacard();
-    if (error != KM_ERROR_OK) {
-        LOG(ERROR) << "Error in initializing javacard.";
-    }
+ScopedAStatus JavacardSharedSecret::computeSharedSecret(
+    const std::vector<SharedSecretParameters>& params, std::vector<uint8_t>* secret) {
     cppbor::Array request;
     cbor_.addSharedSecretParameters(request, params);
-    auto [item, err] = card_->sendRequest(Instruction::INS_COMPUTE_SHARED_SECRET_CMD, request);
+#ifdef INIT_USING_SEHAL_TRANSPORT
+    auto [item, err] =
+        card_->sendRequestSeHal(Instruction::INS_COMPUTE_SHARED_SECRET_CMD, request.encode());
+#else
+    auto [item, err] =
+        card_->sendRequest(Instruction::INS_COMPUTE_SHARED_SECRET_CMD, request.encode());
+#endif
     if (err != KM_ERROR_OK) {
         LOG(ERROR) << "Error in sending in computeSharedSecret.";
         return keymint::km_utils::kmError2ScopedAStatus(err);
diff --git a/KM300/res/config.fs b/KM300/res/config.fs
index 465e5bb..3e98b99 100644
--- a/KM300/res/config.fs
+++ b/KM300/res/config.fs
@@ -7,7 +7,7 @@ value:2902
 [AID_VENDOR_NXP_AUTHSECRET]
 value:2903
 
-[vendor/bin/hw/android.hardware.security.keymint-service.strongbox.nxp]
+[vendor/bin/hw/android.hardware.security.keymint3-service.strongbox.nxp]
 mode: 0755
 user: AID_VENDOR_NXP_STRONGBOX
 group: AID_SYSTEM
diff --git a/KM300/service.cpp b/KM300/service.cpp
index 35dff1e..f424da0 100644
--- a/KM300/service.cpp
+++ b/KM300/service.cpp
@@ -29,7 +29,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2020-2023 NXP
+ ** Copyright 2020-2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "javacard.strongbox-service"
@@ -65,6 +65,7 @@ using keymint::javacard::JavacardSecureElement;
 #if defined OMAPI_TRANSPORT
 using keymint::javacard::OmapiTransport;
 #elif defined HAL_TO_HAL_TRANSPORT
+using keymint::javacard::HalToHalTransport;
 #else
 using keymint::javacard::SocketTransport;
 #endif
diff --git a/transport/Android.bp b/transport/Android.bp
index 3c779d5..58ce80a 100644
--- a/transport/Android.bp
+++ b/transport/Android.bp
@@ -50,16 +50,9 @@ cc_library {
     export_include_dirs: [
         "include"
     ],
-    export_shared_lib_headers: [
-        "android.hardware.secure_element@1.0",
-        "android.hardware.secure_element@1.1",
-        "android.hardware.secure_element@1.2",
-    ],
     shared_libs: [
-        "android.hardware.secure_element@1.0",
-        "android.hardware.secure_element@1.1",
-        "android.hardware.secure_element@1.2",
         "android.se.omapi-V1-ndk",
+        "android.hardware.secure_element-V1-ndk",
         "libbase",
         "liblog",
         "libcutils",
diff --git a/transport/AppletConnection.cpp b/transport/AppletConnection.cpp
index 510ed71..97eee57 100644
--- a/transport/AppletConnection.cpp
+++ b/transport/AppletConnection.cpp
@@ -30,14 +30,14 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2020-2021 NXP
+ ** Copyright 2020-2021,2024 NXP
  **
  *********************************************************************************/
-#define LOG_TAG "OmapiTransport"
+#define LOG_TAG "AppletConnection"
 
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
-#include <log/log.h>
+#include <android/binder_manager.h>
 #include <signal.h>
 #include <iomanip>
 #include <mutex>
@@ -48,100 +48,117 @@
 #include <EseTransportUtils.h>
 #include <SignalHandler.h>
 
-using ::android::hardware::secure_element::V1_0::SecureElementStatus;
-using ::android::hardware::secure_element::V1_0::LogicalChannelResponse;
+using aidl::android::hardware::secure_element::BnSecureElementCallback;
+using aidl::android::hardware::secure_element::ISecureElement;
+using aidl::android::hardware::secure_element::LogicalChannelResponse;
 using android::base::StringPrintf;
+using ndk::ScopedAStatus;
+using ndk::SharedRefBase;
+using ndk::SpAIBinder;
 
 namespace keymint::javacard {
 
 static bool isStrongBox = false; // true when linked with StrongBox HAL process
 const std::vector<uint8_t> kStrongBoxAppletAID = {0xA0, 0x00, 0x00, 0x00, 0x62};
+constexpr const char eseHalServiceName[] = "android.hardware.secure_element.ISecureElement/eSE1";
 
-class SecureElementCallback : public ISecureElementHalCallback {
- public:
-    Return<void> onStateChange(bool state) override {
-        mSEClientState = state;
-        return Void();
+class SecureElementCallback : public BnSecureElementCallback {
+  public:
+    ScopedAStatus onStateChange(bool state, const std::string& in_debugReason) override {
+        LOGD_OMAPI("connected =" << (state ? "true " : "false ") << "reason: " << in_debugReason);
+        mConnState = state;
+        return ScopedAStatus::ok();
     };
-    Return<void> onStateChange_1_1(bool state, const hidl_string& reason) override {
-        LOGD_OMAPI("connected =" << (state?"true " : "false " ) << "reason: " << reason);
-        mSEClientState = state;
-        return Void();
-    };
-    bool isClientConnected() {
-        return mSEClientState;
-    }
- private:
-    bool mSEClientState = false;
-};
-
-sp<SecureElementCallback> mCallback = nullptr;
+    bool isClientConnected() { return mConnState; }
 
-class SEDeathRecipient : public android::hardware::hidl_death_recipient {
-  virtual void serviceDied(uint64_t /*cookie*/, const android::wp<::android::hidl::base::V1_0::IBase>& /*who*/) {
-    LOG(ERROR) << "Secure Element Service died disconnecting SE HAL .....";
-    if(mCallback != nullptr) {
-      LOG(INFO) << "Changing state to disconnect ...";
-      mCallback->onStateChange(false);// Change state to disconnect
-    }
-  }
+  private:
+    bool mConnState = false;
 };
 
-sp<SEDeathRecipient> mSEDeathRecipient = nullptr;
+void AppletConnection::BinderDiedCallback(void* cookie) {
+    LOG(ERROR) << "Received binder death ntf. SE HAL Service died";
+    auto thiz = static_cast<AppletConnection*>(cookie);
+    thiz->mSecureElementCallback->onStateChange(false, "SE HAL died");
+    thiz->mSecureElement = nullptr;
+}
 
-AppletConnection::AppletConnection(const std::vector<uint8_t>& aid) : kAppletAID(aid) {
+AppletConnection::AppletConnection(const std::vector<uint8_t>& aid)
+    : kAppletAID(aid), mSBAccessController(SBAccessController::getInstance()) {
     if (kAppletAID == kStrongBoxAppletAID) {
         isStrongBox = true;
     }
+    mDeathRecipient =
+        ::ndk::ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient_new(BinderDiedCallback));
 }
 
 bool AppletConnection::connectToSEService() {
     if (!SignalHandler::getInstance()->isHandlerRegistered()) {
-        LOG(INFO) << "register signal handler";
+        LOG(DEBUG) << "register signal handler";
         SignalHandler::getInstance()->installHandler(this);
     }
-    if (mSEClient != nullptr && mCallback->isClientConnected()) {
+    if (mSecureElement != nullptr && mSecureElementCallback->isClientConnected()) {
         LOG(INFO) <<"Already connected";
         return true;
     }
-
-    uint8_t retry = 0;
-    bool status = false;
-    while (( mSEClient == nullptr ) && retry++ < MAX_GET_SERVICE_RETRY ){ // How long should we try before giving up !
-      mSEClient = ISecureElement::tryGetService("eSE1");
-
-      if(mSEClient == nullptr){
-        LOG(ERROR) << "failed to get eSE HAL service : retry after 1 sec , retry cnt = " << android::hardware::toString(retry) ;
-      }else {
-        LOG(INFO) << " !!! SuccessFully got Handle to eSE HAL service" ;
-        if (mCallback == nullptr) {
-          mCallback = new SecureElementCallback();
+    bool connected = false;
+    SpAIBinder binder = SpAIBinder(AServiceManager_waitForService(eseHalServiceName));
+    mSecureElement = ISecureElement::fromBinder(binder);
+    if (mSecureElement == nullptr) {
+        LOG(ERROR) << "Failed to connect to Secure element service";
+    } else {
+        mSecureElementCallback = SharedRefBase::make<SecureElementCallback>();
+        auto status = mSecureElement->init(mSecureElementCallback);
+        connected = status.isOk() && mSecureElementCallback->isClientConnected();
+        if (!connected) {
+            LOG(ERROR) << "Failed to initialize SE HAL service";
         }
-        mSEDeathRecipient = new SEDeathRecipient();
-        mSEClient->init_1_1(mCallback);
-        mSEClient->linkToDeath(mSEDeathRecipient, 0/*cookie*/);
-        status = mCallback->isClientConnected();
-        break;
-      }
-      usleep(ONE_SEC);
     }
-    return status;
+    return connected;
 }
 
+// AIDL Hal returns empty response for failure case
+// so prepare response based on service specific errorcode
+void prepareServiceSpecificErrorRepsponse(std::vector<uint8_t>& resp, int32_t errorCode) {
+    resp.clear();
+    switch (errorCode) {
+        case ISecureElement::NO_SUCH_ELEMENT_ERROR:
+            resp.push_back(0x6A);
+            resp.push_back(0x82);
+            break;
+        case ISecureElement::CHANNEL_NOT_AVAILABLE:
+            resp.push_back(0x6A);
+            resp.push_back(0x81);
+            break;
+        case ISecureElement::UNSUPPORTED_OPERATION:
+            resp.push_back(0x6A);
+            resp.push_back(0x86);
+            break;
+        case ISecureElement::IOERROR:
+            resp.push_back(0x64);
+            resp.push_back(0xFF);
+            break;
+        default:
+            resp.push_back(0xFF);
+            resp.push_back(0xFF);
+    }
+}
 bool AppletConnection::selectApplet(std::vector<uint8_t>& resp, uint8_t p2) {
   bool stat = false;
-  mSEClient->openLogicalChannel(
-      kAppletAID, p2, [&](LogicalChannelResponse selectResponse, SecureElementStatus status) {
-        if (status == SecureElementStatus::SUCCESS) {
-          resp = selectResponse.selectResponse;
-          mOpenChannel = selectResponse.channelNumber;
-          stat = true;
-          mSBAccessController.parseResponse(resp);
-          LOG(INFO) << "openLogicalChannel:" << toString(status) << " channelNumber ="
-                    << ::android::hardware::toString(selectResponse.channelNumber) << " "
-                    << selectResponse.selectResponse;
-        }
-      });
+  resp.clear();
+  LogicalChannelResponse logical_channel_response;
+  auto status = mSecureElement->openLogicalChannel(kAppletAID, p2, &logical_channel_response);
+  if (status.isOk()) {
+      mOpenChannel = logical_channel_response.channelNumber;
+      resp = logical_channel_response.selectResponse;
+      stat = true;
+  } else {
+      mOpenChannel = -1;
+      resp = logical_channel_response.selectResponse;
+      LOG(ERROR) << "openLogicalChannel: Failed ";
+      // AIDL Hal returns empty response for failure case
+      // so prepare response based on service specific errorcode
+      prepareServiceSpecificErrorRepsponse(resp, status.getServiceSpecificError());
+  }
   return stat;
 }
 void prepareErrorRepsponse(std::vector<uint8_t>& resp){
@@ -152,14 +169,6 @@ void prepareErrorRepsponse(std::vector<uint8_t>& resp){
 bool AppletConnection::openChannelToApplet(std::vector<uint8_t>& resp) {
   bool ret = false;
   uint8_t retry = 0;
-  if (mCallback == nullptr || !mCallback->isClientConnected()) {
-    mSEClient = nullptr;
-    mOpenChannel = -1;
-    if (!connectToSEService()) {
-      LOG(ERROR) << "Not connected to eSE Service";
-      return ret;
-    }
-  }
   if (isChannelOpen()) {
     LOG(INFO) << "channel Already opened";
     return true;
@@ -180,16 +189,15 @@ bool AppletConnection::openChannelToApplet(std::vector<uint8_t>& resp) {
   } else {
       ret = selectApplet(resp, 0x0);
   }
-
   return ret;
 }
 
 bool AppletConnection::transmit(std::vector<uint8_t>& CommandApdu , std::vector<uint8_t>& output){
-    hidl_vec<uint8_t> cmd = CommandApdu;
+    std::vector<uint8_t> cmd = CommandApdu;
     cmd[0] |= mOpenChannel ;
-    LOGD_OMAPI("Channel number " << ::android::hardware::toString(mOpenChannel));
+    LOGD_OMAPI("Channel number: " << static_cast<int>(mOpenChannel));
 
-    if (mSEClient == nullptr) return false;
+    if (mSecureElement == nullptr) return false;
     if (isStrongBox) {
         if (!mSBAccessController.isOperationAllowed(CommandApdu[APDU_INS_OFFSET])) {
             std::vector<uint8_t> ins;
@@ -201,12 +209,9 @@ bool AppletConnection::transmit(std::vector<uint8_t>& CommandApdu , std::vector<
     }
     // block any fatal signal delivery
     SignalHandler::getInstance()->blockSignals();
-
-    mSEClient->transmit(cmd, [&](hidl_vec<uint8_t> result) {
-        output = result;
-        LOG(INFO) << "received response size = " << ::android::hardware::toString(result.size()) << " data = " << result;
-    });
-
+    std::vector<uint8_t> response;
+    mSecureElement->transmit(cmd, &response);
+    output = response;
     // un-block signal delivery
     SignalHandler::getInstance()->unblockSignals();
     return true;
@@ -218,16 +223,16 @@ int AppletConnection::getSessionTimeout() {
 
 bool AppletConnection::close() {
     std::lock_guard<std::mutex> lock(channel_mutex_);
-    if (mSEClient == nullptr) {
-         LOG(ERROR) << "Channel couldn't be closed mSEClient handle is null";
-         return false;
+    if (mSecureElement == nullptr) {
+        LOG(ERROR) << "Channel couldn't be closed mSEClient handle is null";
+        return false;
     }
     if(mOpenChannel < 0){
        LOG(INFO) << "Channel is already closed";
        return true;
     }
-    SecureElementStatus status = mSEClient->closeChannel(mOpenChannel);
-    if (status != SecureElementStatus::SUCCESS) {
+    auto status = mSecureElement->closeChannel(mOpenChannel);
+    if (!status.isOk()) {
         /*
          * reason could be SE reset or HAL deinit triggered from other client
          * which anyway closes all the opened channels
@@ -241,12 +246,16 @@ bool AppletConnection::close() {
     return true;
 }
 
-bool AppletConnection::isChannelOpen() {
+bool AppletConnection::isServiceConnected() {
     std::lock_guard<std::mutex> lock(channel_mutex_);
-    if(mCallback == nullptr || !mCallback->isClientConnected()) {
-      return false;
+    if (mSecureElement == nullptr || !mSecureElementCallback->isClientConnected()) {
+        return false;
     }
-    return mOpenChannel >= 0;
+    return true;
 }
 
+bool AppletConnection::isChannelOpen() {
+    std::lock_guard<std::mutex> lock(channel_mutex_);
+    return mOpenChannel >= 0;
+}
 }  // namespace keymint::javacard
diff --git a/transport/HalToHalTransport.cpp b/transport/HalToHalTransport.cpp
index 0d0ebd4..33f1c39 100644
--- a/transport/HalToHalTransport.cpp
+++ b/transport/HalToHalTransport.cpp
@@ -30,7 +30,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2020-2021, 2023 NXP
+ ** Copyright 2020-2021, 2023-2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "HalToHalTransport"
@@ -57,27 +57,30 @@ bool HalToHalTransport::openConnection() {
 }
 
 bool HalToHalTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) {
-    bool status = false;
     std::vector<uint8_t> cApdu(inData);
 #ifdef INTERVAL_TIMER
      LOGD_OMAPI("stop the timer");
      mTimer.kill();
 #endif
      if (!isConnected()) {
-         std::vector<uint8_t> selectResponse;
-         status = mAppletConnection.openChannelToApplet(selectResponse);
-         if (!status) {
-             LOG(ERROR) << " Failed to open Logical Channel ,response " << selectResponse;
-             output = std::move(selectResponse);
-             return status;
+         if (!openConnection()) {
+             return false;
          }
      }
+     std::vector<uint8_t> selectResponse;
+     bool status = mAppletConnection.openChannelToApplet(selectResponse);
+     if (!status) {
+         LOG(ERROR) << " Failed to open Logical Channel ,response " << selectResponse;
+         output = std::move(selectResponse);
+         return false;
+     }
     status = mAppletConnection.transmit(cApdu, output);
     if (output.size() < 2 ||
         (output.size() >= 2 && (output.at(output.size() - 2) == LOGICAL_CH_NOT_SUPPORTED_SW1 &&
                                 output.at(output.size() - 1) == LOGICAL_CH_NOT_SUPPORTED_SW2))) {
         LOGD_OMAPI("transmit failed ,close the channel");
-        return mAppletConnection.close();
+        mAppletConnection.close();
+        return false;
     }
 #ifdef INTERVAL_TIMER
      int timeout = mAppletConnection.getSessionTimeout();
@@ -88,7 +91,7 @@ bool HalToHalTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>&
        mTimer.set(mAppletConnection.getSessionTimeout(), this, SessionTimerFunc);
      }
 #endif
-    return status;
+     return true;
 }
 
 bool HalToHalTransport::closeConnection() {
@@ -96,6 +99,6 @@ bool HalToHalTransport::closeConnection() {
 }
 
 bool HalToHalTransport::isConnected() {
-    return mAppletConnection.isChannelOpen();
+    return mAppletConnection.isServiceConnected();
 }
 } // namespace keymint::javacard
diff --git a/transport/OmapiTransport.cpp b/transport/OmapiTransport.cpp
index 186e1b6..530cfc2 100644
--- a/transport/OmapiTransport.cpp
+++ b/transport/OmapiTransport.cpp
@@ -30,7 +30,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2022-2023 NXP
+ ** Copyright 2022-2024 NXP
  **
  *********************************************************************************/
 #define LOG_TAG "OmapiTransport"
@@ -287,9 +287,9 @@ bool OmapiTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>& ou
 #endif
     if (!isConnected()) {
         // Try to initialize connection to eSE
-        LOG(INFO) << "Failed to send data, try to initialize connection SE connection";
+        LOG(INFO) << "Not connected, try to initialize connection to OMAPI";
         if (!initialize()) {
-            LOG(ERROR) << "Failed to send data, initialization not completed";
+            LOG(ERROR) << "Failed to connect to OMAPI";
             closeConnection();
             return false;
         }
@@ -371,6 +371,10 @@ bool OmapiTransport::internalProtectedTransmitApdu(
     //auto mSEListener = std::make_shared<SEListener>();
     std::vector<uint8_t> selectResponse = {};
     const std::vector<uint8_t> sbAppletAID = {0xA0, 0x00, 0x00, 0x00, 0x62};
+    bool isSBAppletAID = false;
+    if (sbAppletAID == mSelectableAid) {
+        isSBAppletAID = true;
+    }
 
     if (reader == nullptr) {
         LOG(ERROR) << "eSE reader is null";
@@ -401,7 +405,7 @@ bool OmapiTransport::internalProtectedTransmitApdu(
     }
 
     if ((channel == nullptr || (channel->isClosed(&status).isOk() && status))) {
-      if (!mSBAccessController.isOperationAllowed(apdu[APDU_INS_OFFSET])) {
+      if (isSBAppletAID && !mSBAccessController.isOperationAllowed(apdu[APDU_INS_OFFSET])) {
         LOG(ERROR) << "Select / Command INS not allowed";
         prepareErrorRepsponse(transmitResponse);
         return false;
@@ -416,6 +420,7 @@ bool OmapiTransport::internalProtectedTransmitApdu(
       }
       if (channel == nullptr) {
         LOG(ERROR) << "Could not open channel null";
+        prepareErrorRepsponse(transmitResponse);
         return false;
       }
 
@@ -431,21 +436,20 @@ bool OmapiTransport::internalProtectedTransmitApdu(
           LOG(ERROR) << "Failed to select the Applet.";
           return false;
       }
-      if (sbAppletAID == mSelectableAid) {
-        mSBAccessController.parseResponse(selectResponse);
+      if (isSBAppletAID) {
+          mSBAccessController.parseResponse(selectResponse);
       }
     }
 
-    status = false;
-    if (mSBAccessController.isOperationAllowed(apdu[APDU_INS_OFFSET])) {
+    if (!isSBAppletAID ||
+        mSBAccessController.isOperationAllowed(apdu[APDU_INS_OFFSET])) {
 #ifdef ENABLE_DEBUG_LOG
       LOGD_OMAPI("constructed apdu: " << apdu);
 #endif
       res = channel->transmit(apdu, &transmitResponse);
-      status = true;
     } else {
-        LOG(ERROR) << "command Ins:" << apdu[APDU_INS_OFFSET] << " not allowed";
-        prepareErrorRepsponse(transmitResponse);
+      LOG(ERROR) << "command Ins:" << apdu[APDU_INS_OFFSET] << " not allowed";
+      prepareErrorRepsponse(transmitResponse);
     }
 #ifdef INTERVAL_TIMER
     int timeout = 0x00;
@@ -478,7 +482,7 @@ bool OmapiTransport::internalProtectedTransmitApdu(
         LOG(ERROR) << "transmit error: " << res.getMessage();
         return false;
     }
-    return status;
+    return true;
 }
 
 void OmapiTransport::prepareErrorRepsponse(std::vector<uint8_t>& resp){
@@ -517,7 +521,19 @@ bool OmapiTransport::openChannelToApplet() {
   return false;
 }
 
-#endif
+void OmapiTransport::setCryptoOperationState(uint8_t state) {
+    mSBAccessController.setCryptoOperationState(state);
+
+    int timeout = mSBAccessController.getSessionTimeout();
+
+    LOGD_OMAPI("Reset the timer with timeout " << timeout << " ms");
+    if (!mTimer.set(timeout, this, omapiSessionTimerFunc)) {
+        LOG(ERROR) << "Set Timer Failed !!!";
+        closeChannel();
+    }
+}
+
+#endif  // NXP_EXTNS
 
 }  // namespace keymint::javacard
 #endif // OMAPI_TRANSPORT
diff --git a/transport/SBAccessController.cpp b/transport/SBAccessController.cpp
index 8f88353..7ccefe8 100644
--- a/transport/SBAccessController.cpp
+++ b/transport/SBAccessController.cpp
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2021-2023 NXP
+ *  Copyright 2021-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -31,18 +31,18 @@
 namespace keymint::javacard {
 
 static bool g_AccessAllowed = true;
-static bool g_IsCryptoOperationRunning = false;
+static std::atomic<uint8_t> g_NumOfCryptoOps = 0;
 
 // These should be in sync with JavacardKeymasterDevice41.cpp
 // Allow listed cmds
-std::map<uint8_t, uint8_t> allowedCmdIns = {{0xD9 /*INS_SET_VERSION_PATCHLEVEL*/, 0},
+std::map<uint8_t, uint8_t> allowedCmdIns = {{0x2D /*INS_GET_HMAC_SHARING_PARAM*/, 0},
                                             {0x2A /*INS_COMPUTE_SHARED_HMAC*/, 0},
-                                            {0x2D /*INS_GET_HMAC_SHARING_PARAM*/, 0}};
+                                            {0x4D /*INS_GET_ROT_CHALLENGE_CMD*/, 0}};
 
 static void CryptoOpTimerFunc(union sigval arg) {
     (void)arg;  // unused
     LOG(DEBUG) << "CryptoOperation timer expired";
-    g_IsCryptoOperationRunning = false;
+    g_NumOfCryptoOps = 0;
 }
 
 static void AccessTimerFunc(union sigval arg) {
@@ -50,7 +50,10 @@ static void AccessTimerFunc(union sigval arg) {
     LOG(DEBUG) << "Applet access-block timer expired";
     g_AccessAllowed = true;
 }
-
+SBAccessController& SBAccessController::getInstance() {
+    static SBAccessController sb_access_cntrl;
+    return sb_access_cntrl;
+}
 void SBAccessController::startTimer(bool isStart, IntervalTimer& t, int timeout,
                                     void (*timerFunc)(union sigval)) {
     t.kill();
@@ -78,7 +81,7 @@ int SBAccessController::getSessionTimeout() {
         return (mBootState == BOOTSTATE::SB_EARLY_BOOT_ENDED) ? SMALLEST_SESSION_TIMEOUT
                                                               : UPGRADE_SESSION_TIMEOUT;
     } else {
-        return g_IsCryptoOperationRunning ? CRYPTO_OP_SESSION_TIMEOUT : REGULAR_SESSION_TIMEOUT;
+        return (g_NumOfCryptoOps > 0) ? CRYPTO_OP_SESSION_TIMEOUT : REGULAR_SESSION_TIMEOUT;
     }
 }
 bool SBAccessController::isSelectAllowed() {
@@ -114,17 +117,23 @@ void SBAccessController::updateBootState() {
         mBootState = BOOTSTATE::SB_EARLY_BOOT_ENDED;
     }
 }
+void SBAccessController::setCryptoOperationState(uint8_t opState) {
+    if (opState == OPERATION_STATE::OP_STARTED) {
+        g_NumOfCryptoOps++;
+        startTimer(true, mTimerCrypto, CRYPTO_OP_SESSION_TIMEOUT, CryptoOpTimerFunc);
+    } else if (opState == OPERATION_STATE::OP_FINISHED) {
+        if (g_NumOfCryptoOps > 0) g_NumOfCryptoOps--;
+        if (g_NumOfCryptoOps == 0) {
+            LOG(INFO) << "All crypto operations finished";
+            startTimer(false, mTimerCrypto, 0, nullptr);
+        }
+    }
+    LOG(INFO) << "Number of operations running: " << std::to_string(g_NumOfCryptoOps);
+}
 bool SBAccessController::isOperationAllowed(uint8_t cmdIns) {
     bool op_allowed = false;
     if (g_AccessAllowed) {
         op_allowed = true;
-        if (cmdIns == BEGIN_OPERATION_CMD) {
-            g_IsCryptoOperationRunning = true;
-            startTimer(true, mTimerCrypto, CRYPTO_OP_SESSION_TIMEOUT, CryptoOpTimerFunc);
-        } else if (cmdIns == FINISH_OPERATION_CMD || cmdIns == ABORT_OPERATION_CMD) {
-            g_IsCryptoOperationRunning = false;
-            startTimer(false, mTimerCrypto, 0, nullptr);
-        }
     } else {
         switch (mBootState) {
             case BOOTSTATE::SB_EARLY_BOOT: {
@@ -139,8 +148,8 @@ bool SBAccessController::isOperationAllowed(uint8_t cmdIns) {
                 break;
         }
     }
-    if (cmdIns == EARLY_BOOT_ENDED_CMD) {
-        // allowed as this is sent by VOLD only during early boot
+    if (cmdIns == EARLY_BOOT_ENDED_CMD || cmdIns == INS_SEND_ROT_DATA_CMD) {
+        // allowed as these may be received during early boot
         op_allowed = true;
     }
     return op_allowed;
diff --git a/transport/include/AppletConnection.h b/transport/include/AppletConnection.h
index c224c18..ef79c99 100644
--- a/transport/include/AppletConnection.h
+++ b/transport/include/AppletConnection.h
@@ -30,32 +30,21 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2020-2021 NXP
+ ** Copyright 2020-2021,2024 NXP
  **
  *********************************************************************************/
 #ifndef __APPLETCONNECTION_H__
 #define __APPLETCONNECTION_H__
 
-#include <android/hardware/secure_element/1.0/types.h>
-#include <android/hardware/secure_element/1.1/ISecureElementHalCallback.h>
-#include <android/hardware/secure_element/1.2/ISecureElement.h>
-#include <hidl/MQDescriptor.h>
-#include <hidl/Status.h>
+#include <aidl/android/hardware/secure_element/BnSecureElementCallback.h>
+#include <aidl/android/hardware/secure_element/ISecureElement.h>
 #include <vector>
 
 #include <SBAccessController.h>
 
 namespace keymint::javacard {
-
-using ::android::hardware::hidl_array;
-using ::android::hardware::hidl_memory;
-using ::android::hardware::hidl_string;
-using ::android::hardware::hidl_vec;
-using ::android::hardware::Return;
-using ::android::hardware::Void;
-using ::android::sp;
-using ::android::hardware::secure_element::V1_2::ISecureElement;
-using ::android::hardware::secure_element::V1_1::ISecureElementHalCallback;
+class SecureElementCallback;
+using aidl::android::hardware::secure_element::ISecureElement;
 
 struct AppletConnection {
 public:
@@ -87,6 +76,11 @@ public:
    * Checks if a channel to the applet is open.
    */
   bool isChannelOpen();
+
+  /**
+   * Checks if service is connected to eSE HAL.
+   */
+  bool isServiceConnected();
   /**
    * Get session timeout value based on select response normal/update session
    */
@@ -99,10 +93,14 @@ public:
   bool selectApplet(std::vector<uint8_t>& resp, uint8_t p2);
 
   std::mutex channel_mutex_;  // exclusive access to isChannelopen()/close()
-  sp<ISecureElement> mSEClient;
+
+  std::shared_ptr<ISecureElement> mSecureElement;
+  std::shared_ptr<SecureElementCallback> mSecureElementCallback;
+  ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
+  static void BinderDiedCallback(void* cookie);
   std::vector<uint8_t> kAppletAID;
   int8_t mOpenChannel = -1;
-  SBAccessController mSBAccessController;
+  SBAccessController& mSBAccessController;
 };
 
 }  // namespace keymint::javacard
diff --git a/transport/include/ITransport.h b/transport/include/ITransport.h
index 15be7b4..59fa915 100644
--- a/transport/include/ITransport.h
+++ b/transport/include/ITransport.h
@@ -30,7 +30,7 @@
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 **
-** Copyright 2021-2023 NXP
+** Copyright 2021-2024 NXP
 **
 *********************************************************************************/
 #pragma once
@@ -60,6 +60,12 @@ class ITransport {
       (void)aid;
       return false;
     }
+
+    /**
+     * Sets state(start/finish) of crypto operation.
+     * This is required for channel session timeout mgmt.
+     */
+    virtual void setCryptoOperationState(uint8_t state) { (void)state; };
 #endif
     /**
      * Opens connection.
diff --git a/transport/include/OmapiTransport.h b/transport/include/OmapiTransport.h
index 57ff755..c8615c4 100644
--- a/transport/include/OmapiTransport.h
+++ b/transport/include/OmapiTransport.h
@@ -30,7 +30,7 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2022-2023 NXP
+ ** Copyright 2022-2024 NXP
  **
  *********************************************************************************/
 #if defined OMAPI_TRANSPORT
@@ -47,11 +47,10 @@
 
 #include <map>
 
-#include "ITransport.h"
-#include <AppletConnection.h>
 #include <IntervalTimer.h>
 #include <memory>
 #include <vector>
+#include "ITransport.h"
 
 #include <SBAccessController.h>
 
@@ -83,6 +82,12 @@ public:
     mSelectableAid = aid;
     return true;
   }
+
+  /**
+   * Sets state(start/finish) of crypto operation.
+   * This is required for channel session timeout mgmt.
+   */
+  void setCryptoOperationState(uint8_t state) override;
 #endif
     /**
      * Gets the binder instance of ISEService, gets te reader corresponding to secure element,
@@ -115,7 +120,7 @@ public:
 
   private:
     //AppletConnection mAppletConnection;
-    SBAccessController mSBAccessController;
+    SBAccessController& mSBAccessController;
     IntervalTimer mTimer;
     int mTimeout;
     std::vector<uint8_t> mSelectableAid;
@@ -129,10 +134,16 @@ public:
     /* Applet ID Weaver */
     const std::vector<uint8_t> kWeaverAID = {0xA0, 0x00, 0x00, 0x03, 0x96, 0x10, 0x10};
 #endif
-    OmapiTransport(const std::vector<uint8_t> &mAppletAID)
-        : ITransport(mAppletAID), mTimeout(0), mSelectableAid(mAppletAID),
-          omapiSeService(nullptr), eSEReader(nullptr), session(nullptr),
-          channel(nullptr), mVSReaders({}) {
+  OmapiTransport(const std::vector<uint8_t>& mAppletAID)
+      : ITransport(mAppletAID),
+        mSBAccessController(SBAccessController::getInstance()),
+        mTimeout(0),
+        mSelectableAid(mAppletAID),
+        omapiSeService(nullptr),
+        eSEReader(nullptr),
+        session(nullptr),
+        channel(nullptr),
+        mVSReaders({}) {
 #ifdef NXP_EXTNS
       mDeathRecipient = ::ndk::ScopedAIBinder_DeathRecipient(
           AIBinder_DeathRecipient_new(BinderDiedCallback));
diff --git a/transport/include/SBAccessController.h b/transport/include/SBAccessController.h
index e5ca0a7..9067c7b 100644
--- a/transport/include/SBAccessController.h
+++ b/transport/include/SBAccessController.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2021 NXP
+ *  Copyright 2021,2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -22,6 +22,7 @@
 #include <vector>
 
 #define EARLY_BOOT_ENDED_CMD (0x35)  // INS Received from VOLD when earlyboot state ends
+#define INS_SEND_ROT_DATA_CMD (0x4F)  // Google defined RoT cmd
 #define BEGIN_OPERATION_CMD (0x30)   // begin()
 #define FINISH_OPERATION_CMD (0x32)  // finish()
 #define ABORT_OPERATION_CMD (0x33)   // abort()
@@ -40,14 +41,15 @@ enum BOOTSTATE {
     SB_EARLY_BOOT = 0,
     SB_EARLY_BOOT_ENDED,
 };
+
+enum OPERATION_STATE {
+    OP_STARTED = 0,
+    OP_FINISHED,
+};
+
 namespace keymint::javacard {
 class SBAccessController {
   public:
-    /**
-     * Constructor
-     */
-    SBAccessController() : mIsUpdateInProgress(false), mBootState(SB_EARLY_BOOT) {}
-
     /**
      * Controls Applet selection
      * 1) Not allowed when actual upgrade is in progress for 40 secs
@@ -65,6 +67,13 @@ class SBAccessController {
      */
     void parseResponse(std::vector<uint8_t>& responseApdu);
 
+    /**
+     * Sets the state of crypto operation
+     * Params : crypto operation start/finish
+     * Returns : void
+     */
+    void setCryptoOperationState(uint8_t opState);
+
     /**
      * Determines if current INS is allowed
      * Params : one bytes INS value
@@ -90,7 +99,17 @@ class SBAccessController {
      */
     void updateBootState();
 
+    /**
+     * Helper function to get singleton instance
+     * Params: void
+     * Returns: Instance of SBAccessController
+     */
+    static SBAccessController& getInstance();
+    SBAccessController(const SBAccessController&) = delete;
+
   private:
+    // mark constructor private
+    SBAccessController() : mIsUpdateInProgress(false), mBootState(SB_EARLY_BOOT) {}
     bool mIsUpdateInProgress;  // stores Applet upgrade state
     BOOTSTATE mBootState;
 
```

