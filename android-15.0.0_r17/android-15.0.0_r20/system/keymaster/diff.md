```diff
diff --git a/Android.bp b/Android.bp
index c4c6589..78c5881 100644
--- a/Android.bp
+++ b/Android.bp
@@ -395,6 +395,50 @@ cc_library {
     ],
 }
 
+cc_library {
+    name: "libkeymasterconfig",
+    vendor_available: true,
+    srcs: [
+        "android_keymaster/keymaster_configuration.cpp",
+    ],
+    defaults: [
+        "keymaster_defaults",
+    ],
+    shared_libs: [
+        "lib_android_keymaster_keymint_utils",
+        "libbase",
+        "libcutils",
+        "libhardware",
+        "libkeymaster_messages",
+        "liblog",
+    ],
+    export_include_dirs: [
+        "include",
+    ],
+}
+
+cc_library {
+    name: "libkeymasterconfig_V3",
+    vendor_available: true,
+    srcs: [
+        "android_keymaster/keymaster_configuration.cpp",
+    ],
+    defaults: [
+        "keymaster_defaults",
+    ],
+    shared_libs: [
+        "lib_android_keymaster_keymint_utils_V3",
+        "libbase",
+        "libcutils",
+        "libhardware",
+        "libkeymaster_messages",
+        "liblog",
+    ],
+    export_include_dirs: [
+        "include",
+    ],
+}
+
 cc_library {
     name: "libkeymint",
     vendor_available: true,
@@ -436,6 +480,46 @@ cc_library {
     ],
 }
 
+cc_library {
+    name: "lib_android_keymaster_keymint_utils_V3",
+    vendor_available: true,
+    srcs: [
+        "ng/KeyMintUtils.cpp",
+    ],
+    defaults: [
+        "keymaster_defaults",
+    ],
+    shared_libs: [
+        "android.hardware.security.keymint-V3-ndk",
+        "libbase",
+        "libhardware",
+    ],
+    export_include_dirs: [
+        "ng/include",
+        "include",
+    ],
+}
+
+cc_library {
+    name: "lib_android_keymaster_keymint_utils_V2",
+    vendor_available: true,
+    srcs: [
+        "ng/KeyMintUtils.cpp",
+    ],
+    defaults: [
+        "keymaster_defaults",
+    ],
+    shared_libs: [
+        "android.hardware.security.keymint-V2-ndk",
+        "libbase",
+        "libhardware",
+    ],
+    export_include_dirs: [
+        "ng/include",
+        "include",
+    ],
+}
+
 cc_library {
     name: "libcppcose_rkp",
     vendor_available: true,
@@ -499,3 +583,9 @@ cc_fuzz {
         "tests/fuzzers/message_serializable_fuzz.cpp",
     ],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_system_keymaster",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/android_keymaster/android_keymaster.cpp b/android_keymaster/android_keymaster.cpp
index e5ea6ac..c8bd3a1 100644
--- a/android_keymaster/android_keymaster.cpp
+++ b/android_keymaster/android_keymaster.cpp
@@ -1090,4 +1090,17 @@ AndroidKeymaster::SetAttestationIdsKM3(const SetAttestationIdsKM3Request& reques
     return response;
 }
 
+SetAdditionalAttestationInfoResponse
+AndroidKeymaster::SetAdditionalAttestationInfo(const SetAdditionalAttestationInfoRequest& request) {
+    SetAdditionalAttestationInfoResponse response(message_version());
+    response.error = KM_ERROR_OK;
+
+    keymaster_blob_t module_hash;
+    if (request.info.GetTagValue(TAG_MODULE_HASH, &module_hash)) {
+        response.error = context_->SetModuleHash(module_hash);
+    }
+
+    return response;
+}
+
 }  // namespace keymaster
diff --git a/android_keymaster/keymaster_enforcement.cpp b/android_keymaster/keymaster_enforcement.cpp
index 9b88661..5e878c4 100644
--- a/android_keymaster/keymaster_enforcement.cpp
+++ b/android_keymaster/keymaster_enforcement.cpp
@@ -323,6 +323,7 @@ keymaster_error_t KeymasterEnforcement::AuthorizeBegin(const keymaster_purpose_t
         case KM_TAG_CERTIFICATE_SERIAL:
         case KM_TAG_CERTIFICATE_NOT_AFTER:
         case KM_TAG_CERTIFICATE_NOT_BEFORE:
+        case KM_TAG_MODULE_HASH:
             return KM_ERROR_INVALID_KEY_BLOB;
 
         /* Tags used for cryptographic parameters in keygen.  Nothing to enforce. */
diff --git a/android_keymaster/keymaster_tags.cpp b/android_keymaster/keymaster_tags.cpp
index f1aafea..e46a8d8 100644
--- a/android_keymaster/keymaster_tags.cpp
+++ b/android_keymaster/keymaster_tags.cpp
@@ -167,6 +167,8 @@ const char* StringifyTag(keymaster_tag_t tag) {
         return "KM_TAG_RSA_OAEP_MGF_DIGEST";
     case KM_TAG_MAX_BOOT_LEVEL:
         return "KM_TAG_MAX_BOOT_LEVEL";
+    case KM_TAG_MODULE_HASH:
+        return "KM_TAG_MODULE_HASH";
     }
     return "<Unknown>";
 }
@@ -220,6 +222,7 @@ DEFINE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_SECOND_IMEI);
 DEFINE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_MEID);
 DEFINE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_MANUFACTURER);
 DEFINE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_MODEL);
+DEFINE_KEYMASTER_TAG(KM_BYTES, TAG_MODULE_HASH);
 DEFINE_KEYMASTER_TAG(KM_BOOL, TAG_UNLOCKED_DEVICE_REQUIRED);
 DEFINE_KEYMASTER_TAG(KM_BOOL, TAG_TRUSTED_CONFIRMATION_REQUIRED);
 DEFINE_KEYMASTER_TAG(KM_BOOL, TAG_EARLY_BOOT_ONLY);
diff --git a/contexts/pure_soft_keymaster_context.cpp b/contexts/pure_soft_keymaster_context.cpp
index c37d5ac..296152d 100644
--- a/contexts/pure_soft_keymaster_context.cpp
+++ b/contexts/pure_soft_keymaster_context.cpp
@@ -141,6 +141,22 @@ keymaster_error_t PureSoftKeymasterContext::SetBootPatchlevel(uint32_t boot_patc
     return KM_ERROR_OK;
 }
 
+keymaster_error_t PureSoftKeymasterContext::SetModuleHash(const keymaster_blob_t& mod_hash) {
+    std::vector<uint8_t> module_hash(mod_hash.data, mod_hash.data + mod_hash.data_length);
+    if (module_hash_.has_value()) {
+        if (module_hash != module_hash_.value()) {
+            // Can't set module hash to a different value.
+            return KM_ERROR_MODULE_HASH_ALREADY_SET;
+        } else {
+            LOG_I("module hash already set, ignoring repeated attempt to set same info");
+            return KM_ERROR_OK;
+        }
+    } else {
+        module_hash_ = module_hash;
+        return KM_ERROR_OK;
+    }
+}
+
 KeyFactory* PureSoftKeymasterContext::GetKeyFactory(keymaster_algorithm_t algorithm) const {
     switch (algorithm) {
     case KM_ALGORITHM_RSA:
@@ -161,7 +177,7 @@ KeyFactory* PureSoftKeymasterContext::GetKeyFactory(keymaster_algorithm_t algori
 static keymaster_algorithm_t supported_algorithms[] = {KM_ALGORITHM_RSA, KM_ALGORITHM_EC,
                                                        KM_ALGORITHM_AES, KM_ALGORITHM_HMAC};
 
-keymaster_algorithm_t*
+const keymaster_algorithm_t*
 PureSoftKeymasterContext::GetSupportedAlgorithms(size_t* algorithms_count) const {
     *algorithms_count = array_length(supported_algorithms);
     return supported_algorithms;
@@ -245,6 +261,10 @@ keymaster_error_t PureSoftKeymasterContext::CreateKeyBlob(const AuthorizationSet
     error =
         ExtendKeyBlobAuthorizations(hw_enforced, sw_enforced, vendor_patchlevel_, boot_patchlevel_);
     if (error != KM_ERROR_OK) return error;
+    if (module_hash_.has_value()) {
+        keymaster_blob_t mod_hash = {module_hash_.value().data(), module_hash_.value().size()};
+        sw_enforced->push_back(TAG_MODULE_HASH, mod_hash);
+    }
 
     AuthorizationSet hidden;
     error = BuildHiddenAuthorizations(key_description, &hidden, softwareRootOfTrust);
diff --git a/include/keymaster/android_keymaster.h b/include/keymaster/android_keymaster.h
index 1e51def..aee0eb9 100644
--- a/include/keymaster/android_keymaster.h
+++ b/include/keymaster/android_keymaster.h
@@ -105,6 +105,8 @@ class AndroidKeymaster {
     GetHwInfoResponse GetHwInfo();
     SetAttestationIdsResponse SetAttestationIds(const SetAttestationIdsRequest& request);
     SetAttestationIdsKM3Response SetAttestationIdsKM3(const SetAttestationIdsKM3Request& request);
+    SetAdditionalAttestationInfoResponse
+    SetAdditionalAttestationInfo(const SetAdditionalAttestationInfoRequest& request);
 
     bool has_operation(keymaster_operation_handle_t op_handle) const;
 
diff --git a/include/keymaster/android_keymaster_messages.h b/include/keymaster/android_keymaster_messages.h
index d7689a8..671d18b 100644
--- a/include/keymaster/android_keymaster_messages.h
+++ b/include/keymaster/android_keymaster_messages.h
@@ -74,6 +74,7 @@ enum AndroidKeymasterCommand : uint32_t {
     GENERATE_CSR_V2 = 37,
     SET_ATTESTATION_IDS = 38,
     SET_ATTESTATION_IDS_KM3 = 39,
+    SET_ADDITIONAL_ATTESTATION_INFO = 40,
 };
 
 /**
@@ -137,6 +138,7 @@ inline int32_t MessageVersion(KmVersion version, uint32_t /* km_date */ = 0) {
     case KmVersion::KEYMINT_1:
     case KmVersion::KEYMINT_2:
     case KmVersion::KEYMINT_3:
+    case KmVersion::KEYMINT_4:
         return 4;
     }
     return kInvalidMessageVersion;
@@ -1215,6 +1217,23 @@ struct SetAttestationIdsKM3Request : public KeymasterMessage {
 
 using SetAttestationIdsKM3Response = EmptyKeymasterResponse;
 
+struct SetAdditionalAttestationInfoRequest : public KeymasterMessage {
+    explicit SetAdditionalAttestationInfoRequest(int32_t ver) : KeymasterMessage(ver) {}
+    size_t SerializedSize() const override { return info.SerializedSize(); }
+
+    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
+        return info.Serialize(buf, end);
+    }
+
+    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
+        return info.Deserialize(buf_ptr, end);
+    }
+
+    AuthorizationSet info;
+};
+
+using SetAdditionalAttestationInfoResponse = EmptyKeymasterResponse;
+
 struct ConfigureVendorPatchlevelRequest : public KeymasterMessage {
     explicit ConfigureVendorPatchlevelRequest(int32_t ver) : KeymasterMessage(ver) {}
 
diff --git a/include/keymaster/contexts/pure_soft_keymaster_context.h b/include/keymaster/contexts/pure_soft_keymaster_context.h
index 834a092..038827c 100644
--- a/include/keymaster/contexts/pure_soft_keymaster_context.h
+++ b/include/keymaster/contexts/pure_soft_keymaster_context.h
@@ -62,7 +62,7 @@ class PureSoftKeymasterContext : public KeymasterContext,
     KeyFactory* GetKeyFactory(keymaster_algorithm_t algorithm) const override;
     OperationFactory* GetOperationFactory(keymaster_algorithm_t algorithm,
                                           keymaster_purpose_t purpose) const override;
-    keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
+    const keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
     keymaster_error_t UpgradeKeyBlob(const KeymasterKeyBlob& key_to_upgrade,
                                      const AuthorizationSet& upgrade_params,
                                      KeymasterKeyBlob* upgraded_key) const override;
@@ -106,6 +106,8 @@ class PureSoftKeymasterContext : public KeymasterContext,
 
     std::optional<uint32_t> GetBootPatchlevel() const override { return boot_patchlevel_; }
 
+    keymaster_error_t SetModuleHash(const keymaster_blob_t& module_hash) override;
+
     /*********************************************************************************************
      * Implement SoftwareKeyBlobMaker
      */
@@ -141,6 +143,7 @@ class PureSoftKeymasterContext : public KeymasterContext,
     std::optional<std::vector<uint8_t>> vbmeta_digest_;
     std::optional<uint32_t> vendor_patchlevel_;
     std::optional<uint32_t> boot_patchlevel_;
+    std::optional<std::vector<uint8_t>> module_hash_;
     SoftKeymasterEnforcement soft_keymaster_enforcement_;
     const keymaster_security_level_t security_level_;
     std::unique_ptr<SecureKeyStorage> pure_soft_secure_key_storage_;
diff --git a/include/keymaster/keymaster_context.h b/include/keymaster/keymaster_context.h
index f4d01dc..9c69306 100644
--- a/include/keymaster/keymaster_context.h
+++ b/include/keymaster/keymaster_context.h
@@ -291,6 +291,13 @@ class KeymasterContext {
         return KM_ERROR_UNIMPLEMENTED;
     }
 
+    /**
+     * Sets the apex module hash for the implementation.
+     */
+    virtual keymaster_error_t SetModuleHash(const keymaster_blob_t& /* module_hash */) {
+        return KM_ERROR_UNIMPLEMENTED;
+    }
+
   private:
     // Uncopyable.
     KeymasterContext(const KeymasterContext&);
diff --git a/include/keymaster/keymaster_tags.h b/include/keymaster/keymaster_tags.h
index dbd195c..67c08dc 100644
--- a/include/keymaster/keymaster_tags.h
+++ b/include/keymaster/keymaster_tags.h
@@ -184,6 +184,7 @@ DECLARE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_SECOND_IMEI);
 DECLARE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_MEID);
 DECLARE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_MANUFACTURER);
 DECLARE_KEYMASTER_TAG(KM_BYTES, TAG_ATTESTATION_ID_MODEL);
+DECLARE_KEYMASTER_TAG(KM_BYTES, TAG_MODULE_HASH);
 DECLARE_KEYMASTER_TAG(KM_BOOL, TAG_EARLY_BOOT_ONLY);
 DECLARE_KEYMASTER_TAG(KM_BOOL, TAG_DEVICE_UNIQUE_ATTESTATION);
 DECLARE_KEYMASTER_TAG(KM_BOOL, TAG_IDENTITY_CREDENTIAL_KEY);
diff --git a/include/keymaster/km_openssl/attestation_record.h b/include/keymaster/km_openssl/attestation_record.h
index c66d44f..1d6e01c 100644
--- a/include/keymaster/km_openssl/attestation_record.h
+++ b/include/keymaster/km_openssl/attestation_record.h
@@ -122,6 +122,7 @@ typedef struct km_auth_list {
     ASN1_NULL* device_unique_attestation;
     ASN1_NULL* identity_credential_key;
     ASN1_OCTET_STRING* attestation_id_second_imei;
+    ASN1_OCTET_STRING* module_hash;
 } KM_AUTH_LIST;
 
 ASN1_SEQUENCE(KM_AUTH_LIST) = {
@@ -194,6 +195,7 @@ ASN1_SEQUENCE(KM_AUTH_LIST) = {
                  TAG_IDENTITY_CREDENTIAL_KEY.masked_tag()),
     ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_second_imei, ASN1_OCTET_STRING,
                  TAG_ATTESTATION_ID_SECOND_IMEI.masked_tag()),
+    ASN1_EXP_OPT(KM_AUTH_LIST, module_hash, ASN1_OCTET_STRING, TAG_MODULE_HASH.masked_tag()),
 } ASN1_SEQUENCE_END(KM_AUTH_LIST);
 DECLARE_ASN1_FUNCTIONS(KM_AUTH_LIST);
 
@@ -424,6 +426,8 @@ inline static uint32_t version_to_attestation_km_version(KmVersion version) {
         return 200;
     case KmVersion::KEYMINT_3:
         return 300;
+    case KmVersion::KEYMINT_4:
+        return 400;
     }
 }
 
@@ -449,6 +453,8 @@ inline static uint32_t version_to_attestation_version(KmVersion version) {
         return 200;
     case KmVersion::KEYMINT_3:
         return 300;
+    case KmVersion::KEYMINT_4:
+        return 400;
     }
 }
 
diff --git a/include/keymaster/km_version.h b/include/keymaster/km_version.h
index f1b96fd..39e03b8 100644
--- a/include/keymaster/km_version.h
+++ b/include/keymaster/km_version.h
@@ -33,6 +33,7 @@ enum class KmVersion : int {
     KEYMINT_1 = 100,
     KEYMINT_2 = 200,
     KEYMINT_3 = 300,
+    KEYMINT_4 = 400,
 };
 
 };  // namespace keymaster
diff --git a/key_blob_utils/software_keyblobs.cpp b/key_blob_utils/software_keyblobs.cpp
index 9874b0a..805c546 100644
--- a/key_blob_utils/software_keyblobs.cpp
+++ b/key_blob_utils/software_keyblobs.cpp
@@ -330,6 +330,7 @@ keymaster_error_t SetKeyBlobAuthorizations(const AuthorizationSet& key_descripti
         case KM_TAG_CERTIFICATE_NOT_AFTER:
         case KM_TAG_INCLUDE_UNIQUE_ID:
         case KM_TAG_RESET_SINCE_ID_ROTATION:
+        case KM_TAG_MODULE_HASH:
             break;
 
         // Everything else we just copy into sw_enforced, unless the KeyFactory has placed it in
diff --git a/km_openssl/attestation_record.cpp b/km_openssl/attestation_record.cpp
index 726b5ce..e1fecc9 100644
--- a/km_openssl/attestation_record.cpp
+++ b/km_openssl/attestation_record.cpp
@@ -692,6 +692,9 @@ keymaster_error_t build_auth_list(const AuthorizationSet& auth_list, KM_AUTH_LIS
         case KM_TAG_ATTESTATION_ID_MODEL:
             string_ptr = &record->attestation_id_model;
             break;
+        case KM_TAG_MODULE_HASH:
+            string_ptr = &record->module_hash;
+            break;
         }
 
         keymaster_tag_type_t type = keymaster_tag_get_type(entry.tag);
@@ -1414,6 +1417,12 @@ keymaster_error_t extract_auth_list(const KM_AUTH_LIST* record, AuthorizationSet
         return KM_ERROR_MEMORY_ALLOCATION_FAILED;
     }
 
+    // Module hash
+    if (record->module_hash && !auth_list->push_back(TAG_MODULE_HASH, record->module_hash->data,
+                                                     record->module_hash->length)) {
+        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
+    }
+
     return KM_ERROR_OK;
 }
 
diff --git a/ng/AndroidKeyMintDevice.cpp b/ng/AndroidKeyMintDevice.cpp
index fb7b632..d3c43fc 100644
--- a/ng/AndroidKeyMintDevice.cpp
+++ b/ng/AndroidKeyMintDevice.cpp
@@ -128,6 +128,7 @@ vector<KeyCharacteristics> convertKeyCharacteristics(SecurityLevel keyMintSecuri
         case KM_TAG_RESET_SINCE_ID_ROTATION:
         case KM_TAG_ROOT_OF_TRUST:
         case KM_TAG_UNIQUE_ID:
+        case KM_TAG_MODULE_HASH:
             break;
 
         /* KeyMint-enforced */
@@ -215,9 +216,9 @@ constexpr size_t kOperationTableSize = 16;
 
 AndroidKeyMintDevice::AndroidKeyMintDevice(SecurityLevel securityLevel)
     : impl_(new(std::nothrow)::keymaster::AndroidKeymaster(
-          [&]() -> auto{
+          [&]() -> auto {
               auto context = new (std::nothrow) PureSoftKeymasterContext(
-                  KmVersion::KEYMINT_3, static_cast<keymaster_security_level_t>(securityLevel));
+                  KmVersion::KEYMINT_4, static_cast<keymaster_security_level_t>(securityLevel));
               context->SetSystemVersion(::keymaster::GetOsVersion(),
                                         ::keymaster::GetOsPatchlevel());
               context->SetVendorPatchlevel(::keymaster::GetVendorPatchlevel());
@@ -242,7 +243,7 @@ AndroidKeyMintDevice::AndroidKeyMintDevice(SecurityLevel securityLevel)
 AndroidKeyMintDevice::~AndroidKeyMintDevice() {}
 
 ScopedAStatus AndroidKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info) {
-    info->versionNumber = 3;
+    info->versionNumber = 4;
     info->securityLevel = securityLevel_;
     info->keyMintName = "FakeKeyMintDevice";
     info->keyMintAuthorName = "Google";
@@ -493,6 +494,19 @@ ScopedAStatus AndroidKeyMintDevice::sendRootOfTrust(const vector<uint8_t>& /* ro
     return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
 }
 
+ScopedAStatus AndroidKeyMintDevice::setAdditionalAttestationInfo(const vector<KeyParameter>& info) {
+    SetAdditionalAttestationInfoRequest request(impl_->message_version());
+    request.info.Reinitialize(KmParamSet(info));
+
+    SetAdditionalAttestationInfoResponse response = impl_->SetAdditionalAttestationInfo(request);
+
+    if (response.error != KM_ERROR_OK) {
+        return kmError2ScopedAStatus(response.error);
+    } else {
+        return ScopedAStatus::ok();
+    }
+}
+
 std::shared_ptr<IKeyMintDevice> CreateKeyMintDevice(SecurityLevel securityLevel) {
     return ndk::SharedRefBase::make<AndroidKeyMintDevice>(securityLevel);
 }
diff --git a/ng/include/AndroidKeyMintDevice.h b/ng/include/AndroidKeyMintDevice.h
index 06557be..83caf9e 100644
--- a/ng/include/AndroidKeyMintDevice.h
+++ b/ng/include/AndroidKeyMintDevice.h
@@ -87,6 +87,9 @@ class AndroidKeyMintDevice : public BnKeyMintDevice {
                                  vector<uint8_t>* rootOfTrust) override;
     ScopedAStatus sendRootOfTrust(const vector<uint8_t>& rootOfTrust) override;
 
+    ScopedAStatus
+    setAdditionalAttestationInfo(const vector<KeyParameter>& additionalAttestationInfo) override;
+
     shared_ptr<::keymaster::AndroidKeymaster>& getKeymasterImpl() { return impl_; }
 
   protected:
```

