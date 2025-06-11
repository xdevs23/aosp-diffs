```diff
diff --git a/OWNERS b/OWNERS
index ad485c0..9445e75 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,5 @@
 drysdale@google.com
 jbires@google.com
-jdanis@google.com
 sethmo@google.com
 swillden@google.com
 zeuthen@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be..c8dbf77 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -3,6 +3,3 @@ clang_format = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
-
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/android_keymaster/android_keymaster_messages.cpp b/android_keymaster/android_keymaster_messages.cpp
index 065c985..520ac22 100644
--- a/android_keymaster/android_keymaster_messages.cpp
+++ b/android_keymaster/android_keymaster_messages.cpp
@@ -704,18 +704,23 @@ size_t GetVersionResponse::NonErrorSerializedSize() const {
 }
 
 uint8_t* GetVersionResponse::NonErrorSerialize(uint8_t* buf, const uint8_t* end) const {
-    if (buf + NonErrorSerializedSize() <= end) {
-        *buf++ = major_ver;
-        *buf++ = minor_ver;
-        *buf++ = subminor_ver;
-    } else {
-        buf += NonErrorSerializedSize();
+    ptrdiff_t buf_size = end - buf;
+    if (buf_size < static_cast<ptrdiff_t>(NonErrorSerializedSize())) {
+        // Not enough space in buffer; return pointer to the end of buffer.
+        return buf + buf_size;
     }
+
+    *buf++ = major_ver;
+    *buf++ = minor_ver;
+    *buf++ = subminor_ver;
+
     return buf;
 }
 
 bool GetVersionResponse::NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) {
-    if (*buf_ptr + NonErrorSerializedSize() > end) return false;
+    if (!(*buf_ptr) || ((end - *buf_ptr) < static_cast<ptrdiff_t>(NonErrorSerializedSize()))) {
+        return false;
+    }
     const uint8_t* tmp = *buf_ptr;
     major_ver = *tmp++;
     minor_ver = *tmp++;
diff --git a/android_keymaster/android_keymaster_utils.cpp b/android_keymaster/android_keymaster_utils.cpp
index 5a07424..88d73de 100644
--- a/android_keymaster/android_keymaster_utils.cpp
+++ b/android_keymaster/android_keymaster_utils.cpp
@@ -27,7 +27,7 @@ const size_t kMaxDupBufferSize = 16 * 1024 * 1024;
 uint8_t* dup_buffer(const void* buf, size_t size) {
     if (size >= kMaxDupBufferSize) return nullptr;
     uint8_t* retval = new (std::nothrow) uint8_t[size];
-    if (retval) memcpy(retval, buf, size);
+    if (retval && buf) memcpy(retval, buf, size);
     return retval;
 }
 
diff --git a/android_keymaster/authorization_set.cpp b/android_keymaster/authorization_set.cpp
index 819ffed..7d17924 100644
--- a/android_keymaster/authorization_set.cpp
+++ b/android_keymaster/authorization_set.cpp
@@ -68,7 +68,9 @@ bool AuthorizationSet::reserve_elems(size_t count) {
             set_invalid(ALLOCATION_FAILURE);
             return false;
         }
-        memcpy(new_elems, elems_, sizeof(*elems_) * elems_size_);
+        if (elems_size_ > 0) {
+            memcpy(new_elems, elems_, sizeof(*elems_) * elems_size_);
+        }
         delete[] elems_;
         elems_ = new_elems;
         elems_capacity_ = count;
@@ -85,7 +87,9 @@ bool AuthorizationSet::reserve_indirect(size_t length) {
             set_invalid(ALLOCATION_FAILURE);
             return false;
         }
-        memcpy(new_data, indirect_data_, indirect_data_size_);
+        if (indirect_data_size_ > 0) {
+            memcpy(new_data, indirect_data_, indirect_data_size_);
+        }
 
         // Fix up the data pointers to point into the new region.
         for (size_t i = 0; i < elems_size_; ++i) {
diff --git a/android_keymaster/serializable.cpp b/android_keymaster/serializable.cpp
index 9820c24..eedbaf2 100644
--- a/android_keymaster/serializable.cpp
+++ b/android_keymaster/serializable.cpp
@@ -90,6 +90,7 @@ bool Buffer::Reinitialize(size_t size) {
     Clear();
     buffer_.reset(new (std::nothrow) uint8_t[size]);
     if (!buffer_.get()) return false;
+
     buffer_size_ = size;
     read_position_ = 0;
     write_position_ = 0;
@@ -98,12 +99,19 @@ bool Buffer::Reinitialize(size_t size) {
 
 bool Buffer::Reinitialize(const void* data, size_t data_len) {
     Clear();
-    if (__pval(data) + data_len < __pval(data))  // Pointer wrap check
+    uintptr_t data_end;
+    // Check for pointer overflow
+    if (__builtin_add_overflow(__pval(data), data_len, &data_end)) {
         return false;
+    }
+
     buffer_.reset(new (std::nothrow) uint8_t[data_len]);
     if (!buffer_.get()) return false;
+    if (data_len) {
+        memcpy(buffer_.get(), data, data_len);
+    }
+
     buffer_size_ = data_len;
-    memcpy(buffer_.get(), data, data_len);
     read_position_ = 0;
     write_position_ = buffer_size_;
     return true;
diff --git a/contexts/pure_soft_keymaster_context.cpp b/contexts/pure_soft_keymaster_context.cpp
index 296152d..f9ba15b 100644
--- a/contexts/pure_soft_keymaster_context.cpp
+++ b/contexts/pure_soft_keymaster_context.cpp
@@ -261,10 +261,6 @@ keymaster_error_t PureSoftKeymasterContext::CreateKeyBlob(const AuthorizationSet
     error =
         ExtendKeyBlobAuthorizations(hw_enforced, sw_enforced, vendor_patchlevel_, boot_patchlevel_);
     if (error != KM_ERROR_OK) return error;
-    if (module_hash_.has_value()) {
-        keymaster_blob_t mod_hash = {module_hash_.value().data(), module_hash_.value().size()};
-        sw_enforced->push_back(TAG_MODULE_HASH, mod_hash);
-    }
 
     AuthorizationSet hidden;
     error = BuildHiddenAuthorizations(key_description, &hidden, softwareRootOfTrust);
diff --git a/contexts/soft_keymaster_context.cpp b/contexts/soft_keymaster_context.cpp
index 0dc6030..246cee9 100644
--- a/contexts/soft_keymaster_context.cpp
+++ b/contexts/soft_keymaster_context.cpp
@@ -114,7 +114,7 @@ KeyFactory* SoftKeymasterContext::GetKeyFactory(keymaster_algorithm_t algorithm)
 static keymaster_algorithm_t supported_algorithms[] = {KM_ALGORITHM_RSA, KM_ALGORITHM_EC,
                                                        KM_ALGORITHM_AES, KM_ALGORITHM_HMAC};
 
-keymaster_algorithm_t*
+const keymaster_algorithm_t*
 SoftKeymasterContext::GetSupportedAlgorithms(size_t* algorithms_count) const {
     *algorithms_count = array_length(supported_algorithms);
     return supported_algorithms;
diff --git a/include/keymaster/attestation_context.h b/include/keymaster/attestation_context.h
index 6d2887d..1889ae0 100644
--- a/include/keymaster/attestation_context.h
+++ b/include/keymaster/attestation_context.h
@@ -16,6 +16,9 @@
 
 #pragma once
 
+#include <optional>
+#include <vector>
+
 #include <keymaster/authorization_set.h>
 #include <keymaster/km_version.h>
 
@@ -98,6 +101,11 @@ class AttestationContext {
     virtual CertificateChain GetAttestationChain(keymaster_algorithm_t algorithm,
                                                  keymaster_error_t* error) const = 0;
 
+    /**
+     * Return the current module hash value to be included in the attestation extension.
+     */
+    virtual std::optional<std::vector<uint8_t>> GetModuleHash() const { return std::nullopt; }
+
   protected:
     KmVersion version_;
 };
diff --git a/include/keymaster/contexts/pure_soft_keymaster_context.h b/include/keymaster/contexts/pure_soft_keymaster_context.h
index 038827c..136e9ff 100644
--- a/include/keymaster/contexts/pure_soft_keymaster_context.h
+++ b/include/keymaster/contexts/pure_soft_keymaster_context.h
@@ -108,6 +108,13 @@ class PureSoftKeymasterContext : public KeymasterContext,
 
     keymaster_error_t SetModuleHash(const keymaster_blob_t& module_hash) override;
 
+    /*********************************************************************************************
+     * Implement AttestationContext
+     */
+    virtual std::optional<std::vector<uint8_t>> GetModuleHash() const override {
+        return module_hash_;
+    }
+
     /*********************************************************************************************
      * Implement SoftwareKeyBlobMaker
      */
diff --git a/include/keymaster/contexts/soft_keymaster_context.h b/include/keymaster/contexts/soft_keymaster_context.h
index aae0542..73c39c2 100644
--- a/include/keymaster/contexts/soft_keymaster_context.h
+++ b/include/keymaster/contexts/soft_keymaster_context.h
@@ -67,7 +67,7 @@ class SoftKeymasterContext : public KeymasterContext,
     KeyFactory* GetKeyFactory(keymaster_algorithm_t algorithm) const override;
     OperationFactory* GetOperationFactory(keymaster_algorithm_t algorithm,
                                           keymaster_purpose_t purpose) const override;
-    keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
+    const keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
     keymaster_error_t UpgradeKeyBlob(const KeymasterKeyBlob& key_to_upgrade,
                                      const AuthorizationSet& upgrade_params,
                                      KeymasterKeyBlob* upgraded_key) const override;
diff --git a/include/keymaster/cppcose/cppcose.h b/include/keymaster/cppcose/cppcose.h
index fa5916f..707c2b9 100644
--- a/include/keymaster/cppcose/cppcose.h
+++ b/include/keymaster/cppcose/cppcose.h
@@ -99,6 +99,8 @@ template <typename T> class ErrMsgOr {
         : errMsg_(std::move(errMsg)) {}
     ErrMsgOr(const char* errMsg)  // NOLINT(google-explicit-constructor)
         : errMsg_(errMsg) {}
+    ErrMsgOr(std::string_view errMsg)  // NOLINT(google-explicit-constructor)
+        : errMsg_(errMsg) {}
     ErrMsgOr(T val)  // NOLINT(google-explicit-constructor)
         : value_(std::move(val)) {}
 
diff --git a/include/keymaster/key_factory.h b/include/keymaster/key_factory.h
index ad9e161..1373eff 100644
--- a/include/keymaster/key_factory.h
+++ b/include/keymaster/key_factory.h
@@ -18,12 +18,12 @@
 
 #include <hardware/keymaster_defs.h>
 #include <keymaster/authorization_set.h>
+#include <keymaster/operation.h>
 
 namespace keymaster {
 
 class Key;
 class KeymasterContext;
-class OperationFactory;
 template <typename BlobType> struct TKeymasterBlob;
 typedef TKeymasterBlob<keymaster_key_blob_t> KeymasterKeyBlob;
 
diff --git a/key_blob_utils/integrity_assured_key_blob.cpp b/key_blob_utils/integrity_assured_key_blob.cpp
index 11d9cf2..7b16977 100644
--- a/key_blob_utils/integrity_assured_key_blob.cpp
+++ b/key_blob_utils/integrity_assured_key_blob.cpp
@@ -102,7 +102,7 @@ keymaster_error_t DeserializeIntegrityAssuredBlob(const KeymasterKeyBlob& key_bl
     const uint8_t* p = key_blob.begin();
     const uint8_t* end = key_blob.end();
 
-    if (p > end || p + HMAC_SIZE > end) return KM_ERROR_INVALID_KEY_BLOB;
+    if (p > end || end - p < HMAC_SIZE) return KM_ERROR_INVALID_KEY_BLOB;
 
     uint8_t computed_hmac[HMAC_SIZE];
     keymaster_error_t error = ComputeHmac(key_blob.begin(), key_blob.key_material_size - HMAC_SIZE,
@@ -121,9 +121,10 @@ keymaster_error_t DeserializeIntegrityAssuredBlob_NoHmacCheck(const KeymasterKey
                                                               AuthorizationSet* hw_enforced,
                                                               AuthorizationSet* sw_enforced) {
     const uint8_t* p = key_blob.begin();
-    const uint8_t* end = key_blob.end() - HMAC_SIZE;
+    const uint8_t* end = key_blob.end();
 
-    if (p > end) return KM_ERROR_INVALID_KEY_BLOB;
+    if (p > end || end - p < HMAC_SIZE) return KM_ERROR_INVALID_KEY_BLOB;
+    end -= HMAC_SIZE;
 
     if (*p != BLOB_VERSION) return KM_ERROR_INVALID_KEY_BLOB;
     ++p;
diff --git a/km_openssl/attestation_record.cpp b/km_openssl/attestation_record.cpp
index e1fecc9..b8cf5c5 100644
--- a/km_openssl/attestation_record.cpp
+++ b/km_openssl/attestation_record.cpp
@@ -1057,6 +1057,15 @@ keymaster_error_t build_attestation_record(const AuthorizationSet& attestation_p
     }
     sw_enforced.push_back(TAG_ATTESTATION_APPLICATION_ID, attestation_app_id);
 
+    auto module_hash = context.GetModuleHash();
+    if (module_hash.has_value()) {
+        // If the attestation context provides a module hash value, include it in the
+        // software-enforced part of the extension (because it will not be included as a key
+        // characteristic).
+        keymaster_blob_t mod_hash = {module_hash.value().data(), module_hash.value().size()};
+        sw_enforced.push_back(TAG_MODULE_HASH, mod_hash);
+    }
+
     error = context.VerifyAndCopyDeviceIds(
         attestation_params,
         context.GetSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE ? &sw_enforced : &tee_enforced);
```

