```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..af5b598
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_keymaster",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/host_unittest/rules.mk b/host_unittest/rules.mk
index bd9817d..1795053 100644
--- a/host_unittest/rules.mk
+++ b/host_unittest/rules.mk
@@ -49,6 +49,9 @@ HOST_FLAGS := -Wpointer-arith \
 HOST_LIBS := \
 	stdc++ \
 
+HOST_DEPS := \
+	trusty/user/base/host/unittest \
+
 # These rules are used to force .pb.h file to be generated before compiling
 # these files.
 $(KEYMASTER_DIR)/secure_storage_manager.cpp: $(NANOPB_GENERATED_HEADER)
diff --git a/ipc/keymaster_ipc.cpp b/ipc/keymaster_ipc.cpp
index 9d1de9f..d713e0c 100644
--- a/ipc/keymaster_ipc.cpp
+++ b/ipc/keymaster_ipc.cpp
@@ -669,6 +669,12 @@ static long keymaster_dispatch_non_secure(keymaster_chan_ctx* ctx,
         return do_dispatch(&TrustyKeymaster::GetRootOfTrust, msg, payload_size,
                            out, out_size);
 
+    case KM_SET_ADDITIONAL_ATTESTATION_INFO:
+        LOG_D("Dispatching KM_SET_ADDITIONAL_ATTESTATION_INFO, size %d",
+              payload_size);
+        return do_dispatch(&TrustyKeymaster::SetAdditionalAttestationInfo, msg,
+                           payload_size, out, out_size);
+
     case KM_GET_HW_INFO:
         LOG_D("Dispatching KM_GET_HW_INFO, size %d", payload_size);
         return do_dispatch(&TrustyKeymaster::GetHwInfo, msg, payload_size, out,
diff --git a/ipc/keymaster_ipc.h b/ipc/keymaster_ipc.h
index 00e35c4..82d3f44 100644
--- a/ipc/keymaster_ipc.h
+++ b/ipc/keymaster_ipc.h
@@ -62,6 +62,7 @@ enum keymaster_command : uint32_t {
     KM_GET_ROOT_OF_TRUST = (34 << KEYMASTER_REQ_SHIFT),
     KM_GET_HW_INFO = (35 << KEYMASTER_REQ_SHIFT),
     KM_GENERATE_CSR_V2 = (36 << KEYMASTER_REQ_SHIFT),
+    KM_SET_ADDITIONAL_ATTESTATION_INFO = (37 << KEYMASTER_REQ_SHIFT),
 
     // Bootloader calls.
     KM_SET_BOOT_PARAMS = (0x1000 << KEYMASTER_REQ_SHIFT),
diff --git a/trusty_keymaster.cpp b/trusty_keymaster.cpp
index 309fdb1..10603c5 100644
--- a/trusty_keymaster.cpp
+++ b/trusty_keymaster.cpp
@@ -32,7 +32,7 @@ GetVersion2Response TrustyKeymaster::GetVersion2(
         break;
 
     case 4:
-        context_->SetKmVersion(KmVersion::KEYMINT_3);
+        context_->SetKmVersion(KmVersion::KEYMINT_4);
         break;
 
     default:
diff --git a/trusty_keymaster_context.cpp b/trusty_keymaster_context.cpp
index 70ac6d8..5eb7c05 100644
--- a/trusty_keymaster_context.cpp
+++ b/trusty_keymaster_context.cpp
@@ -213,6 +213,7 @@ keymaster_error_t TrustyKeymasterContext::SetAuthorizations(
         case KM_TAG_CERTIFICATE_SERIAL:
         case KM_TAG_CERTIFICATE_SUBJECT:
         case KM_TAG_RESET_SINCE_ID_ROTATION:
+        case KM_TAG_MODULE_HASH:
             break;
 
         // Unimplemented tags for which we return an error.
@@ -330,6 +331,11 @@ keymaster_error_t TrustyKeymasterContext::SetAuthorizations(
     if (boot_patchlevel_.has_value()) {
         hw_enforced->push_back(TAG_BOOT_PATCHLEVEL, boot_patchlevel_.value());
     }
+    if (module_hash_.has_value()) {
+        keymaster_blob_t mod_hash = {module_hash_.value().data(),
+                                     module_hash_.value().size()};
+        sw_enforced->push_back(TAG_MODULE_HASH, mod_hash);
+    }
 
     if (sw_enforced->is_valid() != AuthorizationSet::OK)
         return TranslateAuthorizationSetError(sw_enforced->is_valid());
@@ -759,6 +765,24 @@ keymaster_error_t TrustyKeymasterContext::AddRngEntropy(const uint8_t* buf,
     return KM_ERROR_OK;
 }
 
+keymaster_error_t TrustyKeymasterContext::SetModuleHash(
+        const keymaster_blob_t& mod_hash) {
+    std::vector<uint8_t> module_hash(mod_hash.data,
+                                     mod_hash.data + mod_hash.data_length);
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
 bool TrustyKeymasterContext::SeedRngIfNeeded() const {
     if (ShouldReseedRng())
         const_cast<TrustyKeymasterContext*>(this)->ReseedRng();
diff --git a/trusty_keymaster_context.h b/trusty_keymaster_context.h
index 677ad4f..ecd3a77 100644
--- a/trusty_keymaster_context.h
+++ b/trusty_keymaster_context.h
@@ -195,6 +195,9 @@ public:
         return boot_patchlevel_;
     }
 
+    keymaster_error_t SetModuleHash(
+            const keymaster_blob_t& module_hash) override;
+
 private:
     bool SeedRngIfNeeded() const;
     bool ShouldReseedRng() const;
@@ -257,6 +260,7 @@ private:
             trusty_remote_provisioning_context_;
     std::optional<uint32_t> vendor_patchlevel_;
     std::optional<uint32_t> boot_patchlevel_;
+    std::optional<std::vector<uint8_t>> module_hash_;
     mutable std::vector<uint8_t> unique_id_hbk_;
 };
 
```

