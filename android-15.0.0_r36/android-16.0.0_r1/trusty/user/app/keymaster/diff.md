```diff
diff --git a/OWNERS b/OWNERS
index f385cae..4fe39b0 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,9 +2,7 @@ armellel@google.com
 arve@android.com
 drysdale@google.com
 gmar@google.com
-marcone@google.com
 mmaurer@google.com
 ncbray@google.com
 swillden@google.com
-trong@google.com
 wenhaowang@google.com
diff --git a/trusty_keymaster_context.cpp b/trusty_keymaster_context.cpp
index 5eb7c05..ead093d 100644
--- a/trusty_keymaster_context.cpp
+++ b/trusty_keymaster_context.cpp
@@ -193,6 +193,7 @@ keymaster_error_t TrustyKeymasterContext::SetAuthorizations(
         case KM_TAG_ROOT_OF_TRUST:
         case KM_TAG_UNIQUE_ID:
         case KM_TAG_IDENTITY_CREDENTIAL_KEY:
+        case KM_TAG_MODULE_HASH:
             return KM_ERROR_INVALID_KEY_BLOB;
 
         // Tags used only to provide information for certificate creation, but
@@ -213,7 +214,6 @@ keymaster_error_t TrustyKeymasterContext::SetAuthorizations(
         case KM_TAG_CERTIFICATE_SERIAL:
         case KM_TAG_CERTIFICATE_SUBJECT:
         case KM_TAG_RESET_SINCE_ID_ROTATION:
-        case KM_TAG_MODULE_HASH:
             break;
 
         // Unimplemented tags for which we return an error.
@@ -331,11 +331,6 @@ keymaster_error_t TrustyKeymasterContext::SetAuthorizations(
     if (boot_patchlevel_.has_value()) {
         hw_enforced->push_back(TAG_BOOT_PATCHLEVEL, boot_patchlevel_.value());
     }
-    if (module_hash_.has_value()) {
-        keymaster_blob_t mod_hash = {module_hash_.value().data(),
-                                     module_hash_.value().size()};
-        sw_enforced->push_back(TAG_MODULE_HASH, mod_hash);
-    }
 
     if (sw_enforced->is_valid() != AuthorizationSet::OK)
         return TranslateAuthorizationSetError(sw_enforced->is_valid());
diff --git a/trusty_keymaster_context.h b/trusty_keymaster_context.h
index ecd3a77..0327674 100644
--- a/trusty_keymaster_context.h
+++ b/trusty_keymaster_context.h
@@ -198,6 +198,10 @@ public:
     keymaster_error_t SetModuleHash(
             const keymaster_blob_t& module_hash) override;
 
+    virtual std::optional<std::vector<uint8_t>> GetModuleHash() const override {
+        return module_hash_;
+    }
+
 private:
     bool SeedRngIfNeeded() const;
     bool ShouldReseedRng() const;
```

