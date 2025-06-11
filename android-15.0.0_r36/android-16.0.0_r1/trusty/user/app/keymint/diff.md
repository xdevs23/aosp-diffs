```diff
diff --git a/OWNERS b/OWNERS
index 602bcb1..8386ad4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,9 +2,7 @@ armellel@google.com
 arve@android.com
 drysdale@google.com
 hasinitg@google.com
-marcone@google.com
 mmaurer@google.com
 ncbray@google.com
 oarbildo@google.com
 thurston@google.com
-trong@google.com
diff --git a/keymaster_attributes.rs b/keymaster_attributes.rs
index c71c8a2..19336a3 100644
--- a/keymaster_attributes.rs
+++ b/keymaster_attributes.rs
@@ -10,7 +10,6 @@
 #![allow(unused_attributes)]
 #![cfg_attr(rustfmt, rustfmt::skip)]
 
-#![allow(box_pointers)]
 #![allow(dead_code)]
 #![allow(missing_docs)]
 #![allow(non_camel_case_types)]
diff --git a/lib.rs b/lib.rs
index f31dbf7..a5f006a 100644
--- a/lib.rs
+++ b/lib.rs
@@ -21,6 +21,8 @@ mod ffi_bindings;
 mod ipc_manager;
 mod key_wrapper;
 mod keybox;
+// Trusty should not lint generated code
+#[allow(warnings)]
 mod keymaster_attributes;
 mod keys;
 mod monotonic_clock;
diff --git a/rules.mk b/rules.mk
index 617ce04..a23f252 100644
--- a/rules.mk
+++ b/rules.mk
@@ -33,22 +33,13 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/keymint-rust/common \
 	trusty/user/base/lib/keymint-rust/ta \
 	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,protobuf) \
 	trusty/user/base/lib/storage/rust \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/system_state/rust \
 	trusty/user/base/lib/trusty-log \
 	trusty/user/base/lib/trusty-std \
 
-# Special case discovery of the path to the right protobuf crate
-# since the way older versions are located changed with the switch
-# to the rust crate monorepo. This can be simplified to just use
-# `FIND_CRATE` once all Trusty manifests use the monorepo.
-ifneq ($(wildcard external/rust/crates/protobuf/2.27.1/rules.mk),)
-MODULE_LIBRARY_DEPS += external/rust/crates/protobuf/2.27.1
-else
-MODULE_LIBRARY_DEPS += $(call FIND_CRATE,protobuf)
-endif
-
 ifdef TRUSTY_KM_RUST_ACCESS_POLICY
     MODULE_LIBRARY_DEPS+= $(TRUSTY_KM_RUST_ACCESS_POLICY)
 else
diff --git a/secure_deletion_secret_manager.rs b/secure_deletion_secret_manager.rs
index 24df232..2021afe 100644
--- a/secure_deletion_secret_manager.rs
+++ b/secure_deletion_secret_manager.rs
@@ -289,7 +289,7 @@ impl TrustySecureDeletionSecretManager {
     fn get_factory_reset_secret_impl<'a>(
         &'a self,
         session: Option<&'a mut Session>,
-    ) -> Result<RetrieveSecureDeletionSecretFileData, Error> {
+    ) -> Result<RetrieveSecureDeletionSecretFileData<'a>, Error> {
         // Checking if we already have a cached secret we can return
         if let Some(secret) = self.factory_reset_secret.borrow_mut().deref_mut() {
             return Ok(RetrieveSecureDeletionSecretFileData::CachedDataFound(SecureDeletionData {
```

