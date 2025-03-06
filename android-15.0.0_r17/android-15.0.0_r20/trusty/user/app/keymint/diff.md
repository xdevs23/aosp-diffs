```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..7dfe910
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_keymint",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/app/rules.mk b/app/rules.mk
index f2fd732..888595d 100644
--- a/app/rules.mk
+++ b/app/rules.mk
@@ -46,6 +46,11 @@ MODULE_RUSTFLAGS += \
 	--cfg 'feature="with_hwwsk_support"'
 endif
 
+ifeq ($(KEYMINT_TRUSTY_VM),nonsecure)
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="vm_nonsecure"'
+endif
+
 MODULE_RUST_USE_CLIPPY := true
 
 include make/trusted_app.mk
diff --git a/main.rs b/main.rs
index 1d5f052..f726cab 100644
--- a/main.rs
+++ b/main.rs
@@ -17,8 +17,8 @@
 //! Main entrypoint for KeyMint/Rust trusted application (TA) on Trusty.
 
 use keymint::{
-    AttestationIds, CertSignInfo, SharedSddManager, TrustyKeys, TrustyMonotonicClock, TrustyRng,
-    TrustyRpc, TrustySecureDeletionSecretManager,
+    CertSignInfo, SharedSddManager, TrustyKeys, TrustyMonotonicClock, TrustyRng, TrustyRpc,
+    TrustySecureDeletionSecretManager,
 };
 
 #[cfg(feature = "with_hwwsk_support")]
@@ -93,7 +93,10 @@ fn main() {
     let dev = kmr_ta::device::Implementation {
         keys: Box::new(TrustyKeys),
         sign_info: Some(Box::new(CertSignInfo)),
-        attest_ids: Some(Box::new(AttestationIds)),
+        #[cfg(feature = "vm_nonsecure")]
+        attest_ids: None,
+        #[cfg(not(feature = "vm_nonsecure"))]
+        attest_ids: Some(Box::new(keymint::AttestationIds)),
         sdd_mgr: Some(Box::new(shared_sdd_mgr)),
         bootloader: Box::new(kmr_ta::device::BootloaderDone),
         #[cfg(feature = "with_hwwsk_support")]
diff --git a/rules.mk b/rules.mk
index 0a0b91a..617ce04 100644
--- a/rules.mk
+++ b/rules.mk
@@ -33,13 +33,22 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/keymint-rust/common \
 	trusty/user/base/lib/keymint-rust/ta \
 	$(call FIND_CRATE,log) \
-	$(call FIND_CRATE,protobuf)/2.27.1 \
 	trusty/user/base/lib/storage/rust \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/system_state/rust \
 	trusty/user/base/lib/trusty-log \
 	trusty/user/base/lib/trusty-std \
 
+# Special case discovery of the path to the right protobuf crate
+# since the way older versions are located changed with the switch
+# to the rust crate monorepo. This can be simplified to just use
+# `FIND_CRATE` once all Trusty manifests use the monorepo.
+ifneq ($(wildcard external/rust/crates/protobuf/2.27.1/rules.mk),)
+MODULE_LIBRARY_DEPS += external/rust/crates/protobuf/2.27.1
+else
+MODULE_LIBRARY_DEPS += $(call FIND_CRATE,protobuf)
+endif
+
 ifdef TRUSTY_KM_RUST_ACCESS_POLICY
     MODULE_LIBRARY_DEPS+= $(TRUSTY_KM_RUST_ACCESS_POLICY)
 else
```

