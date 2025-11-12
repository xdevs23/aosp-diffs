```diff
diff --git a/ta/src/lib.rs b/ta/src/lib.rs
index a0efe49..4687fe3 100644
--- a/ta/src/lib.rs
+++ b/ta/src/lib.rs
@@ -24,7 +24,7 @@ use alloc::{
 use core::cmp::Ordering;
 use core::mem::size_of;
 use core::{cell::RefCell, convert::TryFrom};
-use device::DiceInfo;
+use device::{DiceInfo, RetrieveCertSigningInfo};
 use kmr_common::{
     crypto::{self, hmac, OpaqueOr},
     get_bool_tag_value,
@@ -373,7 +373,10 @@ impl KeyMintTa {
     /// hashed (if necessary).
     fn boot_info_hashed_key(&self) -> Result<keymint::BootInfo, Error> {
         let mut boot_info = self.boot_info()?.clone();
-        if boot_info.verified_boot_key.len() > 32 {
+        if boot_info.verified_boot_key.is_empty() {
+            // Expand an empty VB key to all-zeroes.
+            boot_info.verified_boot_key = vec_try![0u8; 32]?;
+        } else if boot_info.verified_boot_key.len() > 32 {
             // It looks like we have the actual key, not a hash thereof.  Change that.
             boot_info.verified_boot_key =
                 try_to_vec(&self.imp.sha256.hash(&boot_info.verified_boot_key)?)?;
@@ -662,6 +665,17 @@ impl KeyMintTa {
         self.attestation_id_info.borrow().as_ref().cloned()
     }
 
+    /// Allow an implementation of the [`RetrieveCertSigningInfo`] trait to be provided
+    /// after TA startup.
+    pub fn set_sign_info(&mut self, sign_info: Option<Box<dyn RetrieveCertSigningInfo>>) {
+        if self.dev.sign_info.is_some() {
+            error!("Attempt to set attestation sign info when already set");
+        } else {
+            warn!("Setting attestation sign info after startup");
+            self.dev.sign_info = sign_info;
+        }
+    }
+
     /// Retrieve the DICE info for the device, if available.
     fn get_dice_info(&self) -> Option<Rc<DiceInfo>> {
         if self.dice_info.borrow().is_none() {
```

