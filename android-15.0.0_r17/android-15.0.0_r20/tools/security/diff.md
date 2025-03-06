```diff
diff --git a/OWNERS b/OWNERS
index a9d0762..af3169f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1,7 @@
 # Code owners for various security-related things on Android.
 
 # Sanitizers
-mitchp@google.com
+pcc@google.com
 eugenis@google.com
 fmayer@google.com
 
diff --git a/fuzzing/orphans/OWNERS b/fuzzing/orphans/OWNERS
index 1913c00..1036c55 100644
--- a/fuzzing/orphans/OWNERS
+++ b/fuzzing/orphans/OWNERS
@@ -1,4 +1,3 @@
 hamzeh@google.com
 kalder@google.com
-mitchp@google.com
 mspector@google.com
diff --git a/remote_provisioning/hwtrust/Android.bp b/remote_provisioning/hwtrust/Android.bp
index a42bc27..94ad177 100644
--- a/remote_provisioning/hwtrust/Android.bp
+++ b/remote_provisioning/hwtrust/Android.bp
@@ -10,6 +10,7 @@ rust_defaults {
         "libanyhow",
         "libbase64_rust",
         "libciborium",
+        "libclap",
         "libcoset",
         "libhex",
         "libitertools",
@@ -19,6 +20,8 @@ rust_defaults {
     target: {
         host: {
             rlibs: ["libopenssl_static"],
+            // dylib is disabled due to compile failure in libhwtrust. See b/373621186 for details.
+            dylib: { enabled: false, },
         },
         android: {
             rustlibs: ["libopenssl"],
@@ -30,6 +33,7 @@ rust_library {
     name: "libhwtrust",
     defaults: ["libhwtrust_defaults"],
     crate_name: "hwtrust",
+    product_available: true,
     vendor_available: true,
     apex_available: [
         "//apex_available:platform",
diff --git a/remote_provisioning/hwtrust/OWNERS b/remote_provisioning/hwtrust/OWNERS
index 9fc3bb1..4994d47 100644
--- a/remote_provisioning/hwtrust/OWNERS
+++ b/remote_provisioning/hwtrust/OWNERS
@@ -1,4 +1,4 @@
 asbel@google.com
 hasinitg@google.com
-alanstokes@google.com
+aliceywang@google.com
 ascull@google.com
diff --git a/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp b/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
index 7439bb2..fa0adbf 100644
--- a/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
+++ b/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
@@ -6,45 +6,67 @@ using android::base::Result;
 
 namespace hwtrust {
 
-struct BoxedDiceChain {
-    ::rust::Box<rust::DiceChain> chain;
+rust::DiceChainKind convertKind(DiceChain::Kind kind) {
+  switch (kind) {
+    case DiceChain::Kind::kVsr13:
+      return rust::DiceChainKind::Vsr13;
+    case DiceChain::Kind::kVsr14:
+      return rust::DiceChainKind::Vsr14;
+    case DiceChain::Kind::kVsr15:
+      return rust::DiceChainKind::Vsr15;
+    case DiceChain::Kind::kVsr16:
+      return rust::DiceChainKind::Vsr16;
+  }
+}
+
+// The public API hides all rust deps from clients, so we end up with opaque, boxed types. This
+// class standardizes the syntax for dealing with these types. How to...
+// ...define a boxed opaque type:     struct BoxedFoo : Boxed<Foo, BoxedFoo> {};
+// ...construct an object:            auto foo = BoxedFoo::moveFrom(boxed);
+// ...dereference the inner object:   **foo;
+template <typename BoxedT, typename DerivedT>
+class Boxed {
+public:
+  Boxed(::rust::Box<BoxedT> b) : box_(std::move(b)) {}
+
+  static std::unique_ptr<DerivedT> moveFrom(::rust::Box<BoxedT>& b) {
+    return std::make_unique<DerivedT>(std::move(b));
+  }
+
+  const BoxedT &operator*() const noexcept { return *box_; }
+  BoxedT &operator*() noexcept { return *box_; }
+
+private:
+  ::rust::Box<BoxedT> box_;
 };
 
-// Define with a full definition of BoxedDiceChain to satisfy unique_ptr.
+// Definition of the forward-declared boxed types.
+struct BoxedDiceChain : Boxed<rust::DiceChain, BoxedDiceChain> {};
+struct BoxedCsr : Boxed<rust::Csr, BoxedCsr> {};
+
+
+// Define to satisfy unique_ptr.
 DiceChain::~DiceChain() {}
 
 DiceChain::DiceChain(std::unique_ptr<BoxedDiceChain> chain, size_t size) noexcept
       : chain_(std::move(chain)), size_(size) {}
 
-Result<DiceChain> DiceChain::Verify(const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode) noexcept {
-  rust::DiceChainKind chainKind;
-  switch (kind) {
-    case DiceChain::Kind::kVsr13:
-      chainKind = rust::DiceChainKind::Vsr13;
-      break;
-    case DiceChain::Kind::kVsr14:
-      chainKind = rust::DiceChainKind::Vsr14;
-      break;
-    case DiceChain::Kind::kVsr15:
-      chainKind = rust::DiceChainKind::Vsr15;
-      break;
-    case DiceChain::Kind::kVsr16:
-      chainKind = rust::DiceChainKind::Vsr16;
-      break;
-  }
-  auto res = rust::VerifyDiceChain({chain.data(), chain.size()}, chainKind, allow_any_mode);
+Result<DiceChain> DiceChain::Verify(
+  const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode,
+  std::string_view instance) noexcept {
+  rust::DiceChainKind chainKind = convertKind(kind);
+  auto res = rust::VerifyDiceChain(
+    {chain.data(), chain.size()}, chainKind, allow_any_mode, instance.data());
   if (!res.error.empty()) {
       return Error() << static_cast<std::string>(res.error);
   }
-  BoxedDiceChain boxedChain = { std::move(res.chain) };
-  auto diceChain = std::make_unique<BoxedDiceChain>(std::move(boxedChain));
-  return DiceChain(std::move(diceChain), res.len);
+  return DiceChain(BoxedDiceChain::moveFrom(res.chain), res.len);
 }
 
 Result<std::vector<std::vector<uint8_t>>> DiceChain::CosePublicKeys() const noexcept {
   std::vector<std::vector<uint8_t>> result;
   for (auto i = 0; i < size_; ++i) {
-    auto key = rust::GetDiceChainPublicKey(*chain_->chain, i);
+    auto key = rust::GetDiceChainPublicKey(**chain_, i);
     if (key.empty()) {
       return Error() << "Failed to get public key from chain entry " << i;
     }
@@ -54,7 +76,32 @@ Result<std::vector<std::vector<uint8_t>>> DiceChain::CosePublicKeys() const noex
 }
 
 bool DiceChain::IsProper() const noexcept {
-  return rust::IsDiceChainProper(*chain_->chain);
+  return rust::IsDiceChainProper(**chain_);
+}
+
+// Define with a full definition of BoxedCsr to satisfy unique_ptr.
+Csr::~Csr() {}
+
+Csr::Csr(std::unique_ptr<BoxedCsr> csr, DiceChain::Kind kind, std::string_view instance) noexcept
+    : mCsr(std::move(csr)), mKind(kind), mInstance(instance.data()) {}
+
+Result<Csr> Csr::validate(const std::vector<uint8_t>& request, DiceChain::Kind kind, bool allowAnyMode,
+    std::string_view instance) noexcept {
+    rust::DiceChainKind chainKind = convertKind(kind);
+    auto result = rust::validateCsr(
+        {request.data(), request.size()}, chainKind, allowAnyMode, instance.data());
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+    return Csr(BoxedCsr::moveFrom(result.csr), kind, instance);
+}
+
+Result<DiceChain> Csr::getDiceChain() const noexcept {
+    auto result = rust::getDiceChainFromCsr(**mCsr);
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+  return DiceChain(BoxedDiceChain::moveFrom(result.chain), result.len);
 }
 
 } // namespace hwtrust
diff --git a/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h b/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
index 8e999a3..480d2e9 100644
--- a/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
+++ b/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
@@ -5,13 +5,20 @@
 
 #include <android-base/result.h>
 
+using android::base::Error;
+using android::base::Result;
+
 namespace hwtrust {
 
+class Csr;
+
 // Hide the details of the rust binding from clients with an opaque type.
 struct BoxedDiceChain;
 
 class DiceChain final {
 public:
+  friend Csr;
+
   enum class Kind {
     kVsr13,
     kVsr14,
@@ -19,12 +26,14 @@ public:
     kVsr16,
   };
 
-  static android::base::Result<DiceChain> Verify(const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode) noexcept;
+  static Result<DiceChain> Verify(
+    const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode,
+    std::string_view instance) noexcept;
 
   ~DiceChain();
   DiceChain(DiceChain&&) = default;
 
-  android::base::Result<std::vector<std::vector<uint8_t>>> CosePublicKeys() const noexcept;
+  Result<std::vector<std::vector<uint8_t>>> CosePublicKeys() const noexcept;
 
   bool IsProper() const noexcept;
 
@@ -35,4 +44,24 @@ private:
   size_t size_;
 };
 
+struct BoxedCsr;
+
+class Csr final {
+public:
+  static Result<Csr> validate(const std::vector<uint8_t>& csr, DiceChain::Kind kind,
+    bool allowAnyMode, std::string_view instance) noexcept;
+
+  ~Csr();
+  Csr(Csr&&) = default;
+
+  Result<DiceChain> getDiceChain() const noexcept;
+
+  private:
+    Csr(std::unique_ptr<BoxedCsr> csr, DiceChain::Kind kind, std::string_view instance) noexcept;
+
+    std::unique_ptr<BoxedCsr> mCsr;
+    const DiceChain::Kind mKind;
+    const std::string mInstance;
+};
+
 } // namespace hwtrust
diff --git a/remote_provisioning/hwtrust/cxxbridge/lib.rs b/remote_provisioning/hwtrust/cxxbridge/lib.rs
index dd713bd..4ff2a3c 100644
--- a/remote_provisioning/hwtrust/cxxbridge/lib.rs
+++ b/remote_provisioning/hwtrust/cxxbridge/lib.rs
@@ -3,7 +3,9 @@
 
 use coset::CborSerializable;
 use hwtrust::dice::ChainForm;
-use hwtrust::session::{Options, Session};
+use hwtrust::rkp::Csr as InnerCsr;
+use hwtrust::session::{Options, RkpInstance, Session};
+use std::str::FromStr;
 
 #[allow(clippy::needless_maybe_sized)]
 #[allow(unsafe_op_in_unsafe_fn)]
@@ -33,6 +35,16 @@ mod ffi {
         len: usize,
     }
 
+    /// The result type used by [`validate_csr()`]. The standard [`Result`] is currently only
+    /// converted to exceptions by `cxxbridge` but we can't use exceptions so need to do something
+    /// custom.
+    struct ValidateCsrResult {
+        /// If non-empty, the description of the verification error that occurred.
+        error: String,
+        /// If [`error`] is empty, a handle to the validated Csr.
+        csr: Box<Csr>,
+    }
+
     extern "Rust" {
         type DiceChain;
 
@@ -41,6 +53,7 @@ mod ffi {
             chain: &[u8],
             kind: DiceChainKind,
             allow_any_mode: bool,
+            instance: &str,
         ) -> VerifyDiceChainResult;
 
         #[cxx_name = GetDiceChainPublicKey]
@@ -48,6 +61,19 @@ mod ffi {
 
         #[cxx_name = IsDiceChainProper]
         fn is_dice_chain_proper(chain: &DiceChain) -> bool;
+
+        type Csr;
+
+        #[cxx_name = validateCsr]
+        fn validate_csr(
+            csr: &[u8],
+            kind: DiceChainKind,
+            allow_any_mode: bool,
+            instance: &str,
+        ) -> ValidateCsrResult;
+
+        #[cxx_name = getDiceChainFromCsr]
+        fn get_dice_chain_from_csr(csr: &Csr) -> VerifyDiceChainResult;
     }
 }
 
@@ -58,6 +84,7 @@ fn verify_dice_chain(
     chain: &[u8],
     kind: ffi::DiceChainKind,
     allow_any_mode: bool,
+    instance: &str,
 ) -> ffi::VerifyDiceChainResult {
     let mut session = Session {
         options: match kind {
@@ -74,13 +101,18 @@ fn verify_dice_chain(
             }
         },
     };
+    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
+        return ffi::VerifyDiceChainResult {
+            error: format!("invalid RKP instance: {}", instance),
+            chain: Box::new(DiceChain(None)),
+            len: 0,
+        };
+    };
     session.set_allow_any_mode(allow_any_mode);
+    session.set_rkp_instance(rkp_instance);
     match ChainForm::from_cbor(&session, chain) {
         Ok(chain) => {
-            let len = match chain {
-                ChainForm::Proper(ref chain) => chain.payloads().len(),
-                ChainForm::Degenerate(_) => 1,
-            };
+            let len = chain.length();
             let chain = Box::new(DiceChain(Some(chain)));
             ffi::VerifyDiceChainResult { error: "".to_string(), chain, len }
         }
@@ -116,3 +148,62 @@ fn is_dice_chain_proper(chain: &DiceChain) -> bool {
         false
     }
 }
+
+/// A Csr as exposed over the cxx bridge.
+pub struct Csr(Option<InnerCsr>);
+
+fn validate_csr(
+    csr: &[u8],
+    kind: ffi::DiceChainKind,
+    allow_any_mode: bool,
+    instance: &str,
+) -> ffi::ValidateCsrResult {
+    let mut session = Session {
+        options: match kind {
+            ffi::DiceChainKind::Vsr13 => Options::vsr13(),
+            ffi::DiceChainKind::Vsr14 => Options::vsr14(),
+            ffi::DiceChainKind::Vsr15 => Options::vsr15(),
+            ffi::DiceChainKind::Vsr16 => Options::vsr16(),
+            _ => {
+                return ffi::ValidateCsrResult {
+                    error: "invalid chain kind".to_string(),
+                    csr: Box::new(Csr(None)),
+                }
+            }
+        },
+    };
+    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
+        return ffi::ValidateCsrResult {
+            error: format!("invalid RKP instance: {}", instance),
+            csr: Box::new(Csr(None)),
+        };
+    };
+    session.set_allow_any_mode(allow_any_mode);
+    session.set_rkp_instance(rkp_instance);
+    match InnerCsr::from_cbor(&session, csr) {
+        Ok(csr) => {
+            let csr = Box::new(Csr(Some(csr)));
+            ffi::ValidateCsrResult { error: "".to_string(), csr }
+        }
+        Err(e) => {
+            let error = format!("{:#}", e);
+            ffi::ValidateCsrResult { error, csr: Box::new(Csr(None)) }
+        }
+    }
+}
+
+fn get_dice_chain_from_csr(csr: &Csr) -> ffi::VerifyDiceChainResult {
+    match csr {
+        Csr(Some(csr)) => {
+            let chain = csr.dice_chain();
+            let len = chain.length();
+            let chain = Box::new(DiceChain(Some(chain)));
+            ffi::VerifyDiceChainResult { error: "".to_string(), chain, len }
+        }
+        _ => ffi::VerifyDiceChainResult {
+            error: "CSR could not be destructured".to_string(),
+            chain: Box::new(DiceChain(None)),
+            len: 0,
+        },
+    }
+}
diff --git a/remote_provisioning/hwtrust/src/cbor.rs b/remote_provisioning/hwtrust/src/cbor.rs
index fe3fa88..32d2b24 100644
--- a/remote_provisioning/hwtrust/src/cbor.rs
+++ b/remote_provisioning/hwtrust/src/cbor.rs
@@ -21,7 +21,6 @@ fn value_from_bytes(mut bytes: &[u8]) -> Result<Value, CiboriumError> {
     Ok(value)
 }
 
-#[cfg(test)]
 fn serialize(value: Value) -> Vec<u8> {
     let mut data = Vec::new();
     ciborium::ser::into_writer(&value, &mut data).unwrap();
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/chain.rs b/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
index 96b0a59..15269f7 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
@@ -96,7 +96,7 @@ impl Chain {
             let previous = payloads.last().unwrap();
             previous_public_key = previous.subject_public_key();
         }
-        Self::validate(root, payloads).context("Building chain")
+        Self::validate(root, payloads, session.options.rkp_instance).context("Building chain")
     }
 }
 
diff --git a/remote_provisioning/hwtrust/src/cbor/field_value.rs b/remote_provisioning/hwtrust/src/cbor/field_value.rs
index fb25f86..c9aa764 100644
--- a/remote_provisioning/hwtrust/src/cbor/field_value.rs
+++ b/remote_provisioning/hwtrust/src/cbor/field_value.rs
@@ -45,6 +45,14 @@ impl FieldValue {
         Self { name, value: None }
     }
 
+    pub fn value(&self) -> Option<Value> {
+        self.value.clone()
+    }
+
+    pub fn from_value(name: &'static str, value: Value) -> Self {
+        Self { name, value: Some(value) }
+    }
+
     pub fn from_optional_value(name: &'static str, value: Option<Value>) -> Self {
         Self { name, value }
     }
diff --git a/remote_provisioning/hwtrust/src/cbor/publickey.rs b/remote_provisioning/hwtrust/src/cbor/publickey.rs
index 11743e6..a3e021d 100644
--- a/remote_provisioning/hwtrust/src/cbor/publickey.rs
+++ b/remote_provisioning/hwtrust/src/cbor/publickey.rs
@@ -10,9 +10,11 @@ use openssl::ec::{EcGroup, EcKey};
 use openssl::ecdsa::EcdsaSig;
 use openssl::nid::Nid;
 use openssl::pkey::{Id, PKey, Public};
+use std::collections::HashSet;
 
 impl PublicKey {
-    pub(super) fn from_cose_key(cose_key: &CoseKey) -> Result<Self> {
+    /// Create a public key from a [`CoseKey`].
+    pub fn from_cose_key(cose_key: &CoseKey) -> Result<Self> {
         if !cose_key.key_ops.is_empty() {
             ensure!(cose_key.key_ops.contains(&KeyOperation::Assigned(iana::KeyOperation::Verify)));
         }
@@ -22,15 +24,19 @@ impl PublicKey {
 
     /// Verifies a COSE_Sign1 signature over its message. This function handles the conversion of
     /// the signature format that is needed for some algorithms.
-    pub(in crate::cbor) fn verify_cose_sign1(&self, sign1: &CoseSign1, aad: &[u8]) -> Result<()> {
+    pub fn verify_cose_sign1(&self, sign1: &CoseSign1, aad: &[u8]) -> Result<()> {
         ensure!(sign1.protected.header.crit.is_empty(), "No critical headers allowed");
         ensure!(
             sign1.protected.header.alg == Some(Algorithm::Assigned(iana_algorithm(self.kind()))),
-            "Algorithm mistmatch in protected header"
+            "Algorithm mistmatch in protected header. \
+             Signature - protected.header.alg: {:?}, Key - kind: {:?}",
+            sign1.protected.header.alg,
+            iana_algorithm(self.kind())
         );
         sign1.verify_signature(aad, |signature, message| match self.kind() {
-            SignatureKind::Ec(k) => {
-                let der = ec_cose_signature_to_der(k, signature).context("Signature to DER")?;
+            SignatureKind::Ec(_) => {
+                let der =
+                    ec_cose_signature_to_der(self.kind(), signature).context("Signature to DER")?;
                 self.verify(&der, message)
             }
             _ => self.verify(signature, message),
@@ -114,7 +120,7 @@ fn pkey_from_okp_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
         cose_key.alg == Some(Algorithm::Assigned(iana::Algorithm::EdDSA))
             || cose_key.alg == Some(Algorithm::Assigned(iana::Algorithm::ECDH_ES_HKDF_256))
     );
-    //ensure!(cose_key.alg == Some(Algorithm::Assigned(iana::Algorithm::EdDSA)));
+    ensure_no_disallowed_labels(cose_key)?;
     let crv = get_label_value(cose_key, Label::Int(iana::OkpKeyParameter::Crv.to_i64()))?;
     let x = get_label_value_as_bytes(cose_key, Label::Int(iana::OkpKeyParameter::X.to_i64()))?;
     let curve_id = if crv == &Value::from(iana::EllipticCurve::Ed25519.to_i64()) {
@@ -129,6 +135,7 @@ fn pkey_from_okp_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
 
 fn pkey_from_ec2_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
     ensure!(cose_key.kty == KeyType::Assigned(iana::KeyType::EC2));
+    ensure_no_disallowed_labels(cose_key)?;
     let crv = get_label_value(cose_key, Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))?;
     let x = get_label_value_as_bytes(cose_key, Label::Int(iana::Ec2KeyParameter::X.to_i64()))?;
     let y = get_label_value_as_bytes(cose_key, Label::Int(iana::Ec2KeyParameter::Y.to_i64()))?;
@@ -155,6 +162,40 @@ fn pkey_from_ec_coords(nid: Nid, x: &[u8], y: &[u8]) -> Result<PKey<Public>> {
     PKey::from_ec_key(key).context("Failed to create PKey")
 }
 
+fn ensure_no_disallowed_labels(cose_key: &CoseKey) -> Result<()> {
+    let allow_list = match cose_key.kty {
+        KeyType::Assigned(iana::KeyType::EC2) => HashSet::from([
+            iana::Ec2KeyParameter::Crv.to_i64(),
+            iana::Ec2KeyParameter::X.to_i64(),
+            iana::Ec2KeyParameter::Y.to_i64(),
+        ]),
+        KeyType::Assigned(iana::KeyType::OKP) => {
+            HashSet::from([iana::OkpKeyParameter::Crv.to_i64(), iana::OkpKeyParameter::X.to_i64()])
+        }
+        _ => bail!("Invalid key type in COSE key"),
+    };
+
+    let params = cose_key.params.clone();
+    let disallowed: Vec<(Label, String)> = params
+        .into_iter()
+        .filter(|(label, _)| match label {
+            Label::Int(int) => !allow_list.contains(int),
+            Label::Text(_) => true,
+        })
+        .map(|(label, value)| -> (Label, String) {
+            let string = match value.as_bytes() {
+                Some(bytes) => hex::encode(bytes),
+                None => String::from("Expected Bytes, got {value:?}"),
+            };
+            (label, string)
+        })
+        .collect();
+
+    ensure!(disallowed.is_empty(), "disallowed labels should be empty: {:?}", disallowed);
+
+    Ok(())
+}
+
 /// Get the value corresponding to the provided label within the supplied CoseKey or error if it's
 /// not present.
 fn get_label_value(key: &CoseKey, label: Label) -> Result<&Value> {
@@ -175,7 +216,7 @@ fn get_label_value_as_bytes(key: &CoseKey, label: Label) -> Result<&[u8]> {
         .map(Vec::as_slice)
 }
 
-fn ec_cose_signature_to_der(kind: EcKind, signature: &[u8]) -> Result<Vec<u8>> {
+fn ec_cose_signature_to_der(kind: SignatureKind, signature: &[u8]) -> Result<Vec<u8>> {
     let coord_len = ec_coord_len(kind);
     ensure!(signature.len() == coord_len * 2, "Unexpected signature length");
     let r = BigNum::from_slice(&signature[..coord_len]).context("Creating BigNum for r")?;
@@ -184,10 +225,13 @@ fn ec_cose_signature_to_der(kind: EcKind, signature: &[u8]) -> Result<Vec<u8>> {
     signature.to_der().context("Failed to DER encode signature")
 }
 
-fn ec_coord_len(kind: EcKind) -> usize {
+fn ec_coord_len(kind: SignatureKind) -> usize {
     match kind {
-        EcKind::P256 => 32,
-        EcKind::P384 => 48,
+        SignatureKind::Ec(kind) => match kind {
+            EcKind::P256 => 32,
+            EcKind::P384 => 48,
+        },
+        SignatureKind::Ed25519 => 32,
     }
 }
 
@@ -203,10 +247,11 @@ fn iana_algorithm(kind: SignatureKind) -> iana::Algorithm {
 mod tests {
     use super::*;
     use crate::publickey::testkeys::{
-        PrivateKey, ED25519_KEY_PEM, P256_KEY_PEM, P256_KEY_WITH_LEADING_ZEROS_PEM,
-        P384_KEY_WITH_LEADING_ZEROS_PEM,
+        PrivateKey, EC2_KEY_WITH_HIGH_BITS_SET_PEM, EC2_KEY_WITH_LEADING_ZEROS_PEM,
+        ED25519_KEY_PEM, ED25519_KEY_WITH_LEADING_ZEROS_PEM, P256_KEY_PEM,
     };
     use coset::{CoseSign1Builder, HeaderBuilder};
+    use std::collections::HashSet;
 
     impl PrivateKey {
         pub(in crate::cbor) fn sign_cose_sign1(&self, payload: Vec<u8>) -> CoseSign1 {
@@ -216,7 +261,7 @@ mod tests {
                 .create_signature(b"", |m| {
                     let signature = self.sign(m).unwrap();
                     match self.kind() {
-                        SignatureKind::Ec(ec) => ec_der_signature_to_cose(ec, &signature),
+                        SignatureKind::Ec(_) => ec_der_signature_to_cose(self.kind(), &signature),
                         _ => signature,
                     }
                 })
@@ -224,27 +269,29 @@ mod tests {
         }
     }
 
-    fn ec_der_signature_to_cose(kind: EcKind, signature: &[u8]) -> Vec<u8> {
-        let coord_len = ec_coord_len(kind).try_into().unwrap();
+    fn ec_der_signature_to_cose(kind: SignatureKind, signature: &[u8]) -> Vec<u8> {
+        let coord_len = ec_coord_len(kind);
         let signature = EcdsaSig::from_der(signature).unwrap();
-        let mut r = signature.r().to_vec_padded(coord_len).unwrap();
-        let mut s = signature.s().to_vec_padded(coord_len).unwrap();
+        let mut r = signature.r().to_vec_padded(coord_len.try_into().unwrap()).unwrap();
+        let mut s = signature.s().to_vec_padded(coord_len.try_into().unwrap()).unwrap();
         r.append(&mut s);
         r
     }
 
-    #[test]
-    fn sign_and_verify_okp() {
-        let key = PrivateKey::from_pem(ED25519_KEY_PEM[0]);
+    fn sign_and_verify(pem: &str) {
+        let key = PrivateKey::from_pem(pem);
         let sign1 = key.sign_cose_sign1(b"signed payload".to_vec());
         key.public_key().verify_cose_sign1(&sign1, b"").unwrap();
     }
 
+    #[test]
+    fn sign_and_verify_okp() {
+        sign_and_verify(ED25519_KEY_PEM[0])
+    }
+
     #[test]
     fn sign_and_verify_ec2() {
-        let key = PrivateKey::from_pem(P256_KEY_PEM[0]);
-        let sign1 = key.sign_cose_sign1(b"signed payload".to_vec());
-        key.public_key().verify_cose_sign1(&sign1, b"").unwrap();
+        sign_and_verify(P256_KEY_PEM[0])
     }
 
     #[test]
@@ -312,55 +359,82 @@ mod tests {
         key.public_key().verify_cose_sign1(&sign1, b"").unwrap_err();
     }
 
-    #[test]
-    fn to_and_from_okp_cose_key() {
-        let key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
+    fn to_and_from_cose_key(pem: &str) {
+        let key = PrivateKey::from_pem(pem).public_key();
         let value = key.to_cose_key().unwrap();
         let new_key = PublicKey::from_cose_key(&value).unwrap();
         assert!(key.pkey().public_eq(new_key.pkey()));
     }
+    #[test]
+    fn to_and_from_okp_cose_key() {
+        to_and_from_cose_key(ED25519_KEY_PEM[0]);
+    }
 
     #[test]
     fn to_and_from_ec2_cose_key() {
-        let key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
-        let value = key.to_cose_key().unwrap();
-        let new_key = PublicKey::from_cose_key(&value).unwrap();
-        assert!(key.pkey().public_eq(new_key.pkey()));
+        to_and_from_cose_key(P256_KEY_PEM[0]);
     }
 
     #[test]
-    fn from_p256_pkey_with_leading_zeros() {
-        for pem in P256_KEY_WITH_LEADING_ZEROS_PEM {
+    fn from_ed25519_pkey_with_leading_zeros() {
+        for pem in ED25519_KEY_WITH_LEADING_ZEROS_PEM {
             let key = PrivateKey::from_pem(pem).public_key();
             let cose_key = key.to_cose_key().unwrap();
-
+            let kind = key.kind();
+            assert_eq!(kind, SignatureKind::Ed25519);
+            let expected_size = ec_coord_len(kind);
             let x =
-                get_label_value_as_bytes(&cose_key, Label::Int(iana::Ec2KeyParameter::X.to_i64()))
-                    .unwrap();
-            assert_eq!(x.len(), 32, "X coordinate is the wrong size\n{}", pem);
-
-            let y =
-                get_label_value_as_bytes(&cose_key, Label::Int(iana::Ec2KeyParameter::Y.to_i64()))
+                get_label_value_as_bytes(&cose_key, Label::Int(iana::OkpKeyParameter::X.to_i64()))
                     .unwrap();
-            assert_eq!(y.len(), 32, "Y coordinate is the wrong size\n{}", pem);
+            assert_eq!(x.len(), expected_size, "X coordinate is the wrong size\n{}", pem);
+            assert_eq!(x[0], 0);
         }
     }
 
-    #[test]
-    fn from_p384_pkey_with_leading_zeros() {
-        for pem in P384_KEY_WITH_LEADING_ZEROS_PEM {
+    fn check_coordinate_lengths_and_first_byte(
+        pems: &[&str],
+        first_byte_check: fn(&[u8], &[u8]) -> bool,
+    ) {
+        let mut curves = HashSet::new();
+        for pem in pems {
             let key = PrivateKey::from_pem(pem).public_key();
             let cose_key = key.to_cose_key().unwrap();
-
+            let kind = key.kind();
+            match kind {
+                SignatureKind::Ec(inner) => {
+                    curves.insert(inner);
+                }
+                SignatureKind::Ed25519 => panic!("signature kind should not be ED25519"),
+            };
+            let expected_size = ec_coord_len(kind);
             let x =
                 get_label_value_as_bytes(&cose_key, Label::Int(iana::Ec2KeyParameter::X.to_i64()))
                     .unwrap();
-            assert_eq!(x.len(), 48, "X coordinate is the wrong size\n{}", pem);
+            assert_eq!(x.len(), expected_size, "X coordinate is the wrong size\n{}", pem);
 
             let y =
                 get_label_value_as_bytes(&cose_key, Label::Int(iana::Ec2KeyParameter::Y.to_i64()))
                     .unwrap();
-            assert_eq!(y.len(), 48, "Y coordinate is the wrong size\n{}", pem);
+            assert_eq!(y.len(), expected_size, "Y coordinate is the wrong size\n{}", pem);
+            assert!(first_byte_check(x, y));
+        }
+        assert!(curves.contains(&EcKind::P256));
+        assert!(curves.contains(&EcKind::P384));
+    }
+
+    #[test]
+    fn from_ec2_pkey_with_leading_zeros() {
+        fn check(x: &[u8], y: &[u8]) -> bool {
+            x[0] == 0 || y[0] == 0
+        }
+        check_coordinate_lengths_and_first_byte(EC2_KEY_WITH_LEADING_ZEROS_PEM, check)
+    }
+
+    #[test]
+    fn from_ec2_pkey_with_high_bits_set() {
+        fn check(x: &[u8], y: &[u8]) -> bool {
+            (x[0] & 0x80 == 0x80) && (y[0] & 0x80 == 0x80)
         }
+        check_coordinate_lengths_and_first_byte(EC2_KEY_WITH_HIGH_BITS_SET_PEM, check)
     }
 }
diff --git a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
index a7c5090..48a5d6a 100644
--- a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
@@ -1,14 +1,63 @@
+use std::collections::HashMap;
+
 use crate::cbor::field_value::FieldValue;
-use crate::cbor::value_from_bytes;
+use crate::cbor::{serialize, value_from_bytes};
 use crate::dice::ChainForm;
-use crate::rkp::{Csr, DeviceInfo, ProtectedData};
-use crate::session::Session;
+use crate::rkp::{Csr, CsrPayload, DeviceInfo, ProtectedData};
+use crate::session::{RkpInstance, Session};
 use anyhow::{anyhow, bail, ensure, Context, Result};
 use base64::{prelude::BASE64_STANDARD, Engine};
 use ciborium::value::Value;
+use openssl::pkey::Id;
+use openssl::stack::Stack;
+use openssl::x509::store::X509StoreBuilder;
+use openssl::x509::verify::X509VerifyFlags;
+use openssl::x509::{X509StoreContext, X509};
 
 const VERSION_OR_DEVICE_INFO_INDEX: usize = 0;
 
+impl CsrPayload {
+    fn from_value(value: &Value, session: &Session) -> Result<Self> {
+        let serialized = match value.clone().into_bytes() {
+            Ok(bytes) => bytes,
+            Err(_) => bail!("CsrPayload had no bytes"),
+        };
+
+        let mut csr_payload = match value_from_bytes(serialized.as_slice())? {
+            Value::Array(a) => a,
+            other => bail!("CsrPayload is expected to be an array, found {other:?}"),
+        };
+
+        let keys_to_sign = FieldValue::from_optional_value("KeysToSign", csr_payload.pop());
+        let device_info = FieldValue::from_optional_value("DeviceInfo", csr_payload.pop());
+        let certificate_type =
+            FieldValue::from_optional_value("CertificateType", csr_payload.pop());
+        let version = FieldValue::from_optional_value("Version", csr_payload.pop()).into_u64()?;
+        if version != 3 {
+            bail!("Invalid CSR version. Only '3' is supported");
+        }
+
+        let certificate_type = certificate_type.into_string()?;
+
+        const CERTIFICATE_TYPE_RKPVM: &str = "rkp-vm";
+        match session.options.rkp_instance {
+            RkpInstance::Avf => ensure!(
+                CERTIFICATE_TYPE_RKPVM == certificate_type,
+                "CertificateType must be 'rkp-vm' for AVF"
+            ),
+            _ => ensure!(
+                CERTIFICATE_TYPE_RKPVM != certificate_type,
+                "CertificateType must not be 'rkp-vm' for non-AVF"
+            ),
+        }
+
+        let device_info = DeviceInfo::from_cbor_values(device_info.into_map()?, Some(3))?;
+        let keys_to_sign = serialize(keys_to_sign.value().unwrap());
+
+        Ok(CsrPayload { certificate_type, device_info, keys_to_sign })
+    }
+}
+
 impl Csr {
     /// Parse base64-encoded CBOR data as a Certificate Signing Request.
     pub fn from_base64_cbor<S: AsRef<[u8]>>(session: &Session, base64: &S) -> Result<Self> {
@@ -91,32 +140,130 @@ impl Csr {
 
         let signed_data =
             FieldValue::from_optional_value("SignedData", csr.pop()).into_cose_sign1()?;
-        let dice_chain =
-            ChainForm::from_value(session, csr.pop().ok_or(anyhow!("Missing DiceCertChain"))?)?;
+        let raw_dice_chain = csr.pop().ok_or(anyhow!("Missing DiceCertChain"))?;
+        let uds_certs = FieldValue::from_optional_value("UdsCerts", csr.pop()).into_map()?;
+
+        let dice_chain = ChainForm::from_value(session, raw_dice_chain)?;
+        let uds_certs = Self::parse_and_validate_uds_certs(&dice_chain, uds_certs)?;
+
+        let signing_key = dice_chain.leaf_public_key();
+        signing_key.verify_cose_sign1(&signed_data, &[]).context("verifying SignedData failed")?;
 
         let signed_data_payload = signed_data.payload.context("missing payload in SignedData")?;
-        let csr_payload_value = value_from_bytes(&signed_data_payload)
-            .context("SignedData payload is not valid CBOR")?
-            .as_array_mut()
-            .context("SignedData payload is not a CBOR array")?
-            .pop()
-            .context("Missing CsrPayload in SignedData")?;
-        let csr_payload_bytes = csr_payload_value
-            .as_bytes()
-            .context("CsrPayload (in SignedData) is expected to be encoded CBOR")?
-            .as_slice();
-        let mut csr_payload = match value_from_bytes(csr_payload_bytes)? {
-            Value::Array(a) => a,
-            other => bail!("CsrPayload is expected to be an array, found {other:?}"),
+
+        let mut signed_data_value = value_from_bytes(signed_data_payload.as_slice())
+            .context("SignedData is not valid CBOR")?;
+
+        let signed_data_array =
+            signed_data_value.as_array_mut().context("SignedData is not a CBOR array")?;
+
+        let csr_payload_value =
+            signed_data_array.pop().context("Missing CsrPayload in SignedData")?;
+
+        let csr_payload = CsrPayload::from_value(&csr_payload_value, session)
+            .context("Unable to parse CsrPayload")?;
+
+        let challenge = match signed_data_array.pop().context("missing challenge")?.into_bytes() {
+            Ok(challenge) => challenge,
+            Err(_) => bail!("Challenge is not bytes"),
         };
 
-        let _keys_to_sign = FieldValue::from_optional_value("KeysToSign", csr_payload.pop());
-        let device_info = FieldValue::from_optional_value("DeviceInfo", csr_payload.pop());
-        let _certificate_type =
-            FieldValue::from_optional_value("CertificateType", csr_payload.pop());
+        Ok(Self::V3 { dice_chain, uds_certs, challenge, csr_payload })
+    }
 
-        let device_info = DeviceInfo::from_cbor_values(device_info.into_map()?, Some(3))?;
-        Ok(Self::V3 { device_info, dice_chain })
+    fn parse_and_validate_uds_certs(
+        dice_chain: &ChainForm,
+        uds_certs: Vec<(Value, Value)>,
+    ) -> Result<HashMap<String, Vec<X509>>> {
+        let expected_uds = match dice_chain {
+            ChainForm::Degenerate(chain) => chain.public_key(),
+            ChainForm::Proper(chain) => chain.root_public_key(),
+        }
+        .pkey();
+
+        let mut parsed = HashMap::new();
+        for (signer, der_certs) in uds_certs {
+            let signer = FieldValue::from_value("SignerName", signer).into_string()?;
+            let x509_certs = FieldValue::from_value("UdsCertChain", der_certs)
+                .into_array()?
+                .into_iter()
+                .map(|v| match FieldValue::from_value("X509Certificate", v).into_bytes() {
+                    Ok(b) => X509::from_der(&b).context("Unable to parse DER X509Certificate"),
+                    Err(e) => Err(e).context("Invalid type for X509Certificate"),
+                })
+                .collect::<Result<Vec<X509>>>()?;
+            Self::validate_uds_cert_path(&signer, &x509_certs)?;
+            ensure!(
+                x509_certs.last().unwrap().public_key()?.public_eq(expected_uds),
+                "UdsCert leaf for SignerName '{signer}' does not match the DICE chain root"
+            );
+            ensure!(
+                parsed.insert(signer.clone(), x509_certs).is_none(),
+                "Duplicate signer found: '{signer}'"
+            );
+        }
+        Ok(parsed)
+    }
+
+    fn validate_uds_cert_path(signer: &String, certs: &Vec<X509>) -> Result<()> {
+        ensure!(
+            certs.len() > 1,
+            "Certificate chain for signer '{signer}' is too short: {certs:#?}"
+        );
+
+        for cert in certs {
+            let id = cert.public_key()?.id();
+            ensure!(
+                matches!(id, Id::RSA | Id::EC | Id::ED25519),
+                "Certificate has an unsupported public algorithm id {id:?}"
+            );
+        }
+
+        // OpenSSL wants us to split up root trust anchor, leaf, and intermediates
+        let mut certs_copy = certs.clone();
+        let leaf = certs_copy.pop().unwrap();
+        let mut intermediates = Stack::new()?;
+        while certs_copy.len() > 1 {
+            intermediates.push(certs_copy.pop().unwrap())?;
+        }
+        let root = certs_copy.pop().unwrap();
+
+        let mut root_store_builder = X509StoreBuilder::new()?;
+        root_store_builder.add_cert(root)?;
+        // Setting this flag causes the signature on the root certificate to be checked.
+        // This ensures that the root certificate has not been corrupted.
+        root_store_builder.set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE)?;
+
+        let root_store = root_store_builder.build();
+
+        let mut store = X509StoreContext::new()?;
+        let result = store.init(&root_store, &leaf, &intermediates, |context| {
+            // the with_context function must return Result<T, ErrorStack>, so we have to get
+            // tricky and return Result<Result<()>, ErrorStack> so we can bubble up custom errors.
+            match context.verify_cert() {
+                Ok(true) => (),
+                Ok(false) => return Ok(Err(anyhow!("Cert failed to verify: {}", context.error()))),
+                Err(e) => return Err(e),
+            };
+
+            if let Some(chain) = context.chain() {
+                // OpenSSL returns the leaf at the bottom of the stack.
+                if !chain.iter().rev().eq(certs.iter()) {
+                    let chain: Vec<_> = chain.iter().rev().map(|r| r.to_owned()).collect();
+                    return Ok(Err(anyhow!(
+                        "Verified chain doesn't match input: {chain:#?} vs {certs:#?}"
+                    )));
+                }
+            } else {
+                return Ok(Err(anyhow!("Cert chain is missing (impossible!)")));
+            }
+            Ok(Ok(()))
+        });
+
+        match result {
+            Ok(e) => e,
+            Err(e) => bail!("Error verifying cert chain: {e:?}"),
+        }
     }
 }
 
@@ -128,7 +275,7 @@ mod tests {
     use super::*;
     use crate::cbor::rkp::csr::testutil::{parse_pem_public_key_or_panic, test_device_info};
     use crate::dice::{ChainForm, DegenerateChain, DiceMode};
-    use crate::rkp::DeviceInfoVersion;
+    use crate::rkp::{DeviceInfoSecurityLevel, DeviceInfoVersion};
     use crate::session::{Options, Session};
     use std::fs;
 
@@ -156,12 +303,13 @@ mod tests {
     fn from_base64_valid_v3() {
         let input = fs::read_to_string("testdata/csr/v3_csr.base64").unwrap().trim().to_owned();
         let csr = Csr::from_base64_cbor(&Session::default(), &input).unwrap();
-        if let Csr::V3 { device_info, dice_chain } = csr {
-            assert_eq!(device_info, test_device_info(DeviceInfoVersion::V3));
+        if let Csr::V3 { dice_chain, uds_certs, csr_payload, .. } = csr {
+            assert_eq!(csr_payload.device_info, test_device_info(DeviceInfoVersion::V3));
             let root_public_key = parse_pem_public_key_or_panic(
                 "-----BEGIN PUBLIC KEY-----\n\
-                MCowBQYDK2VwAyEA3FEn/nhqoGOKNok1AJaLfTKI+aFXHf4TfC42vUyPU6s=\n\
-                -----END PUBLIC KEY-----\n",
+                    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh5NUV4872vKEL3XPSp8lfkV4AN3J\n\
+                KJti1Y5kbbR9ucTpSyoOjX9UmBCM/uuPU/MGXMWrgbBf3++02ALzC+V3eQ==\n\
+                    -----END PUBLIC KEY-----\n",
             );
             match dice_chain {
                 ChainForm::Proper(proper_chain) => {
@@ -185,6 +333,7 @@ mod tests {
                 }
                 ChainForm::Degenerate(d) => panic!("Parsed chain is not proper: {:?}", d),
             }
+            assert_eq!(uds_certs.len(), 0);
         } else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         }
@@ -198,6 +347,27 @@ mod tests {
         Ok(())
     }
 
+    #[test]
+    fn from_cbor_valid_v3_avf_with_rkpvm_chain() -> anyhow::Result<()> {
+        let input = fs::read("testdata/csr/v3_csr_avf.cbor")?;
+        let mut session = Session::default();
+        session.set_allow_any_mode(true);
+        session.set_rkp_instance(RkpInstance::Avf);
+        let csr = Csr::from_cbor(&session, input.as_slice())?;
+        let Csr::V3 { dice_chain, csr_payload, .. } = csr else {
+            panic!("Parsed CSR was not V3: {:?}", csr);
+        };
+        assert_eq!(csr_payload.device_info.security_level, Some(DeviceInfoSecurityLevel::Avf));
+        let ChainForm::Proper(proper_chain) = dice_chain else {
+            panic!("Parsed chain is not proper: {:?}", dice_chain);
+        };
+        let expected_len = 7;
+        assert_eq!(proper_chain.payloads().len(), expected_len);
+        assert!(proper_chain.payloads()[expected_len - 1].has_rkpvm_marker());
+        assert!(proper_chain.payloads()[expected_len - 2].has_rkpvm_marker());
+        Ok(())
+    }
+
     #[test]
     fn from_empty_string() {
         let err = Csr::from_base64_cbor(&Session::default(), &"").unwrap_err();
@@ -215,6 +385,104 @@ mod tests {
         let err = Csr::from_base64_cbor(&Session::default(), &"not base64").unwrap_err();
         assert!(err.to_string().contains("invalid base64"));
     }
+
+    const VALID_UDS_CHAIN: &[&str] = &[
+        "-----BEGIN CERTIFICATE-----\n\
+    MIICKjCCAbCgAwIBAgIUPFTOIhGtj7sELYJk5HicdV8r/x8wCgYIKoZIzj0EAwMw\n\
+    RzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUxGjAY\n\
+    BgNVBAMMEVRFU1QgSU5URVJNRURJQVRFMCAXDTI0MTExNDIwMTcwOFoYDzIxMjQx\n\
+    MDIxMjAxNzA4WjA/MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExDzANBgNVBAoM\n\
+    Bkdvb2dsZTESMBAGA1UEAwwJVEVTVCBMRUFGMHYwEAYHKoZIzj0CAQYFK4EEACID\n\
+    YgAEry9HebgpyEnmimjtgs1KN5akdUx6cAEKVwkj0ZkYIW9V+YeRa4ap4yWvh8ZG\n\
+    U1GA0Eu26z7YQZbPuJ8LnyW0cXj3UGpXgP8EWyftWdz9EX6WpzdO7fuxtxeC/X2l\n\
+    ZuFIo2MwYTAdBgNVHQ4EFgQUWl8nH6cOAU3IrNZ2kqOzq3JUlukwHwYDVR0jBBgw\n\
+    FoAUjtSEVIqjzE6pGwlgEHPRn5o9a0YwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n\
+    Af8EBAMCB4AwCgYIKoZIzj0EAwMDaAAwZQIxAMmpFFiMRVnZHZSBCqjWQfA0lqaT\n\
+    HiusLqIEcAobDy80/mzO2yO6exNjoXkMB17COwIwD1YmiMkaqnnJkan9CNTnBXZB\n\
+    WNlU9CCE10ohcVfjssl7YVcnna70Rc1UH4DhjSj6\n\
+    -----END CERTIFICATE-----",
+        "-----BEGIN CERTIFICATE-----\n\
+    MIICLjCCAbOgAwIBAgIUKIsXCCFZRvz0BYboKmgZjyGArAEwCgYIKoZIzj0EAwMw\n\
+    PzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUxEjAQ\n\
+    BgNVBAMMCVRFU1QgUk9PVDAgFw0yNDExMTQyMDE1MzVaGA8yMTI0MTAyMTIwMTUz\n\
+    NVowRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUx\n\
+    GjAYBgNVBAMMEVRFU1QgSU5URVJNRURJQVRFMHYwEAYHKoZIzj0CAQYFK4EEACID\n\
+    YgAEFYWPvG5PCQBBXFi/xY1F3MRqDXHkmqdTErc3wlBakVQmCjiklrEalZhMAr5Q\n\
+    0MYje5/l/ZbN+bvurD5ZsOyWRSrzTkzoUMQszB4fSoJtBp3grcEfd+/tQlC1DZO0\n\
+    wTROo2YwZDAdBgNVHQ4EFgQUjtSEVIqjzE6pGwlgEHPRn5o9a0YwHwYDVR0jBBgw\n\
+    FoAUwQ91rFNLmFq9YMlG1bqk7OvWk44wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNV\n\
+    HQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwMDaQAwZgIxAMWXmsh6d8YSkP1+wR9eMDCe\n\
+    9G0EFAPOn+BiKfthnnboRUEr8BuIt3w9SkEDCdWfcAIxAMJ99xkGf3bcdykao4jh\n\
+    bgG844IvDSx11EwzQV/kcteHOut93YO0D83CgkDc2C4dNA==\n\
+    -----END CERTIFICATE-----",
+        "-----BEGIN CERTIFICATE-----\n\
+    MIICJTCCAaugAwIBAgIUUo4NdEcdRuQdrm5Trm5x+qvx2LEwCgYIKoZIzj0EAwMw\n\
+    PzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUxEjAQ\n\
+    BgNVBAMMCVRFU1QgUk9PVDAgFw0yNDExMTQyMDEzNDRaGA8yMTI0MTAyMTIwMTM0\n\
+    NFowPzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUx\n\
+    EjAQBgNVBAMMCVRFU1QgUk9PVDB2MBAGByqGSM49AgEGBSuBBAAiA2IABOGIoNBS\n\
+    sVs+mTjZpqOyoWTEOIvIIhuFfi49eqleyKTnekgXyXcJfqppsbqYcgPKaTbJmhU/\n\
+    iuOjaSIUlyf5tjJ7bIOAngopcH6u+Qky/a2Q///eOIl7U9WhEMnSYwZ7rqNmMGQw\n\
+    HQYDVR0OBBYEFMEPdaxTS5havWDJRtW6pOzr1pOOMB8GA1UdIwQYMBaAFMEPdaxT\n\
+    S5havWDJRtW6pOzr1pOOMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/\n\
+    AgEBMAoGCCqGSM49BAMDA2gAMGUCMDa2TefBEmKLebf6KziawLXeQRhqb4wcMgtE\n\
+    RUZ7JOojBC6CqN7xqPMIo2Pp9Pn6iwIxANlSkus723tk6OdeG33A++HwZ9KIXzU4\n\
+    cJUsEeE4pQ5exYACy2Nd+LVtmerw8ZF6xg==\n\
+    -----END CERTIFICATE-----",
+    ];
+
+    const INVALID_UDS_ROOT: &str = "-----BEGIN CERTIFICATE-----\n\
+    MIICJTCCAaugAwIBAgIUUo4NdEcdRuQdrm5Trm5x+qvx2LEwCgYIKoZIzj0EAwMw\n\
+    PzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUxEjAQ\n\
+    BgNVBAMMCVRFU1QgUk9PVDAgFw0yNDExMTQyMDEzNDRaGA8yMTI0MTAyMTIwMTM0\n\
+    NFowPzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQ8wDQYDVQQKDAZHb29nbGUx\n\
+    EjAQBgNVBAMMCVRFU1QgUk9PVDB2MBAGByqGSM49AgEGBSuBBAAiA2IABOGIoNBS\n\
+    sVs+mTjZpqOyoWTEOIvIIhuFfi49eqleyKTnekgXyXcJfqppsbqYcgPKaTbJmhU/\n\
+    iuOjaSIUlyf5tjJ7bIOAngopcH6u+Qky/a2Q///eOIl7U9WhEMnSYwZ7rqNmMGQw\n\
+    HQYDVR0OBBYEFMEPdaxTS5havWDJRtW6pOzr1pOOMB8GA1UdIwQYMBaAFMEPdaxT\n\
+    S5havWDJRtW6pOzr1pOOMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/\n\
+    AgEBMAoGCCqGSM49BAMDA2gAMGUCMDa2TefBEmKLebf6KziawLXeQRhqb4wcMgtE\n\
+    RUZ7JOojBC6CqN7xqPMIo2Pp9Pn6iwIxANlSkus723tk6OdeG33A++HwZ9KIXzU4\n\
+    cJUsEeE4pQ5exYACy2Ndthisisaproblem==\n\
+    -----END CERTIFICATE-----";
+
+    #[test]
+    fn verify_a_valid_cert_chain() {
+        let leaf = X509::from_pem(VALID_UDS_CHAIN[0].as_bytes()).unwrap();
+        let intermediate = X509::from_pem(VALID_UDS_CHAIN[1].as_bytes()).unwrap();
+        let root = X509::from_pem(VALID_UDS_CHAIN[2].as_bytes()).unwrap();
+        let certs = vec![root, intermediate, leaf];
+        let signer = "Test Signer".to_string();
+        let result = Csr::validate_uds_cert_path(&signer, &certs);
+        assert!(result.is_ok());
+    }
+
+    #[test]
+    fn make_sure_root_signature_is_checked() {
+        let leaf = X509::from_pem(VALID_UDS_CHAIN[0].as_bytes()).unwrap();
+        let intermediate = X509::from_pem(VALID_UDS_CHAIN[1].as_bytes()).unwrap();
+        let valid_root = X509::from_pem(VALID_UDS_CHAIN[2].as_bytes()).unwrap();
+        let invalid_root = X509::from_pem(INVALID_UDS_ROOT.as_bytes()).unwrap();
+
+        let valid_root_public_key = valid_root.public_key().unwrap();
+        let invalid_root_public_key = invalid_root.public_key().unwrap();
+        assert!(invalid_root_public_key.public_eq(&valid_root_public_key));
+
+        let certs = vec![invalid_root.clone(), intermediate.clone(), leaf.clone()];
+        let signer = "Test Signer".to_string();
+        let error = Csr::validate_uds_cert_path(&signer, &certs).unwrap_err();
+        assert!(error.to_string().contains("certificate signature failure"));
+
+        let mut intermediates = Stack::new().unwrap();
+        intermediates.push(intermediate).unwrap();
+
+        let mut builder = X509StoreBuilder::new().unwrap();
+        builder.add_cert(invalid_root).unwrap();
+        let store = builder.build();
+
+        let mut context = X509StoreContext::new().unwrap();
+        assert!(context.init(&store, &leaf, &intermediates, |c| c.verify_cert()).unwrap());
+    }
 }
 
 #[cfg(test)]
diff --git a/remote_provisioning/hwtrust/src/dice/chain.rs b/remote_provisioning/hwtrust/src/dice/chain.rs
index 9a606cf..3050a7c 100644
--- a/remote_provisioning/hwtrust/src/dice/chain.rs
+++ b/remote_provisioning/hwtrust/src/dice/chain.rs
@@ -1,10 +1,23 @@
 use crate::dice::Payload;
 use crate::publickey::PublicKey;
+use crate::session::RkpInstance;
 use anyhow::Result;
 use std::collections::HashSet;
 use std::fmt::{self, Display, Formatter};
 use thiserror::Error;
 
+/// The minimum number of RKP VM markers required in a valid [RKP VM DICE chain][rkpvm-chain].
+///
+/// An RKP VM chain must have a continuous presence of RKP VM markers, starting from a DICE
+/// certificate derived in the TEE and extending to the leaf DICE certificate.
+/// Therefore, a valid RKP VM chain should have at least two DICE certificates with RKP VM markers:
+///
+/// * One added in the pVM (managed by Android).
+/// * One added in the TEE (managed by vendors).
+///
+/// [rkpvm-chain]: https://android.googlesource.com/platform/packages/modules/Virtualization/+/main/docs/vm_remote_attestation.md
+const RKPVM_CHAIN_MIN_MARKER_NUM: usize = 2;
+
 /// Enumeration of the different forms that a DICE chain can take.
 #[derive(Clone, Debug, Eq, PartialEq)]
 pub enum ChainForm {
@@ -32,6 +45,15 @@ pub(crate) enum ValidationError {
     RepeatedSubject(usize, String),
     #[error("repeated key in payload {0}")]
     RepeatedKey(usize),
+    #[error("RKP VM chain has discontinuous marker at the {0}th payload")]
+    RkpVmChainHasDiscontinuousMarker(usize),
+    #[error(
+        "RKP VM chain does not have enough RKP VM markers. \
+         Minimal marker number:{RKPVM_CHAIN_MIN_MARKER_NUM}, actual marker number:{0}"
+    )]
+    NotEnoughRkpVmMarker(usize),
+    #[error("non RKP VM chain should not have continuous RKP VM markers")]
+    UnexpectedRkpVmMarkers,
 }
 
 impl ChainForm {
@@ -41,6 +63,14 @@ impl ChainForm {
             Self::Degenerate(degenerate) => degenerate.public_key(),
         }
     }
+
+    /// Return the length of the chain.
+    pub fn length(&self) -> usize {
+        match self {
+            ChainForm::Proper(chain) => chain.payloads.len(),
+            ChainForm::Degenerate(_) => 1,
+        }
+    }
 }
 
 impl Chain {
@@ -48,9 +78,17 @@ impl Chain {
     /// equal to the subject of the previous entry. The chain is not allowed to contain any
     /// repeated subjects or subject public keys as that would suggest something untoward has
     /// happened.
+    ///
+    /// Additionally, `rkp_instance` provides additional context for the validation of the chain
+    /// according to the instance-specific chain validation rules.
+    ///
+    /// * AVF instance: The chain is validated against the RKP VM chain validation rules.
+    /// * Non-AVF instances: The chain must not contain RKP VM markers that conform to the RKP VM
+    ///   chain validation rules.
     pub(crate) fn validate(
         root_public_key: PublicKey,
         payloads: Vec<Payload>,
+        rkp_instance: RkpInstance,
     ) -> Result<Self, ValidationError> {
         if payloads.is_empty() {
             return Err(ValidationError::NoPayloads);
@@ -79,7 +117,10 @@ impl Chain {
             }
             previous_subject = Some(payload.subject());
         }
-
+        match rkp_instance {
+            RkpInstance::Avf => validate_rkpvm_chain(&payloads),
+            _ => validate_non_rkpvm_chain(&payloads),
+        }?;
         Ok(Self { root_public_key, payloads })
     }
 
@@ -100,6 +141,30 @@ impl Chain {
     }
 }
 
+fn validate_rkpvm_chain(payloads: &[Payload]) -> Result<(), ValidationError> {
+    let mut rkpvm_marker_count = 0;
+    for (i, payload) in payloads.iter().enumerate() {
+        if payload.has_rkpvm_marker() {
+            rkpvm_marker_count += 1;
+        } else if rkpvm_marker_count > 0 {
+            return Err(ValidationError::RkpVmChainHasDiscontinuousMarker(i));
+        }
+    }
+    if rkpvm_marker_count < RKPVM_CHAIN_MIN_MARKER_NUM {
+        return Err(ValidationError::NotEnoughRkpVmMarker(rkpvm_marker_count));
+    }
+    Ok(())
+}
+
+/// Validates a DICE chain that is not associated with an RKP VM.
+///
+/// While non-RKP VM DICE chains might contain RKP VM markers in some vendor DICE certificates
+/// (e.g., Microdroid pVM DICE chain), they should not have a continuous presence of markers up to
+/// the last certificate in the chain.
+fn validate_non_rkpvm_chain(payloads: &[Payload]) -> Result<(), ValidationError> {
+    validate_rkpvm_chain(payloads).map_or(Ok(()), |_| Err(ValidationError::UnexpectedRkpVmMarkers))
+}
+
 impl Display for Chain {
     fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
         writeln!(f, "Root public key:")?;
@@ -187,7 +252,7 @@ impl Display for DegenerateChain {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::dice::{DiceMode, PayloadBuilder};
+    use crate::dice::{ConfigDescBuilder, DiceMode, PayloadBuilder};
     use crate::publickey::testkeys::{PrivateKey, ED25519_KEY_PEM, P256_KEY_PEM, P384_KEY_PEM};
 
     #[test]
@@ -195,7 +260,7 @@ mod tests {
         let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
         let keys = P256_KEY_PEM[1..4].iter().copied().enumerate();
         let payloads = keys.map(|(n, key)| valid_payload(n, key).build().unwrap()).collect();
-        Chain::validate(root_public_key, payloads).unwrap();
+        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
     }
 
     #[test]
@@ -203,14 +268,14 @@ mod tests {
         let root_public_key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
         let keys = [P256_KEY_PEM[0], P384_KEY_PEM[0]].into_iter().enumerate();
         let payloads = keys.map(|(n, key)| valid_payload(n, key).build().unwrap()).collect();
-        Chain::validate(root_public_key, payloads).unwrap();
+        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
     }
 
     #[test]
     fn chain_validate_fails_without_payloads() {
         let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
         let payloads = Vec::new();
-        let err = Chain::validate(root_public_key, payloads).unwrap_err();
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
         assert_eq!(err, ValidationError::NoPayloads);
     }
 
@@ -219,7 +284,7 @@ mod tests {
         let key = P256_KEY_PEM[0];
         let root_public_key = PrivateKey::from_pem(key).public_key();
         let payloads = vec![valid_payload(0, key).build().unwrap()];
-        let err = Chain::validate(root_public_key, payloads).unwrap_err();
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
         assert_eq!(err, ValidationError::RepeatedKey(0));
     }
 
@@ -231,7 +296,7 @@ mod tests {
             valid_payload(0, repeated_key).build().unwrap(),
             valid_payload(1, repeated_key).build().unwrap(),
         ];
-        let err = Chain::validate(root_public_key, payloads).unwrap_err();
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
         assert_eq!(err, ValidationError::RepeatedKey(1));
     }
 
@@ -245,7 +310,7 @@ mod tests {
             valid_payload(1, keys[1]).issuer(repeated).build().unwrap(),
             valid_payload(2, keys[2]).subject(repeated).build().unwrap(),
         ];
-        let err = Chain::validate(root_public_key, payloads).unwrap_err();
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
         assert_eq!(err, ValidationError::RepeatedSubject(2, repeated.into()));
     }
 
@@ -258,10 +323,95 @@ mod tests {
             valid_payload(0, P256_KEY_PEM[1]).subject(expected).build().unwrap(),
             valid_payload(1, P256_KEY_PEM[2]).issuer(wrong).build().unwrap(),
         ];
-        let err = Chain::validate(root_public_key, payloads).unwrap_err();
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
         assert_eq!(err, ValidationError::IssuerMismatch(1, wrong.into(), expected.into()));
     }
 
+    #[test]
+    fn non_rkpvm_chain_validate_with_discontinuous_markers() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
+        // This chain resembles a Microdroid pVM DICE chain where vendors add RKP VM markers in
+        // the vendor part of the chain, while pVM does not.
+        let payloads = vec![
+            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
+            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
+            valid_payload(2, P256_KEY_PEM[3]).build().unwrap(),
+        ];
+        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
+    }
+
+    #[test]
+    fn non_rkpvm_chain_validate_fails_with_continuous_markers() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
+        let payloads = vec![
+            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
+            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
+            valid_payload(2, P256_KEY_PEM[3]).config_desc(config_desc.clone()).build().unwrap(),
+        ];
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
+        assert_eq!(err, ValidationError::UnexpectedRkpVmMarkers);
+    }
+
+    #[test]
+    fn rkpvm_chain_validate_with_continuous_markers() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
+        let payloads = vec![
+            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
+            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
+            valid_payload(2, P256_KEY_PEM[3]).config_desc(config_desc.clone()).build().unwrap(),
+        ];
+        Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap();
+    }
+
+    #[test]
+    fn rkpvm_chain_validate_fails_with_no_marker() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let payloads = vec![valid_payload(0, P256_KEY_PEM[1]).build().unwrap()];
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
+        assert_eq!(err, ValidationError::NotEnoughRkpVmMarker(0));
+    }
+
+    #[test]
+    fn rkpvm_chain_validate_fails_with_not_enough_markers() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
+        let payloads = vec![
+            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
+            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc).build().unwrap(),
+        ];
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
+        assert_eq!(err, ValidationError::NotEnoughRkpVmMarker(1));
+    }
+
+    #[test]
+    fn rkpvm_chain_validate_fails_with_discontinous_markers() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
+        let payloads = vec![
+            valid_payload(0, P256_KEY_PEM[1]).config_desc(config_desc.clone()).build().unwrap(),
+            valid_payload(1, P256_KEY_PEM[2]).build().unwrap(),
+            valid_payload(2, P256_KEY_PEM[3]).config_desc(config_desc.clone()).build().unwrap(),
+        ];
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
+        assert_eq!(err, ValidationError::RkpVmChainHasDiscontinuousMarker(1));
+    }
+
+    #[test]
+    fn rkpvm_chain_validate_fails_last_payload_has_no_marker() {
+        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
+        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
+        let payloads = vec![
+            valid_payload(0, P256_KEY_PEM[1]).config_desc(config_desc.clone()).build().unwrap(),
+            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
+            valid_payload(2, P256_KEY_PEM[3]).build().unwrap(),
+        ];
+        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
+        assert_eq!(err, ValidationError::RkpVmChainHasDiscontinuousMarker(2));
+    }
+
     fn valid_payload(index: usize, pem: &str) -> PayloadBuilder {
         PayloadBuilder::with_subject_public_key(PrivateKey::from_pem(pem).public_key())
             .issuer(format!("component {}", index))
diff --git a/remote_provisioning/hwtrust/src/dice/entry.rs b/remote_provisioning/hwtrust/src/dice/entry.rs
index eca9c8a..357db72 100644
--- a/remote_provisioning/hwtrust/src/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/dice/entry.rs
@@ -82,6 +82,11 @@ impl Payload {
     pub fn authority_hash(&self) -> &[u8] {
         &self.authority_hash
     }
+
+    /// Returns whether the payload has an RKP VM marker.
+    pub fn has_rkpvm_marker(&self) -> bool {
+        self.config_desc.rkp_vm_marker()
+    }
 }
 
 impl Display for Payload {
diff --git a/remote_provisioning/hwtrust/src/main.rs b/remote_provisioning/hwtrust/src/main.rs
index f7f1de5..e2785fd 100644
--- a/remote_provisioning/hwtrust/src/main.rs
+++ b/remote_provisioning/hwtrust/src/main.rs
@@ -5,7 +5,7 @@ use clap::{Parser, Subcommand, ValueEnum};
 use hwtrust::dice;
 use hwtrust::dice::ChainForm;
 use hwtrust::rkp;
-use hwtrust::session::{Options, Session};
+use hwtrust::session::{Options, RkpInstance, Session};
 use std::io::BufRead;
 use std::{fs, io};
 
@@ -50,6 +50,10 @@ struct DiceChainArgs {
     /// Allow non-normal DICE chain modes.
     #[clap(long)]
     allow_any_mode: bool,
+    /// Validate the chain against the requirements of a specific RKP instance.
+    /// If not specified, the default RKP instance is used.
+    #[clap(value_enum, long, default_value = "default")]
+    rkp_instance: RkpInstance,
 }
 
 #[derive(Parser)]
@@ -77,6 +81,10 @@ struct CsrArgs {
     /// Allow non-normal DICE chain modes.
     #[clap(long)]
     allow_any_mode: bool,
+    /// Validate the chain against the requirements of a specific RKP instance.
+    /// If not specified, the default RKP instance is used.
+    #[clap(value_enum, long, default_value = "default")]
+    rkp_instance: RkpInstance,
 }
 
 #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
@@ -136,6 +144,7 @@ fn main() -> Result<()> {
 fn verify_dice_chain(args: &Args, sub_args: &DiceChainArgs) -> Result<Option<String>> {
     let mut session = session_from_vsr(args.vsr);
     session.set_allow_any_mode(sub_args.allow_any_mode);
+    session.set_rkp_instance(sub_args.rkp_instance);
     let chain = dice::ChainForm::from_cbor(&session, &fs::read(&sub_args.chain)?)?;
     if args.verbose {
         println!("{chain:#?}");
@@ -175,6 +184,7 @@ fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<Option<St
 fn parse_csr(args: &Args, sub_args: &CsrArgs) -> Result<Option<String>> {
     let mut session = session_from_vsr(args.vsr);
     session.set_allow_any_mode(sub_args.allow_any_mode);
+    session.set_rkp_instance(sub_args.rkp_instance);
     let input = &fs::File::open(&sub_args.csr_file)?;
     let csr = rkp::Csr::from_cbor(&session, input)?;
     if args.verbose {
diff --git a/remote_provisioning/hwtrust/src/publickey.rs b/remote_provisioning/hwtrust/src/publickey.rs
index 298c675..7978a14 100644
--- a/remote_provisioning/hwtrust/src/publickey.rs
+++ b/remote_provisioning/hwtrust/src/publickey.rs
@@ -23,7 +23,7 @@ pub(crate) enum KeyAgreementKind {
 }
 
 /// Enumeration of the kinds of elliptic curve keys that are supported.
-#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
 pub(crate) enum EcKind {
     P256,
     P384,
@@ -330,6 +330,10 @@ pub(crate) mod testkeys {
         MC4CAQAwBQYDK2VwBCIEILKW0KEeuieFxhDAzigQPE4XRTiQx+0/AlAjJqHmUWE6\n\
         -----END PRIVATE KEY-----\n"];
 
+    pub const ED25519_KEY_WITH_LEADING_ZEROS_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
+        MC4CAQAwBQYDK2VwBCIEIBDTK4d0dffOye5RD6HsgcOFoDTtvQH1tPmr9RjpadxJ\n\
+        -----END PRIVATE KEY-----\n"];
+
     /// A selection of elliptic curve P-256 private keys.
     pub const P256_KEY_PEM: &[&str] = &[
         "-----BEGIN PRIVATE KEY-----\n\
@@ -355,51 +359,57 @@ pub(crate) mod testkeys {
     ];
 
     /// A selection of EC keys that should have leading zeros in their coordinates
-    pub const P256_KEY_WITH_LEADING_ZEROS_PEM: &[&str] = &[
-        // 31 byte Y coordinate:
+    pub const EC2_KEY_WITH_LEADING_ZEROS_PEM: &[&str] = &[
+        // P256
+        // Public key has Y coordinate with most significant byte of 0x00
         "-----BEGIN PRIVATE KEY-----\n\
         MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCWbRSB3imI03F5YNVq\n\
         8AN8ZbyzW/h+5BQ53caD5VkWJg==\n\
         -----END PRIVATE KEY-----\n",
-        // 31 byte X coordinate:
+        // P256
+        // Public key has X coordinate with most significant byte of 0x00
         "-----BEGIN PRIVATE KEY-----\n\
         MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDe5E5WqNmCLxtsCNTc\n\
         UOb9CPXCn6l3CZpbrp0aivb+Bw==\n\
         -----END PRIVATE KEY-----\n",
-        // X & Y both have MSB set, and some stacks will add a padding byte
-        "-----BEGIN PRIVATE KEY-----\n\
-        MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCWOWcXPDEVZ4Qz3EBK\n\
-        uvSqhD9HmxDGxcNe3yxKi9pazw==\n\
-        -----END PRIVATE KEY-----\n",
-    ];
-
-    /// A selection of elliptic curve P-384 private keys.
-    pub const P384_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
-        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBMZ414LiUpcuNTNq5W\n\
-        Ig/qbnbFn0MpuZZxUn5YZ8/+2/tyXFFHRyQoQ4YpNN1P/+qhZANiAAScPDyisb21\n\
-        GldmGksI5g82hjPRYscWNs/6pFxQTMcxABE+/1lWaryLR193ZD74VxVRIKDBluRs\n\
-        uuHi+VayOreTX1/qlUoxgBT+XTI0nTdLn6WwO6vVO1NIkGEVnYvB2eM=\n\
-        -----END PRIVATE KEY-----\n"];
-
-    /// A selection of EC keys that should have leading zeros in their coordinates
-    pub const P384_KEY_WITH_LEADING_ZEROS_PEM: &[&str] = &[
-        // 47 byte Y coordinate:
+        // P384
+        // Public key has Y coordinate with most significant byte of 0x00
         "-----BEGIN PRIVATE KEY-----\n\
         ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDCzgVHCz7wgmSdb7/IixYik\n\
         3AuQceCtBTiFrJpgpGFluwgLUR0S2NpzIuty4M7xU74=\n\
         -----END PRIVATE KEY-----\n",
-        // 47 byte X coordinate:
+        // P384
+        // Public key has X coordinate with most significant byte of 0x00
         "-----BEGIN PRIVATE KEY-----\n\
         ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDBoW+8zbvwf5fYOS8YPyPEH\n\
         jHP71Vr1MnRYRp/yG1wbthW2XEu0UWbp4qrZ5WTnZPg=\n\
         -----END PRIVATE KEY-----\n",
-        // X & Y both have MSB set, and some stacks will add a padding byte
+    ];
+    pub const EC2_KEY_WITH_HIGH_BITS_SET_PEM: &[&str] = &[
+        // P256
+        // Public key has X & Y coordinate that both have most significant bit set,
+        // and some stacks will add a padding byte
+        "-----BEGIN PRIVATE KEY-----\n\
+        MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCWOWcXPDEVZ4Qz3EBK\n\
+        uvSqhD9HmxDGxcNe3yxKi9pazw==\n\
+        -----END PRIVATE KEY-----\n",
+        // P384
+        // Public key has X & Y coordinate that both have most significant bit set,
+        // and some stacks will add a padding byte
         "-----BEGIN PRIVATE KEY-----\n\
         ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDD2A69j5M/6oc6/WGoYln4t\n\
         Alnn0C6kpJz1EVC+eH6y0YNrcGamz8pPY4NkzUB/tj4=\n\
         -----END PRIVATE KEY-----\n",
     ];
 
+    /// A selection of elliptic curve P-384 private keys.
+    pub const P384_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
+        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBMZ414LiUpcuNTNq5W\n\
+        Ig/qbnbFn0MpuZZxUn5YZ8/+2/tyXFFHRyQoQ4YpNN1P/+qhZANiAAScPDyisb21\n\
+        GldmGksI5g82hjPRYscWNs/6pFxQTMcxABE+/1lWaryLR193ZD74VxVRIKDBluRs\n\
+        uuHi+VayOreTX1/qlUoxgBT+XTI0nTdLn6WwO6vVO1NIkGEVnYvB2eM=\n\
+        -----END PRIVATE KEY-----\n"];
+
     /// A selection of elliptic curve P-521 private keys.
     pub const P521_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
         MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBQuD8Db3jT2yPYR5t\n\
diff --git a/remote_provisioning/hwtrust/src/rkp.rs b/remote_provisioning/hwtrust/src/rkp.rs
index 14929f1..4404f97 100644
--- a/remote_provisioning/hwtrust/src/rkp.rs
+++ b/remote_provisioning/hwtrust/src/rkp.rs
@@ -5,7 +5,7 @@ mod device_info;
 mod factory_csr;
 mod protected_data;
 
-pub use csr::Csr;
+pub use csr::{Csr, CsrPayload};
 
 pub use device_info::{
     DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
diff --git a/remote_provisioning/hwtrust/src/rkp/csr.rs b/remote_provisioning/hwtrust/src/rkp/csr.rs
index 0f680fc..bacc2b0 100644
--- a/remote_provisioning/hwtrust/src/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/csr.rs
@@ -1,9 +1,22 @@
-use std::fmt;
+use std::{collections::HashMap, fmt};
+
+use openssl::x509::X509;
 
 use crate::{dice::ChainForm, rkp::DeviceInfo};
 
 use super::ProtectedData;
 
+/// Represents the payload of a Certificate Signing Request
+#[derive(Clone, Eq, PartialEq)]
+pub struct CsrPayload {
+    /// RKP VM or other?
+    pub certificate_type: String,
+    /// Describes the device that is requesting certificates.
+    pub device_info: DeviceInfo,
+    /// The keys to attest to when doing key attestation in one buffer
+    pub keys_to_sign: Vec<u8>,
+}
+
 /// Represents a Certificate Signing Request that is sent to an RKP backend to request
 /// certificates to be signed for a set of public keys. The CSR is partially generated by an
 /// IRemotelyProvisionedComponent HAL. The set of public keys to be signed is authenticated
@@ -22,13 +35,29 @@ pub enum Csr {
     },
     /// CSR V3 was introduced in Android T. This version drops encryption of the payload.
     V3 {
-        /// Describes the device that is requesting certificates.
-        device_info: DeviceInfo,
         /// The DICE chain for the device
         dice_chain: ChainForm,
+        /// X.509 certificate chain that certifies the dice_chain root key (UDS_pub)
+        uds_certs: HashMap<String, Vec<X509>>,
+        /// This is the challenge that is authenticated inside the signed data.
+        /// The signed data is version (3), certificate type, device info, and keys to sign
+        challenge: Vec<u8>,
+        /// csr payload
+        csr_payload: CsrPayload,
     },
 }
 
+impl Csr {
+    /// copy the DICE chain and return it
+    #[allow(dead_code)]
+    pub fn dice_chain(&self) -> ChainForm {
+        match self {
+            Csr::V2 { protected_data, .. } => protected_data.dice_chain(),
+            Csr::V3 { dice_chain, .. } => dice_chain.clone(),
+        }
+    }
+}
+
 impl fmt::Debug for Csr {
     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
         match self {
@@ -38,10 +67,11 @@ impl fmt::Debug for Csr {
                 .field("Challenge", &hex::encode(challenge))
                 .field("ProtectedData", &protected_data)
                 .finish(),
-            Csr::V3 { device_info, dice_chain } => fmt
+            Csr::V3 { dice_chain, uds_certs, csr_payload, .. } => fmt
                 .debug_struct("CSR V3")
-                .field("DeviceInfo", &device_info)
+                .field("DeviceInfo", &csr_payload.device_info)
                 .field("DiceChain", &dice_chain)
+                .field("UdsCerts", &uds_certs)
                 .finish(),
         }
     }
diff --git a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
index d64d6d1..a04f76f 100644
--- a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
@@ -1,7 +1,8 @@
 use crate::rkp::Csr;
-use crate::session::Session;
+use crate::session::{RkpInstance, Session};
 use anyhow::{bail, Result};
 use serde_json::{Map, Value};
+use std::str::FromStr;
 
 /// Represents a "Factory CSR", which is a JSON value captured for each device on the factory
 /// line. This JSON is uploaded to the RKP backend to register the device. We reuse the CSR
@@ -38,7 +39,9 @@ impl FactoryCsr {
     fn from_map(session: &Session, fields: Map<String, Value>) -> Result<Self> {
         let base64 = get_string_from_map(&fields, "csr")?;
         let name = get_string_from_map(&fields, "name")?;
-        let csr = Csr::from_base64_cbor(session, &base64)?;
+        let mut new_session = session.clone();
+        new_session.set_rkp_instance(RkpInstance::from_str(&name)?);
+        let csr = Csr::from_base64_cbor(&new_session, &base64)?;
         Ok(Self { csr, name })
     }
 }
@@ -126,12 +129,12 @@ mod tests {
     fn from_json_valid_v3_ed25519() {
         let json = fs::read_to_string("testdata/factory_csr/v3_ed25519_valid.json").unwrap();
         let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
-        if let Csr::V3 { device_info, dice_chain } = csr.csr {
-            assert_eq!(device_info, test_device_info(DeviceInfoVersion::V3));
+        if let Csr::V3 { dice_chain, uds_certs, csr_payload, .. } = csr.csr {
+            assert_eq!(csr_payload.device_info, test_device_info(DeviceInfoVersion::V3));
             let root_public_key = parse_pem_public_key_or_panic(
                 "-----BEGIN PUBLIC KEY-----\n\
-                MCowBQYDK2VwAyEA3FEn/nhqoGOKNok1AJaLfTKI+aFXHf4TfC42vUyPU6s=\n\
-                -----END PUBLIC KEY-----\n",
+                    MCowBQYDK2VwAyEArqr7jIIQ8TB1+l/Sh69eiSJL6t6txO1oLhpkdVSUuBk=\n\
+                    -----END PUBLIC KEY-----\n",
             );
             match dice_chain {
                 ChainForm::Proper(p) => {
@@ -140,6 +143,7 @@ mod tests {
                 }
                 ChainForm::Degenerate(d) => panic!("Parsed chain is not proper: {:?}", d),
             }
+            assert_eq!(uds_certs.len(), 0);
         } else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         }
@@ -176,13 +180,13 @@ mod tests {
     fn from_json_valid_v3_p256() {
         let json = fs::read_to_string("testdata/factory_csr/v3_p256_valid.json").unwrap();
         let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
-        if let Csr::V3 { device_info, dice_chain } = csr.csr {
-            assert_eq!(device_info, test_device_info(DeviceInfoVersion::V3));
+        if let Csr::V3 { dice_chain, uds_certs, csr_payload, .. } = csr.csr {
+            assert_eq!(csr_payload.device_info, test_device_info(DeviceInfoVersion::V3));
             let root_public_key = parse_pem_public_key_or_panic(
                 "-----BEGIN PUBLIC KEY-----\n\
-                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqT6ujVegwBbVWtsZeZmvN4WO3THx\n\
-                zpPPnt2rAOdqL9DSDZcIBbLas5xh9psaEaD0o/0KxlUVZplO/BPmRf3Ycg==\n\
-                -----END PUBLIC KEY-----\n",
+                    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh5NUV4872vKEL3XPSp8lfkV4AN3J\n\
+                KJti1Y5kbbR9ucTpSyoOjX9UmBCM/uuPU/MGXMWrgbBf3++02ALzC+V3eQ==\n\
+                    -----END PUBLIC KEY-----\n",
             );
             match dice_chain {
                 ChainForm::Proper(p) => {
@@ -191,11 +195,84 @@ mod tests {
                 }
                 ChainForm::Degenerate(d) => panic!("Parsed chain is not proper: {:?}", d),
             }
+            assert_eq!(uds_certs.len(), 0);
         } else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         }
     }
 
+    fn get_pem_or_die(cert: Option<&X509>) -> String {
+        let cert = cert.unwrap_or_else(|| panic!("Missing x.509 cert"));
+        let pem =
+            cert.to_pem().unwrap_or_else(|e| panic!("Failed to encode X.509 cert to PEM: {e}"));
+        String::from_utf8_lossy(&pem).to_string()
+    }
+
+    #[test]
+    fn from_json_valid_v3_p256_with_uds_certs() {
+        let json =
+            fs::read_to_string("testdata/factory_csr/v3_p256_valid_with_uds_certs.json").unwrap();
+        let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
+        if let Csr::V3 { uds_certs, .. } = csr.csr {
+            assert_eq!(uds_certs.len(), 1);
+            let chain = uds_certs.get("test-signer-name").unwrap_or_else(|| {
+                panic!("Unable to find 'test-signer-name' in UdsCerts: {uds_certs:?}")
+            });
+            assert_eq!(chain.len(), 2);
+            assert_eq!(
+                get_pem_or_die(chain.first()),
+                "-----BEGIN CERTIFICATE-----\n\
+                MIIBaDCCARqgAwIBAgIBezAFBgMrZXAwKzEVMBMGA1UEChMMRmFrZSBDb21wYW55\n\
+                MRIwEAYDVQQDEwlGYWtlIFJvb3QwHhcNMjQxMTA3MTMwOTMxWhcNNDkxMTAxMTMw\n\
+                OTMxWjArMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxEjAQBgNVBAMTCUZha2UgUm9v\n\
+                dDAqMAUGAytlcAMhAOgFrCrwxUYuOBSIk31/ykUsDP1vSRCzs8x2e8u8vumIo2Mw\n\
+                YTAdBgNVHQ4EFgQUtLO8kYH4qiyhGNKhkzZvxk7td94wHwYDVR0jBBgwFoAUtLO8\n\
+                kYH4qiyhGNKhkzZvxk7td94wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n\
+                AgQwBQYDK2VwA0EA1o8kJ3NTsY7B5/rRkJi8i/RZE1/0pQC2OUTOi8S7ZCkVdBJK\n\
+                7RyHo5/rVPXwVcsd3ZU1jZQalooek4mbDAWxAw==\n\
+                -----END CERTIFICATE-----\n"
+            );
+            assert_eq!(
+                get_pem_or_die(chain.get(1)),
+                "-----BEGIN CERTIFICATE-----\n\
+                MIIBmzCCAU2gAwIBAgICAcgwBQYDK2VwMCsxFTATBgNVBAoTDEZha2UgQ29tcGFu\n\
+                eTESMBAGA1UEAxMJRmFrZSBSb290MB4XDTI0MTEwNzEzMDkzMVoXDTQ5MTEwMTEz\n\
+                MDkzMVowLjEVMBMGA1UEChMMRmFrZSBDb21wYW55MRUwEwYDVQQDEwxGYWtlIENo\n\
+                aXBzZXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmCOHpHOZzSZvp1frFACgm\n\
+                Itnj33YAKYseZfT68AlrN4UtC5boNVU5wjKWQFRcOlup5kxX2UVlb+jFCO7eskFU\n\
+                o2MwYTAdBgNVHQ4EFgQU7KrNWsfWHijorD/+b5TBIZCzj3MwHwYDVR0jBBgwFoAU\n\
+                tLO8kYH4qiyhGNKhkzZvxk7td94wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\n\
+                BAMCAgQwBQYDK2VwA0EAuDdXCHTYt92UxftrDJnKXxjtDBCYMqXSlIuYw8p1W/UP\n\
+                Ccerp/jUng8ELnfPj2ZTkTP2+NhvwsYKvbaxaz9pDA==\n\
+                -----END CERTIFICATE-----\n"
+            );
+        } else {
+            panic!("Parsed CSR was not V3: {:?}", csr);
+        }
+    }
+
+    #[test]
+    fn from_json_v3_p256_with_mismatch_uds_certs() {
+        let json =
+            fs::read_to_string("testdata/factory_csr/v3_p256_mismatched_uds_certs.json").unwrap();
+        let err = FactoryCsr::from_json(&Session::default(), &json).unwrap_err();
+        assert!(
+            err.to_string().contains("does not match the DICE chain root"),
+            "Expected mismatch between UDS_pub and UdsCerts leaf"
+        );
+    }
+
+    #[test]
+    fn from_json_v3_p256_with_extra_uds_cert_in_chain() {
+        let json = fs::read_to_string("testdata/factory_csr/v3_p256_extra_uds_cert_in_chain.json")
+            .unwrap();
+        let err = FactoryCsr::from_json(&Session::default(), &json).unwrap_err();
+        assert!(
+            err.to_string().contains("Verified chain doesn't match input"),
+            "Expected cert validation to fail due to extra cert in UDS chain"
+        );
+    }
+
     #[test]
     fn from_json_name_is_missing() {
         let mut value = json_map_from_file("testdata/factory_csr/v2_ed25519_valid.json").unwrap();
@@ -236,4 +313,27 @@ mod tests {
         let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
         assert_eq!(csr.name, "default");
     }
+
+    #[test]
+    fn from_json_valid_v3_avf_with_rkpvm_markers() {
+        let json = fs::read_to_string("testdata/factory_csr/v3_avf_valid_with_rkpvm_markers.json")
+            .unwrap();
+        let mut session = Session::default();
+        session.set_allow_any_mode(true);
+        let csr = FactoryCsr::from_json(&session, &json).unwrap();
+        assert_eq!(csr.name, "avf");
+    }
+
+    #[test]
+    fn from_json_v3_p256_with_private_key() {
+        let json =
+            fs::read_to_string("testdata/factory_csr/v3_p256_with_private_key.json").unwrap();
+        let err = FactoryCsr::from_json(&Session::default(), &json).unwrap_err();
+        let source = err.source().unwrap().to_string();
+        assert!(
+            source.contains("disallowed labels should be empty")
+                && source
+                    .contains("12953f77f0726491a09c5b2d134a26a8a657dbc170c4036ffde81e881e0acd03")
+        );
+    }
 }
diff --git a/remote_provisioning/hwtrust/src/rkp/protected_data.rs b/remote_provisioning/hwtrust/src/rkp/protected_data.rs
index a4fa5bd..00b09c1 100644
--- a/remote_provisioning/hwtrust/src/rkp/protected_data.rs
+++ b/remote_provisioning/hwtrust/src/rkp/protected_data.rs
@@ -26,6 +26,10 @@ impl ProtectedData {
     pub fn new(mac_key: Vec<u8>, dice_chain: ChainForm, uds_certs: Option<UdsCerts>) -> Self {
         Self { mac_key, dice_chain, uds_certs }
     }
+
+    pub fn dice_chain(&self) -> ChainForm {
+        self.dice_chain.clone()
+    }
 }
 
 impl UdsCerts {
diff --git a/remote_provisioning/hwtrust/src/session.rs b/remote_provisioning/hwtrust/src/session.rs
index b9701dc..16e9c22 100644
--- a/remote_provisioning/hwtrust/src/session.rs
+++ b/remote_provisioning/hwtrust/src/session.rs
@@ -1,22 +1,58 @@
 //! Defines the context type for a session handling hwtrust data structures.
 
 use crate::dice::ProfileVersion;
+use anyhow::bail;
+use clap::ValueEnum;
 use std::ops::RangeInclusive;
+use std::str::FromStr;
 
 /// The context for a session handling hwtrust data structures.
-#[derive(Default, Debug)]
+#[derive(Clone, Default, Debug)]
 pub struct Session {
     /// Options that control the behaviour during this session.
     pub options: Options,
 }
 
 /// Options that control the behaviour of a session.
-#[derive(Default, Debug)]
+#[derive(Clone, Default, Debug)]
 pub struct Options {
     /// The range of supported Android Profile for DICE versions.
     pub dice_profile_range: DiceProfileRange,
     /// Allows DICE chains to have non-normal mode values.
     pub allow_any_mode: bool,
+    /// The RKP instance associated to the session.
+    pub rkp_instance: RkpInstance,
+}
+
+/// The set of RKP instances associated to the session.
+#[derive(Clone, Copy, Default, Debug, ValueEnum)]
+pub enum RkpInstance {
+    /// The DICE chain is associated to the default instance.
+    #[default]
+    Default,
+    /// The DICE chain is associated to the strongbox instance.
+    Strongbox,
+    /// The DICE chain is associated to the avf instance.
+    /// This option performs additional checks to ensure the chain conforms to the requirements
+    /// for an RKP VM chain. For detailed information, refer to the RKP VM specification:
+    /// https://android.googlesource.com/platform/packages/modules/Virtualization/+/main/docs/vm_remote_attestation.md#rkp-vm-marker
+    Avf,
+    /// The DICE chain is associated to the Widevine instance.
+    Widevine,
+}
+
+impl FromStr for RkpInstance {
+    type Err = anyhow::Error;
+
+    fn from_str(s: &str) -> Result<Self, Self::Err> {
+        match s {
+            "default" => Ok(RkpInstance::Default),
+            "strongbox" => Ok(RkpInstance::Strongbox),
+            "avf" => Ok(RkpInstance::Avf),
+            "widevine" => Ok(RkpInstance::Widevine),
+            _ => bail!("invalid RKP instance: {}", s),
+        }
+    }
 }
 
 impl Session {
@@ -24,6 +60,11 @@ impl Session {
     pub fn set_allow_any_mode(&mut self, allow_any_mode: bool) {
         self.options.allow_any_mode = allow_any_mode
     }
+
+    /// Sets the RKP instance associated to the session.
+    pub fn set_rkp_instance(&mut self, rkp_instance: RkpInstance) {
+        self.options.rkp_instance = rkp_instance
+    }
 }
 
 /// An inclusive range of Android Profile for DICE versions.
@@ -64,7 +105,7 @@ impl Options {
         Self {
             dice_profile_range: DiceProfileRange::new(
                 ProfileVersion::Android13,
-                ProfileVersion::Android13,
+                ProfileVersion::Android15,
             ),
             ..Default::default()
         }
@@ -75,7 +116,7 @@ impl Options {
         Self {
             dice_profile_range: DiceProfileRange::new(
                 ProfileVersion::Android14,
-                ProfileVersion::Android14,
+                ProfileVersion::Android15,
             ),
             ..Default::default()
         }
diff --git a/remote_provisioning/hwtrust/testdata/csr/v3_csr.base64 b/remote_provisioning/hwtrust/testdata/csr/v3_csr.base64
index 340325c..63874bf 100644
--- a/remote_provisioning/hwtrust/testdata/csr/v3_csr.base64
+++ b/remote_provisioning/hwtrust/testdata/csr/v3_csr.base64
@@ -1 +1 @@
-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
+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
diff --git a/remote_provisioning/hwtrust/testdata/csr/v3_csr_avf.cbor b/remote_provisioning/hwtrust/testdata/csr/v3_csr_avf.cbor
new file mode 100644
index 0000000..4227d6f
Binary files /dev/null and b/remote_provisioning/hwtrust/testdata/csr/v3_csr_avf.cbor differ
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/all_versions_valid.json b/remote_provisioning/hwtrust/testdata/factory_csr/all_versions_valid.json
index 3ca11c1..62eff67 100644
--- a/remote_provisioning/hwtrust/testdata/factory_csr/all_versions_valid.json
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/all_versions_valid.json
@@ -1,10 +1,8 @@
 {"csr":"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","name":"default","serialno":"fake-device-0"}
 
 {"csr":"hIKvZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsZ3ZlcnNpb24CaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjoFABAgMEBQYHCAkKCwwNDg8QhEOhAQOhBVABapIU83y82Kdu6BJ8kkVPWQIiqO6n/WEbgqyajycwMpzCyK8+Iw+tCHozqTfWRfnuiYW0tN5FyqWNs1qkWMRhhirxgxnp+fjKTRiOK7fz4lL3PYqSH2o3h2viWWL1PfjtJyrSFQjspQqINX74kU9bNwBTun6FuZEHxNQYzXI9fLXayehu4NJsgzmiL+O/SFkA618XQKCOHBPRLA30iY6gkzUhsSj1+ytBtyIkA6EbXUcPdKnDMuwgpyRP3OBcZHDK3XzrYixd897zPHtvN00ZdQHRbe2Dntf5hyzrMm9cbko9hiPsUM7f1DuIANFwj1iKBIC+kv7wx5RfuS5SClm5qa5CHbA1IZ3xMDIDLCjN74/3O2yRfIBb1+9aEP3Z33MhG4olEZ2q+uC3dbtYit9elkGNuBDyNb5D76OwGCFux5UTFyynoGxVtAznp6JVaI3ZEiYhyrT+MkNUCtuGZ0DjJkFHcLLrXMyTJSjq1+demfiYyr+Ir7T/1TQi1Y+GJGQIdFHA9fW6QYIZ9xE0sfTd1Zq/wn2YQT8pdzid0VClzi/x2LDbk3mtaCrQhBYZ3VrHveQlQVVHHPriKcsQJYBFnMNS6+JNuEZ4++TEwWbF3hiUmXphgo0GecXQ7bl4q/1RuPzZPsBLkUsExhoh65Ewn9kMc+iHupOQCNDILJDik3V07iuwQ5SlrVUsiby7egZaDVDFy5GbiOczgi2BmZmz2jcsePHJe0s7TAwhYFzWqTwMl8tAgYNEoQE4GKIEWCA1c7c/oIqAibEmZ+nLfHWhrwJh/G5lA5E700t9FJQ+RiCkAQIgASFYIGt72uKbTr5Rccjh4/GcgZqjcoBpA3xUIxdz6XsES2dlIlggSS0rPAjiluqGWPBsSbLBuP6hkH4AL9p7zYdpamznZ1H2hEOhAQWgWJeCpAECIAEhWCCwux4tKxu7COAyzC6QYz2Vc7Tbnydp0JAiC/fT2qeQuiJYIMjS4s2/AKyORPK4QAha/b0EckaA6sVTTpazGH8MDFfmpAECIAEhWCBMvwVxq9o8qwDx058dQJibhQxeuYOHnG6VxGYP+vJBryJYIOr3B/2Ll0vM5Yzc2E9PJ8iPbkc2Ts43waji3Fc7WOl+WCDC8jMqc3vVO7A7vRzY8bSTNRX5prg73a1LIhPmLHpdxQ==","name":"default","serialno":"fake-device-0"}
-{"csr":"hQGggqUBAQMnIAYhWCDcUSf+eGqgY4o2iTUAlot9Moj5oVcd/hN8Lja9TI9TqyNYINbpTLuXQGzX+WCPNsTTPjzF15o8yYWFptEThYpij2ZQhEOhASegWQEoqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWHGmAQIDJiABIVgghPaHz8YJlc4ztK06hmbiC1wmZtM1Air1zQVt8YQq97oiWCBUYQIjz9WbS1XWQQ93CQesOdJYr5XCxekLVTdTsBVusSNYIQCI+fLc8cPFJ7Gfq54OgKRtm7R81ddA8pWjbU3eOQMezzoAR0RYQSBYQDXNmA9jnnpPYldM3QATMpMr4IyqGAzXy3AkziLi397fnNalisoGl9tSk2XJEA2f2S2ALw+Bphu2zeO3P6oyRwaEQ6EBJqBZAg+CWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6YQDZ0tFWU1JTlSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCAyw/UU6r9gQ0l5AcBLebbEa+U/dSIRsO5CKLqAtYatfiJYIDdXT+o28hydMserzyH5A6LG1sUcPJP5a+Wevgefd4d8I1ggW69SlC4b1bAb9tYsmxBrQlLJh+qvv2aDw2BX2QvzUpymAQIDJiABIVggRwQMKiwiURobXaQ7N7MR1Ck5t1Kh5JfvgWk4s2GRpdQiWCCK1PDZ+ZNRe8rTAGzxz7CBPM8FXqOSTumV2B001eFmGyNYIQDal8DBe1tGEKNgBPtTgYFt1gFoVPwOzvhqWluxLo6QPlhA+x5DwVtGqPBFKIwEYW+rKzo/4rdHJzmUnU/2OYXpJURsG7sQnMlf+TxUmjJkaJ2zZ2Zy/ZVoxWyAP+wEVcJjc6FrZmluZ2VycHJpbnR4O2JyYW5kMS9wcm9kdWN0MS9kZXZpY2UxOjExL2lkLzIwMjEwODA1LjQyOnVzZXIvcmVsZWFzZS1rZXlz","name":"default","serialno":"fake-device-0"}
+{"csr":"hQGggqUBAgMmIAEhWCAFA88ryDmPw3Nt+k4fthkYvH7C6XVD3TqDCBLusLSUhSJYILTR5v5W/Lhq3C+Ow4plkhO8DCEPWCa5Te45m7LbsoCqhEOhASagWQEEqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWE2lAQIDJiABIVggTeUEOb5wUDZ9tny7zhy9r8ZZJeHU9bBQ/8oOHTDchukiWCAiILrze1MlgqrCsq7DubG2ms3YGUStSHh5kRhpHlczaToAR0RYQSBYQEyplwBT8+uQTCFoq6oNfzf7M8v1BQsygTM3F4WMFHaBbAicVRFfA7mH2/88pUwH+3Bx+pRBM/Xte+TDs7yLbbOEQ6EBJqBZAhCCWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6oQDZ2tleW1pbnSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCAIcRLSuJEh0KdPfQdNhX1lBjedQyLN+wHfPy/vA/JRyiJYILKVOJMqomKhuB515ua4G9OHklo74PNdeMielqHZPuXLI1ghAInXEclLOmZBnnQAhAK03W9edlVVkB1jo5mEk/93v91MpgECAyYgASFYIEUbO5A+BFqpxzthOpBkiuut2fx7MnXVMLHJNI/jett5IlggtzxBaw0DAkdo5TfKXy3u25qYTRE4EZNUjcj4SQ2DUfMjWCEAm1vSCQ9ZBLHQnLKDrwQbyvORu4BgjcTIKF5r2kBzOnNYQIpG3WZu1LnGOwZjX5nS0FLfy+NF8NnGxDJ46gpSn/+hZg1RmTfTfdmzCbm23+xGl2eqDnbVb1z+ZvpYcpmKHWGha2ZpbmdlcnByaW50eDticmFuZDEvcHJvZHVjdDEvZGV2aWNlMToxMS9pZC8yMDIxMDgwNS40Mjp1c2VyL3JlbGVhc2Uta2V5cw==","name":"default","serialno":"fake-device-0"}
 
 
-
-{"csr":"hQGggqYBAgMmIAEhWCCpPq6NV6DAFtVa2xl5ma83hY7dMfHOk8+e3asA52ov0CJYININlwgFstqznGH2mxoRoPSj/QrGVRVmmU78E+ZF/dhyI1ggEpU/d/ByZJGgnFstE0omqKZX28FwxANv/egeiB4KzQOEQ6EBJqBZASepAWZpc3N1ZXICZ3N1YmplY3Q6AEdEUFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEUlgguJZU4iyk0kqcDkURyPJj8GYNLiBIlpAU9FRjxPQ5MDg6AEdEU1WhOgABEXFuY29tcG9uZW50X25hbWU6AEdEVFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEVkEBOgBHRFdYcKYBAgMmIAEhWCCFTXTgD0Ij31zMNwkMHEHeyJ4R0PVQToYItbHWSBX9CiJYIDFaX3N0+wapfXrb4+8DKNU5VHnDnvb1rsC3cjAlb50lI1ggFFtuT3XEL9kjvKY93UOGxCkqIT8XK4czC8ezX6ykBfk6AEdEWEEgWEBtIzOvyF6PIVIYljj7CfahW+MgOpd4it7iAxvkssZYYXh78NlKJFR0E1G1DdLMfRwSajaXO3wDqG5AbfiUeVy5hEOhASagWQIQglggAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyBZAeqEA2dLRVlNSU5UrmVicmFuZGZHb29nbGVlZnVzZWQBZW1vZGVsZW1vZGVsZmRldmljZWZkZXZpY2VncHJvZHVjdGVwaXhlbGh2Yl9zdGF0ZWVncmVlbmpvc192ZXJzaW9uYjEybG1hbnVmYWN0dXJlcmZHb29nbGVtdmJtZXRhX2RpZ2VzdE8RIjNEVWZ3iJmqu8zd7v9uc2VjdXJpdHlfbGV2ZWxjdGVlcGJvb3RfcGF0Y2hfbGV2ZWwaATSMYnBib290bG9hZGVyX3N0YXRlZmxvY2tlZHJzeXN0ZW1fcGF0Y2hfbGV2ZWwaATSMYXJ2ZW5kb3JfcGF0Y2hfbGV2ZWwaATSMY4KmAQIDJiABIVggN9Y9nAF4lYrevH81hTwirMeHF9lyAXF7MCqiyuY5xXQiWCAMhrBKF2SHHYuLVGMWR/mAYErcLT0JyEG5J690NeM6MSNYIQD/zJBROsd66g7qA9O/HQXpdefN9GgMOhnDQRvUFpUya6YBAgMmIAEhWCCQpbufcGMc+xy60H0wPzbecB81xipX2TDC2LF41FrYeiJYIC4eKnTSeL7astnASAPMGEhgXhUtKJ2vAy86DTvTvZcLI1ghAOMuH5yRYDLMJzAceHafd4Abe1QORt5vqCO/eHun6BnpWED2SzeNFno+SzaMHQ/A6G9JnZqu+teAXGT9eD6MW5ilZ+pFew8+xCnv4Kyk2bABjp2XCsPxkkBjhllDbJakWUz1oWtmaW5nZXJwcmludHg7YnJhbmQxL3Byb2R1Y3QxL2RldmljZTE6MTEvaWQvMjAyMTA4MDUuNDI6dXNlci9yZWxlYXNlLWtleXM=","name":"default","serialno":"fake-device-0"}
-
+{"csr":"hQGggqUBAgMmIAEhWCDKTdn6IFncDPnaAChyo8ak6eyafDY5e+co5sRzfpkahCJYIBfpvHTM0iJ4WoRaqiWF++0SNIUAEuEuUg9Xb2ur6282hEOhASagWQEEqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWE2lAQIDJiABIVggU87omVmlmV40czErZsPKbNw9J2PeOINbXVcZJTUBzBUiWCDVw8LMNrFhnJbVpciCkCPVIBx+ZUYBQ6bbLdBox4n5mDoAR0RYQSBYQET95UbnXnCHi9pfS2dn6WodTP9IcXJzpUy/hdqxsQNnvCTSwhr+ITmwqQuIOjC5SXjmwuq8/2ZnQVA215JS4RiEQ6EBJqBZAg+CWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6YQDZ2tleW1pbnSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCAYnPqvdCkq2irK3P3eY7FbjcLBay0rItkudm7nJt/n+SJYIEoUh/WU1qvLtx+pG8NnOM2SHZxACXznduzxIWsbpGiII1ggZOHYTnb+Db97z2OjCFLr/pGp3OJSL9cd2gGxWHdmJRimAQIDJiABIVggJ2tLL43lr7eA87qC/UlyZIphDYLDJqT/b8Oq2vJP33QiWCCsdxh747dxoFUu6IE/NOcRZDAmvP1Mz3G1rJUQdcyzdSNYIQDSyCyudZ6RXDW9xX8abxzoNPyfPYMAwJX78Iqmr6x0flhAxZDUV9zh5/VIs/Wghx8aQoQQ2PdftdHOtFEq5bsg1GnYrKWOvHcIYFJQpgth/rzT8mdWYmE6gkwHJBSXnYH7f6FrZmluZ2VycHJpbnR4O2JyYW5kMS9wcm9kdWN0MS9kZXZpY2UxOjExL2lkLzIwMjEwODA1LjQyOnVzZXIvcmVsZWFzZS1rZXlz","name":"default","serialno":"fake-device-0"}
 
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_avf_valid_with_rkpvm_markers.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_avf_valid_with_rkpvm_markers.json
new file mode 100644
index 0000000..d02d5ef
--- /dev/null
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_avf_valid_with_rkpvm_markers.json
@@ -0,0 +1 @@
+{"csr":"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g92LmzoAR0RWQQE6AEdEV1gtpQEBAycEgQIgBiFYINyL7v0Vb4TTUGmx7icLfVeKKiTMUIFirkTiQrF6zS84OgBHRFhBIFhA2m6Bqnkx/l5w+hQx6VQKg9JQB8VuAFl3di2DVQCZKlm2x62XO46RMrWE7ivSk6DFkQTu6vbegFogGe0IkJBvCIRDoQEnoFkBKIJYQHG+omtE/FjWrAMhzqtVdu4MWdLSCrQNpWgHw7L2f/SuQChKzvRalY9KmCzNy7MTL7r8oOuU9toI5CikxaGukzdY44QDZnJrcC12ba1lYnJhbmRoYW9zcC1hdmZlZnVzZWQBZW1vZGVsY2F2ZmZkZXZpY2VjYXZmZ3Byb2R1Y3RjYXZmaHZiX3N0YXRlY2F2ZmxtYW51ZmFjdHVyZXJoYW9zcC1hdmZtdmJtZXRhX2RpZ2VzdEEBbnNlY3VyaXR5X2xldmVsY2F2ZnBib290X3BhdGNoX2xldmVsGgE010pwYm9vdGxvYWRlcl9zdGF0ZWNhdmZyc3lzdGVtX3BhdGNoX2xldmVsGgADFqJydmVuZG9yX3BhdGNoX2xldmVsGgE010qAWEAKqD5yiJgdmkU1ibWeuYaa0y4fl6jsLC/7B20Z6pW3yrIDXV4/c6ipTFuUtAWaKARuApNOwMN8ut0zS6uusg4JoWtmaW5nZXJwcmludHhUQW5kcm9pZC9hb3NwX2FybTY0L2dlbmVyaWNfYXJtNjQ6VmFuaWxsYUljZUNyZWFtL01BSU4vZW5nLmFsaWNleTp1c2VyZGVidWcvdGVzdC1rZXlz","name":"avf","serialno":"fake-device-0"}
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_ed25519_valid.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_ed25519_valid.json
index 4767dc1..1573427 100644
--- a/remote_provisioning/hwtrust/testdata/factory_csr/v3_ed25519_valid.json
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_ed25519_valid.json
@@ -1 +1 @@
-{"csr":"hQGggqUBAQMnIAYhWCDcUSf+eGqgY4o2iTUAlot9Moj5oVcd/hN8Lja9TI9TqyNYINbpTLuXQGzX+WCPNsTTPjzF15o8yYWFptEThYpij2ZQhEOhASegWQEoqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWHGmAQIDJiABIVgghPaHz8YJlc4ztK06hmbiC1wmZtM1Air1zQVt8YQq97oiWCBUYQIjz9WbS1XWQQ93CQesOdJYr5XCxekLVTdTsBVusSNYIQCI+fLc8cPFJ7Gfq54OgKRtm7R81ddA8pWjbU3eOQMezzoAR0RYQSBYQDXNmA9jnnpPYldM3QATMpMr4IyqGAzXy3AkziLi397fnNalisoGl9tSk2XJEA2f2S2ALw+Bphu2zeO3P6oyRwaEQ6EBJqBZAg+CWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6YQDZ0tFWU1JTlSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCAyw/UU6r9gQ0l5AcBLebbEa+U/dSIRsO5CKLqAtYatfiJYIDdXT+o28hydMserzyH5A6LG1sUcPJP5a+Wevgefd4d8I1ggW69SlC4b1bAb9tYsmxBrQlLJh+qvv2aDw2BX2QvzUpymAQIDJiABIVggRwQMKiwiURobXaQ7N7MR1Ck5t1Kh5JfvgWk4s2GRpdQiWCCK1PDZ+ZNRe8rTAGzxz7CBPM8FXqOSTumV2B001eFmGyNYIQDal8DBe1tGEKNgBPtTgYFt1gFoVPwOzvhqWluxLo6QPlhA+x5DwVtGqPBFKIwEYW+rKzo/4rdHJzmUnU/2OYXpJURsG7sQnMlf+TxUmjJkaJ2zZ2Zy/ZVoxWyAP+wEVcJjc6FrZmluZ2VycHJpbnR4O2JyYW5kMS9wcm9kdWN0MS9kZXZpY2UxOjExL2lkLzIwMjEwODA1LjQyOnVzZXIvcmVsZWFzZS1rZXlz","name":"default","serialno":"fake-device-0"}
+{"csr":"hQGggqQBAQMnIAYhWCCuqvuMghDxMHX6X9KHr16JIkvq3q3E7WguGmR1VJS4GYRDoQEnoFkBBKkBZmlzc3VlcgJnc3ViamVjdDoAR0RQWCBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVToAR0RSWCC4llTiLKTSSpwORRHI8mPwZg0uIEiWkBT0VGPE9DkwODoAR0RTVaE6AAERcW5jb21wb25lbnRfbmFtZToAR0RUWCBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVToAR0RWQQE6AEdEV1hNpQECAyYgASFYINKU6ND26fY6YU6YExBpVAE0e2MIDRgKH6up0S1EIpUbIlggPxzVj7NqNqZ+vgzmrJMiC/jprFkhxXZ9n3sH7Fdvxss6AEdEWEEgWEANQKueR0rQxEjlmPgmQhDBH8uI9kCi2ymjk7kHqWFbuGkUH6jJMlOeKW30P6krldZsMfqKmnrlRnMMH3D8snIGhEOhASagWQIOglggAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyBZAeiEA2drZXltaW50rmVicmFuZGZHb29nbGVlZnVzZWQBZW1vZGVsZW1vZGVsZmRldmljZWZkZXZpY2VncHJvZHVjdGVwaXhlbGh2Yl9zdGF0ZWVncmVlbmpvc192ZXJzaW9uYjEybG1hbnVmYWN0dXJlcmZHb29nbGVtdmJtZXRhX2RpZ2VzdE8RIjNEVWZ3iJmqu8zd7v9uc2VjdXJpdHlfbGV2ZWxjdGVlcGJvb3RfcGF0Y2hfbGV2ZWwaATSMYnBib290bG9hZGVyX3N0YXRlZmxvY2tlZHJzeXN0ZW1fcGF0Y2hfbGV2ZWwaATSMYXJ2ZW5kb3JfcGF0Y2hfbGV2ZWwaATSMY4KmAQIDJiABIVggMrQ+p3SwhERu4mo8LdqbvnHQbGTK0m6NrI2ZXiAK1W0iWCDxjYLmdGTBBIEfWPBfGE4Ivx6CkDW4hL71I+e1ZEoJ3yNYIDwfAY7pSESH5NYrMchGzM1vMf3O0Zx90FVAXycItjrcpgECAyYgASFYIPwJwytXkosb9J4kiZfX1ICWcX0fOU92yDtOqgMM0gcfIlgg7NPZnSb3cvXlnyA28mjBdIaC0C/+UJ8FxGjxkOHJ0psjWCBOA9RQEyAEcPFjbUWzrd2kAAnGDa2eLC5GJMDGx8OrmVhAbQT0vVrvS14sTVole7LNJ3rFvkV1WHwMP/KFoSvsJAZU1/OMGQyjZ+65CcT9xN6rFXOT46ceORmO45VEvHsrYaFrZmluZ2VycHJpbnR4O2JyYW5kMS9wcm9kdWN0MS9kZXZpY2UxOjExL2lkLzIwMjEwODA1LjQyOnVzZXIvcmVsZWFzZS1rZXlz","name":"default","serialno":"fake-device-0"}
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_extra_uds_cert_in_chain.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_extra_uds_cert_in_chain.json
new file mode 100644
index 0000000..a21c9f1
--- /dev/null
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_extra_uds_cert_in_chain.json
@@ -0,0 +1 @@
+{"csr":"hQGhcHRlc3Qtc2lnbmVyLW5hbWWDWQFsMIIBaDCCARqgAwIBAgIBezAFBgMrZXAwKzEVMBMGA1UEChMMRmFrZSBDb21wYW55MRIwEAYDVQQDEwlGYWtlIFJvb3QwHhcNMjQxMTA3MTcxNjU3WhcNNDkxMTAxMTcxNjU3WjArMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxEjAQBgNVBAMTCUZha2UgUm9vdDAqMAUGAytlcAMhABFIqCDacyfMpq0fHbnyZjDn7Wig5AcJRSwfRIDabQhio2MwYTAdBgNVHQ4EFgQUn4FXnU8P8p1nTIVNIH+XdMxmZxEwHwYDVR0jBBgwFoAUn4FXnU8P8p1nTIVNIH+XdMxmZxEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwBQYDK2VwA0EAWtIs1iGYF/aJwa/4fDGBtB7OUxgccFKoQmGReFiaSlA5/VPBautjtyspYwnwM11gi4YAvWhhah7nHTm3Q95JCVkBbDCCAWgwggEaoAMCAQICAXswBQYDK2VwMCsxFTATBgNVBAoTDEZha2UgQ29tcGFueTESMBAGA1UEAxMJRmFrZSBSb290MB4XDTI0MTEwNzE3MTY1N1oXDTQ5MTEwMTE3MTY1N1owKzEVMBMGA1UEChMMRmFrZSBDb21wYW55MRIwEAYDVQQDEwlGYWtlIFJvb3QwKjAFBgMrZXADIQARSKgg2nMnzKatHx258mYw5+1ooOQHCUUsH0SA2m0IYqNjMGEwHQYDVR0OBBYEFJ+BV51PD/KdZ0yFTSB/l3TMZmcRMB8GA1UdIwQYMBaAFJ+BV51PD/KdZ0yFTSB/l3TMZmcRMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMAUGAytlcANBAFrSLNYhmBf2icGv+HwxgbQezlMYHHBSqEJhkXhYmkpQOf1TwWrrY7crKWMJ8DNdYIuGAL1oYWoe5x05t0PeSQlZAZ8wggGbMIIBTaADAgECAgIByDAFBgMrZXAwKzEVMBMGA1UEChMMRmFrZSBDb21wYW55MRIwEAYDVQQDEwlGYWtlIFJvb3QwHhcNMjQxMTA3MTcxNjU3WhcNNDkxMTAxMTcxNjU3WjAuMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxFTATBgNVBAMTDEZha2UgQ2hpcHNldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBVu8k3Ivf5UL73oP1+97TBtb6wMTegGkzRPHj1srknvfwD1wv4v6GVesqARra4AdoIvCzlJUFX1ixdWK8phXkejYzBhMB0GA1UdDgQWBBThFgHCf9ihTBTvpouQqGNeZ3OrmDAfBgNVHSMEGDAWgBSfgVedTw/ynWdMhU0gf5d0zGZnETAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAFBgMrZXADQQA0NLA7ZqVpa8C0uaa/4h9iHK3u6Jr69OPd2BJshGbpG9+nP0aITLb8R/ADp/6s+PgnpdNXpanqGgMoLPklLQ0DgqUBAgMmIAEhWCAVbvJNyL3+VC+96D9fve0wbW+sDE3oBpM0Tx49bK5J7yJYIH8A9cL+L+hlXrKgEa2uAHaCLws5SVBV9YsXVivKYV5HhEOhASagWQEEqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWE2lAQIDJiABIVgg87+gy5pvRjyJpemxrlarIIPXOuJgVpY5hPiZbdziIoMiWCDt1lz+a5LlAIUH6irVLSIozgCueHuWiFZUFcX7Kdd3QzoAR0RYQSBYQAmHgL/IJtGm1hNBvgTEMam++toTeAlseF+G/JeUTN3Ypy3V0mPIFkrr4INsDwGFYDHTZwUuygR0MWhW6EWPTzSEQ6EBJqBZAhCCWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6oQDZ2tleW1pbnSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCAl9muPyMJ7WghfAfPG2Wtay278noFdnYPeFcrTsZoFtSJYIBC6w6uEPeIQjkOYSL+hM2IS4bKegZVpxUyKur0XrsqTI1ghAOx9Qj1y57aqbv3OSxPncrZwocDTf9B3CSvVcZWZmjpDpgECAyYgASFYILCjokiLioxNnRgovP7Yqfk4uDAMmlpuPoszHM21r9BCIlggXHxXeGtqNKHkHA4sw2sHLbuYLo4eKeZgJCTeT/qCPJYjWCEA+c+bzbh1ykIcKJ5LLXbsy3eHAA1MjYcNx0BLc0dTwp9YQNGNVV0fLJo709faAw+2Da9qSjKg489OFh7caixjWxrnOyvS8DRufRX+lJWbDWg5ASn4JzD5XG9819b17MGROXOha2ZpbmdlcnByaW50eDticmFuZDEvcHJvZHVjdDEvZGV2aWNlMToxMS9pZC8yMDIxMDgwNS40Mjp1c2VyL3JlbGVhc2Uta2V5cw==","name":"default","serialno":"fake-device-0"}
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_mismatched_uds_certs.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_mismatched_uds_certs.json
new file mode 100644
index 0000000..82cf330
--- /dev/null
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_mismatched_uds_certs.json
@@ -0,0 +1 @@
+{"csr":"hQGhcHRlc3Qtc2lnbmVyLW5hbWWCWQFsMIIBaDCCARqgAwIBAgIBezAFBgMrZXAwKzEVMBMGA1UEChMMRmFrZSBDb21wYW55MRIwEAYDVQQDEwlGYWtlIFJvb3QwHhcNMjQxMTA3MTMyMjMwWhcNNDkxMTAxMTMyMjMwWjArMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxEjAQBgNVBAMTCUZha2UgUm9vdDAqMAUGAytlcAMhAKfa3ObIR3h39SmTrYoRsBVi4yWWRdqJ9vlmks8znzoTo2MwYTAdBgNVHQ4EFgQUMuqT62Vh7wTmKd2QKHcRxAMTvtYwHwYDVR0jBBgwFoAUMuqT62Vh7wTmKd2QKHcRxAMTvtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwBQYDK2VwA0EAyKyGYjHUwUJVhYg/UEEoYR+6zEdhwJBKYOen58sB+7EKjqA78r8vVh1nUZIrY+Ij/w6+qcrKKE3ESnl8+4BVDlkBnzCCAZswggFNoAMCAQICAgHIMAUGAytlcDArMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxEjAQBgNVBAMTCUZha2UgUm9vdDAeFw0yNDExMDcxMzIyMzBaFw00OTExMDExMzIyMzBaMC4xFTATBgNVBAoTDEZha2UgQ29tcGFueTEVMBMGA1UEAxMMRmFrZSBDaGlwc2V0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo4HCP+HVdEH5MOerEATu3HjoJw5d8RU6KEfxjfiQKWJLQb6nC/1bxJWnruL72+GFMdq0CSoNITphLdz8W55kMKNjMGEwHQYDVR0OBBYEFDQ8/SCwcdmJ12brLP7NtcFxxKytMB8GA1UdIwQYMBaAFDLqk+tlYe8E5indkCh3EcQDE77WMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMAUGAytlcANBAGTekO5vucM0mPEELDvV3O14LsIWSkdr1dChLtM75o9BT6dMtTqablVqCG7sRxYUCRPk8xmkhUQ3odnfKPvLZgyCpQECAyYgASFYILew9jx2jg+dfBQtjMeJATtWXE3nUEwcaBIrrSNxmceOIlggxokv7IU3C1+CFHx29dsiFPMqDDyVgsHjGWWxMuvwtxGEQ6EBJqBZAQSpAWZpc3N1ZXICZ3N1YmplY3Q6AEdEUFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEUlgguJZU4iyk0kqcDkURyPJj8GYNLiBIlpAU9FRjxPQ5MDg6AEdEU1WhOgABEXFuY29tcG9uZW50X25hbWU6AEdEVFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEVkEBOgBHRFdYTaUBAgMmIAEhWCDu6K+ZeaFbMMd9K8vCFmLN0G1bNKOrCSg5P6Y9T6dsgCJYIK4IACTS24a+gzXkJZwWRvm+U4OjWqJg/WPa24Q9R3rOOgBHRFhBIFhA9Gi/xO7WNGNsuC/BqH6LUdG5AxxVqUj8Sp174OAafTQ90uXAQDZBiq99PufrVdpDf9qauQfoo6OE7dBqnW6VtYRDoQEmoFkCD4JYIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gWQHphANna2V5bWludK5lYnJhbmRmR29vZ2xlZWZ1c2VkAWVtb2RlbGVtb2RlbGZkZXZpY2VmZGV2aWNlZ3Byb2R1Y3RlcGl4ZWxodmJfc3RhdGVlZ3JlZW5qb3NfdmVyc2lvbmIxMmxtYW51ZmFjdHVyZXJmR29vZ2xlbXZibWV0YV9kaWdlc3RPESIzRFVmd4iZqrvM3e7/bnNlY3VyaXR5X2xldmVsY3RlZXBib290X3BhdGNoX2xldmVsGgE0jGJwYm9vdGxvYWRlcl9zdGF0ZWZsb2NrZWRyc3lzdGVtX3BhdGNoX2xldmVsGgE0jGFydmVuZG9yX3BhdGNoX2xldmVsGgE0jGOCpgECAyYgASFYIMCSCLUiV5RDjqb14SCVWg4YC1Lkfa4dOK6RF+Uv3e99Ilgg525OzpfhihFQTZuqJ0jd3C0KCe+0r7DUT2Ouidy2+9UjWCA5JgKPMsu4YFPlhc3YTJzIVgi/M7xjRqYicltc/WAqE6YBAgMmIAEhWCDIMJ0btbP75swIEDf6dd5HTiH/ApE0cfo3CUDOkhe00yJYIKTLaX+3uB6nEU4eWKXkc3FcTtaa6+dj/M2S/hXI50ylI1ghAJKij+iIX15MW+S73avxD8+iRZkt7vfhmWF1lnVBppclWEBNHWpbZdY1yMHxO90+OOJuQatKO1ze1Ba19Gh/cjLnHoPHutruQVCm4z3S/+Gc1OtBevHm39MNeOvCOpmOMm0PoWtmaW5nZXJwcmludHg7YnJhbmQxL3Byb2R1Y3QxL2RldmljZTE6MTEvaWQvMjAyMTA4MDUuNDI6dXNlci9yZWxlYXNlLWtleXM=","name":"default","serialno":"fake-device-0"}
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid.json
index 4b31d7f..74fd7df 100644
--- a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid.json
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid.json
@@ -1 +1 @@
-{"csr":"hQGggqYBAgMmIAEhWCCpPq6NV6DAFtVa2xl5ma83hY7dMfHOk8+e3asA52ov0CJYININlwgFstqznGH2mxoRoPSj/QrGVRVmmU78E+ZF/dhyI1ggEpU/d/ByZJGgnFstE0omqKZX28FwxANv/egeiB4KzQOEQ6EBJqBZASepAWZpc3N1ZXICZ3N1YmplY3Q6AEdEUFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEUlgguJZU4iyk0kqcDkURyPJj8GYNLiBIlpAU9FRjxPQ5MDg6AEdEU1WhOgABEXFuY29tcG9uZW50X25hbWU6AEdEVFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEVkEBOgBHRFdYcKYBAgMmIAEhWCCFTXTgD0Ij31zMNwkMHEHeyJ4R0PVQToYItbHWSBX9CiJYIDFaX3N0+wapfXrb4+8DKNU5VHnDnvb1rsC3cjAlb50lI1ggFFtuT3XEL9kjvKY93UOGxCkqIT8XK4czC8ezX6ykBfk6AEdEWEEgWEBtIzOvyF6PIVIYljj7CfahW+MgOpd4it7iAxvkssZYYXh78NlKJFR0E1G1DdLMfRwSajaXO3wDqG5AbfiUeVy5hEOhASagWQIQglggAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyBZAeqEA2dLRVlNSU5UrmVicmFuZGZHb29nbGVlZnVzZWQBZW1vZGVsZW1vZGVsZmRldmljZWZkZXZpY2VncHJvZHVjdGVwaXhlbGh2Yl9zdGF0ZWVncmVlbmpvc192ZXJzaW9uYjEybG1hbnVmYWN0dXJlcmZHb29nbGVtdmJtZXRhX2RpZ2VzdE8RIjNEVWZ3iJmqu8zd7v9uc2VjdXJpdHlfbGV2ZWxjdGVlcGJvb3RfcGF0Y2hfbGV2ZWwaATSMYnBib290bG9hZGVyX3N0YXRlZmxvY2tlZHJzeXN0ZW1fcGF0Y2hfbGV2ZWwaATSMYXJ2ZW5kb3JfcGF0Y2hfbGV2ZWwaATSMY4KmAQIDJiABIVggN9Y9nAF4lYrevH81hTwirMeHF9lyAXF7MCqiyuY5xXQiWCAMhrBKF2SHHYuLVGMWR/mAYErcLT0JyEG5J690NeM6MSNYIQD/zJBROsd66g7qA9O/HQXpdefN9GgMOhnDQRvUFpUya6YBAgMmIAEhWCCQpbufcGMc+xy60H0wPzbecB81xipX2TDC2LF41FrYeiJYIC4eKnTSeL7astnASAPMGEhgXhUtKJ2vAy86DTvTvZcLI1ghAOMuH5yRYDLMJzAceHafd4Abe1QORt5vqCO/eHun6BnpWED2SzeNFno+SzaMHQ/A6G9JnZqu+teAXGT9eD6MW5ilZ+pFew8+xCnv4Kyk2bABjp2XCsPxkkBjhllDbJakWUz1oWtmaW5nZXJwcmludHg7YnJhbmQxL3Byb2R1Y3QxL2RldmljZTE6MTEvaWQvMjAyMTA4MDUuNDI6dXNlci9yZWxlYXNlLWtleXM=","name":"default","serialno":"fake-device-0"}
+{"csr":"hQGggqUBAgMmIAEhWCCHk1RXjzva8oQvdc9KnyV+RXgA3ckom2LVjmRttH25xCJYIOlLKg6Nf1SYEIz+649T8wZcxauBsF/f77TYAvML5Xd5hEOhASagWQEEqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWE2lAQIDJiABIVgg61L647tSG8b3QhPPHiwc3iTbujf2cxHnEDcTblJYZWgiWCCCEMWdgDNE6pn7VppdaLhspuW837SdTVJZiNtaVrtP4DoAR0RYQSBYQM2neX8L/e4z1yxejVMKlzGcRaUhdseOzpnSWPM90jTG1Ip/Zu5rTa7n+qybsd5RTPfsu+/UDdI9N91w6Jp67wmEQ6EBJqBZAhCCWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6oQDZ2tleW1pbnSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCCx1dc4NpwqjqyQFe+pfLcPyi7Dl/OmD+NLs9b2JVXekyJYINWNoh2t3ATuGisQ+twBWYhnjrxHizHScyRE6ApTOmcfI1ghAKG7GYs+GB2+NV+xVttOmJDI17vBvmnKmBlcSlilK/IKpgECAyYgASFYIKZdIXYLMJWdiFch2LgpEWZDowIAoHLRmSbYAaMwNz/CIlggXrdVRCT5hFKFvI1o7IHUATslIpNeUGFFl8CRoJrkaIcjWCEAxSEDrsLPxLNtcRTjggCU3Zr9yvzWj7QF15lX8RNpOkdYQJ9a6IXlNdyZORYuBuTWH9MVDi1agvaFvWOuCSlZH0jG9TBM27ienFuieb7JzaaiWqna+DOS3f7C+znoO4UZo9mha2ZpbmdlcnByaW50eDticmFuZDEvcHJvZHVjdDEvZGV2aWNlMToxMS9pZC8yMDIxMDgwNS40Mjp1c2VyL3JlbGVhc2Uta2V5cw==","name":"default","serialno":"fake-device-0"}
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid_with_uds_certs.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid_with_uds_certs.json
new file mode 100644
index 0000000..54f20fc
--- /dev/null
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_valid_with_uds_certs.json
@@ -0,0 +1 @@
+{"csr":"hQGhcHRlc3Qtc2lnbmVyLW5hbWWCWQFsMIIBaDCCARqgAwIBAgIBezAFBgMrZXAwKzEVMBMGA1UEChMMRmFrZSBDb21wYW55MRIwEAYDVQQDEwlGYWtlIFJvb3QwHhcNMjQxMTA3MTMwOTMxWhcNNDkxMTAxMTMwOTMxWjArMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxEjAQBgNVBAMTCUZha2UgUm9vdDAqMAUGAytlcAMhAOgFrCrwxUYuOBSIk31/ykUsDP1vSRCzs8x2e8u8vumIo2MwYTAdBgNVHQ4EFgQUtLO8kYH4qiyhGNKhkzZvxk7td94wHwYDVR0jBBgwFoAUtLO8kYH4qiyhGNKhkzZvxk7td94wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwBQYDK2VwA0EA1o8kJ3NTsY7B5/rRkJi8i/RZE1/0pQC2OUTOi8S7ZCkVdBJK7RyHo5/rVPXwVcsd3ZU1jZQalooek4mbDAWxA1kBnzCCAZswggFNoAMCAQICAgHIMAUGAytlcDArMRUwEwYDVQQKEwxGYWtlIENvbXBhbnkxEjAQBgNVBAMTCUZha2UgUm9vdDAeFw0yNDExMDcxMzA5MzFaFw00OTExMDExMzA5MzFaMC4xFTATBgNVBAoTDEZha2UgQ29tcGFueTEVMBMGA1UEAxMMRmFrZSBDaGlwc2V0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5gjh6Rzmc0mb6dX6xQAoJiLZ4992ACmLHmX0+vAJazeFLQuW6DVVOcIylkBUXDpbqeZMV9lFZW/oxQju3rJBVKNjMGEwHQYDVR0OBBYEFOyqzVrH1h4o6Kw//m+UwSGQs49zMB8GA1UdIwQYMBaAFLSzvJGB+KosoRjSoZM2b8ZO7XfeMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMAUGAytlcANBALg3Vwh02LfdlMX7awyZyl8Y7QwQmDKl0pSLmMPKdVv1DwnHq6f41J4PBC53z49mU5Ez9vjYb8LGCr22sWs/aQyCpQECAyYgASFYIOYI4ekc5nNJm+nV+sUAKCYi2ePfdgApix5l9PrwCWs3IlgghS0Llug1VTnCMpZAVFw6W6nmTFfZRWVv6MUI7t6yQVSEQ6EBJqBZAQSpAWZpc3N1ZXICZ3N1YmplY3Q6AEdEUFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEUlgguJZU4iyk0kqcDkURyPJj8GYNLiBIlpAU9FRjxPQ5MDg6AEdEU1WhOgABEXFuY29tcG9uZW50X25hbWU6AEdEVFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEVkEBOgBHRFdYTaUBAgMmIAEhWCAxDFN8FOltOB8cE0fB109PGE8oZPeImty2LZZ/vLjDnCJYIHpbYNJKSoALEDyXe4kZVoCni/ioc1Sa5VlhjiziynvPOgBHRFhBIFhAnbvrL+MymE9n/lgZQShZGruc1qCD8EIfr4HRS4tBPCtXe21A0Gi649yIbDq9P+2HYV95Xk1vnmOC9+1ObGDYroRDoQEmoFkCD4JYIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gWQHphANna2V5bWludK5lYnJhbmRmR29vZ2xlZWZ1c2VkAWVtb2RlbGVtb2RlbGZkZXZpY2VmZGV2aWNlZ3Byb2R1Y3RlcGl4ZWxodmJfc3RhdGVlZ3JlZW5qb3NfdmVyc2lvbmIxMmxtYW51ZmFjdHVyZXJmR29vZ2xlbXZibWV0YV9kaWdlc3RPESIzRFVmd4iZqrvM3e7/bnNlY3VyaXR5X2xldmVsY3RlZXBib290X3BhdGNoX2xldmVsGgE0jGJwYm9vdGxvYWRlcl9zdGF0ZWZsb2NrZWRyc3lzdGVtX3BhdGNoX2xldmVsGgE0jGFydmVuZG9yX3BhdGNoX2xldmVsGgE0jGOCpgECAyYgASFYIFnIBWu298O0kf/QUKn2eV6vign89nILn21DJLE52TLUIlggsC6XlHAB/VuG2cTALAnvat0bZJVj9w6bWnbc5x6X/M0jWCAJfWvc6+57IjP8L5CxJZraBYiNhGA8el/xNxRJeyB/JaYBAgMmIAEhWCCPtaYiCGDbBeDep67k2qvUg/Syy4NGII8JBAbnT2mSAyJYIGzW7kzGW6aJCIeKIE7kFHz4CIFSkDwAm43n4wxMJXVHI1ghAOlPIQ+q4LdN1SHxkOjLDP0gGblgFUbEc4ZqzS5NEpWDWEDiwEaxZ68DkIKC7HJIXyaRefH6QhFXTXZ6UpimZ19flcplQlxFepVFF5LMIoNE3+WXanWzZ3elQfSG2cVSUuhsoWtmaW5nZXJwcmludHg7YnJhbmQxL3Byb2R1Y3QxL2RldmljZTE6MTEvaWQvMjAyMTA4MDUuNDI6dXNlci9yZWxlYXNlLWtleXM=","name":"default","serialno":"fake-device-0"}
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_with_private_key.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_with_private_key.json
new file mode 100644
index 0000000..4b31d7f
--- /dev/null
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_with_private_key.json
@@ -0,0 +1 @@
+{"csr":"hQGggqYBAgMmIAEhWCCpPq6NV6DAFtVa2xl5ma83hY7dMfHOk8+e3asA52ov0CJYININlwgFstqznGH2mxoRoPSj/QrGVRVmmU78E+ZF/dhyI1ggEpU/d/ByZJGgnFstE0omqKZX28FwxANv/egeiB4KzQOEQ6EBJqBZASepAWZpc3N1ZXICZ3N1YmplY3Q6AEdEUFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEUlgguJZU4iyk0kqcDkURyPJj8GYNLiBIlpAU9FRjxPQ5MDg6AEdEU1WhOgABEXFuY29tcG9uZW50X25hbWU6AEdEVFggVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU6AEdEVkEBOgBHRFdYcKYBAgMmIAEhWCCFTXTgD0Ij31zMNwkMHEHeyJ4R0PVQToYItbHWSBX9CiJYIDFaX3N0+wapfXrb4+8DKNU5VHnDnvb1rsC3cjAlb50lI1ggFFtuT3XEL9kjvKY93UOGxCkqIT8XK4czC8ezX6ykBfk6AEdEWEEgWEBtIzOvyF6PIVIYljj7CfahW+MgOpd4it7iAxvkssZYYXh78NlKJFR0E1G1DdLMfRwSajaXO3wDqG5AbfiUeVy5hEOhASagWQIQglggAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyBZAeqEA2dLRVlNSU5UrmVicmFuZGZHb29nbGVlZnVzZWQBZW1vZGVsZW1vZGVsZmRldmljZWZkZXZpY2VncHJvZHVjdGVwaXhlbGh2Yl9zdGF0ZWVncmVlbmpvc192ZXJzaW9uYjEybG1hbnVmYWN0dXJlcmZHb29nbGVtdmJtZXRhX2RpZ2VzdE8RIjNEVWZ3iJmqu8zd7v9uc2VjdXJpdHlfbGV2ZWxjdGVlcGJvb3RfcGF0Y2hfbGV2ZWwaATSMYnBib290bG9hZGVyX3N0YXRlZmxvY2tlZHJzeXN0ZW1fcGF0Y2hfbGV2ZWwaATSMYXJ2ZW5kb3JfcGF0Y2hfbGV2ZWwaATSMY4KmAQIDJiABIVggN9Y9nAF4lYrevH81hTwirMeHF9lyAXF7MCqiyuY5xXQiWCAMhrBKF2SHHYuLVGMWR/mAYErcLT0JyEG5J690NeM6MSNYIQD/zJBROsd66g7qA9O/HQXpdefN9GgMOhnDQRvUFpUya6YBAgMmIAEhWCCQpbufcGMc+xy60H0wPzbecB81xipX2TDC2LF41FrYeiJYIC4eKnTSeL7astnASAPMGEhgXhUtKJ2vAy86DTvTvZcLI1ghAOMuH5yRYDLMJzAceHafd4Abe1QORt5vqCO/eHun6BnpWED2SzeNFno+SzaMHQ/A6G9JnZqu+teAXGT9eD6MW5ilZ+pFew8+xCnv4Kyk2bABjp2XCsPxkkBjhllDbJakWUz1oWtmaW5nZXJwcmludHg7YnJhbmQxL3Byb2R1Y3QxL2RldmljZTE6MTEvaWQvMjAyMTA4MDUuNDI6dXNlci9yZWxlYXNlLWtleXM=","name":"default","serialno":"fake-device-0"}
```

