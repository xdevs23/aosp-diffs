```diff
diff --git a/fuzzing/llm/xz_fuzzer/xz_decoder_fuzzer.cpp b/fuzzing/llm/xz_fuzzer/xz_decoder_fuzzer.cpp
index 06dd7c6..b13891f 100644
--- a/fuzzing/llm/xz_fuzzer/xz_decoder_fuzzer.cpp
+++ b/fuzzing/llm/xz_fuzzer/xz_decoder_fuzzer.cpp
@@ -1,6 +1,9 @@
 #include <fuzzer/FuzzedDataProvider.h>
 #include "xz.h"
 
+constexpr size_t kMinSize = 0;
+constexpr size_t kMaxSize = 1000;
+
 // Function to initialize xz_dec structure using xz_dec_init
 struct xz_dec *init_xz_dec(FuzzedDataProvider& stream) {
     // Randomly select a mode from the xz_mode enum
@@ -8,7 +11,8 @@ struct xz_dec *init_xz_dec(FuzzedDataProvider& stream) {
     enum xz_mode mode = stream.PickValueInArray(modes);
 
     // Generate a random dict_max value
-    uint32_t dict_max = stream.ConsumeIntegral<uint32_t>();
+    uint32_t dict_max =
+        stream.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize);
 
     // Initialize the xz_dec structure
     struct xz_dec *s = xz_dec_init(mode, dict_max);
@@ -41,6 +45,6 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 
     // Call the function under test
     xz_ret result = xz_dec_run(s, &b);
-
+    xz_dec_end(s);
     return 0;  // Non-zero return values are usually reserved for fatal errors
 }
diff --git a/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java b/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java
index 287d065..44ddff7 100644
--- a/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java
+++ b/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java
@@ -3,7 +3,6 @@ package com.google.attestationexample;
 import android.os.AsyncTask;
 import android.security.keystore.KeyGenParameterSpec;
 import android.security.keystore.KeyProperties;
-import android.util.Base64;
 import android.util.Log;
 
 import com.google.common.collect.ImmutableSet;
@@ -26,6 +25,7 @@ import java.security.cert.CertificateFactory;
 import java.security.cert.X509Certificate;
 import java.security.spec.ECGenParameterSpec;
 import java.util.Arrays;
+import java.util.Base64;
 import java.util.Date;
 import java.util.HashSet;
 import java.util.Set;
@@ -209,13 +209,16 @@ public class AttestationTest extends AsyncTask<Void, String, Void> {
         keyPairGenerator.generateKeyPair();
     }
 
+    private static final byte[] CRLF = new byte[] {'\r', '\n'};
+    private static final Base64.Encoder PEM_ENCODER = Base64.getMimeEncoder(64, CRLF);
+
     private void verifyCertificateSignatures(Certificate[] certChain)
             throws GeneralSecurityException {
 
         for (Certificate cert : certChain) {
-            final byte[] derCert = cert.getEncoded();
-            final String pemCertPre = Base64.encodeToString(derCert, Base64.NO_WRAP);
-            Log.e("****", pemCertPre);
+            Log.e("****", "-----BEGIN CERTIFICATE-----");
+            Log.e("****", PEM_ENCODER.encodeToString(cert.getEncoded()));
+            Log.e("****", "-----END CERTIFICATE-----");
         }
 
         for (int i = 1; i < certChain.length; ++i) {
diff --git a/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp b/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
index 804b929..7439bb2 100644
--- a/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
+++ b/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
@@ -16,7 +16,7 @@ DiceChain::~DiceChain() {}
 DiceChain::DiceChain(std::unique_ptr<BoxedDiceChain> chain, size_t size) noexcept
       : chain_(std::move(chain)), size_(size) {}
 
-Result<DiceChain> DiceChain::Verify(const std::vector<uint8_t>& chain, DiceChain::Kind kind) noexcept {
+Result<DiceChain> DiceChain::Verify(const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode) noexcept {
   rust::DiceChainKind chainKind;
   switch (kind) {
     case DiceChain::Kind::kVsr13:
@@ -32,7 +32,7 @@ Result<DiceChain> DiceChain::Verify(const std::vector<uint8_t>& chain, DiceChain
       chainKind = rust::DiceChainKind::Vsr16;
       break;
   }
-  auto res = rust::VerifyDiceChain({chain.data(), chain.size()}, chainKind);
+  auto res = rust::VerifyDiceChain({chain.data(), chain.size()}, chainKind, allow_any_mode);
   if (!res.error.empty()) {
       return Error() << static_cast<std::string>(res.error);
   }
diff --git a/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h b/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
index 35c62b0..8e999a3 100644
--- a/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
+++ b/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
@@ -19,7 +19,7 @@ public:
     kVsr16,
   };
 
-  static android::base::Result<DiceChain> Verify(const std::vector<uint8_t>& chain, DiceChain::Kind kind) noexcept;
+  static android::base::Result<DiceChain> Verify(const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode) noexcept;
 
   ~DiceChain();
   DiceChain(DiceChain&&) = default;
diff --git a/remote_provisioning/hwtrust/cxxbridge/lib.rs b/remote_provisioning/hwtrust/cxxbridge/lib.rs
index 203f1d2..dd713bd 100644
--- a/remote_provisioning/hwtrust/cxxbridge/lib.rs
+++ b/remote_provisioning/hwtrust/cxxbridge/lib.rs
@@ -5,6 +5,7 @@ use coset::CborSerializable;
 use hwtrust::dice::ChainForm;
 use hwtrust::session::{Options, Session};
 
+#[allow(clippy::needless_maybe_sized)]
 #[allow(unsafe_op_in_unsafe_fn)]
 #[cxx::bridge(namespace = "hwtrust::rust")]
 mod ffi {
@@ -36,7 +37,11 @@ mod ffi {
         type DiceChain;
 
         #[cxx_name = VerifyDiceChain]
-        fn verify_dice_chain(chain: &[u8], kind: DiceChainKind) -> VerifyDiceChainResult;
+        fn verify_dice_chain(
+            chain: &[u8],
+            kind: DiceChainKind,
+            allow_any_mode: bool,
+        ) -> VerifyDiceChainResult;
 
         #[cxx_name = GetDiceChainPublicKey]
         fn get_dice_chain_public_key(chain: &DiceChain, n: usize) -> Vec<u8>;
@@ -49,8 +54,12 @@ mod ffi {
 /// A DICE chain as exposed over the cxx bridge.
 pub struct DiceChain(Option<ChainForm>);
 
-fn verify_dice_chain(chain: &[u8], kind: ffi::DiceChainKind) -> ffi::VerifyDiceChainResult {
-    let session = Session {
+fn verify_dice_chain(
+    chain: &[u8],
+    kind: ffi::DiceChainKind,
+    allow_any_mode: bool,
+) -> ffi::VerifyDiceChainResult {
+    let mut session = Session {
         options: match kind {
             ffi::DiceChainKind::Vsr13 => Options::vsr13(),
             ffi::DiceChainKind::Vsr14 => Options::vsr14(),
@@ -65,6 +74,7 @@ fn verify_dice_chain(chain: &[u8], kind: ffi::DiceChainKind) -> ffi::VerifyDiceC
             }
         },
     };
+    session.set_allow_any_mode(allow_any_mode);
     match ChainForm::from_cbor(&session, chain) {
         Ok(chain) => {
             let len = match chain {
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/chain.rs b/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
index 73ca7d3..96b0a59 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
@@ -29,8 +29,16 @@ impl ChainForm {
             let value = it.as_slice()[0].clone();
             let entry = Entry::verify_cbor_value(value, &root_public_key)
                 .context("parsing degenerate entry")?;
-            let fields = PayloadFields::from_cbor(session, entry.payload(), ConfigFormat::Android)
-                .context("parsing degenerate payload")?;
+            let is_root = true;
+            let possibly_degenerate = true;
+            let fields = PayloadFields::from_cbor(
+                session,
+                entry.payload(),
+                ConfigFormat::AndroidOrIgnored,
+                is_root,
+                possibly_degenerate,
+            )
+            .context("parsing degenerate payload")?;
             let chain =
                 DegenerateChain::new(fields.issuer, fields.subject, fields.subject_public_key)
                     .context("creating DegenerateChain")?;
@@ -73,7 +81,8 @@ impl Chain {
         for (n, value) in values.enumerate() {
             let entry = Entry::verify_cbor_value(value, previous_public_key)
                 .with_context(|| format!("Invalid entry at index {}", n))?;
-            let config_format = if n == 0
+            let is_root = n == 0;
+            let config_format = if is_root
                 && session.options.dice_profile_range.contains(ProfileVersion::Android14)
             {
                 // Context: b/261647022
@@ -81,7 +90,7 @@ impl Chain {
             } else {
                 ConfigFormat::default()
             };
-            let payload = Payload::from_cbor(session, entry.payload(), config_format)
+            let payload = Payload::from_cbor(session, entry.payload(), config_format, is_root)
                 .with_context(|| format!("Invalid payload at index {}", n))?;
             payloads.push(payload);
             let previous = payloads.last().unwrap();
@@ -128,7 +137,7 @@ mod tests {
     #[test]
     fn chain_form_valid_proper() {
         let chain = fs::read("testdata/dice/valid_ed25519.chain").unwrap();
-        let session = Session { options: Options::default() };
+        let session = Session { options: Options { allow_any_mode: true, ..Default::default() } };
         let form = ChainForm::from_cbor(&session, &chain).unwrap();
         assert!(matches!(form, ChainForm::Proper(_)));
     }
@@ -144,7 +153,7 @@ mod tests {
     #[test]
     fn check_chain_valid_ed25519() {
         let chain = fs::read("testdata/dice/valid_ed25519.chain").unwrap();
-        let session = Session { options: Options::default() };
+        let session = Session { options: Options { allow_any_mode: true, ..Default::default() } };
         let chain = Chain::from_cbor(&session, &chain).unwrap();
         assert_eq!(chain.payloads().len(), 8);
     }
@@ -153,7 +162,7 @@ mod tests {
     fn check_chain_valid_ed25519_value() {
         let chain = fs::read("testdata/dice/valid_ed25519.chain").unwrap();
         let chain = value_from_bytes(&chain).unwrap();
-        let session = Session { options: Options::default() };
+        let session = Session { options: Options { allow_any_mode: true, ..Default::default() } };
         let chain = Chain::from_value(&session, chain).unwrap();
         assert_eq!(chain.payloads().len(), 8);
     }
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/entry.rs b/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
index 1091728..38af596 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
@@ -35,6 +35,7 @@ const COMPONENT_VERSION: i64 = -70003;
 const RESETTABLE: i64 = -70004;
 const SECURITY_VERSION: i64 = -70005;
 const RKP_VM_MARKER: i64 = -70006;
+const COMPONENT_INSTANCE_NAME: i64 = -70007;
 
 pub(super) struct Entry {
     payload: Vec<u8>,
@@ -70,18 +71,28 @@ impl Payload {
         session: &Session,
         bytes: &[u8],
         config_format: ConfigFormat,
+        is_root: bool,
     ) -> Result<Self> {
         let entries = cbor_map_from_slice(bytes)?;
         let profile_version = PayloadFields::extract_profile_version(session, &entries)?;
-        Self::from_entries(&profile_version.into(), entries, config_format)
+        Self::from_entries(
+            &profile_version.into(),
+            entries,
+            config_format,
+            is_root,
+            session.options.allow_any_mode,
+        )
     }
 
     fn from_entries(
         profile: &Profile,
         entries: Vec<(Value, Value)>,
         config_format: ConfigFormat,
+        is_root: bool,
+        allow_any_mode: bool,
     ) -> Result<Self> {
-        let f = PayloadFields::from_entries(profile, entries, config_format)?;
+        let f =
+            PayloadFields::from_entries(profile, entries, config_format, is_root, allow_any_mode)?;
         PayloadBuilder::with_subject_public_key(f.subject_public_key)
             .issuer(f.issuer)
             .subject(f.subject)
@@ -115,10 +126,14 @@ impl PayloadFields {
         session: &Session,
         bytes: &[u8],
         config_format: ConfigFormat,
+        is_root: bool,
+        possibly_degenerate: bool,
     ) -> Result<Self> {
         let entries = cbor_map_from_slice(bytes)?;
         let profile_version = Self::extract_profile_version(session, &entries)?;
-        Self::from_entries(&profile_version.into(), entries, config_format)
+        let allow_any_mode = session.options.allow_any_mode || possibly_degenerate;
+
+        Self::from_entries(&profile_version.into(), entries, config_format, is_root, allow_any_mode)
     }
 
     fn extract_profile_version(
@@ -156,6 +171,8 @@ impl PayloadFields {
         profile: &Profile,
         entries: Vec<(Value, Value)>,
         config_format: ConfigFormat,
+        is_root: bool,
+        allow_any_mode: bool,
     ) -> Result<Self> {
         let mut issuer = FieldValue::new("issuer");
         let mut subject = FieldValue::new("subject");
@@ -197,21 +214,66 @@ impl PayloadFields {
         let (config_desc, config_hash) =
             validate_config(profile, config_desc, config_hash, config_format).context("config")?;
 
+        let (code_hash, authority_hash) =
+            validate_hash_sizes(profile, code_hash, &config_hash, authority_hash, is_root)?;
+
         Ok(Self {
             issuer: issuer.into_string()?,
             subject: subject.into_string()?,
             subject_public_key: validate_subject_public_key(profile, subject_public_key)?,
-            mode: validate_mode(profile, mode)?,
+            mode: validate_mode(profile, mode, is_root, allow_any_mode)?,
             code_desc: code_desc.into_optional_bytes()?,
-            code_hash: code_hash.into_optional_bytes()?,
+            code_hash,
             config_desc,
             config_hash,
             authority_desc: authority_desc.into_optional_bytes()?,
-            authority_hash: authority_hash.into_optional_bytes()?,
+            authority_hash,
         })
     }
 }
 
+fn validate_hash_sizes(
+    profile: &Profile,
+    code_hash: FieldValue,
+    config_hash: &Option<Vec<u8>>,
+    authority_hash: FieldValue,
+    is_root: bool,
+) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
+    let code_hash = code_hash.into_optional_bytes()?;
+    let authority_hash: Option<Vec<u8>> = authority_hash.into_optional_bytes()?;
+
+    if let Some(ref code_hash) = code_hash {
+        let used_hash_size = code_hash.len();
+
+        if ![32, 48, 64].contains(&(used_hash_size)) {
+            bail!("bad code hash size, actual: {0}, expected: 32, 48, or 64", used_hash_size)
+        }
+
+        if let Some(ref config_hash) = config_hash {
+            if config_hash.len() != used_hash_size {
+                bail!(
+                    "bad config hash size, actual: {0}, expected: {1}",
+                    config_hash.len(),
+                    used_hash_size
+                )
+            }
+        }
+
+        if let Some(ref authority_hash) = authority_hash {
+            let root_exception = profile.allow_root_varied_auth_hash_size && is_root;
+            if authority_hash.len() != used_hash_size && !root_exception {
+                bail!(
+                    "bad authority hash size, actual: {0}, expected: {1}",
+                    authority_hash.len(),
+                    used_hash_size
+                )
+            }
+        }
+    }
+
+    Ok((code_hash, authority_hash))
+}
+
 fn validate_key_usage(profile: &Profile, key_usage: FieldValue) -> Result<()> {
     let key_usage = key_usage.into_bytes().context("key usage")?;
     let key_cert_sign = 1 << 5;
@@ -243,8 +305,13 @@ fn validate_subject_public_key(
         .context("parsing subject public key from COSE_key")
 }
 
-fn validate_mode(profile: &Profile, mode: FieldValue) -> Result<Option<DiceMode>> {
-    Ok(if !mode.is_bytes() && profile.mode_type == ModeType::IntOrBytes {
+fn validate_mode(
+    profile: &Profile,
+    mode: FieldValue,
+    is_root: bool,
+    allow_any_mode: bool,
+) -> Result<Option<DiceMode>> {
+    if !mode.is_bytes() && profile.mode_type == ModeType::IntOrBytes {
         mode.into_optional_i64()?
     } else {
         mode.into_optional_bytes()?
@@ -256,12 +323,26 @@ fn validate_mode(profile: &Profile, mode: FieldValue) -> Result<Option<DiceMode>
             })
             .transpose()?
     }
-    .map(|mode| match mode {
-        1 => DiceMode::Normal,
-        2 => DiceMode::Debug,
-        3 => DiceMode::Recovery,
-        _ => DiceMode::NotConfigured,
-    }))
+    .map(|mode| {
+        let mode = match mode {
+            1 => DiceMode::Normal,
+            2 => DiceMode::Debug,
+            3 => DiceMode::Recovery,
+            _ => DiceMode::NotConfigured,
+        };
+
+        if mode != DiceMode::Normal && !allow_any_mode {
+            let debug_allowed = is_root && profile.allow_root_mode_debug;
+            ensure!(debug_allowed, "Expected mode to be normal, actual mode: {:?}", mode);
+            ensure!(
+                mode == DiceMode::Debug,
+                "Expected mode to be normal or debug, actual mode: {:?}",
+                mode
+            );
+        }
+        Ok(mode)
+    })
+    .transpose()
 }
 
 fn validate_config(
@@ -305,6 +386,7 @@ fn config_desc_from_slice(profile: &Profile, bytes: &[u8]) -> Result<ConfigDesc>
     let entries = cbor_map_from_slice(bytes)?;
 
     let mut component_name = FieldValue::new("component name");
+    let mut component_instance_name = FieldValue::new("component instance name");
     let mut component_version = FieldValue::new("component version");
     let mut resettable = FieldValue::new("resettable");
     let mut security_version = FieldValue::new("security version");
@@ -315,6 +397,7 @@ fn config_desc_from_slice(profile: &Profile, bytes: &[u8]) -> Result<ConfigDesc>
         if let Some(Ok(key)) = key.as_integer().map(TryInto::try_into) {
             let field = match key {
                 COMPONENT_NAME => &mut component_name,
+                COMPONENT_INSTANCE_NAME => &mut component_instance_name,
                 COMPONENT_VERSION => &mut component_version,
                 RESETTABLE => &mut resettable,
                 SECURITY_VERSION => &mut security_version,
@@ -350,6 +433,9 @@ fn config_desc_from_slice(profile: &Profile, bytes: &[u8]) -> Result<ConfigDesc>
 
     Ok(ConfigDescBuilder::new()
         .component_name(component_name.into_optional_string().context("Component name")?)
+        .component_instance_name(
+            component_instance_name.into_optional_string().context("Component instance name")?,
+        )
         .component_version(
             validate_version(profile, component_version).context("Component version")?,
         )
@@ -384,6 +470,10 @@ mod tests {
     use coset::CborSerializable;
     use std::collections::HashMap;
 
+    const ALLOW_ANY_MODE: bool = true;
+    const IS_ROOT: bool = true;
+    const POSSIBLY_DEGENERATE: bool = true;
+
     impl Entry {
         pub(in super::super) fn from_payload(payload: &Payload) -> Result<Self> {
             Ok(Self { payload: serialize(payload.to_cbor_value()?) })
@@ -469,7 +559,8 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         fields.insert(AUTHORITY_HASH, Value::Bytes(vec![2; 32]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap();
     }
 
     #[test]
@@ -482,14 +573,16 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         fields.insert(AUTHORITY_HASH, Value::Bytes(vec![2; 48]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap();
     }
 
     #[test]
     fn valid_payload_sha512() {
         let fields = valid_payload_fields();
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap();
     }
 
     #[test]
@@ -497,7 +590,8 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x20]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap();
     }
 
     #[test]
@@ -505,7 +599,8 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x20, 0x30, 0x40]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
     }
 
     #[test]
@@ -513,7 +608,8 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x10]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
     }
 
     #[test]
@@ -521,56 +617,236 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x21]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn bad_code_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(CODE_HASH, Value::Bytes(vec![1; 16]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn bad_authority_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 16]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn inconsistent_authority_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 32]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn inconsistent_root_authority_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 20]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, IS_ROOT)
+            .unwrap();
+    }
+
+    #[test]
+    fn inconsistent_root_authority_hash_size_auth_differ_unexcepted() {
+        let mut fields = valid_payload_fields();
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 20]));
+        let entries = encode_fields(fields);
+        let profile = Profile { allow_root_varied_auth_hash_size: false, ..Profile::default() };
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn bad_config_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(CONFIG_HASH, Value::Bytes(vec![1; 16]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn inconsistent_config_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(CODE_HASH, Value::Bytes(vec![1; 32]));
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 32]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn inconsistent_root_config_hash_size() {
+        let mut fields = valid_payload_fields();
+        fields.insert(CODE_HASH, Value::Bytes(vec![1; 32]));
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 32]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, IS_ROOT)
+            .unwrap_err();
+    }
+
+    #[test]
+    fn inconsistent_root_config_hash_size_auth_differ_unexcepted() {
+        let mut fields = valid_payload_fields();
+        fields.insert(CODE_HASH, Value::Bytes(vec![1; 32]));
+        fields.insert(AUTHORITY_HASH, Value::Bytes(vec![1; 32]));
+        let entries = encode_fields(fields);
+        let profile = Profile { allow_root_varied_auth_hash_size: false, ..Profile::default() };
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap_err();
     }
 
     #[test]
     fn mode_not_configured() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![0]));
-        let session = Session { options: Options::default() };
+        let mut session = Session { options: Options::default() };
+        let serialized_fields = serialize_fields(fields);
+        Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+        session.set_allow_any_mode(true);
         let payload =
-            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+            Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
+                .unwrap();
         assert_eq!(payload.mode(), DiceMode::NotConfigured);
     }
 
+    #[test]
+    fn mode_not_configured_degenerate() {
+        let mut fields = valid_payload_fields();
+        fields.insert(MODE, Value::Bytes(vec![0]));
+        let session = Session { options: Options::default() };
+        let payload = PayloadFields::from_cbor(
+            &session,
+            &serialize_fields(fields),
+            ConfigFormat::Android,
+            !IS_ROOT,
+            POSSIBLY_DEGENERATE,
+        )
+        .unwrap();
+        assert_eq!(payload.mode.unwrap(), DiceMode::NotConfigured);
+    }
+
     #[test]
     fn mode_normal() {
+        let mut fields = valid_payload_fields();
+        fields.insert(MODE, Value::Bytes(vec![1]));
+        let session = Session { options: Options::default() };
+        let payload = Payload::from_cbor(
+            &session,
+            &serialize_fields(fields),
+            ConfigFormat::Android,
+            !IS_ROOT,
+        )
+        .unwrap();
+        assert_eq!(payload.mode(), DiceMode::Normal);
+    }
+
+    #[test]
+    fn mode_normal_root() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![1]));
         let session = Session { options: Options::default() };
         let payload =
-            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, IS_ROOT)
+                .unwrap();
         assert_eq!(payload.mode(), DiceMode::Normal);
     }
 
+    #[test]
+    fn mode_normal_root_debug_unexcepted() {
+        let mut fields = valid_payload_fields();
+        fields.insert(MODE, Value::Bytes(vec![1]));
+        let entries = encode_fields(fields);
+        let profile = Profile { allow_root_mode_debug: false, ..Profile::default() };
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap();
+    }
+
     #[test]
     fn mode_debug() {
+        let mut fields = valid_payload_fields();
+        fields.insert(MODE, Value::Bytes(vec![2]));
+        let mut session = Session { options: Options::default() };
+        let serialized_fields = serialize_fields(fields);
+        Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+        session.set_allow_any_mode(true);
+        let payload =
+            Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
+                .unwrap();
+        assert_eq!(payload.mode(), DiceMode::Debug);
+    }
+
+    #[test]
+    fn mode_debug_root() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![2]));
         let session = Session { options: Options::default() };
         let payload =
-            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, IS_ROOT)
+                .unwrap();
         assert_eq!(payload.mode(), DiceMode::Debug);
     }
 
+    #[test]
+    fn mode_debug_root_debug_unexcepted() {
+        let mut fields = valid_payload_fields();
+        fields.insert(MODE, Value::Bytes(vec![2]));
+        let entries = encode_fields(fields);
+        let profile = Profile { allow_root_mode_debug: false, ..Profile::default() };
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap_err();
+    }
+
     #[test]
     fn mode_recovery() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![3]));
-        let session = Session { options: Options::default() };
+        let mut session = Session { options: Options::default() };
+        let serialized_fields = serialize_fields(fields);
+        Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
+        session.set_allow_any_mode(true);
         let payload =
-            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+            Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
+                .unwrap();
         assert_eq!(payload.mode(), DiceMode::Recovery);
     }
 
+    #[test]
+    fn mode_recovery_root() {
+        let mut fields = valid_payload_fields();
+        fields.insert(MODE, Value::Bytes(vec![3]));
+        let session = Session { options: Options::default() };
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, IS_ROOT)
+            .unwrap_err();
+    }
+
     #[test]
     fn mode_invalid_becomes_not_configured() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![4]));
-        let session = Session { options: Options::default() };
-        let payload =
-            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        let mut session = Session { options: Options::default() };
+        session.set_allow_any_mode(true);
+        let payload = Payload::from_cbor(
+            &session,
+            &serialize_fields(fields),
+            ConfigFormat::Android,
+            !IS_ROOT,
+        )
+        .unwrap();
         assert_eq!(payload.mode(), DiceMode::NotConfigured);
     }
 
@@ -579,7 +855,8 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![0, 1]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
     }
 
     #[test]
@@ -587,10 +864,23 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::from(2));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            !IS_ROOT,
+            ALLOW_ANY_MODE,
+        )
+        .unwrap_err();
         let profile = Profile { mode_type: ModeType::IntOrBytes, ..Profile::default() };
-        let payload = Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_entries(
+            &profile,
+            entries,
+            ConfigFormat::Android,
+            !IS_ROOT,
+            ALLOW_ANY_MODE,
+        )
+        .unwrap();
         assert_eq!(payload.mode(), DiceMode::Debug);
     }
 
@@ -599,7 +889,8 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(SUBJECT_PUBLIC_KEY, Value::Bytes(vec![17; 64]));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
     }
 
     #[test]
@@ -608,7 +899,7 @@ mod tests {
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x20, 0x00, 0x00]));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
     }
 
     #[test]
@@ -617,7 +908,7 @@ mod tests {
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x20, 0xbe, 0xef]));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap_err();
     }
 
     #[test]
@@ -625,10 +916,17 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x00, 0x20]));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap_err();
         let profile = Profile { allow_big_endian_key_usage: true, ..Profile::default() };
-        Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap();
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, !IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap();
     }
 
     #[test]
@@ -636,10 +934,17 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x00, 0xfe, 0x20]));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap_err();
         let profile = Profile { allow_big_endian_key_usage: true, ..Profile::default() };
-        Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap_err();
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, !IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap_err();
     }
 
     #[test]
@@ -647,10 +952,17 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![0x00, 0x10]));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap_err();
         let profile = Profile { allow_big_endian_key_usage: true, ..Profile::default() };
-        Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap_err();
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, !IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap_err();
     }
 
     #[test]
@@ -658,10 +970,17 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.insert(KEY_USAGE, Value::Bytes(vec![]));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap_err();
         let profile = Profile { allow_big_endian_key_usage: true, ..Profile::default() };
-        Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap_err();
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, !IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap_err();
     }
 
     #[test]
@@ -672,7 +991,8 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap();
     }
 
     #[test]
@@ -683,7 +1003,8 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
     }
 
     #[test]
@@ -694,7 +1015,8 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap_err();
     }
 
     #[test]
@@ -705,7 +1027,8 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android, !IS_ROOT)
+            .unwrap();
     }
 
     #[test]
@@ -716,8 +1039,13 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let session = Session { options: Options::default() };
-        let payload =
-            Payload::from_cbor(&session, &serialize_fields(fields), ConfigFormat::Android).unwrap();
+        let payload = Payload::from_cbor(
+            &session,
+            &serialize_fields(fields),
+            ConfigFormat::Android,
+            !IS_ROOT,
+        )
+        .unwrap();
         let extensions = payload.config_desc().extensions();
         let extensions = HashMap::<_, _>::from_iter(extensions.to_owned());
         assert_eq!(extensions.get("-71000").unwrap(), "Text(\"custom hi\")");
@@ -731,11 +1059,25 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(vec![0xcd; 64]));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap_err();
-        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::AndroidOrIgnored).unwrap();
+        Payload::from_cbor(&session, &cbor, ConfigFormat::Android, false).unwrap_err();
+        let payload =
+            Payload::from_cbor(&session, &cbor, ConfigFormat::AndroidOrIgnored, !IS_ROOT).unwrap();
         assert_eq!(payload.config_desc(), &ConfigDesc::default());
     }
 
+    #[test]
+    fn config_desc_component_instance_name() {
+        let mut fields = valid_payload_fields();
+        let config_desc = serialize(cbor!({COMPONENT_INSTANCE_NAME => "foobar"}).unwrap());
+        let config_hash = sha512(&config_desc).to_vec();
+        fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
+        fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
+        let cbor = serialize_fields(fields);
+        let session = Session { options: Options::default() };
+        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
+        assert_eq!(payload.config_desc().component_instance_name(), Some("foobar"));
+    }
+
     #[test]
     fn config_desc_component_version_string() {
         let mut fields = valid_payload_fields();
@@ -748,9 +1090,22 @@ mod tests {
         let entries = encode_fields(fields);
         let profile =
             Profile { component_version_type: ComponentVersionType::Int, ..Profile::default() };
-        Payload::from_entries(&profile, entries.clone(), ConfigFormat::Android).unwrap_err();
-        let payload =
-            Payload::from_entries(&Profile::default(), entries, ConfigFormat::Android).unwrap();
+        Payload::from_entries(
+            &profile,
+            entries.clone(),
+            ConfigFormat::Android,
+            !IS_ROOT,
+            !ALLOW_ANY_MODE,
+        )
+        .unwrap_err();
+        let payload = Payload::from_entries(
+            &Profile::default(),
+            entries,
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap();
         assert_eq!(
             payload.config_desc().component_version(),
             Some(&ComponentVersion::String("It's version 4".to_string()))
@@ -766,7 +1121,7 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
         assert_eq!(payload.config_desc().security_version(), Some(0x12345678));
     }
 
@@ -778,10 +1133,23 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap_err();
         let profile = Profile { security_version_optional: true, ..Profile::default() };
-        let payload = Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_entries(
+            &profile,
+            entries,
+            ConfigFormat::Android,
+            !IS_ROOT,
+            !ALLOW_ANY_MODE,
+        )
+        .unwrap();
         assert_eq!(payload.config_desc().security_version(), None);
     }
 
@@ -798,7 +1166,7 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
         assert_eq!(payload.config_desc().security_version(), Some(0xcafe));
     }
 
@@ -809,7 +1177,7 @@ mod tests {
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap_err();
+        Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap_err();
     }
 
     #[test]
@@ -821,7 +1189,7 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
         assert!(payload.config_desc().resettable());
     }
 
@@ -834,7 +1202,7 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
         assert!(payload.config_desc().rkp_vm_marker());
     }
 
@@ -847,7 +1215,7 @@ mod tests {
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
         let cbor = serialize_fields(fields);
         let session = Session { options: Options::default() };
-        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android).unwrap();
+        let payload = Payload::from_cbor(&session, &cbor, ConfigFormat::Android, !IS_ROOT).unwrap();
         assert!(!payload.config_desc().resettable());
         assert!(!payload.config_desc().rkp_vm_marker());
     }
@@ -857,7 +1225,14 @@ mod tests {
         let mut fields = valid_payload_fields();
         fields.remove(&CONFIG_HASH);
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries, ConfigFormat::Android).unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries,
+            ConfigFormat::Android,
+            !IS_ROOT,
+            !ALLOW_ANY_MODE,
+        )
+        .unwrap_err();
     }
 
     #[test]
@@ -873,10 +1248,17 @@ mod tests {
         .unwrap();
         fields.insert(SUBJECT_PUBLIC_KEY, Value::Bytes(serialize(subject_public_key)));
         let entries = encode_fields(fields);
-        Payload::from_entries(&Profile::default(), entries.clone(), ConfigFormat::Android)
-            .unwrap_err();
+        Payload::from_entries(
+            &Profile::default(),
+            entries.clone(),
+            ConfigFormat::Android,
+            false,
+            false,
+        )
+        .unwrap_err();
         let profile = Profile { key_ops_type: KeyOpsType::IntOrArray, ..Profile::default() };
-        Payload::from_entries(&profile, entries, ConfigFormat::Android).unwrap();
+        Payload::from_entries(&profile, entries, ConfigFormat::Android, !IS_ROOT, !ALLOW_ANY_MODE)
+            .unwrap();
     }
 
     #[test]
@@ -893,6 +1275,7 @@ mod tests {
             let session = Session {
                 options: Options {
                     dice_profile_range: DiceProfileRange::new(expected_version, expected_version),
+                    ..Default::default()
                 },
             };
             let profile_version =
@@ -909,6 +1292,7 @@ mod tests {
                     ProfileVersion::Android13,
                     ProfileVersion::Android16,
                 ),
+                ..Default::default()
             },
         };
         let mut fields = valid_payload_fields();
@@ -925,6 +1309,7 @@ mod tests {
                     ProfileVersion::Android13,
                     ProfileVersion::Android16,
                 ),
+                ..Default::default()
             },
         };
         let mut fields = valid_payload_fields();
@@ -942,6 +1327,7 @@ mod tests {
                     ProfileVersion::Android15,
                     ProfileVersion::Android15,
                 ),
+                ..Default::default()
             },
         };
         let mut fields = valid_payload_fields();
@@ -963,6 +1349,7 @@ mod tests {
                         expected_version,
                         ProfileVersion::Android16,
                     ),
+                    ..Default::default()
                 },
             };
             let profile_version =
@@ -981,6 +1368,7 @@ mod tests {
                         min_version,
                         ProfileVersion::Android16,
                     ),
+                    ..Default::default()
                 },
             };
             PayloadFields::extract_profile_version(&session, &entries).unwrap_err();
@@ -1003,7 +1391,7 @@ mod tests {
             (CONFIG_DESC, Value::Bytes(config_desc)),
             (CONFIG_HASH, Value::Bytes(config_hash)),
             (AUTHORITY_HASH, Value::Bytes(vec![2; 64])),
-            (MODE, Value::Bytes(vec![0])),
+            (MODE, Value::Bytes(vec![1])),
         ])
     }
 
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/profile.rs b/remote_provisioning/hwtrust/src/cbor/dice/profile.rs
index de28d3f..cf0b9b6 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/profile.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/profile.rs
@@ -34,6 +34,12 @@ pub(super) struct Profile {
 
     /// Whether the security version is a required field in the configuration descriptor.
     pub(super) security_version_optional: bool,
+
+    /// Whether the root certificate is allowed to have its mode set to debug.
+    pub(super) allow_root_mode_debug: bool,
+
+    /// Whether the root certificate's authority hash size is allowed to differ from its code hash size.
+    pub(super) allow_root_varied_auth_hash_size: bool,
 }
 
 /// Type allowed for the DICE certificate mode field.
@@ -79,6 +85,8 @@ impl Profile {
             allow_big_endian_key_usage: true,
             config_hash_unverified: true,
             security_version_optional: true,
+            allow_root_mode_debug: true,
+            allow_root_varied_auth_hash_size: true,
             ..Self::default()
         }
     }
diff --git a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
index e621756..a7c5090 100644
--- a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
@@ -1,6 +1,6 @@
 use crate::cbor::field_value::FieldValue;
 use crate::cbor::value_from_bytes;
-use crate::dice::Chain;
+use crate::dice::ChainForm;
 use crate::rkp::{Csr, DeviceInfo, ProtectedData};
 use crate::session::Session;
 use anyhow::{anyhow, bail, ensure, Context, Result};
@@ -92,7 +92,7 @@ impl Csr {
         let signed_data =
             FieldValue::from_optional_value("SignedData", csr.pop()).into_cose_sign1()?;
         let dice_chain =
-            Chain::from_value(session, csr.pop().ok_or(anyhow!("Missing DiceCertChain"))?)?;
+            ChainForm::from_value(session, csr.pop().ok_or(anyhow!("Missing DiceCertChain"))?)?;
 
         let signed_data_payload = signed_data.payload.context("missing payload in SignedData")?;
         let csr_payload_value = value_from_bytes(&signed_data_payload)
@@ -129,6 +129,7 @@ mod tests {
     use crate::cbor::rkp::csr::testutil::{parse_pem_public_key_or_panic, test_device_info};
     use crate::dice::{ChainForm, DegenerateChain, DiceMode};
     use crate::rkp::DeviceInfoVersion;
+    use crate::session::{Options, Session};
     use std::fs;
 
     #[test]
@@ -162,28 +163,41 @@ mod tests {
                 MCowBQYDK2VwAyEA3FEn/nhqoGOKNok1AJaLfTKI+aFXHf4TfC42vUyPU6s=\n\
                 -----END PUBLIC KEY-----\n",
             );
-            assert_eq!(dice_chain.root_public_key(), &root_public_key);
-            let payloads = dice_chain.payloads();
-            assert_eq!(payloads.len(), 1);
-            assert_eq!(payloads[0].issuer(), "issuer");
-            assert_eq!(payloads[0].subject(), "subject");
-            assert_eq!(payloads[0].mode(), DiceMode::Normal);
-            assert_eq!(payloads[0].code_hash(), &[0x55; 32]);
-            let expected_config_hash: &[u8] =
-                b"\xb8\x96\x54\xe2\x2c\xa4\xd2\x4a\x9c\x0e\x45\x11\xc8\xf2\x63\xf0\
-                  \x66\x0d\x2e\x20\x48\x96\x90\x14\xf4\x54\x63\xc4\xf4\x39\x30\x38";
-            assert_eq!(payloads[0].config_hash(), Some(expected_config_hash));
-            assert_eq!(payloads[0].authority_hash(), &[0x55; 32]);
-            assert_eq!(payloads[0].config_desc().component_name(), Some("component_name"));
-            assert_eq!(payloads[0].config_desc().component_version(), None);
-            assert!(!payloads[0].config_desc().resettable());
-            assert_eq!(payloads[0].config_desc().security_version(), None);
-            assert_eq!(payloads[0].config_desc().extensions(), []);
+            match dice_chain {
+                ChainForm::Proper(proper_chain) => {
+                    assert_eq!(proper_chain.root_public_key(), &root_public_key);
+                    let payloads = proper_chain.payloads();
+                    assert_eq!(payloads.len(), 1);
+                    assert_eq!(payloads[0].issuer(), "issuer");
+                    assert_eq!(payloads[0].subject(), "subject");
+                    assert_eq!(payloads[0].mode(), DiceMode::Normal);
+                    assert_eq!(payloads[0].code_hash(), &[0x55; 32]);
+                    let expected_config_hash: &[u8] =
+                        b"\xb8\x96\x54\xe2\x2c\xa4\xd2\x4a\x9c\x0e\x45\x11\xc8\xf2\x63\xf0\
+                          \x66\x0d\x2e\x20\x48\x96\x90\x14\xf4\x54\x63\xc4\xf4\x39\x30\x38";
+                    assert_eq!(payloads[0].config_hash(), Some(expected_config_hash));
+                    assert_eq!(payloads[0].authority_hash(), &[0x55; 32]);
+                    assert_eq!(payloads[0].config_desc().component_name(), Some("component_name"));
+                    assert_eq!(payloads[0].config_desc().component_version(), None);
+                    assert!(!payloads[0].config_desc().resettable());
+                    assert_eq!(payloads[0].config_desc().security_version(), None);
+                    assert_eq!(payloads[0].config_desc().extensions(), []);
+                }
+                ChainForm::Degenerate(d) => panic!("Parsed chain is not proper: {:?}", d),
+            }
         } else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         }
     }
 
+    #[test]
+    fn from_cbor_valid_v3_with_degenerate_chain() -> anyhow::Result<()> {
+        let cbor = fs::read("testdata/csr/v3_csr_degenerate_chain.cbor")?;
+        let session = Session { options: Options::vsr16() };
+        Csr::from_cbor(&session, cbor.as_slice())?;
+        Ok(())
+    }
+
     #[test]
     fn from_empty_string() {
         let err = Csr::from_base64_cbor(&Session::default(), &"").unwrap_err();
diff --git a/remote_provisioning/hwtrust/src/dice/entry.rs b/remote_provisioning/hwtrust/src/dice/entry.rs
index 2f6cbfd..eca9c8a 100644
--- a/remote_provisioning/hwtrust/src/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/dice/entry.rs
@@ -135,12 +135,6 @@ pub(crate) enum PayloadBuilderError {
     IssuerEmpty,
     #[error("subject empty")]
     SubjectEmpty,
-    #[error("bad code hash size, actual: {0}, expected: 32, 48, or 64")]
-    CodeHashSize(usize),
-    #[error("bad config hash size, actual: {0}, expected: {1}")]
-    ConfigHashSize(usize, usize),
-    #[error("bad authority hash size, actual: {0}, expected: {1}")]
-    AuthorityHashSize(usize, usize),
 }
 
 pub(crate) struct PayloadBuilder(Payload);
@@ -162,7 +156,7 @@ impl PayloadBuilder {
         })
     }
 
-    /// Builds the [`Payload`] after validating the fields.
+    /// Builds the [`Payload`] after validating the issuer and subject.
     pub fn build(self) -> Result<Payload, PayloadBuilderError> {
         if self.0.issuer.is_empty() {
             return Err(PayloadBuilderError::IssuerEmpty);
@@ -170,21 +164,6 @@ impl PayloadBuilder {
         if self.0.subject.is_empty() {
             return Err(PayloadBuilderError::SubjectEmpty);
         }
-        let used_hash_size = self.0.code_hash.len();
-        if ![32, 48, 64].contains(&used_hash_size) {
-            return Err(PayloadBuilderError::CodeHashSize(used_hash_size));
-        }
-        if let Some(ref config_hash) = self.0.config_hash {
-            if config_hash.len() != used_hash_size {
-                return Err(PayloadBuilderError::ConfigHashSize(config_hash.len(), used_hash_size));
-            }
-        }
-        if self.0.authority_hash.len() != used_hash_size {
-            return Err(PayloadBuilderError::AuthorityHashSize(
-                self.0.authority_hash.len(),
-                used_hash_size,
-            ));
-        }
         Ok(self.0)
     }
 
@@ -275,6 +254,7 @@ impl Display for ComponentVersion {
 #[derive(Debug, Default, Clone, PartialEq, Eq)]
 pub struct ConfigDesc {
     component_name: Option<String>,
+    component_instance_name: Option<String>,
     component_version: Option<ComponentVersion>,
     resettable: bool,
     security_version: Option<u64>,
@@ -288,6 +268,11 @@ impl ConfigDesc {
         self.component_name.as_deref()
     }
 
+    /// Gets the component instance name.
+    pub fn component_instance_name(&self) -> Option<&str> {
+        self.component_instance_name.as_deref()
+    }
+
     /// Gets the component version.
     pub fn component_version(&self) -> Option<&ComponentVersion> {
         self.component_version.as_ref()
@@ -319,6 +304,9 @@ impl Display for ConfigDesc {
         if let Some(component_name) = &self.component_name {
             writeln!(f, "Component Name: {}", component_name)?;
         }
+        if let Some(component_instance_name) = &self.component_instance_name {
+            writeln!(f, "Component Instance Name: {}", component_instance_name)?;
+        }
         if let Some(component_version) = &self.component_version {
             writeln!(f, "Component Version: {}", component_version)?;
         }
@@ -358,6 +346,13 @@ impl ConfigDescBuilder {
         self
     }
 
+    /// Sets the component instance name.
+    #[must_use]
+    pub fn component_instance_name(mut self, name: Option<String>) -> Self {
+        self.0.component_instance_name = name;
+        self
+    }
+
     /// Sets the component version.
     #[must_use]
     pub fn component_version(mut self, version: Option<ComponentVersion>) -> Self {
@@ -446,41 +441,6 @@ mod tests {
         assert_eq!(err, PayloadBuilderError::SubjectEmpty);
     }
 
-    #[test]
-    fn payload_builder_bad_code_hash_size() {
-        let err = valid_payload().code_hash(vec![1; 16]).build().unwrap_err();
-        assert_eq!(err, PayloadBuilderError::CodeHashSize(16));
-    }
-
-    #[test]
-    fn payload_builder_bad_authority_hash_size() {
-        let err = valid_payload().authority_hash(vec![1; 16]).build().unwrap_err();
-        assert_eq!(err, PayloadBuilderError::AuthorityHashSize(16, 64));
-    }
-
-    #[test]
-    fn payload_builder_inconsistent_authority_hash_size() {
-        let err =
-            valid_payload().code_hash(vec![1; 32]).authority_hash(vec![1; 64]).build().unwrap_err();
-        assert_eq!(err, PayloadBuilderError::AuthorityHashSize(64, 32));
-    }
-
-    #[test]
-    fn payload_builder_bad_config_hash_size() {
-        let err = valid_payload().config_hash(Some(vec![1; 16])).build().unwrap_err();
-        assert_eq!(err, PayloadBuilderError::ConfigHashSize(16, 64));
-    }
-
-    #[test]
-    fn payload_builder_inconsistent_config_hash_size() {
-        let err = valid_payload()
-            .code_hash(vec![1; 64])
-            .config_hash(Some(vec![1; 32]))
-            .build()
-            .unwrap_err();
-        assert_eq!(err, PayloadBuilderError::ConfigHashSize(32, 64));
-    }
-
     fn valid_payload() -> PayloadBuilder {
         let key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
         PayloadBuilder::with_subject_public_key(key)
diff --git a/remote_provisioning/hwtrust/src/main.rs b/remote_provisioning/hwtrust/src/main.rs
index 9cfcc97..f7f1de5 100644
--- a/remote_provisioning/hwtrust/src/main.rs
+++ b/remote_provisioning/hwtrust/src/main.rs
@@ -45,8 +45,11 @@ enum Action {
 /// [1] -- https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl
 /// [2] -- https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md
 struct DiceChainArgs {
-    /// Path to a file containing a DICE chain
+    /// Path to a file containing a DICE chain.
     chain: String,
+    /// Allow non-normal DICE chain modes.
+    #[clap(long)]
+    allow_any_mode: bool,
 }
 
 #[derive(Parser)]
@@ -58,6 +61,9 @@ struct FactoryCsrArgs {
     /// rkp_factory_extraction_tool. Each line is interpreted as a separate JSON blob containing
     /// a base64-encoded CSR.
     csr_file: String,
+    /// Allow non-normal DICE chain modes.
+    #[clap(long)]
+    allow_any_mode: bool,
 }
 
 #[derive(Parser)]
@@ -68,6 +74,9 @@ struct FactoryCsrArgs {
 struct CsrArgs {
     /// Path to a file containing a single CSR, encoded as CBOR.
     csr_file: String,
+    /// Allow non-normal DICE chain modes.
+    #[clap(long)]
+    allow_any_mode: bool,
 }
 
 #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
@@ -125,7 +134,8 @@ fn main() -> Result<()> {
 }
 
 fn verify_dice_chain(args: &Args, sub_args: &DiceChainArgs) -> Result<Option<String>> {
-    let session = session_from_vsr(args.vsr);
+    let mut session = session_from_vsr(args.vsr);
+    session.set_allow_any_mode(sub_args.allow_any_mode);
     let chain = dice::ChainForm::from_cbor(&session, &fs::read(&sub_args.chain)?)?;
     if args.verbose {
         println!("{chain:#?}");
@@ -141,7 +151,8 @@ favor of full DICE chains, rooted in ROM, that measure the system's boot compone
 }
 
 fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<Option<String>> {
-    let session = session_from_vsr(args.vsr);
+    let mut session = session_from_vsr(args.vsr);
+    session.set_allow_any_mode(sub_args.allow_any_mode);
     let input = &fs::File::open(&sub_args.csr_file)?;
     let mut csr_count = 0;
     for line in io::BufReader::new(input).lines() {
@@ -162,7 +173,8 @@ fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<Option<St
 }
 
 fn parse_csr(args: &Args, sub_args: &CsrArgs) -> Result<Option<String>> {
-    let session = session_from_vsr(args.vsr);
+    let mut session = session_from_vsr(args.vsr);
+    session.set_allow_any_mode(sub_args.allow_any_mode);
     let input = &fs::File::open(&sub_args.csr_file)?;
     let csr = rkp::Csr::from_cbor(&session, input)?;
     if args.verbose {
diff --git a/remote_provisioning/hwtrust/src/rkp/csr.rs b/remote_provisioning/hwtrust/src/rkp/csr.rs
index 23c3081..0f680fc 100644
--- a/remote_provisioning/hwtrust/src/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/csr.rs
@@ -1,6 +1,6 @@
 use std::fmt;
 
-use crate::{dice::Chain, rkp::DeviceInfo};
+use crate::{dice::ChainForm, rkp::DeviceInfo};
 
 use super::ProtectedData;
 
@@ -25,7 +25,7 @@ pub enum Csr {
         /// Describes the device that is requesting certificates.
         device_info: DeviceInfo,
         /// The DICE chain for the device
-        dice_chain: Chain,
+        dice_chain: ChainForm,
     },
 }
 
diff --git a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
index 47fbb95..d64d6d1 100644
--- a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
@@ -133,8 +133,13 @@ mod tests {
                 MCowBQYDK2VwAyEA3FEn/nhqoGOKNok1AJaLfTKI+aFXHf4TfC42vUyPU6s=\n\
                 -----END PUBLIC KEY-----\n",
             );
-            assert_eq!(dice_chain.root_public_key(), &root_public_key);
-            assert_eq!(dice_chain.payloads().len(), 1);
+            match dice_chain {
+                ChainForm::Proper(p) => {
+                    assert_eq!(p.root_public_key(), &root_public_key);
+                    assert_eq!(p.payloads().len(), 1);
+                }
+                ChainForm::Degenerate(d) => panic!("Parsed chain is not proper: {:?}", d),
+            }
         } else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         }
@@ -179,8 +184,13 @@ mod tests {
                 zpPPnt2rAOdqL9DSDZcIBbLas5xh9psaEaD0o/0KxlUVZplO/BPmRf3Ycg==\n\
                 -----END PUBLIC KEY-----\n",
             );
-            assert_eq!(dice_chain.root_public_key(), &root_public_key);
-            assert_eq!(dice_chain.payloads().len(), 1);
+            match dice_chain {
+                ChainForm::Proper(p) => {
+                    assert_eq!(p.root_public_key(), &root_public_key);
+                    assert_eq!(p.payloads().len(), 1);
+                }
+                ChainForm::Degenerate(d) => panic!("Parsed chain is not proper: {:?}", d),
+            }
         } else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         }
diff --git a/remote_provisioning/hwtrust/src/session.rs b/remote_provisioning/hwtrust/src/session.rs
index 0b90ed6..b9701dc 100644
--- a/remote_provisioning/hwtrust/src/session.rs
+++ b/remote_provisioning/hwtrust/src/session.rs
@@ -15,6 +15,15 @@ pub struct Session {
 pub struct Options {
     /// The range of supported Android Profile for DICE versions.
     pub dice_profile_range: DiceProfileRange,
+    /// Allows DICE chains to have non-normal mode values.
+    pub allow_any_mode: bool,
+}
+
+impl Session {
+    /// Set allow_any_mode.
+    pub fn set_allow_any_mode(&mut self, allow_any_mode: bool) {
+        self.options.allow_any_mode = allow_any_mode
+    }
 }
 
 /// An inclusive range of Android Profile for DICE versions.
@@ -57,6 +66,7 @@ impl Options {
                 ProfileVersion::Android13,
                 ProfileVersion::Android13,
             ),
+            ..Default::default()
         }
     }
 
@@ -67,6 +77,7 @@ impl Options {
                 ProfileVersion::Android14,
                 ProfileVersion::Android14,
             ),
+            ..Default::default()
         }
     }
 
@@ -77,6 +88,7 @@ impl Options {
                 ProfileVersion::Android14,
                 ProfileVersion::Android15,
             ),
+            ..Default::default()
         }
     }
 
@@ -87,6 +99,7 @@ impl Options {
                 ProfileVersion::Android14,
                 ProfileVersion::Android16,
             ),
+            ..Default::default()
         }
     }
 }
diff --git a/remote_provisioning/hwtrust/testdata/csr/v3_csr_degenerate_chain.cbor b/remote_provisioning/hwtrust/testdata/csr/v3_csr_degenerate_chain.cbor
new file mode 100644
index 0000000..c9a3a56
Binary files /dev/null and b/remote_provisioning/hwtrust/testdata/csr/v3_csr_degenerate_chain.cbor differ
diff --git a/remote_provisioning/hwtrust/tests/hwtrust_cli.rs b/remote_provisioning/hwtrust/tests/hwtrust_cli.rs
index 8136a7d..a0c7289 100644
--- a/remote_provisioning/hwtrust/tests/hwtrust_cli.rs
+++ b/remote_provisioning/hwtrust/tests/hwtrust_cli.rs
@@ -8,7 +8,7 @@ fn hwtrust_bin() -> &'static str {
 #[test]
 fn exit_code_for_good_chain() {
     let output = Command::new(hwtrust_bin())
-        .args(["dice-chain", "testdata/dice/valid_ed25519.chain"])
+        .args(["dice-chain", "--allow-any-mode", "testdata/dice/valid_ed25519.chain"])
         .output()
         .unwrap();
     assert!(output.status.success());
diff --git a/sanitizer-status/sanitizer-status.cpp b/sanitizer-status/sanitizer-status.cpp
index f631a0a..bd08f01 100644
--- a/sanitizer-status/sanitizer-status.cpp
+++ b/sanitizer-status/sanitizer-status.cpp
@@ -34,6 +34,8 @@
 
 #include <bionic/mte.h>
 
+char global[32] = {};
+
 // crashes if built with -fsanitize={address,hwaddress}
 void test_crash_malloc_overflow() {
   volatile char* heap = reinterpret_cast<volatile char *>(malloc(32));
@@ -57,6 +59,13 @@ void test_crash_stack() {
   printf("(HW)ASAN / Stack MTE: Stack Test Failed\n");
 }
 
+// crashes if built with -fsanitize={address,hwaddress,memtag-globals}
+void test_crash_globals() {
+  volatile char* p_global = global;
+  p_global[32] = p_global[32];
+  printf("(HW)ASAN / Globals MTE: Globals Test Failed\n");
+}
+
 void test_crash_pthread_mutex_unlock() {
   volatile char* heap = reinterpret_cast<volatile char *>(malloc(32));
   pthread_mutex_unlock((pthread_mutex_t*)&heap[32]);
@@ -207,6 +216,7 @@ int main(int argc, const char** argv) {
     hwasan_failures += test(test_crash_malloc_uaf);
     hwasan_failures += test(test_crash_stack);
     hwasan_failures += test(test_crash_pthread_mutex_unlock);
+    hwasan_failures += test(test_crash_globals);
 
     if (!hwasan_failures)
       printf("HWASAN: OK\n");
@@ -319,5 +329,22 @@ int main(int argc, const char** argv) {
     failures += stack_mte_failures;
   }
 
+  if (test_everything || have_option("globals_mte", argv, argc)) {
+    int globals_mte_failures = 0;
+
+    if (!(mte_supported() && !__has_feature(address_sanitizer) &&
+          !__has_feature(hwaddress_sanitizer))) {
+      globals_mte_failures += 1;
+      printf("MTE: Not supported\n");
+    }
+
+    globals_mte_failures += test(test_crash_globals);
+
+    if (!globals_mte_failures)
+      printf("Globals MTE: OK\n");
+
+    failures += globals_mte_failures;
+  }
+
   return failures > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
 }
```

