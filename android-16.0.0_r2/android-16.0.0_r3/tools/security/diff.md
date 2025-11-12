```diff
diff --git a/fuzzing/orphans/libskia/Android.bp b/fuzzing/orphans/libskia/Android.bp
index 128d0fc..62c3897 100644
--- a/fuzzing/orphans/libskia/Android.bp
+++ b/fuzzing/orphans/libskia/Android.bp
@@ -38,7 +38,6 @@ cc_fuzz {
           "libcutils",
           "libEGL",
           "libGLESv2",
-          "libheif",
           "libvulkan",
           "libnativewindow",
       ],
diff --git a/fuzzing/orphans/libskia/OWNERS b/fuzzing/orphans/libskia/OWNERS
new file mode 100644
index 0000000..0afe547
--- /dev/null
+++ b/fuzzing/orphans/libskia/OWNERS
@@ -0,0 +1 @@
+per-file Android.bp = nscobie@google.com, bungeman@google.com, egdaniel@google.com, jmbetancourt@google.com
diff --git a/remote_provisioning/hwtrust/TEST_MAPPING b/remote_provisioning/hwtrust/TEST_MAPPING
index 875094c..2cf446b 100644
--- a/remote_provisioning/hwtrust/TEST_MAPPING
+++ b/remote_provisioning/hwtrust/TEST_MAPPING
@@ -18,11 +18,6 @@
       "name": "libclient_vm_csr.test"
     }
   ],
-  "avf-presubmit": [
-    {
-      "name": "rialto_test"
-    }
-  ],
   "avf-postsubmit": [
     {
       "name": "VtsHalRemotelyProvisionedComponentTargetTest"
diff --git a/remote_provisioning/hwtrust/cxxbridge/lib.rs b/remote_provisioning/hwtrust/cxxbridge/lib.rs
index fcea41a..5600501 100644
--- a/remote_provisioning/hwtrust/cxxbridge/lib.rs
+++ b/remote_provisioning/hwtrust/cxxbridge/lib.rs
@@ -133,11 +133,14 @@ impl TryInto<Options> for ffi::DiceChainKind {
 /// A DICE chain as exposed over the cxx bridge.
 pub struct DiceChain(Option<ChainForm>);
 
-fn new_session(
+fn new_session<F>(
     kind: ffi::DiceChainKind,
-    allow_any_mode: bool,
     instance: &str,
-) -> Result<Session, String> {
+    set_options: F,
+) -> Result<Session, String>
+where
+    F: Fn(&mut Options),
+{
     let mut options: Options = kind.try_into()?;
     let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
         return Err(format!("invalid RKP instance: {}", instance));
@@ -146,10 +149,9 @@ fn new_session(
         options.dice_profile_range =
             DiceProfileRange::new(options.dice_profile_range.start(), AVF_DICE_PROFILE_VERSION)
     }
-    let mut session = Session { options };
-    session.set_rkp_instance(rkp_instance);
-    session.set_allow_any_mode(allow_any_mode);
-    Ok(session)
+    options.rkp_instance = rkp_instance;
+    set_options(&mut options);
+    Ok(Session { options })
 }
 
 fn verify_dice_chain(
@@ -158,7 +160,7 @@ fn verify_dice_chain(
     allow_any_mode: bool,
     instance: &str,
 ) -> ffi::VerifyDiceChainResult {
-    let session = match new_session(kind, allow_any_mode, instance) {
+    let session = match new_session(kind, instance, |o| o.allow_any_mode = allow_any_mode) {
         Ok(session) => session,
         Err(e) => {
             return ffi::VerifyDiceChainResult {
@@ -279,11 +281,13 @@ fn validate_csr(
     allow_any_mode: bool,
     instance: &str,
 ) -> ffi::ValidateCsrResult {
-    let mut session = match new_session(kind, allow_any_mode, instance) {
+    let session = match new_session(kind, instance, |o| {
+        o.allow_any_mode = allow_any_mode;
+        o.is_factory = is_factory;
+    }) {
         Ok(session) => session,
         Err(e) => return ffi::ValidateCsrResult { error: e, csr: Box::new(Csr(None)) },
     };
-    session.set_is_factory(is_factory);
     match InnerCsr::from_cbor(&session, csr) {
         Ok(csr) => {
             let csr = Box::new(Csr(Some(csr)));
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/chain.rs b/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
index 15269f7..2fd09b3 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/chain.rs
@@ -3,6 +3,7 @@ use super::{cose_key_from_cbor_value, KeyOpsType};
 use crate::cbor::dice::entry::PayloadFields;
 use crate::cbor::value_from_bytes;
 use crate::dice::{Chain, ChainForm, DegenerateChain, Payload, ProfileVersion};
+use crate::log_verbose;
 use crate::publickey::PublicKey;
 use crate::session::Session;
 use anyhow::{bail, Context, Result};
@@ -78,6 +79,7 @@ impl Chain {
     ) -> Result<Self> {
         let mut payloads = Vec::with_capacity(values.len());
         let mut previous_public_key = &root;
+        log_verbose!(session, "Received DICE chain with {} entries", values.len());
         for (n, value) in values.enumerate() {
             let entry = Entry::verify_cbor_value(value, previous_public_key)
                 .with_context(|| format!("Invalid entry at index {}", n))?;
@@ -92,6 +94,7 @@ impl Chain {
             };
             let payload = Payload::from_cbor(session, entry.payload(), config_format, is_root)
                 .with_context(|| format!("Invalid payload at index {}", n))?;
+            log_verbose!(session, "Entry {n}: {payload:?}");
             payloads.push(payload);
             let previous = payloads.last().unwrap();
             previous_public_key = previous.subject_public_key();
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/entry.rs b/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
index dc8dd7f..654ad67 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
@@ -710,11 +710,11 @@ mod tests {
     fn mode_not_configured() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![0]));
-        let mut session = Session { options: Options::default() };
+        let session = Session { options: Options::default() };
         let serialized_fields = serialize_fields(fields);
         Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
             .unwrap_err();
-        session.set_allow_any_mode(true);
+        let session = Session { options: Options { allow_any_mode: true, ..Options::default() } };
         let payload =
             Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
                 .unwrap();
@@ -777,11 +777,11 @@ mod tests {
     fn mode_debug() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![2]));
-        let mut session = Session { options: Options::default() };
+        let session = Session { options: Options::default() };
         let serialized_fields = serialize_fields(fields);
         Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
             .unwrap_err();
-        session.set_allow_any_mode(true);
+        let session = Session { options: Options { allow_any_mode: true, ..Options::default() } };
         let payload =
             Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
                 .unwrap();
@@ -813,11 +813,11 @@ mod tests {
     fn mode_recovery() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![3]));
-        let mut session = Session { options: Options::default() };
+        let session = Session { options: Options::default() };
         let serialized_fields = serialize_fields(fields);
         Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
             .unwrap_err();
-        session.set_allow_any_mode(true);
+        let session = Session { options: Options { allow_any_mode: true, ..Options::default() } };
         let payload =
             Payload::from_cbor(&session, &serialized_fields, ConfigFormat::Android, !IS_ROOT)
                 .unwrap();
@@ -837,8 +837,7 @@ mod tests {
     fn mode_invalid_becomes_not_configured() {
         let mut fields = valid_payload_fields();
         fields.insert(MODE, Value::Bytes(vec![4]));
-        let mut session = Session { options: Options::default() };
-        session.set_allow_any_mode(true);
+        let session = Session { options: Options { allow_any_mode: true, ..Options::default() } };
         let payload = Payload::from_cbor(
             &session,
             &serialize_fields(fields),
diff --git a/remote_provisioning/hwtrust/src/cbor/field_value.rs b/remote_provisioning/hwtrust/src/cbor/field_value.rs
index 8c2e54c..08d50eb 100644
--- a/remote_provisioning/hwtrust/src/cbor/field_value.rs
+++ b/remote_provisioning/hwtrust/src/cbor/field_value.rs
@@ -64,7 +64,7 @@ impl FieldValue {
     }
 
     pub fn is_bytes(&self) -> bool {
-        self.value.as_ref().map_or(false, |v| v.is_bytes())
+        self.value.as_ref().is_some_and(|v| v.is_bytes())
     }
 
     pub fn into_optional_bytes(self) -> Result<Option<Vec<u8>>, FieldValueError> {
@@ -174,7 +174,7 @@ impl FieldValue {
     }
 
     pub fn is_integer(&self) -> bool {
-        self.value.as_ref().map_or(false, |v| v.is_integer())
+        self.value.as_ref().is_some_and(|v| v.is_integer())
     }
 
     pub fn into_u32(self) -> Result<u32, FieldValueError> {
diff --git a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
index 3f3526e..8800a6d 100644
--- a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
@@ -391,9 +391,13 @@ mod tests {
     #[test]
     fn from_cbor_valid_v3_avf_with_rkpvm_chain() -> anyhow::Result<()> {
         let input = fs::read("testdata/csr/v3_csr_avf.cbor")?;
-        let mut session = Session::default();
-        session.set_allow_any_mode(true);
-        session.set_rkp_instance(RkpInstance::Avf);
+        let session = Session {
+            options: Options {
+                allow_any_mode: true,
+                rkp_instance: RkpInstance::Avf,
+                ..Options::default()
+            },
+        };
         let csr = Csr::from_cbor(&session, input.as_slice())?;
         let Csr::V3 { dice_chain, csr_payload, .. } = csr else {
             panic!("Parsed CSR was not V3: {:?}", csr);
diff --git a/remote_provisioning/hwtrust/src/dice/entry.rs b/remote_provisioning/hwtrust/src/dice/entry.rs
index 9e68850..28e14fa 100644
--- a/remote_provisioning/hwtrust/src/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/dice/entry.rs
@@ -1,3 +1,4 @@
+use crate::debug_option;
 use crate::publickey::PublicKey;
 use std::fmt::{self, Display, Formatter};
 use thiserror::Error;
@@ -237,7 +238,7 @@ impl PayloadBuilder {
 }
 
 /// Version of the component from the configuration descriptor.
-#[derive(Debug, Clone, PartialEq, Eq)]
+#[derive(Clone, PartialEq, Eq)]
 pub enum ComponentVersion {
     /// An integer component version number.
     Integer(i64),
@@ -249,14 +250,20 @@ impl Display for ComponentVersion {
     fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
         match self {
             ComponentVersion::Integer(n) => write!(f, "{n}")?,
-            ComponentVersion::String(s) => write!(f, "{s}")?,
+            ComponentVersion::String(s) => write!(f, "\"{s}\"")?,
         }
         Ok(())
     }
 }
 
+impl fmt::Debug for ComponentVersion {
+    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
+        write!(f, "{self}")
+    }
+}
+
 /// Fields from the configuration descriptor.
-#[derive(Debug, Default, Clone, PartialEq, Eq)]
+#[derive(Default, Clone, PartialEq, Eq)]
 pub struct ConfigDesc {
     component_name: Option<String>,
     component_instance_name: Option<String>,
@@ -331,6 +338,22 @@ impl Display for ConfigDesc {
     }
 }
 
+impl fmt::Debug for ConfigDesc {
+    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
+        let mut debug = f.debug_struct("ConfigDesc");
+        debug.field("component_name", debug_option(&self.component_name));
+        debug.field("component_instance_name", debug_option(&self.component_instance_name));
+        debug.field("component_version", debug_option(&self.component_version));
+        debug.field("resettable", &self.resettable);
+        debug.field("security_version", &self.security_version);
+        debug.field("rkp_vm_marker", &self.rkp_vm_marker);
+        for (key, value) in &self.extensions {
+            debug.field(&format!("[ext] {key}"), &hex::encode(value));
+        }
+        debug.finish()
+    }
+}
+
 pub(crate) struct ConfigDescBuilder(ConfigDesc);
 
 impl ConfigDescBuilder {
diff --git a/remote_provisioning/hwtrust/src/lib.rs b/remote_provisioning/hwtrust/src/lib.rs
index 2b14dba..a74ada1 100644
--- a/remote_provisioning/hwtrust/src/lib.rs
+++ b/remote_provisioning/hwtrust/src/lib.rs
@@ -8,3 +8,10 @@ pub mod session;
 
 mod cbor;
 mod eek;
+
+pub(crate) fn debug_option<T: std::fmt::Debug>(option: &Option<T>) -> &dyn std::fmt::Debug {
+    match option {
+        Some(x) => x,
+        n => n,
+    }
+}
diff --git a/remote_provisioning/hwtrust/src/main.rs b/remote_provisioning/hwtrust/src/main.rs
index e2785fd..15b9f42 100644
--- a/remote_provisioning/hwtrust/src/main.rs
+++ b/remote_provisioning/hwtrust/src/main.rs
@@ -4,6 +4,7 @@ use anyhow::{bail, Result};
 use clap::{Parser, Subcommand, ValueEnum};
 use hwtrust::dice;
 use hwtrust::dice::ChainForm;
+use hwtrust::log_verbose;
 use hwtrust::rkp;
 use hwtrust::session::{Options, RkpInstance, Session};
 use std::io::BufRead;
@@ -99,27 +100,31 @@ enum VsrVersion {
     Vsr16,
 }
 
-fn session_from_vsr(vsr: Option<VsrVersion>) -> Session {
-    Session {
-        options: match vsr {
-            Some(VsrVersion::Vsr13) => Options::vsr13(),
-            Some(VsrVersion::Vsr14) => Options::vsr14(),
-            Some(VsrVersion::Vsr15) => Options::vsr15(),
-            Some(VsrVersion::Vsr16) => {
-                println!();
-                println!();
-                println!("  ********************************************************************");
-                println!("  ! The selected VSR is not finalized and is subject to change.      !");
-                println!("  ! Please contact your TAM if you intend to depend on the           !");
-                println!("  ! validation rules use for the selected VSR.                       !");
-                println!("  ********************************************************************");
-                println!();
-                println!();
-                Options::vsr16()
-            }
-            None => Options::default(),
-        },
-    }
+fn session_from_args<F>(args: &Args, set_options: F) -> Session
+where
+    F: Fn(&mut Options),
+{
+    let mut options = match args.vsr {
+        Some(VsrVersion::Vsr13) => Options::vsr13(),
+        Some(VsrVersion::Vsr14) => Options::vsr14(),
+        Some(VsrVersion::Vsr15) => Options::vsr15(),
+        Some(VsrVersion::Vsr16) => {
+            println!();
+            println!();
+            println!("  ********************************************************************");
+            println!("  ! The selected VSR is not finalized and is subject to change.      !");
+            println!("  ! Please contact your TAM if you intend to depend on the           !");
+            println!("  ! validation rules use for the selected VSR.                       !");
+            println!("  ********************************************************************");
+            println!();
+            println!();
+            Options::vsr16()
+        }
+        None => Options::default(),
+    };
+    options.verbose = args.verbose;
+    set_options(&mut options);
+    Session { options }
 }
 
 fn main() -> Result<()> {
@@ -142,13 +147,12 @@ fn main() -> Result<()> {
 }
 
 fn verify_dice_chain(args: &Args, sub_args: &DiceChainArgs) -> Result<Option<String>> {
-    let mut session = session_from_vsr(args.vsr);
-    session.set_allow_any_mode(sub_args.allow_any_mode);
-    session.set_rkp_instance(sub_args.rkp_instance);
+    let session = session_from_args(args, |o| {
+        o.allow_any_mode = sub_args.allow_any_mode;
+        o.rkp_instance = sub_args.rkp_instance;
+    });
     let chain = dice::ChainForm::from_cbor(&session, &fs::read(&sub_args.chain)?)?;
-    if args.verbose {
-        println!("{chain:#?}");
-    }
+    log_verbose!(session, "{chain:#?}");
     if let ChainForm::Degenerate(_) = chain {
         return Ok(Some(String::from(
             "WARNING!
@@ -160,8 +164,7 @@ favor of full DICE chains, rooted in ROM, that measure the system's boot compone
 }
 
 fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<Option<String>> {
-    let mut session = session_from_vsr(args.vsr);
-    session.set_allow_any_mode(sub_args.allow_any_mode);
+    let session = session_from_args(args, |o| o.allow_any_mode = sub_args.allow_any_mode);
     let input = &fs::File::open(&sub_args.csr_file)?;
     let mut csr_count = 0;
     for line in io::BufReader::new(input).lines() {
@@ -171,9 +174,7 @@ fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<Option<St
         }
         let csr = rkp::FactoryCsr::from_json(&session, &line)?;
         csr_count += 1;
-        if args.verbose {
-            println!("{csr_count}: {csr:#?}");
-        }
+        log_verbose!(session, "{csr_count}: {csr:#?}");
     }
     if csr_count == 0 {
         bail!("No CSRs found in the input file '{}'", sub_args.csr_file);
@@ -182,14 +183,13 @@ fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<Option<St
 }
 
 fn parse_csr(args: &Args, sub_args: &CsrArgs) -> Result<Option<String>> {
-    let mut session = session_from_vsr(args.vsr);
-    session.set_allow_any_mode(sub_args.allow_any_mode);
-    session.set_rkp_instance(sub_args.rkp_instance);
+    let session = session_from_args(args, |o| {
+        o.allow_any_mode = sub_args.allow_any_mode;
+        o.rkp_instance = sub_args.rkp_instance;
+    });
     let input = &fs::File::open(&sub_args.csr_file)?;
     let csr = rkp::Csr::from_cbor(&session, input)?;
-    if args.verbose {
-        print!("{csr:#?}");
-    }
+    log_verbose!(session, "{csr:#?}");
     Ok(None)
 }
 
diff --git a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
index f1ce6b4..e3c941f 100644
--- a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
@@ -54,6 +54,7 @@ mod tests {
     use crate::rkp::device_info::DeviceInfoVersion;
     use crate::rkp::factory_csr::FactoryCsr;
     use crate::rkp::{ProtectedData, UdsCerts, UdsCertsEntry};
+    use crate::session::Options;
     use anyhow::anyhow;
     use itertools::Itertools;
     use openssl::{pkey::PKey, x509::X509};
@@ -318,8 +319,7 @@ mod tests {
     fn from_json_valid_v3_avf_with_rkpvm_markers() {
         let json = fs::read_to_string("testdata/factory_csr/v3_avf_valid_with_rkpvm_markers.json")
             .unwrap();
-        let mut session = Session::default();
-        session.set_allow_any_mode(true);
+        let session = Session { options: Options { allow_any_mode: true, ..Options::default() } };
         let csr = FactoryCsr::from_json(&session, &json).unwrap();
         assert_eq!(csr.name, "avf");
     }
diff --git a/remote_provisioning/hwtrust/src/session.rs b/remote_provisioning/hwtrust/src/session.rs
index 2c96360..36bedca 100644
--- a/remote_provisioning/hwtrust/src/session.rs
+++ b/remote_provisioning/hwtrust/src/session.rs
@@ -59,17 +59,17 @@ impl FromStr for RkpInstance {
     }
 }
 
-impl Session {
-    /// Set is_factory
-    pub fn set_is_factory(&mut self, is_factory: bool) {
-        self.options.is_factory = is_factory;
-    }
-
-    /// Set allow_any_mode.
-    pub fn set_allow_any_mode(&mut self, allow_any_mode: bool) {
-        self.options.allow_any_mode = allow_any_mode
-    }
+/// Wrapper for Session.log_verbose with inline format string support.
+#[macro_export]
+macro_rules! log_verbose {
+    ($session:ident, $($arg:tt)*) => {
+        if $session.options.verbose {
+            println!($($arg)*);
+        }
+    };
+}
 
+impl Session {
     /// Sets the RKP instance associated to the session.
     pub fn set_rkp_instance(&mut self, rkp_instance: RkpInstance) {
         self.options.rkp_instance = rkp_instance
```

