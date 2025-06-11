```diff
diff --git a/OWNERS b/OWNERS
index af3169f..199ae99 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,7 +2,6 @@
 
 # Sanitizers
 pcc@google.com
-eugenis@google.com
 fmayer@google.com
 
 
@@ -12,7 +11,6 @@ kalder@google.com
 mspector@google.com
 
 # ASA
-olorin@google.com
 
 # Remote Provisioning
 jbires@google.com
diff --git a/fuzzing/orphans/OWNERS b/fuzzing/orphans/OWNERS
index 1036c55..6f75e04 100644
--- a/fuzzing/orphans/OWNERS
+++ b/fuzzing/orphans/OWNERS
@@ -1,3 +1,2 @@
 hamzeh@google.com
 kalder@google.com
-mspector@google.com
diff --git a/fuzzing/orphans/sbcdecoder/OWNERS b/fuzzing/orphans/sbcdecoder/OWNERS
index 241b65a..e133ca6 100644
--- a/fuzzing/orphans/sbcdecoder/OWNERS
+++ b/fuzzing/orphans/sbcdecoder/OWNERS
@@ -2,4 +2,3 @@ hamzeh@google.com
 ispo@google.com
 kalder@google.com
 mspector@google.com
-semsmith@google.com
diff --git a/fuzzing/orphans/widevine/trusty/OWNERS b/fuzzing/orphans/widevine/trusty/OWNERS
index 5f8199f..e69de29 100644
--- a/fuzzing/orphans/widevine/trusty/OWNERS
+++ b/fuzzing/orphans/widevine/trusty/OWNERS
@@ -1 +0,0 @@
-trong@google.com
diff --git a/fuzzing/system_fuzzers/OWNERS b/fuzzing/system_fuzzers/OWNERS
index 241b65a..ad9b93b 100644
--- a/fuzzing/system_fuzzers/OWNERS
+++ b/fuzzing/system_fuzzers/OWNERS
@@ -1,5 +1,3 @@
 hamzeh@google.com
 ispo@google.com
 kalder@google.com
-mspector@google.com
-semsmith@google.com
diff --git a/remote_provisioning/attestation_testing/attestation_test_host.py b/remote_provisioning/attestation_testing/attestation_test_host.py
index 4632cd9..a73b1aa 100644
--- a/remote_provisioning/attestation_testing/attestation_test_host.py
+++ b/remote_provisioning/attestation_testing/attestation_test_host.py
@@ -9,6 +9,8 @@ FAILURE_PREFIX = 'Failure: '
 FINISHED_TAG = 'AttestationFinished'
 INFO_TAG = 'AttestationFailInfo'
 INFO_PREFIX = ' ' * len(FAILURE_PREFIX)
+ATTESTATION_PRINT_TAG = 'AttestationPrint'
+ATTESTATION_PRINT_PREFIX = 'Printed Attestation: '
 devnull = open(os.devnull, 'wb')
 
 # Clear logcat
@@ -23,7 +25,9 @@ while not finished and read_retry < 5:
     time.sleep(1)
     logcat = subprocess.check_output(['adb', 'logcat', '-d'], stderr=subprocess.STDOUT)
     for line in logcat.decode('utf-8').split('\n'):
-        if INFO_TAG in line:
+        if ATTESTATION_PRINT_TAG in line:
+            print(ATTESTATION_PRINT_PREFIX + line[line.index('AttestationPrint') + len('AttestationPrint:'):])
+        elif INFO_TAG in line:
             print(INFO_PREFIX + line[line.index('AttestationFailInfo') + len('AttestationFailInfo:'):])
         elif FAILURE_TAG in line:
             failures += 1
diff --git a/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java b/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java
index 44ddff7..53691a5 100644
--- a/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java
+++ b/remote_provisioning/attestation_testing/java/com/google/attestationexample/AttestationTest.java
@@ -169,6 +169,8 @@ public class AttestationTest extends AsyncTask<Void, String, Void> {
         }
 
         Attestation attestation = new Attestation(attestationCert);
+        Utils.logAttestation(attestation.toString());
+
         if (!Arrays.equals(attestation.getAttestationChallenge(), challenge)) {
             Utils.logError("challenge mismatch\nExpected:",
                     challenge, attestation.getAttestationChallenge());
diff --git a/remote_provisioning/attestation_testing/java/com/google/attestationexample/AuthorizationList.java b/remote_provisioning/attestation_testing/java/com/google/attestationexample/AuthorizationList.java
index 29b317e..6d30e3c 100644
--- a/remote_provisioning/attestation_testing/java/com/google/attestationexample/AuthorizationList.java
+++ b/remote_provisioning/attestation_testing/java/com/google/attestationexample/AuthorizationList.java
@@ -29,6 +29,7 @@ import org.bouncycastle.asn1.ASN1Primitive;
 import org.bouncycastle.asn1.ASN1Sequence;
 import org.bouncycastle.asn1.ASN1SequenceParser;
 import org.bouncycastle.asn1.ASN1TaggedObject;
+import org.bouncycastle.util.encoders.Hex;
 
 import java.io.IOException;
 import java.security.cert.CertificateParsingException;
@@ -123,6 +124,7 @@ public class AuthorizationList {
     private static final int KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709;
     private static final int KM_TAG_VENDOR_PATCHLEVEL = KM_UINT | 718;
     private static final int KM_TAG_BOOT_PATCHLEVEL = KM_UINT | 719;
+    private static final int KM_TAG_MODULE_HASH = KM_BYTES | 724;
 
     // Map for converting padding values to strings
     private static final ImmutableMap<Integer, String> paddingMap = ImmutableMap
@@ -180,6 +182,7 @@ public class AuthorizationList {
     private Integer vendorPatchLevel;
     private Integer bootPatchLevel;
     private AttestationApplicationId attestationApplicationId;
+    private byte[] moduleHash;
 
     public AuthorizationList(ASN1Encodable sequence) throws CertificateParsingException {
         if (!(sequence instanceof ASN1Sequence)) {
@@ -279,6 +282,9 @@ public class AuthorizationList {
                 case KM_TAG_ALL_APPLICATIONS & KEYMASTER_TAG_TYPE_MASK:
                     allApplications = true;
                     break;
+                case KM_TAG_MODULE_HASH & KEYMASTER_TAG_TYPE_MASK:
+                    moduleHash = Asn1Utils.getByteArrayFromAsn1(value);
+                    break;
             }
         }
 
@@ -512,6 +518,10 @@ public class AuthorizationList {
         return attestationApplicationId;
     }
 
+    public byte[] getModuleHash() {
+        return moduleHash.clone();
+    }
+
     @Override
     public String toString() {
         StringBuilder s = new StringBuilder();
@@ -602,7 +612,11 @@ public class AuthorizationList {
         }
 
         if (attestationApplicationId != null) {
-            s.append("\nApplication ID:").append(attestationApplicationId.toString());
+            s.append("\nAttestation Application ID:").append(attestationApplicationId.toString());
+        }
+
+        if (moduleHash != null) {
+            s.append("\nModule Hash: ").append(Hex.toHexString(moduleHash));
         }
 
         return s.toString();
diff --git a/remote_provisioning/attestation_testing/java/com/google/attestationexample/Utils.java b/remote_provisioning/attestation_testing/java/com/google/attestationexample/Utils.java
index e13d8a8..e9c839e 100644
--- a/remote_provisioning/attestation_testing/java/com/google/attestationexample/Utils.java
+++ b/remote_provisioning/attestation_testing/java/com/google/attestationexample/Utils.java
@@ -7,6 +7,7 @@ import java.util.Arrays;
 public class Utils {
     public static final String FAIL = "AttestationFail";
     public static final String FAIL_INFO = "AttestationFailInfo";
+    public static final String ATTESTATION_PRINT = "AttestationPrint";
 
     public static void logError(String message, int expected, int actual) {
         Log.e(FAIL, message);
@@ -19,4 +20,8 @@ public class Utils {
         Log.e(FAIL_INFO, "Expected: " + Arrays.toString(expected));
         Log.e(FAIL_INFO, "Actual: " + Arrays.toString(actual));
     }
+
+    public static void logAttestation(String attestation) {
+        Log.i(ATTESTATION_PRINT, attestation + "\n");
+    }
 }
diff --git a/remote_provisioning/hwtrust/Android.bp b/remote_provisioning/hwtrust/Android.bp
index 94ad177..75782c7 100644
--- a/remote_provisioning/hwtrust/Android.bp
+++ b/remote_provisioning/hwtrust/Android.bp
@@ -9,6 +9,7 @@ rust_defaults {
     rustlibs: [
         "libanyhow",
         "libbase64_rust",
+        "libchrono",
         "libciborium",
         "libclap",
         "libcoset",
@@ -21,11 +22,13 @@ rust_defaults {
         host: {
             rlibs: ["libopenssl_static"],
             // dylib is disabled due to compile failure in libhwtrust. See b/373621186 for details.
-            dylib: { enabled: false, },
+            dylib: {
+                enabled: false,
+            },
         },
         android: {
             rustlibs: ["libopenssl"],
-        }
+        },
     },
 }
 
@@ -40,6 +43,7 @@ rust_library {
         "com.android.compos",
         "com.android.virt",
     ],
+    min_sdk_version: "35",
 }
 
 rust_test {
@@ -74,7 +78,7 @@ rust_binary {
             },
             static_executable: true,
         },
-    }
+    },
 }
 
 rust_test {
@@ -92,7 +96,7 @@ rust_test {
     compile_multilib: "first",
 }
 
-filegroup(
-    name = "testdata",
-    srcs = ["testdata/**/*"],
-)
+filegroup {
+    name: "testdata",
+    srcs: ["testdata/**/*"],
+}
diff --git a/remote_provisioning/hwtrust/Cargo.lock b/remote_provisioning/hwtrust/Cargo.lock
index 8a5769a..a78889d 100644
--- a/remote_provisioning/hwtrust/Cargo.lock
+++ b/remote_provisioning/hwtrust/Cargo.lock
@@ -71,6 +71,15 @@ version = "1.0.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd"
 
+[[package]]
+name = "chrono"
+version = "0.4.38"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a21f936df1771bf62b77f047b726c4625ff2e8aa607c01ec06e5a05bd8463401"
+dependencies = [
+ "num-traits",
+]
+
 [[package]]
 name = "ciborium"
 version = "0.2.1"
@@ -226,6 +235,7 @@ version = "0.1.0"
 dependencies = [
  "anyhow",
  "base64",
+ "chrono",
  "ciborium",
  "clap",
  "coset",
@@ -300,6 +310,15 @@ dependencies = [
  "adler",
 ]
 
+[[package]]
+name = "num-traits"
+version = "0.2.19"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841"
+dependencies = [
+ "autocfg",
+]
+
 [[package]]
 name = "object"
 version = "0.30.3"
diff --git a/remote_provisioning/hwtrust/Cargo.toml b/remote_provisioning/hwtrust/Cargo.toml
index b304462..af341aa 100644
--- a/remote_provisioning/hwtrust/Cargo.toml
+++ b/remote_provisioning/hwtrust/Cargo.toml
@@ -18,4 +18,5 @@ openssl = "0.10.45"
 serde_json = "1.0.96"
 itertools = "0.10.5"
 base64 = "0.21.0"
+chrono = { version = "0.4.34", features = ["now"], default-features = false }
 
diff --git a/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp b/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
index fa0adbf..d6c4090 100644
--- a/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
+++ b/remote_provisioning/hwtrust/cxxbridge/hwtrust.cpp
@@ -51,6 +51,8 @@ DiceChain::~DiceChain() {}
 DiceChain::DiceChain(std::unique_ptr<BoxedDiceChain> chain, size_t size) noexcept
       : chain_(std::move(chain)), size_(size) {}
 
+DiceChain::DiceChain(DiceChain&& other) : DiceChain(std::move(other.chain_), other.size_) {}
+
 Result<DiceChain> DiceChain::Verify(
   const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode,
   std::string_view instance) noexcept {
@@ -75,6 +77,30 @@ Result<std::vector<std::vector<uint8_t>>> DiceChain::CosePublicKeys() const noex
   return result;
 }
 
+Result<bool> DiceChain::compareRootPublicKey(const DiceChain& other) const noexcept {
+    auto result = rust::compareRootPublicKeyInDiceChain(**chain_, **other.chain_);
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+    return result.value;
+}
+
+Result<bool> DiceChain::componentNameContains(std::string_view value) const noexcept {
+    auto result = rust::componentNameInDiceChainContains(**chain_, value.data());
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+    return result.value;
+}
+
+Result<bool> DiceChain::hasNonNormalMode() const noexcept {
+    auto result = rust::hasNonNormalModeInDiceChain(**chain_);
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+    return result.value;
+}
+
 bool DiceChain::IsProper() const noexcept {
   return rust::IsDiceChainProper(**chain_);
 }
@@ -85,11 +111,13 @@ Csr::~Csr() {}
 Csr::Csr(std::unique_ptr<BoxedCsr> csr, DiceChain::Kind kind, std::string_view instance) noexcept
     : mCsr(std::move(csr)), mKind(kind), mInstance(instance.data()) {}
 
-Result<Csr> Csr::validate(const std::vector<uint8_t>& request, DiceChain::Kind kind, bool allowAnyMode,
-    std::string_view instance) noexcept {
+Csr::Csr(Csr&& other) : Csr(std::move(other.mCsr), other.mKind, std::move(other.mInstance)) {}
+
+Result<Csr> Csr::validate(const std::vector<uint8_t>& request, DiceChain::Kind kind, bool isFactory,
+    bool allowAnyMode, std::string_view instance) noexcept {
     rust::DiceChainKind chainKind = convertKind(kind);
     auto result = rust::validateCsr(
-        {request.data(), request.size()}, chainKind, allowAnyMode, instance.data());
+        {request.data(), request.size()}, chainKind, isFactory, allowAnyMode, instance.data());
     if (!result.error.empty()) {
         return Error() << static_cast<std::string>(result.error);
     }
@@ -104,4 +132,32 @@ Result<DiceChain> Csr::getDiceChain() const noexcept {
   return DiceChain(BoxedDiceChain::moveFrom(result.chain), result.len);
 }
 
+bool Csr::hasUdsCerts() const noexcept {
+    return rust::csrHasUdsCerts(**mCsr);
+}
+
+Result<std::vector<uint8_t>> Csr::getCsrPayload() const noexcept {
+    auto vector = rust::getCsrPayloadFromCsr(**mCsr);
+    if (vector.empty()) {
+        return Error() << "Failed to get CsrPayload";
+    }
+    return std::vector<uint8_t>{vector.begin(), vector.end()};
+}
+
+Result<bool> Csr::compareKeysToSign(const std::vector<uint8_t>& keysToSign) const noexcept {
+    auto result = rust::compareKeysToSignInCsr(**mCsr, {keysToSign.data(), keysToSign.size()});
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+    return result.value;
+}
+
+Result<bool> Csr::compareChallenge(const std::vector<uint8_t>& challenge) const noexcept {
+    auto result = rust::compareChallengeInCsr(**mCsr, {challenge.data(), challenge.size()});
+    if (!result.error.empty()) {
+        return Error() << static_cast<std::string>(result.error);
+    }
+    return result.value;
+}
+
 } // namespace hwtrust
diff --git a/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h b/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
index 480d2e9..7e382d7 100644
--- a/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
+++ b/remote_provisioning/hwtrust/cxxbridge/include/hwtrust/hwtrust.h
@@ -31,10 +31,18 @@ public:
     std::string_view instance) noexcept;
 
   ~DiceChain();
-  DiceChain(DiceChain&&) = default;
+  DiceChain(DiceChain&&);
 
+  // The root public key (UDS public key) is not included here
   Result<std::vector<std::vector<uint8_t>>> CosePublicKeys() const noexcept;
 
+  Result<bool> compareRootPublicKey(const DiceChain& other) const noexcept;
+
+  // whether a certificate in the DICE chain has a non-normal mode
+  Result<bool> hasNonNormalMode() const noexcept;
+
+  Result<bool> componentNameContains(std::string_view value) const noexcept;
+
   bool IsProper() const noexcept;
 
 private:
@@ -48,14 +56,22 @@ struct BoxedCsr;
 
 class Csr final {
 public:
-  static Result<Csr> validate(const std::vector<uint8_t>& csr, DiceChain::Kind kind,
+  static Result<Csr> validate(const std::vector<uint8_t>& csr, DiceChain::Kind kind, bool isFactory,
     bool allowAnyMode, std::string_view instance) noexcept;
 
   ~Csr();
-  Csr(Csr&&) = default;
+  Csr(Csr&&);
 
   Result<DiceChain> getDiceChain() const noexcept;
 
+  bool hasUdsCerts() const noexcept;
+
+  Result<std::vector<uint8_t>> getCsrPayload() const noexcept;
+
+  Result<bool> compareKeysToSign(const std::vector<uint8_t>& keysToSign) const noexcept;
+
+  Result<bool> compareChallenge(const std::vector<uint8_t>& challenge) const noexcept;
+
   private:
     Csr(std::unique_ptr<BoxedCsr> csr, DiceChain::Kind kind, std::string_view instance) noexcept;
 
diff --git a/remote_provisioning/hwtrust/cxxbridge/lib.rs b/remote_provisioning/hwtrust/cxxbridge/lib.rs
index 4ff2a3c..fcea41a 100644
--- a/remote_provisioning/hwtrust/cxxbridge/lib.rs
+++ b/remote_provisioning/hwtrust/cxxbridge/lib.rs
@@ -3,10 +3,19 @@
 
 use coset::CborSerializable;
 use hwtrust::dice::ChainForm;
+use hwtrust::dice::DiceMode;
+use hwtrust::dice::ProfileVersion;
 use hwtrust::rkp::Csr as InnerCsr;
-use hwtrust::session::{Options, RkpInstance, Session};
+use hwtrust::session::{DiceProfileRange, Options, RkpInstance, Session};
 use std::str::FromStr;
 
+/// Since the AVF DICE chain combines both vendor and AOSP DICE chains, the chain doesn't rely
+/// solely on the VSR for vendors, unlike pure vendor DICE chains. This constant defines the
+/// minimum profile version required for the AOSP/AVF portion of the DICE chain.
+///
+/// Since the AVF portion follows the vendor portion, its version is always higher.
+const AVF_DICE_PROFILE_VERSION: ProfileVersion = ProfileVersion::Android16;
+
 #[allow(clippy::needless_maybe_sized)]
 #[allow(unsafe_op_in_unsafe_fn)]
 #[cxx::bridge(namespace = "hwtrust::rust")]
@@ -45,6 +54,11 @@ mod ffi {
         csr: Box<Csr>,
     }
 
+    struct BoolResult {
+        error: String,
+        value: bool,
+    }
+
     extern "Rust" {
         type DiceChain;
 
@@ -59,6 +73,18 @@ mod ffi {
         #[cxx_name = GetDiceChainPublicKey]
         fn get_dice_chain_public_key(chain: &DiceChain, n: usize) -> Vec<u8>;
 
+        #[cxx_name = compareRootPublicKeyInDiceChain]
+        fn compare_root_public_key_in_dice_chain(
+            chain1: &DiceChain,
+            chain2: &DiceChain,
+        ) -> BoolResult;
+
+        #[cxx_name = componentNameInDiceChainContains]
+        fn component_name_in_dice_chain_contains(chain: &DiceChain, substring: &str) -> BoolResult;
+
+        #[cxx_name = hasNonNormalModeInDiceChain]
+        fn has_non_normal_mode_in_dice_chain(chain: &DiceChain) -> BoolResult;
+
         #[cxx_name = IsDiceChainProper]
         fn is_dice_chain_proper(chain: &DiceChain) -> bool;
 
@@ -68,48 +94,81 @@ mod ffi {
         fn validate_csr(
             csr: &[u8],
             kind: DiceChainKind,
+            is_factory: bool,
             allow_any_mode: bool,
             instance: &str,
         ) -> ValidateCsrResult;
 
         #[cxx_name = getDiceChainFromCsr]
         fn get_dice_chain_from_csr(csr: &Csr) -> VerifyDiceChainResult;
+
+        #[cxx_name = csrHasUdsCerts]
+        fn csr_has_uds_certs(csr: &Csr) -> bool;
+
+        #[cxx_name = getCsrPayloadFromCsr]
+        fn get_csr_payload_from_csr(csr: &Csr) -> Vec<u8>;
+
+        #[cxx_name = compareKeysToSignInCsr]
+        fn compare_keys_to_sign_in_csr(csr: &Csr, keys_to_sign: &[u8]) -> BoolResult;
+
+        #[cxx_name = compareChallengeInCsr]
+        fn compare_challenge_in_csr(csr: &Csr, challenge: &[u8]) -> BoolResult;
+    }
+}
+
+impl TryInto<Options> for ffi::DiceChainKind {
+    type Error = String;
+
+    fn try_into(self) -> Result<Options, Self::Error> {
+        match self {
+            ffi::DiceChainKind::Vsr13 => Ok(Options::vsr13()),
+            ffi::DiceChainKind::Vsr14 => Ok(Options::vsr14()),
+            ffi::DiceChainKind::Vsr15 => Ok(Options::vsr15()),
+            ffi::DiceChainKind::Vsr16 => Ok(Options::vsr16()),
+            _ => Err("invalid chain kind".to_string()),
+        }
     }
 }
 
 /// A DICE chain as exposed over the cxx bridge.
 pub struct DiceChain(Option<ChainForm>);
 
+fn new_session(
+    kind: ffi::DiceChainKind,
+    allow_any_mode: bool,
+    instance: &str,
+) -> Result<Session, String> {
+    let mut options: Options = kind.try_into()?;
+    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
+        return Err(format!("invalid RKP instance: {}", instance));
+    };
+    if rkp_instance == RkpInstance::Avf {
+        options.dice_profile_range =
+            DiceProfileRange::new(options.dice_profile_range.start(), AVF_DICE_PROFILE_VERSION)
+    }
+    let mut session = Session { options };
+    session.set_rkp_instance(rkp_instance);
+    session.set_allow_any_mode(allow_any_mode);
+    Ok(session)
+}
+
 fn verify_dice_chain(
     chain: &[u8],
     kind: ffi::DiceChainKind,
     allow_any_mode: bool,
     instance: &str,
 ) -> ffi::VerifyDiceChainResult {
-    let mut session = Session {
-        options: match kind {
-            ffi::DiceChainKind::Vsr13 => Options::vsr13(),
-            ffi::DiceChainKind::Vsr14 => Options::vsr14(),
-            ffi::DiceChainKind::Vsr15 => Options::vsr15(),
-            ffi::DiceChainKind::Vsr16 => Options::vsr16(),
-            _ => {
-                return ffi::VerifyDiceChainResult {
-                    error: "invalid chain kind".to_string(),
-                    chain: Box::new(DiceChain(None)),
-                    len: 0,
-                }
+    let session = match new_session(kind, allow_any_mode, instance) {
+        Ok(session) => session,
+        Err(e) => {
+            return ffi::VerifyDiceChainResult {
+                error: e,
+                chain: Box::new(DiceChain(None)),
+                len: 0,
             }
-        },
-    };
-    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
-        return ffi::VerifyDiceChainResult {
-            error: format!("invalid RKP instance: {}", instance),
-            chain: Box::new(DiceChain(None)),
-            len: 0,
-        };
+        }
     };
-    session.set_allow_any_mode(allow_any_mode);
-    session.set_rkp_instance(rkp_instance);
+
     match ChainForm::from_cbor(&session, chain) {
         Ok(chain) => {
             let len = chain.length();
@@ -138,6 +197,67 @@ fn get_dice_chain_public_key(chain: &DiceChain, n: usize) -> Vec<u8> {
     Vec::new()
 }
 
+fn compare_root_public_key_in_dice_chain(
+    chain1: &DiceChain,
+    chain2: &DiceChain,
+) -> ffi::BoolResult {
+    match (chain1, chain2) {
+        (
+            DiceChain(Some(ChainForm::Proper(chain1))),
+            DiceChain(Some(ChainForm::Proper(chain2))),
+        ) => {
+            let equal = chain1.root_public_key() == chain2.root_public_key();
+            ffi::BoolResult { error: "".to_string(), value: equal }
+        }
+        _ => ffi::BoolResult {
+            error: "Two proper DICE chains were not provided".to_string(),
+            value: false,
+        },
+    }
+}
+
+fn component_name_in_dice_chain_contains(chain: &DiceChain, substring: &str) -> ffi::BoolResult {
+    match chain {
+        DiceChain(Some(chain)) => match chain {
+            ChainForm::Proper(chain) => {
+                match chain
+                    .payloads()
+                    .last()
+                    .expect("leaf cert was empty")
+                    .config_desc()
+                    .component_name()
+                {
+                    Some(name) => {
+                        ffi::BoolResult { error: "".to_string(), value: name.contains(substring) }
+                    }
+                    None => ffi::BoolResult {
+                        error: "component name could not be retrieved".to_string(),
+                        value: false,
+                    },
+                }
+            }
+            ChainForm::Degenerate(_) => {
+                ffi::BoolResult { error: "DICE chain is degenerate".to_string(), value: false }
+            }
+        },
+        _ => ffi::BoolResult { error: "A DICE chain must be provided".to_string(), value: false },
+    }
+}
+
+fn has_non_normal_mode_in_dice_chain(chain: &DiceChain) -> ffi::BoolResult {
+    match chain {
+        DiceChain(Some(ChainForm::Proper(chain))) => {
+            let has_non_normal_mode =
+                chain.payloads().iter().any(|payload| payload.mode() != DiceMode::Normal);
+            ffi::BoolResult { error: "".to_string(), value: has_non_normal_mode }
+        }
+        _ => ffi::BoolResult {
+            error: "A proper DICE chain must be provided".to_string(),
+            value: false,
+        },
+    }
+}
+
 fn is_dice_chain_proper(chain: &DiceChain) -> bool {
     if let DiceChain(Some(chain)) = chain {
         match chain {
@@ -155,31 +275,15 @@ pub struct Csr(Option<InnerCsr>);
 fn validate_csr(
     csr: &[u8],
     kind: ffi::DiceChainKind,
+    is_factory: bool,
     allow_any_mode: bool,
     instance: &str,
 ) -> ffi::ValidateCsrResult {
-    let mut session = Session {
-        options: match kind {
-            ffi::DiceChainKind::Vsr13 => Options::vsr13(),
-            ffi::DiceChainKind::Vsr14 => Options::vsr14(),
-            ffi::DiceChainKind::Vsr15 => Options::vsr15(),
-            ffi::DiceChainKind::Vsr16 => Options::vsr16(),
-            _ => {
-                return ffi::ValidateCsrResult {
-                    error: "invalid chain kind".to_string(),
-                    csr: Box::new(Csr(None)),
-                }
-            }
-        },
+    let mut session = match new_session(kind, allow_any_mode, instance) {
+        Ok(session) => session,
+        Err(e) => return ffi::ValidateCsrResult { error: e, csr: Box::new(Csr(None)) },
     };
-    let Ok(rkp_instance) = RkpInstance::from_str(instance) else {
-        return ffi::ValidateCsrResult {
-            error: format!("invalid RKP instance: {}", instance),
-            csr: Box::new(Csr(None)),
-        };
-    };
-    session.set_allow_any_mode(allow_any_mode);
-    session.set_rkp_instance(rkp_instance);
+    session.set_is_factory(is_factory);
     match InnerCsr::from_cbor(&session, csr) {
         Ok(csr) => {
             let csr = Box::new(Csr(Some(csr)));
@@ -201,9 +305,43 @@ fn get_dice_chain_from_csr(csr: &Csr) -> ffi::VerifyDiceChainResult {
             ffi::VerifyDiceChainResult { error: "".to_string(), chain, len }
         }
         _ => ffi::VerifyDiceChainResult {
-            error: "CSR could not be destructured".to_string(),
+            error: "A CSR needs to be provided".to_string(),
             chain: Box::new(DiceChain(None)),
             len: 0,
         },
     }
 }
+
+fn csr_has_uds_certs(csr: &Csr) -> bool {
+    match csr {
+        Csr(Some(csr)) => csr.has_uds_certs(),
+        _ => false,
+    }
+}
+
+fn get_csr_payload_from_csr(csr: &Csr) -> Vec<u8> {
+    match csr {
+        Csr(Some(csr)) => csr.csr_payload(),
+        _ => Vec::new(),
+    }
+}
+
+fn compare_keys_to_sign_in_csr(csr: &Csr, keys_to_sign: &[u8]) -> ffi::BoolResult {
+    match csr {
+        Csr(Some(csr)) => {
+            ffi::BoolResult { error: "".to_string(), value: csr.compare_keys_to_sign(keys_to_sign) }
+        }
+        _ => {
+            ffi::BoolResult { error: "KeysToSign could not be compared".to_string(), value: false }
+        }
+    }
+}
+
+fn compare_challenge_in_csr(csr: &Csr, challenge: &[u8]) -> ffi::BoolResult {
+    match csr {
+        Csr(Some(csr)) => {
+            ffi::BoolResult { error: "".to_string(), value: challenge == csr.challenge() }
+        }
+        _ => ffi::BoolResult { error: "challenge could not be compared".to_string(), value: false },
+    }
+}
diff --git a/remote_provisioning/hwtrust/src/cbor.rs b/remote_provisioning/hwtrust/src/cbor.rs
index 32d2b24..c40458f 100644
--- a/remote_provisioning/hwtrust/src/cbor.rs
+++ b/remote_provisioning/hwtrust/src/cbor.rs
@@ -5,7 +5,9 @@ mod field_value;
 mod publickey;
 pub(crate) mod rkp;
 
+use ciborium::value::CanonicalValue;
 use ciborium::{de::from_reader, value::Value};
+use std::collections::BTreeMap;
 use std::io::Read;
 
 type CiboriumError = ciborium::de::Error<std::io::Error>;
@@ -27,6 +29,20 @@ fn serialize(value: Value) -> Vec<u8> {
     data
 }
 
+fn canonicalize_map(value: Value) -> Result<Vec<u8>, CiboriumError> {
+    match value {
+        Value::Map(map) => {
+            let btree: BTreeMap<CanonicalValue, Value> =
+                map.into_iter().map(|(k, v)| (CanonicalValue::from(k), v)).collect();
+
+            let mut data = Vec::new();
+            ciborium::ser::into_writer(&btree, &mut data).unwrap();
+            Ok(data)
+        }
+        _ => Err(CiboriumError::Semantic(None, format!("expected map, got {:?}", &value))),
+    }
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -52,4 +68,41 @@ mod tests {
         let bytes = [0x82, 0x04, 0x02, 0x00];
         assert!(value_from_bytes(&bytes).is_err());
     }
+
+    #[test]
+    fn integers_and_lengths_are_canonicalized() {
+        // Both are encodings of the following.
+        // [1, "12", {2 : 1, 1 : 2}]
+        let noncanonical_bytes = [
+            0x83, // array with size 3
+            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // integer 1
+            0x7a, 0x00, 0x00, 0x00, 0x02, 0x31, 0x32, // string "12"
+            0xa2, // map with size 2
+            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, // 2 : 1
+            0x01, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 1 : 2
+        ];
+        // This is almost canonical because the keys of the map are not sorted.
+        // In order to be canonical, the entries of the map should be swapped.
+        let almost_canonical_bytes = [
+            0x83, // array with size 3
+            0x01, // integer 1
+            0x62, 0x31, 0x32, // string "12"
+            0xa2, // map with size 2
+            0x02, 0x01, // 2 : 1
+            0x01, 0x02, // 1 : 2
+        ];
+
+        let value = value_from_bytes(noncanonical_bytes.as_slice()).unwrap();
+        let serialized = serialize(value);
+
+        assert_eq!(serialized.as_slice(), almost_canonical_bytes);
+    }
+
+    #[test]
+    fn canonicalization_works() {
+        let bytes = [0xa2, 0x03, 0x04, 0x01, 0x02];
+        let value = value_from_bytes(&bytes).unwrap();
+        let canonicalized = canonicalize_map(value.clone()).unwrap();
+        assert_eq!(&hex::encode(canonicalized), "a201020304");
+    }
 }
diff --git a/remote_provisioning/hwtrust/src/cbor/dice/entry.rs b/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
index 38af596..dc8dd7f 100644
--- a/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/cbor/dice/entry.rs
@@ -1,6 +1,6 @@
 use super::cose_key_from_cbor_value;
 use super::profile::{ComponentVersionType, ModeType, Profile};
-use crate::cbor::{field_value::FieldValue, value_from_bytes};
+use crate::cbor::{field_value::FieldValue, serialize, value_from_bytes};
 use crate::dice::{
     ComponentVersion, ConfigDesc, ConfigDescBuilder, DiceMode, Payload, PayloadBuilder,
     ProfileVersion,
@@ -421,8 +421,7 @@ fn config_desc_from_slice(profile: &Profile, bytes: &[u8]) -> Result<ConfigDesc>
         }
     }
 
-    let extensions =
-        extensions.into_iter().map(|(k, v)| (k.to_string(), format!("{v:?}"))).collect();
+    let extensions = extensions.into_iter().map(|(k, v)| (k, serialize(v))).collect();
 
     let security_version = if profile.security_version_optional {
         security_version.into_optional_u64()
@@ -1032,9 +1031,9 @@ mod tests {
     }
 
     #[test]
-    fn config_desc_custom_fields() {
+    fn config_desc_custom_fields() -> anyhow::Result<()> {
         let mut fields = valid_payload_fields();
-        let config_desc = serialize(cbor!({-71000 => "custom hi", -69999 => "custom lo"}).unwrap());
+        let config_desc = serialize(cbor!({-71000 => "custom hi", -69999 => "custom lo"})?);
         let config_hash = sha512(&config_desc).to_vec();
         fields.insert(CONFIG_DESC, Value::Bytes(config_desc));
         fields.insert(CONFIG_HASH, Value::Bytes(config_hash));
@@ -1044,13 +1043,15 @@ mod tests {
             &serialize_fields(fields),
             ConfigFormat::Android,
             !IS_ROOT,
-        )
-        .unwrap();
+        )?;
         let extensions = payload.config_desc().extensions();
         let extensions = HashMap::<_, _>::from_iter(extensions.to_owned());
-        assert_eq!(extensions.get("-71000").unwrap(), "Text(\"custom hi\")");
-        assert_eq!(extensions.get("-69999").unwrap(), "Text(\"custom lo\")");
+
+        assert_eq!(extensions.get(&-71000).unwrap(), &serialize(cbor!("custom hi")?));
+        assert_eq!(extensions.get(&-69999).unwrap(), &serialize(cbor!("custom lo")?));
         assert_eq!(extensions.len(), 2);
+
+        Ok(())
     }
 
     #[test]
diff --git a/remote_provisioning/hwtrust/src/cbor/field_value.rs b/remote_provisioning/hwtrust/src/cbor/field_value.rs
index c9aa764..8c2e54c 100644
--- a/remote_provisioning/hwtrust/src/cbor/field_value.rs
+++ b/remote_provisioning/hwtrust/src/cbor/field_value.rs
@@ -19,8 +19,6 @@ pub enum FieldValueError {
     NotI64(&'static str, Value),
     #[error("expected u64 for field {0}, but found `{1:?}`")]
     NotU64(&'static str, Value),
-    #[error("expected boolean for field {0}, but found `{1:?}`")]
-    NotBool(&'static str, Value),
     #[error("expected map for field {0}, but found `{1:?}`")]
     NotMap(&'static str, Value),
     #[error("expected array for field {0}, but found `{1:?}`")]
@@ -45,10 +43,6 @@ impl FieldValue {
         Self { name, value: None }
     }
 
-    pub fn value(&self) -> Option<Value> {
-        self.value.clone()
-    }
-
     pub fn from_value(name: &'static str, value: Value) -> Self {
         Self { name, value: Some(value) }
     }
@@ -167,21 +161,6 @@ impl FieldValue {
             .transpose()
     }
 
-    pub fn into_bool(self) -> Result<bool, FieldValueError> {
-        require_present(self.name, self.into_optional_bool())
-    }
-
-    pub fn into_optional_bool(self) -> Result<Option<bool>, FieldValueError> {
-        self.value
-            .map(|v| match v {
-                Value::Bool(b) => Ok(b),
-                Value::Integer(i) if i == 0.into() => Ok(false),
-                Value::Integer(i) if i == 1.into() => Ok(true),
-                _ => Err(FieldValueError::NotBool(self.name, v)),
-            })
-            .transpose()
-    }
-
     pub fn is_null(&self) -> Result<bool, FieldValueError> {
         // If there's no value, return false; if there is a null value, return true; anything else
         // is an error.
@@ -207,7 +186,7 @@ impl FieldValue {
             .map(|v| {
                 let value =
                     if let Value::Integer(i) = v { i128::from(i).try_into().ok() } else { None };
-                value.ok_or_else(|| FieldValueError::NotU32(self.name, v))
+                value.ok_or(FieldValueError::NotU32(self.name, v))
             })
             .transpose()
     }
@@ -217,7 +196,7 @@ impl FieldValue {
             .map(|v| {
                 let value =
                     if let Value::Integer(i) = v { i128::from(i).try_into().ok() } else { None };
-                value.ok_or_else(|| FieldValueError::NotI64(self.name, v))
+                value.ok_or(FieldValueError::NotI64(self.name, v))
             })
             .transpose()
     }
@@ -231,7 +210,7 @@ impl FieldValue {
             .map(|v| {
                 let value =
                     if let Value::Integer(i) = v { i128::from(i).try_into().ok() } else { None };
-                value.ok_or_else(|| FieldValueError::NotU64(self.name, v))
+                value.ok_or(FieldValueError::NotU64(self.name, v))
             })
             .transpose()
     }
diff --git a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
index 48a5d6a..3f3526e 100644
--- a/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/cbor/rkp/csr.rs
@@ -1,13 +1,14 @@
 use std::collections::HashMap;
 
 use crate::cbor::field_value::FieldValue;
-use crate::cbor::{serialize, value_from_bytes};
+use crate::cbor::{canonicalize_map, serialize, value_from_bytes};
 use crate::dice::ChainForm;
-use crate::rkp::{Csr, CsrPayload, DeviceInfo, ProtectedData};
+use crate::rkp::{Csr, CsrPayload, DeviceInfo, DeviceInfoVersion, KeysToSign, ProtectedData};
 use crate::session::{RkpInstance, Session};
 use anyhow::{anyhow, bail, ensure, Context, Result};
 use base64::{prelude::BASE64_STANDARD, Engine};
 use ciborium::value::Value;
+use coset::{AsCborValue, CoseKey};
 use openssl::pkey::Id;
 use openssl::stack::Stack;
 use openssl::x509::store::X509StoreBuilder;
@@ -16,6 +17,19 @@ use openssl::x509::{X509StoreContext, X509};
 
 const VERSION_OR_DEVICE_INFO_INDEX: usize = 0;
 
+impl KeysToSign {
+    pub(crate) fn from_bytes(buffer: &[u8]) -> Result<Self> {
+        let value = value_from_bytes(buffer)?;
+        let field_value = FieldValue::from_value("KeysToSign", value);
+        Self::from_value(field_value)
+    }
+    fn from_value(value: FieldValue) -> Result<KeysToSign> {
+        Ok(KeysToSign(
+            value.into_array()?.into_iter().map(|v| CoseKey::from_cbor_value(v).unwrap()).collect(),
+        ))
+    }
+}
+
 impl CsrPayload {
     fn from_value(value: &Value, session: &Session) -> Result<Self> {
         let serialized = match value.clone().into_bytes() {
@@ -34,7 +48,7 @@ impl CsrPayload {
             FieldValue::from_optional_value("CertificateType", csr_payload.pop());
         let version = FieldValue::from_optional_value("Version", csr_payload.pop()).into_u64()?;
         if version != 3 {
-            bail!("Invalid CSR version. Only '3' is supported");
+            bail!("Invalid CsrPayload version. Only '3' is supported");
         }
 
         let certificate_type = certificate_type.into_string()?;
@@ -51,10 +65,14 @@ impl CsrPayload {
             ),
         }
 
-        let device_info = DeviceInfo::from_cbor_values(device_info.into_map()?, Some(3))?;
-        let keys_to_sign = serialize(keys_to_sign.value().unwrap());
+        let device_info = DeviceInfo::from_cbor_values(
+            device_info.into_map()?,
+            Some(DeviceInfoVersion::V3),
+            session.options.is_factory,
+        )?;
+        let keys_to_sign = KeysToSign::from_value(keys_to_sign)?;
 
-        Ok(CsrPayload { certificate_type, device_info, keys_to_sign })
+        Ok(CsrPayload { serialized, certificate_type, device_info, keys_to_sign })
     }
 }
 
@@ -98,8 +116,21 @@ impl Csr {
 
         ensure!(device_info.len() == 2, "Device info should contain exactly 2 entries");
         device_info.pop(); // ignore unverified info
-        let verified_device_info = match device_info.pop() {
-            Some(Value::Map(d)) => Value::Map(d),
+        let device_info = device_info.pop().unwrap();
+        let device_info_serialized = serialize(device_info.clone());
+        let device_info_canonicalized = canonicalize_map(device_info.clone())?;
+        if device_info_canonicalized != device_info_serialized {
+            match session.options.verbose {
+                true => bail!(
+                    "Device info is not canonical:\nexpected: {:?}\nactual: {:?}",
+                    &hex::encode(device_info_canonicalized),
+                    &hex::encode(device_info_serialized)
+                ),
+                false => bail!("Device info is not canonical"),
+            }
+        }
+        let verified_device_info = match device_info {
+            Value::Map(d) => Value::Map(d),
             other => bail!("Expected a map for verified device info, found '{:?}'", other),
         };
 
@@ -117,7 +148,11 @@ impl Csr {
         };
 
         Ok(Self::V2 {
-            device_info: DeviceInfo::from_cbor_values(verified_device_info, None)?,
+            device_info: DeviceInfo::from_cbor_values(
+                verified_device_info,
+                None, // version must be determined by "version" in DeviceInfo
+                session.options.is_factory,
+            )?,
             challenge,
             protected_data,
         })
@@ -129,7 +164,10 @@ impl Csr {
         version: i128,
     ) -> Result<Self> {
         if version != 1 {
-            bail!("Invalid CSR version. Only '1' is supported, found '{}", version);
+            bail!(
+                "Invalid AuthenticatedRequest version. Only '1' is supported, found '{}",
+                version
+            );
         }
 
         // CSRs that are uploaded to the backend have an additional unverified info field tacked
@@ -137,6 +175,9 @@ impl Csr {
         if csr.len() == 5 {
             FieldValue::from_optional_value("UnverifiedDeviceInfo", csr.pop());
         }
+        if csr.len() != 4 {
+            bail!("AuthenticatedRequest should have 4 elements. Found {}.", csr.len());
+        }
 
         let signed_data =
             FieldValue::from_optional_value("SignedData", csr.pop()).into_cose_sign1()?;
@@ -357,7 +398,7 @@ mod tests {
         let Csr::V3 { dice_chain, csr_payload, .. } = csr else {
             panic!("Parsed CSR was not V3: {:?}", csr);
         };
-        assert_eq!(csr_payload.device_info.security_level, Some(DeviceInfoSecurityLevel::Avf));
+        assert_eq!(csr_payload.device_info.security_level, DeviceInfoSecurityLevel::Avf);
         let ChainForm::Proper(proper_chain) = dice_chain else {
             panic!("Parsed chain is not proper: {:?}", dice_chain);
         };
@@ -515,8 +556,8 @@ pub(crate) mod testutil {
             system_patch_level: 20221025,
             boot_patch_level: 20221026,
             vendor_patch_level: 20221027,
-            security_level: Some(DeviceInfoSecurityLevel::Tee),
-            fused: true,
+            security_level: DeviceInfoSecurityLevel::Tee,
+            fused: 1,
         }
     }
 }
diff --git a/remote_provisioning/hwtrust/src/cbor/rkp/device_info.rs b/remote_provisioning/hwtrust/src/cbor/rkp/device_info.rs
index ec1fc74..41930dd 100644
--- a/remote_provisioning/hwtrust/src/cbor/rkp/device_info.rs
+++ b/remote_provisioning/hwtrust/src/cbor/rkp/device_info.rs
@@ -1,15 +1,18 @@
 use crate::cbor::field_value::FieldValue;
 use crate::rkp::{
     DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
+    DeviceInfoVersion,
 };
-use anyhow::{bail, ensure, Context, Result};
+use anyhow::{bail, ensure, Result};
+use chrono::NaiveDate;
 use ciborium::value::Value;
 
 impl DeviceInfo {
     /// Create a new DeviceInfo struct from Values parsed by ciborium
     pub fn from_cbor_values(
         values: Vec<(Value, Value)>,
-        explicit_version: Option<u32>,
+        device_info_version: Option<DeviceInfoVersion>,
+        is_factory: bool,
     ) -> Result<Self> {
         let mut brand = FieldValue::new("brand");
         let mut manufacturer = FieldValue::new("manufacturer");
@@ -49,19 +52,22 @@ impl DeviceInfo {
             field_value.set_once(value)?;
         }
 
-        let version = match version.into_optional_u32() {
-            Ok(Some(v)) if v == explicit_version.unwrap_or(v) => v,
-            Ok(Some(v)) => bail!(
-                "Parsed DeviceInfo version '{v}' does not match expected version \
-                '{explicit_version:?}'"
-            ),
-            Ok(None) => explicit_version.context("missing required version")?,
+        let parsed_version = match version.into_optional_u32() {
+            Ok(v) => v,
             Err(e) => return Err(e.into()),
         };
 
-        let security_level = match security_level.into_optional_string()? {
-            Some(s) => Some(s.as_str().try_into()?),
-            None => None,
+        let version = match device_info_version {
+            Some(DeviceInfoVersion::V3) => {
+                ensure!(parsed_version.is_none(), "DeviceInfoV3 should not have version entry.");
+                DeviceInfoVersion::V3
+            }
+            None => match parsed_version {
+                Some(2) => DeviceInfoVersion::V2,
+                Some(v) => bail!("Unexpected DeviceInfo version: {}", v),
+                None => bail!("DeviceInfo requires a version entry."),
+            },
+            _ => bail!("Unexpected DeviceInfo version: {:?}", device_info_version.unwrap()),
         };
 
         let info = DeviceInfo {
@@ -77,23 +83,16 @@ impl DeviceInfo {
             system_patch_level: system_patch_level.into_u32()?,
             boot_patch_level: boot_patch_level.into_u32()?,
             vendor_patch_level: vendor_patch_level.into_u32()?,
-            security_level,
-            fused: fused.into_bool()?,
-            version: version.try_into()?,
+            security_level: security_level.into_string()?.as_str().try_into()?,
+            fused: fused.into_u32()?,
+            version,
         };
-        info.validate()?;
+        info.validate(is_factory)?;
         Ok(info)
     }
 
-    fn validate(&self) -> Result<()> {
-        ensure!(!self.vbmeta_digest.is_empty(), "vbmeta_digest must not be empty");
-        ensure!(
-            !self.vbmeta_digest.iter().all(|b| *b == 0u8),
-            "vbmeta_digest must not be all zeros. Got {:?}",
-            self.vbmeta_digest
-        );
-
-        if Some(DeviceInfoSecurityLevel::Avf) == self.security_level {
+    fn validate(&self, is_factory: bool) -> Result<()> {
+        if DeviceInfoSecurityLevel::Avf == self.security_level {
             ensure!(
                 self.bootloader_state == DeviceInfoBootloaderState::Avf
                     && self.vb_state == DeviceInfoVbState::Avf
@@ -105,6 +104,7 @@ impl DeviceInfo {
                 "AVF security level requires AVF fields. Got: {:?}",
                 self
             );
+            return Ok(());
         } else {
             ensure!(
                 self.bootloader_state != DeviceInfoBootloaderState::Avf
@@ -118,6 +118,73 @@ impl DeviceInfo {
                 self
             );
         }
+
+        ensure!(!self.manufacturer.is_empty(), "manufacturer must not be empty");
+
+        if !is_factory {
+            self.check_entries()?;
+        }
+
+        Ok(())
+    }
+
+    fn check_patch_level(key: &str, level: String) -> Result<()> {
+        let mut maybe_modified_level = level.clone();
+        if level.len() == 6 {
+            maybe_modified_level += "01";
+        }
+
+        let string = maybe_modified_level.as_str();
+        match string.len() {
+            8 => match NaiveDate::parse_from_str(string, "%Y%m%d") {
+                Ok(_) => Ok(()),
+                Err(e) => bail!("Error parsing {key}:{level}: {}", e.to_string()),
+            },
+            _ => bail!("value for {key} must be in format YYYYMMDD or YYYYMM, found: '{level}'"),
+        }
+    }
+
+    fn check_entries(&self) -> Result<()> {
+        if self.version == DeviceInfoVersion::V3 {
+            Self::check_patch_level("system_patch_level", self.system_patch_level.to_string())?;
+            Self::check_patch_level("boot_patch_level", self.boot_patch_level.to_string())?;
+            Self::check_patch_level("vendor_patch_level", self.vendor_patch_level.to_string())?;
+        }
+        if self.version == DeviceInfoVersion::V3 || self.version == DeviceInfoVersion::V2 {
+            ensure!(!self.vbmeta_digest.is_empty(), "vbmeta_digest must not be empty");
+            ensure!(
+                !self.vbmeta_digest.iter().all(|b| *b == 0u8),
+                "vbmeta_digest must not be all zeros. Got {:?}",
+                self.vbmeta_digest
+            );
+
+            ensure!(
+                self.vb_state != DeviceInfoVbState::Factory,
+                "vb_state must be a valid production value"
+            );
+            ensure!(
+                self.bootloader_state != DeviceInfoBootloaderState::Factory,
+                "bootloader_state must be a valid production value"
+            );
+            ensure!(
+                self.fused == 0 || self.fused == 1,
+                "fused must be a valid production value {}",
+                self.fused
+            );
+            ensure!(
+                self.security_level != DeviceInfoSecurityLevel::Factory,
+                "security_level must be a valid production value"
+            );
+            ensure!(
+                self.security_level != DeviceInfoSecurityLevel::Tee || self.os_version.is_some(),
+                "OS version is not optional with TEE"
+            );
+            ensure!(!self.brand.is_empty(), "brand must not be empty");
+            ensure!(!self.device.is_empty(), "device must not be empty");
+            ensure!(!self.model.is_empty(), "model must not be empty");
+            ensure!(!self.product.is_empty(), "product must not be empty");
+        }
+
         Ok(())
     }
 }
@@ -130,21 +197,27 @@ mod tests {
     #[test]
     fn device_info_from_cbor_values_optional_os_version() {
         let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "os_version");
-        let info = DeviceInfo::from_cbor_values(values, None).unwrap();
+        let info = DeviceInfo::from_cbor_values(values, None, true).unwrap();
         assert!(info.os_version.is_none());
     }
 
+    #[test]
+    fn device_info_from_cbor_values_optional_os_version_is_not_optional_with_tee() {
+        let values: Vec<(Value, Value)> = get_valid_tee_values_filtered(|x| x != "os_version");
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
+        assert!(err.to_string().contains("OS version is not optional with TEE"));
+    }
+
     #[test]
     fn device_info_from_cbor_values_missing_required_field() {
         let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "brand");
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
-        println!("{err:?}");
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         assert!(err.to_string().contains("brand"));
     }
 
     #[test]
     fn from_cbor_values_valid_v2() {
-        let actual = DeviceInfo::from_cbor_values(get_valid_values(), None).unwrap();
+        let actual = DeviceInfo::from_cbor_values(get_valid_values(), None, false).unwrap();
         let expected = DeviceInfo {
             brand: "generic".to_string(),
             manufacturer: "acme".to_string(),
@@ -158,8 +231,8 @@ mod tests {
             system_patch_level: 303010,
             boot_patch_level: 30300102,
             vendor_patch_level: 30300304,
-            security_level: Some(DeviceInfoSecurityLevel::Tee),
-            fused: true,
+            security_level: DeviceInfoSecurityLevel::StrongBox,
+            fused: 1,
             version: DeviceInfoVersion::V2,
         };
         assert_eq!(actual, expected);
@@ -168,7 +241,8 @@ mod tests {
     #[test]
     fn device_info_from_cbor_values_valid_v3() {
         let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
-        let actual = DeviceInfo::from_cbor_values(values, Some(3)).unwrap();
+        let actual =
+            DeviceInfo::from_cbor_values(values, Some(DeviceInfoVersion::V3), false).unwrap();
         let expected = DeviceInfo {
             brand: "generic".to_string(),
             manufacturer: "acme".to_string(),
@@ -182,8 +256,8 @@ mod tests {
             system_patch_level: 303010,
             boot_patch_level: 30300102,
             vendor_patch_level: 30300304,
-            security_level: Some(DeviceInfoSecurityLevel::Tee),
-            fused: true,
+            security_level: DeviceInfoSecurityLevel::StrongBox,
+            fused: 1,
             version: DeviceInfoVersion::V3,
         };
         assert_eq!(actual, expected);
@@ -192,7 +266,8 @@ mod tests {
     #[test]
     fn device_info_from_cbor_values_mismatched_version() {
         let values: Vec<(Value, Value)> = get_valid_values();
-        let err = DeviceInfo::from_cbor_values(values, Some(3)).unwrap_err();
+        let err =
+            DeviceInfo::from_cbor_values(values, Some(DeviceInfoVersion::V3), false).unwrap_err();
         println!("{err:?}");
         assert!(err.to_string().contains("version"));
     }
@@ -200,15 +275,7 @@ mod tests {
     #[test]
     fn device_info_from_cbor_values_invalid_version_value() {
         let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
-        println!("{err:?}");
-        assert!(err.to_string().contains("version"));
-    }
-
-    #[test]
-    fn device_info_from_cbor_values_invalid_explicit_version() {
-        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
-        let err = DeviceInfo::from_cbor_values(values, Some(0)).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         println!("{err:?}");
         assert!(err.to_string().contains("version"));
     }
@@ -216,7 +283,7 @@ mod tests {
     #[test]
     fn device_info_from_cbor_values_missing_version() {
         let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         println!("{err:?}");
         assert!(err.to_string().contains("version"));
     }
@@ -226,7 +293,7 @@ mod tests {
         let mut values: Vec<(Value, Value)> = get_valid_values();
         values.push(("brand".into(), "generic".into()));
 
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         println!("{err:?}");
         assert!(err.to_string().contains("may be set only once"));
     }
@@ -236,7 +303,7 @@ mod tests {
         let mut values: Vec<(Value, Value)> = get_valid_values_filtered(|v| v != "vbmeta_digest");
         values.push(("vbmeta_digest".into(), vec![0u8; 0].into()));
 
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         println!("{err:?}");
         assert!(err.to_string().contains("vbmeta_digest must not be empty"), "{err:?}");
     }
@@ -246,7 +313,7 @@ mod tests {
         let mut values: Vec<(Value, Value)> = get_valid_values_filtered(|v| v != "vbmeta_digest");
         values.push(("vbmeta_digest".into(), vec![0u8; 16].into()));
 
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         println!("{err:?}");
         assert!(err.to_string().contains("vbmeta_digest must not be all zeros"), "{err:?}");
     }
@@ -256,7 +323,7 @@ mod tests {
         let mut values = get_valid_values_filtered(|x| x != "vb_state");
         values.push(("vb_state".into(), "avf".into()));
 
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         assert!(err.to_string().contains("Non-AVF security level"), "{err:?}");
     }
 
@@ -265,7 +332,7 @@ mod tests {
         let mut values = get_valid_values_filtered(|x| x != "bootloader_state");
         values.push(("bootloader_state".into(), "avf".into()));
 
-        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
+        let err = DeviceInfo::from_cbor_values(values, None, false).unwrap_err();
         assert!(err.to_string().contains("Non-AVF security level"), "{err:?}");
     }
 
@@ -276,14 +343,16 @@ mod tests {
             .filter(|(k, _v)| k.as_text().unwrap() != "vb_state")
             .chain(vec![("vb_state".into(), "green".into())])
             .collect();
-        let err = DeviceInfo::from_cbor_values(values, Some(3)).unwrap_err();
+        let err =
+            DeviceInfo::from_cbor_values(values, Some(DeviceInfoVersion::V3), false).unwrap_err();
         assert!(err.to_string().contains("AVF security level requires AVF fields"), "{err:?}");
     }
 
     #[test]
     fn device_info_from_cbor_values_avf_security_level_has_avf_fields() {
         let values = get_valid_avf_values();
-        let actual = DeviceInfo::from_cbor_values(values, Some(3)).unwrap();
+        let actual =
+            DeviceInfo::from_cbor_values(values, Some(DeviceInfoVersion::V3), false).unwrap();
         let expected = DeviceInfo {
             brand: "aosp-avf".to_string(),
             manufacturer: "aosp-avf".to_string(),
@@ -297,14 +366,34 @@ mod tests {
             system_patch_level: 303010,
             boot_patch_level: 30300102,
             vendor_patch_level: 30300304,
-            security_level: Some(DeviceInfoSecurityLevel::Avf),
-            fused: true,
+            security_level: DeviceInfoSecurityLevel::Avf,
+            fused: 1,
             version: DeviceInfoVersion::V3,
         };
         assert_eq!(expected, actual);
     }
 
     fn get_valid_values() -> Vec<(Value, Value)> {
+        vec![
+            ("brand".into(), "generic".into()),
+            ("manufacturer".into(), "acme".into()),
+            ("product".into(), "phone".into()),
+            ("model".into(), "the best one".into()),
+            ("device".into(), "really the best".into()),
+            ("vb_state".into(), "green".into()),
+            ("bootloader_state".into(), "locked".into()),
+            ("vbmeta_digest".into(), b"abcdefg".as_ref().into()),
+            ("os_version".into(), "dessert".into()),
+            ("system_patch_level".into(), 303010.into()),
+            ("boot_patch_level".into(), 30300102.into()),
+            ("vendor_patch_level".into(), 30300304.into()),
+            ("security_level".into(), "strongbox".into()),
+            ("fused".into(), 1.into()),
+            ("version".into(), 2.into()),
+        ]
+    }
+
+    fn get_valid_tee_values() -> Vec<(Value, Value)> {
         vec![
             ("brand".into(), "generic".into()),
             ("manufacturer".into(), "acme".into()),
@@ -346,4 +435,8 @@ mod tests {
     fn get_valid_values_filtered<F: Fn(&str) -> bool>(filter: F) -> Vec<(Value, Value)> {
         get_valid_values().into_iter().filter(|x| filter(x.0.as_text().unwrap())).collect()
     }
+
+    fn get_valid_tee_values_filtered<F: Fn(&str) -> bool>(filter: F) -> Vec<(Value, Value)> {
+        get_valid_tee_values().into_iter().filter(|x| filter(x.0.as_text().unwrap())).collect()
+    }
 }
diff --git a/remote_provisioning/hwtrust/src/dice/entry.rs b/remote_provisioning/hwtrust/src/dice/entry.rs
index 357db72..9e68850 100644
--- a/remote_provisioning/hwtrust/src/dice/entry.rs
+++ b/remote_provisioning/hwtrust/src/dice/entry.rs
@@ -11,7 +11,7 @@ pub enum DiceMode {
     NotConfigured,
     /// The device is operating normally under secure configuration.
     Normal,
-    /// At least one criteria for [`Normal`] is not met and the device is not in a secure state.
+    /// At least one criterion for [`Normal`] is not met and the device is not in a secure state.
     Debug,
     /// A recovery or maintenance mode of some kind.
     Recovery,
@@ -264,7 +264,7 @@ pub struct ConfigDesc {
     resettable: bool,
     security_version: Option<u64>,
     rkp_vm_marker: bool,
-    extensions: Vec<(String, String)>,
+    extensions: Vec<(i64, Vec<u8>)>,
 }
 
 impl ConfigDesc {
@@ -299,7 +299,7 @@ impl ConfigDesc {
     }
 
     /// Return any extensions present in the descriptor.
-    pub fn extensions(&self) -> &[(String, String)] {
+    pub fn extensions(&self) -> &[(i64, Vec<u8>)] {
         &self.extensions
     }
 }
@@ -325,7 +325,7 @@ impl Display for ConfigDesc {
             writeln!(f, "RKP VM Marker")?;
         }
         for (key, value) in &self.extensions {
-            writeln!(f, "{key}: {value}")?;
+            writeln!(f, "{key}: {value:?}")?;
         }
         Ok(())
     }
@@ -388,7 +388,7 @@ impl ConfigDescBuilder {
 
     /// Sets the extension key/value pairs.
     #[must_use]
-    pub fn extensions(mut self, extensions: Vec<(String, String)>) -> Self {
+    pub fn extensions(mut self, extensions: Vec<(i64, Vec<u8>)>) -> Self {
         self.0.extensions = extensions;
         self
     }
diff --git a/remote_provisioning/hwtrust/src/publickey.rs b/remote_provisioning/hwtrust/src/publickey.rs
index 7978a14..d35421e 100644
--- a/remote_provisioning/hwtrust/src/publickey.rs
+++ b/remote_provisioning/hwtrust/src/publickey.rs
@@ -10,8 +10,10 @@ use std::fmt;
 
 /// The kinds of digital signature keys that are supported.
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
-pub(crate) enum SignatureKind {
+pub enum SignatureKind {
+    /// Edwards-curve Digital Signature Algorithm Ed25519.
     Ed25519,
+    /// Elliptic Curve Digital Signature Algorithm (ECDSA).
     Ec(EcKind),
 }
 
@@ -24,8 +26,10 @@ pub(crate) enum KeyAgreementKind {
 
 /// Enumeration of the kinds of elliptic curve keys that are supported.
 #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
-pub(crate) enum EcKind {
+pub enum EcKind {
+    /// P-256 elliptic curve.
     P256,
+    /// P-384 elliptic curve.
     P384,
 }
 
@@ -49,11 +53,13 @@ pub struct KeyAgreementPublicKey {
 }
 
 impl PublicKey {
-    pub(crate) fn kind(&self) -> SignatureKind {
+    /// The signature kind of this key.
+    pub fn kind(&self) -> SignatureKind {
         self.kind
     }
 
-    pub(crate) fn pkey(&self) -> &PKeyRef<Public> {
+    /// Reference to the underlying public key.
+    pub fn pkey(&self) -> &PKeyRef<Public> {
         &self.pkey.0
     }
 
diff --git a/remote_provisioning/hwtrust/src/rkp.rs b/remote_provisioning/hwtrust/src/rkp.rs
index 4404f97..9f9e4a8 100644
--- a/remote_provisioning/hwtrust/src/rkp.rs
+++ b/remote_provisioning/hwtrust/src/rkp.rs
@@ -5,13 +5,15 @@ mod device_info;
 mod factory_csr;
 mod protected_data;
 
-pub use csr::{Csr, CsrPayload};
+pub use csr::{Csr, CsrBuilderError, CsrPayload, CsrV2Builder, CsrV3Builder, KeysToSign};
 
 pub use device_info::{
     DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
     DeviceInfoVersion,
 };
 
-pub(crate) use protected_data::{ProtectedData, UdsCerts, UdsCertsEntry};
+pub(crate) use protected_data::{UdsCerts, UdsCertsEntry};
+
+pub use protected_data::ProtectedData;
 
 pub use factory_csr::FactoryCsr;
diff --git a/remote_provisioning/hwtrust/src/rkp/csr.rs b/remote_provisioning/hwtrust/src/rkp/csr.rs
index bacc2b0..77e2904 100644
--- a/remote_provisioning/hwtrust/src/rkp/csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/csr.rs
@@ -1,27 +1,35 @@
+use coset::CoseKey;
+use openssl::x509::X509;
 use std::{collections::HashMap, fmt};
+use thiserror::Error;
 
-use openssl::x509::X509;
+use crate::dice::ChainForm;
 
-use crate::{dice::ChainForm, rkp::DeviceInfo};
+use super::{DeviceInfo, ProtectedData, UdsCerts};
 
-use super::ProtectedData;
+/// Represents the keys to sign that are to be signed
+#[derive(Clone, Debug, PartialEq)]
+pub struct KeysToSign(pub Vec<CoseKey>);
 
 /// Represents the payload of a Certificate Signing Request
-#[derive(Clone, Eq, PartialEq)]
+#[derive(Clone, PartialEq)]
 pub struct CsrPayload {
+    /// The original serialized CSR payload
+    pub serialized: Vec<u8>,
     /// RKP VM or other?
     pub certificate_type: String,
     /// Describes the device that is requesting certificates.
     pub device_info: DeviceInfo,
     /// The keys to attest to when doing key attestation in one buffer
-    pub keys_to_sign: Vec<u8>,
+    pub keys_to_sign: KeysToSign,
 }
 
 /// Represents a Certificate Signing Request that is sent to an RKP backend to request
 /// certificates to be signed for a set of public keys. The CSR is partially generated by an
 /// IRemotelyProvisionedComponent HAL. The set of public keys to be signed is authenticated
 /// (signed) with a device-unique key.
-#[derive(Clone, Eq, PartialEq)]
+#[derive(Clone, PartialEq)]
+#[allow(clippy::large_enum_variant)]
 pub enum Csr {
     /// CSR V2 was introduced in Android T. In this version, the payload is encrypted using
     /// an Endpoint Encryption Key (EEK).
@@ -33,29 +41,69 @@ pub enum Csr {
         /// Contains the plaintext of the payload that was encrypted to an EEK.
         protected_data: ProtectedData,
     },
-    /// CSR V3 was introduced in Android T. This version drops encryption of the payload.
+    /// CSR V3 was introduced in Android U. This version drops encryption of the payload.
     V3 {
         /// The DICE chain for the device
         dice_chain: ChainForm,
         /// X.509 certificate chain that certifies the dice_chain root key (UDS_pub)
         uds_certs: HashMap<String, Vec<X509>>,
-        /// This is the challenge that is authenticated inside the signed data.
-        /// The signed data is version (3), certificate type, device info, and keys to sign
+        /// The challenge that is authenticated inside the signed data.
         challenge: Vec<u8>,
-        /// csr payload
+        /// The payload of the signed data.
         csr_payload: CsrPayload,
     },
 }
 
 impl Csr {
     /// copy the DICE chain and return it
-    #[allow(dead_code)]
     pub fn dice_chain(&self) -> ChainForm {
         match self {
             Csr::V2 { protected_data, .. } => protected_data.dice_chain(),
             Csr::V3 { dice_chain, .. } => dice_chain.clone(),
         }
     }
+
+    /// copy the UDS certs map and return it
+    pub fn has_uds_certs(&self) -> bool {
+        match self {
+            Csr::V2 { protected_data, .. } => match protected_data.uds_certs() {
+                Some(uds_certs) => match uds_certs {
+                    UdsCerts(map) => !map.is_empty(),
+                },
+                None => false,
+            },
+            Csr::V3 { uds_certs, .. } => !uds_certs.is_empty(),
+        }
+    }
+
+    /// copy the challenge and return it
+    pub fn challenge(&self) -> Vec<u8> {
+        match self {
+            Csr::V2 { challenge, .. } => challenge.clone(),
+            Csr::V3 { challenge, .. } => challenge.clone(),
+        }
+    }
+
+    /// copy the serialized CSR payload and return it
+    pub fn csr_payload(&self) -> Vec<u8> {
+        match self {
+            Csr::V2 { .. } => Vec::new(),
+            Csr::V3 { csr_payload, .. } => csr_payload.serialized.clone(),
+        }
+    }
+
+    /// copy the device info and return it
+    pub fn compare_keys_to_sign(&self, keys_to_sign: &[u8]) -> bool {
+        let keys_to_sign = match KeysToSign::from_bytes(keys_to_sign) {
+            Ok(keys_to_sign) => keys_to_sign,
+            Err(_) => return false,
+        };
+
+        match self {
+            Csr::V2 { .. } => false,
+            Csr::V3 { csr_payload, .. } => csr_payload.keys_to_sign == keys_to_sign,
+        }
+    }
 }
 
 impl fmt::Debug for Csr {
@@ -76,3 +124,209 @@ impl fmt::Debug for Csr {
         }
     }
 }
+
+/// Builder errors for Csr V2 and V3.
+#[derive(Debug, PartialEq, Error)]
+pub enum CsrBuilderError {
+    /// Device info is missing.
+    #[error("Missing device info")]
+    MissingDeviceInfo,
+    /// Challenge is missing.
+    #[error("Missing challenge")]
+    MissingChallenge,
+    /// Protected data is missing.
+    #[error("Missing protected data")]
+    MissingProtectedData,
+    /// DICE chain is missing.
+    #[error("Missing DICE chain")]
+    MissingDiceChain,
+    /// CSR payload is missing.
+    #[error("Missing CSR payload")]
+    MissingCsrPayload,
+    /// UDS certificates are missing.
+    #[error("Missing UDS certificates")]
+    MissingUdsCerts,
+}
+
+/// Builder for Csr::V2.
+#[derive(Default)]
+pub struct CsrV2Builder {
+    device_info: Option<DeviceInfo>,
+    challenge: Option<Vec<u8>>,
+    protected_data: Option<ProtectedData>,
+}
+
+impl CsrV2Builder {
+    /// Builds the CSR V2.
+    pub fn build(self) -> Result<Csr, CsrBuilderError> {
+        let device_info = self.device_info.ok_or(CsrBuilderError::MissingDeviceInfo)?;
+        let challenge = self.challenge.ok_or(CsrBuilderError::MissingChallenge)?;
+        let protected_data = self.protected_data.ok_or(CsrBuilderError::MissingProtectedData)?;
+
+        Ok(Csr::V2 { device_info, challenge, protected_data })
+    }
+
+    /// Sets the device info.
+    #[must_use]
+    pub fn device_info(mut self, device_info: DeviceInfo) -> Self {
+        self.device_info = Some(device_info);
+        self
+    }
+
+    /// Sets the challenge.
+    #[must_use]
+    pub fn challenge(mut self, challenge: Vec<u8>) -> Self {
+        self.challenge = Some(challenge);
+        self
+    }
+
+    /// Sets the protected data.
+    #[must_use]
+    pub fn protected_data(mut self, protected_data: ProtectedData) -> Self {
+        self.protected_data = Some(protected_data);
+        self
+    }
+}
+
+/// Builder for Csr::V3.
+#[derive(Default)]
+pub struct CsrV3Builder {
+    challenge: Option<Vec<u8>>,
+    dice_chain: Option<ChainForm>,
+    uds_certs: Option<HashMap<String, Vec<X509>>>,
+    csr_payload: Option<CsrPayload>,
+}
+
+impl CsrV3Builder {
+    /// Builds Csr::V3.
+    pub fn build(self) -> Result<Csr, CsrBuilderError> {
+        let challenge = self.challenge.ok_or(CsrBuilderError::MissingChallenge)?;
+        let dice_chain = self.dice_chain.ok_or(CsrBuilderError::MissingDiceChain)?;
+        let uds_certs = self.uds_certs.ok_or(CsrBuilderError::MissingUdsCerts)?;
+        let csr_payload = self.csr_payload.ok_or(CsrBuilderError::MissingCsrPayload)?;
+
+        Ok(Csr::V3 { dice_chain, uds_certs, challenge, csr_payload })
+    }
+
+    /// Sets the challenge.
+    #[must_use]
+    pub fn challenge(mut self, challenge: Vec<u8>) -> Self {
+        self.challenge = Some(challenge);
+        self
+    }
+
+    /// Sets the DICE chain.
+    #[must_use]
+    pub fn dice_chain(mut self, dice_chain: ChainForm) -> Self {
+        self.dice_chain = Some(dice_chain);
+        self
+    }
+
+    /// Sets the UDS certificates.
+    #[must_use]
+    pub fn uds_certs(mut self, uds_certs: HashMap<String, Vec<X509>>) -> Self {
+        self.uds_certs = Some(uds_certs);
+        self
+    }
+
+    /// Sets the CSR payload.
+    #[must_use]
+    pub fn csr_payload(mut self, csr_payload: CsrPayload) -> Self {
+        self.csr_payload = Some(csr_payload);
+        self
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::cbor::rkp::csr::testutil::{parse_pem_public_key_or_panic, test_device_info};
+    use crate::dice::{ChainForm, DegenerateChain};
+    use crate::rkp::device_info::DeviceInfoVersion;
+    use crate::rkp::protected_data::ProtectedData;
+    use anyhow::{Context, Result};
+    use coset::{iana, CoseKey, CoseKeyBuilder};
+    use openssl::bn::BigNum;
+
+    fn create_test_key() -> Result<CoseKey> {
+        let x = BigNum::from_u32(1234).context("Failed to create x coord")?;
+        let y = BigNum::from_u32(4321).context("Failed to create y coord")?;
+        Ok(CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
+            .build())
+    }
+
+    #[test]
+    fn build_and_debug_csr_v2() {
+        let device_info = test_device_info(DeviceInfoVersion::V2);
+        let challenge = b"challenge".to_vec();
+        let root_public_key = parse_pem_public_key_or_panic(
+            "-----BEGIN PUBLIC KEY-----\n\
+                MCowBQYDK2VwAyEArqr7jIIQ8TB1+l/Sh69eiSJL6t6txO1oLhpkdVSUuBk=\n\
+                -----END PUBLIC KEY-----\n",
+        );
+
+        let degenerate_chain = DegenerateChain::new("test_issuer", "test_subject", root_public_key)
+            .expect("Failed to create certificate chain");
+        let protected_data =
+            ProtectedData::new(vec![0; 32], ChainForm::Degenerate(degenerate_chain), None);
+
+        let csr = CsrV2Builder::default()
+            .device_info(device_info.clone())
+            .challenge(challenge.clone())
+            .protected_data(protected_data.clone())
+            .build()
+            .expect("Failed to build CSR V2");
+
+        let expected = format!(
+            "CSR V2 {{ DeviceInfo: {device_info:?}, Challenge: {:?}, ProtectedData: {protected_data:?} }}",
+            hex::encode(&challenge)
+        );
+
+        assert_eq!(format!("{csr:?}"), expected);
+    }
+
+    #[test]
+    fn build_and_debug_csr_v3() {
+        let device_info = test_device_info(DeviceInfoVersion::V3);
+
+        let challenge = b"challenge".to_vec();
+
+        let serialized_payload = b"serialized_payload".to_vec();
+        let certificate_type = "test_certificate_type".to_string();
+        let mut keys_to_sign_vec = Vec::new();
+        let key = create_test_key().expect("Failed to create test key");
+        keys_to_sign_vec.push(key);
+
+        let keys_to_sign = KeysToSign(keys_to_sign_vec);
+
+        let csr_payload = CsrPayload {
+            serialized: serialized_payload,
+            certificate_type,
+            device_info: device_info.clone(),
+            keys_to_sign,
+        };
+        let root_public_key = parse_pem_public_key_or_panic(
+            "-----BEGIN PUBLIC KEY-----\n\
+                MCowBQYDK2VwAyEArqr7jIIQ8TB1+l/Sh69eiSJL6t6txO1oLhpkdVSUuBk=\n\
+                -----END PUBLIC KEY-----\n",
+        );
+        let degenerate_chain = DegenerateChain::new("test_issuer", "test_subject", root_public_key)
+            .expect("Failed to create certificate chain");
+        let dice_chain = ChainForm::Degenerate(degenerate_chain);
+        let uds_certs = HashMap::new();
+
+        let csr = CsrV3Builder::default()
+            .challenge(challenge.clone())
+            .dice_chain(dice_chain.clone())
+            .uds_certs(uds_certs.clone())
+            .csr_payload(csr_payload.clone())
+            .build()
+            .expect("Failed to build CSR V3");
+
+        let expected = format!(
+            "CSR V3 {{ DeviceInfo: {device_info:?}, DiceChain: {dice_chain:?}, UdsCerts: {uds_certs:?} }}",
+        );
+
+        assert_eq!(format!("{csr:?}"), expected);
+    }
+}
diff --git a/remote_provisioning/hwtrust/src/rkp/device_info.rs b/remote_provisioning/hwtrust/src/rkp/device_info.rs
index c99f74d..6973db6 100644
--- a/remote_provisioning/hwtrust/src/rkp/device_info.rs
+++ b/remote_provisioning/hwtrust/src/rkp/device_info.rs
@@ -7,7 +7,7 @@ use std::fmt;
 /// Describes a device that is registered with the RKP backend. This implementation contains fields
 /// common to all versions defined in DeviceInfo.aidl.
 pub struct DeviceInfo {
-    /// Version of this data structure.
+    /// Version of this data structure. Currently, this is the same as the HAL version.
     pub version: DeviceInfoVersion,
     /// The device's marketed brand.
     pub brand: String,
@@ -36,14 +36,13 @@ pub struct DeviceInfo {
     /// Patch level of the vendor partition.
     pub vendor_patch_level: u32,
     /// If backed by KeyMint, this is the security level of the HAL.
-    pub security_level: Option<DeviceInfoSecurityLevel>,
-    /// Whether or not secure boot is enforced/required by the SoC.
-    pub fused: bool,
+    pub security_level: DeviceInfoSecurityLevel,
+    /// Whether secure boot is enforced/required by the SoC.
+    pub fused: u32,
 }
 
 impl fmt::Debug for DeviceInfo {
     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
-        let security_level: &dyn fmt::Debug = self.security_level.as_ref().map_or(&"<none>", |s| s);
         let os_version: &dyn fmt::Debug = self.os_version.as_ref().map_or(&"<none>", |v| v);
 
         fmt.debug_struct("DeviceInfo")
@@ -60,7 +59,7 @@ impl fmt::Debug for DeviceInfo {
             .field("system_patch_level", &self.system_patch_level)
             .field("boot_patch_level", &self.boot_patch_level)
             .field("vendor_patch_level", &self.vendor_patch_level)
-            .field("security_level", security_level)
+            .field("security_level", &self.security_level)
             .field("fused", &self.fused)
             .finish()
     }
@@ -75,6 +74,8 @@ pub enum DeviceInfoBootloaderState {
     Unlocked,
     /// This field is a placeholder for the AVF backend.
     Avf,
+    /// This field is a placeholder for a Factory CSR
+    Factory,
 }
 
 impl TryFrom<&str> for DeviceInfoBootloaderState {
@@ -85,7 +86,7 @@ impl TryFrom<&str> for DeviceInfoBootloaderState {
             "locked" => Ok(Self::Locked),
             "unlocked" => Ok(Self::Unlocked),
             "avf" => Ok(Self::Avf),
-            _ => Err(anyhow!("Invalid bootloader state: `{s}`")),
+            _ => Ok(Self::Factory),
         }
     }
 }
@@ -101,6 +102,8 @@ pub enum DeviceInfoVbState {
     Orange,
     /// This field is a placeholder for the AVF backend.
     Avf,
+    /// This field is a placeholder for a Factory CSR
+    Factory,
 }
 
 impl TryFrom<&str> for DeviceInfoVbState {
@@ -112,17 +115,18 @@ impl TryFrom<&str> for DeviceInfoVbState {
             "yellow" => Ok(Self::Yellow),
             "orange" => Ok(Self::Orange),
             "avf" => Ok(Self::Avf),
-            _ => Err(anyhow!("Invalid VB state: `{s}`")),
+            _ => Ok(Self::Factory),
         }
     }
 }
 
 #[derive(Copy, Clone, Debug, Eq, PartialEq)]
-/// The version of the DeviceInfo structure, which may updated with HAL changes.
+/// The version of the DeviceInfo structure, which may update with HAL changes.
+/// Currently, this is the same as the HAL version.
 pub enum DeviceInfoVersion {
     /// First supported version. Prior to this (V1), almost all fields were optional.
     V2,
-    /// Explicit version removed from the CBOR. Otherwise identical to V2.
+    /// Explicit version removed from the CBOR. Otherwise, identical to V2.
     V3,
 }
 
@@ -133,7 +137,7 @@ impl TryFrom<u32> for DeviceInfoVersion {
         match i {
             2 => Ok(Self::V2),
             3 => Ok(Self::V3),
-            _ => Err(anyhow!("Invalid version: `{i}`")),
+            _ => Err(anyhow!("Invalid DeviceInfo version: `{i}`")),
         }
     }
 }
@@ -147,6 +151,8 @@ pub enum DeviceInfoSecurityLevel {
     StrongBox,
     /// AVF's backend.
     Avf,
+    /// This field is a placeholder for a Factory CSR
+    Factory,
 }
 
 impl TryFrom<&str> for DeviceInfoSecurityLevel {
@@ -157,7 +163,7 @@ impl TryFrom<&str> for DeviceInfoSecurityLevel {
             "strongbox" => Ok(Self::StrongBox),
             "tee" => Ok(Self::Tee),
             "avf" => Ok(Self::Avf),
-            _ => Err(anyhow!("Invalid security level: `{s}`")),
+            _ => Ok(Self::Factory),
         }
     }
 }
@@ -176,7 +182,10 @@ mod tests {
             DeviceInfoBootloaderState::try_from("UNLocked").unwrap(),
             DeviceInfoBootloaderState::Unlocked
         );
-        DeviceInfoBootloaderState::try_from("nope").unwrap_err();
+        assert_eq!(
+            DeviceInfoBootloaderState::try_from("nope").unwrap(),
+            DeviceInfoBootloaderState::Factory
+        );
     }
 
     #[test]
@@ -184,7 +193,7 @@ mod tests {
         assert_eq!(DeviceInfoVbState::try_from("greEN").unwrap(), DeviceInfoVbState::Green);
         assert_eq!(DeviceInfoVbState::try_from("YeLLoW").unwrap(), DeviceInfoVbState::Yellow);
         assert_eq!(DeviceInfoVbState::try_from("ORange").unwrap(), DeviceInfoVbState::Orange);
-        DeviceInfoVbState::try_from("bad").unwrap_err();
+        assert_eq!(DeviceInfoVbState::try_from("bad").unwrap(), DeviceInfoVbState::Factory);
     }
 
     #[test]
@@ -202,6 +211,9 @@ mod tests {
             DeviceInfoSecurityLevel::StrongBox
         );
         assert_eq!(DeviceInfoSecurityLevel::try_from("TeE").unwrap(), DeviceInfoSecurityLevel::Tee);
-        DeviceInfoSecurityLevel::try_from("insecure").unwrap_err();
+        assert_eq!(
+            DeviceInfoSecurityLevel::try_from("insecure").unwrap(),
+            DeviceInfoSecurityLevel::Factory
+        );
     }
 }
diff --git a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
index a04f76f..f1ce6b4 100644
--- a/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
+++ b/remote_provisioning/hwtrust/src/rkp/factory_csr.rs
@@ -9,7 +9,7 @@ use std::str::FromStr;
 /// (Certificate Signing Request) format for this as an implementation convenience. The CSR
 /// actually contains an empty set of keys for which certificates are needed.
 #[non_exhaustive]
-#[derive(Debug, Eq, PartialEq)]
+#[derive(Debug, PartialEq)]
 pub struct FactoryCsr {
     /// The CSR, as created by an IRemotelyProvisionedComponent HAL.
     pub csr: Csr,
@@ -336,4 +336,13 @@ mod tests {
                     .contains("12953f77f0726491a09c5b2d134a26a8a657dbc170c4036ffde81e881e0acd03")
         );
     }
+
+    #[test]
+    fn from_json_v3_p256_with_corrupted_payload() {
+        let json =
+            fs::read_to_string("testdata/factory_csr/v3_p256_with_corrupted_payload.json").unwrap();
+        let err = FactoryCsr::from_json(&Session::default(), &json).unwrap_err();
+        let source = err.source().unwrap().to_string();
+        assert!(source.contains("Signature verification failed"));
+    }
 }
diff --git a/remote_provisioning/hwtrust/src/rkp/protected_data.rs b/remote_provisioning/hwtrust/src/rkp/protected_data.rs
index 00b09c1..bc23a44 100644
--- a/remote_provisioning/hwtrust/src/rkp/protected_data.rs
+++ b/remote_provisioning/hwtrust/src/rkp/protected_data.rs
@@ -4,6 +4,7 @@ use std::{collections::HashMap, fmt};
 
 use crate::dice::ChainForm;
 
+/// The CSR V2 payload that is encrypted with an Endpoint Encryption Key (EEK).
 #[derive(Clone, Eq, PartialEq)]
 pub struct ProtectedData {
     mac_key: Vec<u8>,
@@ -23,13 +24,20 @@ pub enum UdsCertsEntry {
 }
 
 impl ProtectedData {
+    /// Constructs a new `ProtectedData` with a MAC key, DICE chain, and optional UDS certificates.
     pub fn new(mac_key: Vec<u8>, dice_chain: ChainForm, uds_certs: Option<UdsCerts>) -> Self {
         Self { mac_key, dice_chain, uds_certs }
     }
 
+    /// Returns the DICE chain.
     pub fn dice_chain(&self) -> ChainForm {
         self.dice_chain.clone()
     }
+
+    /// Returns the UDS certificates.
+    pub fn uds_certs(&self) -> Option<UdsCerts> {
+        self.uds_certs.clone()
+    }
 }
 
 impl UdsCerts {
diff --git a/remote_provisioning/hwtrust/src/session.rs b/remote_provisioning/hwtrust/src/session.rs
index 16e9c22..2c96360 100644
--- a/remote_provisioning/hwtrust/src/session.rs
+++ b/remote_provisioning/hwtrust/src/session.rs
@@ -22,10 +22,14 @@ pub struct Options {
     pub allow_any_mode: bool,
     /// The RKP instance associated to the session.
     pub rkp_instance: RkpInstance,
+    /// This flag is used during DeviceInfo validation
+    pub is_factory: bool,
+    /// Verbose output
+    pub verbose: bool,
 }
 
 /// The set of RKP instances associated to the session.
-#[derive(Clone, Copy, Default, Debug, ValueEnum)]
+#[derive(Clone, Copy, Default, Debug, ValueEnum, PartialEq, Eq)]
 pub enum RkpInstance {
     /// The DICE chain is associated to the default instance.
     #[default]
@@ -56,6 +60,11 @@ impl FromStr for RkpInstance {
 }
 
 impl Session {
+    /// Set is_factory
+    pub fn set_is_factory(&mut self, is_factory: bool) {
+        self.options.is_factory = is_factory;
+    }
+
     /// Set allow_any_mode.
     pub fn set_allow_any_mode(&mut self, allow_any_mode: bool) {
         self.options.allow_any_mode = allow_any_mode
diff --git a/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_with_corrupted_payload.json b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_with_corrupted_payload.json
new file mode 100644
index 0000000..6af2572
--- /dev/null
+++ b/remote_provisioning/hwtrust/testdata/factory_csr/v3_p256_with_corrupted_payload.json
@@ -0,0 +1 @@
+{"csr":"hQGggqUBAgMmIAEhWCCHk1RXjzva8oQvdc9KnyV+RXgA3ckom2LVjmRttH25xCJYIOlLKg6Nf1SYEIz+649T8wZcxauBsF/f77TYAvML5Xd5hEOhASagWQEEqQFmaXNzdWVyAmdzdWJqZWN0OgBHRFBYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFJYILiWVOIspNJKnA5FEcjyY/BmDS4gSJaQFPRUY8T0OTA4OgBHRFNVoToAARFxbmNvbXBvbmVudF9uYW1lOgBHRFRYIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVOgBHRFZBAToAR0RXWE2lAQIDJiABIVgg61L647tSG8b3QhPPHiwc3iTbujf2cxHnEDcTblJYZWgiWCCCEMWdgDNE6pn7VppdaLhspuW837SdTVJZiNtaVrtP4DoAR0RYQSBYQM2neX8L/e4z1yxejVMKlzGcRaUhdseOzpnSWPM90jTG1Ip/Zu5rTa7n+qybsd5RTPfsu+/UDdI9N91w6Jp67wmEQ6EBJqBZAhCCWCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIFkB6oQDZ0tleW1pbnSuZWJyYW5kZkdvb2dsZWVmdXNlZAFlbW9kZWxlbW9kZWxmZGV2aWNlZmRldmljZWdwcm9kdWN0ZXBpeGVsaHZiX3N0YXRlZWdyZWVuam9zX3ZlcnNpb25iMTJsbWFudWZhY3R1cmVyZkdvb2dsZW12Ym1ldGFfZGlnZXN0TxEiM0RVZneImaq7zN3u/25zZWN1cml0eV9sZXZlbGN0ZWVwYm9vdF9wYXRjaF9sZXZlbBoBNIxicGJvb3Rsb2FkZXJfc3RhdGVmbG9ja2VkcnN5c3RlbV9wYXRjaF9sZXZlbBoBNIxhcnZlbmRvcl9wYXRjaF9sZXZlbBoBNIxjgqYBAgMmIAEhWCCx1dc4NpwqjqyQFe+pfLcPyi7Dl/OmD+NLs9b2JVXekyJYINWNoh2t3ATuGisQ+twBWYhnjrxHizHScyRE6ApTOmcfI1ghAKG7GYs+GB2+NV+xVttOmJDI17vBvmnKmBlcSlilK/IKpgECAyYgASFYIKZdIXYLMJWdiFch2LgpEWZDowIAoHLRmSbYAaMwNz/CIlggXrdVRCT5hFKFvI1o7IHUATslIpNeUGFFl8CRoJrkaIcjWCEAxSEDrsLPxLNtcRTjggCU3Zr9yvzWj7QF15lX8RNpOkdYQJ9a6IXlNdyZORYuBuTWH9MVDi1agvaFvWOuCSlZH0jG9TBM27ienFuieb7JzaaiWqna+DOS3f7C+znoO4UZo9mha2ZpbmdlcnByaW50eDticmFuZDEvcHJvZHVjdDEvZGV2aWNlMToxMS9pZC8yMDIxMDgwNS40Mjp1c2VyL3JlbGVhc2Uta2V5cw==","name":"default","serialno":"fake-device-0"}
```

