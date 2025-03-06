```diff
diff --git a/OWNERS b/OWNERS
index 6fdb550a..b1c1feac 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,11 +1,7 @@
-alanstokes@google.com
 drysdale@google.com
-eranm@google.com
 hasinitg@google.com
 jbires@google.com
 jeffv@google.com
-kroot@google.com
 sethmo@google.com
 swillden@google.com
-trong@google.com
 zeuthen@google.com
diff --git a/keystore/keystore_cli_v2.cpp b/keystore/keystore_cli_v2.cpp
index ab3e22c3..d442e482 100644
--- a/keystore/keystore_cli_v2.cpp
+++ b/keystore/keystore_cli_v2.cpp
@@ -22,11 +22,12 @@
 #include <variant>
 #include <vector>
 
+#include <android-base/strings.h>
+
 #include <base/command_line.h>
 #include <base/files/file_util.h>
 #include <base/strings/string_number_conversions.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
 
 #include <aidl/android/security/apc/BnConfirmationCallback.h>
 #include <aidl/android/security/apc/IProtectedConfirmation.h>
@@ -705,12 +706,12 @@ int BrilloPlatformTest(const std::string& prefix, bool test_for_0_3) {
     std::vector<TestCase> test_cases = GetTestCases();
     for (const auto& test_case : test_cases) {
         if (!prefix.empty() &&
-            !base::StartsWith(test_case.name, prefix, base::CompareCase::SENSITIVE)) {
+            !android::base::StartsWith(test_case.name, prefix)) {
             continue;
         }
         if (test_for_0_3 &&
-            (base::StartsWith(test_case.name, "AES", base::CompareCase::SENSITIVE) ||
-             base::StartsWith(test_case.name, "HMAC", base::CompareCase::SENSITIVE))) {
+            (android::base::StartsWith(test_case.name, "AES") ||
+             android::base::StartsWith(test_case.name, "HMAC"))) {
             continue;
         }
         ++test_count;
@@ -1016,8 +1017,7 @@ int Confirmation(const std::string& promptText, const std::string& extraDataHex,
         return 1;
     }
 
-    std::vector<std::string> pieces =
-        base::SplitString(uiOptionsStr, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
+    std::vector<std::string> pieces = android::base::Tokenize(uiOptionsStr, ",");
     int uiOptionsAsFlags = 0;
     for (auto& p : pieces) {
         int value;
diff --git a/keystore2/Android.bp b/keystore2/Android.bp
index 7bba6870..ef5111fd 100644
--- a/keystore2/Android.bp
+++ b/keystore2/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_hardware_backed_security",
     // See: http://go/android-license-faq
     // A large-scale-change added 'default_applicable_licenses' to import
     // all of the 'license_kinds' from "system_security_license"
@@ -49,6 +50,8 @@ rust_defaults {
         "libandroid_security_flags_rust",
         "libanyhow",
         "libbinder_rs",
+        "libbssl_crypto",
+        "libder",
         "libkeystore2_aaid-rust",
         "libkeystore2_apc_compat-rust",
         "libkeystore2_crypto_rust",
@@ -59,6 +62,7 @@ rust_defaults {
         "liblibc",
         "liblog_rust",
         "libmessage_macro",
+        "libpostprocessor_client",
         "librand",
         "librkpd_client",
         "librustutils",
@@ -123,6 +127,11 @@ rust_test {
     require_root: true,
 }
 
+vintf_fragment {
+    name: "android.system.keystore2-service.xml",
+    src: "android.system.keystore2-service.xml",
+}
+
 rust_defaults {
     name: "keystore2_defaults",
     srcs: ["src/keystore2_main.rs"],
@@ -141,7 +150,7 @@ rust_defaults {
     // selection available in the build system.
     prefer_rlib: true,
 
-    vintf_fragments: ["android.system.keystore2-service.xml"],
+    vintf_fragment_modules: ["android.system.keystore2-service.xml"],
 
     required: ["keystore_cli_v2"],
 }
@@ -170,6 +179,18 @@ java_aconfig_library {
     aconfig_declarations: "keystore2_flags",
 }
 
+java_aconfig_library {
+    name: "keystore2_flags_java-host",
+    aconfig_declarations: "keystore2_flags",
+    host_supported: true,
+}
+
+java_aconfig_library {
+    name: "keystore2_flags_java-framework",
+    aconfig_declarations: "keystore2_flags",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+}
+
 rust_aconfig_library {
     name: "libkeystore2_flags_rust",
     crate_name: "keystore2_flags",
diff --git a/keystore2/OWNERS b/keystore2/OWNERS
index bf9d61b3..1fcc785d 100644
--- a/keystore2/OWNERS
+++ b/keystore2/OWNERS
@@ -1,8 +1,9 @@
 set noparent
 # Bug component: 1084732
-eranm@google.com
+cvlasov@google.com
 drysdale@google.com
 hasinitg@google.com
 jbires@google.com
+kwadhera@google.com
 sethmo@google.com
 swillden@google.com
diff --git a/keystore2/aconfig/flags.aconfig b/keystore2/aconfig/flags.aconfig
index ff817b77..b15230ec 100644
--- a/keystore2/aconfig/flags.aconfig
+++ b/keystore2/aconfig/flags.aconfig
@@ -40,3 +40,19 @@ flag {
   bug: "283077822"
   is_fixed_read_only: true
 }
+
+flag {
+  name: "use_blob_state_column"
+  namespace: "hardware_backed_security"
+  description: "Use state database column to track superseded blobentry rows"
+  bug: "319563050"
+  is_fixed_read_only: true
+}
+
+flag {
+  name: "attest_modules"
+  namespace: "hardware_backed_security"
+  description: "Support attestation of modules"
+  bug: "369375199"
+  is_fixed_read_only: true
+}
diff --git a/keystore2/aidl/Android.bp b/keystore2/aidl/Android.bp
index c297a158..13bf455e 100644
--- a/keystore2/aidl/Android.bp
+++ b/keystore2/aidl/Android.bp
@@ -21,30 +21,11 @@ package {
     default_applicable_licenses: ["system_security_license"],
 }
 
-aidl_interface {
-    name: "android.security.attestationmanager",
-    srcs: ["android/security/attestationmanager/*.aidl"],
-    imports: ["android.hardware.security.keymint-V3"],
-    unstable: true,
-    backend: {
-        java: {
-            platform_apis: true,
-        },
-        rust: {
-            enabled: true,
-        },
-        ndk: {
-            enabled: true,
-            apps_enabled: false,
-        },
-    },
-}
-
 aidl_interface {
     name: "android.security.authorization",
     srcs: ["android/security/authorization/*.aidl"],
+    defaults: ["android.hardware.security.keymint-latest-defaults"],
     imports: [
-        "android.hardware.security.keymint-V3",
         "android.hardware.security.secureclock-V1",
     ],
     unstable: true,
@@ -82,8 +63,8 @@ aidl_interface {
 aidl_interface {
     name: "android.security.compat",
     srcs: ["android/security/compat/*.aidl"],
+    defaults: ["android.hardware.security.keymint-latest-defaults"],
     imports: [
-        "android.hardware.security.keymint-V3",
         "android.hardware.security.secureclock-V1",
         "android.hardware.security.sharedsecret-V1",
     ],
@@ -105,8 +86,8 @@ aidl_interface {
 aidl_interface {
     name: "android.security.maintenance",
     srcs: ["android/security/maintenance/*.aidl"],
-    imports: [
-        "android.system.keystore2-V4",
+    defaults: [
+        "android.system.keystore2-latest-defaults",
     ],
     unstable: true,
     backend: {
@@ -141,11 +122,31 @@ aidl_interface {
     },
 }
 
+aidl_interface {
+    name: "android.security.postprocessor",
+    srcs: ["android/security/postprocessor/*.aidl"],
+    unstable: true,
+    backend: {
+        java: {
+            enabled: false,
+        },
+        cpp: {
+            enabled: false,
+        },
+        ndk: {
+            enabled: false,
+        },
+        rust: {
+            enabled: true,
+        },
+    },
+}
+
 aidl_interface {
     name: "android.security.metrics",
     srcs: ["android/security/metrics/*.aidl"],
-    imports: [
-        "android.system.keystore2-V4",
+    defaults: [
+        "android.system.keystore2-latest-defaults",
     ],
     unstable: true,
     backend: {
@@ -168,21 +169,21 @@ aidl_interface {
 java_defaults {
     name: "keystore2_use_latest_aidl_java_static",
     static_libs: [
-        "android.system.keystore2-V4-java-source",
+        "android.system.keystore2-V5-java-source",
     ],
 }
 
 java_defaults {
     name: "keystore2_use_latest_aidl_java_shared",
     libs: [
-        "android.system.keystore2-V4-java-source",
+        "android.system.keystore2-V5-java-source",
     ],
 }
 
 java_defaults {
     name: "keystore2_use_latest_aidl_java",
     libs: [
-        "android.system.keystore2-V4-java",
+        "android.system.keystore2-V5-java",
     ],
 }
 
@@ -192,28 +193,28 @@ java_defaults {
 cc_defaults {
     name: "keystore2_use_latest_aidl_ndk_static",
     static_libs: [
-        "android.system.keystore2-V4-ndk",
+        "android.system.keystore2-V5-ndk",
     ],
 }
 
 cc_defaults {
     name: "keystore2_use_latest_aidl_ndk_shared",
     shared_libs: [
-        "android.system.keystore2-V4-ndk",
+        "android.system.keystore2-V5-ndk",
     ],
 }
 
 cc_defaults {
     name: "keystore2_use_latest_aidl_cpp_shared",
     shared_libs: [
-        "android.system.keystore2-V4-cpp",
+        "android.system.keystore2-V5-cpp",
     ],
 }
 
 cc_defaults {
     name: "keystore2_use_latest_aidl_cpp_static",
     static_libs: [
-        "android.system.keystore2-V4-cpp",
+        "android.system.keystore2-V5-cpp",
     ],
 }
 
@@ -223,6 +224,6 @@ cc_defaults {
 rust_defaults {
     name: "keystore2_use_latest_aidl_rust",
     rustlibs: [
-        "android.system.keystore2-V4-rust",
+        "android.system.keystore2-V5-rust",
     ],
 }
diff --git a/keystore2/aidl/android/security/attestationmanager/ByteArray.aidl b/keystore2/aidl/android/security/attestationmanager/ByteArray.aidl
deleted file mode 100644
index dc37b1b7..00000000
--- a/keystore2/aidl/android/security/attestationmanager/ByteArray.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.security.attestationmanager;
-
-/**
- * Simple data holder for a byte array, allowing for multidimensional arrays in AIDL.
- * @hide
- */
-parcelable ByteArray {
-    byte[] data;
-}
\ No newline at end of file
diff --git a/keystore2/aidl/android/security/attestationmanager/IAttestationManager.aidl b/keystore2/aidl/android/security/attestationmanager/IAttestationManager.aidl
deleted file mode 100644
index e77a21e2..00000000
--- a/keystore2/aidl/android/security/attestationmanager/IAttestationManager.aidl
+++ /dev/null
@@ -1,36 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.security.attestationmanager;
-
-import android.security.attestationmanager.ByteArray;
-import android.hardware.security.keymint.KeyParameter;
-
-/**
- * Internal interface for performing device attestation.
- * @hide
- */
-interface IAttestationManager {
-    /**
-     * Attest a provided list of device identifiers.
-     *
-     * @return The signed certificate chain, with each individual certificate encoded as a byte
-     *         array.
-     */
-    ByteArray[] attestDevice(
-            in KeyParameter[] deviceIdentifiers, boolean useIndividualAttestation,
-            in byte[] attestationChallenge, int securityLevel);
-}
\ No newline at end of file
diff --git a/keystore2/aidl/android/security/postprocessor/CertificateChain.aidl b/keystore2/aidl/android/security/postprocessor/CertificateChain.aidl
new file mode 100644
index 00000000..8d9daadd
--- /dev/null
+++ b/keystore2/aidl/android/security/postprocessor/CertificateChain.aidl
@@ -0,0 +1,34 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package android.security.postprocessor;
+
+/**
+ * General parcelable for holding the encoded certificates to be used in Keystore. This parcelable
+ * is returned by `IKeystoreCertificatePostProcessor::processKeystoreCertificates`.
+ * @hide
+ */
+@RustDerive(Clone=true)
+parcelable CertificateChain {
+    /**
+     * Holds the DER-encoded representation of the leaf certificate.
+     */
+    byte[] leafCertificate;
+    /**
+     * Holds a byte array containing the concatenation of all the remaining elements of the
+     * certificate chain with root certificate as the last with each certificate represented in
+     * DER-encoded format.
+     */
+    byte[] remainingChain;
+}
diff --git a/keystore2/aidl/android/security/postprocessor/IKeystoreCertificatePostProcessor.aidl b/keystore2/aidl/android/security/postprocessor/IKeystoreCertificatePostProcessor.aidl
new file mode 100644
index 00000000..0ceaacb0
--- /dev/null
+++ b/keystore2/aidl/android/security/postprocessor/IKeystoreCertificatePostProcessor.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.security.postprocessor;
+
+import android.security.postprocessor.CertificateChain;
+
+interface IKeystoreCertificatePostProcessor {
+    /**
+     * Allows implementing services to process the keystore certificates after the certificate
+     * chain has been generated.
+     *
+     * certificateChain holds the chain associated with a newly generated Keystore asymmetric
+     * keypair, where the leafCertificate is the certificate for the public key of generated key.
+     * The remaining attestation certificates are stored as a concatenated byte array of the
+     * encoded certificates with root certificate as the last element.
+     *
+     * Successful calls would get the processed certificate chain which then replaces the original
+     * certificate chain. In case of any failures/exceptions, keystore would fallback to the
+     * original certificate chain.
+     *
+     * @hide
+     */
+    CertificateChain processKeystoreCertificates(in CertificateChain certificateChain);
+}
diff --git a/keystore2/android.system.keystore2-service.xml b/keystore2/android.system.keystore2-service.xml
index 4d8a756d..35b9cc88 100644
--- a/keystore2/android.system.keystore2-service.xml
+++ b/keystore2/android.system.keystore2-service.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="framework">
     <hal format="aidl">
         <name>android.system.keystore2</name>
-        <version>4</version>
+        <version>5</version>
         <interface>
             <name>IKeystoreService</name>
             <instance>default</instance>
diff --git a/keystore2/postprocessor_client/Android.bp b/keystore2/postprocessor_client/Android.bp
new file mode 100644
index 00000000..7f0194ac
--- /dev/null
+++ b/keystore2/postprocessor_client/Android.bp
@@ -0,0 +1,47 @@
+//
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "system_security_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["system_security_license"],
+}
+
+rust_defaults {
+    name: "libpostprocessor_client_defaults",
+    crate_name: "postprocessor_client",
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "android.security.postprocessor-rust",
+        "libanyhow",
+        "libbinder_rs",
+        "liblog_rust",
+        "libmessage_macro",
+        "libthiserror",
+    ],
+    defaults: [
+        "keymint_use_latest_hal_aidl_rust",
+    ],
+}
+
+rust_library {
+    name: "libpostprocessor_client",
+    defaults: [
+        "libpostprocessor_client_defaults",
+    ],
+}
diff --git a/keystore2/postprocessor_client/src/lib.rs b/keystore2/postprocessor_client/src/lib.rs
new file mode 100644
index 00000000..8b347f9f
--- /dev/null
+++ b/keystore2/postprocessor_client/src/lib.rs
@@ -0,0 +1,109 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Helper wrapper around PostProcessor interface.
+
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::Certificate::Certificate;
+use android_security_postprocessor::aidl::android::security::postprocessor::{
+    CertificateChain::CertificateChain,
+    IKeystoreCertificatePostProcessor::IKeystoreCertificatePostProcessor,
+};
+use anyhow::{Context, Result};
+use binder::{StatusCode, Strong};
+use log::{error, info, warn};
+use message_macro::source_location_msg;
+use std::sync::atomic::{AtomicBool, Ordering};
+use std::sync::mpsc;
+use std::thread;
+use std::time::Duration;
+
+/// Errors occurred during the interaction with Certificate Processor
+#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
+#[error("Binder transaction error {0:?}")]
+pub struct Error(pub StatusCode);
+
+static CERT_PROCESSOR_FAILURE: AtomicBool = AtomicBool::new(false);
+
+fn send_certificate_chain_to_processor(
+    attestation_chain: CertificateChain,
+) -> Result<CertificateChain> {
+    let cert_processing_server: Strong<dyn IKeystoreCertificatePostProcessor> = wait_for_interface(
+        "rkp_cert_processor.service".to_string(),
+    )
+    .context(source_location_msg!("While trying to connect to the post processor service."))?;
+    cert_processing_server
+        .processKeystoreCertificates(&attestation_chain)
+        .context(source_location_msg!("While trying to post process certificates."))
+}
+
+/// Processes the keystore certificates after the certificate chain has been generated by Keystore.
+/// More details about this function provided in IKeystoreCertificatePostProcessor.aidl
+pub fn process_certificate_chain(
+    mut certificates: Vec<Certificate>,
+    attestation_certs: Vec<u8>,
+) -> Vec<Certificate> {
+    // If no certificates are provided from keymint, return the original chain.
+    if certificates.is_empty() {
+        error!("No leaf certificate provided.");
+        return vec![Certificate { encodedCertificate: attestation_certs }];
+    }
+
+    if certificates.len() > 1 {
+        warn!("dropping {} unexpected extra certificates after the leaf", certificates.len() - 1);
+    }
+
+    let attestation_chain = CertificateChain {
+        leafCertificate: certificates[0].encodedCertificate.clone(),
+        remainingChain: attestation_certs.clone(),
+    };
+    let result = send_certificate_chain_to_processor(attestation_chain);
+    match result {
+        Ok(certificate_chain) => {
+            info!("Post processing successful. Replacing certificates.");
+            vec![
+                Certificate { encodedCertificate: certificate_chain.leafCertificate },
+                Certificate { encodedCertificate: certificate_chain.remainingChain },
+            ]
+        }
+        Err(err) => {
+            error!("Failed to replace certificates ({err:#?}), falling back to original chain.");
+            certificates.push(Certificate { encodedCertificate: attestation_certs });
+            certificates
+        }
+    }
+}
+
+fn wait_for_interface(
+    service_name: String,
+) -> Result<Strong<dyn IKeystoreCertificatePostProcessor>> {
+    if CERT_PROCESSOR_FAILURE.load(Ordering::Relaxed) {
+        return Err(Error(StatusCode::INVALID_OPERATION).into());
+    }
+    let (sender, receiver) = mpsc::channel();
+    let _t = thread::spawn(move || {
+        if let Err(e) = sender.send(binder::wait_for_interface(&service_name)) {
+            error!("failed to send result of wait_for_interface({service_name}), likely due to timeout: {e:?}");
+        }
+    });
+
+    match receiver.recv_timeout(Duration::from_secs(5)) {
+        Ok(service_binder) => Ok(service_binder?),
+        Err(e) => {
+            error!("Timed out while connecting to post processor service: {e:#?}");
+            // Cert processor has failed. Retry only after reboot.
+            CERT_PROCESSOR_FAILURE.store(true, Ordering::Relaxed);
+            Err(e.into())
+        }
+    }
+}
diff --git a/keystore2/src/attestation_key_utils.rs b/keystore2/src/attestation_key_utils.rs
index 184b3cbd..4a8923c9 100644
--- a/keystore2/src/attestation_key_utils.rs
+++ b/keystore2/src/attestation_key_utils.rs
@@ -23,7 +23,7 @@ use crate::permission::KeyPerm;
 use crate::remote_provisioning::RemProvState;
 use crate::utils::check_key_permission;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    AttestationKey::AttestationKey, Certificate::Certificate, KeyParameter::KeyParameter, Tag::Tag,
+    AttestationKey::AttestationKey, KeyParameter::KeyParameter, Tag::Tag,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
@@ -37,7 +37,8 @@ use keystore2_crypto::parse_subject_from_certificate;
 pub enum AttestationKeyInfo {
     RkpdProvisioned {
         attestation_key: AttestationKey,
-        attestation_certs: Certificate,
+        /// Concatenated chain of DER-encoded certificates (ending with the root).
+        attestation_certs: Vec<u8>,
     },
     UserGenerated {
         key_id_guard: KeyIdGuard,
diff --git a/keystore2/src/database.rs b/keystore2/src/database.rs
index 84576034..9f27b5a3 100644
--- a/keystore2/src/database.rs
+++ b/keystore2/src/database.rs
@@ -125,6 +125,14 @@ impl TransactionBehavior {
     }
 }
 
+/// Access information for a key.
+#[derive(Debug)]
+struct KeyAccessInfo {
+    key_id: i64,
+    descriptor: KeyDescriptor,
+    vector: Option<KeyPermSet>,
+}
+
 /// If the database returns a busy error code, retry after this interval.
 const DB_BUSY_RETRY_INTERVAL: Duration = Duration::from_micros(500);
 
@@ -500,6 +508,40 @@ impl FromSql for KeyLifeCycle {
     }
 }
 
+/// Current state of a `blobentry` row.
+#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
+enum BlobState {
+    #[default]
+    /// Current blobentry (of its `subcomponent_type`) for the associated key.
+    Current,
+    /// Blobentry that is no longer the current blob (of its `subcomponent_type`) for the associated
+    /// key.
+    Superseded,
+    /// Blobentry for a key that no longer exists.
+    Orphaned,
+}
+
+impl ToSql for BlobState {
+    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
+        match self {
+            Self::Current => Ok(ToSqlOutput::Owned(Value::Integer(0))),
+            Self::Superseded => Ok(ToSqlOutput::Owned(Value::Integer(1))),
+            Self::Orphaned => Ok(ToSqlOutput::Owned(Value::Integer(2))),
+        }
+    }
+}
+
+impl FromSql for BlobState {
+    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
+        match i64::column_result(value)? {
+            0 => Ok(Self::Current),
+            1 => Ok(Self::Superseded),
+            2 => Ok(Self::Orphaned),
+            v => Err(FromSqlError::OutOfRange(v)),
+        }
+    }
+}
+
 /// Keys have a KeyMint blob component and optional public certificate and
 /// certificate chain components.
 /// KeyEntryLoadBits is a bitmap that indicates to `KeystoreDB::load_key_entry`
@@ -870,8 +912,9 @@ pub struct SupersededBlob {
 
 impl KeystoreDB {
     const UNASSIGNED_KEY_ID: i64 = -1i64;
-    const CURRENT_DB_VERSION: u32 = 1;
-    const UPGRADERS: &'static [fn(&Transaction) -> Result<u32>] = &[Self::from_0_to_1];
+    const CURRENT_DB_VERSION: u32 = 2;
+    const UPGRADERS: &'static [fn(&Transaction) -> Result<u32>] =
+        &[Self::from_0_to_1, Self::from_1_to_2];
 
     /// Name of the file that holds the cross-boot persistent database.
     pub const PERSISTENT_DB_FILENAME: &'static str = "persistent.sqlite";
@@ -913,9 +956,77 @@ impl KeystoreDB {
             params![KeyLifeCycle::Unreferenced, Tag::MAX_BOOT_LEVEL.0, BlobMetaData::MaxBootLevel],
         )
         .context(ks_err!("Failed to delete logical boot level keys."))?;
+
+        // DB version is now 1.
         Ok(1)
     }
 
+    // This upgrade function adds an additional `state INTEGER` column to the blobentry
+    // table, and populates it based on whether each blob is the most recent of its type for
+    // the corresponding key.
+    fn from_1_to_2(tx: &Transaction) -> Result<u32> {
+        tx.execute(
+            "ALTER TABLE persistent.blobentry ADD COLUMN state INTEGER DEFAULT 0;",
+            params![],
+        )
+        .context(ks_err!("Failed to add state column"))?;
+
+        // Mark keyblobs that are not the most recent for their corresponding key.
+        // This may take a while if there are excessive numbers of keys in the database.
+        let _wp = wd::watch("KeystoreDB::from_1_to_2 mark all non-current keyblobs");
+        let sc_key_blob = SubComponentType::KEY_BLOB;
+        let mut stmt = tx
+            .prepare(
+                "UPDATE persistent.blobentry SET state=?
+                     WHERE subcomponent_type = ?
+                     AND id NOT IN (
+                             SELECT MAX(id) FROM persistent.blobentry
+                             WHERE subcomponent_type = ?
+                             GROUP BY keyentryid, subcomponent_type
+                         );",
+            )
+            .context("Trying to prepare query to mark superseded keyblobs")?;
+        stmt.execute(params![BlobState::Superseded, sc_key_blob, sc_key_blob])
+            .context(ks_err!("Failed to set state=superseded state for keyblobs"))?;
+        log::info!("marked non-current blobentry rows for keyblobs as superseded");
+
+        // Mark keyblobs that don't have a corresponding key.
+        // This may take a while if there are excessive numbers of keys in the database.
+        let _wp = wd::watch("KeystoreDB::from_1_to_2 mark all orphaned keyblobs");
+        let mut stmt = tx
+            .prepare(
+                "UPDATE persistent.blobentry SET state=?
+                     WHERE subcomponent_type = ?
+                     AND NOT EXISTS (SELECT id FROM persistent.keyentry
+                                     WHERE id = keyentryid);",
+            )
+            .context("Trying to prepare query to mark orphaned keyblobs")?;
+        stmt.execute(params![BlobState::Orphaned, sc_key_blob])
+            .context(ks_err!("Failed to set state=orphaned for keyblobs"))?;
+        log::info!("marked orphaned blobentry rows for keyblobs");
+
+        // Add an index to make it fast to find out of date blobentry rows.
+        let _wp = wd::watch("KeystoreDB::from_1_to_2 add blobentry index");
+        tx.execute(
+            "CREATE INDEX IF NOT EXISTS persistent.blobentry_state_index
+            ON blobentry(subcomponent_type, state);",
+            [],
+        )
+        .context("Failed to create index blobentry_state_index.")?;
+
+        // Add an index to make it fast to find unreferenced keyentry rows.
+        let _wp = wd::watch("KeystoreDB::from_1_to_2 add keyentry state index");
+        tx.execute(
+            "CREATE INDEX IF NOT EXISTS persistent.keyentry_state_index
+            ON keyentry(state);",
+            [],
+        )
+        .context("Failed to create index keyentry_state_index.")?;
+
+        // DB version is now 2.
+        Ok(2)
+    }
+
     fn init_tables(tx: &Transaction) -> Result<()> {
         tx.execute(
             "CREATE TABLE IF NOT EXISTS persistent.keyentry (
@@ -944,12 +1055,21 @@ impl KeystoreDB {
         )
         .context("Failed to create index keyentry_domain_namespace_index.")?;
 
+        // Index added in v2 of database schema.
+        tx.execute(
+            "CREATE INDEX IF NOT EXISTS persistent.keyentry_state_index
+            ON keyentry(state);",
+            [],
+        )
+        .context("Failed to create index keyentry_state_index.")?;
+
         tx.execute(
             "CREATE TABLE IF NOT EXISTS persistent.blobentry (
                     id INTEGER PRIMARY KEY,
                     subcomponent_type INTEGER,
                     keyentryid INTEGER,
-                    blob BLOB);",
+                    blob BLOB,
+                    state INTEGER DEFAULT 0);", // `state` added in v2 of schema
             [],
         )
         .context("Failed to initialize \"blobentry\" table.")?;
@@ -961,6 +1081,14 @@ impl KeystoreDB {
         )
         .context("Failed to create index blobentry_keyentryid_index.")?;
 
+        // Index added in v2 of database schema.
+        tx.execute(
+            "CREATE INDEX IF NOT EXISTS persistent.blobentry_state_index
+            ON blobentry(subcomponent_type, state);",
+            [],
+        )
+        .context("Failed to create index blobentry_state_index.")?;
+
         tx.execute(
             "CREATE TABLE IF NOT EXISTS persistent.blobmetadata (
                      id INTEGER PRIMARY KEY,
@@ -1117,7 +1245,7 @@ impl KeystoreDB {
     /// types that map to a table, information about the table's storage is
     /// returned. Requests for storage types that are not DB tables return None.
     pub fn get_storage_stat(&mut self, storage_type: MetricsStorage) -> Result<StorageStats> {
-        let _wp = wd::watch("KeystoreDB::get_storage_stat");
+        let _wp = wd::watch_millis_with("KeystoreDB::get_storage_stat", 500, storage_type);
 
         match storage_type {
             MetricsStorage::DATABASE => self.get_total_size(),
@@ -1195,9 +1323,28 @@ impl KeystoreDB {
 
             Self::cleanup_unreferenced(tx).context("Trying to cleanup unreferenced.")?;
 
-            // Find up to `max_blobs` more superseded key blobs, load their metadata and return it.
-            let result: Vec<(i64, Vec<u8>)> = {
-                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next");
+            // Find up to `max_blobs` more out-of-date key blobs, load their metadata and return it.
+            let result: Vec<(i64, Vec<u8>)> = if keystore2_flags::use_blob_state_column() {
+                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next v2");
+                let mut stmt = tx
+                    .prepare(
+                        "SELECT id, blob FROM persistent.blobentry
+                        WHERE subcomponent_type = ? AND state != ?
+                        LIMIT ?;",
+                    )
+                    .context("Trying to prepare query for superseded blobs.")?;
+
+                let rows = stmt
+                    .query_map(
+                        params![SubComponentType::KEY_BLOB, BlobState::Current, max_blobs as i64],
+                        |row| Ok((row.get(0)?, row.get(1)?)),
+                    )
+                    .context("Trying to query superseded blob.")?;
+
+                rows.collect::<Result<Vec<(i64, Vec<u8>)>, rusqlite::Error>>()
+                    .context("Trying to extract superseded blobs.")?
+            } else {
+                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next v1");
                 let mut stmt = tx
                     .prepare(
                         "SELECT id, blob FROM persistent.blobentry
@@ -1244,22 +1391,32 @@ impl KeystoreDB {
                 return Ok(result).no_gc();
             }
 
-            // We did not find any superseded key blob, so let's remove other superseded blob in
-            // one transaction.
-            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete");
-            tx.execute(
-                "DELETE FROM persistent.blobentry
-                 WHERE NOT subcomponent_type = ?
-                 AND (
-                     id NOT IN (
-                        SELECT MAX(id) FROM persistent.blobentry
-                        WHERE NOT subcomponent_type = ?
-                        GROUP BY keyentryid, subcomponent_type
-                     ) OR keyentryid NOT IN (SELECT id FROM persistent.keyentry)
-                 );",
-                params![SubComponentType::KEY_BLOB, SubComponentType::KEY_BLOB],
-            )
-            .context("Trying to purge superseded blobs.")?;
+            // We did not find any out-of-date key blobs, so let's remove other types of superseded
+            // blob in one transaction.
+            if keystore2_flags::use_blob_state_column() {
+                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete v2");
+                tx.execute(
+                    "DELETE FROM persistent.blobentry
+                    WHERE subcomponent_type != ? AND state != ?;",
+                    params![SubComponentType::KEY_BLOB, BlobState::Current],
+                )
+                .context("Trying to purge out-of-date blobs (other than keyblobs)")?;
+            } else {
+                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete v1");
+                tx.execute(
+                    "DELETE FROM persistent.blobentry
+                    WHERE NOT subcomponent_type = ?
+                    AND (
+                        id NOT IN (
+                           SELECT MAX(id) FROM persistent.blobentry
+                           WHERE NOT subcomponent_type = ?
+                           GROUP BY keyentryid, subcomponent_type
+                        ) OR keyentryid NOT IN (SELECT id FROM persistent.keyentry)
+                    );",
+                    params![SubComponentType::KEY_BLOB, SubComponentType::KEY_BLOB],
+                )
+                .context("Trying to purge superseded blobs.")?;
+            }
 
             Ok(vec![]).no_gc()
         })
@@ -1530,18 +1687,33 @@ impl KeystoreDB {
     ) -> Result<()> {
         match (blob, sc_type) {
             (Some(blob), _) => {
+                // Mark any previous blobentry(s) of the same type for the same key as superseded.
+                tx.execute(
+                    "UPDATE persistent.blobentry SET state = ?
+                    WHERE keyentryid = ? AND subcomponent_type = ?",
+                    params![BlobState::Superseded, key_id, sc_type],
+                )
+                .context(ks_err!(
+                    "Failed to mark prior {sc_type:?} blobentrys for {key_id} as superseded"
+                ))?;
+
+                // Now insert the new, un-superseded, blob.  (If this fails, the marking of
+                // old blobs as superseded will be rolled back, because we're inside a
+                // transaction.)
                 tx.execute(
                     "INSERT INTO persistent.blobentry
                      (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
                     params![sc_type, key_id, blob],
                 )
                 .context(ks_err!("Failed to insert blob."))?;
+
                 if let Some(blob_metadata) = blob_metadata {
                     let blob_id = tx
                         .query_row("SELECT MAX(id) FROM persistent.blobentry;", [], |row| {
                             row.get(0)
                         })
                         .context(ks_err!("Failed to get new blob id."))?;
+
                     blob_metadata
                         .store_in_db(blob_id, tx)
                         .context(ks_err!("Trying to store blob metadata."))?;
@@ -1907,7 +2079,7 @@ impl KeystoreDB {
         key: &KeyDescriptor,
         key_type: KeyType,
         caller_uid: u32,
-    ) -> Result<(i64, KeyDescriptor, Option<KeyPermSet>)> {
+    ) -> Result<KeyAccessInfo> {
         match key.domain {
             // Domain App or SELinux. In this case we load the key_id from
             // the keyentry database for further loading of key components.
@@ -1923,7 +2095,7 @@ impl KeystoreDB {
                 let key_id = Self::load_key_entry_id(tx, &access_key, key_type)
                     .with_context(|| format!("With key.domain = {:?}.", access_key.domain))?;
 
-                Ok((key_id, access_key, None))
+                Ok(KeyAccessInfo { key_id, descriptor: access_key, vector: None })
             }
 
             // Domain::GRANT. In this case we load the key_id and the access_vector
@@ -1949,7 +2121,11 @@ impl KeystoreDB {
                         ))
                     })
                     .context("Domain::GRANT.")?;
-                Ok((key_id, key.clone(), Some(access_vector.into())))
+                Ok(KeyAccessInfo {
+                    key_id,
+                    descriptor: key.clone(),
+                    vector: Some(access_vector.into()),
+                })
             }
 
             // Domain::KEY_ID. In this case we load the domain and namespace from the
@@ -2005,7 +2181,7 @@ impl KeystoreDB {
                 access_key.domain = domain;
                 access_key.nspace = namespace;
 
-                Ok((key_id, access_key, access_vector))
+                Ok(KeyAccessInfo { key_id, descriptor: access_key, vector: access_vector })
             }
             _ => Err(anyhow!(KsError::Rc(ResponseCode::INVALID_ARGUMENT))),
         }
@@ -2192,12 +2368,11 @@ impl KeystoreDB {
             .context(ks_err!("Failed to initialize transaction."))?;
 
         // Load the key_id and complete the access control tuple.
-        let (key_id, access_key_descriptor, access_vector) =
-            Self::load_access_tuple(&tx, key, key_type, caller_uid).context(ks_err!())?;
+        let access = Self::load_access_tuple(&tx, key, key_type, caller_uid).context(ks_err!())?;
 
         // Perform access control. It is vital that we return here if the permission is denied.
         // So do not touch that '?' at the end.
-        check_permission(&access_key_descriptor, access_vector).context(ks_err!())?;
+        check_permission(&access.descriptor, access.vector).context(ks_err!())?;
 
         // KEY ID LOCK 2/2
         // If we did not get a key id lock by now, it was because we got a key descriptor
@@ -2211,13 +2386,13 @@ impl KeystoreDB {
         // that the caller had access to the given key. But we need to make sure that the
         // key id still exists. So we have to load the key entry by key id this time.
         let (key_id_guard, tx) = match key_id_guard {
-            None => match KEY_ID_LOCK.try_get(key_id) {
+            None => match KEY_ID_LOCK.try_get(access.key_id) {
                 None => {
                     // Roll back the transaction.
                     tx.rollback().context(ks_err!("Failed to roll back transaction."))?;
 
                     // Block until we have a key id lock.
-                    let key_id_guard = KEY_ID_LOCK.get(key_id);
+                    let key_id_guard = KEY_ID_LOCK.get(access.key_id);
 
                     // Create a new transaction.
                     let tx = self
@@ -2231,7 +2406,7 @@ impl KeystoreDB {
                         // alias may have been rebound after we rolled back the transaction.
                         &KeyDescriptor {
                             domain: Domain::KEY_ID,
-                            nspace: key_id,
+                            nspace: access.key_id,
                             ..Default::default()
                         },
                         key_type,
@@ -2263,6 +2438,15 @@ impl KeystoreDB {
             .context("Trying to delete keyparameters.")?;
         tx.execute("DELETE FROM persistent.grant WHERE keyentryid = ?;", params![key_id])
             .context("Trying to delete grants.")?;
+        // The associated blobentry rows are not immediately deleted when the owning keyentry is
+        // removed, because a KeyMint `deleteKey()` invocation is needed (specifically for the
+        // `KEY_BLOB`).  Mark the affected rows with `state=Orphaned` so a subsequent garbage
+        // collection can do this.
+        tx.execute(
+            "UPDATE persistent.blobentry SET state = ? WHERE keyentryid = ?",
+            params![BlobState::Orphaned, key_id],
+        )
+        .context("Trying to mark blobentrys as superseded")?;
         Ok(updated != 0)
     }
 
@@ -2278,16 +2462,15 @@ impl KeystoreDB {
         let _wp = wd::watch("KeystoreDB::unbind_key");
 
         self.with_transaction(Immediate("TX_unbind_key"), |tx| {
-            let (key_id, access_key_descriptor, access_vector) =
-                Self::load_access_tuple(tx, key, key_type, caller_uid)
-                    .context("Trying to get access tuple.")?;
+            let access = Self::load_access_tuple(tx, key, key_type, caller_uid)
+                .context("Trying to get access tuple.")?;
 
             // Perform access control. It is vital that we return here if the permission is denied.
             // So do not touch that '?' at the end.
-            check_permission(&access_key_descriptor, access_vector)
+            check_permission(&access.descriptor, access.vector)
                 .context("While checking permission.")?;
 
-            Self::mark_unreferenced(tx, key_id)
+            Self::mark_unreferenced(tx, access.key_id)
                 .map(|need_gc| (need_gc, ()))
                 .context("Trying to mark the key unreferenced.")
         })
@@ -2547,6 +2730,8 @@ impl KeystoreDB {
     /// The key descriptors will have the domain, nspace, and alias field set.
     /// The returned list will be sorted by alias.
     /// Domain must be APP or SELINUX, the caller must make sure of that.
+    /// Number of returned values is limited to 10,000 (which is empirically roughly
+    /// what will fit in a Binder message).
     pub fn list_past_alias(
         &mut self,
         domain: Domain,
@@ -2564,7 +2749,8 @@ impl KeystoreDB {
                      AND state = ?
                      AND key_type = ?
                      {}
-                     ORDER BY alias ASC;",
+                     ORDER BY alias ASC
+                     LIMIT 10000;",
             if start_past_alias.is_some() { " AND alias > ?" } else { "" }
         );
 
@@ -2654,7 +2840,7 @@ impl KeystoreDB {
             // We could check key.domain == Domain::GRANT and fail early.
             // But even if we load the access tuple by grant here, the permission
             // check denies the attempt to create a grant by grant descriptor.
-            let (key_id, access_key_descriptor, _) =
+            let access =
                 Self::load_access_tuple(tx, key, KeyType::Client, caller_uid).context(ks_err!())?;
 
             // Perform access control. It is vital that we return here if the permission
@@ -2662,14 +2848,14 @@ impl KeystoreDB {
             // This permission check checks if the caller has the grant permission
             // for the given key and in addition to all of the permissions
             // expressed in `access_vector`.
-            check_permission(&access_key_descriptor, &access_vector)
+            check_permission(&access.descriptor, &access_vector)
                 .context(ks_err!("check_permission failed"))?;
 
             let grant_id = if let Some(grant_id) = tx
                 .query_row(
                     "SELECT id FROM persistent.grant
                 WHERE keyentryid = ? AND grantee = ?;",
-                    params![key_id, grantee_uid],
+                    params![access.key_id, grantee_uid],
                     |row| row.get(0),
                 )
                 .optional()
@@ -2688,7 +2874,7 @@ impl KeystoreDB {
                     tx.execute(
                         "INSERT INTO persistent.grant (id, grantee, keyentryid, access_vector)
                         VALUES (?, ?, ?, ?);",
-                        params![id, grantee_uid, key_id, i32::from(access_vector)],
+                        params![id, grantee_uid, access.key_id, i32::from(access_vector)],
                     )
                 })
                 .context(ks_err!())?
@@ -2713,18 +2899,17 @@ impl KeystoreDB {
         self.with_transaction(Immediate("TX_ungrant"), |tx| {
             // Load the key_id and complete the access control tuple.
             // We ignore the access vector here because grants cannot be granted.
-            let (key_id, access_key_descriptor, _) =
+            let access =
                 Self::load_access_tuple(tx, key, KeyType::Client, caller_uid).context(ks_err!())?;
 
             // Perform access control. We must return here if the permission
             // was denied. So do not touch the '?' at the end of this line.
-            check_permission(&access_key_descriptor)
-                .context(ks_err!("check_permission failed."))?;
+            check_permission(&access.descriptor).context(ks_err!("check_permission failed."))?;
 
             tx.execute(
                 "DELETE FROM persistent.grant
                 WHERE keyentryid = ? AND grantee = ?;",
-                params![key_id, grantee_uid],
+                params![access.key_id, grantee_uid],
             )
             .context("Failed to delete grant.")?;
 
diff --git a/keystore2/src/database/tests.rs b/keystore2/src/database/tests.rs
index 5f882cda..4ada6942 100644
--- a/keystore2/src/database/tests.rs
+++ b/keystore2/src/database/tests.rs
@@ -2429,6 +2429,20 @@ fn blob_count(db: &mut KeystoreDB, sc_type: SubComponentType) -> usize {
     .unwrap()
 }
 
+fn blob_count_in_state(db: &mut KeystoreDB, sc_type: SubComponentType, state: BlobState) -> usize {
+    db.with_transaction(TransactionBehavior::Deferred, |tx| {
+        tx.query_row(
+            "SELECT COUNT(*) FROM persistent.blobentry
+                     WHERE subcomponent_type = ? AND state = ?;",
+            params![sc_type, state],
+            |row| row.get(0),
+        )
+        .context(ks_err!("Failed to count number of {sc_type:?} blobs"))
+        .no_gc()
+    })
+    .unwrap()
+}
+
 #[test]
 fn test_blobentry_gc() -> Result<()> {
     let mut db = new_test_db()?;
@@ -2439,6 +2453,9 @@ fn test_blobentry_gc() -> Result<()> {
     let key_id5 = make_test_key_entry(&mut db, Domain::APP, 5, "key5", None)?.0;
 
     assert_eq!(5, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
@@ -2447,6 +2464,9 @@ fn test_blobentry_gc() -> Result<()> {
     db.set_blob(&key_guard3, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
 
     assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
@@ -2459,6 +2479,9 @@ fn test_blobentry_gc() -> Result<()> {
     .unwrap();
 
     assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
@@ -2468,6 +2491,9 @@ fn test_blobentry_gc() -> Result<()> {
     let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
     assert_eq!(4, superseded.len());
     assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
@@ -2477,6 +2503,9 @@ fn test_blobentry_gc() -> Result<()> {
     let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
     assert_eq!(0, superseded.len());
     assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
     assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
@@ -2484,12 +2513,64 @@ fn test_blobentry_gc() -> Result<()> {
     let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
     assert_eq!(0, superseded.len());
     assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
     assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
     Ok(())
 }
 
+#[test]
+fn test_upgrade_1_to_2() -> Result<()> {
+    let mut db = new_test_db()?;
+    let _key_id1 = make_test_key_entry(&mut db, Domain::APP, 1, "key1", None)?.0;
+    let key_guard2 = make_test_key_entry(&mut db, Domain::APP, 2, "key2", None)?;
+    let key_guard3 = make_test_key_entry(&mut db, Domain::APP, 3, "key3", None)?;
+    let key_id4 = make_test_key_entry(&mut db, Domain::APP, 4, "key4", None)?.0;
+    let key_id5 = make_test_key_entry(&mut db, Domain::APP, 5, "key5", None)?.0;
+
+    // Replace the keyblobs for keys 2 and 3.  The previous blobs will still exist.
+    db.set_blob(&key_guard2, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
+    db.set_blob(&key_guard3, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
+
+    // Delete keys 4 and 5.  The keyblobs aren't removed yet.
+    db.with_transaction(Immediate("TX_delete_test_keys"), |tx| {
+        KeystoreDB::mark_unreferenced(tx, key_id4)?;
+        KeystoreDB::mark_unreferenced(tx, key_id5)?;
+        Ok(()).no_gc()
+    })
+    .unwrap();
+    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // Manually downgrade the database to the v1 schema.
+    db.with_transaction(Immediate("TX_downgrade_2_to_1"), |tx| {
+        tx.execute("DROP INDEX persistent.keyentry_state_index;", params!())?;
+        tx.execute("DROP INDEX persistent.blobentry_state_index;", params!())?;
+        tx.execute("ALTER TABLE persistent.blobentry DROP COLUMN state;", params!())?;
+        Ok(()).no_gc()
+    })?;
+
+    // Run the upgrade process.
+    let version = db.with_transaction(Immediate("TX_upgrade_1_to_2"), |tx| {
+        KeystoreDB::from_1_to_2(tx).no_gc()
+    })?;
+    assert_eq!(version, 2);
+
+    // Check blobs have acquired the right `state` values.
+    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
+    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    Ok(())
+}
+
 #[test]
 fn test_load_key_descriptor() -> Result<()> {
     let mut db = new_test_db()?;
@@ -2651,6 +2732,16 @@ fn db_populate_keys(db: &mut KeystoreDB, next_keyid: usize, key_count: usize) {
 fn run_with_many_keys<F, T>(max_count: usize, test_fn: F) -> Result<()>
 where
     F: Fn(&mut KeystoreDB) -> T,
+{
+    prep_and_run_with_many_keys(max_count, |_db| (), test_fn)
+}
+
+/// Run the provided `test_fn` against the database at various increasing stages of
+/// database population.
+fn prep_and_run_with_many_keys<F, T, P>(max_count: usize, prep_fn: P, test_fn: F) -> Result<()>
+where
+    F: Fn(&mut KeystoreDB) -> T,
+    P: Fn(&mut KeystoreDB),
 {
     android_logger::init_once(
         android_logger::Config::default()
@@ -2670,6 +2761,10 @@ where
         db_populate_keys(&mut db, next_keyid, key_count);
         assert_eq!(db_key_count(&mut db), key_count);
 
+        // Perform any test-specific preparation
+        prep_fn(&mut db);
+
+        // Time execution of the test function.
         let start = std::time::Instant::now();
         let _result = test_fn(&mut db);
         println!("{key_count}, {}", start.elapsed().as_secs_f64());
@@ -2737,6 +2832,7 @@ fn test_list_keys_with_many_keys() -> Result<()> {
             let batch_size = crate::utils::estimate_safe_amount_to_return(
                 domain,
                 namespace,
+                None,
                 &keys,
                 crate::utils::RESPONSE_SIZE_LIMIT,
             );
@@ -2753,3 +2849,27 @@ fn test_list_keys_with_many_keys() -> Result<()> {
         }
     })
 }
+
+#[test]
+fn test_upgrade_1_to_2_with_many_keys() -> Result<()> {
+    prep_and_run_with_many_keys(
+        1_000_000,
+        |db: &mut KeystoreDB| {
+            // Manually downgrade the database to the v1 schema.
+            db.with_transaction(Immediate("TX_downgrade_2_to_1"), |tx| {
+                tx.execute("DROP INDEX persistent.keyentry_state_index;", params!())?;
+                tx.execute("DROP INDEX persistent.blobentry_state_index;", params!())?;
+                tx.execute("ALTER TABLE persistent.blobentry DROP COLUMN state;", params!())?;
+                Ok(()).no_gc()
+            })
+            .unwrap();
+        },
+        |db: &mut KeystoreDB| -> Result<()> {
+            // Run the upgrade process.
+            db.with_transaction(Immediate("TX_upgrade_1_to_2"), |tx| {
+                KeystoreDB::from_1_to_2(tx).no_gc()
+            })?;
+            Ok(())
+        },
+    )
+}
diff --git a/keystore2/src/database/versioning.rs b/keystore2/src/database/versioning.rs
index bc68f159..a047cf36 100644
--- a/keystore2/src/database/versioning.rs
+++ b/keystore2/src/database/versioning.rs
@@ -61,7 +61,7 @@ fn create_or_get_version(tx: &Transaction, current_version: u32) -> Result<u32>
     Ok(version)
 }
 
-fn update_version(tx: &Transaction, new_version: u32) -> Result<()> {
+pub(crate) fn update_version(tx: &Transaction, new_version: u32) -> Result<()> {
     let updated = tx
         .execute("UPDATE persistent.version SET version = ? WHERE id = 0;", params![new_version])
         .context("In update_version: Failed to update row.")?;
@@ -82,9 +82,11 @@ where
     let mut db_version = create_or_get_version(tx, current_version)
         .context("In upgrade_database: Failed to get database version.")?;
     while db_version < current_version {
+        log::info!("Current DB version={db_version}, perform upgrade");
         db_version = upgraders[db_version as usize](tx).with_context(|| {
             format!("In upgrade_database: Trying to upgrade from db version {}.", db_version)
         })?;
+        log::info!("DB upgrade successful, current DB version now={db_version}");
     }
     update_version(tx, db_version).context("In upgrade_database.")
 }
diff --git a/keystore2/src/enforcements.rs b/keystore2/src/enforcements.rs
index 70383237..d086dd27 100644
--- a/keystore2/src/enforcements.rs
+++ b/keystore2/src/enforcements.rs
@@ -545,8 +545,9 @@ impl Enforcements {
             || (user_auth_type.is_none() && !user_secure_ids.is_empty())
         {
             return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
-                "Auth required, but either auth type or secure ids \
-                 are not present."
+                "Auth required, but auth type {:?} + sids {:?} inconsistently specified",
+                user_auth_type,
+                user_secure_ids,
             ));
         }
 
@@ -582,17 +583,36 @@ impl Enforcements {
                 None => false, // not reachable due to earlier check
             })
             .ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
-            .context(ks_err!("No suitable auth token found."))?;
+            .context(ks_err!(
+                "No suitable auth token for sids {:?} type {:?} received in last {}s found.",
+                user_secure_ids,
+                user_auth_type,
+                key_time_out
+            ))?;
             let now = BootTime::now();
             let token_age =
                 now.checked_sub(&hat.time_received()).ok_or_else(Error::sys).context(ks_err!(
-                    "Overflow while computing Auth token validity. \
-                Validity cannot be established."
+                    "Overflow while computing Auth token validity. Validity cannot be established."
                 ))?;
 
             if token_age.seconds() > key_time_out {
-                return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
-                    .context(ks_err!("matching auth token is expired."));
+                return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
+                    concat!(
+                        "matching auth token (challenge={}, userId={}, authId={}, ",
+                        "authType={:#x}, timestamp={}ms) rcved={:?} ",
+                        "for sids {:?} type {:?} is expired ({}s old > timeout={}s)"
+                    ),
+                    hat.auth_token().challenge,
+                    hat.auth_token().userId,
+                    hat.auth_token().authenticatorId,
+                    hat.auth_token().authenticatorType.0,
+                    hat.auth_token().timestamp.milliSeconds,
+                    hat.time_received(),
+                    user_secure_ids,
+                    user_auth_type,
+                    token_age.seconds(),
+                    key_time_out
+                ));
             }
             let state = if requires_timestamp {
                 DeferredAuthState::TimeStampRequired(hat.auth_token().clone())
@@ -633,16 +653,12 @@ impl Enforcements {
     /// Check if the device is locked for the given user. If there's no entry yet for the user,
     /// we assume that the device is locked
     fn is_device_locked(&self, user_id: i32) -> bool {
-        // unwrap here because there's no way this mutex guard can be poisoned and
-        // because there's no way to recover, even if it is poisoned.
         let set = self.device_unlocked_set.lock().unwrap();
         !set.contains(&user_id)
     }
 
     /// Sets the device locked status for the user. This method is called externally.
     pub fn set_device_locked(&self, user_id: i32, device_locked_status: bool) {
-        // unwrap here because there's no way this mutex guard can be poisoned and
-        // because there's no way to recover, even if it is poisoned.
         let mut set = self.device_unlocked_set.lock().unwrap();
         if device_locked_status {
             set.remove(&user_id);
diff --git a/keystore2/src/error.rs b/keystore2/src/error.rs
index 5e80266e..d57ba0c1 100644
--- a/keystore2/src/error.rs
+++ b/keystore2/src/error.rs
@@ -34,6 +34,7 @@ use android_system_keystore2::binder::{
     ExceptionCode, Result as BinderResult, Status as BinderStatus, StatusCode,
 };
 use keystore2_selinux as selinux;
+use postprocessor_client::Error as PostProcessorError;
 use rkpd_client::Error as RkpdError;
 use std::cmp::PartialEq;
 use std::ffi::CString;
@@ -103,6 +104,14 @@ impl From<RkpdError> for Error {
     }
 }
 
+impl From<PostProcessorError> for Error {
+    fn from(e: PostProcessorError) -> Self {
+        match e {
+            PostProcessorError(s) => Error::BinderTransaction(s),
+        }
+    }
+}
+
 /// Maps an `rkpd_client::Error` that is wrapped with an `anyhow::Error` to a keystore2 `Error`.
 pub fn wrapped_rkpd_error_to_ks_error(e: &anyhow::Error) -> Error {
     match e.downcast_ref::<RkpdError>() {
diff --git a/keystore2/src/globals.rs b/keystore2/src/globals.rs
index 39d6f9c1..3b9c631b 100644
--- a/keystore2/src/globals.rs
+++ b/keystore2/src/globals.rs
@@ -165,6 +165,8 @@ pub static LEGACY_IMPORTER: LazyLock<Arc<LegacyImporter>> =
     LazyLock::new(|| Arc::new(LegacyImporter::new(Arc::new(Default::default()))));
 /// Background thread which handles logging via statsd and logd
 pub static LOGS_HANDLER: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);
+/// DER-encoded module information returned by `getSupplementaryAttestationInfo(Tag.MODULE_HASH)`.
+pub static ENCODED_MODULE_INFO: RwLock<Option<Vec<u8>>> = RwLock::new(None);
 
 static GC: LazyLock<Arc<Gc>> = LazyLock::new(|| {
     Arc::new(Gc::new_init_with(ASYNC_TASK.clone(), || {
@@ -271,17 +273,8 @@ fn connect_keymint(
     // If the KeyMint device is back-level, use a wrapper that intercepts and
     // emulates things that are not supported by the hardware.
     let keymint = match hal_version {
-        Some(300) => {
-            // Current KeyMint version: use as-is as v3 Keymint is current version
-            log::info!(
-                "KeyMint device is current version ({:?}) for security level: {:?}",
-                hal_version,
-                security_level
-            );
-            keymint
-        }
-        Some(200) => {
-            // Previous KeyMint version: use as-is as we don't have any software emulation of v3-specific KeyMint features.
+        Some(400) | Some(300) | Some(200) => {
+            // KeyMint v2+: use as-is (we don't have any software emulation of v3 or v4-specific KeyMint features).
             log::info!(
                 "KeyMint device is current version ({:?}) for security level: {:?}",
                 hal_version,
diff --git a/keystore2/src/km_compat.rs b/keystore2/src/km_compat.rs
index 5e3bdfa7..95e92943 100644
--- a/keystore2/src/km_compat.rs
+++ b/keystore2/src/km_compat.rs
@@ -214,6 +214,12 @@ where
     fn sendRootOfTrust(&self, root_of_trust: &[u8]) -> binder::Result<()> {
         self.real.sendRootOfTrust(root_of_trust)
     }
+    fn setAdditionalAttestationInfo(
+        &self,
+        additional_attestation_info: &[KeyParameter],
+    ) -> binder::Result<()> {
+        self.real.setAdditionalAttestationInfo(additional_attestation_info)
+    }
 
     // For methods that emit keyblobs, check whether the underlying real device
     // supports the relevant parameters, and forward to the appropriate device.
diff --git a/keystore2/src/km_compat/km_compat.cpp b/keystore2/src/km_compat/km_compat.cpp
index e9ff1fff..7a6ef4ae 100644
--- a/keystore2/src/km_compat/km_compat.cpp
+++ b/keystore2/src/km_compat/km_compat.cpp
@@ -839,6 +839,11 @@ ScopedAStatus KeyMintDevice::sendRootOfTrust(const std::vector<uint8_t>& /* root
     return convertErrorCode(KMV1::ErrorCode::UNIMPLEMENTED);
 }
 
+ScopedAStatus KeyMintDevice::setAdditionalAttestationInfo(
+    const std::vector<KeyParameter>& /* additionalAttestationInfo */) {
+    return convertErrorCode(KMV1::ErrorCode::UNIMPLEMENTED);
+}
+
 ScopedAStatus KeyMintOperation::updateAad(const std::vector<uint8_t>& input,
                                           const std::optional<HardwareAuthToken>& optAuthToken,
                                           const std::optional<TimeStampToken>& optTimeStampToken) {
diff --git a/keystore2/src/km_compat/km_compat.h b/keystore2/src/km_compat/km_compat.h
index c4bcdaa9..71f7fbef 100644
--- a/keystore2/src/km_compat/km_compat.h
+++ b/keystore2/src/km_compat/km_compat.h
@@ -147,6 +147,9 @@ class KeyMintDevice : public aidl::android::hardware::security::keymint::BnKeyMi
                                  std::vector<uint8_t>* rootOfTrust);
     ScopedAStatus sendRootOfTrust(const std::vector<uint8_t>& rootOfTrust);
 
+    ScopedAStatus
+    setAdditionalAttestationInfo(const std::vector<KeyParameter>& additionalAttestationInfo);
+
     // These are public to allow testing code to use them directly.
     // This class should not be used publicly anyway.
     std::variant<std::vector<Certificate>, KMV1_ErrorCode>
diff --git a/keystore2/src/km_compat/km_compat_type_conversion.h b/keystore2/src/km_compat/km_compat_type_conversion.h
index 5db7e3d8..d6a2dcc4 100644
--- a/keystore2/src/km_compat/km_compat_type_conversion.h
+++ b/keystore2/src/km_compat/km_compat_type_conversion.h
@@ -750,8 +750,12 @@ static V4_0::KeyParameter convertKeyParameterToLegacy(const KMV1::KeyParameter&
     case KMV1::Tag::CERTIFICATE_SUBJECT:
     case KMV1::Tag::CERTIFICATE_NOT_BEFORE:
     case KMV1::Tag::CERTIFICATE_NOT_AFTER:
+        // These tags do not exist in KM < KeyMint 1.
+        break;
     case KMV1::Tag::ATTESTATION_ID_SECOND_IMEI:
-        // These tags do not exist in KM < KeyMint 1.0.
+        // This tag doesn't exist in KM < KeyMint 3.
+    case KMV1::Tag::MODULE_HASH:
+        // This tag doesn't exist in KM < KeyMint 4.
         break;
     case KMV1::Tag::MAX_BOOT_LEVEL:
         // Does not exist in API level 30 or below.
diff --git a/keystore2/src/legacy_importer.rs b/keystore2/src/legacy_importer.rs
index 24f32637..0d8dc4a9 100644
--- a/keystore2/src/legacy_importer.rs
+++ b/keystore2/src/legacy_importer.rs
@@ -786,7 +786,7 @@ impl LegacyImporterState {
                 .context(ks_err!("Trying to load legacy blob."))?;
 
             // Determine if the key needs special handling to be deleted.
-            let (need_gc, is_super_encrypted) = km_blob_params
+            let (need_gc, is_super_encrypted, is_de_critical) = km_blob_params
                 .as_ref()
                 .map(|(blob, params)| {
                     let params = match params {
@@ -798,13 +798,18 @@ impl LegacyImporterState {
                             KeyParameterValue::RollbackResistance == *kp.key_parameter_value()
                         }),
                         blob.is_encrypted(),
+                        blob.is_critical_to_device_encryption(),
                     )
                 })
-                .unwrap_or((false, false));
+                .unwrap_or((false, false, false));
 
             if keep_non_super_encrypted_keys && !is_super_encrypted {
                 continue;
             }
+            if uid == rustutils::users::AID_SYSTEM && is_de_critical {
+                log::info!("skip deletion of system key '{alias}' which is DE-critical");
+                continue;
+            }
 
             if need_gc {
                 let mark_deleted = match km_blob_params
diff --git a/keystore2/src/maintenance.rs b/keystore2/src/maintenance.rs
index 4c895aed..1a5045ec 100644
--- a/keystore2/src/maintenance.rs
+++ b/keystore2/src/maintenance.rs
@@ -19,7 +19,7 @@ use crate::error::into_logged_binder;
 use crate::error::map_km_error;
 use crate::error::Error;
 use crate::globals::get_keymint_device;
-use crate::globals::{DB, LEGACY_IMPORTER, SUPER_KEY};
+use crate::globals::{DB, LEGACY_IMPORTER, SUPER_KEY, ENCODED_MODULE_INFO};
 use crate::ks_err;
 use crate::permission::{KeyPerm, KeystorePerm};
 use crate::super_key::SuperKeyManager;
@@ -28,7 +28,7 @@ use crate::utils::{
     check_keystore_permission, uid_to_android_user, watchdog as wd,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
+    ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
 };
 use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::{
     BnKeystoreMaintenance, IKeystoreMaintenance,
@@ -41,12 +41,37 @@ use android_security_metrics::aidl::android::security::metrics::{
 };
 use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
 use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
-use anyhow::{Context, Result};
+use anyhow::{anyhow, Context, Result};
+use bssl_crypto::digest;
+use der::{DerOrd, Encode, asn1::OctetString, asn1::SetOfVec, Sequence};
 use keystore2_crypto::Password;
+use std::cmp::Ordering;
 
 /// Reexport Domain for the benefit of DeleteListener
 pub use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;
 
+/// Version number of KeyMint V4.
+pub const KEYMINT_V4: i32 = 400;
+
+/// Module information structure for DER-encoding.
+#[derive(Sequence, Debug)]
+struct ModuleInfo {
+    name: OctetString,
+    version: i32,
+}
+
+impl DerOrd for ModuleInfo {
+    // DER mandates "encodings of the component values of a set-of value shall appear in ascending
+    // order". `der_cmp` serves as a proxy for determining that ordering (though why the `der` crate
+    // requires this is unclear). Essentially, we just need to compare the `name` lengths, and then
+    // if those are equal, the `name`s themselves. (No need to consider `version`s since there can't
+    // be more than one `ModuleInfo` with the same `name` in the set-of `ModuleInfo`s.) We rely on
+    // `OctetString`'s `der_cmp` to do the aforementioned comparison.
+    fn der_cmp(&self, other: &Self) -> std::result::Result<Ordering, der::Error> {
+        self.name.der_cmp(&other.name)
+    }
+}
+
 /// The Maintenance module takes a delete listener argument which observes user and namespace
 /// deletion events.
 pub trait DeleteListener {
@@ -139,19 +164,35 @@ impl Maintenance {
             .context(ks_err!("While invoking the delete listener."))
     }
 
-    fn call_with_watchdog<F>(sec_level: SecurityLevel, name: &'static str, op: &F) -> Result<()>
+    fn call_with_watchdog<F>(
+        sec_level: SecurityLevel,
+        name: &'static str,
+        op: &F,
+        min_version: Option<i32>,
+    ) -> Result<()>
     where
         F: Fn(Strong<dyn IKeyMintDevice>) -> binder::Result<()>,
     {
-        let (km_dev, _, _) =
+        let (km_dev, hw_info, _) =
             get_keymint_device(&sec_level).context(ks_err!("getting keymint device"))?;
 
+        if let Some(min_version) = min_version {
+            if hw_info.versionNumber < min_version {
+                log::info!("skipping {name} for {sec_level:?} since its keymint version {} is less than the minimum required version {min_version}", hw_info.versionNumber);
+                return Ok(());
+            }
+        }
+
         let _wp = wd::watch_millis_with("Maintenance::call_with_watchdog", 500, (sec_level, name));
         map_km_error(op(km_dev)).with_context(|| ks_err!("calling {}", name))?;
         Ok(())
     }
 
-    fn call_on_all_security_levels<F>(name: &'static str, op: F) -> Result<()>
+    fn call_on_all_security_levels<F>(
+        name: &'static str,
+        op: F,
+        min_version: Option<i32>,
+    ) -> Result<()>
     where
         F: Fn(Strong<dyn IKeyMintDevice>) -> binder::Result<()>,
     {
@@ -160,7 +201,7 @@ impl Maintenance {
             (SecurityLevel::STRONGBOX, "STRONGBOX"),
         ];
         sec_levels.iter().try_fold((), |_result, (sec_level, sec_level_string)| {
-            let curr_result = Maintenance::call_with_watchdog(*sec_level, name, &op);
+            let curr_result = Maintenance::call_with_watchdog(*sec_level, name, &op, min_version);
             match curr_result {
                 Ok(()) => log::info!(
                     "Call to {} succeeded for security level {}.",
@@ -197,7 +238,8 @@ impl Maintenance {
         {
             log::error!("SUPER_KEY.set_up_boot_level_cache failed:\n{:?}\n:(", e);
         }
-        Maintenance::call_on_all_security_levels("earlyBootEnded", |dev| dev.earlyBootEnded())
+
+        Maintenance::call_on_all_security_levels("earlyBootEnded", |dev| dev.earlyBootEnded(), None)
     }
 
     fn migrate_key_namespace(source: &KeyDescriptor, destination: &KeyDescriptor) -> Result<()> {
@@ -253,7 +295,7 @@ impl Maintenance {
             .context(ks_err!("Checking permission"))?;
         log::info!("In delete_all_keys.");
 
-        Maintenance::call_on_all_security_levels("deleteAllKeys", |dev| dev.deleteAllKeys())
+        Maintenance::call_on_all_security_levels("deleteAllKeys", |dev| dev.deleteAllKeys(), None)
     }
 
     fn get_app_uids_affected_by_sid(
@@ -320,6 +362,44 @@ impl Maintenance {
 
         Ok(())
     }
+
+    #[allow(dead_code)]
+    fn set_module_info(module_info: Vec<ModuleInfo>) -> Result<()> {
+        let encoding = Self::encode_module_info(module_info)
+            .map_err(|e| anyhow!({ e }))
+            .context(ks_err!("Failed to encode module_info"))?;
+        let hash = digest::Sha256::hash(&encoding).to_vec();
+
+        {
+            let mut saved = ENCODED_MODULE_INFO.write().unwrap();
+            if let Some(saved_encoding) = &*saved {
+                if *saved_encoding == encoding {
+                    log::warn!(
+                        "Module info already set, ignoring repeated attempt to set same info."
+                    );
+                    return Ok(());
+                }
+                return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(ks_err!(
+                    "Failed to set module info as it is already set to a different value."
+                ));
+            }
+            *saved = Some(encoding);
+        }
+
+        let kps =
+            vec![KeyParameter { tag: Tag::MODULE_HASH, value: KeyParameterValue::Blob(hash) }];
+
+        Maintenance::call_on_all_security_levels(
+            "setAdditionalAttestationInfo",
+            |dev| dev.setAdditionalAttestationInfo(&kps),
+            Some(KEYMINT_V4),
+        )
+    }
+
+    #[allow(dead_code)]
+    fn encode_module_info(module_info: Vec<ModuleInfo>) -> Result<Vec<u8>, der::Error> {
+        SetOfVec::<ModuleInfo>::from_iter(module_info.into_iter())?.to_der()
+    }
 }
 
 impl Interface for Maintenance {
diff --git a/keystore2/src/metrics.rs b/keystore2/src/metrics.rs
index 47577393..b8848093 100644
--- a/keystore2/src/metrics.rs
+++ b/keystore2/src/metrics.rs
@@ -51,7 +51,7 @@ impl Interface for Metrics {}
 
 impl IKeystoreMetrics for Metrics {
     fn pullMetrics(&self, atom_id: AtomID) -> BinderResult<Vec<KeystoreAtom>> {
-        let _wp = wd::watch("IKeystoreMetrics::pullMetrics");
+        let _wp = wd::watch_millis_with("IKeystoreMetrics::pullMetrics", 500, atom_id);
         self.pull_metrics(atom_id).map_err(into_logged_binder)
     }
 }
diff --git a/keystore2/src/metrics_store.rs b/keystore2/src/metrics_store.rs
index 7149d128..fd1f9b54 100644
--- a/keystore2/src/metrics_store.rs
+++ b/keystore2/src/metrics_store.rs
@@ -22,6 +22,7 @@ use crate::globals::DB;
 use crate::key_parameter::KeyParameterValue as KsKeyParamValue;
 use crate::ks_err;
 use crate::operation::Outcome;
+use crate::utils::watchdog as wd;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
     HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
@@ -104,11 +105,13 @@ impl MetricsStore {
         // StorageStats is an original pulled atom (i.e. not a pushed atom converted to a
         // pulled atom). Therefore, it is handled separately.
         if AtomID::STORAGE_STATS == atom_id {
+            let _wp = wd::watch("MetricsStore::get_atoms calling pull_storage_stats");
             return pull_storage_stats();
         }
 
         // Process keystore crash stats.
         if AtomID::CRASH_STATS == atom_id {
+            let _wp = wd::watch("MetricsStore::get_atoms calling read_keystore_crash_count");
             return match read_keystore_crash_count()? {
                 Some(count) => Ok(vec![KeystoreAtom {
                     payload: KeystoreAtomPayload::CrashStats(CrashStats {
@@ -120,8 +123,6 @@ impl MetricsStore {
             };
         }
 
-        // It is safe to call unwrap here since the lock can not be poisoned based on its usage
-        // in this module and the lock is not acquired in the same thread before.
         let metrics_store_guard = self.metrics_store.lock().unwrap();
         metrics_store_guard.get(&atom_id).map_or(Ok(Vec::<KeystoreAtom>::new()), |atom_count_map| {
             Ok(atom_count_map
@@ -133,8 +134,6 @@ impl MetricsStore {
 
     /// Insert an atom object to the metrics_store indexed by the atom ID.
     fn insert_atom(&self, atom_id: AtomID, atom: KeystoreAtomPayload) {
-        // It is ok to unwrap here since the mutex cannot be poisoned according to the way it is
-        // used in this module. And the lock is not acquired by this thread before.
         let mut metrics_store_guard = self.metrics_store.lock().unwrap();
         let atom_count_map = metrics_store_guard.entry(atom_id).or_default();
         if atom_count_map.len() < MetricsStore::SINGLE_ATOM_STORE_MAX_SIZE {
diff --git a/keystore2/src/operation.rs b/keystore2/src/operation.rs
index 9ae8ccfc..c11c1f43 100644
--- a/keystore2/src/operation.rs
+++ b/keystore2/src/operation.rs
@@ -308,9 +308,8 @@ impl Operation {
         locked_outcome: &mut Outcome,
         err: Result<T, Error>,
     ) -> Result<T, Error> {
-        match &err {
-            Err(e) => *locked_outcome = Outcome::ErrorCode(error_to_serialized_error(e)),
-            Ok(_) => (),
+        if let Err(e) = &err {
+            *locked_outcome = Outcome::ErrorCode(error_to_serialized_error(e))
         }
         err
     }
diff --git a/keystore2/src/permission.rs b/keystore2/src/permission.rs
index 7bf17b59..023774f1 100644
--- a/keystore2/src/permission.rs
+++ b/keystore2/src/permission.rs
@@ -282,12 +282,19 @@ pub fn check_keystore_permission(caller_ctx: &CStr, perm: KeystorePerm) -> anyho
 ///                      SELinux keystore key backend, and the result is used
 ///                      as target context.
 pub fn check_grant_permission(
+    caller_uid: u32,
     caller_ctx: &CStr,
     access_vec: KeyPermSet,
     key: &KeyDescriptor,
 ) -> anyhow::Result<()> {
     let target_context = match key.domain {
-        Domain::APP => getcon().context("check_grant_permission: getcon failed.")?,
+        Domain::APP => {
+            if caller_uid as i64 != key.nspace {
+                return Err(selinux::Error::perm())
+                    .context("Trying to access key without ownership.");
+            }
+            getcon().context("check_grant_permission: getcon failed.")?
+        }
         Domain::SELINUX => lookup_keystore2_key_context(key.nspace)
             .context("check_grant_permission: Domain::SELINUX: Failed to lookup namespace.")?,
         _ => return Err(KsError::sys()).context(format!("Cannot grant {:?}.", key.domain)),
diff --git a/keystore2/src/permission/tests.rs b/keystore2/src/permission/tests.rs
index f555c12c..68c9b746 100644
--- a/keystore2/src/permission/tests.rs
+++ b/keystore2/src/permission/tests.rs
@@ -134,15 +134,12 @@ fn check_keystore_permission_test() -> Result<()> {
 #[test]
 fn check_grant_permission_app() -> Result<()> {
     let system_server_ctx = Context::new("u:r:system_server:s0")?;
-    let shell_ctx = Context::new("u:r:shell:s0")?;
     let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
-    check_grant_permission(&system_server_ctx, SYSTEM_SERVER_PERMISSIONS_NO_GRANT, &key)
+    check_grant_permission(0, &system_server_ctx, SYSTEM_SERVER_PERMISSIONS_NO_GRANT, &key)
         .expect("Grant permission check failed.");
 
     // attempts to grant the grant permission must always fail even when privileged.
-    assert_perm_failed!(check_grant_permission(&system_server_ctx, KeyPerm::Grant.into(), &key));
-    // unprivileged grant attempts always fail. shell does not have the grant permission.
-    assert_perm_failed!(check_grant_permission(&shell_ctx, UNPRIV_PERMS, &key));
+    assert_perm_failed!(check_grant_permission(0, &system_server_ctx, KeyPerm::Grant.into(), &key));
     Ok(())
 }
 
@@ -156,12 +153,12 @@ fn check_grant_permission_selinux() -> Result<()> {
         blob: None,
     };
     if is_su {
-        assert!(check_grant_permission(&sctx, NOT_GRANT_PERMS, &key).is_ok());
+        assert!(check_grant_permission(0, &sctx, NOT_GRANT_PERMS, &key).is_ok());
         // attempts to grant the grant permission must always fail even when privileged.
-        assert_perm_failed!(check_grant_permission(&sctx, KeyPerm::Grant.into(), &key));
+        assert_perm_failed!(check_grant_permission(0, &sctx, KeyPerm::Grant.into(), &key));
     } else {
         // unprivileged grant attempts always fail. shell does not have the grant permission.
-        assert_perm_failed!(check_grant_permission(&sctx, UNPRIV_PERMS, &key));
+        assert_perm_failed!(check_grant_permission(0, &sctx, UNPRIV_PERMS, &key));
     }
     Ok(())
 }
@@ -209,7 +206,6 @@ fn check_key_permission_domain_app() -> Result<()> {
     assert!(check_key_permission(0, &shell_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
     assert!(check_key_permission(0, &shell_ctx, KeyPerm::Rebind, &key, &None).is_ok());
     assert!(check_key_permission(0, &shell_ctx, KeyPerm::Update, &key, &None).is_ok());
-    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::Grant, &key, &None));
     assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ReqForcedOp, &key, &None));
     assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ManageBlob, &key, &None));
     assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::UseDevId, &key, &None));
diff --git a/keystore2/src/remote_provisioning.rs b/keystore2/src/remote_provisioning.rs
index cda93b3f..2bdafd47 100644
--- a/keystore2/src/remote_provisioning.rs
+++ b/keystore2/src/remote_provisioning.rs
@@ -20,9 +20,8 @@
 //! DB.
 
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Algorithm::Algorithm, AttestationKey::AttestationKey, Certificate::Certificate,
-    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel,
-    Tag::Tag,
+    Algorithm::Algorithm, AttestationKey::AttestationKey, KeyParameter::KeyParameter,
+    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
 };
 use android_security_rkp_aidl::aidl::android::security::rkp::RemotelyProvisionedKey::RemotelyProvisionedKey;
 use android_system_keystore2::aidl::android::system::keystore2::{
@@ -85,7 +84,7 @@ impl RemProvState {
         key: &KeyDescriptor,
         caller_uid: u32,
         params: &[KeyParameter],
-    ) -> Result<Option<(AttestationKey, Certificate)>> {
+    ) -> Result<Option<(AttestationKey, Vec<u8>)>> {
         if !self.is_asymmetric_key(params) || key.domain != Domain::APP {
             Ok(None)
         } else {
@@ -106,13 +105,14 @@ impl RemProvState {
                     AttestationKey {
                         keyBlob: rkpd_key.keyBlob,
                         attestKeyParams: vec![],
-                        // Batch certificate is at the beginning of the certificate chain.
+                        // Batch certificate is at the beginning of the concatenated certificate
+                        // chain, and the helper function only looks at the first cert.
                         issuerSubjectName: parse_subject_from_certificate(
                             &rkpd_key.encodedCertChain,
                         )
                         .context(ks_err!("Failed to parse subject."))?,
                     },
-                    Certificate { encodedCertificate: rkpd_key.encodedCertChain },
+                    rkpd_key.encodedCertChain,
                 ))),
             }
         }
diff --git a/keystore2/src/security_level.rs b/keystore2/src/security_level.rs
index bd20afb7..233f2ae9 100644
--- a/keystore2/src/security_level.rs
+++ b/keystore2/src/security_level.rs
@@ -49,7 +49,7 @@ use crate::{
 };
 use crate::{globals::get_keymint_device, id_rotation::IdRotationState};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Algorithm::Algorithm, AttestationKey::AttestationKey,
+    Algorithm::Algorithm, AttestationKey::AttestationKey, Certificate::Certificate,
     HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
     KeyCreationResult::KeyCreationResult, KeyFormat::KeyFormat,
     KeyMintHardwareInfo::KeyMintHardwareInfo, KeyParameter::KeyParameter,
@@ -64,7 +64,9 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     KeyMetadata::KeyMetadata, KeyParameters::KeyParameters, ResponseCode::ResponseCode,
 };
 use anyhow::{anyhow, Context, Result};
+use postprocessor_client::process_certificate_chain;
 use rkpd_client::store_rkpd_attestation_key;
+use rustutils::system_properties::read_bool;
 use std::convert::TryInto;
 use std::time::SystemTime;
 
@@ -131,11 +133,21 @@ impl KeystoreSecurityLevel {
             certificateChain: mut certificate_chain,
         } = creation_result;
 
+        // Unify the possible contents of the certificate chain.  The first entry in the `Vec` is
+        // always the leaf certificate (if present), but the rest of the chain may be present as
+        // either:
+        //  - `certificate_chain[1..n]`: each entry holds a single certificate, as returned by
+        //    KeyMint, or
+        //  - `certificate[1`]: a single `Certificate` from RKP that actually (and confusingly)
+        //    holds the DER-encoded certs of the chain concatenated together.
         let mut cert_info: CertificateInfo = CertificateInfo::new(
+            // Leaf is always a single cert in the first entry, if present.
             match certificate_chain.len() {
                 0 => None,
                 _ => Some(certificate_chain.remove(0).encodedCertificate),
             },
+            // Remainder may be either `[1..n]` individual certs, or just `[1]` holding a
+            // concatenated chain. Convert the former to the latter.
             match certificate_chain.len() {
                 0 => None,
                 _ => Some(
@@ -622,7 +634,30 @@ impl KeystoreSecurityLevel {
                     log_security_safe_params(&params)
                 ))
                 .map(|(mut result, _)| {
-                    result.certificateChain.push(attestation_certs);
+                    if read_bool("remote_provisioning.use_cert_processor", false).unwrap_or(false) {
+                        let _wp = self.watch_millis(
+                            concat!(
+                                "KeystoreSecurityLevel::generate_key (RkpdProvisioned): ",
+                                "calling KeystorePostProcessor::process_certificate_chain",
+                            ),
+                            1000, // Post processing may take a little while due to network call.
+                        );
+                        // process_certificate_chain would either replace the certificate chain if
+                        // post-processing is successful or it would fallback to the original chain
+                        // on failure. In either case, we should get back the certificate chain
+                        // that is fit for storing with the newly generated key.
+                        result.certificateChain =
+                            process_certificate_chain(result.certificateChain, attestation_certs);
+                    } else {
+                        // The `certificateChain` in a `KeyCreationResult` should normally have one
+                        // `Certificate` for each certificate in the chain. To avoid having to
+                        // unnecessarily parse the RKP chain (which is concatenated DER-encoded
+                        // certs), stuff the whole concatenated chain into a single `Certificate`.
+                        // This is untangled by `store_new_key()`.
+                        result
+                            .certificateChain
+                            .push(Certificate { encodedCertificate: attestation_certs });
+                    }
                     result
                 })
             }
diff --git a/keystore2/src/service.rs b/keystore2/src/service.rs
index 95e17445..85ac7bc4 100644
--- a/keystore2/src/service.rs
+++ b/keystore2/src/service.rs
@@ -27,7 +27,10 @@ use crate::utils::{
 };
 use crate::{
     database::Uuid,
-    globals::{create_thread_local_db, DB, LEGACY_BLOB_LOADER, LEGACY_IMPORTER, SUPER_KEY},
+    globals::{
+        create_thread_local_db, DB, ENCODED_MODULE_INFO, LEGACY_BLOB_LOADER, LEGACY_IMPORTER,
+        SUPER_KEY,
+    },
 };
 use crate::{database::KEYSTORE_UUID, permission};
 use crate::{
@@ -39,6 +42,7 @@ use crate::{
     id_rotation::IdRotationState,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::Tag::Tag;
 use android_hardware_security_keymint::binder::{BinderFeatures, Strong, ThreadState};
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
@@ -314,6 +318,20 @@ impl KeystoreService {
         DB.with(|db| count_key_entries(&mut db.borrow_mut(), k.domain, k.nspace))
     }
 
+    fn get_supplementary_attestation_info(&self, tag: Tag) -> Result<Vec<u8>> {
+        match tag {
+            Tag::MODULE_HASH => {
+                let info = ENCODED_MODULE_INFO.read().unwrap();
+                (*info)
+                    .clone()
+                    .ok_or(Error::Rc(ResponseCode::INFO_NOT_AVAILABLE))
+                    .context(ks_err!("Module info not received."))
+            }
+            _ => Err(Error::Rc(ResponseCode::INVALID_ARGUMENT))
+                .context(ks_err!("Tag {tag:?} not supported for getSupplementaryAttestationInfo.")),
+        }
+    }
+
     fn list_entries_batched(
         &self,
         domain: Domain,
@@ -441,4 +459,14 @@ impl IKeystoreService for KeystoreService {
         let _wp = wd::watch("IKeystoreService::getNumberOfEntries");
         self.count_num_entries(domain, namespace).map_err(into_logged_binder)
     }
+
+    fn getSupplementaryAttestationInfo(&self, tag: Tag) -> binder::Result<Vec<u8>> {
+        if keystore2_flags::attest_modules() {
+            let _wp = wd::watch("IKeystoreService::getSupplementaryAttestationInfo");
+            self.get_supplementary_attestation_info(tag).map_err(into_logged_binder)
+        } else {
+            log::error!("attest_modules flag is not toggled");
+            Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
+        }
+    }
 }
diff --git a/keystore2/src/utils.rs b/keystore2/src/utils.rs
index 2b69d1ef..35290df5 100644
--- a/keystore2/src/utils.rs
+++ b/keystore2/src/utils.rs
@@ -80,6 +80,7 @@ pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
 pub fn check_grant_permission(access_vec: KeyPermSet, key: &KeyDescriptor) -> anyhow::Result<()> {
     ThreadState::with_calling_sid(|calling_sid| {
         permission::check_grant_permission(
+            ThreadState::get_calling_uid(),
             calling_sid
                 .ok_or_else(Error::sys)
                 .context(ks_err!("Cannot check permission without calling_sid."))?,
@@ -540,39 +541,40 @@ fn merge_and_filter_key_entry_lists(
 pub(crate) fn estimate_safe_amount_to_return(
     domain: Domain,
     namespace: i64,
+    start_past_alias: Option<&str>,
     key_descriptors: &[KeyDescriptor],
     response_size_limit: usize,
 ) -> usize {
-    let mut items_to_return = 0;
-    let mut returned_bytes: usize = 0;
+    let mut count = 0;
+    let mut bytes: usize = 0;
     // Estimate the transaction size to avoid returning more items than what
     // could fit in a binder transaction.
     for kd in key_descriptors.iter() {
         // 4 bytes for the Domain enum
         // 8 bytes for the Namespace long.
-        returned_bytes += 4 + 8;
+        bytes += 4 + 8;
         // Size of the alias string. Includes 4 bytes for length encoding.
         if let Some(alias) = &kd.alias {
-            returned_bytes += 4 + alias.len();
+            bytes += 4 + alias.len();
         }
         // Size of the blob. Includes 4 bytes for length encoding.
         if let Some(blob) = &kd.blob {
-            returned_bytes += 4 + blob.len();
+            bytes += 4 + blob.len();
         }
         // The binder transaction size limit is 1M. Empirical measurements show
         // that the binder overhead is 60% (to be confirmed). So break after
         // 350KB and return a partial list.
-        if returned_bytes > response_size_limit {
+        if bytes > response_size_limit {
             log::warn!(
-                "{domain:?}:{namespace}: Key descriptors list ({} items) may exceed binder \
-                       size, returning {items_to_return} items est {returned_bytes} bytes.",
+                "{domain:?}:{namespace}: Key descriptors list ({} items after {start_past_alias:?}) \
+                 may exceed binder size, returning {count} items est. {bytes} bytes",
                 key_descriptors.len(),
             );
             break;
         }
-        items_to_return += 1;
+        count += 1;
     }
-    items_to_return
+    count
 }
 
 /// Estimate for maximum size of a Binder response in bytes.
@@ -601,8 +603,13 @@ pub fn list_key_entries(
         start_past_alias,
     );
 
-    let safe_amount_to_return =
-        estimate_safe_amount_to_return(domain, namespace, &merged_key_entries, RESPONSE_SIZE_LIMIT);
+    let safe_amount_to_return = estimate_safe_amount_to_return(
+        domain,
+        namespace,
+        start_past_alias,
+        &merged_key_entries,
+        RESPONSE_SIZE_LIMIT,
+    );
     Ok(merged_key_entries[..safe_amount_to_return].to_vec())
 }
 
diff --git a/keystore2/src/utils/tests.rs b/keystore2/src/utils/tests.rs
index 618ea472..e514b2a8 100644
--- a/keystore2/src/utils/tests.rs
+++ b/keystore2/src/utils/tests.rs
@@ -53,9 +53,9 @@ fn test_safe_amount_to_return() -> Result<()> {
     let key_aliases = vec!["key1", "key2", "key3"];
     let key_descriptors = create_key_descriptors_from_aliases(&key_aliases);
 
-    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, &key_descriptors, 20), 1);
-    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, &key_descriptors, 50), 2);
-    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, &key_descriptors, 100), 3);
+    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, None, &key_descriptors, 20), 1);
+    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, None, &key_descriptors, 50), 2);
+    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, None, &key_descriptors, 100), 3);
     Ok(())
 }
 
diff --git a/keystore2/test_utils/Android.bp b/keystore2/test_utils/Android.bp
index d0b55401..57da27fc 100644
--- a/keystore2/test_utils/Android.bp
+++ b/keystore2/test_utils/Android.bp
@@ -62,8 +62,8 @@ rust_library {
     static_libs: [
         // Also include static_libs for the NDK variants so that they are available
         // for dependencies.
-        "android.system.keystore2-V4-ndk",
-        "android.hardware.security.keymint-V3-ndk",
+        "android.system.keystore2-V5-ndk",
+        "android.hardware.security.keymint-V4-ndk",
     ],
 }
 
diff --git a/keystore2/test_utils/authorizations.rs b/keystore2/test_utils/authorizations.rs
index a96d9946..d3d6fc4a 100644
--- a/keystore2/test_utils/authorizations.rs
+++ b/keystore2/test_utils/authorizations.rs
@@ -18,8 +18,9 @@ use std::ops::Deref;
 
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
-    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
-    PaddingMode::PaddingMode, Tag::Tag,
+    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyParameter::KeyParameter,
+    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
+    Tag::Tag,
 };
 
 /// Helper struct to create set of Authorizations.
@@ -369,6 +370,33 @@ impl AuthSetBuilder {
         });
         self
     }
+
+    /// Set user secure ID.
+    pub fn user_secure_id(mut self, sid: i64) -> Self {
+        self.0.push(KeyParameter {
+            tag: Tag::USER_SECURE_ID,
+            value: KeyParameterValue::LongInteger(sid),
+        });
+        self
+    }
+
+    /// Set user auth type.
+    pub fn user_auth_type(mut self, auth_type: HardwareAuthenticatorType) -> Self {
+        self.0.push(KeyParameter {
+            tag: Tag::USER_AUTH_TYPE,
+            value: KeyParameterValue::HardwareAuthenticatorType(auth_type),
+        });
+        self
+    }
+
+    /// Set auth timeout.
+    pub fn auth_timeout(mut self, timeout_secs: i32) -> Self {
+        self.0.push(KeyParameter {
+            tag: Tag::AUTH_TIMEOUT,
+            value: KeyParameterValue::Integer(timeout_secs),
+        });
+        self
+    }
 }
 
 impl Deref for AuthSetBuilder {
diff --git a/keystore2/test_utils/key_generations.rs b/keystore2/test_utils/key_generations.rs
index e63ee60f..5e823c25 100644
--- a/keystore2/test_utils/key_generations.rs
+++ b/keystore2/test_utils/key_generations.rs
@@ -392,6 +392,30 @@ pub fn map_ks_error<T>(r: BinderResult<T>) -> Result<T, Error> {
     })
 }
 
+/// Check for a specific KeyMint error.
+#[macro_export]
+macro_rules! expect_km_error {
+    { $result:expr, $want:expr } => {
+        match $result {
+            Ok(_) => return Err(format!(
+                "{}:{}: Expected KeyMint error {:?}, found success",
+                file!(),
+                line!(),
+                $want
+            ).into()),
+            Err(s) if s.exception_code() == ExceptionCode::SERVICE_SPECIFIC
+                    && s.service_specific_error() == $want.0 => {}
+            Err(e) => return Err(format!(
+                "{}:{}: Expected KeyMint service-specific error {:?}, got {e:?}",
+                file!(),
+                line!(),
+                $want
+            ).into()),
+        }
+
+    };
+}
+
 /// Get the value of the given system property, if the given system property doesn't exist
 /// then returns an empty byte vector.
 pub fn get_system_prop(name: &str) -> Vec<u8> {
diff --git a/keystore2/test_utils/run_as.rs b/keystore2/test_utils/run_as.rs
index 2cd9fec3..7a9acb76 100644
--- a/keystore2/test_utils/run_as.rs
+++ b/keystore2/test_utils/run_as.rs
@@ -32,12 +32,104 @@ use nix::unistd::{
     fork, pipe as nix_pipe, read as nix_read, setgid, setuid, write as nix_write, ForkResult, Gid,
     Pid, Uid,
 };
-use serde::{de::DeserializeOwned, Serialize};
+use serde::{de::DeserializeOwned, Deserialize, Serialize};
 use std::io::{Read, Write};
 use std::marker::PhantomData;
 use std::os::fd::AsRawFd;
 use std::os::fd::OwnedFd;
 
+/// Newtype string error, which can be serialized and transferred out from a sub-process.
+#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
+pub struct Error(pub String);
+
+/// Allow ergonomic use of [`anyhow::Error`].
+impl From<anyhow::Error> for Error {
+    fn from(err: anyhow::Error) -> Self {
+        // Use the debug format of [`anyhow::Error`] to include backtrace.
+        Self(format!("{:?}", err))
+    }
+}
+impl From<String> for Error {
+    fn from(val: String) -> Self {
+        Self(val)
+    }
+}
+impl From<&str> for Error {
+    fn from(val: &str) -> Self {
+        Self(val.to_string())
+    }
+}
+
+impl std::fmt::Display for Error {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "{}", self.0)
+    }
+}
+
+impl std::error::Error for Error {}
+
+/// Equivalent to the [`assert!`] macro which returns an [`Error`] rather than emitting a panic.
+/// This is useful for test code that is `run_as`, so failures are more accessible.
+#[macro_export]
+macro_rules! expect {
+    ($cond:expr $(,)?) => {{
+        let result = $cond;
+        if !result {
+            return Err($crate::run_as::Error(format!(
+                "{}:{}: check '{}' failed",
+                file!(),
+                line!(),
+                stringify!($cond)
+            )));
+        }
+    }};
+    ($cond:expr, $($arg:tt)+) => {{
+        let result = $cond;
+        if !result {
+            return Err($crate::run_as::Error(format!(
+                "{}:{}: check '{}' failed: {}",
+                file!(),
+                line!(),
+                stringify!($cond),
+                format_args!($($arg)+)
+            )));
+        }
+    }};
+}
+
+/// Equivalent to the [`assert_eq!`] macro which returns an [`Error`] rather than emitting a panic.
+/// This is useful for test code that is `run_as`, so failures are more accessible.
+#[macro_export]
+macro_rules! expect_eq {
+    ($left:expr, $right:expr $(,)?) => {{
+        let left = $left;
+        let right = $right;
+        if left != right {
+            return Err($crate::run_as::Error(format!(
+                "{}:{}: assertion {} == {} failed\n  left: {left:?}\n right: {right:?}\n",
+                file!(),
+                line!(),
+                stringify!($left),
+                stringify!($right),
+            )));
+        }
+    }};
+    ($left:expr, $right:expr, $($arg:tt)+) => {{
+        let left = $left;
+        let right = $right;
+        if left != right {
+            return Err($crate::run_as::Error(format!(
+                "{}:{}: assertion {} == {} failed: {}\n  left: {left:?}\n right: {right:?}\n",
+                file!(),
+                line!(),
+                stringify!($left),
+                stringify!($right),
+                format_args!($($arg)+)
+            )));
+        }
+    }};
+}
+
 fn transition(se_context: selinux::Context, uid: Uid, gid: Gid) {
     setgid(gid).expect("Failed to set GID. This test might need more privileges.");
     setuid(uid).expect("Failed to set UID. This test might need more privileges.");
@@ -119,31 +211,48 @@ impl<T: Serialize + DeserializeOwned> ChannelReader<T> {
     /// Receiving blocks until an object of type T has been read from the channel.
     /// Panics if an error occurs during io or deserialization.
     pub fn recv(&mut self) -> T {
+        match self.recv_err() {
+            Ok(val) => val,
+            Err(e) => panic!("{e}"),
+        }
+    }
+
+    /// Receives a serializable object from the corresponding ChannelWriter.
+    /// Receiving blocks until an object of type T has been read from the channel.
+    pub fn recv_err(&mut self) -> Result<T, Error> {
         let mut size_buffer = [0u8; std::mem::size_of::<usize>()];
         match self.0.read(&mut size_buffer).expect("In ChannelReader::recv: Failed to read size.") {
             r if r != size_buffer.len() => {
-                panic!("In ChannelReader::recv: Failed to read size. Insufficient data: {}", r);
+                return Err(format!(
+                    "In ChannelReader::recv: Failed to read size. Insufficient data: {}",
+                    r
+                )
+                .into());
             }
             _ => {}
         };
         let size = usize::from_be_bytes(size_buffer);
         let mut data_buffer = vec![0u8; size];
-        match self
-            .0
-            .read(&mut data_buffer)
-            .expect("In ChannelReader::recv: Failed to read serialized data.")
-        {
-            r if r != data_buffer.len() => {
-                panic!(
+        match self.0.read(&mut data_buffer) {
+            Ok(r) if r != data_buffer.len() => {
+                return Err(format!(
                     "In ChannelReader::recv: Failed to read serialized data. Insufficient data: {}",
                     r
-                );
+                )
+                .into());
+            }
+            Ok(_) => {}
+            Err(e) => {
+                return Err(format!(
+                    "In ChannelReader::recv: Failed to read serialized data: {e:?}"
+                )
+                .into())
             }
-            _ => {}
         };
 
-        serde_cbor::from_slice(&data_buffer)
-            .expect("In ChannelReader::recv: Failed to deserialize data.")
+        serde_cbor::from_slice(&data_buffer).map_err(|e| {
+            format!("In ChannelReader::recv: Failed to deserialize data: {e:?}").into()
+        })
     }
 }
 
@@ -186,6 +295,11 @@ impl<R: Serialize + DeserializeOwned, M: Serialize + DeserializeOwned> ChildHand
     /// Get child result. Panics if the child did not exit with status 0 or if a serialization
     /// error occurred.
     pub fn get_result(mut self) -> R {
+        self.get_death_result()
+    }
+
+    /// Get child result via a mutable reference.
+    fn get_death_result(&mut self) -> R {
         let status =
             waitpid(self.pid, None).expect("ChildHandle::wait: Failed while waiting for child.");
         match status {
@@ -205,6 +319,31 @@ impl<R: Serialize + DeserializeOwned, M: Serialize + DeserializeOwned> ChildHand
     }
 }
 
+impl<R, M> ChildHandle<Result<R, Error>, M>
+where
+    R: Serialize + DeserializeOwned,
+    M: Serialize + DeserializeOwned,
+{
+    /// Receive a response from the child.  If the child has closed the response
+    /// channel, assume it has terminated and read the final result.
+    /// Panics on child failure, but will display the child error value.
+    pub fn recv_or_die(&mut self) -> M {
+        match self.response_reader.recv_err() {
+            Ok(v) => v,
+            Err(_e) => {
+                // We have failed to read from the `response_reader` channel.
+                // Assume this is because the child completed early with an error.
+                match self.get_death_result() {
+                    Ok(_) => {
+                        panic!("Child completed OK despite failure to read a response!")
+                    }
+                    Err(e) => panic!("Child failed with:\n{e}"),
+                }
+            }
+        }
+    }
+}
+
 impl<R: Serialize + DeserializeOwned, M: Serialize + DeserializeOwned> Drop for ChildHandle<R, M> {
     fn drop(&mut self) {
         if self.exit_status.is_none() {
@@ -213,6 +352,40 @@ impl<R: Serialize + DeserializeOwned, M: Serialize + DeserializeOwned> Drop for
     }
 }
 
+/// Run the given closure in a new process running as an untrusted app with the given `uid` and
+/// `gid`. Parent process will run without waiting for child status.
+///
+/// # Safety
+/// run_as_child runs the given closure in the client branch of fork. And it uses non
+/// async signal safe API. This means that calling this function in a multi threaded program
+/// yields undefined behavior in the child. As of this writing, it is safe to call this function
+/// from a Rust device test, because every test itself is spawned as a separate process.
+///
+/// # Safety Binder
+/// It is okay for the closure to use binder services, however, this does not work
+/// if the parent initialized libbinder already. So do not use binder outside of the closure
+/// in your test.
+pub unsafe fn run_as_child_app<F, R, M>(
+    uid: u32,
+    gid: u32,
+    f: F,
+) -> Result<ChildHandle<R, M>, nix::Error>
+where
+    R: Serialize + DeserializeOwned,
+    M: Serialize + DeserializeOwned,
+    F: 'static + Send + FnOnce(&mut ChannelReader<M>, &mut ChannelWriter<M>) -> R,
+{
+    // Safety: Caller guarantees that the process only has a single thread.
+    unsafe {
+        run_as_child(
+            "u:r:untrusted_app:s0:c91,c256,c10,c20",
+            Uid::from_raw(uid),
+            Gid::from_raw(gid),
+            f,
+        )
+    }
+}
+
 /// Run the given closure in a new process running with the new identity given as
 /// `uid`, `gid`, and `se_context`. Parent process will run without waiting for child status.
 ///
@@ -244,7 +417,7 @@ where
     let (response_reader, mut response_writer) =
         pipe_channel().expect("Failed to create cmd pipe.");
 
-    // SAFETY: Our caller guarantees that the process only has a single thread, so calling
+    // Safety: Our caller guarantees that the process only has a single thread, so calling
     // non-async-signal-safe functions in the child is in fact safe.
     match unsafe { fork() } {
         Ok(ForkResult::Parent { child, .. }) => {
@@ -283,6 +456,50 @@ where
     }
 }
 
+/// Run the given closure in a new process running with the root identity.
+///
+/// # Safety
+/// run_as runs the given closure in the client branch of fork. And it uses non
+/// async signal safe API. This means that calling this function in a multi threaded program
+/// yields undefined behavior in the child. As of this writing, it is safe to call this function
+/// from a Rust device test, because every test itself is spawned as a separate process.
+///
+/// # Safety Binder
+/// It is okay for the closure to use binder services, however, this does not work
+/// if the parent initialized libbinder already. So do not use binder outside of the closure
+/// in your test.
+pub unsafe fn run_as_root<F, R>(f: F) -> R
+where
+    R: Serialize + DeserializeOwned,
+    F: 'static + Send + FnOnce() -> R,
+{
+    // SAFETY: Our caller guarantees that the process only has a single thread.
+    unsafe { run_as("u:r:su:s0", Uid::from_raw(0), Gid::from_raw(0), f) }
+}
+
+/// Run the given closure in a new `untrusted_app` process running with the given `uid` and `gid`.
+///
+/// # Safety
+/// run_as runs the given closure in the client branch of fork. And it uses non
+/// async signal safe API. This means that calling this function in a multi threaded program
+/// yields undefined behavior in the child. As of this writing, it is safe to call this function
+/// from a Rust device test, because every test itself is spawned as a separate process.
+///
+/// # Safety Binder
+/// It is okay for the closure to use binder services, however, this does not work
+/// if the parent initialized libbinder already. So do not use binder outside of the closure
+/// in your test.
+pub unsafe fn run_as_app<F, R>(uid: u32, gid: u32, f: F) -> R
+where
+    R: Serialize + DeserializeOwned,
+    F: 'static + Send + FnOnce() -> R,
+{
+    // SAFETY: Our caller guarantees that the process only has a single thread.
+    unsafe {
+        run_as("u:r:untrusted_app:s0:c91,c256,c10,c20", Uid::from_raw(uid), Gid::from_raw(gid), f)
+    }
+}
+
 /// Run the given closure in a new process running with the new identity given as
 /// `uid`, `gid`, and `se_context`.
 ///
diff --git a/keystore2/tests/Android.bp b/keystore2/tests/Android.bp
index dbef46c9..1f3d0b8e 100644
--- a/keystore2/tests/Android.bp
+++ b/keystore2/tests/Android.bp
@@ -31,23 +31,26 @@ rust_test {
     static_libs: [
         // Also include static_libs for the NDK variants so that they are available
         // for dependencies.
-        "android.system.keystore2-V4-ndk",
-        "android.hardware.security.keymint-V3-ndk",
+        "android.system.keystore2-V5-ndk",
+        "android.hardware.security.keymint-V4-ndk",
     ],
     srcs: ["keystore2_client_tests.rs"],
     test_suites: [
+        "automotive-sdv-tests",
         "general-tests",
         "vts",
     ],
     test_config: "AndroidTest.xml",
 
     rustlibs: [
+        "android.hardware.gatekeeper-V1-rust",
         "android.hardware.security.secureclock-V1-rust",
         "android.security.authorization-rust",
         "android.security.maintenance-rust",
         "libaconfig_android_hardware_biometrics_rust",
         "libandroid_logger",
         "libandroid_security_flags_rust",
+        "libanyhow",
         "libbinder_rs",
         "libkeystore2_test_utils",
         "liblog_rust",
diff --git a/keystore2/tests/keystore2_client_aes_key_tests.rs b/keystore2/tests/keystore2_client_aes_key_tests.rs
index 3c5fda50..7128911d 100644
--- a/keystore2/tests/keystore2_client_aes_key_tests.rs
+++ b/keystore2/tests/keystore2_client_aes_key_tests.rs
@@ -203,7 +203,7 @@ fn keystore2_aes_gcm_key_fails_missing_min_mac_len() {
 }
 
 /// Try to create an operation using AES key with multiple block modes. Test should fail to create
-/// an operation with `UNSUPPORTED_BLOCK_MODE` error code.
+/// an operation.
 #[test]
 fn keystore2_aes_key_op_fails_multi_block_modes() {
     let sl = SecLevel::tee();
@@ -247,7 +247,12 @@ fn keystore2_aes_key_op_fails_multi_block_modes() {
         false,
     ));
     assert!(result.is_err());
-    assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_BLOCK_MODE), result.unwrap_err());
+    assert!(matches!(
+        result.unwrap_err(),
+        Error::Km(ErrorCode::INCOMPATIBLE_BLOCK_MODE)
+            | Error::Km(ErrorCode::UNSUPPORTED_BLOCK_MODE)
+            | Error::Km(ErrorCode::INVALID_ARGUMENT)
+    ));
 }
 
 /// Try to create an operation using AES key with multiple padding modes. Test should fail to create
diff --git a/keystore2/tests/keystore2_client_attest_key_tests.rs b/keystore2/tests/keystore2_client_attest_key_tests.rs
index f723d023..02dfd3fd 100644
--- a/keystore2/tests/keystore2_client_attest_key_tests.rs
+++ b/keystore2/tests/keystore2_client_attest_key_tests.rs
@@ -33,7 +33,7 @@ use keystore2_test_utils::ffi_test_utils::{get_value_from_attest_record, validat
 use keystore2_test_utils::{
     authorizations, key_generations, key_generations::Error, run_as, SecLevel,
 };
-use nix::unistd::{getuid, Gid, Uid};
+use nix::unistd::getuid;
 use rustutils::users::AID_USER_OFFSET;
 
 /// Generate RSA and EC attestation keys and use them for signing RSA-signing keys.
@@ -615,6 +615,8 @@ fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_
         // Skip this test on device supporting `DEVICE_ID_ATTESTATION_FEATURE`.
         return;
     }
+    skip_device_id_attestation_tests!();
+    skip_test_if_no_app_attest_key_feature!();
 
     let sl = SecLevel::tee();
 
@@ -653,47 +655,47 @@ fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_
 /// should return error response code - `GET_ATTESTATION_APPLICATION_ID_FAILED`.
 #[test]
 fn keystore2_generate_attested_key_fail_to_get_aaid() {
-    static APP_USER_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 19901;
     static APP_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static APP_GID: u32 = APP_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(APP_USER_CTX, Uid::from_raw(APP_UID), Gid::from_raw(APP_GID), || {
-            skip_test_if_no_app_attest_key_feature!();
-            let sl = SecLevel::tee();
-            if sl.keystore2.getInterfaceVersion().unwrap() < 4 {
-                // `GET_ATTESTATION_APPLICATION_ID_FAILED` is supported on devices with
-                // `IKeystoreService` version >= 4.
-                return;
-            }
-            let att_challenge: &[u8] = b"foo";
-            let alias = format!("ks_attest_rsa_encrypt_key_aaid_fail{}", getuid());
+    let gen_key_fn = || {
+        skip_test_if_no_app_attest_key_feature!();
+        let sl = SecLevel::tee();
+        if sl.keystore2.getInterfaceVersion().unwrap() < 4 {
+            // `GET_ATTESTATION_APPLICATION_ID_FAILED` is supported on devices with
+            // `IKeystoreService` version >= 4.
+            return;
+        }
+        let att_challenge: &[u8] = b"foo";
+        let alias = format!("ks_attest_rsa_encrypt_key_aaid_fail{}", getuid());
 
-            let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
-                &sl,
-                Domain::APP,
-                -1,
-                Some(alias),
-                &key_generations::KeyParams {
-                    key_size: 2048,
-                    purpose: vec![KeyPurpose::ATTEST_KEY],
-                    padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
-                    digest: Some(Digest::SHA_2_256),
-                    mgf_digest: None,
-                    block_mode: None,
-                    att_challenge: Some(att_challenge.to_vec()),
-                },
-                None,
-            ));
-
-            assert!(result.is_err());
-            assert_eq!(
-                result.unwrap_err(),
-                Error::Rc(ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED)
-            );
-        })
+        let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
+            &sl,
+            Domain::APP,
+            -1,
+            Some(alias),
+            &key_generations::KeyParams {
+                key_size: 2048,
+                purpose: vec![KeyPurpose::ATTEST_KEY],
+                padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
+                digest: Some(Digest::SHA_2_256),
+                mgf_digest: None,
+                block_mode: None,
+                att_challenge: Some(att_challenge.to_vec()),
+            },
+            None,
+        ));
+
+        assert!(result.is_err());
+        assert_eq!(
+            result.unwrap_err(),
+            Error::Rc(ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED)
+        );
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(APP_UID, APP_GID, gen_key_fn) };
 }
diff --git a/keystore2/tests/keystore2_client_authorizations_tests.rs b/keystore2/tests/keystore2_client_authorizations_tests.rs
index 6732f5c1..504e6ab2 100644
--- a/keystore2/tests/keystore2_client_authorizations_tests.rs
+++ b/keystore2/tests/keystore2_client_authorizations_tests.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    app_attest_key_feature_exists, delete_app_key,
+    app_attest_key_feature_exists, delete_app_key, get_vsr_api_level,
     perform_sample_asym_sign_verify_op, perform_sample_hmac_sign_verify_op,
     perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op,
     verify_certificate_serial_num, verify_certificate_subject_name, SAMPLE_PLAIN_TEXT,
@@ -472,6 +472,13 @@ fn keystore2_gen_key_auth_early_boot_only_op_fail() {
 #[test]
 fn keystore2_gen_key_auth_max_uses_per_boot() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() {
+        // Older devices with Keymaster implementation may use the key during generateKey to export
+        // the generated public key (EC Key), leading to an unnecessary increment of the
+        // key-associated counter. This can cause the test to fail, so skipping this test on older
+        // devices to avoid test failure.
+        return;
+    }
     const MAX_USES_COUNT: i32 = 3;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -633,20 +640,26 @@ fn keystore2_gen_key_auth_include_unique_id_success() {
     }
 }
 
-/// Generate a key with `APPLICATION_DATA`. Test should create an operation using the
-/// same `APPLICATION_DATA` successfully.
+/// Generate a key with `APPLICATION_DATA` and `APPLICATION_ID`. Test should create an operation
+/// successfully using the same `APPLICATION_DATA` and `APPLICATION_ID`.
 #[test]
-fn keystore2_gen_key_auth_app_data_test_success() {
+fn keystore2_gen_key_auth_app_data_app_id_test_success() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() && get_vsr_api_level() < 35 {
+        // `APPLICATION_DATA` key-parameter is causing the error on older devices, so skipping this
+        // test to run on older devices.
+        return;
+    }
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
         .purpose(KeyPurpose::SIGN)
         .purpose(KeyPurpose::VERIFY)
-        .digest(Digest::SHA_2_256)
+        .digest(Digest::NONE)
         .ec_curve(EcCurve::P_256)
-        .app_data(b"app-data".to_vec());
+        .app_data(b"app-data".to_vec())
+        .app_id(b"app-id".to_vec());
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::create_key_and_operation(
@@ -654,29 +667,35 @@ fn keystore2_gen_key_auth_app_data_test_success() {
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
-            .digest(Digest::SHA_2_256)
-            .app_data(b"app-data".to_vec()),
+            .digest(Digest::NONE)
+            .app_data(b"app-data".to_vec())
+            .app_id(b"app-id".to_vec()),
         alias,
     );
     assert!(result.is_ok());
     delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
-/// Generate a key with `APPLICATION_DATA`. Try to create an operation using the
-/// different `APPLICATION_DATA`, test should fail to create an operation with error code
-/// `INVALID_KEY_BLOB`.
+/// Generate a key with `APPLICATION_DATA` and `APPLICATION_ID`. Try to create an operation using
+/// the different `APPLICATION_DATA` and `APPLICATION_ID`, test should fail to create an operation.
 #[test]
-fn keystore2_gen_key_auth_app_data_test_fail() {
+fn keystore2_op_auth_invalid_app_data_app_id_test_fail() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() && get_vsr_api_level() < 35 {
+        // `APPLICATION_DATA` key-parameter is causing the error on older devices, so skipping this
+        // test to run on older devices.
+        return;
+    }
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
         .purpose(KeyPurpose::SIGN)
         .purpose(KeyPurpose::VERIFY)
-        .digest(Digest::SHA_2_256)
+        .digest(Digest::NONE)
         .ec_curve(EcCurve::P_256)
-        .app_data(b"app-data".to_vec());
+        .app_data(b"app-data".to_vec())
+        .app_id(b"app-id".to_vec());
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
@@ -684,8 +703,9 @@ fn keystore2_gen_key_auth_app_data_test_fail() {
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
-            .digest(Digest::SHA_2_256)
-            .app_data(b"invalid-app-data".to_vec()),
+            .digest(Digest::NONE)
+            .app_data(b"invalid-app-data".to_vec())
+            .app_id(b"invalid-app-id".to_vec()),
         alias,
     ));
     assert!(result.is_err());
@@ -693,49 +713,62 @@ fn keystore2_gen_key_auth_app_data_test_fail() {
     delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
-/// Generate a key with `APPLICATION_ID`. Test should create an operation using the
-/// same `APPLICATION_ID` successfully.
+/// Generate a key with `APPLICATION_DATA` and `APPLICATION_ID`. Try to create an operation using
+/// only `APPLICATION_ID`, test should fail to create an operation.
 #[test]
-fn keystore2_gen_key_auth_app_id_test_success() {
+fn keystore2_op_auth_missing_app_data_test_fail() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() && get_vsr_api_level() < 35 {
+        // `APPLICATION_DATA` key-parameter is causing the error on older devices, so skipping this
+        // test to run on older devices.
+        return;
+    }
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
         .purpose(KeyPurpose::SIGN)
         .purpose(KeyPurpose::VERIFY)
-        .digest(Digest::SHA_2_256)
+        .digest(Digest::NONE)
         .ec_curve(EcCurve::P_256)
-        .app_id(b"app-id".to_vec());
+        .app_id(b"app-id".to_vec())
+        .app_data(b"app-data".to_vec());
 
     let alias = "ks_test_auth_tags_test";
-    let result = key_generations::create_key_and_operation(
+    let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
         &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
-            .digest(Digest::SHA_2_256)
+            .digest(Digest::NONE)
             .app_id(b"app-id".to_vec()),
         alias,
-    );
-    assert!(result.is_ok());
+    ));
+
+    assert!(result.is_err());
+    assert_eq!(Error::Km(ErrorCode::INVALID_KEY_BLOB), result.unwrap_err());
     delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
-/// Generate a key with `APPLICATION_ID`. Try to create an operation using the
-/// different `APPLICATION_ID`, test should fail to create an operation with error code
-/// `INVALID_KEY_BLOB`.
+/// Generate a key with `APPLICATION_DATA` and `APPLICATION_ID`. Try to create an operation using
+/// only `APPLICATION_DATA`, test should fail to create an operation.
 #[test]
-fn keystore2_gen_key_auth_app_id_test_fail() {
+fn keystore2_op_auth_missing_app_id_test_fail() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() && get_vsr_api_level() < 35 {
+        // `APPLICATION_DATA` key-parameter is causing the error on older devices, so skipping this
+        // test to run on older devices.
+        return;
+    }
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
         .purpose(KeyPurpose::SIGN)
         .purpose(KeyPurpose::VERIFY)
-        .digest(Digest::SHA_2_256)
+        .digest(Digest::NONE)
         .ec_curve(EcCurve::P_256)
+        .app_data(b"app-data".to_vec())
         .app_id(b"app-id".to_vec());
 
     let alias = "ks_test_auth_tags_test";
@@ -744,8 +777,8 @@ fn keystore2_gen_key_auth_app_id_test_fail() {
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
-            .digest(Digest::SHA_2_256)
-            .app_id(b"invalid-app-id".to_vec()),
+            .digest(Digest::NONE)
+            .app_data(b"app-data".to_vec()),
         alias,
     ));
     assert!(result.is_err());
@@ -760,6 +793,11 @@ fn keystore2_gen_key_auth_app_id_test_fail() {
 fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
     skip_test_if_no_app_attest_key_feature!();
     let sl = SecLevel::tee();
+    if sl.is_keymaster() && get_vsr_api_level() < 35 {
+        // `APPLICATION_DATA` key-parameter is causing the error on older devices, so skipping this
+        // test to run on older devices.
+        return;
+    }
 
     // Generate attestation key.
     let attest_gen_params = authorizations::AuthSetBuilder::new()
@@ -809,14 +847,18 @@ fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
 
 /// Generate an attestation-key with specifying `APPLICATION_ID` and `APPLICATION_DATA`.
 /// Test should try to generate an attested key using previously generated attestation-key without
-/// specifying app-id and app-data. Test should fail to generate a new key with error code
-/// `INVALID_KEY_BLOB`.
+/// specifying app-id and app-data. Test should fail to generate a new key.
 /// It is an oversight of the Keystore API that `APPLICATION_ID` and `APPLICATION_DATA` tags cannot
 /// be provided to generateKey for an attestation key that was generated with them.
 #[test]
 fn keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail() {
     skip_test_if_no_app_attest_key_feature!();
     let sl = SecLevel::tee();
+    if sl.is_keymaster() && get_vsr_api_level() < 35 {
+        // `APPLICATION_DATA` key-parameter is causing the error on older devices, so skipping this
+        // test to run on older devices.
+        return;
+    }
 
     // Generate attestation key.
     let attest_gen_params = authorizations::AuthSetBuilder::new()
diff --git a/keystore2/tests/keystore2_client_ec_key_tests.rs b/keystore2/tests/keystore2_client_ec_key_tests.rs
index 8aa9bc49..526a3390 100644
--- a/keystore2/tests/keystore2_client_ec_key_tests.rs
+++ b/keystore2/tests/keystore2_client_ec_key_tests.rs
@@ -425,7 +425,9 @@ fn keystore2_key_owner_validation() {
     // Client#1: Generate a key and create an operation using generated key.
     // Wait until the parent notifies to continue. Once the parent notifies, this operation
     // is expected to be completed successfully.
-    // SAFETY: The test is run in a separate process with no other threads.
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     let mut child_handle = unsafe {
         execute_op_run_as_child(
             TARGET_CTX,
@@ -446,20 +448,23 @@ fn keystore2_key_owner_validation() {
     const APPLICATION_ID_2: u32 = 10602;
     let uid2 = USER_ID * AID_USER_OFFSET + APPLICATION_ID_2;
     let gid2 = USER_ID * AID_USER_OFFSET + APPLICATION_ID_2;
-    // SAFETY: The test is run in a separate process with no other threads.
+
+    let get_key_fn = move || {
+        let keystore2_inst = get_keystore_service();
+        let result = key_generations::map_ks_error(keystore2_inst.getKeyEntry(&KeyDescriptor {
+            domain: Domain::APP,
+            nspace: -1,
+            alias: Some(alias.to_string()),
+            blob: None,
+        }));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(uid2), Gid::from_raw(gid2), move || {
-            let keystore2_inst = get_keystore_service();
-            let result =
-                key_generations::map_ks_error(keystore2_inst.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(alias.to_string()),
-                    blob: None,
-                }));
-            assert!(result.is_err());
-            assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-        });
+        run_as::run_as_app(uid2, gid2, get_key_fn);
     };
 
     // Notify the child process (client#1) to resume and finish.
diff --git a/keystore2/tests/keystore2_client_grant_key_tests.rs b/keystore2/tests/keystore2_client_grant_key_tests.rs
index 50b87b9a..c171ab15 100644
--- a/keystore2/tests/keystore2_client_grant_key_tests.rs
+++ b/keystore2/tests/keystore2_client_grant_key_tests.rs
@@ -19,20 +19,35 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
     Digest::Digest, KeyPurpose::KeyPurpose,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
-    ResponseCode::ResponseCode,
+    Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
+    KeyEntryResponse::KeyEntryResponse, KeyPermission::KeyPermission, ResponseCode::ResponseCode,
 };
 use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
+    authorizations, get_keystore_service, key_generations,
+    key_generations::{map_ks_error, Error},
+    run_as, SecLevel,
 };
-use nix::unistd::{getuid, Gid, Uid};
+use nix::unistd::getuid;
 use rustutils::users::AID_USER_OFFSET;
 
-/// Generate an EC signing key and grant it to the user with given access vector.
-fn generate_ec_key_and_grant_to_user(
-    grantee_uid: i32,
+/// Produce a [`KeyDescriptor`] for a granted key.
+fn granted_key_descriptor(nspace: i64) -> KeyDescriptor {
+    KeyDescriptor { domain: Domain::GRANT, nspace, alias: None, blob: None }
+}
+
+fn get_granted_key(
+    ks2: &binder::Strong<dyn IKeystoreService>,
+    nspace: i64,
+) -> Result<KeyEntryResponse, Error> {
+    map_ks_error(ks2.getKeyEntry(&granted_key_descriptor(nspace)))
+}
+
+/// Generate an EC signing key in the SELINUX domain and grant it to the user with given access
+/// vector.
+fn generate_and_grant_selinux_key(
+    grantee_uid: u32,
     access_vector: i32,
-) -> binder::Result<KeyDescriptor> {
+) -> Result<KeyDescriptor, Error> {
     let sl = SecLevel::tee();
     let alias = format!("{}{}", "ks_grant_test_key_1", getuid());
 
@@ -45,204 +60,287 @@ fn generate_ec_key_and_grant_to_user(
     )
     .unwrap();
 
-    sl.keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
+    map_ks_error(sl.keystore2.grant(
+        &key_metadata.key,
+        grantee_uid.try_into().unwrap(),
+        access_vector,
+    ))
 }
 
-fn load_grant_key_and_perform_sign_operation(
-    sl: &SecLevel,
-    grant_key_nspace: i64,
-) -> Result<(), binder::Status> {
-    let key_entry_response = sl.keystore2.getKeyEntry(&KeyDescriptor {
-        domain: Domain::GRANT,
-        nspace: grant_key_nspace,
-        alias: None,
-        blob: None,
-    })?;
+/// Use a granted key to perform a signing operation.
+fn sign_with_granted_key(grant_key_nspace: i64) -> Result<(), Error> {
+    let sl = SecLevel::tee();
+    let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace)?;
 
     // Perform sample crypto operation using granted key.
-    let op_response = sl.binder.createOperation(
+    let op_response = map_ks_error(sl.binder.createOperation(
         &key_entry_response.metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
-    )?;
+    ))?;
 
     assert!(op_response.iOperation.is_some());
     assert_eq!(
         Ok(()),
-        key_generations::map_ks_error(perform_sample_sign_operation(
-            &op_response.iOperation.unwrap()
-        ))
+        map_ks_error(perform_sample_sign_operation(&op_response.iOperation.unwrap()))
     );
 
     Ok(())
 }
 
-/// Try to grant a key with permission that does not map to any of the `KeyPermission` values.
-/// An error is expected with values that does not map to set of permissions listed in
+/// Try to grant an SELINUX key with permission that does not map to any of the `KeyPermission`
+/// values.  An error is expected with values that does not map to set of permissions listed in
 /// `KeyPermission`.
 #[test]
-fn keystore2_grant_key_with_invalid_perm_expecting_syserror() {
+fn grant_selinux_key_with_invalid_perm() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     let grantee_uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     let invalid_access_vector = KeyPermission::CONVERT_STORAGE_KEY_TO_EPHEMERAL.0 << 19;
 
-    let result = key_generations::map_ks_error(generate_ec_key_and_grant_to_user(
-        grantee_uid.try_into().unwrap(),
-        invalid_access_vector,
-    ));
+    let result = generate_and_grant_selinux_key(grantee_uid, invalid_access_vector);
     assert!(result.is_err());
     assert_eq!(Error::Rc(ResponseCode::SYSTEM_ERROR), result.unwrap_err());
 }
 
-/// Try to grant a key with empty access vector `KeyPermission::NONE`, should be able to grant a
-/// key with empty access vector successfully. In grantee context try to use the granted key, it
-/// should fail to load the key with permission denied error.
+/// Try to grant an SELINUX key with empty access vector `KeyPermission::NONE`, should be able to
+/// grant a key with empty access vector successfully. In grantee context try to use the granted
+/// key, it should fail to load the key with permission denied error.
 #[test]
-fn keystore2_grant_key_with_perm_none() {
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
-
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn grant_selinux_key_with_perm_none() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let empty_access_vector = KeyPermission::NONE.0;
+    let grantor_fn = || {
+        let empty_access_vector = KeyPermission::NONE.0;
 
-            let grant_key = key_generations::map_ks_error(generate_ec_key_and_grant_to_user(
-                GRANTEE_UID.try_into().unwrap(),
-                empty_access_vector,
-            ))
-            .unwrap();
+        let grant_key = generate_and_grant_selinux_key(GRANTEE_UID, empty_access_vector).unwrap();
 
-            assert_eq!(grant_key.domain, Domain::GRANT);
+        assert_eq!(grant_key.domain, Domain::GRANT);
 
-            grant_key.nspace
-        })
+        grant_key.nspace
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // In grantee context try to load the key, it should fail to load the granted key as it is
     // granted with empty access vector.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-
-                let result = key_generations::map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::GRANT,
-                    nspace: grant_key_nspace,
-                    alias: None,
-                    blob: None,
-                }));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
 
-/// Grant a key to the user (grantee) with `GET_INFO|USE` key permissions. Verify whether grantee
-/// can succeed in loading the granted key and try to perform simple operation using this granted
-/// key. Grantee should be able to load the key and use the key to perform crypto operation
+/// Grant an SELINUX key to the user (grantee) with `GET_INFO|USE` key permissions. Verify whether
+/// grantee can succeed in loading the granted key and try to perform simple operation using this
+/// granted key. Grantee should be able to load the key and use the key to perform crypto operation
 /// successfully. Try to delete the granted key in grantee context where it is expected to fail to
 /// delete it as `DELETE` permission is not granted.
 #[test]
-fn keystore2_grant_get_info_use_key_perm() {
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
-
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn grant_selinux_key_get_info_use_perms() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
     // Generate a key and grant it to a user with GET_INFO|USE key permissions.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
-            let grant_key = key_generations::map_ks_error(generate_ec_key_and_grant_to_user(
-                GRANTEE_UID.try_into().unwrap(),
-                access_vector,
-            ))
+    let grantor_fn = || {
+        let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
+        let grant_key = generate_and_grant_selinux_key(GRANTEE_UID, access_vector).unwrap();
+
+        assert_eq!(grant_key.domain, Domain::GRANT);
+
+        grant_key.nspace
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
+    // In grantee context load the key and try to perform crypto operation.
+    let grantee_fn = move || {
+        let sl = SecLevel::tee();
+
+        // Load the granted key.
+        let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace).unwrap();
+
+        // Perform sample crypto operation using granted key.
+        let op_response = sl
+            .binder
+            .createOperation(
+                &key_entry_response.metadata.key,
+                &authorizations::AuthSetBuilder::new()
+                    .purpose(KeyPurpose::SIGN)
+                    .digest(Digest::SHA_2_256),
+                false,
+            )
             .unwrap();
+        assert!(op_response.iOperation.is_some());
+        assert_eq!(
+            Ok(()),
+            map_ks_error(perform_sample_sign_operation(&op_response.iOperation.unwrap()))
+        );
+
+        // Try to delete the key, it is expected to be fail with permission denied error.
+        let result =
+            map_ks_error(sl.keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+    };
 
-            assert_eq!(grant_key.domain, Domain::GRANT);
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
+}
 
-            grant_key.nspace
-        })
+/// Grant an SELINUX key to the user (grantee) with just `GET_INFO` key permissions. Verify whether
+/// grantee can succeed in loading the granted key and try to perform simple operation using this
+/// granted key.
+#[test]
+fn grant_selinux_key_get_info_only() {
+    const USER_ID: u32 = 99;
+    const APPLICATION_ID: u32 = 10001;
+    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
+    static GRANTEE_GID: u32 = GRANTEE_UID;
+
+    // Generate a key and grant it to a user with (just) GET_INFO key permissions.
+    let grantor_fn = || {
+        let access_vector = KeyPermission::GET_INFO.0;
+        let grant_key = generate_and_grant_selinux_key(GRANTEE_UID, access_vector).unwrap();
+
+        assert_eq!(grant_key.domain, Domain::GRANT);
+
+        grant_key.nspace
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // In grantee context load the key and try to perform crypto operation.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let sl = SecLevel::tee();
-
-                // Load the granted key.
-                let key_entry_response = sl
-                    .keystore2
-                    .getKeyEntry(&KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: grant_key_nspace,
-                        alias: None,
-                        blob: None,
-                    })
-                    .unwrap();
-
-                // Perform sample crypto operation using granted key.
-                let op_response = sl
-                    .binder
-                    .createOperation(
-                        &key_entry_response.metadata.key,
-                        &authorizations::AuthSetBuilder::new()
-                            .purpose(KeyPurpose::SIGN)
-                            .digest(Digest::SHA_2_256),
-                        false,
-                    )
-                    .unwrap();
-                assert!(op_response.iOperation.is_some());
-                assert_eq!(
-                    Ok(()),
-                    key_generations::map_ks_error(perform_sample_sign_operation(
-                        &op_response.iOperation.unwrap()
-                    ))
-                );
-
-                // Try to delete the key, it is expected to be fail with permission denied error.
-                let result =
-                    key_generations::map_ks_error(sl.keystore2.deleteKey(&KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: grant_key_nspace,
-                        alias: None,
-                        blob: None,
-                    }));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-            },
+    let grantee_fn = move || {
+        let sl = SecLevel::tee();
+
+        // Load the granted key.
+        let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace)
+            .expect("failed to get info for granted key");
+
+        // Attempt to perform sample crypto operation using granted key, now identified by <KEY_ID,
+        // key_id>.
+        let result = map_ks_error(
+            sl.binder.createOperation(
+                &key_entry_response.metadata.key,
+                &authorizations::AuthSetBuilder::new()
+                    .purpose(KeyPurpose::SIGN)
+                    .digest(Digest::SHA_2_256),
+                false,
+            ),
+        );
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+
+        // Try to delete the key using a <GRANT, grant_id> descriptor.
+        let result =
+            map_ks_error(sl.keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+
+        // Try to delete the key using a <KEY_ID, key_id> descriptor.
+        let result = map_ks_error(sl.keystore2.deleteKey(&key_entry_response.metadata.key));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
+}
+
+/// Grant an APP key to the user (grantee) with just `GET_INFO` key permissions. Verify whether
+/// grantee can succeed in loading the granted key and try to perform simple operation using this
+/// granted key.
+#[test]
+fn grant_app_key_get_info_only() {
+    const USER_ID: u32 = 99;
+    const APPLICATION_ID: u32 = 10001;
+    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
+    static GRANTEE_GID: u32 = GRANTEE_UID;
+    static ALIAS: &str = "ks_grant_key_info_only";
+
+    // Generate a key and grant it to a user with (just) GET_INFO key permissions.
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let access_vector = KeyPermission::GET_INFO.0;
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(ALIAS.to_string()),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
         )
+        .unwrap();
+
+        grant_keys.remove(0)
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
+    // In grantee context load the key and try to perform crypto operation.
+    let grantee_fn = move || {
+        let sl = SecLevel::tee();
+
+        // Load the granted key.
+        let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace)
+            .expect("failed to get info for granted key");
+
+        // Attempt to perform sample crypto operation using granted key, now identified by <KEY_ID,
+        // key_id>.
+        let result = map_ks_error(
+            sl.binder.createOperation(
+                &key_entry_response.metadata.key,
+                &authorizations::AuthSetBuilder::new()
+                    .purpose(KeyPurpose::SIGN)
+                    .digest(Digest::SHA_2_256),
+                false,
+            ),
+        );
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+
+        // Try to delete the key using a <GRANT, grant_id> descriptor.
+        let result =
+            map_ks_error(sl.keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+
+        // Try to delete the key using a <KEY_ID, key_id> descriptor.
+        let result = map_ks_error(sl.keystore2.deleteKey(&key_entry_response.metadata.key));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
 
-/// Grant a key to the user with DELETE access. In grantee context load the key and delete it.
+/// Grant an APP key to the user with DELETE access. In grantee context load the key and delete it.
 /// Verify that grantee should succeed in deleting the granted key and in grantor context test
 /// should fail to find the key with error response `KEY_NOT_FOUND`.
 #[test]
-fn keystore2_grant_delete_key_success() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn grant_app_key_delete_success() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
@@ -250,70 +348,63 @@ fn keystore2_grant_delete_key_success() {
     static ALIAS: &str = "ks_grant_key_delete_success";
 
     // Generate a key and grant it to a user with DELETE permission.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let access_vector = KeyPermission::DELETE.0;
-            let mut grant_keys = generate_ec_key_and_grant_to_users(
-                &sl,
-                Some(ALIAS.to_string()),
-                vec![GRANTEE_UID.try_into().unwrap()],
-                access_vector,
-            )
-            .unwrap();
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let access_vector = KeyPermission::DELETE.0;
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(ALIAS.to_string()),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap();
 
-            grant_keys.remove(0)
-        })
+        grant_keys.remove(0)
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // Grantee context, delete the key.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-                keystore2
-                    .deleteKey(&KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: grant_key_nspace,
-                        alias: None,
-                        blob: None,
-                    })
-                    .unwrap();
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)).unwrap();
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
+
     // Verify whether key got deleted in grantor's context.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), move || {
-            let keystore2_inst = get_keystore_service();
-            let result =
-                key_generations::map_ks_error(keystore2_inst.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS.to_string()),
-                    blob: None,
-                }));
-            assert!(result.is_err());
-            assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-        })
+    let grantor_fn = move || {
+        let keystore2_inst = get_keystore_service();
+        let result = map_ks_error(keystore2_inst.getKeyEntry(&KeyDescriptor {
+            domain: Domain::APP,
+            nspace: -1,
+            alias: Some(ALIAS.to_string()),
+            blob: None,
+        }));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_root(grantor_fn) };
 }
 
-/// Grant a key to the user. In grantee context load the granted key and try to grant it to second
-/// user. Test should fail with a response code `PERMISSION_DENIED` to grant a key to second user
-/// from grantee context. Test should make sure second grantee should not have a access to granted
-/// key.
+/// Grant an APP key to the user. In grantee context load the granted key and try to grant it to
+/// second user. Test should fail with a response code `PERMISSION_DENIED` to grant a key to second
+/// user from grantee context. Test should make sure second grantee should not have a access to
+/// granted key.
 #[test]
-fn keystore2_grant_key_fails_with_permission_denied() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn grant_granted_app_key_fails() {
+    const GRANTOR_USER_ID: u32 = 97;
+    const GRANTOR_APPLICATION_ID: u32 = 10003;
+    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
+    static GRANTOR_GID: u32 = GRANTOR_UID;
+
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
@@ -325,83 +416,148 @@ fn keystore2_grant_key_fails_with_permission_denied() {
     static SEC_GRANTEE_GID: u32 = SEC_GRANTEE_UID;
 
     // Generate a key and grant it to a user with GET_INFO permission.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let access_vector = KeyPermission::GET_INFO.0;
-            let alias = format!("ks_grant_perm_denied_key_{}", getuid());
-            let mut grant_keys = generate_ec_key_and_grant_to_users(
-                &sl,
-                Some(alias),
-                vec![GRANTEE_UID.try_into().unwrap()],
-                access_vector,
-            )
-            .unwrap();
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let access_vector = KeyPermission::GET_INFO.0;
+        let alias = format!("ks_grant_perm_denied_key_{}", getuid());
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap();
 
-            grant_keys.remove(0)
-        })
+        grant_keys.remove(0)
     };
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_app(GRANTOR_UID, GRANTOR_GID, grantor_fn) };
 
     // Grantee context, load the granted key and try to grant it to `SEC_GRANTEE_UID` grantee.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-                let access_vector = KeyPermission::GET_INFO.0;
-
-                let key_entry_response = keystore2
-                    .getKeyEntry(&KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: grant_key_nspace,
-                        alias: None,
-                        blob: None,
-                    })
-                    .unwrap();
-
-                let result = key_generations::map_ks_error(keystore2.grant(
-                    &key_entry_response.metadata.key,
-                    SEC_GRANTEE_UID.try_into().unwrap(),
-                    access_vector,
-                ));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        let access_vector = KeyPermission::GET_INFO.0;
+
+        // Try to grant when identifying the key with <GRANT, grant_nspace>.
+        let result = map_ks_error(keystore2.grant(
+            &granted_key_descriptor(grant_key_nspace),
+            SEC_GRANTEE_UID.try_into().unwrap(),
+            access_vector,
+        ));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::SYSTEM_ERROR), result.unwrap_err());
+
+        // Load the key info and try to grant when identifying the key with <KEY_ID, keyid>.
+        let key_entry_response = get_granted_key(&keystore2, grant_key_nspace).unwrap();
+        let result = map_ks_error(keystore2.grant(
+            &key_entry_response.metadata.key,
+            SEC_GRANTEE_UID.try_into().unwrap(),
+            access_vector,
+        ));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
+
     // Make sure second grantee shouldn't have access to the above granted key.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(SEC_GRANTEE_UID),
-            Gid::from_raw(SEC_GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-
-                let result = key_generations::map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::GRANT,
-                    nspace: grant_key_nspace,
-                    alias: None,
-                    blob: None,
-                }));
-
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-            },
+    let grantee2_fn = move || {
+        let keystore2 = get_keystore_service();
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(SEC_GRANTEE_UID, SEC_GRANTEE_GID, grantee2_fn) };
+}
+
+/// Grant an APP key to one user, from a normal user. Check that grantee context can load the
+/// granted key, but that a second unrelated context cannot.
+#[test]
+fn grant_app_key_only_to_grantee() {
+    const GRANTOR_USER_ID: u32 = 97;
+    const GRANTOR_APPLICATION_ID: u32 = 10003;
+    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
+    static GRANTOR_GID: u32 = GRANTOR_UID;
+
+    const USER_ID: u32 = 99;
+    const APPLICATION_ID: u32 = 10001;
+    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
+    static GRANTEE_GID: u32 = GRANTEE_UID;
+
+    const SEC_USER_ID: u32 = 98;
+    const SEC_APPLICATION_ID: u32 = 10001;
+    static SEC_GRANTEE_UID: u32 = SEC_USER_ID * AID_USER_OFFSET + SEC_APPLICATION_ID;
+    static SEC_GRANTEE_GID: u32 = SEC_GRANTEE_UID;
+
+    // Child function to generate a key and grant it to a user with `GET_INFO` permission.
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let access_vector = KeyPermission::GET_INFO.0;
+        let alias = format!("ks_grant_single_{}", getuid());
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
         )
+        .unwrap();
+
+        grant_keys.remove(0)
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    let grant_key_nspace = unsafe { run_as::run_as_app(GRANTOR_UID, GRANTOR_GID, grantor_fn) };
+
+    // Child function for the grantee context: can load the granted key.
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        let rsp = get_granted_key(&keystore2, grant_key_nspace).expect("failed to get granted key");
+
+        // Return the underlying key ID to simulate an ID leak.
+        assert_eq!(rsp.metadata.key.domain, Domain::KEY_ID);
+        rsp.metadata.key.nspace
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    let key_id = unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
+
+    // Second context does not have access to the above granted key, because it's identified
+    // by <uid, grant_nspace> and the implicit uid value is different.  Also, even if the
+    // second context gets hold of the key ID somehow, that also doesn't work.
+    let non_grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
+
+        let result = map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
+            domain: Domain::KEY_ID,
+            nspace: key_id,
+            alias: None,
+            blob: None,
+        }));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_app(SEC_GRANTEE_UID, SEC_GRANTEE_GID, non_grantee_fn) };
 }
 
-/// Try to grant a key with `GRANT` access. Keystore2 system shouldn't allow to grant a key with
-/// `GRANT` access. Test should fail to grant a key with `PERMISSION_DENIED` error response code.
+/// Try to grant an APP key with `GRANT` access. Keystore2 system shouldn't allow to grant a key
+/// with `GRANT` access. Test should fail to grant a key with `PERMISSION_DENIED` error response
+/// code.
 #[test]
-fn keystore2_grant_key_fails_with_grant_perm_expect_perm_denied() {
+fn grant_app_key_with_grant_perm_fails() {
     let sl = SecLevel::tee();
     let access_vector = KeyPermission::GRANT.0;
     let alias = format!("ks_grant_access_vec_key_{}", getuid());
@@ -409,7 +565,7 @@ fn keystore2_grant_key_fails_with_grant_perm_expect_perm_denied() {
     let application_id = 10001;
     let grantee_uid = user_id * AID_USER_OFFSET + application_id;
 
-    let result = key_generations::map_ks_error(generate_ec_key_and_grant_to_users(
+    let result = map_ks_error(generate_ec_key_and_grant_to_users(
         &sl,
         Some(alias),
         vec![grantee_uid.try_into().unwrap()],
@@ -419,10 +575,10 @@ fn keystore2_grant_key_fails_with_grant_perm_expect_perm_denied() {
     assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
 }
 
-/// Try to grant a non-existing key to the user. Test should fail with `KEY_NOT_FOUND` error
+/// Try to grant a non-existing SELINUX key to the user. Test should fail with `KEY_NOT_FOUND` error
 /// response.
 #[test]
-fn keystore2_grant_fails_with_non_existing_key_expect_key_not_found_err() {
+fn grant_fails_with_non_existing_selinux_key() {
     let keystore2 = get_keystore_service();
     let alias = format!("ks_grant_test_non_existing_key_5_{}", getuid());
     let user_id = 98;
@@ -430,7 +586,7 @@ fn keystore2_grant_fails_with_non_existing_key_expect_key_not_found_err() {
     let grantee_uid = user_id * AID_USER_OFFSET + application_id;
     let access_vector = KeyPermission::GET_INFO.0;
 
-    let result = key_generations::map_ks_error(keystore2.grant(
+    let result = map_ks_error(keystore2.grant(
         &KeyDescriptor {
             domain: Domain::SELINUX,
             nspace: key_generations::SELINUX_SHELL_NAMESPACE,
@@ -444,71 +600,56 @@ fn keystore2_grant_fails_with_non_existing_key_expect_key_not_found_err() {
     assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
 }
 
-/// Grant a key to the user and immediately ungrant the granted key. In grantee context try to load
+/// Grant an APP key to the user and immediately ungrant the granted key. In grantee context try to load
 /// the key. Grantee should fail to load the ungranted key with `KEY_NOT_FOUND` error response.
 #[test]
-fn keystore2_ungrant_key_success() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn ungrant_app_key_success() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
     // Generate a key and grant it to a user with GET_INFO permission.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = format!("ks_ungrant_test_key_1{}", getuid());
-            let access_vector = KeyPermission::GET_INFO.0;
-            let mut grant_keys = generate_ec_key_and_grant_to_users(
-                &sl,
-                Some(alias.to_string()),
-                vec![GRANTEE_UID.try_into().unwrap()],
-                access_vector,
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = format!("ks_ungrant_test_key_1{}", getuid());
+        let access_vector = KeyPermission::GET_INFO.0;
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias.to_string()),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap();
+
+        let grant_key_nspace = grant_keys.remove(0);
+
+        // Ungrant above granted key.
+        sl.keystore2
+            .ungrant(
+                &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
+                GRANTEE_UID.try_into().unwrap(),
             )
             .unwrap();
 
-            let grant_key_nspace = grant_keys.remove(0);
-
-            // Ungrant above granted key.
-            sl.keystore2
-                .ungrant(
-                    &KeyDescriptor {
-                        domain: Domain::APP,
-                        nspace: -1,
-                        alias: Some(alias),
-                        blob: None,
-                    },
-                    GRANTEE_UID.try_into().unwrap(),
-                )
-                .unwrap();
-
-            grant_key_nspace
-        })
+        grant_key_nspace
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // Grantee context, try to load the ungranted key.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-                let result = key_generations::map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::GRANT,
-                    nspace: grant_key_nspace,
-                    alias: None,
-                    blob: None,
-                }));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
 
 /// Generate a key, grant it to the user and then delete the granted key. Try to ungrant
@@ -517,94 +658,78 @@ fn keystore2_ungrant_key_success() {
 /// key in grantee context. Test should fail to load the granted key in grantee context as the
 /// associated key is deleted from grantor context.
 #[test]
-fn keystore2_ungrant_fails_with_non_existing_key_expect_key_not_found_error() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
+fn ungrant_deleted_app_key_fails() {
     const APPLICATION_ID: u32 = 10001;
     const USER_ID: u32 = 99;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = format!("{}{}", "ks_grant_delete_ungrant_test_key_1", getuid());
-
-            let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sl,
-                Domain::SELINUX,
-                key_generations::SELINUX_SHELL_NAMESPACE,
-                Some(alias.to_string()),
-                None,
-            )
-            .unwrap();
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = format!("{}{}", "ks_grant_delete_ungrant_test_key_1", getuid());
+
+        let key_metadata = key_generations::generate_ec_p256_signing_key(
+            &sl,
+            Domain::SELINUX,
+            key_generations::SELINUX_SHELL_NAMESPACE,
+            Some(alias.to_string()),
+            None,
+        )
+        .unwrap();
 
-            let access_vector = KeyPermission::GET_INFO.0;
-            let grant_key = sl
-                .keystore2
-                .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
-                .unwrap();
-            assert_eq!(grant_key.domain, Domain::GRANT);
-
-            // Delete above granted key.
-            sl.keystore2.deleteKey(&key_metadata.key).unwrap();
-
-            // Try to ungrant above granted key.
-            let result = key_generations::map_ks_error(
-                sl.keystore2.ungrant(&key_metadata.key, GRANTEE_UID.try_into().unwrap()),
-            );
-            assert!(result.is_err());
-            assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-
-            // Generate a new key with the same alias and try to access the earlier granted key
-            // in grantee context.
-            let result = key_generations::generate_ec_p256_signing_key(
-                &sl,
-                Domain::SELINUX,
-                key_generations::SELINUX_SHELL_NAMESPACE,
-                Some(alias),
-                None,
-            );
-            assert!(result.is_ok());
-
-            grant_key.nspace
-        })
+        let access_vector = KeyPermission::GET_INFO.0;
+        let grant_key = sl
+            .keystore2
+            .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
+            .unwrap();
+        assert_eq!(grant_key.domain, Domain::GRANT);
+
+        // Delete above granted key.
+        sl.keystore2.deleteKey(&key_metadata.key).unwrap();
+
+        // Try to ungrant above granted key.
+        let result =
+            map_ks_error(sl.keystore2.ungrant(&key_metadata.key, GRANTEE_UID.try_into().unwrap()));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
+
+        // Generate a new key with the same alias and try to access the earlier granted key
+        // in grantee context.
+        let result = key_generations::generate_ec_p256_signing_key(
+            &sl,
+            Domain::SELINUX,
+            key_generations::SELINUX_SHELL_NAMESPACE,
+            Some(alias),
+            None,
+        );
+        assert!(result.is_ok());
+
+        grant_key.nspace
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // Make sure grant did not persist, try to access the earlier granted key in grantee context.
     // Grantee context should fail to load the granted key as its associated key is deleted in
     // grantor context.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-
-                let result = key_generations::map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::GRANT,
-                    nspace: grant_key_nspace,
-                    alias: None,
-                    blob: None,
-                }));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
 
 /// Grant a key to multiple users. Verify that all grantees should succeed in loading the key and
 /// use it for performing an operation successfully.
 #[test]
-fn keystore2_grant_key_to_multi_users_success() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
+fn grant_app_key_to_multi_users_success() {
     const APPLICATION_ID: u32 = 10001;
     const USER_ID_1: u32 = 99;
     static GRANTEE_1_UID: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID;
@@ -615,46 +740,34 @@ fn keystore2_grant_key_to_multi_users_success() {
     static GRANTEE_2_GID: u32 = GRANTEE_2_UID;
 
     // Generate a key and grant it to multiple users with GET_INFO|USE permissions.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let mut grant_keys = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = format!("ks_grant_test_key_2{}", getuid());
-            let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
-
-            generate_ec_key_and_grant_to_users(
-                &sl,
-                Some(alias),
-                vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
-                access_vector,
-            )
-            .unwrap()
-        })
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = format!("ks_grant_test_key_2{}", getuid());
+        let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
+
+        generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias),
+            vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap()
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut grant_keys = unsafe { run_as::run_as_root(grantor_fn) };
+
     for (grantee_uid, grantee_gid) in
         &[(GRANTEE_1_UID, GRANTEE_1_GID), (GRANTEE_2_UID, GRANTEE_2_GID)]
     {
         let grant_key_nspace = grant_keys.remove(0);
-        // SAFETY: The test is run in a separate process with no other threads.
-        unsafe {
-            run_as::run_as(
-                GRANTEE_CTX,
-                Uid::from_raw(*grantee_uid),
-                Gid::from_raw(*grantee_gid),
-                move || {
-                    let sl = SecLevel::tee();
-
-                    assert_eq!(
-                        Ok(()),
-                        key_generations::map_ks_error(load_grant_key_and_perform_sign_operation(
-                            &sl,
-                            grant_key_nspace
-                        ))
-                    );
-                },
-            )
+        let grantee_fn = move || {
+            assert_eq!(Ok(()), sign_with_granted_key(grant_key_nspace));
         };
+        // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+        // `--test-threads=1`), and nothing yet done with binder.
+        unsafe { run_as::run_as_app(*grantee_uid, *grantee_gid, grantee_fn) };
     }
 }
 
@@ -662,10 +775,7 @@ fn keystore2_grant_key_to_multi_users_success() {
 /// use the key and delete it. Try to load the granted key in another grantee context. Test should
 /// fail to load the granted key with `KEY_NOT_FOUND` error response.
 #[test]
-fn keystore2_grant_key_to_multi_users_delete_fails_with_key_not_found_error() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
+fn grant_app_key_to_multi_users_delete_then_key_not_found() {
     const USER_ID_1: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_1_UID: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID;
@@ -676,76 +786,50 @@ fn keystore2_grant_key_to_multi_users_delete_fails_with_key_not_found_error() {
     static GRANTEE_2_GID: u32 = GRANTEE_2_UID;
 
     // Generate a key and grant it to multiple users with GET_INFO permission.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let mut grant_keys = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = format!("ks_grant_test_key_2{}", getuid());
-            let access_vector =
-                KeyPermission::GET_INFO.0 | KeyPermission::USE.0 | KeyPermission::DELETE.0;
-
-            generate_ec_key_and_grant_to_users(
-                &sl,
-                Some(alias),
-                vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
-                access_vector,
-            )
-            .unwrap()
-        })
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = format!("ks_grant_test_key_2{}", getuid());
+        let access_vector =
+            KeyPermission::GET_INFO.0 | KeyPermission::USE.0 | KeyPermission::DELETE.0;
+
+        generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias),
+            vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap()
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut grant_keys = unsafe { run_as::run_as_root(grantor_fn) };
+
     // Grantee #1 context
     let grant_key1_nspace = grant_keys.remove(0);
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_1_UID),
-            Gid::from_raw(GRANTEE_1_GID),
-            move || {
-                let sl = SecLevel::tee();
-
-                assert_eq!(
-                    Ok(()),
-                    key_generations::map_ks_error(load_grant_key_and_perform_sign_operation(
-                        &sl,
-                        grant_key1_nspace
-                    ))
-                );
-
-                // Delete the granted key.
-                sl.keystore2
-                    .deleteKey(&KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: grant_key1_nspace,
-                        alias: None,
-                        blob: None,
-                    })
-                    .unwrap();
-            },
-        )
+    let grantee1_fn = move || {
+        assert_eq!(Ok(()), sign_with_granted_key(grant_key1_nspace));
+
+        // Delete the granted key.
+        get_keystore_service().deleteKey(&granted_key_descriptor(grant_key1_nspace)).unwrap();
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_1_UID, GRANTEE_1_GID, grantee1_fn) };
+
     // Grantee #2 context
     let grant_key2_nspace = grant_keys.remove(0);
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_2_UID),
-            Gid::from_raw(GRANTEE_2_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-
-                let result = key_generations::map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
-                    domain: Domain::GRANT,
-                    nspace: grant_key2_nspace,
-                    alias: None,
-                    blob: None,
-                }));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
-            },
-        )
+    let grantee2_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let result =
+            map_ks_error(keystore2.getKeyEntry(&granted_key_descriptor(grant_key2_nspace)));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_2_UID, GRANTEE_2_GID, grantee2_fn) };
 }
diff --git a/keystore2/tests/keystore2_client_keystore_engine_tests.rs b/keystore2/tests/keystore2_client_keystore_engine_tests.rs
index 01f8917e..a4d7f2cb 100644
--- a/keystore2/tests/keystore2_client_keystore_engine_tests.rs
+++ b/keystore2/tests/keystore2_client_keystore_engine_tests.rs
@@ -24,7 +24,6 @@ use keystore2_test_utils::ffi_test_utils::perform_crypto_op_using_keystore_engin
 use keystore2_test_utils::{
     authorizations::AuthSetBuilder, get_keystore_service, run_as, SecLevel,
 };
-use nix::unistd::{Gid, Uid};
 use openssl::x509::X509;
 use rustutils::users::AID_USER_OFFSET;
 
@@ -152,80 +151,65 @@ fn perform_crypto_op_using_granted_key(
 }
 
 #[test]
-fn keystore2_perofrm_crypto_op_using_keystore2_engine_rsa_key_success() {
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
-
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn keystore2_perform_crypto_op_using_keystore2_engine_rsa_key_success() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
     // Generate a key and grant it to a user with GET_INFO|USE|DELETE key permissions.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = "keystore2_engine_rsa_key";
-            generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::RSA).unwrap()
-        })
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = "keystore2_engine_rsa_key";
+        generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::RSA).unwrap()
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // In grantee context load the key and try to perform crypto operation.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-                perform_crypto_op_using_granted_key(&keystore2, grant_key_nspace);
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        perform_crypto_op_using_granted_key(&keystore2, grant_key_nspace);
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
 
 #[test]
-fn keystore2_perofrm_crypto_op_using_keystore2_engine_ec_key_success() {
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
-
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn keystore2_perform_crypto_op_using_keystore2_engine_ec_key_success() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
     // Generate a key and grant it to a user with GET_INFO|USE|DELETE key permissions.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = "keystore2_engine_ec_test_key";
-            generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::EC).unwrap()
-        })
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = "keystore2_engine_ec_test_key";
+        generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::EC).unwrap()
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // In grantee context load the key and try to perform crypto operation.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-                perform_crypto_op_using_granted_key(&keystore2, grant_key_nspace);
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        perform_crypto_op_using_granted_key(&keystore2, grant_key_nspace);
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
 
 #[test]
-fn keystore2_perofrm_crypto_op_using_keystore2_engine_pem_pub_key_success() {
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
-
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+fn keystore2_perform_crypto_op_using_keystore2_engine_pem_pub_key_success() {
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
@@ -233,46 +217,43 @@ fn keystore2_perofrm_crypto_op_using_keystore2_engine_pem_pub_key_success() {
 
     // Generate a key and re-encode it's certificate as PEM and update it and
     // grant it to a user with GET_INFO|USE|DELETE key permissions.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let grant_key_nspace = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = "keystore2_engine_rsa_pem_pub_key";
-            let grant_key_nspace =
-                generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::RSA).unwrap();
-
-            // Update certificate with encodeed PEM data.
-            let key_entry_response = sl
-                .keystore2
-                .getKeyEntry(&KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(alias.to_string()),
-                    blob: None,
-                })
-                .unwrap();
-            let cert_bytes = key_entry_response.metadata.certificate.as_ref().unwrap();
-            let cert = X509::from_der(cert_bytes.as_ref()).unwrap();
-            let cert_pem = cert.to_pem().unwrap();
-            sl.keystore2
-                .updateSubcomponent(&key_entry_response.metadata.key, Some(&cert_pem), None)
-                .expect("updateSubcomponent failed.");
-
-            grant_key_nspace
-        })
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = "keystore2_engine_rsa_pem_pub_key";
+        let grant_key_nspace =
+            generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::RSA).unwrap();
+
+        // Update certificate with encodeed PEM data.
+        let key_entry_response = sl
+            .keystore2
+            .getKeyEntry(&KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(alias.to_string()),
+                blob: None,
+            })
+            .unwrap();
+        let cert_bytes = key_entry_response.metadata.certificate.as_ref().unwrap();
+        let cert = X509::from_der(cert_bytes.as_ref()).unwrap();
+        let cert_pem = cert.to_pem().unwrap();
+        sl.keystore2
+            .updateSubcomponent(&key_entry_response.metadata.key, Some(&cert_pem), None)
+            .expect("updateSubcomponent failed.");
+
+        grant_key_nspace
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };
+
     // In grantee context load the key and try to perform crypto operation.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-                perform_crypto_op_using_granted_key(&keystore2, grant_key_nspace);
-            },
-        )
+    let grantee_fn = move || {
+        let keystore2 = get_keystore_service();
+        perform_crypto_op_using_granted_key(&keystore2, grant_key_nspace);
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
 }
diff --git a/keystore2/tests/keystore2_client_list_entries_tests.rs b/keystore2/tests/keystore2_client_list_entries_tests.rs
index 539dac2d..bb1d6cff 100644
--- a/keystore2/tests/keystore2_client_list_entries_tests.rs
+++ b/keystore2/tests/keystore2_client_list_entries_tests.rs
@@ -20,7 +20,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 use keystore2_test_utils::{
     get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
 };
-use nix::unistd::{getuid, Gid, Uid};
+use nix::unistd::getuid;
 use rustutils::users::AID_USER_OFFSET;
 use std::collections::HashSet;
 use std::fmt::Write;
@@ -51,103 +51,97 @@ fn key_alias_exists(
 ///    context. GRANT keys shouldn't be part of this list.
 #[test]
 fn keystore2_list_entries_success() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID: u32 = 91;
     const APPLICATION_ID: u32 = 10006;
     static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static GRANTEE_GID: u32 = GRANTEE_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-
-            let alias = format!("list_entries_grant_key1_{}", getuid());
-
-            // Make sure there is no key exist with this `alias` in `SELINUX` domain and
-            // `SELINUX_SHELL_NAMESPACE` namespace.
-            if key_alias_exists(
-                &sl.keystore2,
-                Domain::SELINUX,
-                key_generations::SELINUX_SHELL_NAMESPACE,
-                alias.to_string(),
-            ) {
-                sl.keystore2
-                    .deleteKey(&KeyDescriptor {
-                        domain: Domain::SELINUX,
-                        nspace: key_generations::SELINUX_SHELL_NAMESPACE,
-                        alias: Some(alias.to_string()),
-                        blob: None,
-                    })
-                    .unwrap();
-            }
-
-            // Generate a key with above defined `alias`.
-            let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sl,
-                Domain::SELINUX,
-                key_generations::SELINUX_SHELL_NAMESPACE,
-                Some(alias.to_string()),
-                None,
-            )
-            .unwrap();
+    let gen_key_fn = || {
+        let sl = SecLevel::tee();
+
+        let alias = format!("list_entries_grant_key1_{}", getuid());
 
-            // Verify that above generated key entry is listed with domain SELINUX and
-            // namespace SELINUX_SHELL_NAMESPACE
-            assert!(key_alias_exists(
-                &sl.keystore2,
-                Domain::SELINUX,
-                key_generations::SELINUX_SHELL_NAMESPACE,
-                alias,
-            ));
-
-            // Grant a key with GET_INFO permission.
-            let access_vector = KeyPermission::GET_INFO.0;
+        // Make sure there is no key exist with this `alias` in `SELINUX` domain and
+        // `SELINUX_SHELL_NAMESPACE` namespace.
+        if key_alias_exists(
+            &sl.keystore2,
+            Domain::SELINUX,
+            key_generations::SELINUX_SHELL_NAMESPACE,
+            alias.to_string(),
+        ) {
             sl.keystore2
-                .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
+                .deleteKey(&KeyDescriptor {
+                    domain: Domain::SELINUX,
+                    nspace: key_generations::SELINUX_SHELL_NAMESPACE,
+                    alias: Some(alias.to_string()),
+                    blob: None,
+                })
                 .unwrap();
-        })
+        }
+
+        // Generate a key with above defined `alias`.
+        let key_metadata = key_generations::generate_ec_p256_signing_key(
+            &sl,
+            Domain::SELINUX,
+            key_generations::SELINUX_SHELL_NAMESPACE,
+            Some(alias.to_string()),
+            None,
+        )
+        .unwrap();
+
+        // Verify that above generated key entry is listed with domain SELINUX and
+        // namespace SELINUX_SHELL_NAMESPACE
+        assert!(key_alias_exists(
+            &sl.keystore2,
+            Domain::SELINUX,
+            key_generations::SELINUX_SHELL_NAMESPACE,
+            alias,
+        ));
+
+        // Grant a key with GET_INFO permission.
+        let access_vector = KeyPermission::GET_INFO.0;
+        sl.keystore2
+            .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
+            .unwrap();
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_root(gen_key_fn) };
+
     // In user context validate list of key entries associated with it.
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_UID),
-            Gid::from_raw(GRANTEE_GID),
-            move || {
-                let sl = SecLevel::tee();
-                let alias = format!("list_entries_success_key{}", getuid());
-
-                let key_metadata = key_generations::generate_ec_p256_signing_key(
-                    &sl,
-                    Domain::APP,
-                    -1,
-                    Some(alias.to_string()),
-                    None,
-                )
-                .unwrap();
+    let list_keys_fn = move || {
+        let sl = SecLevel::tee();
+        let alias = format!("list_entries_success_key{}", getuid());
+
+        let key_metadata = key_generations::generate_ec_p256_signing_key(
+            &sl,
+            Domain::APP,
+            -1,
+            Some(alias.to_string()),
+            None,
+        )
+        .unwrap();
 
-                // Make sure there is only one key entry exist and that should be the same key
-                // generated in this user context. Granted key shouldn't be included in this list.
-                let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
-                assert_eq!(1, key_descriptors.len());
+        // Make sure there is only one existing key entry and that should be the same key
+        // generated in this user context. Granted key shouldn't be included in this list.
+        let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
+        assert_eq!(1, key_descriptors.len());
 
-                let key = key_descriptors.first().unwrap();
-                assert_eq!(key.alias, Some(alias));
-                assert_eq!(key.nspace, GRANTEE_UID.try_into().unwrap());
-                assert_eq!(key.domain, Domain::APP);
+        let key = key_descriptors.first().unwrap();
+        assert_eq!(key.alias, Some(alias));
+        assert_eq!(key.nspace, GRANTEE_UID.try_into().unwrap());
+        assert_eq!(key.domain, Domain::APP);
 
-                sl.keystore2.deleteKey(&key_metadata.key).unwrap();
+        sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 
-                let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
-                assert_eq!(0, key_descriptors.len());
-            },
-        )
+        let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
+        assert_eq!(0, key_descriptors.len());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, list_keys_fn) };
 }
 
 /// Try to list the key entries with domain SELINUX from user context where user doesn't possesses
@@ -157,20 +151,19 @@ fn keystore2_list_entries_success() {
 fn keystore2_list_entries_fails_perm_denied() {
     let auid = 91 * AID_USER_OFFSET + 10001;
     let agid = 91 * AID_USER_OFFSET + 10001;
-    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(auid), Gid::from_raw(agid), move || {
-            let keystore2 = get_keystore_service();
-
-            let result = key_generations::map_ks_error(
-                keystore2.listEntries(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE),
-            );
-            assert!(result.is_err());
-            assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-        })
+    let list_keys_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let result = key_generations::map_ks_error(
+            keystore2.listEntries(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE),
+        );
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(auid, agid, list_keys_fn) };
 }
 
 /// Try to list key entries with domain BLOB. Test should fail with error repose code
@@ -190,64 +183,63 @@ fn keystore2_list_entries_fails_invalid_arg() {
 /// of all the entries in the keystore.
 #[test]
 fn keystore2_list_entries_with_long_aliases_success() {
-    static CLIENT_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID: u32 = 92;
     const APPLICATION_ID: u32 = 10002;
     static CLIENT_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static CLIENT_GID: u32 = CLIENT_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let sl = SecLevel::tee();
-
-            // Make sure there are no keystore entries exist before adding new entries.
+    let import_keys_fn = || {
+        let sl = SecLevel::tee();
+
+        // Make sure there are no keystore entries exist before adding new entries.
+        let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
+        if !key_descriptors.is_empty() {
+            key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
+                delete_app_key(&sl.keystore2, &alias).unwrap();
+            });
+        }
+
+        let mut imported_key_aliases = HashSet::new();
+
+        // Import 100 keys with aliases of length 6000.
+        for count in 1..101 {
+            let mut alias = String::new();
+            write!(alias, "{}_{}", "X".repeat(6000), count).unwrap();
+            imported_key_aliases.insert(alias.clone());
+
+            let result = key_generations::import_aes_key(&sl, Domain::APP, -1, Some(alias));
+            assert!(result.is_ok());
+        }
+
+        // b/222287335 Limiting Keystore `listEntries` API to return subset of the Keystore
+        // entries to avoid running out of binder buffer space.
+        // To verify that all the imported key aliases are present in Keystore,
+        //  - get the list of entries from Keystore
+        //  - check whether the retrieved key entries list is a subset of imported key aliases
+        //  - delete this subset of keystore entries from Keystore as well as from imported
+        //    list of key aliases
+        //  - continue above steps till it cleanup all the imported keystore entries.
+        while !imported_key_aliases.is_empty() {
             let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
-            if !key_descriptors.is_empty() {
-                key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
-                    delete_app_key(&sl.keystore2, &alias).unwrap();
-                });
-            }
-
-            let mut imported_key_aliases = HashSet::new();
-
-            // Import 100 keys with aliases of length 6000.
-            for count in 1..101 {
-                let mut alias = String::new();
-                write!(alias, "{}_{}", "X".repeat(6000), count).unwrap();
-                imported_key_aliases.insert(alias.clone());
-
-                let result = key_generations::import_aes_key(&sl, Domain::APP, -1, Some(alias));
-                assert!(result.is_ok());
-            }
-
-            // b/222287335 Limiting Keystore `listEntries` API to return subset of the Keystore
-            // entries to avoid running out of binder buffer space.
-            // To verify that all the imported key aliases are present in Keystore,
-            //  - get the list of entries from Keystore
-            //  - check whether the retrieved key entries list is a subset of imported key aliases
-            //  - delete this subset of keystore entries from Keystore as well as from imported
-            //    list of key aliases
-            //  - continue above steps till it cleanup all the imported keystore entries.
-            while !imported_key_aliases.is_empty() {
-                let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
-
-                // Check retrieved key entries list is a subset of imported keys list.
-                assert!(key_descriptors
-                    .iter()
-                    .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
-
-                // Delete the listed key entries from Keystore as well as from imported keys list.
-                key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
-                    delete_app_key(&sl.keystore2, &alias).unwrap();
-                    assert!(imported_key_aliases.remove(&alias));
-                });
-            }
-
-            assert!(imported_key_aliases.is_empty());
-        })
+
+            // Check retrieved key entries list is a subset of imported keys list.
+            assert!(key_descriptors
+                .iter()
+                .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
+
+            // Delete the listed key entries from Keystore as well as from imported keys list.
+            key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
+                delete_app_key(&sl.keystore2, &alias).unwrap();
+                assert!(imported_key_aliases.remove(&alias));
+            });
+        }
+
+        assert!(imported_key_aliases.is_empty());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(CLIENT_UID, CLIENT_GID, import_keys_fn) };
 }
 
 /// Import large number of Keystore entries with long aliases such that the
@@ -255,58 +247,57 @@ fn keystore2_list_entries_with_long_aliases_success() {
 /// Try to list aliases of all the entries in the keystore using `listEntriesBatched` API.
 #[test]
 fn keystore2_list_entries_batched_with_long_aliases_success() {
-    static CLIENT_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID: u32 = 92;
     const APPLICATION_ID: u32 = 10002;
     static CLIENT_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static CLIENT_GID: u32 = CLIENT_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let sl = SecLevel::tee();
-
-            // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&sl.keystore2);
-
-            // Import 100 keys with aliases of length 6000.
-            let mut imported_key_aliases =
-                key_generations::import_aes_keys(&sl, "X".repeat(6000), 1..101).unwrap();
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                100,
-                "Error while importing keys"
-            );
-
-            let mut start_past_alias = None;
-            let mut alias;
-            while !imported_key_aliases.is_empty() {
-                let key_descriptors =
-                    sl.keystore2.listEntriesBatched(Domain::APP, -1, start_past_alias).unwrap();
-
-                // Check retrieved key entries list is a subset of imported keys list.
-                assert!(key_descriptors
-                    .iter()
-                    .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
-
-                alias = key_descriptors.last().unwrap().alias.clone().unwrap();
-                start_past_alias = Some(alias.as_ref());
-                // Delete the listed key entries from imported keys list.
-                key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
-                    assert!(imported_key_aliases.remove(&alias));
-                });
-            }
-
-            assert!(imported_key_aliases.is_empty());
-            delete_all_entries(&sl.keystore2);
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                0,
-                "Error while doing cleanup"
-            );
-        })
+    let import_keys_fn = || {
+        let sl = SecLevel::tee();
+
+        // Make sure there are no keystore entries exist before adding new entries.
+        delete_all_entries(&sl.keystore2);
+
+        // Import 100 keys with aliases of length 6000.
+        let mut imported_key_aliases =
+            key_generations::import_aes_keys(&sl, "X".repeat(6000), 1..101).unwrap();
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            100,
+            "Error while importing keys"
+        );
+
+        let mut start_past_alias = None;
+        let mut alias;
+        while !imported_key_aliases.is_empty() {
+            let key_descriptors =
+                sl.keystore2.listEntriesBatched(Domain::APP, -1, start_past_alias).unwrap();
+
+            // Check retrieved key entries list is a subset of imported keys list.
+            assert!(key_descriptors
+                .iter()
+                .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
+
+            alias = key_descriptors.last().unwrap().alias.clone().unwrap();
+            start_past_alias = Some(alias.as_ref());
+            // Delete the listed key entries from imported keys list.
+            key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
+                assert!(imported_key_aliases.remove(&alias));
+            });
+        }
+
+        assert!(imported_key_aliases.is_empty());
+        delete_all_entries(&sl.keystore2);
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            0,
+            "Error while doing cleanup"
+        );
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(CLIENT_UID, CLIENT_GID, import_keys_fn) };
 }
 
 /// Import keys from multiple processes with same user context and try to list the keystore entries
@@ -321,128 +312,127 @@ fn keystore2_list_entries_batched_with_long_aliases_success() {
 ///    `startingPastAlias` as None. It should list all the keys imported in process-1 and process-2.
 #[test]
 fn keystore2_list_entries_batched_with_multi_procs_success() {
-    static CLIENT_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID: u32 = 92;
     const APPLICATION_ID: u32 = 10002;
     static CLIENT_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static CLIENT_GID: u32 = CLIENT_UID;
     static ALIAS_PREFIX: &str = "key_test_batch_list";
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let sl = SecLevel::tee();
-
-            // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&sl.keystore2);
-
-            // Import 3 keys with below aliases -
-            // [key_test_batch_list_1, key_test_batch_list_2, key_test_batch_list_3]
-            let imported_key_aliases =
-                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 1..4).unwrap();
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                3,
-                "Error while importing keys"
-            );
-
-            // List all entries in keystore for this user-id.
-            let key_descriptors = sl.keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
-            assert_eq!(key_descriptors.len(), 3);
-
-            // Makes sure all listed aliases are matching with imported keys aliases.
-            assert!(key_descriptors
-                .iter()
-                .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
-        })
+    let import_keys_fn = || {
+        let sl = SecLevel::tee();
+
+        // Make sure there are no keystore entries exist before adding new entries.
+        delete_all_entries(&sl.keystore2);
+
+        // Import 3 keys with below aliases -
+        // [key_test_batch_list_1, key_test_batch_list_2, key_test_batch_list_3]
+        let imported_key_aliases =
+            key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 1..4).unwrap();
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            3,
+            "Error while importing keys"
+        );
+
+        // List all entries in keystore for this user-id.
+        let key_descriptors = sl.keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
+        assert_eq!(key_descriptors.len(), 3);
+
+        // Makes sure all listed aliases are matching with imported keys aliases.
+        assert!(key_descriptors
+            .iter()
+            .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
     };
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let sl = SecLevel::tee();
-
-            // Import another 5 keys with below aliases -
-            // [ key_test_batch_list_4, key_test_batch_list_5, key_test_batch_list_6,
-            //   key_test_batch_list_7, key_test_batch_list_8 ]
-            let mut imported_key_aliases =
-                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 4..9).unwrap();
-
-            // Above context already 3 keys are imported, in this context 5 keys are imported,
-            // total 8 keystore entries are expected to be present in Keystore for this user-id.
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                8,
-                "Error while importing keys"
-            );
-
-            // List keystore entries with `start_past_alias` as "key_test_batch_list_3".
-            // `listEntriesBatched` should list all the keystore entries with
-            // alias > "key_test_batch_list_3".
-            let key_descriptors = sl
-                .keystore2
-                .listEntriesBatched(Domain::APP, -1, Some("key_test_batch_list_3"))
-                .unwrap();
-            assert_eq!(key_descriptors.len(), 5);
-
-            // Make sure above listed aliases are matching with imported keys aliases.
-            assert!(key_descriptors
-                .iter()
-                .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
-
-            // List all keystore entries with `start_past_alias` as `None`.
-            // `listEntriesBatched` should list all the keystore entries.
-            let key_descriptors = sl.keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
-            assert_eq!(key_descriptors.len(), 8);
-
-            // Include previously imported keys aliases as well
-            imported_key_aliases.insert(ALIAS_PREFIX.to_owned() + "_1");
-            imported_key_aliases.insert(ALIAS_PREFIX.to_owned() + "_2");
-            imported_key_aliases.insert(ALIAS_PREFIX.to_owned() + "_3");
-
-            // Make sure all the above listed aliases are matching with imported keys aliases.
-            assert!(key_descriptors
-                .iter()
-                .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
-
-            delete_all_entries(&sl.keystore2);
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                0,
-                "Error while doing cleanup"
-            );
-        })
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(CLIENT_UID, CLIENT_GID, import_keys_fn) };
+
+    let import_more_fn = || {
+        let sl = SecLevel::tee();
+
+        // Import another 5 keys with below aliases -
+        // [ key_test_batch_list_4, key_test_batch_list_5, key_test_batch_list_6,
+        //   key_test_batch_list_7, key_test_batch_list_8 ]
+        let mut imported_key_aliases =
+            key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 4..9).unwrap();
+
+        // Above context already 3 keys are imported, in this context 5 keys are imported,
+        // total 8 keystore entries are expected to be present in Keystore for this user-id.
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            8,
+            "Error while importing keys"
+        );
+
+        // List keystore entries with `start_past_alias` as "key_test_batch_list_3".
+        // `listEntriesBatched` should list all the keystore entries with
+        // alias > "key_test_batch_list_3".
+        let key_descriptors = sl
+            .keystore2
+            .listEntriesBatched(Domain::APP, -1, Some("key_test_batch_list_3"))
+            .unwrap();
+        assert_eq!(key_descriptors.len(), 5);
+
+        // Make sure above listed aliases are matching with imported keys aliases.
+        assert!(key_descriptors
+            .iter()
+            .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
+
+        // List all keystore entries with `start_past_alias` as `None`.
+        // `listEntriesBatched` should list all the keystore entries.
+        let key_descriptors = sl.keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
+        assert_eq!(key_descriptors.len(), 8);
+
+        // Include previously imported keys aliases as well
+        imported_key_aliases.insert(ALIAS_PREFIX.to_owned() + "_1");
+        imported_key_aliases.insert(ALIAS_PREFIX.to_owned() + "_2");
+        imported_key_aliases.insert(ALIAS_PREFIX.to_owned() + "_3");
+
+        // Make sure all the above listed aliases are matching with imported keys aliases.
+        assert!(key_descriptors
+            .iter()
+            .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
+
+        delete_all_entries(&sl.keystore2);
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            0,
+            "Error while doing cleanup"
+        );
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(CLIENT_UID, CLIENT_GID, import_more_fn) };
 }
 
 #[test]
 fn keystore2_list_entries_batched_with_empty_keystore_success() {
-    static CLIENT_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID: u32 = 92;
     const APPLICATION_ID: u32 = 10002;
     static CLIENT_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static CLIENT_GID: u32 = CLIENT_UID;
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let keystore2 = get_keystore_service();
+    let list_keys_fn = || {
+        let keystore2 = get_keystore_service();
 
-            // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&keystore2);
+        // Make sure there are no keystore entries exist before adding new entries.
+        delete_all_entries(&keystore2);
 
-            // List all entries in keystore for this user-id, pass startingPastAlias = None
-            let key_descriptors = keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
-            assert_eq!(key_descriptors.len(), 0);
+        // List all entries in keystore for this user-id, pass startingPastAlias = None
+        let key_descriptors = keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
+        assert_eq!(key_descriptors.len(), 0);
 
-            // List all entries in keystore for this user-id, pass startingPastAlias = <random value>
-            let key_descriptors =
-                keystore2.listEntriesBatched(Domain::APP, -1, Some("startingPastAlias")).unwrap();
-            assert_eq!(key_descriptors.len(), 0);
-        })
+        // List all entries in keystore for this user-id, pass startingPastAlias = <random value>
+        let key_descriptors =
+            keystore2.listEntriesBatched(Domain::APP, -1, Some("startingPastAlias")).unwrap();
+        assert_eq!(key_descriptors.len(), 0);
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(CLIENT_UID, CLIENT_GID, list_keys_fn) };
 }
 
 /// Import a key with SELINUX as domain, list aliases using `listEntriesBatched`.
@@ -502,140 +492,135 @@ fn keystore2_list_entries_batched_with_selinux_domain_success() {
 
 #[test]
 fn keystore2_list_entries_batched_validate_count_and_order_success() {
-    static CLIENT_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID: u32 = 92;
     const APPLICATION_ID: u32 = 10002;
     static CLIENT_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     static CLIENT_GID: u32 = CLIENT_UID;
     static ALIAS_PREFIX: &str = "key_test_batch_list";
 
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let sl = SecLevel::tee();
-
-            // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&sl.keystore2);
-
-            // Import keys with below mentioned aliases -
-            // [
-            //   key_test_batch_list_1,
-            //   key_test_batch_list_2,
-            //   key_test_batch_list_3,
-            //   key_test_batch_list_4,
-            //   key_test_batch_list_5,
-            //   key_test_batch_list_10,
-            //   key_test_batch_list_11,
-            //   key_test_batch_list_12,
-            //   key_test_batch_list_21,
-            //   key_test_batch_list_22,
-            // ]
-            let _imported_key_aliases =
-                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 1..6).unwrap();
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                5,
-                "Error while importing keys"
-            );
-            let _imported_key_aliases =
-                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 10..13).unwrap();
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                8,
-                "Error while importing keys"
-            );
-            let _imported_key_aliases =
-                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 21..23).unwrap();
-            assert_eq!(
-                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
-                10,
-                "Error while importing keys"
-            );
-
-            // List the aliases using given `startingPastAlias` and verify the listed
-            // aliases with the expected list of aliases.
-            verify_aliases(
-                &sl.keystore2,
-                Some(format!("{}{}", ALIAS_PREFIX, "_5").as_str()),
-                vec![],
-            );
-
-            verify_aliases(
-                &sl.keystore2,
-                Some(format!("{}{}", ALIAS_PREFIX, "_4").as_str()),
-                vec![ALIAS_PREFIX.to_owned() + "_5"],
-            );
-
-            verify_aliases(
-                &sl.keystore2,
-                Some(format!("{}{}", ALIAS_PREFIX, "_3").as_str()),
-                vec![ALIAS_PREFIX.to_owned() + "_4", ALIAS_PREFIX.to_owned() + "_5"],
-            );
-
-            verify_aliases(
-                &sl.keystore2,
-                Some(format!("{}{}", ALIAS_PREFIX, "_2").as_str()),
-                vec![
-                    ALIAS_PREFIX.to_owned() + "_21",
-                    ALIAS_PREFIX.to_owned() + "_22",
-                    ALIAS_PREFIX.to_owned() + "_3",
-                    ALIAS_PREFIX.to_owned() + "_4",
-                    ALIAS_PREFIX.to_owned() + "_5",
-                ],
-            );
-
-            verify_aliases(
-                &sl.keystore2,
-                Some(format!("{}{}", ALIAS_PREFIX, "_1").as_str()),
-                vec![
-                    ALIAS_PREFIX.to_owned() + "_10",
-                    ALIAS_PREFIX.to_owned() + "_11",
-                    ALIAS_PREFIX.to_owned() + "_12",
-                    ALIAS_PREFIX.to_owned() + "_2",
-                    ALIAS_PREFIX.to_owned() + "_21",
-                    ALIAS_PREFIX.to_owned() + "_22",
-                    ALIAS_PREFIX.to_owned() + "_3",
-                    ALIAS_PREFIX.to_owned() + "_4",
-                    ALIAS_PREFIX.to_owned() + "_5",
-                ],
-            );
-
-            verify_aliases(
-                &sl.keystore2,
-                Some(ALIAS_PREFIX),
-                vec![
-                    ALIAS_PREFIX.to_owned() + "_1",
-                    ALIAS_PREFIX.to_owned() + "_10",
-                    ALIAS_PREFIX.to_owned() + "_11",
-                    ALIAS_PREFIX.to_owned() + "_12",
-                    ALIAS_PREFIX.to_owned() + "_2",
-                    ALIAS_PREFIX.to_owned() + "_21",
-                    ALIAS_PREFIX.to_owned() + "_22",
-                    ALIAS_PREFIX.to_owned() + "_3",
-                    ALIAS_PREFIX.to_owned() + "_4",
-                    ALIAS_PREFIX.to_owned() + "_5",
-                ],
-            );
-
-            verify_aliases(
-                &sl.keystore2,
-                None,
-                vec![
-                    ALIAS_PREFIX.to_owned() + "_1",
-                    ALIAS_PREFIX.to_owned() + "_10",
-                    ALIAS_PREFIX.to_owned() + "_11",
-                    ALIAS_PREFIX.to_owned() + "_12",
-                    ALIAS_PREFIX.to_owned() + "_2",
-                    ALIAS_PREFIX.to_owned() + "_21",
-                    ALIAS_PREFIX.to_owned() + "_22",
-                    ALIAS_PREFIX.to_owned() + "_3",
-                    ALIAS_PREFIX.to_owned() + "_4",
-                    ALIAS_PREFIX.to_owned() + "_5",
-                ],
-            );
-        })
+    let list_keys_fn = || {
+        let sl = SecLevel::tee();
+
+        // Make sure there are no keystore entries exist before adding new entries.
+        delete_all_entries(&sl.keystore2);
+
+        // Import keys with below mentioned aliases -
+        // [
+        //   key_test_batch_list_1,
+        //   key_test_batch_list_2,
+        //   key_test_batch_list_3,
+        //   key_test_batch_list_4,
+        //   key_test_batch_list_5,
+        //   key_test_batch_list_10,
+        //   key_test_batch_list_11,
+        //   key_test_batch_list_12,
+        //   key_test_batch_list_21,
+        //   key_test_batch_list_22,
+        // ]
+        let _imported_key_aliases =
+            key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 1..6).unwrap();
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            5,
+            "Error while importing keys"
+        );
+        let _imported_key_aliases =
+            key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 10..13).unwrap();
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            8,
+            "Error while importing keys"
+        );
+        let _imported_key_aliases =
+            key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 21..23).unwrap();
+        assert_eq!(
+            sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+            10,
+            "Error while importing keys"
+        );
+
+        // List the aliases using given `startingPastAlias` and verify the listed
+        // aliases with the expected list of aliases.
+        verify_aliases(&sl.keystore2, Some(format!("{}{}", ALIAS_PREFIX, "_5").as_str()), vec![]);
+
+        verify_aliases(
+            &sl.keystore2,
+            Some(format!("{}{}", ALIAS_PREFIX, "_4").as_str()),
+            vec![ALIAS_PREFIX.to_owned() + "_5"],
+        );
+
+        verify_aliases(
+            &sl.keystore2,
+            Some(format!("{}{}", ALIAS_PREFIX, "_3").as_str()),
+            vec![ALIAS_PREFIX.to_owned() + "_4", ALIAS_PREFIX.to_owned() + "_5"],
+        );
+
+        verify_aliases(
+            &sl.keystore2,
+            Some(format!("{}{}", ALIAS_PREFIX, "_2").as_str()),
+            vec![
+                ALIAS_PREFIX.to_owned() + "_21",
+                ALIAS_PREFIX.to_owned() + "_22",
+                ALIAS_PREFIX.to_owned() + "_3",
+                ALIAS_PREFIX.to_owned() + "_4",
+                ALIAS_PREFIX.to_owned() + "_5",
+            ],
+        );
+
+        verify_aliases(
+            &sl.keystore2,
+            Some(format!("{}{}", ALIAS_PREFIX, "_1").as_str()),
+            vec![
+                ALIAS_PREFIX.to_owned() + "_10",
+                ALIAS_PREFIX.to_owned() + "_11",
+                ALIAS_PREFIX.to_owned() + "_12",
+                ALIAS_PREFIX.to_owned() + "_2",
+                ALIAS_PREFIX.to_owned() + "_21",
+                ALIAS_PREFIX.to_owned() + "_22",
+                ALIAS_PREFIX.to_owned() + "_3",
+                ALIAS_PREFIX.to_owned() + "_4",
+                ALIAS_PREFIX.to_owned() + "_5",
+            ],
+        );
+
+        verify_aliases(
+            &sl.keystore2,
+            Some(ALIAS_PREFIX),
+            vec![
+                ALIAS_PREFIX.to_owned() + "_1",
+                ALIAS_PREFIX.to_owned() + "_10",
+                ALIAS_PREFIX.to_owned() + "_11",
+                ALIAS_PREFIX.to_owned() + "_12",
+                ALIAS_PREFIX.to_owned() + "_2",
+                ALIAS_PREFIX.to_owned() + "_21",
+                ALIAS_PREFIX.to_owned() + "_22",
+                ALIAS_PREFIX.to_owned() + "_3",
+                ALIAS_PREFIX.to_owned() + "_4",
+                ALIAS_PREFIX.to_owned() + "_5",
+            ],
+        );
+
+        verify_aliases(
+            &sl.keystore2,
+            None,
+            vec![
+                ALIAS_PREFIX.to_owned() + "_1",
+                ALIAS_PREFIX.to_owned() + "_10",
+                ALIAS_PREFIX.to_owned() + "_11",
+                ALIAS_PREFIX.to_owned() + "_12",
+                ALIAS_PREFIX.to_owned() + "_2",
+                ALIAS_PREFIX.to_owned() + "_21",
+                ALIAS_PREFIX.to_owned() + "_22",
+                ALIAS_PREFIX.to_owned() + "_3",
+                ALIAS_PREFIX.to_owned() + "_4",
+                ALIAS_PREFIX.to_owned() + "_5",
+            ],
+        );
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(CLIENT_UID, CLIENT_GID, list_keys_fn) };
 }
 
 /// Try to list the key entries with domain SELINUX from user context where user doesn't possesses
@@ -645,22 +630,21 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
 fn keystore2_list_entries_batched_fails_perm_denied() {
     let auid = 91 * AID_USER_OFFSET + 10001;
     let agid = 91 * AID_USER_OFFSET + 10001;
-    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(auid), Gid::from_raw(agid), move || {
-            let keystore2 = get_keystore_service();
-
-            let result = key_generations::map_ks_error(keystore2.listEntriesBatched(
-                Domain::SELINUX,
-                key_generations::SELINUX_SHELL_NAMESPACE,
-                None,
-            ));
-            assert!(result.is_err());
-            assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-        })
+    let list_keys_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let result = key_generations::map_ks_error(keystore2.listEntriesBatched(
+            Domain::SELINUX,
+            key_generations::SELINUX_SHELL_NAMESPACE,
+            None,
+        ));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(auid, agid, list_keys_fn) };
 }
 
 /// Try to list key entries with domain BLOB. Test should fail with error response code
@@ -685,21 +669,19 @@ fn keystore2_list_entries_batched_fails_invalid_arg() {
 fn keystore2_get_number_of_entries_fails_perm_denied() {
     let auid = 91 * AID_USER_OFFSET + 10001;
     let agid = 91 * AID_USER_OFFSET + 10001;
-    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(auid), Gid::from_raw(agid), move || {
-            let keystore2 = get_keystore_service();
-
-            let result = key_generations::map_ks_error(
-                keystore2
-                    .getNumberOfEntries(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE),
-            );
-            assert!(result.is_err());
-            assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-        })
+    let get_num_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let result = key_generations::map_ks_error(
+            keystore2.getNumberOfEntries(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE),
+        );
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(auid, agid, get_num_fn) };
 }
 
 /// Try to get number of key entries with domain BLOB. Test should fail with error response code
diff --git a/keystore2/tests/keystore2_client_operation_tests.rs b/keystore2/tests/keystore2_client_operation_tests.rs
index 5f640efa..1f8396e2 100644
--- a/keystore2/tests/keystore2_client_operation_tests.rs
+++ b/keystore2/tests/keystore2_client_operation_tests.rs
@@ -40,7 +40,8 @@ use std::thread::JoinHandle;
 ///
 /// # Safety
 ///
-/// Must be called from a process with no other threads.
+/// Must only be called from a single-threaded process (e.g. as enforced by `AndroidTest.xml`
+/// setting `--test-threads=1`).
 pub unsafe fn create_operations(
     target_ctx: &'static str,
     forced_op: ForcedOp,
@@ -50,7 +51,7 @@ pub unsafe fn create_operations(
     let base_gid = 99 * AID_USER_OFFSET + 10001;
     let base_uid = 99 * AID_USER_OFFSET + 10001;
     (0..max_ops)
-        // SAFETY: The caller guarantees that there are no other threads.
+        // Safety: The caller guarantees that there are no other threads.
         .map(|i| unsafe {
             execute_op_run_as_child(
                 target_ctx,
@@ -93,7 +94,8 @@ fn keystore2_backend_busy_test() {
     const MAX_OPS: i32 = 100;
     static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
 
-    // SAFETY: The test is run in a separate process with no other threads.
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     let mut child_handles = unsafe { create_operations(TARGET_CTX, ForcedOp(false), MAX_OPS) };
 
     // Wait until all child procs notifies us to continue,
@@ -127,7 +129,8 @@ fn keystore2_forced_op_after_backendbusy_test() {
     static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
 
     // Create regular operations.
-    // SAFETY: The test is run in a separate process with no other threads.
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     let mut child_handles = unsafe { create_operations(TARGET_CTX, ForcedOp(false), MAX_OPS) };
 
     // Wait until all child procs notifies us to continue, so that there are enough
@@ -139,28 +142,31 @@ fn keystore2_forced_op_after_backendbusy_test() {
     // Create a forced operation.
     let auid = 99 * AID_USER_OFFSET + 10604;
     let agid = 99 * AID_USER_OFFSET + 10604;
-    // SAFETY: The test is run in a separate process with no other threads.
+    let force_op_fn = move || {
+        let alias = format!("ks_prune_forced_op_key_{}", getuid());
+
+        // To make room for this forced op, system should be able to prune one of the
+        // above created regular operations and create a slot for this forced operation
+        // successfully.
+        create_signing_operation(
+            ForcedOp(true),
+            KeyPurpose::SIGN,
+            Digest::SHA_2_256,
+            Domain::SELINUX,
+            100,
+            Some(alias),
+        )
+        .expect("Client failed to create forced operation after BACKEND_BUSY state.");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     unsafe {
         run_as::run_as(
             key_generations::TARGET_VOLD_CTX,
             Uid::from_raw(auid),
             Gid::from_raw(agid),
-            move || {
-                let alias = format!("ks_prune_forced_op_key_{}", getuid());
-
-                // To make room for this forced op, system should be able to prune one of the
-                // above created regular operations and create a slot for this forced operation
-                // successfully.
-                create_signing_operation(
-                    ForcedOp(true),
-                    KeyPurpose::SIGN,
-                    Digest::SHA_2_256,
-                    Domain::SELINUX,
-                    100,
-                    Some(alias),
-                )
-                .expect("Client failed to create forced operation after BACKEND_BUSY state.");
-            },
+            force_op_fn,
         );
     };
 
@@ -212,7 +218,9 @@ fn keystore2_max_forced_ops_test() {
     // Create initial forced operation in a child process
     // and wait for the parent to notify to perform operation.
     let alias = format!("ks_forced_op_key_{}", getuid());
-    // SAFETY: The test is run in a separate process with no other threads.
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     let mut first_op_handle = unsafe {
         execute_op_run_as_child(
             key_generations::TARGET_SU_CTX,
@@ -231,7 +239,8 @@ fn keystore2_max_forced_ops_test() {
 
     // Create MAX_OPS number of forced operations.
     let mut child_handles =
-    // SAFETY: The test is run in a separate process with no other threads.
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
         unsafe { create_operations(key_generations::TARGET_SU_CTX, ForcedOp(true), MAX_OPS) };
 
     // Wait until all child procs notifies us to continue, so that  there are enough operations
@@ -295,7 +304,9 @@ fn keystore2_ops_prune_test() {
     // Create an operation in an untrusted_app context. Wait until the parent notifies to continue.
     // Once the parent notifies, this operation is expected to be completed successfully.
     let alias = format!("ks_reg_op_key_{}", getuid());
-    // SAFETY: The test is run in a separate process with no other threads.
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     let mut child_handle = unsafe {
         execute_op_run_as_child(
             TARGET_CTX,
@@ -393,21 +404,24 @@ fn keystore2_forced_op_perm_denied_test() {
     let gid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
 
     for context in TARGET_CTXS.iter() {
-        // SAFETY: The test is run in a separate process with no other threads.
+        let forced_op_fn = move || {
+            let alias = format!("ks_app_forced_op_test_key_{}", getuid());
+            let result = key_generations::map_ks_error(create_signing_operation(
+                ForcedOp(true),
+                KeyPurpose::SIGN,
+                Digest::SHA_2_256,
+                Domain::APP,
+                -1,
+                Some(alias),
+            ));
+            assert!(result.is_err());
+            assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+        };
+
+        // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+        // `--test-threads=1`), and nothing yet done with binder.
         unsafe {
-            run_as::run_as(context, Uid::from_raw(uid), Gid::from_raw(gid), move || {
-                let alias = format!("ks_app_forced_op_test_key_{}", getuid());
-                let result = key_generations::map_ks_error(create_signing_operation(
-                    ForcedOp(true),
-                    KeyPurpose::SIGN,
-                    Digest::SHA_2_256,
-                    Domain::APP,
-                    -1,
-                    Some(alias),
-                ));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
-            });
+            run_as::run_as(context, Uid::from_raw(uid), Gid::from_raw(gid), forced_op_fn);
         }
     }
 }
@@ -416,27 +430,29 @@ fn keystore2_forced_op_perm_denied_test() {
 /// Should be able to create forced operation with `vold` context successfully.
 #[test]
 fn keystore2_forced_op_success_test() {
-    static TARGET_CTX: &str = "u:r:vold:s0";
+    static TARGET_VOLD_CTX: &str = "u:r:vold:s0";
     const USER_ID: u32 = 99;
     const APPLICATION_ID: u32 = 10601;
 
     let uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
     let gid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
+    let forced_op_fn = move || {
+        let alias = format!("ks_vold_forced_op_key_{}", getuid());
+        create_signing_operation(
+            ForcedOp(true),
+            KeyPurpose::SIGN,
+            Digest::SHA_2_256,
+            Domain::SELINUX,
+            key_generations::SELINUX_VOLD_NAMESPACE,
+            Some(alias),
+        )
+        .expect("Client with vold context failed to create forced operation.");
+    };
 
-    // SAFETY: The test is run in a separate process with no other threads.
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(uid), Gid::from_raw(gid), move || {
-            let alias = format!("ks_vold_forced_op_key_{}", getuid());
-            create_signing_operation(
-                ForcedOp(true),
-                KeyPurpose::SIGN,
-                Digest::SHA_2_256,
-                Domain::SELINUX,
-                key_generations::SELINUX_VOLD_NAMESPACE,
-                Some(alias),
-            )
-            .expect("Client with vold context failed to create forced operation.");
-        });
+        run_as::run_as(TARGET_VOLD_CTX, Uid::from_raw(uid), Gid::from_raw(gid), forced_op_fn);
     }
 }
 
diff --git a/keystore2/tests/keystore2_client_test_utils.rs b/keystore2/tests/keystore2_client_test_utils.rs
index f028a65a..831fc855 100644
--- a/keystore2/tests/keystore2_client_test_utils.rs
+++ b/keystore2/tests/keystore2_client_test_utils.rs
@@ -25,7 +25,11 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 };
 use binder::wait_for_interface;
 use keystore2_test_utils::{
-    authorizations, key_generations, key_generations::Error, run_as, SecLevel,
+    authorizations, key_generations,
+    key_generations::Error,
+    run_as,
+    run_as::{ChannelReader, ChannelWriter},
+    SecLevel,
 };
 use nix::unistd::{Gid, Uid};
 use openssl::bn::BigNum;
@@ -51,10 +55,21 @@ pub enum TestOutcome {
     OtherErr,
 }
 
-/// This is used to notify the child or parent process that the expected state is reched.
+/// This is used to notify the child or parent process that the expected state is reached.
 #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
 pub struct BarrierReached;
 
+/// This is used to notify the child or parent process that the expected state is reached,
+/// passing a value
+#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
+pub struct BarrierReachedWithData<T: Send + Sync>(pub T);
+
+impl<T: Send + Sync> BarrierReachedWithData<T> {
+    pub fn new(val: T) -> Self {
+        Self(val)
+    }
+}
+
 /// Forced operation.
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub struct ForcedOp(pub bool);
@@ -294,7 +309,8 @@ pub fn perform_sample_asym_sign_verify_op(
 ///
 /// # Safety
 ///
-/// Must only be called from a single-threaded process.
+/// Must only be called from a single-threaded process (e.g. as enforced by `AndroidTest.xml`
+/// setting `--test-threads=1`).
 pub unsafe fn execute_op_run_as_child(
     target_ctx: &'static str,
     domain: Domain,
@@ -304,41 +320,44 @@ pub unsafe fn execute_op_run_as_child(
     agid: Gid,
     forced_op: ForcedOp,
 ) -> run_as::ChildHandle<TestOutcome, BarrierReached> {
-    // SAFETY: The caller guarantees that there are no other threads.
-    unsafe {
-        run_as::run_as_child(target_ctx, auid, agid, move |reader, writer| {
-            let result = key_generations::map_ks_error(create_signing_operation(
-                forced_op,
-                KeyPurpose::SIGN,
-                Digest::SHA_2_256,
-                domain,
-                nspace,
-                alias,
-            ));
-
-            // Let the parent know that an operation has been started, then
-            // wait until the parent notifies us to continue, so the operation
-            // remains open.
-            writer.send(&BarrierReached {});
-            reader.recv();
-
-            // Continue performing the operation after parent notifies.
-            match &result {
-                Ok(CreateOperationResponse { iOperation: Some(op), .. }) => {
-                    match key_generations::map_ks_error(perform_sample_sign_operation(op)) {
-                        Ok(()) => TestOutcome::Ok,
-                        Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => {
-                            TestOutcome::InvalidHandle
-                        }
-                        Err(e) => panic!("Error in performing op: {:#?}", e),
+    let child_fn = move |reader: &mut ChannelReader<BarrierReached>,
+                         writer: &mut ChannelWriter<BarrierReached>| {
+        let result = key_generations::map_ks_error(create_signing_operation(
+            forced_op,
+            KeyPurpose::SIGN,
+            Digest::SHA_2_256,
+            domain,
+            nspace,
+            alias,
+        ));
+
+        // Let the parent know that an operation has been started, then
+        // wait until the parent notifies us to continue, so the operation
+        // remains open.
+        writer.send(&BarrierReached {});
+        reader.recv();
+
+        // Continue performing the operation after parent notifies.
+        match &result {
+            Ok(CreateOperationResponse { iOperation: Some(op), .. }) => {
+                match key_generations::map_ks_error(perform_sample_sign_operation(op)) {
+                    Ok(()) => TestOutcome::Ok,
+                    Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => {
+                        TestOutcome::InvalidHandle
                     }
+                    Err(e) => panic!("Error in performing op: {:#?}", e),
                 }
-                Ok(_) => TestOutcome::OtherErr,
-                Err(Error::Rc(ResponseCode::BACKEND_BUSY)) => TestOutcome::BackendBusy,
-                _ => TestOutcome::OtherErr,
             }
-        })
-        .expect("Failed to create an operation.")
+            Ok(_) => TestOutcome::OtherErr,
+            Err(Error::Rc(ResponseCode::BACKEND_BUSY)) => TestOutcome::BackendBusy,
+            _ => TestOutcome::OtherErr,
+        }
+    };
+
+    // Safety: The caller guarantees that there are no other threads.
+    unsafe {
+        run_as::run_as_child(target_ctx, auid, agid, child_fn)
+            .expect("Failed to create an operation.")
     }
 }
 
diff --git a/keystore2/tests/keystore2_client_update_subcomponent_tests.rs b/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
index e25e52a2..0e382988 100644
--- a/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
+++ b/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
@@ -22,7 +22,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 use keystore2_test_utils::{
     get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
 };
-use nix::unistd::{getuid, Gid, Uid};
+use nix::unistd::getuid;
 use rustutils::users::AID_USER_OFFSET;
 
 /// Generate a key and update its public certificate and certificate chain. Test should be able to
@@ -153,9 +153,6 @@ fn keystore2_update_subcomponent_no_key_entry_cert_chain_success() {
 /// permissions, test should be able to update public certificate and cert-chain successfully.
 #[test]
 fn keystore2_update_subcomponent_fails_permission_denied() {
-    static GRANTOR_SU_CTX: &str = "u:r:su:s0";
-    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-
     const USER_ID_1: u32 = 99;
     const APPLICATION_ID: u32 = 10001;
     static GRANTEE_1_UID: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID;
@@ -166,117 +163,102 @@ fn keystore2_update_subcomponent_fails_permission_denied() {
     static GRANTEE_2_GID: u32 = GRANTEE_2_UID;
 
     // Generate a key and grant it to multiple users with different access permissions.
-    // SAFETY: The test is run in a separate process with no other threads.
-    let mut granted_keys = unsafe {
-        run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let sl = SecLevel::tee();
-            let alias = format!("ks_update_subcompo_test_1_{}", getuid());
-            let mut granted_keys = Vec::new();
-
-            let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sl,
-                Domain::APP,
-                -1,
-                Some(alias),
-                None,
-            )
-            .unwrap();
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let alias = format!("ks_update_subcompo_test_1_{}", getuid());
+        let mut granted_keys = Vec::new();
 
-            // Grant a key without update permission.
-            let access_vector = KeyPermission::GET_INFO.0;
-            let granted_key = sl
-                .keystore2
-                .grant(&key_metadata.key, GRANTEE_1_UID.try_into().unwrap(), access_vector)
+        let key_metadata =
+            key_generations::generate_ec_p256_signing_key(&sl, Domain::APP, -1, Some(alias), None)
                 .unwrap();
-            assert_eq!(granted_key.domain, Domain::GRANT);
-            granted_keys.push(granted_key.nspace);
-
-            // Grant a key with update permission.
-            let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::UPDATE.0;
-            let granted_key = sl
-                .keystore2
-                .grant(&key_metadata.key, GRANTEE_2_UID.try_into().unwrap(), access_vector)
-                .unwrap();
-            assert_eq!(granted_key.domain, Domain::GRANT);
-            granted_keys.push(granted_key.nspace);
 
-            granted_keys
-        })
+        // Grant a key without update permission.
+        let access_vector = KeyPermission::GET_INFO.0;
+        let granted_key = sl
+            .keystore2
+            .grant(&key_metadata.key, GRANTEE_1_UID.try_into().unwrap(), access_vector)
+            .unwrap();
+        assert_eq!(granted_key.domain, Domain::GRANT);
+        granted_keys.push(granted_key.nspace);
+
+        // Grant a key with update permission.
+        let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::UPDATE.0;
+        let granted_key = sl
+            .keystore2
+            .grant(&key_metadata.key, GRANTEE_2_UID.try_into().unwrap(), access_vector)
+            .unwrap();
+        assert_eq!(granted_key.domain, Domain::GRANT);
+        granted_keys.push(granted_key.nspace);
+
+        granted_keys
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut granted_keys = unsafe { run_as::run_as_root(grantor_fn) };
+
     // Grantee context, try to update the key public certs, permission denied error is expected.
     let granted_key1_nspace = granted_keys.remove(0);
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_1_UID),
-            Gid::from_raw(GRANTEE_1_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-
-                let other_cert: [u8; 32] = [123; 32];
-                let other_cert_chain: [u8; 32] = [12; 32];
-
-                let result = key_generations::map_ks_error(keystore2.updateSubcomponent(
-                    &KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: granted_key1_nspace,
-                        alias: None,
-                        blob: None,
-                    },
-                    Some(&other_cert),
-                    Some(&other_cert_chain),
-                ));
-                assert!(result.is_err());
-                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+    let grantee1_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let other_cert: [u8; 32] = [123; 32];
+        let other_cert_chain: [u8; 32] = [12; 32];
+
+        let result = key_generations::map_ks_error(keystore2.updateSubcomponent(
+            &KeyDescriptor {
+                domain: Domain::GRANT,
+                nspace: granted_key1_nspace,
+                alias: None,
+                blob: None,
             },
-        )
+            Some(&other_cert),
+            Some(&other_cert_chain),
+        ));
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_1_UID, GRANTEE_1_GID, grantee1_fn) };
+
     // Grantee context, update granted key public certs. Update should happen successfully.
     let granted_key2_nspace = granted_keys.remove(0);
-    // SAFETY: The test is run in a separate process with no other threads.
-    unsafe {
-        run_as::run_as(
-            GRANTEE_CTX,
-            Uid::from_raw(GRANTEE_2_UID),
-            Gid::from_raw(GRANTEE_2_GID),
-            move || {
-                let keystore2 = get_keystore_service();
-
-                let other_cert: [u8; 32] = [124; 32];
-                let other_cert_chain: [u8; 32] = [13; 32];
-
-                keystore2
-                    .updateSubcomponent(
-                        &KeyDescriptor {
-                            domain: Domain::GRANT,
-                            nspace: granted_key2_nspace,
-                            alias: None,
-                            blob: None,
-                        },
-                        Some(&other_cert),
-                        Some(&other_cert_chain),
-                    )
-                    .expect("updateSubcomponent should have succeeded.");
-
-                let key_entry_response = keystore2
-                    .getKeyEntry(&KeyDescriptor {
-                        domain: Domain::GRANT,
-                        nspace: granted_key2_nspace,
-                        alias: None,
-                        blob: None,
-                    })
-                    .unwrap();
-                assert_eq!(Some(other_cert.to_vec()), key_entry_response.metadata.certificate);
-                assert_eq!(
-                    Some(other_cert_chain.to_vec()),
-                    key_entry_response.metadata.certificateChain
-                );
-            },
-        )
+    let grantee2_fn = move || {
+        let keystore2 = get_keystore_service();
+
+        let other_cert: [u8; 32] = [124; 32];
+        let other_cert_chain: [u8; 32] = [13; 32];
+
+        keystore2
+            .updateSubcomponent(
+                &KeyDescriptor {
+                    domain: Domain::GRANT,
+                    nspace: granted_key2_nspace,
+                    alias: None,
+                    blob: None,
+                },
+                Some(&other_cert),
+                Some(&other_cert_chain),
+            )
+            .expect("updateSubcomponent should have succeeded.");
+
+        let key_entry_response = keystore2
+            .getKeyEntry(&KeyDescriptor {
+                domain: Domain::GRANT,
+                nspace: granted_key2_nspace,
+                alias: None,
+                blob: None,
+            })
+            .unwrap();
+        assert_eq!(Some(other_cert.to_vec()), key_entry_response.metadata.certificate);
+        assert_eq!(Some(other_cert_chain.to_vec()), key_entry_response.metadata.certificateChain);
     };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(GRANTEE_2_UID, GRANTEE_2_GID, grantee2_fn) };
 }
 
 #[test]
diff --git a/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs b/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs
index 11a4c0b1..d71f4637 100644
--- a/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs
+++ b/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs
@@ -27,7 +27,7 @@ use keystore2::legacy_blob::LegacyKeyCharacteristics;
 use keystore2::utils::AesGcm;
 use keystore2_crypto::{Password, ZVec};
 use keystore2_test_utils::{get_keystore_service, key_generations, run_as, SecLevel};
-use nix::unistd::{getuid, Gid, Uid};
+use nix::unistd::getuid;
 use rustutils::users::AID_USER_OFFSET;
 use serde::{Deserialize, Serialize};
 use std::ops::Deref;
@@ -128,8 +128,6 @@ fn keystore2_restart_service() {
 fn keystore2_encrypted_characteristics() -> anyhow::Result<()> {
     let auid = 99 * AID_USER_OFFSET + 10001;
     let agid = 99 * AID_USER_OFFSET + 10001;
-    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
 
     // Cleanup user directory if it exists
     let path_buf = PathBuf::from("/data/misc/keystore/user_99");
@@ -137,205 +135,202 @@ fn keystore2_encrypted_characteristics() -> anyhow::Result<()> {
         std::fs::remove_dir_all(path_buf.as_path()).unwrap();
     }
 
-    // Safety: run_as must be called from a single threaded process.
-    // This device test is run as a separate single threaded process.
-    let mut gen_key_result = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            // Remove user if already exist.
-            let maint_service = get_maintenance();
-            match maint_service.onUserRemoved(99) {
-                Ok(_) => {
-                    println!("User was existed, deleted successfully");
-                }
-                Err(e) => {
-                    println!("onUserRemoved error: {:#?}", e);
-                }
+    let gen_key_fn = || {
+        // Remove user if already exist.
+        let maint_service = get_maintenance();
+        match maint_service.onUserRemoved(99) {
+            Ok(_) => {
+                println!("User did exist, deleted successfully");
             }
-            let sl = SecLevel::tee();
-
-            // Generate Key BLOB and prepare legacy keystore blob files.
-            let att_challenge: Option<&[u8]> = if rkp_only() { None } else { Some(b"foo") };
-            let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sl,
-                Domain::BLOB,
-                SELINUX_SHELL_NAMESPACE,
-                None,
-                att_challenge,
-            )
-            .expect("Failed to generate key blob");
+            Err(e) => {
+                println!("onUserRemoved error: {:#?}", e);
+            }
+        }
+        let sl = SecLevel::tee();
+
+        // Generate Key BLOB and prepare legacy keystore blob files.
+        let att_challenge: Option<&[u8]> = if rkp_only() { None } else { Some(b"foo") };
+        let key_metadata = key_generations::generate_ec_p256_signing_key(
+            &sl,
+            Domain::BLOB,
+            SELINUX_SHELL_NAMESPACE,
+            None,
+            att_challenge,
+        )
+        .expect("Failed to generate key blob");
+
+        // Create keystore file layout for user_99.
+        let pw: Password = PASSWORD.into();
+        let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
+        let super_key =
+            TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap());
+
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
+        if !path_buf.as_path().is_dir() {
+            std::fs::create_dir(path_buf.as_path()).unwrap();
+        }
+        path_buf.push(".masterkey");
+        if !path_buf.as_path().is_file() {
+            std::fs::write(path_buf.as_path(), SUPERKEY).unwrap();
+        }
 
-            // Create keystore file layout for user_99.
-            let pw: Password = PASSWORD.into();
-            let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
-            let super_key =
-                TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap());
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
+        path_buf.push("9910001_USRPKEY_authbound");
+        if !path_buf.as_path().is_file() {
+            make_encrypted_key_file(
+                path_buf.as_path(),
+                &super_key,
+                &key_metadata.key.blob.unwrap(),
+            )
+            .unwrap();
+        }
 
-            let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
-            if !path_buf.as_path().is_dir() {
-                std::fs::create_dir(path_buf.as_path()).unwrap();
-            }
-            path_buf.push(".masterkey");
-            if !path_buf.as_path().is_file() {
-                std::fs::write(path_buf.as_path(), SUPERKEY).unwrap();
-            }
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
+        path_buf.push(".9910001_chr_USRPKEY_authbound");
+        if !path_buf.as_path().is_file() {
+            make_encrypted_characteristics_file(path_buf.as_path(), &super_key, KEY_PARAMETERS)
+                .unwrap();
+        }
 
-            let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
-            path_buf.push("9910001_USRPKEY_authbound");
-            if !path_buf.as_path().is_file() {
-                make_encrypted_key_file(
-                    path_buf.as_path(),
-                    &super_key,
-                    &key_metadata.key.blob.unwrap(),
-                )
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
+        path_buf.push("9910001_USRCERT_authbound");
+        if !path_buf.as_path().is_file() {
+            make_cert_blob_file(path_buf.as_path(), key_metadata.certificate.as_ref().unwrap())
                 .unwrap();
-            }
+        }
 
+        if let Some(chain) = key_metadata.certificateChain.as_ref() {
             let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
-            path_buf.push(".9910001_chr_USRPKEY_authbound");
+            path_buf.push("9910001_CACERT_authbound");
             if !path_buf.as_path().is_file() {
-                make_encrypted_characteristics_file(path_buf.as_path(), &super_key, KEY_PARAMETERS)
-                    .unwrap();
+                make_cert_blob_file(path_buf.as_path(), chain).unwrap();
             }
+        }
 
-            let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
-            path_buf.push("9910001_USRCERT_authbound");
-            if !path_buf.as_path().is_file() {
-                make_cert_blob_file(path_buf.as_path(), key_metadata.certificate.as_ref().unwrap())
-                    .unwrap();
-            }
+        // Keystore2 disables the legacy importer when it finds the legacy database empty.
+        // However, if the device boots with an empty legacy database, the optimization kicks in
+        // and keystore2 never checks the legacy file system layout.
+        // So, restart keystore2 service to detect populated legacy database.
+        keystore2_restart_service();
 
-            if let Some(chain) = key_metadata.certificateChain.as_ref() {
-                let mut path_buf = PathBuf::from("/data/misc/keystore/user_99");
-                path_buf.push("9910001_CACERT_authbound");
-                if !path_buf.as_path().is_file() {
-                    make_cert_blob_file(path_buf.as_path(), chain).unwrap();
-                }
+        let auth_service = get_authorization();
+        match auth_service.onDeviceUnlocked(99, Some(PASSWORD)) {
+            Ok(result) => {
+                println!("Unlock Result: {:?}", result);
             }
-
-            // Keystore2 disables the legacy importer when it finds the legacy database empty.
-            // However, if the device boots with an empty legacy database, the optimization kicks in
-            // and keystore2 never checks the legacy file system layout.
-            // So, restart keystore2 service to detect populated legacy database.
-            keystore2_restart_service();
-
-            let auth_service = get_authorization();
-            match auth_service.onDeviceUnlocked(99, Some(PASSWORD)) {
-                Ok(result) => {
-                    println!("Unlock Result: {:?}", result);
-                }
-                Err(e) => {
-                    panic!("Unlock should have succeeded: {:?}", e);
-                }
+            Err(e) => {
+                panic!("Unlock should have succeeded: {:?}", e);
             }
+        }
 
-            let mut key_params: Vec<KsKeyparameter> = Vec::new();
-            for param in key_metadata.authorizations {
-                let key_param = KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
-                key_params.push(key_param);
-            }
+        let mut key_params: Vec<KsKeyparameter> = Vec::new();
+        for param in key_metadata.authorizations {
+            let key_param = KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
+            key_params.push(key_param);
+        }
 
-            KeygenResult {
-                cert: key_metadata.certificate.unwrap(),
-                cert_chain: key_metadata.certificateChain.unwrap_or_default(),
-                key_parameters: key_params,
-            }
-        })
+        KeygenResult {
+            cert: key_metadata.certificate.unwrap(),
+            cert_chain: key_metadata.certificateChain.unwrap_or_default(),
+            key_parameters: key_params,
+        }
     };
 
-    // Safety: run_as must be called from a single threaded process.
-    // This device test is run as a separate single threaded process.
-    unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(auid), Gid::from_raw(agid), move || {
-            println!("UID: {}", getuid());
-            println!("Android User ID: {}", rustutils::users::multiuser_get_user_id(9910001));
-            println!("Android app ID: {}", rustutils::users::multiuser_get_app_id(9910001));
-
-            let test_alias = "authbound";
-            let keystore2 = get_keystore_service();
-
-            match keystore2.getKeyEntry(&KeyDescriptor {
-                domain: Domain::APP,
-                nspace: SELINUX_SHELL_NAMESPACE,
-                alias: Some(test_alias.to_string()),
-                blob: None,
-            }) {
-                Ok(key_entry_response) => {
-                    assert_eq!(
-                        key_entry_response.metadata.certificate.unwrap(),
-                        gen_key_result.cert
-                    );
-                    assert_eq!(
-                        key_entry_response.metadata.certificateChain.unwrap_or_default(),
-                        gen_key_result.cert_chain
-                    );
-                    assert_eq!(key_entry_response.metadata.key.domain, Domain::KEY_ID);
-                    assert_ne!(key_entry_response.metadata.key.nspace, 0);
-                    assert_eq!(
-                        key_entry_response.metadata.keySecurityLevel,
-                        SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT
-                    );
-
-                    // Preapare KsKeyParameter list from getKeEntry response Authorizations.
-                    let mut key_params: Vec<KsKeyparameter> = Vec::new();
-                    for param in key_entry_response.metadata.authorizations {
-                        let key_param =
-                            KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
-                        key_params.push(key_param);
-                    }
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut gen_key_result = unsafe { run_as::run_as_root(gen_key_fn) };
+
+    let use_key_fn = move || {
+        println!("UID: {}", getuid());
+        println!("Android User ID: {}", rustutils::users::multiuser_get_user_id(9910001));
+        println!("Android app ID: {}", rustutils::users::multiuser_get_app_id(9910001));
+
+        let test_alias = "authbound";
+        let keystore2 = get_keystore_service();
+
+        match keystore2.getKeyEntry(&KeyDescriptor {
+            domain: Domain::APP,
+            nspace: SELINUX_SHELL_NAMESPACE,
+            alias: Some(test_alias.to_string()),
+            blob: None,
+        }) {
+            Ok(key_entry_response) => {
+                assert_eq!(key_entry_response.metadata.certificate.unwrap(), gen_key_result.cert);
+                assert_eq!(
+                    key_entry_response.metadata.certificateChain.unwrap_or_default(),
+                    gen_key_result.cert_chain
+                );
+                assert_eq!(key_entry_response.metadata.key.domain, Domain::KEY_ID);
+                assert_ne!(key_entry_response.metadata.key.nspace, 0);
+                assert_eq!(
+                    key_entry_response.metadata.keySecurityLevel,
+                    SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT
+                );
+
+                // Preapare KsKeyParameter list from getKeEntry response Authorizations.
+                let mut key_params: Vec<KsKeyparameter> = Vec::new();
+                for param in key_entry_response.metadata.authorizations {
+                    let key_param =
+                        KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
+                    key_params.push(key_param);
+                }
 
-                    // Combine keyparameters from gen_key_result and keyparameters
-                    // from legacy key-char file.
-                    let mut legacy_file_key_params: Vec<KsKeyparameter> = Vec::new();
-                    match structured_test_params() {
-                        LegacyKeyCharacteristics::File(legacy_key_params) => {
-                            for param in &legacy_key_params {
-                                let mut present_in_gen_params = false;
-                                for gen_param in &gen_key_result.key_parameters {
-                                    if param.get_tag() == gen_param.get_tag() {
-                                        present_in_gen_params = true;
-                                    }
-                                }
-                                if !present_in_gen_params {
-                                    legacy_file_key_params.push(param.clone());
+                // Combine keyparameters from gen_key_result and keyparameters
+                // from legacy key-char file.
+                let mut legacy_file_key_params: Vec<KsKeyparameter> = Vec::new();
+                match structured_test_params() {
+                    LegacyKeyCharacteristics::File(legacy_key_params) => {
+                        for param in &legacy_key_params {
+                            let mut present_in_gen_params = false;
+                            for gen_param in &gen_key_result.key_parameters {
+                                if param.get_tag() == gen_param.get_tag() {
+                                    present_in_gen_params = true;
                                 }
                             }
-                        }
-                        _ => {
-                            panic!("Expecting file characteristics");
+                            if !present_in_gen_params {
+                                legacy_file_key_params.push(param.clone());
+                            }
                         }
                     }
+                    _ => {
+                        panic!("Expecting file characteristics");
+                    }
+                }
 
-                    // Remove Key-Params which have security levels other than TRUSTED_ENVIRONMENT
-                    gen_key_result.key_parameters.retain(|in_element| {
-                        *in_element.security_level()
-                            == SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT
-                    });
-
-                    println!("GetKeyEntry response key params: {:#?}", key_params);
-                    println!("Generated key params: {:#?}", gen_key_result.key_parameters);
+                // Remove Key-Params which have security levels other than TRUSTED_ENVIRONMENT
+                gen_key_result.key_parameters.retain(|in_element| {
+                    *in_element.security_level()
+                        == SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT
+                });
 
-                    gen_key_result.key_parameters.append(&mut legacy_file_key_params);
+                println!("GetKeyEntry response key params: {:#?}", key_params);
+                println!("Generated key params: {:#?}", gen_key_result.key_parameters);
 
-                    println!("Combined key params: {:#?}", gen_key_result.key_parameters);
+                gen_key_result.key_parameters.append(&mut legacy_file_key_params);
 
-                    // Validate all keyparameters present in getKeyEntry response.
-                    for param in &key_params {
-                        gen_key_result.key_parameters.retain(|in_element| *in_element != *param);
-                    }
+                println!("Combined key params: {:#?}", gen_key_result.key_parameters);
 
-                    println!(
-                        "GetKeyEntry response unmatched key params: {:#?}",
-                        gen_key_result.key_parameters
-                    );
-                    assert_eq!(gen_key_result.key_parameters.len(), 0);
+                // Validate all keyparameters present in getKeyEntry response.
+                for param in &key_params {
+                    gen_key_result.key_parameters.retain(|in_element| *in_element != *param);
                 }
-                Err(s) => {
-                    panic!("getKeyEntry should have succeeded. {:?}", s);
-                }
-            };
-        })
+
+                println!(
+                    "GetKeyEntry response unmatched key params: {:#?}",
+                    gen_key_result.key_parameters
+                );
+                assert_eq!(gen_key_result.key_parameters.len(), 0);
+            }
+            Err(s) => {
+                panic!("getKeyEntry should have succeeded. {:?}", s);
+            }
+        };
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(auid, agid, use_key_fn) };
+
     // Make sure keystore2 clean up imported legacy db.
     let path_buf = PathBuf::from("/data/misc/keystore/user_99");
     if path_buf.as_path().is_dir() {
@@ -367,7 +362,7 @@ fn keystore2_encrypted_characteristics() -> anyhow::Result<()> {
 ///     6. To load and import the legacy key using its alias.
 ///     7. After successful key import validate the user cert and cert-chain with initially
 ///        generated blobs.
-///     8. Validate imported key perameters. Imported key parameters list should be the combination
+///     8. Validate imported key parameters. Imported key parameters list should be the combination
 ///        of the key-parameters in characteristics file and the characteristics according to
 ///        the augmentation rules. There might be duplicate entries with different values for the
 ///        parameters like OS_VERSION, OS_VERSION, BOOT_PATCHLEVEL, VENDOR_PATCHLEVEL etc.
@@ -376,8 +371,6 @@ fn keystore2_encrypted_characteristics() -> anyhow::Result<()> {
 fn keystore2_encrypted_certificates() -> anyhow::Result<()> {
     let auid = 98 * AID_USER_OFFSET + 10001;
     let agid = 98 * AID_USER_OFFSET + 10001;
-    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-    static TARGET_SU_CTX: &str = "u:r:su:s0";
 
     // Cleanup user directory if it exists
     let path_buf = PathBuf::from("/data/misc/keystore/user_98");
@@ -385,177 +378,171 @@ fn keystore2_encrypted_certificates() -> anyhow::Result<()> {
         std::fs::remove_dir_all(path_buf.as_path()).unwrap();
     }
 
-    // Safety: run_as must be called from a single threaded process.
-    // This device test is run as a separate single threaded process.
-    let gen_key_result = unsafe {
-        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            // Remove user if already exist.
-            let maint_service = get_maintenance();
-            match maint_service.onUserRemoved(98) {
-                Ok(_) => {
-                    println!("User was existed, deleted successfully");
-                }
-                Err(e) => {
-                    println!("onUserRemoved error: {:#?}", e);
-                }
+    let gen_key_fn = || {
+        // Remove user if already exist.
+        let maint_service = get_maintenance();
+        match maint_service.onUserRemoved(98) {
+            Ok(_) => {
+                println!("User did exist, deleted successfully");
             }
+            Err(e) => {
+                println!("onUserRemoved error: {:#?}", e);
+            }
+        }
+
+        let sl = SecLevel::tee();
+        // Generate Key BLOB and prepare legacy keystore blob files.
+        let att_challenge: Option<&[u8]> = if rkp_only() { None } else { Some(b"foo") };
+        let key_metadata = key_generations::generate_ec_p256_signing_key(
+            &sl,
+            Domain::BLOB,
+            SELINUX_SHELL_NAMESPACE,
+            None,
+            att_challenge,
+        )
+        .expect("Failed to generate key blob");
+
+        // Create keystore file layout for user_98.
+        let pw: Password = PASSWORD.into();
+        let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
+        let super_key =
+            TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap());
+
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
+        if !path_buf.as_path().is_dir() {
+            std::fs::create_dir(path_buf.as_path()).unwrap();
+        }
+        path_buf.push(".masterkey");
+        if !path_buf.as_path().is_file() {
+            std::fs::write(path_buf.as_path(), SUPERKEY).unwrap();
+        }
 
-            let sl = SecLevel::tee();
-            // Generate Key BLOB and prepare legacy keystore blob files.
-            let att_challenge: Option<&[u8]> = if rkp_only() { None } else { Some(b"foo") };
-            let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sl,
-                Domain::BLOB,
-                SELINUX_SHELL_NAMESPACE,
-                None,
-                att_challenge,
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
+        path_buf.push("9810001_USRPKEY_authboundcertenc");
+        if !path_buf.as_path().is_file() {
+            make_encrypted_key_file(
+                path_buf.as_path(),
+                &super_key,
+                &key_metadata.key.blob.unwrap(),
             )
-            .expect("Failed to generate key blob");
+            .unwrap();
+        }
 
-            // Create keystore file layout for user_98.
-            let pw: Password = PASSWORD.into();
-            let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
-            let super_key =
-                TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap());
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
+        path_buf.push(".9810001_chr_USRPKEY_authboundcertenc");
+        if !path_buf.as_path().is_file() {
+            std::fs::write(path_buf.as_path(), USRPKEY_AUTHBOUND_CHR).unwrap();
+        }
 
-            let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
-            if !path_buf.as_path().is_dir() {
-                std::fs::create_dir(path_buf.as_path()).unwrap();
-            }
-            path_buf.push(".masterkey");
-            if !path_buf.as_path().is_file() {
-                std::fs::write(path_buf.as_path(), SUPERKEY).unwrap();
-            }
+        let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
+        path_buf.push("9810001_USRCERT_authboundcertenc");
+        if !path_buf.as_path().is_file() {
+            make_encrypted_usr_cert_file(
+                path_buf.as_path(),
+                &super_key,
+                key_metadata.certificate.as_ref().unwrap(),
+            )
+            .unwrap();
+        }
 
+        if let Some(chain) = key_metadata.certificateChain.as_ref() {
             let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
-            path_buf.push("9810001_USRPKEY_authboundcertenc");
+            path_buf.push("9810001_CACERT_authboundcertenc");
             if !path_buf.as_path().is_file() {
-                make_encrypted_key_file(
-                    path_buf.as_path(),
-                    &super_key,
-                    &key_metadata.key.blob.unwrap(),
-                )
-                .unwrap();
+                make_encrypted_ca_cert_file(path_buf.as_path(), &super_key, chain).unwrap();
             }
+        }
 
-            let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
-            path_buf.push(".9810001_chr_USRPKEY_authboundcertenc");
-            if !path_buf.as_path().is_file() {
-                std::fs::write(path_buf.as_path(), USRPKEY_AUTHBOUND_CHR).unwrap();
-            }
+        // Keystore2 disables the legacy importer when it finds the legacy database empty.
+        // However, if the device boots with an empty legacy database, the optimization kicks in
+        // and keystore2 never checks the legacy file system layout.
+        // So, restart keystore2 service to detect populated legacy database.
+        keystore2_restart_service();
 
-            let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
-            path_buf.push("9810001_USRCERT_authboundcertenc");
-            if !path_buf.as_path().is_file() {
-                make_encrypted_usr_cert_file(
-                    path_buf.as_path(),
-                    &super_key,
-                    key_metadata.certificate.as_ref().unwrap(),
-                )
-                .unwrap();
+        let auth_service = get_authorization();
+        match auth_service.onDeviceUnlocked(98, Some(PASSWORD)) {
+            Ok(result) => {
+                println!("Unlock Result: {:?}", result);
             }
-
-            if let Some(chain) = key_metadata.certificateChain.as_ref() {
-                let mut path_buf = PathBuf::from("/data/misc/keystore/user_98");
-                path_buf.push("9810001_CACERT_authboundcertenc");
-                if !path_buf.as_path().is_file() {
-                    make_encrypted_ca_cert_file(path_buf.as_path(), &super_key, chain).unwrap();
-                }
-            }
-
-            // Keystore2 disables the legacy importer when it finds the legacy database empty.
-            // However, if the device boots with an empty legacy database, the optimization kicks in
-            // and keystore2 never checks the legacy file system layout.
-            // So, restart keystore2 service to detect populated legacy database.
-            keystore2_restart_service();
-
-            let auth_service = get_authorization();
-            match auth_service.onDeviceUnlocked(98, Some(PASSWORD)) {
-                Ok(result) => {
-                    println!("Unlock Result: {:?}", result);
-                }
-                Err(e) => {
-                    panic!("Unlock should have succeeded: {:?}", e);
-                }
+            Err(e) => {
+                panic!("Unlock should have succeeded: {:?}", e);
             }
+        }
 
-            let mut key_params: Vec<KsKeyparameter> = Vec::new();
-            for param in key_metadata.authorizations {
-                let key_param = KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
-                key_params.push(key_param);
-            }
+        let mut key_params: Vec<KsKeyparameter> = Vec::new();
+        for param in key_metadata.authorizations {
+            let key_param = KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
+            key_params.push(key_param);
+        }
 
-            KeygenResult {
-                cert: key_metadata.certificate.unwrap(),
-                cert_chain: key_metadata.certificateChain.unwrap_or_default(),
-                key_parameters: key_params,
-            }
-        })
+        KeygenResult {
+            cert: key_metadata.certificate.unwrap(),
+            cert_chain: key_metadata.certificateChain.unwrap_or_default(),
+            key_parameters: key_params,
+        }
     };
 
-    // Safety: run_as must be called from a single threaded process.
-    // This device test is run as a separate single threaded process.
-    unsafe {
-        run_as::run_as(TARGET_CTX, Uid::from_raw(auid), Gid::from_raw(agid), move || {
-            println!("UID: {}", getuid());
-            println!("Android User ID: {}", rustutils::users::multiuser_get_user_id(9810001));
-            println!("Android app ID: {}", rustutils::users::multiuser_get_app_id(9810001));
-
-            let test_alias = "authboundcertenc";
-            let keystore2 = get_keystore_service();
-
-            match keystore2.getKeyEntry(&KeyDescriptor {
-                domain: Domain::APP,
-                nspace: SELINUX_SHELL_NAMESPACE,
-                alias: Some(test_alias.to_string()),
-                blob: None,
-            }) {
-                Ok(key_entry_response) => {
-                    assert_eq!(
-                        key_entry_response.metadata.certificate.unwrap(),
-                        gen_key_result.cert
-                    );
-                    assert_eq!(
-                        key_entry_response.metadata.certificateChain.unwrap_or_default(),
-                        gen_key_result.cert_chain
-                    );
-
-                    // Preapare KsKeyParameter list from getKeEntry response Authorizations.
-                    let mut key_params: Vec<KsKeyparameter> = Vec::new();
-                    for param in key_entry_response.metadata.authorizations {
-                        let key_param =
-                            KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
-                        key_params.push(key_param);
-                    }
-
-                    println!("GetKeyEntry response key params: {:#?}", key_params);
-                    println!("Generated key params: {:#?}", gen_key_result.key_parameters);
-                    match structured_test_params_cache() {
-                        LegacyKeyCharacteristics::Cache(legacy_key_params) => {
-                            println!("Legacy key-char cache: {:#?}", legacy_key_params);
-                            // Validate all keyparameters present in getKeyEntry response.
-                            for param in &legacy_key_params {
-                                key_params.retain(|in_element| *in_element != *param);
-                            }
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let gen_key_result = unsafe { run_as::run_as_root(gen_key_fn) };
+
+    let use_key_fn = move || {
+        println!("UID: {}", getuid());
+        println!("Android User ID: {}", rustutils::users::multiuser_get_user_id(9810001));
+        println!("Android app ID: {}", rustutils::users::multiuser_get_app_id(9810001));
+
+        let test_alias = "authboundcertenc";
+        let keystore2 = get_keystore_service();
+
+        match keystore2.getKeyEntry(&KeyDescriptor {
+            domain: Domain::APP,
+            nspace: SELINUX_SHELL_NAMESPACE,
+            alias: Some(test_alias.to_string()),
+            blob: None,
+        }) {
+            Ok(key_entry_response) => {
+                assert_eq!(key_entry_response.metadata.certificate.unwrap(), gen_key_result.cert);
+                assert_eq!(
+                    key_entry_response.metadata.certificateChain.unwrap_or_default(),
+                    gen_key_result.cert_chain
+                );
+
+                // Preapare KsKeyParameter list from getKeEntry response Authorizations.
+                let mut key_params: Vec<KsKeyparameter> = Vec::new();
+                for param in key_entry_response.metadata.authorizations {
+                    let key_param =
+                        KsKeyparameter::new(param.keyParameter.into(), param.securityLevel);
+                    key_params.push(key_param);
+                }
 
-                            println!(
-                                "GetKeyEntry response unmatched key params: {:#?}",
-                                key_params
-                            );
-                            assert_eq!(key_params.len(), 0);
-                        }
-                        _ => {
-                            panic!("Expecting file characteristics");
+                println!("GetKeyEntry response key params: {:#?}", key_params);
+                println!("Generated key params: {:#?}", gen_key_result.key_parameters);
+                match structured_test_params_cache() {
+                    LegacyKeyCharacteristics::Cache(legacy_key_params) => {
+                        println!("Legacy key-char cache: {:#?}", legacy_key_params);
+                        // Validate all keyparameters present in getKeyEntry response.
+                        for param in &legacy_key_params {
+                            key_params.retain(|in_element| *in_element != *param);
                         }
+
+                        println!("GetKeyEntry response unmatched key params: {:#?}", key_params);
+                        assert_eq!(key_params.len(), 0);
+                    }
+                    _ => {
+                        panic!("Expecting file characteristics");
                     }
                 }
-                Err(s) => {
-                    panic!("getKeyEntry should have succeeded. {:?}", s);
-                }
-            };
-        })
+            }
+            Err(s) => {
+                panic!("getKeyEntry should have succeeded. {:?}", s);
+            }
+        };
     };
 
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    unsafe { run_as::run_as_app(auid, agid, use_key_fn) };
+
     // Make sure keystore2 clean up imported legacy db.
     let path_buf = PathBuf::from("/data/misc/keystore/user_98");
     if path_buf.as_path().is_dir() {
diff --git a/keystore2/tests/user_auth.rs b/keystore2/tests/user_auth.rs
index 4e3c6925..187256b7 100644
--- a/keystore2/tests/user_auth.rs
+++ b/keystore2/tests/user_auth.rs
@@ -14,7 +14,7 @@
 
 //! Tests for user authentication interactions (via `IKeystoreAuthorization`).
 
-use crate::keystore2_client_test_utils::BarrierReached;
+use crate::keystore2_client_test_utils::{BarrierReached, BarrierReachedWithData};
 use android_security_authorization::aidl::android::security::authorization::{
     IKeystoreAuthorization::IKeystoreAuthorization
 };
@@ -22,39 +22,49 @@ use android_security_maintenance::aidl::android::security::maintenance::IKeystor
      IKeystoreMaintenance,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, HardwareAuthToken::HardwareAuthToken,
-    HardwareAuthenticatorType::HardwareAuthenticatorType, SecurityLevel::SecurityLevel,
-    KeyPurpose::KeyPurpose
+    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
+    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
+    KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
+};
+use android_hardware_gatekeeper::aidl::android::hardware::gatekeeper::{
+    IGatekeeper::IGatekeeper, IGatekeeper::ERROR_RETRY_TIMEOUT,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     CreateOperationResponse::CreateOperationResponse, Domain::Domain, KeyDescriptor::KeyDescriptor,
     KeyMetadata::KeyMetadata,
 };
+use android_system_keystore2::binder::{ExceptionCode, Result as BinderResult};
 use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
     Timestamp::Timestamp,
 };
+use anyhow::Context;
 use keystore2_test_utils::{
-    get_keystore_service, run_as, authorizations::AuthSetBuilder,
+    authorizations::AuthSetBuilder, expect, get_keystore_service, run_as,
+    run_as::{ChannelReader, ChannelWriter}, expect_km_error,
 };
 use log::{warn, info};
-use nix::unistd::{Gid, Uid};
 use rustutils::users::AID_USER_OFFSET;
+use std::{time::Duration, thread::sleep};
 
 /// Test user ID.
 const TEST_USER_ID: i32 = 100;
-/// Fake password blob.
-static PASSWORD: &[u8] = &[
+/// Corresponding uid value.
+const UID: u32 = TEST_USER_ID as u32 * AID_USER_OFFSET + 1001;
+/// Fake synthetic password blob.
+static SYNTHETIC_PASSWORD: &[u8] = &[
     0x42, 0x39, 0x30, 0x37, 0x44, 0x37, 0x32, 0x37, 0x39, 0x39, 0x43, 0x42, 0x39, 0x41, 0x42, 0x30,
     0x34, 0x31, 0x30, 0x38, 0x46, 0x44, 0x33, 0x45, 0x39, 0x42, 0x32, 0x38, 0x36, 0x35, 0x41, 0x36,
     0x33, 0x44, 0x42, 0x42, 0x43, 0x36, 0x33, 0x42, 0x34, 0x39, 0x37, 0x33, 0x35, 0x45, 0x41, 0x41,
     0x32, 0x45, 0x31, 0x35, 0x43, 0x43, 0x46, 0x32, 0x39, 0x36, 0x33, 0x34, 0x31, 0x32, 0x41, 0x39,
 ];
+/// Gatekeeper password.
+static GK_PASSWORD: &[u8] = b"correcthorsebatterystaple";
 /// Fake SID value corresponding to Gatekeeper.
-static GK_SID: i64 = 123456;
+static GK_FAKE_SID: i64 = 123456;
 /// Fake SID value corresponding to a biometric authenticator.
-static BIO_SID1: i64 = 345678;
+static BIO_FAKE_SID1: i64 = 345678;
 /// Fake SID value corresponding to a biometric authenticator.
-static BIO_SID2: i64 = 456789;
+static BIO_FAKE_SID2: i64 = 456789;
 
 const WEAK_UNLOCK_ENABLED: bool = true;
 const WEAK_UNLOCK_DISABLED: bool = false;
@@ -68,6 +78,18 @@ fn get_maintenance() -> binder::Strong<dyn IKeystoreMaintenance> {
     binder::get_interface("android.security.maintenance").unwrap()
 }
 
+/// Get the default Gatekeeper instance. This may fail on older devices where Gatekeeper is still a
+/// HIDL interface rather than AIDL.
+fn get_gatekeeper() -> Option<binder::Strong<dyn IGatekeeper>> {
+    binder::get_interface("android.hardware.gatekeeper.IGatekeeper/default").ok()
+}
+
+/// Indicate whether a Gatekeeper result indicates a delayed-retry is needed.
+fn is_gk_retry<T: std::fmt::Debug>(result: &BinderResult<T>) -> bool {
+    matches!(result, Err(s) if s.exception_code() == ExceptionCode::SERVICE_SPECIFIC
+                 && s.service_specific_error() == ERROR_RETRY_TIMEOUT)
+}
+
 fn abort_op(result: binder::Result<CreateOperationResponse>) {
     if let Ok(rsp) = result {
         if let Some(op) = rsp.iOperation {
@@ -86,117 +108,684 @@ fn abort_op(result: binder::Result<CreateOperationResponse>) {
 struct TestUser {
     id: i32,
     maint: binder::Strong<dyn IKeystoreMaintenance>,
+    gk: Option<binder::Strong<dyn IGatekeeper>>,
+    gk_sid: Option<i64>,
+    gk_handle: Vec<u8>,
 }
 
 impl TestUser {
     fn new() -> Self {
-        Self::new_user(TEST_USER_ID, PASSWORD)
+        Self::new_user(TEST_USER_ID, SYNTHETIC_PASSWORD)
     }
-    fn new_user(user_id: i32, password: &[u8]) -> Self {
+    fn new_user(user_id: i32, sp: &[u8]) -> Self {
         let maint = get_maintenance();
         maint.onUserAdded(user_id).expect("failed to add test user");
         maint
-            .initUserSuperKeys(user_id, password, /* allowExisting= */ false)
+            .initUserSuperKeys(user_id, sp, /* allowExisting= */ false)
             .expect("failed to init test user");
-        Self { id: user_id, maint }
+        let gk = get_gatekeeper();
+        let (gk_sid, gk_handle) = if let Some(gk) = &gk {
+            // AIDL Gatekeeper is available, so enroll a password.
+            loop {
+                let result = gk.enroll(user_id, &[], &[], GK_PASSWORD);
+                if is_gk_retry(&result) {
+                    sleep(Duration::from_secs(1));
+                    continue;
+                }
+                let rsp = result.expect("gk.enroll() failed");
+                info!("registered test user {user_id} as sid {} with GK", rsp.secureUserId);
+                break (Some(rsp.secureUserId), rsp.data);
+            }
+        } else {
+            (None, vec![])
+        };
+        Self { id: user_id, maint, gk, gk_sid, gk_handle }
+    }
+
+    /// Perform Gatekeeper verification, which will return a HAT on success.
+    fn gk_verify(&self, challenge: i64) -> Option<HardwareAuthToken> {
+        let Some(gk) = &self.gk else { return None };
+        loop {
+            let result = gk.verify(self.id, challenge, &self.gk_handle, GK_PASSWORD);
+            if is_gk_retry(&result) {
+                sleep(Duration::from_secs(1));
+                continue;
+            }
+            let rsp = result.expect("gk.verify failed");
+            break Some(rsp.hardwareAuthToken);
+        }
     }
 }
 
 impl Drop for TestUser {
     fn drop(&mut self) {
         let _ = self.maint.onUserRemoved(self.id);
+        if let Some(gk) = &self.gk {
+            info!("deregister test user {} with GK", self.id);
+            if let Err(e) = gk.deleteUser(self.id) {
+                warn!("failed to deregister test user {}: {e:?}", self.id);
+            }
+        }
     }
 }
 
 #[test]
-fn keystore2_test_unlocked_device_required() {
+fn test_auth_bound_timeout_with_gk() {
+    type Barrier = BarrierReachedWithData<Option<i64>>;
     android_logger::init_once(
         android_logger::Config::default()
             .with_tag("keystore2_client_tests")
             .with_max_level(log::LevelFilter::Debug),
     );
-    static CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
-    const UID: u32 = TEST_USER_ID as u32 * AID_USER_OFFSET + 1001;
 
-    // Safety: only one thread at this point, and nothing yet done with binder.
+    let child_fn = move |reader: &mut ChannelReader<Barrier>,
+                         writer: &mut ChannelWriter<Barrier>|
+          -> Result<(), run_as::Error> {
+        // Now we're in a new process, wait to be notified before starting.
+        let gk_sid: i64 = match reader.recv().0 {
+            Some(sid) => sid,
+            None => {
+                // There is no AIDL Gatekeeper available, so abandon the test.  It would be nice to
+                // know this before starting the child process, but finding it out requires Binder,
+                // which can't be used until after the child has forked.
+                return Ok(());
+            }
+        };
+
+        // Action A: create a new auth-bound key which requires auth in the last 3 seconds,
+        // and fail to start an operation using it.
+        let ks2 = get_keystore_service();
+        let sec_level =
+            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
+        let params = AuthSetBuilder::new()
+            .user_secure_id(gk_sid)
+            .user_secure_id(BIO_FAKE_SID1)
+            .user_secure_id(BIO_FAKE_SID2)
+            .user_auth_type(HardwareAuthenticatorType::ANY)
+            .auth_timeout(3)
+            .algorithm(Algorithm::EC)
+            .purpose(KeyPurpose::SIGN)
+            .purpose(KeyPurpose::VERIFY)
+            .digest(Digest::SHA_2_256)
+            .ec_curve(EcCurve::P_256);
+
+        let KeyMetadata { key, .. } = sec_level
+            .generateKey(
+                &KeyDescriptor {
+                    domain: Domain::APP,
+                    nspace: -1,
+                    alias: Some("auth-bound-timeout".to_string()),
+                    blob: None,
+                },
+                None,
+                &params,
+                0,
+                b"entropy",
+            )
+            .context("key generation failed")?;
+        info!("A: created auth-timeout key {key:?}");
+
+        // No HATs so cannot create an operation using the key.
+        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("A: failed auth-bound operation (no HAT) as expected {result:?}");
+
+        writer.send(&Barrier::new(None)); // A done.
+
+        // Action B: succeed when a valid HAT is available.
+        reader.recv();
+
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        expect!(result.is_ok());
+        let op = result.unwrap().iOperation.context("no operation in result")?;
+        let result = op.finish(Some(b"data"), None);
+        expect!(result.is_ok());
+        info!("B: performed auth-bound operation (with valid GK HAT) as expected");
+
+        writer.send(&Barrier::new(None)); // B done.
+
+        // Action C: fail again when the HAT is old enough to not even be checked.
+        reader.recv();
+        info!("C: wait so that any HAT times out");
+        sleep(Duration::from_secs(4));
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        info!("C: failed auth-bound operation (HAT is too old) as expected {result:?}");
+        writer.send(&Barrier::new(None)); // C done.
+
+        Ok(())
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
     let mut child_handle = unsafe {
         // Perform keystore actions while running as the test user.
-        run_as::run_as_child(
-            CTX,
-            Uid::from_raw(UID),
-            Gid::from_raw(UID),
-            move |reader, writer| -> Result<(), String> {
-                // Action A: create a new unlocked-device-required key (which thus requires
-                // super-encryption), while the device is unlocked.
-                let ks2 = get_keystore_service();
-                if ks2.getInterfaceVersion().unwrap() < 4 {
-                    // Assuming `IKeystoreAuthorization::onDeviceLocked` and
-                    // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
-                    // with `IKeystoreService` >= 4.
-                    return Ok(());
-                }
+        run_as::run_as_child_app(UID, UID, child_fn)
+    }
+    .unwrap();
+
+    // Now that the separate process has been forked off, it's safe to use binder to setup a test
+    // user.
+    let _ks2 = get_keystore_service();
+    let user = TestUser::new();
+    if user.gk.is_none() {
+        // Can't run this test if there's no AIDL Gatekeeper.
+        child_handle.send(&Barrier::new(None));
+        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+        return;
+    }
+    let user_id = user.id;
+    let auth_service = get_authorization();
+
+    // Lock and unlock to ensure super keys are already created.
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+
+    info!("trigger child process action A and wait for completion");
+    child_handle.send(&Barrier::new(Some(user.gk_sid.unwrap())));
+    child_handle.recv_or_die();
+
+    // Unlock with GK password to get a genuine auth token.
+    let real_hat = user.gk_verify(0).expect("failed to perform GK verify");
+    auth_service.addAuthToken(&real_hat).unwrap();
+
+    info!("trigger child process action B and wait for completion");
+    child_handle.send(&Barrier::new(None));
+    child_handle.recv_or_die();
+
+    info!("trigger child process action C and wait for completion");
+    child_handle.send(&Barrier::new(None));
+    child_handle.recv_or_die();
+
+    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+}
+
+#[test]
+fn test_auth_bound_timeout_failure() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_client_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    let child_fn = move |reader: &mut ChannelReader<BarrierReached>,
+                         writer: &mut ChannelWriter<BarrierReached>|
+          -> Result<(), run_as::Error> {
+        // Now we're in a new process, wait to be notified before starting.
+        reader.recv();
+
+        // Action A: create a new auth-bound key which requires auth in the last 3 seconds,
+        // and fail to start an operation using it.
+        let ks2 = get_keystore_service();
+
+        let sec_level =
+            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
+        let params = AuthSetBuilder::new()
+            .user_secure_id(BIO_FAKE_SID1)
+            .user_secure_id(BIO_FAKE_SID2)
+            .user_auth_type(HardwareAuthenticatorType::ANY)
+            .auth_timeout(3)
+            .algorithm(Algorithm::EC)
+            .purpose(KeyPurpose::SIGN)
+            .purpose(KeyPurpose::VERIFY)
+            .digest(Digest::SHA_2_256)
+            .ec_curve(EcCurve::P_256);
+
+        let KeyMetadata { key, .. } = sec_level
+            .generateKey(
+                &KeyDescriptor {
+                    domain: Domain::APP,
+                    nspace: -1,
+                    alias: Some("auth-bound-timeout".to_string()),
+                    blob: None,
+                },
+                None,
+                &params,
+                0,
+                b"entropy",
+            )
+            .context("key generation failed")?;
+        info!("A: created auth-timeout key {key:?}");
+
+        // No HATs so cannot create an operation using the key.
+        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("A: failed auth-bound operation (no HAT) as expected {result:?}");
+
+        writer.send(&BarrierReached {}); // A done.
+
+        // Action B: fail again when an invalid HAT is available.
+        reader.recv();
+
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("B: failed auth-bound operation (HAT is invalid) as expected {result:?}");
+
+        writer.send(&BarrierReached {}); // B done.
 
-                // Now we're in a new process, wait to be notified before starting.
-                reader.recv();
-
-                let sec_level = ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
-                let params = AuthSetBuilder::new()
-                    .no_auth_required()
-                    .unlocked_device_required()
-                    .algorithm(Algorithm::EC)
-                    .purpose(KeyPurpose::SIGN)
-                    .purpose(KeyPurpose::VERIFY)
-                    .digest(Digest::SHA_2_256)
-                    .ec_curve(EcCurve::P_256);
-
-                let KeyMetadata { key, .. } = sec_level
-                    .generateKey(
-                        &KeyDescriptor {
-                            domain: Domain::APP,
-                            nspace: -1,
-                            alias: Some("unlocked-device-required".to_string()),
-                            blob: None,
-                        },
-                        None,
-                        &params,
-                        0,
-                        b"entropy",
-                    )
-                    .expect("key generation failed");
-                info!("A: created unlocked-device-required key while unlocked {key:?}");
-                writer.send(&BarrierReached {}); // A done.
-
-                // Action B: fail to use the unlocked-device-required key while locked.
-                reader.recv();
-                let params =
-                    AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
-                let result = sec_level.createOperation(&key, &params, UNFORCED);
-                info!("B: use unlocked-device-required key while locked => {result:?}");
-                assert!(result.is_err());
-                writer.send(&BarrierReached {}); // B done.
-
-                // Action C: try to use the unlocked-device-required key while unlocked with a
-                // password.
-                reader.recv();
-                let result = sec_level.createOperation(&key, &params, UNFORCED);
-                info!("C: use unlocked-device-required key while lskf-unlocked => {result:?}");
-                assert!(result.is_ok(), "failed with {result:?}");
-                abort_op(result);
-                writer.send(&BarrierReached {}); // C done.
-
-                // Action D: try to use the unlocked-device-required key while unlocked with a weak
-                // biometric.
-                reader.recv();
-                let result = sec_level.createOperation(&key, &params, UNFORCED);
-                info!("D: use unlocked-device-required key while weak-locked => {result:?}");
-                assert!(result.is_ok(), "createOperation failed: {result:?}");
-                abort_op(result);
-                writer.send(&BarrierReached {}); // D done.
-
-                let _ = sec_level.deleteKey(&key);
-                Ok(())
-            },
-        )
+        // Action C: fail again when the HAT is old enough to not even be checked.
+        reader.recv();
+        info!("C: wait so that any HAT times out");
+        sleep(Duration::from_secs(4));
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("C: failed auth-bound operation (HAT is too old) as expected {result:?}");
+        writer.send(&BarrierReached {}); // C done.
+
+        Ok(())
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut child_handle = unsafe {
+        // Perform keystore actions while running as the test user.
+        run_as::run_as_child_app(UID, UID, child_fn)
+    }
+    .unwrap();
+
+    // Now that the separate process has been forked off, it's safe to use binder to setup a test
+    // user.
+    let _ks2 = get_keystore_service();
+    let user = TestUser::new();
+    let user_id = user.id;
+    let auth_service = get_authorization();
+
+    // Lock and unlock to ensure super keys are already created.
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+
+    info!("trigger child process action A and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv_or_die();
+
+    // Unlock with password and a fake auth token that matches the key
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_bio_lskf_token(GK_FAKE_SID, BIO_FAKE_SID1)).unwrap();
+
+    info!("trigger child process action B and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv_or_die();
+
+    info!("trigger child process action C and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv_or_die();
+
+    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+}
+
+#[test]
+fn test_auth_bound_per_op_with_gk() {
+    type Barrier = BarrierReachedWithData<Option<i64>>;
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_client_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    let child_fn = move |reader: &mut ChannelReader<Barrier>,
+                         writer: &mut ChannelWriter<Barrier>|
+          -> Result<(), run_as::Error> {
+        // Now we're in a new process, wait to be notified before starting.
+        let gk_sid: i64 = match reader.recv().0 {
+            Some(sid) => sid,
+            None => {
+                // There is no AIDL Gatekeeper available, so abandon the test.  It would be nice to
+                // know this before starting the child process, but finding it out requires Binder,
+                // which can't be used until after the child has forked.
+                return Ok(());
+            }
+        };
+
+        // Action A: create a new auth-bound key which requires auth-per-operation (because
+        // AUTH_TIMEOUT is not specified), and fail to finish an operation using it.
+        let ks2 = get_keystore_service();
+        let sec_level =
+            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
+        let params = AuthSetBuilder::new()
+            .user_secure_id(gk_sid)
+            .user_secure_id(BIO_FAKE_SID1)
+            .user_auth_type(HardwareAuthenticatorType::ANY)
+            .algorithm(Algorithm::EC)
+            .purpose(KeyPurpose::SIGN)
+            .purpose(KeyPurpose::VERIFY)
+            .digest(Digest::SHA_2_256)
+            .ec_curve(EcCurve::P_256);
+
+        let KeyMetadata { key, .. } = sec_level
+            .generateKey(
+                &KeyDescriptor {
+                    domain: Domain::APP,
+                    nspace: -1,
+                    alias: Some("auth-per-op".to_string()),
+                    blob: None,
+                },
+                None,
+                &params,
+                0,
+                b"entropy",
+            )
+            .context("key generation failed")?;
+        info!("A: created auth-per-op key {key:?}");
+
+        // We can create an operation using the key...
+        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
+        let result = sec_level
+            .createOperation(&key, &params, UNFORCED)
+            .expect("failed to create auth-per-op operation");
+        let op = result.iOperation.context("no operation in result")?;
+        info!("A: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
+
+        // .. but attempting to finish the operation fails because Keystore can't find a HAT.
+        let result = op.finish(Some(b"data"), None);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("A: failed auth-per-op op (no HAT) as expected {result:?}");
+
+        writer.send(&Barrier::new(None)); // A done.
+
+        // Action B: start an operation and pass out the challenge
+        reader.recv();
+        let result = sec_level
+            .createOperation(&key, &params, UNFORCED)
+            .expect("failed to create auth-per-op operation");
+        let op = result.iOperation.context("no operation in result")?;
+        info!("B: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
+        writer.send(&Barrier::new(Some(result.operationChallenge.unwrap().challenge))); // B done.
+
+        // Action C: finishing the operation succeeds now there's a per-op HAT.
+        reader.recv();
+        let result = op.finish(Some(b"data"), None);
+        expect!(result.is_ok());
+        info!("C: performed auth-per-op op expected");
+        writer.send(&Barrier::new(None)); // D done.
+
+        Ok(())
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut child_handle = unsafe {
+        // Perform keystore actions while running as the test user.
+        run_as::run_as_child_app(UID, UID, child_fn)
+    }
+    .unwrap();
+
+    // Now that the separate process has been forked off, it's safe to use binder to setup a test
+    // user.
+    let _ks2 = get_keystore_service();
+    let user = TestUser::new();
+    if user.gk.is_none() {
+        // Can't run this test if there's no AIDL Gatekeeper.
+        child_handle.send(&Barrier::new(None));
+        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+        return;
+    }
+    let user_id = user.id;
+    let auth_service = get_authorization();
+
+    // Lock and unlock to ensure super keys are already created.
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+
+    info!("trigger child process action A and wait for completion");
+    child_handle.send(&Barrier::new(Some(user.gk_sid.unwrap())));
+    child_handle.recv_or_die();
+
+    info!("trigger child process action B and wait for completion");
+    child_handle.send(&Barrier::new(None));
+    let challenge = child_handle.recv_or_die().0.expect("no challenge");
+
+    // Unlock with GK and the challenge to get a genuine per-op auth token
+    let real_hat = user.gk_verify(challenge).expect("failed to perform GK verify");
+    auth_service.addAuthToken(&real_hat).unwrap();
+
+    info!("trigger child process action C and wait for completion");
+    child_handle.send(&Barrier::new(None));
+    child_handle.recv_or_die();
+
+    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+}
+
+#[test]
+fn test_auth_bound_per_op_failure() {
+    type Barrier = BarrierReachedWithData<i64>;
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_client_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    let child_fn = move |reader: &mut ChannelReader<Barrier>,
+                         writer: &mut ChannelWriter<Barrier>|
+          -> Result<(), run_as::Error> {
+        // Now we're in a new process, wait to be notified before starting.
+        reader.recv();
+
+        // Action A: create a new auth-bound key which requires auth-per-operation (because
+        // AUTH_TIMEOUT is not specified), and fail to finish an operation using it.
+        let ks2 = get_keystore_service();
+
+        let sec_level =
+            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
+        let params = AuthSetBuilder::new()
+            .user_secure_id(GK_FAKE_SID)
+            .user_secure_id(BIO_FAKE_SID1)
+            .user_auth_type(HardwareAuthenticatorType::ANY)
+            .algorithm(Algorithm::EC)
+            .purpose(KeyPurpose::SIGN)
+            .purpose(KeyPurpose::VERIFY)
+            .digest(Digest::SHA_2_256)
+            .ec_curve(EcCurve::P_256);
+
+        let KeyMetadata { key, .. } = sec_level
+            .generateKey(
+                &KeyDescriptor {
+                    domain: Domain::APP,
+                    nspace: -1,
+                    alias: Some("auth-per-op".to_string()),
+                    blob: None,
+                },
+                None,
+                &params,
+                0,
+                b"entropy",
+            )
+            .context("key generation failed")?;
+        info!("A: created auth-per-op key {key:?}");
+
+        // We can create an operation using the key...
+        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
+        let result = sec_level
+            .createOperation(&key, &params, UNFORCED)
+            .expect("failed to create auth-per-op operation");
+        let op = result.iOperation.context("no operation in result")?;
+        info!("A: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
+
+        // .. but attempting to finish the operation fails because Keystore can't find a HAT.
+        let result = op.finish(Some(b"data"), None);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("A: failed auth-per-op op (no HAT) as expected {result:?}");
+
+        writer.send(&Barrier::new(0)); // A done.
+
+        // Action B: fail again when an irrelevant HAT is available.
+        reader.recv();
+
+        let result = sec_level
+            .createOperation(&key, &params, UNFORCED)
+            .expect("failed to create auth-per-op operation");
+        let op = result.iOperation.context("no operation in result")?;
+        info!("B: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
+        // The operation fails because the HAT that Keystore received is not related to the
+        // challenge.
+        let result = op.finish(Some(b"data"), None);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("B: failed auth-per-op op (HAT is not per-op) as expected {result:?}");
+
+        writer.send(&Barrier::new(0)); // B done.
+
+        // Action C: start an operation and pass out the challenge
+        reader.recv();
+        let result = sec_level
+            .createOperation(&key, &params, UNFORCED)
+            .expect("failed to create auth-per-op operation");
+        let op = result.iOperation.context("no operation in result")?;
+        info!("C: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
+        writer.send(&Barrier::new(result.operationChallenge.unwrap().challenge)); // C done.
+
+        // Action D: finishing the operation still fails because the per-op HAT
+        // is invalid (the HMAC signature is faked and so the secure world
+        // rejects the HAT).
+        reader.recv();
+        let result = op.finish(Some(b"data"), None);
+        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        info!("D: failed auth-per-op op (HAT is per-op but invalid) as expected {result:?}");
+        writer.send(&Barrier::new(0)); // D done.
+
+        Ok(())
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut child_handle = unsafe {
+        // Perform keystore actions while running as the test user.
+        run_as::run_as_child_app(UID, UID, child_fn)
+    }
+    .unwrap();
+
+    // Now that the separate process has been forked off, it's safe to use binder to setup a test
+    // user.
+    let _ks2 = get_keystore_service();
+    let user = TestUser::new();
+    let user_id = user.id;
+    let auth_service = get_authorization();
+
+    // Lock and unlock to ensure super keys are already created.
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+
+    info!("trigger child process action A and wait for completion");
+    child_handle.send(&Barrier::new(0));
+    child_handle.recv_or_die();
+
+    // Unlock with password and a fake auth token.
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+
+    info!("trigger child process action B and wait for completion");
+    child_handle.send(&Barrier::new(0));
+    child_handle.recv_or_die();
+
+    info!("trigger child process action C and wait for completion");
+    child_handle.send(&Barrier::new(0));
+    let challenge = child_handle.recv_or_die().0;
+
+    // Add a fake auth token with the challenge value.
+    auth_service.addAuthToken(&fake_lskf_token_with_challenge(GK_FAKE_SID, challenge)).unwrap();
+
+    info!("trigger child process action D and wait for completion");
+    child_handle.send(&Barrier::new(0));
+    child_handle.recv_or_die();
+
+    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+}
+
+#[test]
+fn test_unlocked_device_required() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_client_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    let child_fn = move |reader: &mut ChannelReader<BarrierReached>,
+                         writer: &mut ChannelWriter<BarrierReached>|
+          -> Result<(), run_as::Error> {
+        let ks2 = get_keystore_service();
+        if ks2.getInterfaceVersion().unwrap() < 4 {
+            // Assuming `IKeystoreAuthorization::onDeviceLocked` and
+            // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
+            // with `IKeystoreService` >= 4.
+            return Ok(());
+        }
+
+        // Now we're in a new process, wait to be notified before starting.
+        reader.recv();
+
+        // Action A: create a new unlocked-device-required key (which thus requires
+        // super-encryption), while the device is unlocked.
+        let sec_level =
+            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
+        let params = AuthSetBuilder::new()
+            .no_auth_required()
+            .unlocked_device_required()
+            .algorithm(Algorithm::EC)
+            .purpose(KeyPurpose::SIGN)
+            .purpose(KeyPurpose::VERIFY)
+            .digest(Digest::SHA_2_256)
+            .ec_curve(EcCurve::P_256);
+
+        let KeyMetadata { key, .. } = sec_level
+            .generateKey(
+                &KeyDescriptor {
+                    domain: Domain::APP,
+                    nspace: -1,
+                    alias: Some("unlocked-device-required".to_string()),
+                    blob: None,
+                },
+                None,
+                &params,
+                0,
+                b"entropy",
+            )
+            .context("key generation failed")?;
+        info!("A: created unlocked-device-required key while unlocked {key:?}");
+        writer.send(&BarrierReached {}); // A done.
+
+        // Action B: fail to use the unlocked-device-required key while locked.
+        reader.recv();
+        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        info!("B: use unlocked-device-required key while locked => {result:?}");
+        expect_km_error!(&result, ErrorCode::DEVICE_LOCKED);
+        writer.send(&BarrierReached {}); // B done.
+
+        // Action C: try to use the unlocked-device-required key while unlocked with a
+        // password.
+        reader.recv();
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        info!("C: use unlocked-device-required key while lskf-unlocked => {result:?}");
+        expect!(result.is_ok(), "failed with {result:?}");
+        abort_op(result);
+        writer.send(&BarrierReached {}); // C done.
+
+        // Action D: try to use the unlocked-device-required key while unlocked with a weak
+        // biometric.
+        reader.recv();
+        let result = sec_level.createOperation(&key, &params, UNFORCED);
+        info!("D: use unlocked-device-required key while weak-locked => {result:?}");
+        expect!(result.is_ok(), "createOperation failed: {result:?}");
+        abort_op(result);
+        writer.send(&BarrierReached {}); // D done.
+
+        Ok(())
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder.
+    let mut child_handle = unsafe {
+        // Perform keystore actions while running as the test user.
+        run_as::run_as_child_app(UID, UID, child_fn)
     }
     .unwrap();
 
@@ -214,44 +803,55 @@ fn keystore2_test_unlocked_device_required() {
     let auth_service = get_authorization();
 
     // Lock and unlock to ensure super keys are already created.
-    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_DISABLED).unwrap();
-    auth_service.onDeviceUnlocked(user_id, Some(PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_SID)).unwrap();
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
 
     info!("trigger child process action A while unlocked and wait for completion");
     child_handle.send(&BarrierReached {});
-    child_handle.recv();
+    child_handle.recv_or_die();
 
     // Move to locked and don't allow weak unlock, so super keys are wiped.
-    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_DISABLED).unwrap();
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .unwrap();
 
     info!("trigger child process action B while locked and wait for completion");
     child_handle.send(&BarrierReached {});
-    child_handle.recv();
+    child_handle.recv_or_die();
 
     // Unlock with password => loads super key from database.
-    auth_service.onDeviceUnlocked(user_id, Some(PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_SID)).unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
 
     info!("trigger child process action C while lskf-unlocked and wait for completion");
     child_handle.send(&BarrierReached {});
-    child_handle.recv();
+    child_handle.recv_or_die();
 
     // Move to locked and allow weak unlock, then do a weak unlock.
-    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_ENABLED).unwrap();
+    auth_service
+        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_ENABLED)
+        .unwrap();
     auth_service.onDeviceUnlocked(user_id, None).unwrap();
 
     info!("trigger child process action D while weak-unlocked and wait for completion");
     child_handle.send(&BarrierReached {});
-    child_handle.recv();
+    child_handle.recv_or_die();
 
     assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
 }
 
 /// Generate a fake [`HardwareAuthToken`] for the given sid.
 fn fake_lskf_token(gk_sid: i64) -> HardwareAuthToken {
+    fake_lskf_token_with_challenge(gk_sid, 0)
+}
+
+/// Generate a fake [`HardwareAuthToken`] for the given sid and challenge.
+fn fake_lskf_token_with_challenge(gk_sid: i64, challenge: i64) -> HardwareAuthToken {
     HardwareAuthToken {
-        challenge: 0,
+        challenge,
         userId: gk_sid,
         authenticatorId: 0,
         authenticatorType: HardwareAuthenticatorType::PASSWORD,
@@ -259,3 +859,15 @@ fn fake_lskf_token(gk_sid: i64) -> HardwareAuthToken {
         mac: vec![1, 2, 3],
     }
 }
+
+/// Generate a fake [`HardwareAuthToken`] for the given sids
+fn fake_bio_lskf_token(gk_sid: i64, bio_sid: i64) -> HardwareAuthToken {
+    HardwareAuthToken {
+        challenge: 0,
+        userId: gk_sid,
+        authenticatorId: bio_sid,
+        authenticatorType: HardwareAuthenticatorType::PASSWORD,
+        timestamp: Timestamp { milliSeconds: 123 },
+        mac: vec![1, 2, 3],
+    }
+}
diff --git a/provisioner/rkp_factory_extraction_lib.cpp b/provisioner/rkp_factory_extraction_lib.cpp
index 2c2614d3..9b046263 100644
--- a/provisioner/rkp_factory_extraction_lib.cpp
+++ b/provisioner/rkp_factory_extraction_lib.cpp
@@ -25,7 +25,6 @@
 #include <cstring>
 #include <iterator>
 #include <keymaster/cppcose/cppcose.h>
-#include <openssl/base64.h>
 #include <remote_prov/remote_prov_utils.h>
 #include <sys/random.h>
 
@@ -33,6 +32,7 @@
 #include <optional>
 #include <string>
 #include <string_view>
+#include <unordered_set>
 #include <vector>
 
 #include "cppbor_parse.h"
@@ -42,6 +42,7 @@ using aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
 using aidl::android::hardware::security::keymint::MacedPublicKey;
 using aidl::android::hardware::security::keymint::ProtectedData;
 using aidl::android::hardware::security::keymint::RpcHardwareInfo;
+using aidl::android::hardware::security::keymint::remote_prov::BccEntryData;
 using aidl::android::hardware::security::keymint::remote_prov::EekChain;
 using aidl::android::hardware::security::keymint::remote_prov::generateEekChain;
 using aidl::android::hardware::security::keymint::remote_prov::getProdEekChain;
@@ -50,35 +51,13 @@ using aidl::android::hardware::security::keymint::remote_prov::parseAndValidateF
 using aidl::android::hardware::security::keymint::remote_prov::verifyFactoryCsr;
 using aidl::android::hardware::security::keymint::remote_prov::verifyFactoryProtectedData;
 
-using namespace cppbor;
-using namespace cppcose;
+using cppbor::Array;
+using cppbor::Map;
+using cppbor::Null;
+template <class T> using ErrMsgOr = cppcose::ErrMsgOr<T>;
 
 constexpr size_t kVersionWithoutSuperencryption = 3;
 
-std::string toBase64(const std::vector<uint8_t>& buffer) {
-    size_t base64Length;
-    int rc = EVP_EncodedLength(&base64Length, buffer.size());
-    if (!rc) {
-        std::cerr << "Error getting base64 length. Size overflow?" << std::endl;
-        exit(-1);
-    }
-
-    std::string base64(base64Length, ' ');
-    rc = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(base64.data()), buffer.data(), buffer.size());
-    ++rc;  // Account for NUL, which BoringSSL does not for some reason.
-    if (rc != base64Length) {
-        std::cerr << "Error writing base64. Expected " << base64Length
-                  << " bytes to be written, but " << rc << " bytes were actually written."
-                  << std::endl;
-        exit(-1);
-    }
-
-    // BoringSSL automatically adds a NUL -- remove it from the string data
-    base64.pop_back();
-
-    return base64;
-}
-
 std::vector<uint8_t> generateChallenge() {
     std::vector<uint8_t> challenge(kChallengeSize);
 
@@ -90,7 +69,8 @@ std::vector<uint8_t> generateChallenge() {
             if (errno == EINTR) {
                 continue;
             } else {
-                std::cerr << errno << ": " << strerror(errno) << std::endl;
+                std::cerr << "generateChallenge: getrandom returned an error with errno " << errno
+                          << ": " << strerror(errno) << ". Exiting..." << std::endl;
                 exit(-1);
             }
         }
@@ -105,7 +85,7 @@ CborResult<Array> composeCertificateRequestV1(const ProtectedData& protectedData
                                               const DeviceInfo& verifiedDeviceInfo,
                                               const std::vector<uint8_t>& challenge,
                                               const std::vector<uint8_t>& keysToSignMac,
-                                              IRemotelyProvisionedComponent* provisionable) {
+                                              const RpcHardwareInfo& rpcHardwareInfo) {
     Array macedKeysToSign = Array()
                                 .add(Map().add(1, 5).encode())  // alg: hmac-sha256
                                 .add(Map())                     // empty unprotected headers
@@ -113,12 +93,12 @@ CborResult<Array> composeCertificateRequestV1(const ProtectedData& protectedData
                                 .add(keysToSignMac);            // MAC as returned from the HAL
 
     ErrMsgOr<std::unique_ptr<Map>> parsedVerifiedDeviceInfo =
-        parseAndValidateFactoryDeviceInfo(verifiedDeviceInfo.deviceInfo, provisionable);
+        parseAndValidateFactoryDeviceInfo(verifiedDeviceInfo.deviceInfo, rpcHardwareInfo);
     if (!parsedVerifiedDeviceInfo) {
         return {nullptr, parsedVerifiedDeviceInfo.moveMessage()};
     }
 
-    auto [parsedProtectedData, ignore2, errMsg] = parse(protectedData.protectedData);
+    auto [parsedProtectedData, ignore2, errMsg] = cppbor::parse(protectedData.protectedData);
     if (!parsedProtectedData) {
         std::cerr << "Error parsing protected data: '" << errMsg << "'" << std::endl;
         return {nullptr, errMsg};
@@ -145,7 +125,7 @@ CborResult<Array> getCsrV1(std::string_view componentName, IRemotelyProvisionedC
     if (!status.isOk()) {
         std::cerr << "Failed to get hardware info for '" << componentName
                   << "'. Description: " << status.getDescription() << "." << std::endl;
-        exit(-1);
+        return {nullptr, status.getDescription()};
     }
 
     const std::vector<uint8_t> eek = getProdEekChain(hwInfo.supportedEekCurve);
@@ -156,13 +136,14 @@ CborResult<Array> getCsrV1(std::string_view componentName, IRemotelyProvisionedC
     if (!status.isOk()) {
         std::cerr << "Bundle extraction failed for '" << componentName
                   << "'. Description: " << status.getDescription() << "." << std::endl;
-        exit(-1);
+        return {nullptr, status.getDescription()};
     }
     return composeCertificateRequestV1(protectedData, verifiedDeviceInfo, challenge, keysToSignMac,
-                                       irpc);
+                                       hwInfo);
 }
 
-void selfTestGetCsrV1(std::string_view componentName, IRemotelyProvisionedComponent* irpc) {
+std::optional<std::string> selfTestGetCsrV1(std::string_view componentName,
+                                            IRemotelyProvisionedComponent* irpc) {
     std::vector<uint8_t> keysToSignMac;
     std::vector<MacedPublicKey> emptyKeys;
     DeviceInfo verifiedDeviceInfo;
@@ -172,14 +153,14 @@ void selfTestGetCsrV1(std::string_view componentName, IRemotelyProvisionedCompon
     if (!status.isOk()) {
         std::cerr << "Failed to get hardware info for '" << componentName
                   << "'. Description: " << status.getDescription() << "." << std::endl;
-        exit(-1);
+        return status.getDescription();
     }
 
     const std::vector<uint8_t> eekId = {0, 1, 2, 3, 4, 5, 6, 7};
     ErrMsgOr<EekChain> eekChain = generateEekChain(hwInfo.supportedEekCurve, /*length=*/3, eekId);
     if (!eekChain) {
         std::cerr << "Error generating test EEK certificate chain: " << eekChain.message();
-        exit(-1);
+        return eekChain.message();
     }
     const std::vector<uint8_t> challenge = generateChallenge();
     status = irpc->generateCertificateRequest(
@@ -188,18 +169,19 @@ void selfTestGetCsrV1(std::string_view componentName, IRemotelyProvisionedCompon
     if (!status.isOk()) {
         std::cerr << "Error generating test cert chain for '" << componentName
                   << "'. Description: " << status.getDescription() << "." << std::endl;
-        exit(-1);
+        return status.getDescription();
     }
 
     auto result = verifyFactoryProtectedData(verifiedDeviceInfo, /*keysToSign=*/{}, keysToSignMac,
-                                             protectedData, *eekChain, eekId,
-                                             hwInfo.supportedEekCurve, irpc, challenge);
+                                             protectedData, *eekChain, eekId, hwInfo,
+                                             std::string(componentName), challenge);
 
     if (!result) {
         std::cerr << "Self test failed for IRemotelyProvisionedComponent '" << componentName
                   << "'. Error message: '" << result.message() << "'." << std::endl;
-        exit(-1);
+        return result.message();
     }
+    return std::nullopt;
 }
 
 CborResult<Array> composeCertificateRequestV3(const std::vector<uint8_t>& csr) {
@@ -223,27 +205,35 @@ CborResult<Array> composeCertificateRequestV3(const std::vector<uint8_t>& csr) {
     return {std::unique_ptr<Array>(parsedCsr.release()->asArray()), ""};
 }
 
-CborResult<cppbor::Array> getCsrV3(std::string_view componentName,
-                                   IRemotelyProvisionedComponent* irpc, bool selfTest,
-                                   bool allowDegenerate) {
+CborResult<Array> getCsrV3(std::string_view componentName, IRemotelyProvisionedComponent* irpc,
+                           bool selfTest, bool allowDegenerate, bool requireUdsCerts) {
     std::vector<uint8_t> csr;
     std::vector<MacedPublicKey> emptyKeys;
     const std::vector<uint8_t> challenge = generateChallenge();
 
-    auto status = irpc->generateCertificateRequestV2(emptyKeys, challenge, &csr);
+    RpcHardwareInfo hwInfo;
+    auto status = irpc->getHardwareInfo(&hwInfo);
+    if (!status.isOk()) {
+        std::cerr << "Failed to get hardware info for '" << componentName
+                  << "'. Description: " << status.getDescription() << "." << std::endl;
+        return {nullptr, status.getDescription()};
+    }
+
+    status = irpc->generateCertificateRequestV2(emptyKeys, challenge, &csr);
     if (!status.isOk()) {
         std::cerr << "Bundle extraction failed for '" << componentName
                   << "'. Description: " << status.getDescription() << "." << std::endl;
-        exit(-1);
+        return {nullptr, status.getDescription()};
     }
 
     if (selfTest) {
-        auto result =
-            verifyFactoryCsr(/*keysToSign=*/cppbor::Array(), csr, irpc, challenge, allowDegenerate);
+        auto result = verifyFactoryCsr(/*keysToSign=*/cppbor::Array(), csr, hwInfo,
+                                       std::string(componentName), challenge, allowDegenerate,
+                                       requireUdsCerts);
         if (!result) {
             std::cerr << "Self test failed for IRemotelyProvisionedComponent '" << componentName
                       << "'. Error message: '" << result.message() << "'." << std::endl;
-            exit(-1);
+            return {nullptr, result.message()};
         }
     }
 
@@ -251,35 +241,37 @@ CborResult<cppbor::Array> getCsrV3(std::string_view componentName,
 }
 
 CborResult<Array> getCsr(std::string_view componentName, IRemotelyProvisionedComponent* irpc,
-                         bool selfTest, bool allowDegenerate) {
+                         bool selfTest, bool allowDegenerate, bool requireUdsCerts) {
     RpcHardwareInfo hwInfo;
     auto status = irpc->getHardwareInfo(&hwInfo);
     if (!status.isOk()) {
         std::cerr << "Failed to get hardware info for '" << componentName
                   << "'. Description: " << status.getDescription() << "." << std::endl;
-        exit(-1);
+        return {nullptr, status.getDescription()};
     }
 
     if (hwInfo.versionNumber < kVersionWithoutSuperencryption) {
         if (selfTest) {
-            selfTestGetCsrV1(componentName, irpc);
+            auto errMsg = selfTestGetCsrV1(componentName, irpc);
+            if (errMsg) {
+                return {nullptr, *errMsg};
+            }
         }
         return getCsrV1(componentName, irpc);
     } else {
-        return getCsrV3(componentName, irpc, selfTest, allowDegenerate);
+        return getCsrV3(componentName, irpc, selfTest, allowDegenerate, requireUdsCerts);
     }
 }
 
-bool isRemoteProvisioningSupported(IRemotelyProvisionedComponent* irpc) {
-    RpcHardwareInfo hwInfo;
-    auto status = irpc->getHardwareInfo(&hwInfo);
-    if (status.isOk()) {
-        return true;
-    }
-    if (status.getExceptionCode() == EX_UNSUPPORTED_OPERATION) {
-        return false;
+std::unordered_set<std::string> parseCommaDelimited(const std::string& input) {
+    std::stringstream ss(input);
+    std::unordered_set<std::string> result;
+    while (ss.good()) {
+        std::string name;
+        std::getline(ss, name, ',');
+        if (!name.empty()) {
+            result.insert(name);
+        }
     }
-    std::cerr << "Unexpected error when getting hardware info. Description: "
-              << status.getDescription() << "." << std::endl;
-    exit(-1);
-}
+    return result;
+}
\ No newline at end of file
diff --git a/provisioner/rkp_factory_extraction_lib.h b/provisioner/rkp_factory_extraction_lib.h
index 94bd7519..3515f489 100644
--- a/provisioner/rkp_factory_extraction_lib.h
+++ b/provisioner/rkp_factory_extraction_lib.h
@@ -23,8 +23,13 @@
 #include <memory>
 #include <string>
 #include <string_view>
+#include <unordered_set>
 #include <vector>
 
+// Parse a comma-delimited string.
+// Ignores any empty strings.
+std::unordered_set<std::string> parseCommaDelimited(const std::string& input);
+
 // Challenge size must be between 32 and 64 bytes inclusive.
 constexpr size_t kChallengeSize = 64;
 
@@ -35,9 +40,6 @@ template <typename T> struct CborResult {
     std::string errMsg;
 };
 
-// Return `buffer` encoded as a base64 string.
-std::string toBase64(const std::vector<uint8_t>& buffer);
-
 // Generate a random challenge containing `kChallengeSize` bytes.
 std::vector<uint8_t> generateChallenge();
 
@@ -47,13 +49,4 @@ std::vector<uint8_t> generateChallenge();
 CborResult<cppbor::Array>
 getCsr(std::string_view componentName,
        aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent* irpc,
-       bool selfTest, bool allowDegenerate);
-
-// Generates a test certificate chain and validates it, exiting the process on error.
-void selfTestGetCsr(
-    std::string_view componentName,
-    aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent* irpc);
-
-// Returns true if the given IRemotelyProvisionedComponent supports remote provisioning.
-bool isRemoteProvisioningSupported(
-    aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent* irpc);
+       bool selfTest, bool allowDegenerate, bool requireUdsCerts);
\ No newline at end of file
diff --git a/provisioner/rkp_factory_extraction_lib_test.cpp b/provisioner/rkp_factory_extraction_lib_test.cpp
index 247c508b..9bfb25e8 100644
--- a/provisioner/rkp_factory_extraction_lib_test.cpp
+++ b/provisioner/rkp_factory_extraction_lib_test.cpp
@@ -25,6 +25,7 @@
 #include <android-base/properties.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
+#include <openssl/base64.h>
 
 #include <cstdint>
 #include <memory>
@@ -60,6 +61,30 @@ std::ostream& operator<<(std::ostream& os, const Item* item) {
 
 }  // namespace cppbor
 
+std::string toBase64(const std::vector<uint8_t>& buffer) {
+    size_t base64Length;
+    int rc = EVP_EncodedLength(&base64Length, buffer.size());
+    if (!rc) {
+        std::cerr << "Error getting base64 length. Size overflow?" << std::endl;
+        exit(-1);
+    }
+
+    std::string base64(base64Length, ' ');
+    rc = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(base64.data()), buffer.data(), buffer.size());
+    ++rc;  // Account for NUL, which BoringSSL does not for some reason.
+    if (rc != base64Length) {
+        std::cerr << "Error writing base64. Expected " << base64Length
+                  << " bytes to be written, but " << rc << " bytes were actually written."
+                  << std::endl;
+        exit(-1);
+    }
+
+    // BoringSSL automatically adds a NUL -- remove it from the string data
+    base64.pop_back();
+
+    return base64;
+}
+
 class MockIRemotelyProvisionedComponent : public IRemotelyProvisionedComponentDefault {
   public:
     MOCK_METHOD(ScopedAStatus, getHardwareInfo, (RpcHardwareInfo * _aidl_return), (override));
@@ -77,7 +102,7 @@ class MockIRemotelyProvisionedComponent : public IRemotelyProvisionedComponentDe
                 (const std::vector<MacedPublicKey>& in_keysToSign,
                  const std::vector<uint8_t>& in_challenge, std::vector<uint8_t>* _aidl_return),
                 (override));
-    MOCK_METHOD(ScopedAStatus, getInterfaceVersion, (int32_t * _aidl_return), (override));
+    MOCK_METHOD(ScopedAStatus, getInterfaceVersion, (int32_t* _aidl_return), (override));
     MOCK_METHOD(ScopedAStatus, getInterfaceHash, (std::string * _aidl_return), (override));
 };
 
@@ -87,7 +112,7 @@ TEST(LibRkpFactoryExtractionTests, ToBase64) {
         input[i] = i;
     }
 
-    // Test three lengths so we get all the different paddding options
+    // Test three lengths so we get all the different padding options
     EXPECT_EQ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4"
               "vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV"
               "5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMj"
@@ -180,8 +205,9 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV2Hal) {
                         SetArgPointee<6>(kFakeMac),             //
                         Return(ByMove(ScopedAStatus::ok()))));  //
 
-    auto [csr, csrErrMsg] = getCsr("mock component name", mockRpc.get(),
-                                   /*selfTest=*/false, /*allowDegenerate=*/true);
+    auto [csr, csrErrMsg] =
+        getCsr("mock component name", mockRpc.get(),
+               /*selfTest=*/false, /*allowDegenerate=*/true, /*requireUdsCerts=*/false);
     ASSERT_THAT(csr, NotNull()) << csrErrMsg;
     ASSERT_THAT(csr->asArray(), Pointee(Property(&Array::size, Eq(4))));
 
@@ -230,7 +256,7 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV2Hal) {
 
 TEST(LibRkpFactoryExtractionTests, GetCsrWithV3Hal) {
     const std::vector<uint8_t> kCsr = Array()
-                                          .add(3 /* version */)
+                                          .add(1 /* version */)
                                           .add(Map() /* UdsCerts */)
                                           .add(Array() /* DiceCertChain */)
                                           .add(Array() /* SignedData */)
@@ -250,12 +276,13 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV3Hal) {
         .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(kCsr),
                         Return(ByMove(ScopedAStatus::ok()))));
 
-    auto [csr, csrErrMsg] = getCsr("mock component name", mockRpc.get(),
-                                   /*selfTest=*/false, /*allowDegenerate=*/true);
+    auto [csr, csrErrMsg] =
+        getCsr("mock component name", mockRpc.get(),
+               /*selfTest=*/false, /*allowDegenerate=*/true, /*requireUdsCerts=*/false);
     ASSERT_THAT(csr, NotNull()) << csrErrMsg;
     ASSERT_THAT(csr, Pointee(Property(&Array::size, Eq(5))));
 
-    EXPECT_THAT(csr->get(0 /* version */), Pointee(Eq(Uint(3))));
+    EXPECT_THAT(csr->get(0 /* version */), Pointee(Eq(Uint(1))));
     EXPECT_THAT(csr->get(1)->asMap(), NotNull());
     EXPECT_THAT(csr->get(2)->asArray(), NotNull());
     EXPECT_THAT(csr->get(3)->asArray(), NotNull());
@@ -266,3 +293,73 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV3Hal) {
     const Tstr fingerprint(android::base::GetProperty("ro.build.fingerprint", ""));
     EXPECT_THAT(*unverifedDeviceInfo->get("fingerprint")->asTstr(), Eq(fingerprint));
 }
+
+TEST(LibRkpFactoryExtractionTests, requireUdsCerts) {
+    const std::vector<uint8_t> kCsr = Array()
+                                          .add(1 /* version */)
+                                          .add(Map() /* UdsCerts */)
+                                          .add(Array() /* DiceCertChain */)
+                                          .add(Array() /* SignedData */)
+                                          .encode();
+    std::vector<uint8_t> challenge;
+
+    // Set up mock, then call getCsr
+    auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
+    EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
+        hwInfo->versionNumber = 3;
+        return ScopedAStatus::ok();
+    });
+    EXPECT_CALL(*mockRpc,
+                generateCertificateRequestV2(IsEmpty(),   // keysToSign
+                                             _,           // challenge
+                                             NotNull()))  // _aidl_return
+        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(kCsr),
+                        Return(ByMove(ScopedAStatus::ok()))));
+
+    auto [csr, csrErrMsg] =
+        getCsr("mock component name", mockRpc.get(),
+               /*selfTest=*/true, /*allowDegenerate=*/false, /*requireUdsCerts=*/true);
+    ASSERT_EQ(csr, nullptr);
+    ASSERT_THAT(csrErrMsg, testing::HasSubstr("UdsCerts must not be empty"));
+}
+
+TEST(LibRkpFactoryExtractionTests, dontRequireUdsCerts) {
+    const std::vector<uint8_t> kCsr = Array()
+                                          .add(1 /* version */)
+                                          .add(Map() /* UdsCerts */)
+                                          .add(Array() /* DiceCertChain */)
+                                          .add(Array() /* SignedData */)
+                                          .encode();
+    std::vector<uint8_t> challenge;
+
+    // Set up mock, then call getCsr
+    auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
+    EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
+        hwInfo->versionNumber = 3;
+        return ScopedAStatus::ok();
+    });
+    EXPECT_CALL(*mockRpc,
+                generateCertificateRequestV2(IsEmpty(),   // keysToSign
+                                             _,           // challenge
+                                             NotNull()))  // _aidl_return
+        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(kCsr),
+                        Return(ByMove(ScopedAStatus::ok()))));
+
+    auto [csr, csrErrMsg] =
+        getCsr("mock component name", mockRpc.get(),
+               /*selfTest=*/true, /*allowDegenerate=*/false, /*requireUdsCerts=*/false);
+    ASSERT_EQ(csr, nullptr);
+    ASSERT_THAT(csrErrMsg, testing::Not(testing::HasSubstr("UdsCerts must not be empty")));
+}
+
+TEST(LibRkpFactoryExtractionTests, parseCommaDelimitedString) {
+    const auto& rpcNames = "default,avf,,default,Strongbox,strongbox,,";
+    const auto& rpcSet = parseCommaDelimited(rpcNames);
+
+    ASSERT_EQ(rpcSet.size(), 4);
+    ASSERT_TRUE(rpcSet.count("") == 0);
+    ASSERT_TRUE(rpcSet.count("default") == 1);
+    ASSERT_TRUE(rpcSet.count("avf") == 1);
+    ASSERT_TRUE(rpcSet.count("strongbox") == 1);
+    ASSERT_TRUE(rpcSet.count("Strongbox") == 1);
+}
\ No newline at end of file
diff --git a/provisioner/rkp_factory_extraction_tool.cpp b/provisioner/rkp_factory_extraction_tool.cpp
index c0f6beb1..599b52a4 100644
--- a/provisioner/rkp_factory_extraction_tool.cpp
+++ b/provisioner/rkp_factory_extraction_tool.cpp
@@ -26,6 +26,7 @@
 
 #include <future>
 #include <string>
+#include <unordered_set>
 #include <vector>
 
 #include "DrmRkpAdapter.h"
@@ -33,10 +34,9 @@
 
 using aidl::android::hardware::drm::IDrmFactory;
 using aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
+using aidl::android::hardware::security::keymint::RpcHardwareInfo;
 using aidl::android::hardware::security::keymint::remote_prov::jsonEncodeCsrWithBuild;
-
-using namespace cppbor;
-using namespace cppcose;
+using aidl::android::hardware::security::keymint::remote_prov::RKPVM_INSTANCE_NAME;
 
 DEFINE_string(output_format, "build+csr", "How to format the output. Defaults to 'build+csr'.");
 DEFINE_bool(self_test, true,
@@ -47,6 +47,10 @@ DEFINE_bool(allow_degenerate, true,
             "If true, self_test validation will allow degenerate DICE chains in the CSR.");
 DEFINE_string(serialno_prop, "ro.serialno",
               "The property of getting serial number. Defaults to 'ro.serialno'.");
+DEFINE_string(require_uds_certs, "",
+              "The comma-delimited names of remotely provisioned "
+              "components whose UDS certificate chains are required to be present in the CSR. "
+              "Example: avf,default,strongbox");
 
 namespace {
 
@@ -59,15 +63,15 @@ std::string getFullServiceName(const char* descriptor, const char* name) {
     return  std::string(descriptor) + "/" + name;
 }
 
-void writeOutput(const std::string instance_name, const Array& csr) {
+void writeOutput(const std::string instance_name, const cppbor::Array& csr) {
     if (FLAGS_output_format == kBinaryCsrOutput) {
         auto bytes = csr.encode();
         std::copy(bytes.begin(), bytes.end(), std::ostream_iterator<char>(std::cout));
     } else if (FLAGS_output_format == kBuildPlusCsr) {
         auto [json, error] = jsonEncodeCsrWithBuild(instance_name, csr, FLAGS_serialno_prop);
         if (!error.empty()) {
-            std::cerr << "Error JSON encoding the output: " << error;
-            exit(1);
+            std::cerr << "Error JSON encoding the output: " << error << std::endl;
+            exit(-1);
         }
         std::cout << json << std::endl;
     } else {
@@ -75,20 +79,28 @@ void writeOutput(const std::string instance_name, const Array& csr) {
         std::cerr << "Valid formats:" << std::endl;
         std::cerr << "  " << kBinaryCsrOutput << std::endl;
         std::cerr << "  " << kBuildPlusCsr << std::endl;
-        exit(1);
+        exit(-1);
     }
 }
 
-void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisionedComponent* irpc) {
+void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisionedComponent* irpc,
+                   bool requireUdsCerts) {
+    auto fullName = getFullServiceName(descriptor, name);
     // AVF RKP HAL is not always supported, so we need to check if it is supported before
     // generating the CSR.
-    if (std::string(name) == "avf" && !isRemoteProvisioningSupported(irpc)) {
-        return;
+    if (fullName == RKPVM_INSTANCE_NAME) {
+        RpcHardwareInfo hwInfo;
+        auto status = irpc->getHardwareInfo(&hwInfo);
+        if (!status.isOk()) {
+            return;
+        }
     }
-    auto [request, errMsg] = getCsr(name, irpc, FLAGS_self_test, FLAGS_allow_degenerate);
-    auto fullName = getFullServiceName(descriptor, name);
+
+    auto [request, errMsg] =
+        getCsr(name, irpc, FLAGS_self_test, FLAGS_allow_degenerate, requireUdsCerts);
     if (!request) {
-        std::cerr << "Unable to build CSR for '" << fullName << ": " << errMsg << std::endl;
+        std::cerr << "Unable to build CSR for '" << fullName << "': " << errMsg << ", exiting."
+                  << std::endl;
         exit(-1);
     }
 
@@ -97,23 +109,33 @@ void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisione
 
 // Callback for AServiceManager_forEachDeclaredInstance that writes out a CSR
 // for every IRemotelyProvisionedComponent.
-void getCsrForInstance(const char* name, void* /*context*/) {
+void getCsrForInstance(const char* name, void* context) {
     auto fullName = getFullServiceName(IRemotelyProvisionedComponent::descriptor, name);
-    std::future<AIBinder*> wait_for_service_func =
+    std::future<AIBinder*> waitForServiceFunc =
         std::async(std::launch::async, AServiceManager_waitForService, fullName.c_str());
-    if (wait_for_service_func.wait_for(std::chrono::seconds(10)) == std::future_status::timeout) {
-        std::cerr << "Wait for service timed out after 10 seconds: " << fullName;
+    if (waitForServiceFunc.wait_for(std::chrono::seconds(10)) == std::future_status::timeout) {
+        std::cerr << "Wait for service timed out after 10 seconds: '" << fullName << "', exiting."
+                  << std::endl;
         exit(-1);
     }
-    AIBinder* rkpAiBinder = wait_for_service_func.get();
+    AIBinder* rkpAiBinder = waitForServiceFunc.get();
     ::ndk::SpAIBinder rkp_binder(rkpAiBinder);
-    auto rkp_service = IRemotelyProvisionedComponent::fromBinder(rkp_binder);
-    if (!rkp_service) {
-        std::cerr << "Unable to get binder object for '" << fullName << "', skipping.";
+    auto rkpService = IRemotelyProvisionedComponent::fromBinder(rkp_binder);
+    if (!rkpService) {
+        std::cerr << "Unable to get binder object for '" << fullName << "', exiting." << std::endl;
         exit(-1);
     }
 
-    getCsrForIRpc(IRemotelyProvisionedComponent::descriptor, name, rkp_service.get());
+    if (context == nullptr) {
+        std::cerr << "Unable to get context for '" << fullName << "', exiting." << std::endl;
+        exit(-1);
+    }
+
+    auto requireUdsCertsRpcNames = static_cast<std::unordered_set<std::string>*>(context);
+    auto requireUdsCerts = requireUdsCertsRpcNames->count(name) != 0;
+    requireUdsCertsRpcNames->erase(name);
+    getCsrForIRpc(IRemotelyProvisionedComponent::descriptor, name, rkpService.get(),
+                  requireUdsCerts);
 }
 
 }  // namespace
@@ -121,12 +143,21 @@ void getCsrForInstance(const char* name, void* /*context*/) {
 int main(int argc, char** argv) {
     gflags::ParseCommandLineFlags(&argc, &argv, /*remove_flags=*/true);
 
+    auto requireUdsCertsRpcNames = parseCommaDelimited(FLAGS_require_uds_certs);
+
     AServiceManager_forEachDeclaredInstance(IRemotelyProvisionedComponent::descriptor,
-                                            /*context=*/nullptr, getCsrForInstance);
+                                            &requireUdsCertsRpcNames, getCsrForInstance);
+
+    // Append drm CSRs
+    for (auto const& [name, irpc] : android::mediadrm::getDrmRemotelyProvisionedComponents()) {
+        auto requireUdsCerts = requireUdsCertsRpcNames.count(name) != 0;
+        requireUdsCertsRpcNames.erase(name);
+        getCsrForIRpc(IDrmFactory::descriptor, name.c_str(), irpc.get(), requireUdsCerts);
+    }
 
-    // Append drm csr's
-    for (auto const& e : android::mediadrm::getDrmRemotelyProvisionedComponents()) {
-        getCsrForIRpc(IDrmFactory::descriptor, e.first.c_str(), e.second.get());
+    for (auto const& rpcName : requireUdsCertsRpcNames) {
+        std::cerr << "WARNING: You requested to enforce the presence of UDS Certs for '" << rpcName
+                  << "', but no Remotely Provisioned Component had that name." << std::endl;
     }
 
     return 0;
```

