```diff
diff --git a/Android.bp b/Android.bp
index 2691829..ae683c9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,6 +39,12 @@ cc_library_headers {
     export_include_dirs: ["include/dice/config/boringssl_ecdsa_p384"],
 }
 
+cc_library_headers {
+    name: "libopen_dice_boringssl_multialg_headers",
+    defaults: ["libopen_dice.cc_defaults"],
+    export_include_dirs: ["include/dice/config/boringssl_multialg"],
+}
+
 filegroup {
     name: "libopen_dice_common_srcs",
     srcs: [
@@ -61,7 +67,6 @@ filegroup {
     name: "libopen_dice_cbor_ed25519_srcs",
     srcs: [
         "src/boringssl_ed25519_ops.c",
-        "src/cbor_ed25519_cert_op.c",
     ],
 }
 
@@ -70,7 +75,14 @@ filegroup {
     srcs: [
         "src/boringssl_ecdsa_utils.c",
         "src/boringssl_p384_ops.c",
-        "src/cbor_p384_cert_op.c",
+    ],
+}
+
+filegroup {
+    name: "libopen_dice_cbor_multialg_srcs",
+    srcs: [
+        "src/boringssl_ecdsa_utils.c",
+        "src/boringssl_multialg_ops.c",
     ],
 }
 
@@ -120,20 +132,21 @@ cc_library_static {
 
 // Version of the library missing DiceClearMemory, for baremetal client code.
 cc_library_static {
-    name: "libopen_dice_cbor_baremetal",
+    name: "libopen_dice_cbor_baremetal_multialg",
+    defaults: ["cc_baremetal_defaults"],
     srcs: [
         ":libopen_dice_cbor_common_srcs",
-        ":libopen_dice_cbor_ed25519_srcs",
+        ":libopen_dice_cbor_multialg_srcs",
         ":libopen_dice_common_srcs",
     ],
     exclude_srcs: ["src/clear_memory.c"],
     allow_undefined_symbols: true,
     header_libs: [
-        "libopen_dice_boringssl_ed25519_headers",
+        "libopen_dice_boringssl_multialg_headers",
         "libopen_dice_headers",
     ],
     export_header_lib_headers: [
-        "libopen_dice_boringssl_ed25519_headers",
+        "libopen_dice_boringssl_multialg_headers",
         "libopen_dice_headers",
     ],
     static_libs: ["libcrypto_baremetal"],
@@ -145,6 +158,21 @@ cc_library_static {
     },
 }
 
+// Basic, standalone implementation of DiceClearMemory, for tests.
+//
+// Attention has not been given to performance, clearing caches or other
+// potential side channels. This should only be used in contexts that are not
+// security sensitive, such as tests.
+cc_library_static {
+    name: "libopen_dice_clear_memory",
+    defaults: ["cc_baremetal_defaults"],
+    srcs: ["src/clear_memory.c"],
+    header_libs: ["libopen_dice_headers"],
+    visibility: [
+        "//packages/modules/Virtualization:__subpackages__",
+    ],
+}
+
 filegroup {
     name: "libopen_dice_android_srcs",
     srcs: [
@@ -171,12 +199,13 @@ cc_library {
 }
 
 cc_library_static {
-    name: "libopen_dice_android_baremetal",
+    name: "libopen_dice_android_baremetal_multialg",
+    defaults: ["cc_baremetal_defaults"],
     srcs: [":libopen_dice_android_srcs"],
-    export_static_lib_headers: ["libopen_dice_cbor_baremetal"],
+    export_static_lib_headers: ["libopen_dice_cbor_baremetal_multialg"],
     static_libs: [
         "libcrypto_baremetal",
-        "libopen_dice_cbor_baremetal",
+        "libopen_dice_cbor_baremetal_multialg",
     ],
 
     // b/336916369: This library gets linked into a rust rlib.  Disable LTO
@@ -339,3 +368,9 @@ cc_fuzz {
     ],
     shared_libs: ["libcrypto"],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_open-dice",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/BUILD.gn b/BUILD.gn
index eb43c80..2e21c22 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -67,6 +67,10 @@ config("boringssl_ecdsa_p384_ops_config") {
   include_dirs = [ "//include/dice/config/boringssl_ecdsa_p384" ]
 }
 
+config("boringssl_multialg_ops_config") {
+  include_dirs = [ "//include/dice/config/boringssl_multialg" ]
+}
+
 pw_static_library("dice_with_boringssl_ed25519_ops") {
   public = [
     "include/dice/dice.h",
@@ -147,7 +151,6 @@ pw_static_library("dice_with_cbor_ed25519_cert") {
     "src/boringssl_ed25519_ops.c",
     "src/boringssl_hash_kdf_ops.c",
     "src/cbor_cert_op.c",
-    "src/cbor_ed25519_cert_op.c",
     "src/clear_memory.c",
     "src/dice.c",
     "src/utils.c",
@@ -178,7 +181,6 @@ pw_static_library("dice_with_cbor_p256_cert") {
     "src/boringssl_hash_kdf_ops.c",
     "src/boringssl_p256_ops.c",
     "src/cbor_cert_op.c",
-    "src/cbor_p256_cert_op.c",
     "src/clear_memory.c",
     "src/dice.c",
     "src/utils.c",
@@ -200,7 +202,6 @@ pw_static_library("dice_with_cbor_p384_cert") {
     "src/boringssl_hash_kdf_ops.c",
     "src/boringssl_p384_ops.c",
     "src/cbor_cert_op.c",
-    "src/cbor_p384_cert_op.c",
     "src/clear_memory.c",
     "src/dice.c",
     "src/utils.c",
@@ -213,6 +214,27 @@ pw_static_library("dice_with_cbor_p384_cert") {
   all_dependent_configs = [ ":boringssl_ecdsa_p384_ops_config" ]
 }
 
+pw_static_library("dice_with_cbor_multialg") {
+  public = [
+    "include/dice/dice.h",
+    "include/dice/utils.h",
+  ]
+  sources = [
+    "src/boringssl_hash_kdf_ops.c",
+    "src/boringssl_multialg_ops.c",
+    "src/cbor_cert_op.c",
+    "src/clear_memory.c",
+    "src/dice.c",
+    "src/utils.c",
+  ]
+  deps = [
+    ":boringssl_ecdsa_utils",
+    ":cbor_writer",
+    "//third_party/boringssl:crypto",
+  ]
+  all_dependent_configs = [ ":boringssl_multialg_ops_config" ]
+}
+
 pw_static_library("dice_with_cbor_template_ed25519_cert") {
   public = [
     "include/dice/dice.h",
@@ -381,6 +403,20 @@ pw_test("cbor_p384_cert_op_test") {
   ]
 }
 
+pw_test("cbor_multialg_op_test") {
+  sources = [
+    "src/cbor_multialg_op_test.cc",
+    "src/test_utils.cc",
+  ]
+  deps = [
+    ":boringssl_ecdsa_utils",
+    ":dice_with_cbor_multialg",
+    "$dir_pw_string:pw_string",
+    "//third_party/boringssl:crypto",
+    "//third_party/cose-c:cose-c_multialg",
+  ]
+}
+
 pw_executable("cbor_ed25519_cert_op_fuzzer") {
   deps = [
     ":dice_with_cbor_ed25519_cert",
@@ -460,6 +496,7 @@ pw_test_group("tests") {
     ":cbor_ed25519_cert_op_test",
     ":cbor_p256_cert_op_test",
     ":cbor_p384_cert_op_test",
+    ":cbor_multialg_op_test",
     ":cbor_reader_test",
     ":cbor_writer_test",
     ":dice_test",
@@ -608,6 +645,11 @@ pw_size_diff("library_size_report") {
       label = "CBOR P384 Cert"
       base = ":dice_standalone"
     },
+    {
+      target = ":dice_with_cbor_multialg"
+      label = "CBOR Multi-Alg"
+      base = ":dice_standalone"
+    },
     {
       target = ":dice_with_cbor_template_ed25519_cert"
       label = "CBOR Template Cert"
@@ -627,6 +669,7 @@ group("optimized_libs") {
     ":dice_standalone",
     ":dice_with_boringssl_ed25519_ops",
     ":dice_with_cbor_ed25519_cert",
+    ":dice_with_cbor_multialg",
     ":dice_with_cbor_p256_cert",
     ":dice_with_cbor_p384_cert",
     ":dice_with_cbor_template_ed25519_cert",
diff --git a/docs/android.md b/docs/android.md
index 980e63c..f557cbe 100644
--- a/docs/android.md
+++ b/docs/android.md
@@ -85,7 +85,7 @@ Security&nbsp;version  | -70005 | uint                 | Machine-comparable, mon
 [RKP&nbsp;VM][rkp-vm]&nbsp;marker | -70006 | null      | See the [Android HAL documentation][rkp-hal-readme] for precise semantics, as they vary by Android version.
 Component&nbsp;instance&nbsp;name | -70007 | tstr      | When component is meant as a type, class or category, one can further specify the particular instance of that component.
 
-[rkp-vm]: https://android.googlesource.com/platform/packages/modules/Virtualization/+/main/service_vm/README.md#rkp-vm-remote-key-provisioning-virtual-machine
+[rkp-vm]: https://android.googlesource.com/platform/packages/modules/Virtualization/+/main/docs/service_vm.md#rkp-vm-remote-key-provisioning-virtual-machine
 [rkp-hal-readme]: https://android.googlesource.com/platform/hardware/interfaces/+/main/security/rkp/README.md
 
 ### Versions
diff --git a/include/dice/config/boringssl_ecdsa_p256/dice/config.h b/include/dice/config/boringssl_ecdsa_p256/dice/config.h
index 98045f7..7e390d5 100644
--- a/include/dice/config/boringssl_ecdsa_p256/dice/config.h
+++ b/include/dice/config/boringssl_ecdsa_p256/dice/config.h
@@ -17,10 +17,8 @@
 
 // ECDSA P256
 // From table 1 of RFC 9053
-#define DICE_COSE_KEY_ALG_VALUE (-7)
-#define DICE_PUBLIC_KEY_SIZE 64
-#define DICE_PRIVATE_KEY_SIZE 32
-#define DICE_SIGNATURE_SIZE 64
-#define DICE_PROFILE_NAME "opendice.example.p256"
+#define DICE_PUBLIC_KEY_BUFFER_SIZE 64
+#define DICE_PRIVATE_KEY_BUFFER_SIZE 32
+#define DICE_SIGNATURE_BUFFER_SIZE 64
 
 #endif  // DICE_CONFIG_BORINGSSL_ECDSA_P256_DICE_DICE_CONFIG_H_
diff --git a/include/dice/config/boringssl_ecdsa_p384/dice/config.h b/include/dice/config/boringssl_ecdsa_p384/dice/config.h
index e5deb98..48ff621 100644
--- a/include/dice/config/boringssl_ecdsa_p384/dice/config.h
+++ b/include/dice/config/boringssl_ecdsa_p384/dice/config.h
@@ -17,10 +17,8 @@
 
 // ECDSA P384
 // From table 1 of RFC 9053
-#define DICE_COSE_KEY_ALG_VALUE (-35)
-#define DICE_PUBLIC_KEY_SIZE 96
-#define DICE_PRIVATE_KEY_SIZE 48
-#define DICE_SIGNATURE_SIZE 96
-#define DICE_PROFILE_NAME "opendice.example.p384"
+#define DICE_PUBLIC_KEY_BUFFER_SIZE 96
+#define DICE_PRIVATE_KEY_BUFFER_SIZE 48
+#define DICE_SIGNATURE_BUFFER_SIZE 96
 
 #endif  // DICE_CONFIG_BORINGSSL_ECDSA_P384_DICE_DICE_CONFIG_H_
diff --git a/include/dice/config/boringssl_ed25519/dice/config.h b/include/dice/config/boringssl_ed25519/dice/config.h
index ce5a8be..79d1eab 100644
--- a/include/dice/config/boringssl_ed25519/dice/config.h
+++ b/include/dice/config/boringssl_ed25519/dice/config.h
@@ -17,10 +17,8 @@
 
 // Ed25519
 // COSE Key alg value from Table 2 of RFC9053
-#define DICE_COSE_KEY_ALG_VALUE (-8)
-#define DICE_PUBLIC_KEY_SIZE 32
-#define DICE_PRIVATE_KEY_SIZE 64
-#define DICE_SIGNATURE_SIZE 64
-#define DICE_PROFILE_NAME NULL
+#define DICE_PUBLIC_KEY_BUFFER_SIZE 32
+#define DICE_PRIVATE_KEY_BUFFER_SIZE 64
+#define DICE_SIGNATURE_BUFFER_SIZE 64
 
 #endif  // DICE_CONFIG_BORINGSSL_ED25519_DICE_DICE_CONFIG_H_
diff --git a/include/dice/config/boringssl_multialg/dice/config.h b/include/dice/config/boringssl_multialg/dice/config.h
new file mode 100644
index 0000000..1158a1b
--- /dev/null
+++ b/include/dice/config/boringssl_multialg/dice/config.h
@@ -0,0 +1,67 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#ifndef DICE_CONFIG_BORINGSSL_MULTIALG_DICE_CONFIG_H_
+#define DICE_CONFIG_BORINGSSL_MULTIALG_DICE_CONFIG_H_
+
+#include <stddef.h>
+#include <stdint.h>
+
+#include "dice/types.h"
+
+// Upper bound of sizes for all the supported algorithms.
+#define DICE_PUBLIC_KEY_BUFFER_SIZE 96
+#define DICE_PRIVATE_KEY_BUFFER_SIZE 64
+#define DICE_SIGNATURE_BUFFER_SIZE 96
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+typedef enum {
+  kDiceKeyAlgorithmEd25519,
+  kDiceKeyAlgorithmP256,
+  kDiceKeyAlgorithmP384,
+} DiceKeyAlgorithm;
+
+// Provides the algorithm configuration and must be passed as the context
+// parameter to every function in the library.
+typedef struct DiceContext_ {
+  DiceKeyAlgorithm authority_algorithm;
+  DiceKeyAlgorithm subject_algorithm;
+} DiceContext;
+
+static inline DiceResult DiceGetKeyAlgorithm(void* context,
+                                             DicePrincipal principal,
+                                             DiceKeyAlgorithm* alg) {
+  DiceContext* c = (DiceContext*)context;
+  if (context == NULL) {
+    return kDiceResultInvalidInput;
+  }
+  switch (principal) {
+    case kDicePrincipalAuthority:
+      *alg = c->authority_algorithm;
+      break;
+    case kDicePrincipalSubject:
+      *alg = c->subject_algorithm;
+      break;
+  }
+  return kDiceResultOk;
+}
+
+#ifdef __cplusplus
+}  // extern "C"
+#endif
+
+#endif  // DICE_CONFIG_BORINGSSL_MULTIALG_DICE_DICE_CONFIG_H_
diff --git a/include/dice/config/cose_key_config.h b/include/dice/config/cose_key_config.h
new file mode 100644
index 0000000..e6a27db
--- /dev/null
+++ b/include/dice/config/cose_key_config.h
@@ -0,0 +1,41 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#ifndef DICE_CONFIG_COSE_KEY_CONFIG_H_
+#define DICE_CONFIG_COSE_KEY_CONFIG_H_
+
+#include <stdint.h>
+
+// Constants per RFC 8152.
+static const int64_t kCoseKeyKtyLabel = 1;
+static const int64_t kCoseKeyKtyOkp = 1;
+static const int64_t kCoseKeyKtyEc2 = 2;
+static const int64_t kCoseKeyAlgLabel = 3;
+static const int64_t kCoseKeyOpsLabel = 4;
+static const int64_t kCoseKeyOpsVerify = 2;
+static const int64_t kCoseKeyCrvLabel = -1;
+static const int64_t kCoseKeyXLabel = -2;
+static const int64_t kCoseKeyYLabel = -3;
+
+// Constants for Ed25519 keys.
+static const int64_t kCoseAlgEdDsa = -8;
+static const int64_t kCoseCrvEd25519 = 6;
+
+// Constants for ECDSA P-256/P-384 keys.
+static const int64_t kCoseAlgEs256 = -7;
+static const int64_t kCoseCrvP256 = 1;
+static const int64_t kCoseAlgEs384 = -35;
+static const int64_t kCoseCrvP384 = 2;
+
+#endif  // DICE_CONFIG_COSE_KEY_CONFIG_H_
diff --git a/include/dice/config/mbedtls_ecdsa_p256/dice/config.h b/include/dice/config/mbedtls_ecdsa_p256/dice/config.h
index c5e23e1..624682c 100644
--- a/include/dice/config/mbedtls_ecdsa_p256/dice/config.h
+++ b/include/dice/config/mbedtls_ecdsa_p256/dice/config.h
@@ -16,9 +16,9 @@
 #define DICE_CONFIG_MBEDTLS_ECDSA_P256_DICE_CONFIG_H_
 
 // ECDSA-P256
-#define DICE_PUBLIC_KEY_SIZE 33
-#define DICE_PRIVATE_KEY_SIZE 32
-#define DICE_SIGNATURE_SIZE 64
+#define DICE_PUBLIC_KEY_BUFFER_SIZE 33
+#define DICE_PRIVATE_KEY_BUFFER_SIZE 32
+#define DICE_SIGNATURE_BUFFER_SIZE 64
 #define DICE_PROFILE_NAME "openssl.example.p256_compressed"
 
 #endif  // DICE_CONFIG_MBEDTLS_ECDSA_P256_DICE_DICE_CONFIG_H_
diff --git a/include/dice/config/standalone/dice/config.h b/include/dice/config/standalone/dice/config.h
index d71ec76..791e491 100644
--- a/include/dice/config/standalone/dice/config.h
+++ b/include/dice/config/standalone/dice/config.h
@@ -19,9 +19,9 @@
 // for tests that focus on the core aspects of the library and not the ops.
 // These value aren't yet used meaningfully in such tests so are given
 // placeholder values.
-#define DICE_PUBLIC_KEY_SIZE 1
-#define DICE_PRIVATE_KEY_SIZE 1
-#define DICE_SIGNATURE_SIZE 1
+#define DICE_PUBLIC_KEY_BUFFER_SIZE 1
+#define DICE_PRIVATE_KEY_BUFFER_SIZE 1
+#define DICE_SIGNATURE_BUFFER_SIZE 1
 #define DICE_PROFILE_NAME NULL
 
 #endif  // DICE_CONFIG_STANDALONE_DICE_CONFIG_H_
diff --git a/include/dice/dice.h b/include/dice/dice.h
index cf54942..b95f6ca 100644
--- a/include/dice/dice.h
+++ b/include/dice/dice.h
@@ -18,6 +18,8 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include "dice/types.h"
+
 #ifdef __cplusplus
 extern "C" {
 #endif
@@ -29,25 +31,6 @@ extern "C" {
 #define DICE_PRIVATE_KEY_SEED_SIZE 32
 #define DICE_ID_SIZE 20
 
-typedef enum {
-  kDiceResultOk,
-  kDiceResultInvalidInput,
-  kDiceResultBufferTooSmall,
-  kDiceResultPlatformError,
-} DiceResult;
-
-typedef enum {
-  kDiceModeNotInitialized,
-  kDiceModeNormal,
-  kDiceModeDebug,
-  kDiceModeMaintenance,
-} DiceMode;
-
-typedef enum {
-  kDiceConfigTypeInline,
-  kDiceConfigTypeDescriptor,
-} DiceConfigType;
-
 // Contains a full set of input values describing the target program or system.
 // See the Open Profile for DICE specification for a detailed explanation of
 // these inputs.
diff --git a/include/dice/ops.h b/include/dice/ops.h
index 53f8d8e..99fb41d 100644
--- a/include/dice/ops.h
+++ b/include/dice/ops.h
@@ -17,6 +17,7 @@
 
 #include <dice/config.h>
 #include <dice/dice.h>
+#include <dice/ops/clear_memory.h>
 
 // These are the set of functions that implement various operations that the
 // main DICE functions depend on. They are provided as part of an integration
@@ -26,6 +27,11 @@
 extern "C" {
 #endif
 
+// Retrieves the DICE key parameters based on the key pair generation
+// algorithm set up at compile time or in the |context| parameter at runtime.
+DiceResult DiceGetKeyParam(void* context, DicePrincipal principal,
+                           DiceKeyParam* key_param);
+
 // An implementation of SHA-512, or an alternative hash. Hashes |input_size|
 // bytes of |input| and populates |output| on success.
 DiceResult DiceHash(void* context, const uint8_t* input, size_t input_size,
@@ -42,25 +48,26 @@ DiceResult DiceKdf(void* context, size_t length, const uint8_t* ikm,
 // Since this is deterministic, |seed| is as sensitive as a private key and can
 // be used directly as the private key. The |private_key| may use an
 // implementation defined format so may only be passed to the |sign| operation.
-DiceResult DiceKeypairFromSeed(void* context,
-                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
-                               uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-                               uint8_t private_key[DICE_PRIVATE_KEY_SIZE]);
+DiceResult DiceKeypairFromSeed(
+    void* context, DicePrincipal principal,
+    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
+    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]);
 
 // Calculates a signature of |message_size| bytes from |message| using
 // |private_key|. |private_key| was generated by |keypair_from_seed| to allow
 // an implementation to use their own private key format. |signature| points to
 // the buffer where the calculated signature is written.
 DiceResult DiceSign(void* context, const uint8_t* message, size_t message_size,
-                    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
-                    uint8_t signature[DICE_SIGNATURE_SIZE]);
+                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
+                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]);
 
 // Verifies, using |public_key|, that |signature| covers |message_size| bytes
 // from |message|.
 DiceResult DiceVerify(void* context, const uint8_t* message,
                       size_t message_size,
-                      const uint8_t signature[DICE_SIGNATURE_SIZE],
-                      const uint8_t public_key[DICE_PUBLIC_KEY_SIZE]);
+                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
+                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]);
 
 // Generates an X.509 certificate, or an alternative certificate format, from
 // the given |subject_private_key_seed| and |input_values|, and signed by
@@ -74,14 +81,6 @@ DiceResult DiceGenerateCertificate(
     const DiceInputValues* input_values, size_t certificate_buffer_size,
     uint8_t* certificate, size_t* certificate_actual_size);
 
-// Securely clears |size| bytes at |address|. This project contains a basic
-// implementation. OPENSSL_cleanse from boringssl, SecureZeroMemory from
-// Windows and memset_s from C11 could also be used as an implementation but a
-// particular target platform or toolchain may have a better implementation
-// available that can be plugged in here. Care may be needed to ensure sensitive
-// data does not leak due to features such as caches.
-void DiceClearMemory(void* context, size_t size, void* address);
-
 #ifdef __cplusplus
 }  // extern "C"
 #endif
diff --git a/include/dice/ops/clear_memory.h b/include/dice/ops/clear_memory.h
new file mode 100644
index 0000000..7229586
--- /dev/null
+++ b/include/dice/ops/clear_memory.h
@@ -0,0 +1,36 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#ifndef DICE_OPS_CLEAR_MEMORY_H_
+#define DICE_OPS_CLEAR_MEMORY_H_
+
+#include <stddef.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+// Securely clears |size| bytes at |address|. This project contains a basic
+// implementation. OPENSSL_cleanse from boringssl, SecureZeroMemory from
+// Windows and memset_s from C11 could also be used as an implementation but a
+// particular target platform or toolchain may have a better implementation
+// available that can be plugged in here. Care may be needed to ensure sensitive
+// data does not leak due to features such as caches.
+void DiceClearMemory(void* context, size_t size, void* address);
+
+#ifdef __cplusplus
+}  // extern "C"
+#endif
+
+#endif  // DICE_OPS_CLEAR_MEMORY_H_
diff --git a/include/dice/ops/trait/cose.h b/include/dice/ops/trait/cose.h
index 78cb838..0ac0dc1 100644
--- a/include/dice/ops/trait/cose.h
+++ b/include/dice/ops/trait/cose.h
@@ -33,8 +33,9 @@ extern "C" {
 // kDiceResultBufferTooSmall is returned |encoded_size| will be set to the
 // required size of the buffer.
 DiceResult DiceCoseEncodePublicKey(
-    void* context, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-    size_t buffer_size, uint8_t* buffer, size_t* encoded_size);
+    void* context, DicePrincipal principal,
+    const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE], size_t buffer_size,
+    uint8_t* buffer, size_t* encoded_size);
 
 // Signs the payload and additional authenticated data, formatting the result
 // into a COSE_Sign1 structure. There are no unprotected attributes included in
@@ -47,7 +48,7 @@ DiceResult DiceCoseEncodePublicKey(
 DiceResult DiceCoseSignAndEncodeSign1(
     void* context, const uint8_t* payload, size_t payload_size,
     const uint8_t* aad, size_t aad_size,
-    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE], size_t buffer_size,
+    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE], size_t buffer_size,
     uint8_t* buffer, size_t* encoded_size);
 
 #ifdef __cplusplus
diff --git a/include/dice/types.h b/include/dice/types.h
new file mode 100644
index 0000000..3f004df
--- /dev/null
+++ b/include/dice/types.h
@@ -0,0 +1,65 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#ifndef DICE_TYPES_H_
+#define DICE_TYPES_H_
+
+#include <stddef.h>
+#include <stdint.h>
+
+typedef enum {
+  kDiceResultOk,
+  kDiceResultInvalidInput,
+  kDiceResultBufferTooSmall,
+  kDiceResultPlatformError,
+} DiceResult;
+
+typedef enum {
+  kDicePrincipalAuthority,
+  kDicePrincipalSubject,
+} DicePrincipal;
+
+typedef enum {
+  kDiceModeNotInitialized,
+  kDiceModeNormal,
+  kDiceModeDebug,
+  kDiceModeMaintenance,
+} DiceMode;
+
+typedef enum {
+  kDiceConfigTypeInline,
+  kDiceConfigTypeDescriptor,
+} DiceConfigType;
+
+// Parameters related to the DICE key operations.
+//
+// Fields:
+//   profile_name: Name of the profile. NULL if not specified. The pointer
+//   should point to a valid static string or NULL.
+//   public_key_size: Actual size of the public key.
+//   signature_size: Actual size of the signature.
+//   cose_key_type: Key type that is represented as the 'kty' member of the
+//    COSE_Key object as per RFC 8152.
+//   cose_key_algorithm: COSE algorithm identifier for the key.
+//   cose_key_curve: COSE curve identifier for the key.
+typedef struct DiceKeyParam_ {
+  const char* profile_name;
+  size_t public_key_size;
+  size_t signature_size;
+  int64_t cose_key_type;
+  int64_t cose_key_algorithm;
+  int64_t cose_key_curve;
+} DiceKeyParam;
+
+#endif  // DICE_TYPES_H_
diff --git a/rules.mk b/rules.mk
index 4f10233..091d4f9 100644
--- a/rules.mk
+++ b/rules.mk
@@ -23,7 +23,6 @@ MODULE_SRCS := \
 	$(LOCAL_DIR)/src/boringssl_hash_kdf_ops.c \
 	$(LOCAL_DIR)/src/boringssl_ed25519_ops.c \
 	$(LOCAL_DIR)/src/cbor_cert_op.c \
-	$(LOCAL_DIR)/src/cbor_ed25519_cert_op.c \
 	$(LOCAL_DIR)/src/cbor_reader.c \
 	$(LOCAL_DIR)/src/cbor_writer.c \
 	$(LOCAL_DIR)/src/clear_memory.c \
diff --git a/src/android.c b/src/android.c
index cf540db..86cd851 100644
--- a/src/android.c
+++ b/src/android.c
@@ -149,8 +149,8 @@ static DiceResult DiceAndroidMainFlowWithNewDiceChain(
     size_t* chain_size, uint8_t next_cdi_attest[DICE_CDI_SIZE],
     uint8_t next_cdi_seal[DICE_CDI_SIZE]) {
   uint8_t current_cdi_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
-  uint8_t attestation_public_key[DICE_PUBLIC_KEY_SIZE];
-  uint8_t attestation_private_key[DICE_PRIVATE_KEY_SIZE];
+  uint8_t attestation_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+  uint8_t attestation_private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
   // Derive an asymmetric private key seed from the current attestation CDI
   // value.
   DiceResult result = DiceDeriveCdiPrivateKeySeed(context, current_cdi_attest,
@@ -159,7 +159,8 @@ static DiceResult DiceAndroidMainFlowWithNewDiceChain(
     goto out;
   }
   // Derive attestation key pair.
-  result = DiceKeypairFromSeed(context, current_cdi_private_key_seed,
+  result = DiceKeypairFromSeed(context, kDicePrincipalAuthority,
+                               current_cdi_private_key_seed,
                                attestation_public_key, attestation_private_key);
   if (result != kDiceResultOk) {
     goto out;
@@ -180,8 +181,9 @@ static DiceResult DiceAndroidMainFlowWithNewDiceChain(
   }
 
   size_t encoded_pub_key_size = 0;
-  result = DiceCoseEncodePublicKey(context, attestation_public_key, buffer_size,
-                                   buffer, &encoded_pub_key_size);
+  result = DiceCoseEncodePublicKey(context, kDicePrincipalAuthority,
+                                   attestation_public_key, buffer_size, buffer,
+                                   &encoded_pub_key_size);
   if (result == kDiceResultOk) {
     buffer += encoded_pub_key_size;
     buffer_size -= encoded_pub_key_size;
diff --git a/src/boringssl_cert_op.c b/src/boringssl_cert_op.c
index 9ece559..21ce297 100644
--- a/src/boringssl_cert_op.c
+++ b/src/boringssl_cert_op.c
@@ -310,7 +310,8 @@ out:
   return result;
 }
 
-static DiceResult GetDiceExtensionData(const DiceInputValues* input_values,
+static DiceResult GetDiceExtensionData(const char* profile_name,
+                                       const DiceInputValues* input_values,
                                        size_t buffer_size, uint8_t* buffer,
                                        size_t* actual_size) {
   DiceResult result = kDiceResultOk;
@@ -430,14 +431,14 @@ static DiceResult GetDiceExtensionData(const DiceInputValues* input_values,
   }
 
   // Encode profile name.
-  if (DICE_PROFILE_NAME) {
+  if (profile_name) {
     asn1->profile_name = ASN1_UTF8STRING_new();
     if (!asn1->profile_name) {
       result = kDiceResultPlatformError;
       goto out;
     }
-    if (!ASN1_STRING_set(asn1->profile_name, DICE_PROFILE_NAME,
-                         strlen(DICE_PROFILE_NAME))) {
+    if (!ASN1_STRING_set(asn1->profile_name, profile_name,
+                         strlen(profile_name))) {
       result = kDiceResultPlatformError;
       goto out;
     }
@@ -457,7 +458,8 @@ out:
   return result;
 }
 
-static DiceResult AddDiceExtension(const DiceInputValues* input_values,
+static DiceResult AddDiceExtension(const char* profile_name,
+                                   const DiceInputValues* input_values,
                                    X509* x509) {
   const char* kDiceExtensionOid = "1.3.6.1.4.1.11129.2.1.24";
 
@@ -469,7 +471,7 @@ static DiceResult AddDiceExtension(const DiceInputValues* input_values,
   uint8_t extension_buffer[DICE_MAX_EXTENSION_SIZE];
   size_t extension_size = 0;
   DiceResult result =
-      GetDiceExtensionData(input_values, sizeof(extension_buffer),
+      GetDiceExtensionData(profile_name, input_values, sizeof(extension_buffer),
                            extension_buffer, &extension_size);
   if (result != kDiceResultOk) {
     goto out;
@@ -582,7 +584,12 @@ DiceResult DiceGenerateCertificate(
   if (result != kDiceResultOk) {
     goto out;
   }
-  result = AddDiceExtension(input_values, x509);
+  DiceKeyParam key_param;
+  result = DiceGetKeyParam(context, kDicePrincipalSubject, &key_param);
+  if (result != kDiceResultOk) {
+    goto out;
+  }
+  result = AddDiceExtension(key_param.profile_name, input_values, x509);
   if (result != kDiceResultOk) {
     goto out;
   }
diff --git a/src/boringssl_ed25519_ops.c b/src/boringssl_ed25519_ops.c
index a1b9797..7d94bff 100644
--- a/src/boringssl_ed25519_ops.c
+++ b/src/boringssl_ed25519_ops.c
@@ -16,37 +16,56 @@
 
 #include <stdint.h>
 
+#include "dice/config/cose_key_config.h"
 #include "dice/dice.h"
 #include "dice/ops.h"
 #include "openssl/curve25519.h"
-#include "openssl/evp.h"
 
 #if DICE_PRIVATE_KEY_SEED_SIZE != 32
 #error "Private key seed is expected to be 32 bytes."
 #endif
-#if DICE_PUBLIC_KEY_SIZE != 32
+#if DICE_PUBLIC_KEY_BUFFER_SIZE != 32
 #error "Ed25519 needs 32 bytes to store the public key."
 #endif
-#if DICE_PRIVATE_KEY_SIZE != 64
+#if DICE_PRIVATE_KEY_BUFFER_SIZE != 64
 #error "This Ed25519 implementation needs 64 bytes for the private key."
 #endif
-#if DICE_SIGNATURE_SIZE != 64
+#if DICE_SIGNATURE_BUFFER_SIZE != 64
 #error "Ed25519 needs 64 bytes to store the signature."
 #endif
 
-DiceResult DiceKeypairFromSeed(void* context_not_used,
-                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
-                               uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-                               uint8_t private_key[DICE_PRIVATE_KEY_SIZE]) {
+#define DICE_PROFILE_NAME NULL
+
+DiceResult DiceGetKeyParam(void* context_not_used,
+                           DicePrincipal principal_not_used,
+                           DiceKeyParam* key_param) {
+  (void)context_not_used;
+  (void)principal_not_used;
+  key_param->profile_name = DICE_PROFILE_NAME;
+  key_param->public_key_size = DICE_PUBLIC_KEY_BUFFER_SIZE;
+  key_param->signature_size = DICE_SIGNATURE_BUFFER_SIZE;
+
+  key_param->cose_key_type = kCoseKeyKtyOkp;
+  key_param->cose_key_algorithm = kCoseAlgEdDsa;
+  key_param->cose_key_curve = kCoseCrvEd25519;
+  return kDiceResultOk;
+}
+
+DiceResult DiceKeypairFromSeed(
+    void* context_not_used, DicePrincipal principal_not_used,
+    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
+    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]) {
   (void)context_not_used;
+  (void)principal_not_used;
   ED25519_keypair_from_seed(public_key, private_key, seed);
   return kDiceResultOk;
 }
 
 DiceResult DiceSign(void* context_not_used, const uint8_t* message,
                     size_t message_size,
-                    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
-                    uint8_t signature[DICE_SIGNATURE_SIZE]) {
+                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
+                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]) {
   (void)context_not_used;
   if (1 != ED25519_sign(signature, message, message_size, private_key)) {
     return kDiceResultPlatformError;
@@ -56,8 +75,8 @@ DiceResult DiceSign(void* context_not_used, const uint8_t* message,
 
 DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
                       size_t message_size,
-                      const uint8_t signature[DICE_SIGNATURE_SIZE],
-                      const uint8_t public_key[DICE_PUBLIC_KEY_SIZE]) {
+                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
+                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]) {
   (void)context_not_used;
   if (1 != ED25519_verify(message, message_size, signature, public_key)) {
     return kDiceResultPlatformError;
diff --git a/src/boringssl_multialg_ops.c b/src/boringssl_multialg_ops.c
new file mode 100644
index 0000000..745329e
--- /dev/null
+++ b/src/boringssl_multialg_ops.c
@@ -0,0 +1,168 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+// This is a configurable, multi-algorithm implementation of signature
+// operations using boringssl.
+
+#include <stdint.h>
+#include <stdio.h>
+
+#include "dice/boringssl_ecdsa_utils.h"
+#include "dice/config/cose_key_config.h"
+#include "dice/dice.h"
+#include "dice/ops.h"
+#include "openssl/curve25519.h"
+
+#if DICE_PRIVATE_KEY_SEED_SIZE != 32
+#error "Private key seed is expected to be 32 bytes."
+#endif
+#if DICE_PUBLIC_KEY_BUFFER_SIZE != 96
+#error "Multialg needs 96 bytes to for the public key (P-384)"
+#endif
+#if DICE_PRIVATE_KEY_BUFFER_SIZE != 64
+#error "Multialg needs 64 bytes for the private key (Ed25519)"
+#endif
+#if DICE_SIGNATURE_BUFFER_SIZE != 96
+#error "Multialg needs 96 bytes to store the signature (P-384)"
+#endif
+
+#define DICE_PROFILE_NAME_ED25519 NULL
+#define DICE_PROFILE_NAME_P256 "opendice.example.p256"
+#define DICE_PROFILE_NAME_P384 "opendice.example.p384"
+
+DiceResult DiceGetKeyParam(void* context, DicePrincipal principal,
+                           DiceKeyParam* key_param) {
+  DiceKeyAlgorithm alg;
+  DiceResult result = DiceGetKeyAlgorithm(context, principal, &alg);
+  if (result != kDiceResultOk) {
+    return result;
+  }
+  switch (alg) {
+    case kDiceKeyAlgorithmEd25519:
+      key_param->profile_name = DICE_PROFILE_NAME_ED25519;
+      key_param->public_key_size = 32;
+      key_param->signature_size = 64;
+
+      key_param->cose_key_type = kCoseKeyKtyOkp;
+      key_param->cose_key_algorithm = kCoseAlgEdDsa;
+      key_param->cose_key_curve = kCoseCrvEd25519;
+      return kDiceResultOk;
+    case kDiceKeyAlgorithmP256:
+      key_param->profile_name = DICE_PROFILE_NAME_P256;
+      key_param->public_key_size = 64;
+      key_param->signature_size = 64;
+
+      key_param->cose_key_type = kCoseKeyKtyEc2;
+      key_param->cose_key_algorithm = kCoseAlgEs256;
+      key_param->cose_key_curve = kCoseCrvP256;
+      return kDiceResultOk;
+    case kDiceKeyAlgorithmP384:
+      key_param->profile_name = DICE_PROFILE_NAME_P384;
+      key_param->public_key_size = 96;
+      key_param->signature_size = 96;
+
+      key_param->cose_key_type = kCoseKeyKtyEc2;
+      key_param->cose_key_algorithm = kCoseAlgEs384;
+      key_param->cose_key_curve = kCoseCrvP384;
+      return kDiceResultOk;
+  }
+  return kDiceResultPlatformError;
+}
+
+DiceResult DiceKeypairFromSeed(
+    void* context, DicePrincipal principal,
+    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
+    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]) {
+  DiceKeyAlgorithm alg;
+  DiceResult result = DiceGetKeyAlgorithm(context, principal, &alg);
+  if (result != kDiceResultOk) {
+    return result;
+  }
+  switch (alg) {
+    case kDiceKeyAlgorithmEd25519:
+      ED25519_keypair_from_seed(public_key, private_key, seed);
+      return kDiceResultOk;
+    case kDiceKeyAlgorithmP256:
+      if (1 == P256KeypairFromSeed(public_key, private_key, seed)) {
+        return kDiceResultOk;
+      }
+      break;
+    case kDiceKeyAlgorithmP384:
+      if (1 == P384KeypairFromSeed(public_key, private_key, seed)) {
+        return kDiceResultOk;
+      }
+      break;
+  }
+  return kDiceResultPlatformError;
+}
+
+DiceResult DiceSign(void* context, const uint8_t* message, size_t message_size,
+                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
+                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]) {
+  DiceKeyAlgorithm alg;
+  DiceResult result =
+      DiceGetKeyAlgorithm(context, kDicePrincipalAuthority, &alg);
+  if (result != kDiceResultOk) {
+    return result;
+  }
+  switch (alg) {
+    case kDiceKeyAlgorithmEd25519:
+      if (1 == ED25519_sign(signature, message, message_size, private_key)) {
+        return kDiceResultOk;
+      }
+      break;
+    case kDiceKeyAlgorithmP256:
+      if (1 == P256Sign(signature, message, message_size, private_key)) {
+        return kDiceResultOk;
+      }
+      break;
+    case kDiceKeyAlgorithmP384:
+      if (1 == P384Sign(signature, message, message_size, private_key)) {
+        return kDiceResultOk;
+      }
+      break;
+  }
+  return kDiceResultPlatformError;
+}
+
+DiceResult DiceVerify(void* context, const uint8_t* message,
+                      size_t message_size,
+                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
+                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]) {
+  DiceKeyAlgorithm alg;
+  DiceResult result =
+      DiceGetKeyAlgorithm(context, kDicePrincipalAuthority, &alg);
+  if (result != kDiceResultOk) {
+    return result;
+  }
+  switch (alg) {
+    case kDiceKeyAlgorithmEd25519:
+      if (1 == ED25519_verify(message, message_size, signature, public_key)) {
+        return kDiceResultOk;
+      }
+      break;
+    case kDiceKeyAlgorithmP256:
+      if (1 == P256Verify(message, message_size, signature, public_key)) {
+        return kDiceResultOk;
+      }
+      break;
+    case kDiceKeyAlgorithmP384:
+      if (1 == P384Verify(message, message_size, signature, public_key)) {
+        return kDiceResultOk;
+      }
+      break;
+  }
+  return kDiceResultPlatformError;
+}
diff --git a/src/boringssl_p256_ops.c b/src/boringssl_p256_ops.c
index e6e030a..a39f3b8 100644
--- a/src/boringssl_p256_ops.c
+++ b/src/boringssl_p256_ops.c
@@ -18,27 +18,47 @@
 #include <stdio.h>
 
 #include "dice/boringssl_ecdsa_utils.h"
+#include "dice/config/cose_key_config.h"
 #include "dice/dice.h"
 #include "dice/ops.h"
 
 #if DICE_PRIVATE_KEY_SEED_SIZE != 32
 #error "Private key seed is expected to be 32 bytes."
 #endif
-#if DICE_PUBLIC_KEY_SIZE != 64
+#if DICE_PUBLIC_KEY_BUFFER_SIZE != 64
 #error "This P-256 implementation needs 64 bytes to store the public key."
 #endif
-#if DICE_PRIVATE_KEY_SIZE != 32
+#if DICE_PRIVATE_KEY_BUFFER_SIZE != 32
 #error "P-256 needs 32 bytes for the private key."
 #endif
-#if DICE_SIGNATURE_SIZE != 64
+#if DICE_SIGNATURE_BUFFER_SIZE != 64
 #error "P-256 needs 64 bytes to store the signature."
 #endif
 
-DiceResult DiceKeypairFromSeed(void* context_not_used,
-                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
-                               uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-                               uint8_t private_key[DICE_PRIVATE_KEY_SIZE]) {
+#define DICE_PROFILE_NAME "opendice.example.p256"
+
+DiceResult DiceGetKeyParam(void* context_not_used,
+                           DicePrincipal principal_not_used,
+                           DiceKeyParam* key_param) {
+  (void)context_not_used;
+  (void)principal_not_used;
+  key_param->profile_name = DICE_PROFILE_NAME;
+  key_param->public_key_size = DICE_PUBLIC_KEY_BUFFER_SIZE;
+  key_param->signature_size = DICE_SIGNATURE_BUFFER_SIZE;
+
+  key_param->cose_key_type = kCoseKeyKtyEc2;
+  key_param->cose_key_algorithm = kCoseAlgEs256;
+  key_param->cose_key_curve = kCoseCrvP256;
+  return kDiceResultOk;
+}
+
+DiceResult DiceKeypairFromSeed(
+    void* context_not_used, DicePrincipal principal_not_used,
+    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
+    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]) {
   (void)context_not_used;
+  (void)principal_not_used;
   if (1 == P256KeypairFromSeed(public_key, private_key, seed)) {
     return kDiceResultOk;
   }
@@ -47,8 +67,8 @@ DiceResult DiceKeypairFromSeed(void* context_not_used,
 
 DiceResult DiceSign(void* context_not_used, const uint8_t* message,
                     size_t message_size,
-                    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
-                    uint8_t signature[DICE_SIGNATURE_SIZE]) {
+                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
+                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]) {
   (void)context_not_used;
   if (1 == P256Sign(signature, message, message_size, private_key)) {
     return kDiceResultOk;
@@ -58,8 +78,8 @@ DiceResult DiceSign(void* context_not_used, const uint8_t* message,
 
 DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
                       size_t message_size,
-                      const uint8_t signature[DICE_SIGNATURE_SIZE],
-                      const uint8_t public_key[DICE_PUBLIC_KEY_SIZE]) {
+                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
+                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]) {
   (void)context_not_used;
   if (1 == P256Verify(message, message_size, signature, public_key)) {
     return kDiceResultOk;
diff --git a/src/boringssl_p384_ops.c b/src/boringssl_p384_ops.c
index d5a0d0c..9ff53c9 100644
--- a/src/boringssl_p384_ops.c
+++ b/src/boringssl_p384_ops.c
@@ -18,27 +18,47 @@
 #include <stdio.h>
 
 #include "dice/boringssl_ecdsa_utils.h"
+#include "dice/config/cose_key_config.h"
 #include "dice/dice.h"
 #include "dice/ops.h"
 
 #if DICE_PRIVATE_KEY_SEED_SIZE != 32
 #error "Private key seed is expected to be 32 bytes."
 #endif
-#if DICE_PUBLIC_KEY_SIZE != 96
+#if DICE_PUBLIC_KEY_BUFFER_SIZE != 96
 #error "This P-384 implementation needs 96 bytes to store the public key."
 #endif
-#if DICE_PRIVATE_KEY_SIZE != 48
+#if DICE_PRIVATE_KEY_BUFFER_SIZE != 48
 #error "P-384 needs 48 bytes for the private key."
 #endif
-#if DICE_SIGNATURE_SIZE != 96
+#if DICE_SIGNATURE_BUFFER_SIZE != 96
 #error "P-384 needs 96 bytes to store the signature."
 #endif
 
-DiceResult DiceKeypairFromSeed(void* context_not_used,
-                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
-                               uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-                               uint8_t private_key[DICE_PRIVATE_KEY_SIZE]) {
+#define DICE_PROFILE_NAME "opendice.example.p384"
+
+DiceResult DiceGetKeyParam(void* context_not_used,
+                           DicePrincipal principal_not_used,
+                           DiceKeyParam* key_param) {
+  (void)context_not_used;
+  (void)principal_not_used;
+  key_param->profile_name = DICE_PROFILE_NAME;
+  key_param->public_key_size = DICE_PUBLIC_KEY_BUFFER_SIZE;
+  key_param->signature_size = DICE_SIGNATURE_BUFFER_SIZE;
+
+  key_param->cose_key_type = kCoseKeyKtyEc2;
+  key_param->cose_key_algorithm = kCoseAlgEs384;
+  key_param->cose_key_curve = kCoseCrvP384;
+  return kDiceResultOk;
+}
+
+DiceResult DiceKeypairFromSeed(
+    void* context_not_used, DicePrincipal principal_not_used,
+    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
+    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]) {
   (void)context_not_used;
+  (void)principal_not_used;
   if (1 == P384KeypairFromSeed(public_key, private_key, seed)) {
     return kDiceResultOk;
   }
@@ -47,8 +67,8 @@ DiceResult DiceKeypairFromSeed(void* context_not_used,
 
 DiceResult DiceSign(void* context_not_used, const uint8_t* message,
                     size_t message_size,
-                    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
-                    uint8_t signature[DICE_SIGNATURE_SIZE]) {
+                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
+                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]) {
   (void)context_not_used;
   if (1 == P384Sign(signature, message, message_size, private_key)) {
     return kDiceResultOk;
@@ -58,8 +78,8 @@ DiceResult DiceSign(void* context_not_used, const uint8_t* message,
 
 DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
                       size_t message_size,
-                      const uint8_t signature[DICE_SIGNATURE_SIZE],
-                      const uint8_t public_key[DICE_PUBLIC_KEY_SIZE]) {
+                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
+                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]) {
   (void)context_not_used;
   if (1 == P384Verify(message, message_size, signature, public_key)) {
     return kDiceResultOk;
diff --git a/src/cbor_cert_op.c b/src/cbor_cert_op.c
index 5416958..49664e3 100644
--- a/src/cbor_cert_op.c
+++ b/src/cbor_cert_op.c
@@ -21,17 +21,20 @@
 #include <string.h>
 
 #include "dice/cbor_writer.h"
+#include "dice/config/cose_key_config.h"
 #include "dice/dice.h"
 #include "dice/ops.h"
 #include "dice/ops/trait/cose.h"
 #include "dice/utils.h"
 
 // Max size of COSE_Key encoding.
-#define DICE_MAX_PUBLIC_KEY_SIZE (DICE_PUBLIC_KEY_SIZE + 32)
+#define DICE_MAX_PUBLIC_KEY_SIZE (DICE_PUBLIC_KEY_BUFFER_SIZE + 32)
 // Max size of the COSE_Sign1 protected attributes.
 #define DICE_MAX_PROTECTED_ATTRIBUTES_SIZE 16
 
-static DiceResult EncodeProtectedAttributes(size_t buffer_size, uint8_t* buffer,
+static DiceResult EncodeProtectedAttributes(void* context,
+                                            DicePrincipal principal,
+                                            size_t buffer_size, uint8_t* buffer,
                                             size_t* encoded_size) {
   // Constants per RFC 8152.
   const int64_t kCoseHeaderAlgLabel = 1;
@@ -40,8 +43,13 @@ static DiceResult EncodeProtectedAttributes(size_t buffer_size, uint8_t* buffer,
   CborOutInit(buffer, buffer_size, &out);
   CborWriteMap(/*num_elements=*/1, &out);
   // Add the algorithm.
+  DiceKeyParam key_param;
+  DiceResult result = DiceGetKeyParam(context, principal, &key_param);
+  if (result != kDiceResultOk) {
+    return result;
+  }
   CborWriteInt(kCoseHeaderAlgLabel, &out);
-  CborWriteInt(DICE_COSE_KEY_ALG_VALUE, &out);
+  CborWriteInt(key_param.cose_key_algorithm, &out);
   *encoded_size = CborOutSize(&out);
   if (CborOutOverflowed(&out)) {
     return kDiceResultBufferTooSmall;
@@ -74,13 +82,12 @@ static DiceResult EncodeCoseTbs(const uint8_t* protected_attributes,
   return kDiceResultOk;
 }
 
-static DiceResult EncodeCoseSign1(const uint8_t* protected_attributes,
-                                  size_t protected_attributes_size,
-                                  const uint8_t* payload, size_t payload_size,
-                                  bool move_payload,
-                                  const uint8_t signature[DICE_SIGNATURE_SIZE],
-                                  size_t buffer_size, uint8_t* buffer,
-                                  size_t* encoded_size) {
+static DiceResult EncodeCoseSign1(
+    void* context, const uint8_t* protected_attributes,
+    size_t protected_attributes_size, const uint8_t* payload,
+    size_t payload_size, bool move_payload,
+    const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE], size_t buffer_size,
+    uint8_t* buffer, size_t* encoded_size) {
   struct CborOut out;
   CborOutInit(buffer, buffer_size, &out);
   // COSE_Sign1 is an array of four elements.
@@ -105,8 +112,14 @@ static DiceResult EncodeCoseSign1(const uint8_t* protected_attributes,
   } else {
     CborWriteBstr(payload_size, payload, &out);
   }
+  DiceKeyParam key_param;
+  DiceResult result =
+      DiceGetKeyParam(context, kDicePrincipalAuthority, &key_param);
+  if (result != kDiceResultOk) {
+    return result;
+  }
   // Signature.
-  CborWriteBstr(/*num_elements=*/DICE_SIGNATURE_SIZE, signature, &out);
+  CborWriteBstr(/*num_elements=*/key_param.signature_size, signature, &out);
   *encoded_size = CborOutSize(&out);
   if (CborOutOverflowed(&out)) {
     return kDiceResultBufferTooSmall;
@@ -117,7 +130,7 @@ static DiceResult EncodeCoseSign1(const uint8_t* protected_attributes,
 DiceResult DiceCoseSignAndEncodeSign1(
     void* context, const uint8_t* payload, size_t payload_size,
     const uint8_t* aad, size_t aad_size,
-    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE], size_t buffer_size,
+    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE], size_t buffer_size,
     uint8_t* buffer, size_t* encoded_size) {
   DiceResult result;
 
@@ -127,9 +140,9 @@ DiceResult DiceCoseSignAndEncodeSign1(
   // COSE_Sign1 structure.
   uint8_t protected_attributes[DICE_MAX_PROTECTED_ATTRIBUTES_SIZE];
   size_t protected_attributes_size = 0;
-  result = EncodeProtectedAttributes(sizeof(protected_attributes),
-                                     protected_attributes,
-                                     &protected_attributes_size);
+  result = EncodeProtectedAttributes(
+      context, kDicePrincipalAuthority, sizeof(protected_attributes),
+      protected_attributes, &protected_attributes_size);
   if (result != kDiceResultOk) {
     return kDiceResultPlatformError;
   }
@@ -143,9 +156,10 @@ DiceResult DiceCoseSignAndEncodeSign1(
   if (result != kDiceResultOk) {
     // Check how big the buffer needs to be in total.
     size_t final_encoded_size = 0;
-    EncodeCoseSign1(protected_attributes, protected_attributes_size, payload,
-                    payload_size, /*move_payload=*/false, /*signature=*/NULL,
-                    /*buffer_size=*/0, /*buffer=*/NULL, &final_encoded_size);
+    EncodeCoseSign1(context, protected_attributes, protected_attributes_size,
+                    payload, payload_size, /*move_payload=*/false,
+                    /*signature=*/NULL, /*buffer_size=*/0, /*buffer=*/NULL,
+                    &final_encoded_size);
     if (*encoded_size < final_encoded_size) {
       *encoded_size = final_encoded_size;
     }
@@ -154,16 +168,17 @@ DiceResult DiceCoseSignAndEncodeSign1(
   memcpy(payload_buffer, payload, payload_size);
 
   // Sign the TBS with the authority key.
-  uint8_t signature[DICE_SIGNATURE_SIZE];
+  uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE];
   result = DiceSign(context, buffer, *encoded_size, private_key, signature);
   if (result != kDiceResultOk) {
     return result;
   }
 
   // The final certificate is an untagged COSE_Sign1 structure.
-  return EncodeCoseSign1(protected_attributes, protected_attributes_size,
-                         payload, payload_size, /*move_payload=*/false,
-                         signature, buffer_size, buffer, encoded_size);
+  return EncodeCoseSign1(context, protected_attributes,
+                         protected_attributes_size, payload, payload_size,
+                         /*move_payload=*/false, signature, buffer_size, buffer,
+                         encoded_size);
 }
 
 // Encodes a CBOR Web Token (CWT) with an issuer, subject, and additional
@@ -204,7 +219,14 @@ static DiceResult EncodeCwt(void* context, const DiceInputValues* input_values,
   if (input_values->authority_descriptor_size > 0) {
     map_pairs += 1;
   }
-  if (DICE_PROFILE_NAME) {
+
+  DiceKeyParam key_param;
+  DiceResult result =
+      DiceGetKeyParam(context, kDicePrincipalSubject, &key_param);
+  if (result != kDiceResultOk) {
+    return result;
+  }
+  if (key_param.profile_name) {
     map_pairs += 1;
   }
 
@@ -231,9 +253,9 @@ static DiceResult EncodeCwt(void* context, const DiceInputValues* input_values,
     uint8_t config_descriptor_hash[DICE_HASH_SIZE];
     // Skip hashing if we're not going to use the answer.
     if (!CborOutOverflowed(&out)) {
-      DiceResult result = DiceHash(context, input_values->config_descriptor,
-                                   input_values->config_descriptor_size,
-                                   config_descriptor_hash);
+      result = DiceHash(context, input_values->config_descriptor,
+                        input_values->config_descriptor_size,
+                        config_descriptor_hash);
       if (result != kDiceResultOk) {
         return result;
       }
@@ -270,9 +292,9 @@ static DiceResult EncodeCwt(void* context, const DiceInputValues* input_values,
   CborWriteInt(kKeyUsageLabel, &out);
   CborWriteBstr(/*data_size=*/1, &key_usage, &out);
   // Add the profile name
-  if (DICE_PROFILE_NAME) {
+  if (key_param.profile_name) {
     CborWriteInt(kProfileNameLabel, &out);
-    CborWriteTstr(DICE_PROFILE_NAME, &out);
+    CborWriteTstr(key_param.profile_name, &out);
   }
   *encoded_size = CborOutSize(&out);
   if (CborOutOverflowed(&out)) {
@@ -296,20 +318,34 @@ DiceResult DiceGenerateCertificate(
   }
 
   // Declare buffers which are cleared on 'goto out'.
-  uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE];
-  uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE];
+  uint8_t subject_private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
+  uint8_t authority_private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
 
   // Derive keys and IDs from the private key seeds.
-  uint8_t subject_public_key[DICE_PUBLIC_KEY_SIZE];
-  result = DiceKeypairFromSeed(context, subject_private_key_seed,
-                               subject_public_key, subject_private_key);
+  uint8_t subject_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+  result = DiceKeypairFromSeed(context, kDicePrincipalSubject,
+                               subject_private_key_seed, subject_public_key,
+                               subject_private_key);
+  if (result != kDiceResultOk) {
+    goto out;
+  }
+
+  DiceKeyParam subject_key_param;
+  DiceKeyParam authority_key_param;
+  result = DiceGetKeyParam(context, kDicePrincipalSubject, &subject_key_param);
+  if (result != kDiceResultOk) {
+    goto out;
+  }
+  result =
+      DiceGetKeyParam(context, kDicePrincipalAuthority, &authority_key_param);
   if (result != kDiceResultOk) {
     goto out;
   }
 
   uint8_t subject_id[DICE_ID_SIZE];
-  result = DiceDeriveCdiCertificateId(context, subject_public_key,
-                                      DICE_PUBLIC_KEY_SIZE, subject_id);
+  result =
+      DiceDeriveCdiCertificateId(context, subject_public_key,
+                                 subject_key_param.public_key_size, subject_id);
   if (result != kDiceResultOk) {
     goto out;
   }
@@ -318,16 +354,18 @@ DiceResult DiceGenerateCertificate(
                 sizeof(subject_id_hex));
   subject_id_hex[sizeof(subject_id_hex) - 1] = '\0';
 
-  uint8_t authority_public_key[DICE_PUBLIC_KEY_SIZE];
-  result = DiceKeypairFromSeed(context, authority_private_key_seed,
-                               authority_public_key, authority_private_key);
+  uint8_t authority_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+  result = DiceKeypairFromSeed(context, kDicePrincipalAuthority,
+                               authority_private_key_seed, authority_public_key,
+                               authority_private_key);
   if (result != kDiceResultOk) {
     goto out;
   }
 
   uint8_t authority_id[DICE_ID_SIZE];
   result = DiceDeriveCdiCertificateId(context, authority_public_key,
-                                      DICE_PUBLIC_KEY_SIZE, authority_id);
+                                      authority_key_param.public_key_size,
+                                      authority_id);
   if (result != kDiceResultOk) {
     goto out;
   }
@@ -340,8 +378,8 @@ DiceResult DiceGenerateCertificate(
   uint8_t encoded_public_key[DICE_MAX_PUBLIC_KEY_SIZE];
   size_t encoded_public_key_size = 0;
   result = DiceCoseEncodePublicKey(
-      context, subject_public_key, sizeof(encoded_public_key),
-      encoded_public_key, &encoded_public_key_size);
+      context, kDicePrincipalSubject, subject_public_key,
+      sizeof(encoded_public_key), encoded_public_key, &encoded_public_key_size);
   if (result != kDiceResultOk) {
     result = kDiceResultPlatformError;
     goto out;
@@ -351,9 +389,9 @@ DiceResult DiceGenerateCertificate(
   // COSE_Sign1 structure.
   uint8_t protected_attributes[DICE_MAX_PROTECTED_ATTRIBUTES_SIZE];
   size_t protected_attributes_size = 0;
-  result = EncodeProtectedAttributes(sizeof(protected_attributes),
-                                     protected_attributes,
-                                     &protected_attributes_size);
+  result = EncodeProtectedAttributes(
+      context, kDicePrincipalAuthority, sizeof(protected_attributes),
+      protected_attributes, &protected_attributes_size);
   if (result != kDiceResultOk) {
     result = kDiceResultPlatformError;
     goto out;
@@ -383,9 +421,10 @@ DiceResult DiceGenerateCertificate(
     // we need is either the amount needed for the TBS, or the amount needed for
     // encoded payload and signature.
     size_t final_encoded_size = 0;
-    EncodeCoseSign1(protected_attributes, protected_attributes_size, cwt_ptr,
-                    cwt_size, /*move_payload=*/false, /*signature=*/NULL,
-                    /*buffer_size=*/0, /*buffer=*/NULL, &final_encoded_size);
+    EncodeCoseSign1(context, protected_attributes, protected_attributes_size,
+                    cwt_ptr, cwt_size, /*move_payload=*/false,
+                    /*signature=*/NULL, /*buffer_size=*/0, /*buffer=*/NULL,
+                    &final_encoded_size);
     *certificate_actual_size =
         final_encoded_size > tbs_size ? final_encoded_size : tbs_size;
     result = kDiceResultBufferTooSmall;
@@ -405,7 +444,7 @@ DiceResult DiceGenerateCertificate(
   }
 
   // Sign the now-complete TBS.
-  uint8_t signature[DICE_SIGNATURE_SIZE];
+  uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE];
   result = DiceSign(context, certificate, tbs_size, authority_private_key,
                     signature);
   if (result != kDiceResultOk) {
@@ -414,10 +453,10 @@ DiceResult DiceGenerateCertificate(
 
   // And now we can produce the complete CoseSign1, including the signature, and
   // moving the payload into place as we do it.
-  result = EncodeCoseSign1(protected_attributes, protected_attributes_size,
-                           cwt_ptr, cwt_size, /*move_payload=*/true, signature,
-                           certificate_buffer_size, certificate,
-                           certificate_actual_size);
+  result = EncodeCoseSign1(
+      context, protected_attributes, protected_attributes_size, cwt_ptr,
+      cwt_size, /*move_payload=*/true, signature, certificate_buffer_size,
+      certificate, certificate_actual_size);
 
 out:
   DiceClearMemory(context, sizeof(subject_private_key), subject_private_key);
@@ -426,3 +465,55 @@ out:
 
   return result;
 }
+
+DiceResult DiceCoseEncodePublicKey(
+    void* context, DicePrincipal principal,
+    const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE], size_t buffer_size,
+    uint8_t* buffer, size_t* encoded_size) {
+  DiceKeyParam key_param;
+  DiceResult result = DiceGetKeyParam(context, principal, &key_param);
+  if (result != kDiceResultOk) {
+    return result;
+  }
+  struct CborOut out;
+  CborOutInit(buffer, buffer_size, &out);
+  if (key_param.cose_key_type == kCoseKeyKtyOkp) {
+    CborWriteMap(/*num_pairs=*/5, &out);
+  } else if (key_param.cose_key_type == kCoseKeyKtyEc2) {
+    CborWriteMap(/*num_pairs=*/6, &out);
+  } else {
+    return kDiceResultInvalidInput;
+  }
+  // Add the key type.
+  CborWriteInt(kCoseKeyKtyLabel, &out);
+  CborWriteInt(key_param.cose_key_type, &out);
+  // Add the algorithm.
+  CborWriteInt(kCoseKeyAlgLabel, &out);
+  CborWriteInt(key_param.cose_key_algorithm, &out);
+  // Add the KeyOps.
+  CborWriteInt(kCoseKeyOpsLabel, &out);
+  CborWriteArray(/*num_elements=*/1, &out);
+  CborWriteInt(kCoseKeyOpsVerify, &out);
+  // Add the curve.
+  CborWriteInt(kCoseKeyCrvLabel, &out);
+  CborWriteInt(key_param.cose_key_curve, &out);
+
+  // Add the public key.
+  if (key_param.cose_key_type == kCoseKeyKtyOkp) {
+    CborWriteInt(kCoseKeyXLabel, &out);
+    CborWriteBstr(key_param.public_key_size, public_key, &out);
+  } else if (key_param.cose_key_type == kCoseKeyKtyEc2) {
+    // Add the subject public key x and y coordinates
+    int xy_param_size = key_param.public_key_size / 2;
+    CborWriteInt(kCoseKeyXLabel, &out);
+    CborWriteBstr(xy_param_size, &public_key[0], &out);
+    CborWriteInt(kCoseKeyYLabel, &out);
+    CborWriteBstr(xy_param_size, &public_key[xy_param_size], &out);
+  }
+
+  *encoded_size = CborOutSize(&out);
+  if (CborOutOverflowed(&out)) {
+    return kDiceResultBufferTooSmall;
+  }
+  return kDiceResultOk;
+}
diff --git a/src/cbor_cert_op_test.cc b/src/cbor_cert_op_test.cc
index 46ae094..db7545f 100644
--- a/src/cbor_cert_op_test.cc
+++ b/src/cbor_cert_op_test.cc
@@ -250,16 +250,17 @@ TEST(DiceOpsTest, CoseSignAndEncodeSign1) {
                                        private_key_seed);
   ASSERT_EQ(kDiceResultOk, result);
 
-  uint8_t private_key[DICE_PRIVATE_KEY_SIZE];
-  uint8_t public_key[DICE_PUBLIC_KEY_SIZE];
-  result = DiceKeypairFromSeed(NULL, private_key_seed, public_key, private_key);
+  uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
+  uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+  result = DiceKeypairFromSeed(NULL, kDicePrincipalAuthority, private_key_seed,
+                               public_key, private_key);
   ASSERT_EQ(kDiceResultOk, result);
 
-  uint8_t encoded_public_key[DICE_PUBLIC_KEY_SIZE + 32];
+  uint8_t encoded_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE + 32];
   size_t encoded_public_key_size = 0;
-  result =
-      DiceCoseEncodePublicKey(NULL, public_key, sizeof(encoded_public_key),
-                              encoded_public_key, &encoded_public_key_size);
+  result = DiceCoseEncodePublicKey(
+      NULL, kDicePrincipalAuthority, public_key, sizeof(encoded_public_key),
+      encoded_public_key, &encoded_public_key_size);
   ASSERT_EQ(kDiceResultOk, result);
 
   uint8_t payload[500];
diff --git a/src/cbor_ed25519_cert_op.c b/src/cbor_ed25519_cert_op.c
deleted file mode 100644
index a2c5fbf..0000000
--- a/src/cbor_ed25519_cert_op.c
+++ /dev/null
@@ -1,70 +0,0 @@
-// Copyright 2023 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License"); you may not
-// use this file except in compliance with the License. You may obtain a copy of
-// the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-// License for the specific language governing permissions and limitations under
-// the License.
-
-#include <stddef.h>
-#include <stdint.h>
-#include <string.h>
-
-#include "dice/cbor_writer.h"
-#include "dice/ops/trait/cose.h"
-
-#if DICE_PUBLIC_KEY_SIZE != 32
-#error "Only Ed25519 is supported; 32 bytes needed to store the public key."
-#endif
-#if DICE_SIGNATURE_SIZE != 64
-#error "Only Ed25519 is supported; 64 bytes needed to store the signature."
-#endif
-
-DiceResult DiceCoseEncodePublicKey(
-    void* context_not_used, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-    size_t buffer_size, uint8_t* buffer, size_t* encoded_size) {
-  (void)context_not_used;
-
-  // Constants per RFC 8152.
-  const int64_t kCoseKeyKtyLabel = 1;
-  const int64_t kCoseKeyAlgLabel = 3;
-  const int64_t kCoseKeyOpsLabel = 4;
-  const int64_t kCoseOkpCrvLabel = -1;
-  const int64_t kCoseOkpXLabel = -2;
-  const int64_t kCoseKeyTypeOkp = 1;
-  const int64_t kCoseAlgEdDSA = DICE_COSE_KEY_ALG_VALUE;
-  const int64_t kCoseKeyOpsVerify = 2;
-  const int64_t kCoseCrvEd25519 = 6;
-
-  struct CborOut out;
-  CborOutInit(buffer, buffer_size, &out);
-  CborWriteMap(/*num_pairs=*/5, &out);
-  // Add the key type.
-  CborWriteInt(kCoseKeyKtyLabel, &out);
-  CborWriteInt(kCoseKeyTypeOkp, &out);
-  // Add the algorithm.
-  CborWriteInt(kCoseKeyAlgLabel, &out);
-  CborWriteInt(kCoseAlgEdDSA, &out);
-  // Add the KeyOps.
-  CborWriteInt(kCoseKeyOpsLabel, &out);
-  CborWriteArray(/*num_elements=*/1, &out);
-  CborWriteInt(kCoseKeyOpsVerify, &out);
-  // Add the curve.
-  CborWriteInt(kCoseOkpCrvLabel, &out);
-  CborWriteInt(kCoseCrvEd25519, &out);
-  // Add the public key.
-  CborWriteInt(kCoseOkpXLabel, &out);
-  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE, public_key, &out);
-
-  *encoded_size = CborOutSize(&out);
-  if (CborOutOverflowed(&out)) {
-    return kDiceResultBufferTooSmall;
-  }
-  return kDiceResultOk;
-}
diff --git a/src/cbor_multialg_op_test.cc b/src/cbor_multialg_op_test.cc
new file mode 100644
index 0000000..8e8eadd
--- /dev/null
+++ b/src/cbor_multialg_op_test.cc
@@ -0,0 +1,754 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+
+#include <memory>
+
+#include "dice/config.h"
+#include "dice/dice.h"
+#include "dice/known_test_values.h"
+#include "dice/test_framework.h"
+#include "dice/test_utils.h"
+#include "dice/utils.h"
+#include "pw_string/format.h"
+
+namespace {
+
+using dice::test::CertificateType_Cbor;
+using dice::test::DeriveFakeInputValue;
+using dice::test::DiceStateForTest;
+using dice::test::KeyType_Ed25519;
+using dice::test::KeyType_P256;
+using dice::test::KeyType_P384;
+
+TEST(DiceOpsTest, InvalidContextReturnsError) {
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultInvalidInput, result);
+}
+
+TEST(DiceOpsTest, Ed25519KnownAnswerZeroInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_Ed25519, "zero_input", next_state);
+  // The CDI values should be deterministic.
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
+                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
+                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_ZeroInput),
+            next_state.certificate_size);
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_ZeroInput,
+                      next_state.certificate, next_state.certificate_size));
+}
+
+TEST(DiceOpsTest, P256KnownAnswerZeroInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P256, "zero_input", next_state);
+  // The CDI values should be deterministic.
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
+                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
+                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_ZeroInput),
+            next_state.certificate_size);
+  // Comparing everything except for the signature, since ECDSA signatures are
+  // not deterministic
+  constexpr size_t signature_size = 64;
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_ZeroInput,
+                      next_state.certificate,
+                      next_state.certificate_size - signature_size));
+}
+
+TEST(DiceOpsTest, P384KnownAnswerZeroInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P384, "zero_input", next_state);
+  // The CDI values should be deterministic.
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
+                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
+                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_ZeroInput),
+            next_state.certificate_size);
+  // Comparing everything except for the signature, since ECDSA signatures are
+  // not deterministic
+  constexpr size_t signature_size = 96;
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_ZeroInput,
+                      next_state.certificate,
+                      next_state.certificate_size - signature_size));
+}
+
+TEST(DiceOpsTest, Ed25519KnownAnswerHashOnlyInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  input_values.config_type = kDiceConfigTypeInline;
+  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
+                       input_values.config_value);
+
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_Ed25519, "hash_only_input",
+            next_state);
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
+                DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_HashOnlyInput),
+            next_state.certificate_size);
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_HashOnlyInput,
+                      next_state.certificate, next_state.certificate_size));
+}
+
+TEST(DiceOpsTest, P256KnownAnswerHashOnlyInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  input_values.config_type = kDiceConfigTypeInline;
+  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
+                       input_values.config_value);
+
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P256, "hash_only_input", next_state);
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
+                DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_HashOnlyInput),
+            next_state.certificate_size);
+  constexpr size_t signature_size = 64;
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_HashOnlyInput,
+                      next_state.certificate,
+                      next_state.certificate_size - signature_size));
+}
+
+TEST(DiceOpsTest, P384KnownAnswerHashOnlyInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  input_values.config_type = kDiceConfigTypeInline;
+  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
+                       input_values.config_value);
+
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P384, "hash_only_input", next_state);
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
+                DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_HashOnlyInput),
+            next_state.certificate_size);
+  constexpr size_t signature_size = 96;
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_HashOnlyInput,
+                      next_state.certificate,
+                      next_state.certificate_size - signature_size));
+}
+
+TEST(DiceOpsTest, Ed25519KnownAnswerDescriptorInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+
+  DiceStateForTest next_state = {};
+
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  uint8_t code_descriptor[100];
+  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
+  input_values.code_descriptor = code_descriptor;
+  input_values.code_descriptor_size = sizeof(code_descriptor);
+
+  uint8_t config_descriptor[40];
+  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
+                       config_descriptor);
+  input_values.config_descriptor = config_descriptor;
+  input_values.config_descriptor_size = sizeof(config_descriptor);
+  input_values.config_type = kDiceConfigTypeDescriptor;
+
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  uint8_t authority_descriptor[65];
+  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
+                       authority_descriptor);
+  input_values.authority_descriptor = authority_descriptor;
+  input_values.authority_descriptor_size = sizeof(authority_descriptor);
+
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_Ed25519, "descriptor_input",
+            next_state);
+  // Both CDI values and the certificate should be deterministic.
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal,
+                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_DescriptorInput),
+            next_state.certificate_size);
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_DescriptorInput,
+                      next_state.certificate, next_state.certificate_size));
+}
+
+TEST(DiceOpsTest, P256KnownAnswerDescriptorInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+
+  DiceStateForTest next_state = {};
+
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  uint8_t code_descriptor[100];
+  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
+  input_values.code_descriptor = code_descriptor;
+  input_values.code_descriptor_size = sizeof(code_descriptor);
+
+  uint8_t config_descriptor[40];
+  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
+                       config_descriptor);
+  input_values.config_descriptor = config_descriptor;
+  input_values.config_descriptor_size = sizeof(config_descriptor);
+  input_values.config_type = kDiceConfigTypeDescriptor;
+
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  uint8_t authority_descriptor[65];
+  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
+                       authority_descriptor);
+  input_values.authority_descriptor = authority_descriptor;
+  input_values.authority_descriptor_size = sizeof(authority_descriptor);
+
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P256, "descriptor_input", next_state);
+  // Both CDI values and the certificate should be deterministic.
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal,
+                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_DescriptorInput),
+            next_state.certificate_size);
+  constexpr size_t signature_size = 64;
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_DescriptorInput,
+                      next_state.certificate,
+                      next_state.certificate_size - signature_size));
+}
+
+TEST(DiceOpsTest, P384KnownAnswerDescriptorInput) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+
+  DiceStateForTest next_state = {};
+
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  uint8_t code_descriptor[100];
+  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
+  input_values.code_descriptor = code_descriptor;
+  input_values.code_descriptor_size = sizeof(code_descriptor);
+
+  uint8_t config_descriptor[40];
+  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
+                       config_descriptor);
+  input_values.config_descriptor = config_descriptor;
+  input_values.config_descriptor_size = sizeof(config_descriptor);
+  input_values.config_type = kDiceConfigTypeDescriptor;
+
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  uint8_t authority_descriptor[65];
+  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
+                       authority_descriptor);
+  input_values.authority_descriptor = authority_descriptor;
+  input_values.authority_descriptor_size = sizeof(authority_descriptor);
+
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P384, "descriptor_input", next_state);
+  // Both CDI values and the certificate should be deterministic.
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal,
+                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_DescriptorInput),
+            next_state.certificate_size);
+  constexpr size_t signature_size = 96;
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_DescriptorInput,
+                      next_state.certificate,
+                      next_state.certificate_size - signature_size));
+}
+
+TEST(DiceOpsTest, Ed25519NonZeroMode) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  constexpr size_t kModeOffsetInCert = 315;
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.mode = kDiceModeDebug;
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
+}
+
+TEST(DiceOpsTest, P256NonZeroMode) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  constexpr size_t kModeOffsetInCert = 315;
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.mode = kDiceModeDebug;
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
+}
+
+TEST(DiceOpsTest, P384NonZeroMode) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  constexpr size_t kModeOffsetInCert = 316;
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.mode = kDiceModeDebug;
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
+}
+
+TEST(DiceOpsTest, Ed25519LargeInputs) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.code_descriptor = kBigBuffer;
+  input_values.code_descriptor_size = sizeof(kBigBuffer);
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultBufferTooSmall, result);
+}
+
+TEST(DiceOpsTest, P256LargeInputs) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.code_descriptor = kBigBuffer;
+  input_values.code_descriptor_size = sizeof(kBigBuffer);
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultBufferTooSmall, result);
+}
+
+TEST(DiceOpsTest, P384LargeInputs) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.code_descriptor = kBigBuffer;
+  input_values.code_descriptor_size = sizeof(kBigBuffer);
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultBufferTooSmall, result);
+}
+
+TEST(DiceOpsTest, Ed25519InvalidConfigType) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.config_type = (DiceConfigType)55;
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultInvalidInput, result);
+}
+
+TEST(DiceOpsTest, P256InvalidConfigType) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.config_type = (DiceConfigType)55;
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultInvalidInput, result);
+}
+
+TEST(DiceOpsTest, P384InvalidConfigType) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.config_type = (DiceConfigType)55;
+  DiceResult result = DiceMainFlow(
+      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultInvalidInput, result);
+}
+
+TEST(DiceOpsTest, Ed25519PartialCertChain) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "part_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_Ed25519, suffix, states[i + 1]);
+  }
+  // Use the first derived CDI cert as the 'root' of partial chain.
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
+      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
+}
+
+TEST(DiceOpsTest, P256PartialCertChain) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "part_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_P256, suffix, states[i + 1]);
+  }
+  // Use the first derived CDI cert as the 'root' of partial chain.
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
+      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
+}
+
+TEST(DiceOpsTest, P384PartialCertChain) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "part_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_P384, suffix, states[i + 1]);
+  }
+  // Use the first derived CDI cert as the 'root' of partial chain.
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
+      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
+}
+
+TEST(DiceOpsTest, Ed25519FullCertChain) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
+                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "full_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_Ed25519, suffix, states[i + 1]);
+  }
+  // Use a fake self-signed UDS cert as the 'root'.
+  uint8_t root_certificate[dice::test::kTestCertSize];
+  size_t root_certificate_size = 0;
+  dice::test::CreateFakeUdsCertificate(
+      &context, states[0].cdi_attest, CertificateType_Cbor, KeyType_Ed25519,
+      root_certificate, &root_certificate_size);
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
+      kNumLayers, /*is_partial_chain=*/false));
+}
+
+TEST(DiceOpsTest, P256FullCertChain) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
+                      .subject_algorithm = kDiceKeyAlgorithmP256};
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "full_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_P256, suffix, states[i + 1]);
+  }
+  // Use a fake self-signed UDS cert as the 'root'.
+  uint8_t root_certificate[dice::test::kTestCertSize];
+  size_t root_certificate_size = 0;
+  dice::test::CreateFakeUdsCertificate(
+      &context, states[0].cdi_attest, CertificateType_Cbor, KeyType_P256,
+      root_certificate, &root_certificate_size);
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
+      kNumLayers, /*is_partial_chain=*/false));
+}
+
+TEST(DiceOpsTest, P384FullCertChain) {
+  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
+                      .subject_algorithm = kDiceKeyAlgorithmP384};
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "full_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_P384, suffix, states[i + 1]);
+  }
+  // Use a fake self-signed UDS cert as the 'root'.
+  uint8_t root_certificate[dice::test::kTestCertSize];
+  size_t root_certificate_size = 0;
+  dice::test::CreateFakeUdsCertificate(
+      &context, states[0].cdi_attest, CertificateType_Cbor, KeyType_P384,
+      root_certificate, &root_certificate_size);
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
+      kNumLayers, /*is_partial_chain=*/false));
+}
+
+}  // namespace
diff --git a/src/cbor_p256_cert_op.c b/src/cbor_p256_cert_op.c
deleted file mode 100644
index fdc7e11..0000000
--- a/src/cbor_p256_cert_op.c
+++ /dev/null
@@ -1,80 +0,0 @@
-// Copyright 2024 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License"); you may not
-// use this file except in compliance with the License. You may obtain a copy of
-// the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-// License for the specific language governing permissions and limitations under
-// the License.
-
-// This is a DiceGenerateCertificate implementation that generates a CWT-style
-// CBOR certificate using the P-256 signature algorithm.
-
-#include <stddef.h>
-#include <stdint.h>
-#include <string.h>
-
-#include "dice/cbor_writer.h"
-#include "dice/dice.h"
-#include "dice/ops.h"
-#include "dice/ops/trait/cose.h"
-#include "dice/utils.h"
-
-#if DICE_PUBLIC_KEY_SIZE != 64
-#error "64 bytes needed to store the public key."
-#endif
-#if DICE_SIGNATURE_SIZE != 64
-#error "64 bytes needed to store the signature."
-#endif
-
-DiceResult DiceCoseEncodePublicKey(
-    void* context_not_used, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-    size_t buffer_size, uint8_t* buffer, size_t* encoded_size) {
-  (void)context_not_used;
-
-  // Constants per RFC 8152.
-  const int64_t kCoseKeyKtyLabel = 1;
-  const int64_t kCoseKeyAlgLabel = 3;
-  const int64_t kCoseKeyAlgValue = DICE_COSE_KEY_ALG_VALUE;
-  const int64_t kCoseKeyOpsLabel = 4;
-  const int64_t kCoseKeyOpsValue = 2;  // Verify
-  const int64_t kCoseKeyKtyValue = 2;  // EC2
-  const int64_t kCoseEc2CrvLabel = -1;
-  const int64_t kCoseEc2CrvValue = 1;  // P-256
-  const int64_t kCoseEc2XLabel = -2;
-  const int64_t kCoseEc2YLabel = -3;
-
-  struct CborOut out;
-  CborOutInit(buffer, buffer_size, &out);
-  CborWriteMap(/*num_pairs=*/6, &out);
-  // Add the key type.
-  CborWriteInt(kCoseKeyKtyLabel, &out);
-  CborWriteInt(kCoseKeyKtyValue, &out);
-  // Add the algorithm.
-  CborWriteInt(kCoseKeyAlgLabel, &out);
-  CborWriteInt(kCoseKeyAlgValue, &out);
-  // Add the KeyOps.
-  CborWriteInt(kCoseKeyOpsLabel, &out);
-  CborWriteArray(/*num_elements=*/1, &out);
-  CborWriteInt(kCoseKeyOpsValue, &out);
-  // Add the curve.
-  CborWriteInt(kCoseEc2CrvLabel, &out);
-  CborWriteInt(kCoseEc2CrvValue, &out);
-  // Add the subject public key x and y coordinates
-  CborWriteInt(kCoseEc2XLabel, &out);
-  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2, &public_key[0], &out);
-  CborWriteInt(kCoseEc2YLabel, &out);
-  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2,
-                &public_key[DICE_PUBLIC_KEY_SIZE / 2], &out);
-
-  *encoded_size = CborOutSize(&out);
-  if (CborOutOverflowed(&out)) {
-    return kDiceResultBufferTooSmall;
-  }
-  return kDiceResultOk;
-}
diff --git a/src/cbor_p256_cert_op_test.cc b/src/cbor_p256_cert_op_test.cc
index 32fc2e2..c345e8b 100644
--- a/src/cbor_p256_cert_op_test.cc
+++ b/src/cbor_p256_cert_op_test.cc
@@ -56,9 +56,10 @@ TEST(DiceOpsTest, KnownAnswerZeroInput) {
             next_state.certificate_size);
   // Comparing everything except for the signature, since ECDSA signatures are
   // not deterministic
-  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_ZeroInput,
-                      next_state.certificate,
-                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+  EXPECT_EQ(0,
+            memcmp(dice::test::kExpectedCborP256Cert_ZeroInput,
+                   next_state.certificate,
+                   next_state.certificate_size - DICE_SIGNATURE_BUFFER_SIZE));
 }
 
 TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
@@ -92,9 +93,10 @@ TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
                 DICE_CDI_SIZE));
   ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_HashOnlyInput),
             next_state.certificate_size);
-  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_HashOnlyInput,
-                      next_state.certificate,
-                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+  EXPECT_EQ(0,
+            memcmp(dice::test::kExpectedCborP256Cert_HashOnlyInput,
+                   next_state.certificate,
+                   next_state.certificate_size - DICE_SIGNATURE_BUFFER_SIZE));
 }
 
 TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
@@ -141,9 +143,10 @@ TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
                 dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
   ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_DescriptorInput),
             next_state.certificate_size);
-  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_DescriptorInput,
-                      next_state.certificate,
-                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+  EXPECT_EQ(0,
+            memcmp(dice::test::kExpectedCborP256Cert_DescriptorInput,
+                   next_state.certificate,
+                   next_state.certificate_size - DICE_SIGNATURE_BUFFER_SIZE));
 }
 
 TEST(DiceOpsTest, NonZeroMode) {
diff --git a/src/cbor_p384_cert_op.c b/src/cbor_p384_cert_op.c
deleted file mode 100644
index 8e9df7a..0000000
--- a/src/cbor_p384_cert_op.c
+++ /dev/null
@@ -1,80 +0,0 @@
-// Copyright 2023 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License"); you may not
-// use this file except in compliance with the License. You may obtain a copy of
-// the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-// License for the specific language governing permissions and limitations under
-// the License.
-
-// This is a DiceGenerateCertificate implementation that generates a CWT-style
-// CBOR certificate using the P-384 signature algorithm.
-
-#include <stddef.h>
-#include <stdint.h>
-#include <string.h>
-
-#include "dice/cbor_writer.h"
-#include "dice/dice.h"
-#include "dice/ops.h"
-#include "dice/ops/trait/cose.h"
-#include "dice/utils.h"
-
-#if DICE_PUBLIC_KEY_SIZE != 96
-#error "96 bytes needed to store the public key."
-#endif
-#if DICE_SIGNATURE_SIZE != 96
-#error "96 bytes needed to store the signature."
-#endif
-
-DiceResult DiceCoseEncodePublicKey(
-    void* context_not_used, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
-    size_t buffer_size, uint8_t* buffer, size_t* encoded_size) {
-  (void)context_not_used;
-
-  // Constants per RFC 8152.
-  const int64_t kCoseKeyKtyLabel = 1;
-  const int64_t kCoseKeyAlgLabel = 3;
-  const int64_t kCoseKeyAlgValue = DICE_COSE_KEY_ALG_VALUE;
-  const int64_t kCoseKeyOpsLabel = 4;
-  const int64_t kCoseKeyOpsValue = 2;  // Verify
-  const int64_t kCoseKeyKtyValue = 2;  // EC2
-  const int64_t kCoseEc2CrvLabel = -1;
-  const int64_t kCoseEc2CrvValue = 2;  // P-384
-  const int64_t kCoseEc2XLabel = -2;
-  const int64_t kCoseEc2YLabel = -3;
-
-  struct CborOut out;
-  CborOutInit(buffer, buffer_size, &out);
-  CborWriteMap(/*num_pairs=*/6, &out);
-  // Add the key type.
-  CborWriteInt(kCoseKeyKtyLabel, &out);
-  CborWriteInt(kCoseKeyKtyValue, &out);
-  // Add the algorithm.
-  CborWriteInt(kCoseKeyAlgLabel, &out);
-  CborWriteInt(kCoseKeyAlgValue, &out);
-  // Add the KeyOps.
-  CborWriteInt(kCoseKeyOpsLabel, &out);
-  CborWriteArray(/*num_elements=*/1, &out);
-  CborWriteInt(kCoseKeyOpsValue, &out);
-  // Add the curve.
-  CborWriteInt(kCoseEc2CrvLabel, &out);
-  CborWriteInt(kCoseEc2CrvValue, &out);
-  // Add the subject public key x and y coordinates
-  CborWriteInt(kCoseEc2XLabel, &out);
-  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2, &public_key[0], &out);
-  CborWriteInt(kCoseEc2YLabel, &out);
-  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2,
-                &public_key[DICE_PUBLIC_KEY_SIZE / 2], &out);
-
-  *encoded_size = CborOutSize(&out);
-  if (CborOutOverflowed(&out)) {
-    return kDiceResultBufferTooSmall;
-  }
-  return kDiceResultOk;
-}
diff --git a/src/cbor_p384_cert_op_test.cc b/src/cbor_p384_cert_op_test.cc
index 21d0331..44624e6 100644
--- a/src/cbor_p384_cert_op_test.cc
+++ b/src/cbor_p384_cert_op_test.cc
@@ -56,9 +56,10 @@ TEST(DiceOpsTest, KnownAnswerZeroInput) {
             next_state.certificate_size);
   // Comparing everything except for the signature, since ECDSA signatures are
   // not deterministic
-  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_ZeroInput,
-                      next_state.certificate,
-                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+  EXPECT_EQ(0,
+            memcmp(dice::test::kExpectedCborP384Cert_ZeroInput,
+                   next_state.certificate,
+                   next_state.certificate_size - DICE_SIGNATURE_BUFFER_SIZE));
 }
 
 TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
@@ -92,9 +93,10 @@ TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
                 DICE_CDI_SIZE));
   ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_HashOnlyInput),
             next_state.certificate_size);
-  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_HashOnlyInput,
-                      next_state.certificate,
-                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+  EXPECT_EQ(0,
+            memcmp(dice::test::kExpectedCborP384Cert_HashOnlyInput,
+                   next_state.certificate,
+                   next_state.certificate_size - DICE_SIGNATURE_BUFFER_SIZE));
 }
 
 TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
@@ -141,9 +143,10 @@ TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
                 dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
   ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_DescriptorInput),
             next_state.certificate_size);
-  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_DescriptorInput,
-                      next_state.certificate,
-                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+  EXPECT_EQ(0,
+            memcmp(dice::test::kExpectedCborP384Cert_DescriptorInput,
+                   next_state.certificate,
+                   next_state.certificate_size - DICE_SIGNATURE_BUFFER_SIZE));
 }
 
 TEST(DiceOpsTest, NonZeroMode) {
diff --git a/src/clear_memory.c b/src/clear_memory.c
index 0fdc7cf..405793c 100644
--- a/src/clear_memory.c
+++ b/src/clear_memory.c
@@ -17,7 +17,9 @@
 // volatile data pointer. Attention has not been given to performance, clearing
 // caches or other potential side channels.
 
-#include "dice/ops.h"
+#include "dice/ops/clear_memory.h"
+
+#include <stdint.h>
 
 void DiceClearMemory(void* context, size_t size, void* address) {
   (void)context;
diff --git a/src/template_cbor_cert_op.c b/src/template_cbor_cert_op.c
index c935dfb..3492505 100644
--- a/src/template_cbor_cert_op.c
+++ b/src/template_cbor_cert_op.c
@@ -42,10 +42,10 @@
 #include "dice/ops.h"
 #include "dice/utils.h"
 
-#if DICE_PUBLIC_KEY_SIZE != 32
+#if DICE_PUBLIC_KEY_BUFFER_SIZE != 32
 #error "Only Ed25519 is supported; 32 bytes needed to store the public key."
 #endif
-#if DICE_SIGNATURE_SIZE != 64
+#if DICE_SIGNATURE_BUFFER_SIZE != 64
 #error "Only Ed25519 is supported; 64 bytes needed to store the signature."
 #endif
 
@@ -164,10 +164,16 @@ DiceResult DiceGenerateCertificate(
     uint8_t* certificate, size_t* certificate_actual_size) {
   DiceResult result = kDiceResultOk;
 
+  DiceKeyParam key_param;
+  result = DiceGetKeyParam(context, kDicePrincipalSubject, &key_param);
+  if (result != kDiceResultOk) {
+    goto out;
+  }
+
   // Variable length descriptors are not supported.
   if (input_values->code_descriptor_size > 0 ||
       input_values->config_type != kDiceConfigTypeInline ||
-      input_values->authority_descriptor_size > 0 || DICE_PROFILE_NAME) {
+      input_values->authority_descriptor_size > 0 || key_param.profile_name) {
     return kDiceResultInvalidInput;
   }
 
@@ -178,20 +184,21 @@ DiceResult DiceGenerateCertificate(
   }
 
   // Declare buffers which are cleared on 'goto out'.
-  uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE];
-  uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE];
+  uint8_t subject_private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
+  uint8_t authority_private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
 
   // Derive keys and IDs from the private key seeds.
-  uint8_t subject_public_key[DICE_PUBLIC_KEY_SIZE];
-  result = DiceKeypairFromSeed(context, subject_private_key_seed,
-                               subject_public_key, subject_private_key);
+  uint8_t subject_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+  result = DiceKeypairFromSeed(context, kDicePrincipalSubject,
+                               subject_private_key_seed, subject_public_key,
+                               subject_private_key);
   if (result != kDiceResultOk) {
     goto out;
   }
 
   uint8_t subject_id[DICE_ID_SIZE];
   result = DiceDeriveCdiCertificateId(context, subject_public_key,
-                                      DICE_PUBLIC_KEY_SIZE, subject_id);
+                                      DICE_PUBLIC_KEY_BUFFER_SIZE, subject_id);
   if (result != kDiceResultOk) {
     goto out;
   }
@@ -199,16 +206,17 @@ DiceResult DiceGenerateCertificate(
   DiceHexEncode(subject_id, sizeof(subject_id), subject_id_hex,
                 sizeof(subject_id_hex));
 
-  uint8_t authority_public_key[DICE_PUBLIC_KEY_SIZE];
-  result = DiceKeypairFromSeed(context, authority_private_key_seed,
-                               authority_public_key, authority_private_key);
+  uint8_t authority_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+  result = DiceKeypairFromSeed(context, kDicePrincipalAuthority,
+                               authority_private_key_seed, authority_public_key,
+                               authority_private_key);
   if (result != kDiceResultOk) {
     goto out;
   }
 
   uint8_t authority_id[DICE_ID_SIZE];
-  result = DiceDeriveCdiCertificateId(context, authority_public_key,
-                                      DICE_PUBLIC_KEY_SIZE, authority_id);
+  result = DiceDeriveCdiCertificateId(
+      context, authority_public_key, DICE_PUBLIC_KEY_BUFFER_SIZE, authority_id);
   if (result != kDiceResultOk) {
     goto out;
   }
@@ -235,7 +243,7 @@ DiceResult DiceGenerateCertificate(
          &certificate[kFieldTable[kFieldIndexPayload].offset],
          kFieldTable[kFieldIndexPayload].length);
 
-  uint8_t signature[DICE_SIGNATURE_SIZE];
+  uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE];
   result =
       DiceSign(context, tbs, sizeof(tbs), authority_private_key, signature);
   if (result != kDiceResultOk) {
diff --git a/src/template_cert_op.c b/src/template_cert_op.c
index 7dcb16f..cc9f553 100644
--- a/src/template_cert_op.c
+++ b/src/template_cert_op.c
@@ -174,10 +174,16 @@ DiceResult DiceGenerateCertificate(
     uint8_t* certificate, size_t* certificate_actual_size) {
   DiceResult result = kDiceResultOk;
 
+  DiceKeyParam key_param;
+  result = DiceGetKeyParam(context, kDicePrincipalSubject, &key_param);
+  if (result != kDiceResultOk) {
+    goto out;
+  }
+
   // Variable length descriptors are not supported.
   if (input_values->code_descriptor_size > 0 ||
       input_values->config_type != kDiceConfigTypeInline ||
-      input_values->authority_descriptor_size > 0 || DICE_PROFILE_NAME) {
+      input_values->authority_descriptor_size > 0 || key_param.profile_name) {
     return kDiceResultInvalidInput;
   }
 
diff --git a/third_party/cose-c/BUILD.gn b/third_party/cose-c/BUILD.gn
index 6d26a92..558828a 100644
--- a/third_party/cose-c/BUILD.gn
+++ b/third_party/cose-c/BUILD.gn
@@ -36,6 +36,13 @@ config("external_config_p384") {
   ]
 }
 
+config("external_config_multialg") {
+  include_dirs = [
+    "src/include",
+    "include/multialg",
+  ]
+}
+
 config("internal_config") {
   visibility = [ ":*" ]  # Only targets in this file can depend on this.
   include_dirs = [ "src/src" ]
@@ -82,3 +89,20 @@ pw_static_library("cose-c_p384") {
     "//third_party/cn-cbor:cn-cbor",
   ]
 }
+
+pw_static_library("cose-c_multialg") {
+  public = [ "src/include/cose/cose.h" ]
+  sources = [
+    "cose_deps.cc",
+    "src/src/Cose.cpp",
+    "src/src/CoseKey.cpp",
+    "src/src/Sign1.cpp",
+    "src/src/cbor.cpp",
+  ]
+  public_configs = [ ":external_config_multialg" ]
+  configs = [ ":internal_config" ]
+  public_deps = [
+    "//third_party/boringssl:crypto",
+    "//third_party/cn-cbor:cn-cbor",
+  ]
+}
diff --git a/third_party/cose-c/include/multialg/cose/cose_configure.h b/third_party/cose-c/include/multialg/cose/cose_configure.h
new file mode 100644
index 0000000..e4e3e0c
--- /dev/null
+++ b/third_party/cose-c/include/multialg/cose/cose_configure.h
@@ -0,0 +1,17 @@
+#ifndef THIRD_PARTY_COSE_C_MULTIALG_COSE_COSE_CONFIGURE_H_
+#define THIRD_PARTY_COSE_C_MULTIALG_COSE_COSE_CONFIGURE_H_
+
+#define USE_EDDSA
+#define USE_ECDSA_SHA_256
+#define USE_ECDSA_SHA_384
+
+#define INCLUDE_ENCRYPT 0
+#define INCLUDE_ENCRYPT0 0
+#define INCLUDE_MAC 0
+#define INCLUDE_MAC0 0
+#define INCLUDE_SIGN 0
+#define INCLUDE_SIGN1 1
+#define INCLUDE_COUNTERSIGNATURE 0
+#define INCLUDE_COUNTERSIGNATURE1 0
+
+#endif  // THIRD_PARTY_COSE_C_MULTIALG_COSE_COSE_CONFIGURE_H_
```

