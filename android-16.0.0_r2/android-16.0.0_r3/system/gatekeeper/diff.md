```diff
diff --git a/rust/.gitignore b/rust/.gitignore
new file mode 100644
index 0000000..f1b3f97
--- /dev/null
+++ b/rust/.gitignore
@@ -0,0 +1,3 @@
+aidl
+target
+**/Cargo.lock
diff --git a/rust/Android.bp b/rust/Android.bp
new file mode 100644
index 0000000..cda66e9
--- /dev/null
+++ b/rust/Android.bp
@@ -0,0 +1,18 @@
+// Copyright 2025, The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_hardware_backed_security",
+}
diff --git a/rust/Cargo.toml b/rust/Cargo.toml
new file mode 100644
index 0000000..1eaf7a8
--- /dev/null
+++ b/rust/Cargo.toml
@@ -0,0 +1,14 @@
+[workspace]
+members = [
+  "ta",
+  "tests",
+  "wire",
+]
+resolver = "2"
+
+[patch.crates-io]
+gk-ta = { path = "ta" }
+gk-tests = { path = "tests" }
+gk-wire = { path = "wire" }
+hal-wire = { path = "../../security/hals/wire" }
+hal-wire-derive = { path = "../../security/hals/derive" }
diff --git a/rust/NOTICE b/rust/NOTICE
new file mode 100644
index 0000000..89ae7c4
--- /dev/null
+++ b/rust/NOTICE
@@ -0,0 +1,190 @@
+
+   Copyright (c) 2008-2015, The Android Open Source Project
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+   you may not use this file except in compliance with the License.
+
+   Unless required by applicable law or agreed to in writing, software
+   distributed under the License is distributed on an "AS IS" BASIS,
+   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+   See the License for the specific language governing permissions and
+   limitations under the License.
+
+
+                                 Apache License
+                           Version 2.0, January 2004
+                        http://www.apache.org/licenses/
+
+   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
+
+   1. Definitions.
+
+      "License" shall mean the terms and conditions for use, reproduction,
+      and distribution as defined by Sections 1 through 9 of this document.
+
+      "Licensor" shall mean the copyright owner or entity authorized by
+      the copyright owner that is granting the License.
+
+      "Legal Entity" shall mean the union of the acting entity and all
+      other entities that control, are controlled by, or are under common
+      control with that entity. For the purposes of this definition,
+      "control" means (i) the power, direct or indirect, to cause the
+      direction or management of such entity, whether by contract or
+      otherwise, or (ii) ownership of fifty percent (50%) or more of the
+      outstanding shares, or (iii) beneficial ownership of such entity.
+
+      "You" (or "Your") shall mean an individual or Legal Entity
+      exercising permissions granted by this License.
+
+      "Source" form shall mean the preferred form for making modifications,
+      including but not limited to software source code, documentation
+      source, and configuration files.
+
+      "Object" form shall mean any form resulting from mechanical
+      transformation or translation of a Source form, including but
+      not limited to compiled object code, generated documentation,
+      and conversions to other media types.
+
+      "Work" shall mean the work of authorship, whether in Source or
+      Object form, made available under the License, as indicated by a
+      copyright notice that is included in or attached to the work
+      (an example is provided in the Appendix below).
+
+      "Derivative Works" shall mean any work, whether in Source or Object
+      form, that is based on (or derived from) the Work and for which the
+      editorial revisions, annotations, elaborations, or other modifications
+      represent, as a whole, an original work of authorship. For the purposes
+      of this License, Derivative Works shall not include works that remain
+      separable from, or merely link (or bind by name) to the interfaces of,
+      the Work and Derivative Works thereof.
+
+      "Contribution" shall mean any work of authorship, including
+      the original version of the Work and any modifications or additions
+      to that Work or Derivative Works thereof, that is intentionally
+      submitted to Licensor for inclusion in the Work by the copyright owner
+      or by an individual or Legal Entity authorized to submit on behalf of
+      the copyright owner. For the purposes of this definition, "submitted"
+      means any form of electronic, verbal, or written communication sent
+      to the Licensor or its representatives, including but not limited to
+      communication on electronic mailing lists, source code control systems,
+      and issue tracking systems that are managed by, or on behalf of, the
+      Licensor for the purpose of discussing and improving the Work, but
+      excluding communication that is conspicuously marked or otherwise
+      designated in writing by the copyright owner as "Not a Contribution."
+
+      "Contributor" shall mean Licensor and any individual or Legal Entity
+      on behalf of whom a Contribution has been received by Licensor and
+      subsequently incorporated within the Work.
+
+   2. Grant of Copyright License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      copyright license to reproduce, prepare Derivative Works of,
+      publicly display, publicly perform, sublicense, and distribute the
+      Work and such Derivative Works in Source or Object form.
+
+   3. Grant of Patent License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      (except as stated in this section) patent license to make, have made,
+      use, offer to sell, sell, import, and otherwise transfer the Work,
+      where such license applies only to those patent claims licensable
+      by such Contributor that are necessarily infringed by their
+      Contribution(s) alone or by combination of their Contribution(s)
+      with the Work to which such Contribution(s) was submitted. If You
+      institute patent litigation against any entity (including a
+      cross-claim or counterclaim in a lawsuit) alleging that the Work
+      or a Contribution incorporated within the Work constitutes direct
+      or contributory patent infringement, then any patent licenses
+      granted to You under this License for that Work shall terminate
+      as of the date such litigation is filed.
+
+   4. Redistribution. You may reproduce and distribute copies of the
+      Work or Derivative Works thereof in any medium, with or without
+      modifications, and in Source or Object form, provided that You
+      meet the following conditions:
+
+      (a) You must give any other recipients of the Work or
+          Derivative Works a copy of this License; and
+
+      (b) You must cause any modified files to carry prominent notices
+          stating that You changed the files; and
+
+      (c) You must retain, in the Source form of any Derivative Works
+          that You distribute, all copyright, patent, trademark, and
+          attribution notices from the Source form of the Work,
+          excluding those notices that do not pertain to any part of
+          the Derivative Works; and
+
+      (d) If the Work includes a "NOTICE" text file as part of its
+          distribution, then any Derivative Works that You distribute must
+          include a readable copy of the attribution notices contained
+          within such NOTICE file, excluding those notices that do not
+          pertain to any part of the Derivative Works, in at least one
+          of the following places: within a NOTICE text file distributed
+          as part of the Derivative Works; within the Source form or
+          documentation, if provided along with the Derivative Works; or,
+          within a display generated by the Derivative Works, if and
+          wherever such third-party notices normally appear. The contents
+          of the NOTICE file are for informational purposes only and
+          do not modify the License. You may add Your own attribution
+          notices within Derivative Works that You distribute, alongside
+          or as an addendum to the NOTICE text from the Work, provided
+          that such additional attribution notices cannot be construed
+          as modifying the License.
+
+      You may add Your own copyright statement to Your modifications and
+      may provide additional or different license terms and conditions
+      for use, reproduction, or distribution of Your modifications, or
+      for any such Derivative Works as a whole, provided Your use,
+      reproduction, and distribution of the Work otherwise complies with
+      the conditions stated in this License.
+
+   5. Submission of Contributions. Unless You explicitly state otherwise,
+      any Contribution intentionally submitted for inclusion in the Work
+      by You to the Licensor shall be under the terms and conditions of
+      this License, without any additional terms or conditions.
+      Notwithstanding the above, nothing herein shall supersede or modify
+      the terms of any separate license agreement you may have executed
+      with Licensor regarding such Contributions.
+
+   6. Trademarks. This License does not grant permission to use the trade
+      names, trademarks, service marks, or product names of the Licensor,
+      except as required for reasonable and customary use in describing the
+      origin of the Work and reproducing the content of the NOTICE file.
+
+   7. Disclaimer of Warranty. Unless required by applicable law or
+      agreed to in writing, Licensor provides the Work (and each
+      Contributor provides its Contributions) on an "AS IS" BASIS,
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
+      implied, including, without limitation, any warranties or conditions
+      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
+      PARTICULAR PURPOSE. You are solely responsible for determining the
+      appropriateness of using or redistributing the Work and assume any
+      risks associated with Your exercise of permissions under this License.
+
+   8. Limitation of Liability. In no event and under no legal theory,
+      whether in tort (including negligence), contract, or otherwise,
+      unless required by applicable law (such as deliberate and grossly
+      negligent acts) or agreed to in writing, shall any Contributor be
+      liable to You for damages, including any direct, indirect, special,
+      incidental, or consequential damages of any character arising as a
+      result of this License or out of the use or inability to use the
+      Work (including but not limited to damages for loss of goodwill,
+      work stoppage, computer failure or malfunction, or any and all
+      other commercial damages or losses), even if such Contributor
+      has been advised of the possibility of such damages.
+
+   9. Accepting Warranty or Additional Liability. While redistributing
+      the Work or Derivative Works thereof, You may choose to offer,
+      and charge a fee for, acceptance of support, warranty, indemnity,
+      or other liability obligations and/or rights consistent with this
+      License. However, in accepting such obligations, You may act only
+      on Your own behalf and on Your sole responsibility, not on behalf
+      of any other Contributor, and only if You agree to indemnify,
+      defend, and hold each Contributor harmless for any liability
+      incurred by, or claims asserted against, such Contributor by reason
+      of your accepting any such warranty or additional liability.
+
+   END OF TERMS AND CONDITIONS
+
diff --git a/rust/PREUPLOAD.cfg b/rust/PREUPLOAD.cfg
new file mode 100644
index 0000000..7ba873b
--- /dev/null
+++ b/rust/PREUPLOAD.cfg
@@ -0,0 +1,7 @@
+[Builtin Hooks]
+clang_format = true
+rustfmt = true
+
+[Builtin Hooks Options]
+clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=rustfmt.toml
diff --git a/rust/README.md b/rust/README.md
new file mode 100644
index 0000000..39fd03f
--- /dev/null
+++ b/rust/README.md
@@ -0,0 +1,142 @@
+# Gatekeeper Rust Reference Implementation
+
+This repository holds a reference implementation of the Android
+[Gatekeeper
+HAL](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/gatekeeper/aidl/android/hardware/gatekeeper/IGatekeeper.aidl).
+
+## Repository Structure
+
+The codebase is divided into a number of interdependent crates, as follows.
+
+- `wire/`: The `gk-wire` crate holds the types that are used for communication between the
+  userspace HAL service and the trusted application code that runs in the secure world, together
+  with code for serializing and deserializing these types as CBOR. This crate is `no_std` but uses
+  `alloc`.
+- `ta/`: The `gk-ta` crate holds the implementation of the Gatekeeper trusted application (TA),
+  which is expected to run within the device's secure environment. This crate is `no_std` but uses
+  `alloc`.
+- `hal/`: The `gk-hal` crate holds the implementation of the HAL service for Gatekeeper, which is
+  expected to run in the Android userspace and respond to Binder method invocations. This crate uses
+  `std` (as it runs within Android, not within the more restricted secure environment).
+- `boringssl/`: The `gk-boring` crate holds a BoringSSL-based implementation of some of the
+  abstractions from `gk-ta`. This crate is `no_std`, but uses `alloc`.
+- `tests/`: The `gk-tests` crate holds internal testing code.
+
+| Subdir          | Crate Name     | `std`?           | Description                                           |
+|-----------------|----------------|------------------|-------------------------------------------------------|
+| **`wire`**      | `gk-wire`      | No               | Types for HAL <-> TA communication                    |
+| **`ta`**        | `gk-ta`        | No               | TA implementation                                     |
+| **`hal`**       | `gk-hal`       | Yes              | HAL service implementation                            |
+| **`boringssl`** | `gk-boringssl` | No               | Boring/OpenSSL-based implementations of crypto traits |
+| `tests`         | `gk-tests`     | Yes              | Tests and test infrastructure                         |
+
+## Porting to a Device
+
+To use the Rust reference implementation on an Android device, implementations of various
+abstractions must be provided.  This section describes the different areas of functionality that are
+required.
+
+### Rust Toolchain and Heap Allocator
+
+Using the reference implementation requires a Rust toolchain that can target the secure environment.
+This toolchain (and any associated system libraries) must also support heap allocation (or an
+approximation thereof) via the [`alloc` sysroot crate](https://doc.rust-lang.org/alloc/).
+
+If the BoringSSL-based implementation of cryptographic functionality is used (see below), then some
+parts of the Rust `std` library must also be provided, in order to support the compilation of the
+[`openssl`](https://docs.rs/openssl) wrapper crate.
+
+**Checklist:**
+
+- [ ] Rust toolchain that targets secure environment.
+- [ ] Heap allocation support via `alloc`.
+
+### HAL Service
+
+Gatekeeper appears as a HAL service in userspace, and so an executable that registers for and
+services the Gatekeeper related HALs must be provided.
+
+The implementation of this service is mostly provided by the `gk-hal` crate, but a driver program
+must be provided that:
+
+- Performs start-of-day administration (e.g. logging setup, panic handler setup)
+- Creates a communication channel to the Gatekeeper TA.
+- Registers for the Gatekeeper HAL services.
+- Starts a thread pool to service requests.
+
+The Gatekeeper HAL service (which runs in userspace) must communicate with the Gatekeeper TA (which
+runs in the secure environment).  The reference implementation assumes the existence of a reliable,
+message-oriented, bi-directional communication channel for this, as encapsulated in the
+`gk_hal::SerializedChannel` trait.
+
+This trait has a single method `execute()`, which takes as input a request message (as bytes), and
+returns a response message (as bytes) or an error.
+
+**Checklist:**
+
+- [ ] Implementation of HAL service main executable.
+- [ ] SELinux policy for the HAL service.
+- [ ] init.rc configuration for the HAL service.
+- [ ] Implementation of `SerializedChannel` trait, for reliable HAL <-> TA communication.
+
+The <a
+href="https://cs.android.com/android/platform/superproject/main/+/main:system/core/trusty/gatekeeper/rust/">Trusty-specific
+implementation</a> provides an example of this.
+
+### TA Driver
+
+The `gk-ta` crate provides the majority of the implementation of the Gatekeeper TA, but needs a
+driver program that:
+
+- Performs start-of-day administration (e.g. logging setup).
+- Creates a `gk_ta::GatekeeperTa` instance.
+- Configures the communication channel with the HAL service.
+- Provides a mechanism for obtaining the shared HMAC key used for authentication.
+- Holds the main loop that:
+    - reads request messages from the channel(s)
+    - passes request messages to `gk_ta::GatekeeperTa::process()`, receiving a response
+    - writes response messages back to the relevant channel.
+
+**Checklist:**
+
+- [ ] Implementation of `main` equivalent for TA, handling scheduling of incoming requests.
+- [ ] Implementation of communication channel between HAL service and TA.
+- [ ] Implementation of mechanism to retrieve HMAC key (see next section).
+
+The <a
+href="https://android.googlesource.com/trusty/app/gatekeeper/+/refs/heads/main/rust/">Trusty-specific
+implementation</a> provides an example of this.
+
+### Auth Key Retrieval
+
+Gatekeeper signs its authentication tokens with a per-boot HMAC key, which can be obtained in one of
+the following ways:
+
+- The Gatekeeper TA can directly retrieve the auth token key from another component (typically
+  KeyMint) in the secure environment.  In this case, the device-specific implementation of the
+  `AuthKeyManagement` trait performs signing operations using the retrieved key.
+- The Gatekeeper TA can implement the `ISharedSecret` HAL and take part in the negotiation of the
+  HMAC key. The common code includes an implementation of the `AuthKeyManagement` trait that handles
+  this scenario, but the device must provide implementations of the following traits:
+  - [ ] CDKF key derivation operation: `SharedSecretDerive`
+  - [ ] Mechanism to retrieve a pre-shared key: `RetrievePresharedKey`
+
+### Device-Specific Abstractions
+
+The Gatekeeper TA requires implementations for low-level primitives to be provided, in the form of
+implementations of the various Rust traits held in [`gk_ta::traits`](ta/src/traits.rs).
+
+Note that some of these traits include methods that have default implementations, which means that
+an external implementation is not required (but can be provided if desired).
+
+**Checklist:**
+
+- [ ] RNG implementation: `Rng`.
+- [ ] Constant time comparison implementation: `ConstTimeEq`.
+- [ ] Secure time implementation (monotonic, shared with authenticators): `MonotonicClock`.
+- [ ] Implementation of mechanism to retrieve password key: `PasswordKeyRetrieval`
+- [ ] Persistent secure storage of failure records: `FailureRecording`
+   - [ ] The TA code includes one implementation of the `FailureRecording` trait, based on an
+         implementation of a trait for accessing files in a secure filesystem: `SecureFilesystem`
+
+BoringSSL-based implementations are available for some of the above, in the `boringssl/` directory.
diff --git a/rust/TEST_MAPPING b/rust/TEST_MAPPING
new file mode 100644
index 0000000..1098910
--- /dev/null
+++ b/rust/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "VtsHalGatekeeperTargetTest"
+    }
+  ]
+}
diff --git a/rust/boringssl/Android.bp b/rust/boringssl/Android.bp
new file mode 100644
index 0000000..2551396
--- /dev/null
+++ b/rust/boringssl/Android.bp
@@ -0,0 +1,54 @@
+// Copyright 2025, The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_defaults {
+    name: "libgk_boringssl_defaults",
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "libbssl_crypto",
+        "libbssl_sys",
+        "liblog_rust",
+        "libgk_ta",
+        "libhal_wire",
+    ],
+}
+
+rust_library {
+    name: "libgk_boringssl",
+    crate_name: "gk_boringssl",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    host_supported: true,
+    defaults: [
+        "libgk_boringssl_defaults",
+    ],
+}
+
+rust_test {
+    name: "libgk_boringssl_test",
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libgk_tests",
+        "libhex",
+    ],
+    defaults: [
+        "libgk_boringssl_defaults",
+    ],
+    test_suites: ["general-tests"],
+}
diff --git a/rust/boringssl/TEST_MAPPING b/rust/boringssl/TEST_MAPPING
new file mode 100644
index 0000000..4ab03df
--- /dev/null
+++ b/rust/boringssl/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "presubmit": [
+    {
+      "name": "libgk_boringssl_test"
+    }
+  ]
+}
diff --git a/rust/boringssl/src/lib.rs b/rust/boringssl/src/lib.rs
new file mode 100644
index 0000000..37b8670
--- /dev/null
+++ b/rust/boringssl/src/lib.rs
@@ -0,0 +1,157 @@
+// Copyright 2025, The Android Open Source Project
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
+//! BoringSSL-based implementations of Gatekeeper device-specific traits.
+#![no_std]
+extern crate alloc;
+
+use alloc::boxed::Box;
+use alloc::vec::Vec;
+use bssl_sys as ffi;
+use gk_ta::{
+    traits::{self, AccumulatingOperation, Aes256Key, AesCmac, HmacKey, OpaqueOr, AES_BLOCK_SIZE},
+    Error,
+};
+use hal_wire::vec_try;
+use log::error;
+
+#[cfg(test)]
+mod tests;
+
+/// [`traits::Rng`] implementation based on BoringSSL.
+#[derive(Default)]
+pub struct Rng;
+
+impl traits::Rng for Rng {
+    fn fill_bytes(&mut self, dest: &mut [u8]) {
+        bssl_crypto::rand_bytes(dest)
+    }
+}
+
+/// Constant time comparator based on BoringSSL.
+#[derive(Clone)]
+pub struct ConstEq;
+
+impl traits::ConstTimeEq for ConstEq {
+    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
+        bssl_crypto::constant_time_compare(left, right)
+    }
+}
+
+/// HMAC-SHA256 implementation based on BoringSSL.
+#[derive(Clone)]
+pub struct HmacSha256;
+
+impl traits::HmacSha256 for HmacSha256 {
+    fn sign(&self, key: &OpaqueOr<HmacKey>, data: &[u8]) -> Result<Vec<u8>, Error> {
+        let OpaqueOr::Explicit(ref key) = key else {
+            return Err(Error::Internal);
+        };
+        Ok(bssl_crypto::hmac::HmacSha256::mac(&key.0, data).to_vec())
+    }
+}
+
+/// AES-CMAC implementation based on BoringSSL.
+///
+/// This implementation uses the `unsafe` wrappers around bindgen-erated `CMAC_*` functions
+/// directly, because `bssl-crypto` currently has no wrappers.
+pub struct BoringAesCmac;
+
+impl AesCmac for BoringAesCmac {
+    fn begin(key: &OpaqueOr<Aes256Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
+        let OpaqueOr::Explicit(key) = key else {
+            error!("Only expect to deal with explicit key material");
+            return Err(Error::Internal);
+        };
+
+        // Safety: raw pointer is immediately checked for null below, and BoringSSL only emits
+        // valid pointers or null.
+        let ctx = unsafe { ffi::CMAC_CTX_new() };
+        let Some(ctx) = core::ptr::NonNull::new(ctx) else {
+            return Err(Error::AllocationFailed);
+        };
+
+        // Safety: `ffi::EVP_aes_256_cbc` returns a non-null valid pointer.
+        let cipher = unsafe { ffi::EVP_aes_256_cbc() };
+
+        // Safety: `ctx` is known non-null and valid, as is `cipher`.  `key` is a valid array of
+        // `u8`, of non-zero length.
+        let result = unsafe {
+            ffi::CMAC_Init(
+                ctx.as_ptr(),
+                key.as_ptr() as *const core::ffi::c_void,
+                key.len(),
+                cipher,
+                core::ptr::null_mut(),
+            )
+        };
+        if result != 1 {
+            error!("Failed to CMAC_Init()");
+            return Err(Error::Internal);
+        }
+        Ok(Box::new(AesCmacOperation { ctx }))
+    }
+}
+
+struct AesCmacOperation {
+    // Safety: `ctx` is always non-null (checked in `AesCmac::begin()` before construction).
+    ctx: core::ptr::NonNull<ffi::CMAC_CTX>,
+}
+
+// Safety: Checked CMAC_CTX allocation, initialization and destruction code to insure that it is
+//         safe to share it between threads.
+unsafe impl Send for AesCmacOperation {}
+
+impl core::ops::Drop for AesCmacOperation {
+    fn drop(&mut self) {
+        // Safety: `self.ctx` is always non-null and valid as it's created from
+        // `ffi::CMAC_CTX_new()`.
+        unsafe {
+            ffi::CMAC_CTX_free(self.ctx.as_ptr());
+        }
+    }
+}
+
+impl AccumulatingOperation for AesCmacOperation {
+    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
+        if data.is_empty() {
+            return Ok(());
+        }
+        // Safety: `self.ctx` is non-null and valid, and `data` is a valid non-empty slice.
+        let result = unsafe { ffi::CMAC_Update(self.ctx.as_ptr(), data.as_ptr(), data.len()) };
+        if result != 1 {
+            return Err(Error::Internal);
+        }
+        Ok(())
+    }
+
+    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
+        let mut output_len: usize = AES_BLOCK_SIZE;
+        let mut output = vec_try![0; AES_BLOCK_SIZE]?;
+
+        // Safety: `self.ctx` is non-null and valid; `output_len` is correct (non-zero) size of
+        // `output` buffer.
+        let result = unsafe {
+            ffi::CMAC_Final(self.ctx.as_ptr(), output.as_mut_ptr(), &mut output_len as *mut usize)
+        };
+        if result != 1 {
+            return Err(Error::Internal);
+        }
+        if output_len != AES_BLOCK_SIZE {
+            error!("Unexpected CMAC output size of {output_len}");
+            return Err(Error::Internal);
+        }
+        Ok(output)
+    }
+}
diff --git a/rust/boringssl/src/tests.rs b/rust/boringssl/src/tests.rs
new file mode 100644
index 0000000..551f058
--- /dev/null
+++ b/rust/boringssl/src/tests.rs
@@ -0,0 +1,52 @@
+// Copyright 2022, The Android Open Source Project
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
+//! Tests for the BoringSSL-based implementations of crypto traits.
+//!
+//! Inject the local trait implementation into the into the smoke tests from `gk_tests`.
+
+#[test]
+fn test_aes_cmac() {
+    gk_tests::test_aes_cmac::<crate::BoringAesCmac>();
+}
+
+#[test]
+fn test_shared_secret_derive() {
+    let aes_cmac = crate::BoringAesCmac;
+    gk_tests::test_shared_secret_derive(aes_cmac);
+}
+
+#[test]
+fn test_rng() {
+    let mut rng = crate::Rng;
+    gk_tests::test_rng(&mut rng);
+}
+
+#[test]
+fn test_eq() {
+    let comparator = crate::ConstEq;
+    gk_tests::test_eq(comparator);
+}
+
+#[test]
+fn test_constant_time_eq() {
+    let comparator = crate::ConstEq;
+    gk_tests::test_constant_time_eq(comparator);
+}
+
+#[test]
+fn test_hmac() {
+    let hmac = crate::HmacSha256;
+    gk_tests::test_hmac(hmac);
+}
diff --git a/rust/hal/Android.bp b/rust/hal/Android.bp
new file mode 100644
index 0000000..224e254
--- /dev/null
+++ b/rust/hal/Android.bp
@@ -0,0 +1,78 @@
+// Copyright 2025, The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_defaults {
+    name: "gk_hal_defaults",
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "android.hardware.gatekeeper-V1-rust",
+        "android.hardware.security.secureclock-V1-rust",
+        "libbinder_rs",
+        "libciborium",
+        "libciborium_io",
+        "libgk_wire",
+        "libhal_wire",
+        "liblog_rust",
+    ],
+    defaults: [
+        "keymint_use_latest_hal_aidl_rust",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+}
+
+// This variant of the library just supports `IGatekeeper`.
+rust_library {
+    name: "libgk_hal",
+    crate_name: "gk_hal",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    defaults: [
+        "gk_hal_defaults",
+    ],
+}
+
+// This variant of the library enables the `sharedsecret` crate feature, which adds
+// support for the `ISharedSecret` HAL in addition to `IGatekeeper`.
+rust_library {
+    name: "libgk_hal_with_sharedsecret",
+    crate_name: "gk_hal",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    features: [
+        "sharedsecret",
+    ],
+    rustlibs: [
+        "android.hardware.security.sharedsecret-V1-rust",
+    ],
+    defaults: [
+        "gk_hal_defaults",
+    ],
+}
+
+rust_test {
+    name: "libgk_hal_test",
+    crate_name: "libgk_hal_test",
+    srcs: ["src/lib.rs"],
+    defaults: [
+        "gk_hal_defaults",
+    ],
+    test_suites: ["general-tests"],
+}
diff --git a/rust/hal/src/channel.rs b/rust/hal/src/channel.rs
new file mode 100644
index 0000000..fdb3144
--- /dev/null
+++ b/rust/hal/src/channel.rs
@@ -0,0 +1,121 @@
+// Copyright 2023 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+////////////////////////////////////////////////////////////////////////////////
+
+//! Channel-related functionality and helpers.
+
+use crate::{PerformOpReq, PerformOpResponse};
+use hal_wire::{AsCborValue, CborError};
+use log::error;
+use std::ffi::CString;
+use std::io::{Read, Write};
+use std::sync::MutexGuard;
+
+/// Abstraction of a channel to a secure world TA implementation.
+///
+/// The channel is expected to be message-oriented (rather than stream-oriented): a message sent by
+/// one end is expected to arrive as a complete message at the other end.
+pub trait SerializedChannel: Send {
+    /// Maximum supported size for the channel in bytes.
+    const MAX_SIZE: usize;
+
+    /// Accepts serialized request messages and returns serialized response messages
+    /// (or an error if communication via the channel is lost).
+    fn execute(&mut self, serialized_req: &[u8]) -> binder::Result<Vec<u8>>;
+}
+
+/// Abstraction of a Gatekeeper-related HAL service that uses an underlying [`SerializedChannel`] to
+/// communicate with an associated TA.
+pub trait ChannelHalService<T: SerializedChannel> {
+    /// Return the underlying channel.
+    fn channel(&self) -> MutexGuard<T>;
+
+    /// Execute the given request, by serializing it and sending it down the channel.  Then
+    /// read and deserialize the response.
+    fn execute_req(&self, req: PerformOpReq) -> binder::Result<PerformOpResponse> {
+        let code = req.code();
+        let req_data = req.into_vec().map_err(failed_cbor)?;
+        if req_data.len() > T::MAX_SIZE {
+            error!(
+                "HAL operation {code:?} encodes bigger {} than max size {}",
+                req_data.len(),
+                T::MAX_SIZE
+            );
+            return Err(binder::Status::new_exception(binder::ExceptionCode::BAD_PARCELABLE, None));
+        }
+
+        // Pass the request to the channel and read the response, all while holding exclusive use of
+        // the channel.
+        let rsp_data = self.channel().execute(&req_data)?;
+
+        PerformOpResponse::from_slice(&rsp_data).map_err(failed_cbor)
+    }
+}
+
+/// Emit a failure for a failed CBOR conversion.
+#[inline]
+pub fn failed_cbor(err: CborError) -> binder::Status {
+    error!("failed CBOR conversion: {err:?}");
+    binder::Status::new_exception(binder::ExceptionCode::BAD_PARCELABLE, None)
+}
+
+// The following functions can help to convert an underlying stream-oriented channel into a
+// message-oriented channel.
+
+/// Write a message to a stream-oriented [`Write`] item, with length framing.
+pub fn write_msg<W: Write>(w: &mut W, data: &[u8]) -> binder::Result<()> {
+    // The underlying `Write` item does not guarantee delivery of complete messages.
+    // Make this possible by adding framing in the form of a big-endian `u32` holding
+    // the message length.
+    let data_len: u32 = data.len().try_into().map_err(|_e| {
+        binder::Status::new_exception(
+            binder::ExceptionCode::BAD_PARCELABLE,
+            Some(&CString::new("encoded request message too large").unwrap()),
+        )
+    })?;
+    let data_len_data = data_len.to_be_bytes();
+    w.write_all(&data_len_data[..]).map_err(|e| {
+        error!("Failed to write length to stream: {}", e);
+        binder::Status::new_exception(
+            binder::ExceptionCode::BAD_PARCELABLE,
+            Some(&CString::new("failed to write framing length").unwrap()),
+        )
+    })?;
+    w.write_all(data).map_err(|e| {
+        error!("Failed to write data to stream: {}", e);
+        binder::Status::new_exception(
+            binder::ExceptionCode::BAD_PARCELABLE,
+            Some(&CString::new("failed to write data").unwrap()),
+        )
+    })?;
+    Ok(())
+}
+
+/// Read a message from a stream-oriented [`Read`] item, with length framing.
+pub fn read_msg<R: Read>(r: &mut R) -> binder::Result<Vec<u8>> {
+    // The data read from the `Read` item has a 4-byte big-endian length prefix.
+    let mut len_data = [0u8; 4];
+    r.read_exact(&mut len_data).map_err(|e| {
+        error!("Failed to read length from stream: {}", e);
+        binder::Status::new_exception(binder::ExceptionCode::TRANSACTION_FAILED, None)
+    })?;
+    let len = u32::from_be_bytes(len_data);
+    let mut data = vec![0; len as usize];
+    r.read_exact(&mut data).map_err(|e| {
+        error!("Failed to read data from stream: {}", e);
+        binder::Status::new_exception(binder::ExceptionCode::TRANSACTION_FAILED, None)
+    })?;
+    Ok(data)
+}
diff --git a/rust/hal/src/lib.rs b/rust/hal/src/lib.rs
new file mode 100644
index 0000000..870783f
--- /dev/null
+++ b/rust/hal/src/lib.rs
@@ -0,0 +1,222 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Implementation of a HAL service for Gatekeeper.
+//!
+//! This implementation relies on a `SerializedChannel` abstraction for a communication channel to
+//! the trusted application (TA).  Incoming method invocations for the HAL service are converted
+//! into corresponding request structures, which are then serialized (using CBOR) and sent down the
+//! channel.  A serialized response is then read from the channel, which is deserialized into a
+//! response structure.  The contents of this response structure are then used to populate the
+//! return values of the HAL service method.
+
+use crate::channel::{ChannelHalService, SerializedChannel};
+use android_hardware_gatekeeper::aidl::android::hardware::gatekeeper::{
+    GatekeeperEnrollResponse::GatekeeperEnrollResponse,
+    GatekeeperVerifyResponse::GatekeeperVerifyResponse,
+    IGatekeeper::{BnGatekeeper, IGatekeeper, ERROR_RETRY_TIMEOUT, STATUS_OK, STATUS_REENROLL},
+};
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
+};
+use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
+    Timestamp::Timestamp,
+};
+use gk_wire as wire;
+use log::{error, info, warn};
+use wire::{
+    Password, PasswordHandle, PerformOpReq, PerformOpResponse, PerformOpRsp,
+};
+use std::sync::{Arc, Mutex, MutexGuard};
+
+pub mod channel;
+#[cfg(feature = "sharedsecret")]
+pub mod sharedsecret;
+
+/// Implementation of the `IGatekeeper` HAL service, communicating with a TA
+/// in a secure environment via a communication channel.
+pub struct GatekeeperService<T: SerializedChannel + 'static> {
+    channel: Arc<Mutex<T>>,
+}
+
+impl<T: SerializedChannel + 'static> GatekeeperService<T> {
+    /// Construct a new instance that uses the provided channel.
+    pub fn new(channel: Arc<Mutex<T>>) -> Self {
+        Self { channel }
+    }
+
+    /// Create a new instance wrapped in a proxy object.
+    pub fn new_as_binder(channel: Arc<Mutex<T>>) -> binder::Strong<dyn IGatekeeper> {
+        BnGatekeeper::new_binder(Self::new(channel), binder::BinderFeatures::default())
+    }
+}
+
+impl<T: SerializedChannel> ChannelHalService<T> for GatekeeperService<T> {
+    fn channel(&self) -> MutexGuard<T> {
+        self.channel.lock().unwrap()
+    }
+}
+
+impl<T: SerializedChannel + Send> binder::Interface for GatekeeperService<T> {}
+
+/// Implement the `IGatekeeper` interface by translating incoming method invocations into request
+/// messages, which are passed to the TA.  The corresponding response from the TA is then parsed and
+/// the return values extracted.
+impl<T: SerializedChannel> IGatekeeper for GatekeeperService<T> {
+    fn deleteAllUsers(&self) -> binder::Result<()> {
+        const OP: &str = "deleteAllUsers";
+        let req = PerformOpReq::DeleteAllUsers(wire::DeleteAllUsersRequest {});
+        match self.execute_req(req)? {
+            PerformOpResponse::Ok(PerformOpRsp::DeleteAllUsers(_rsp)) => Ok(()),
+            PerformOpResponse::Ok(_) => {
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::RetryTimeout(timeout) => {
+                error!("unexpected retry-in-{timeout}-ms return from {OP}");
+                Err(gk_err_to_binder(OP, wire::ApiStatus::RetryTimeout as i32))
+            }
+            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
+        }
+    }
+
+    fn deleteUser(&self, user_id: i32) -> binder::Result<()> {
+        const OP: &str = "deleteUser";
+        let req = PerformOpReq::DeleteUser(wire::DeleteUserRequest {
+            user_id: wire::AndroidUserId(user_id),
+        });
+        match self.execute_req(req)? {
+            PerformOpResponse::Ok(PerformOpRsp::DeleteUser(_rsp)) => Ok(()),
+            PerformOpResponse::Ok(_) => {
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::RetryTimeout(timeout) => {
+                error!("unexpected retry-in-{timeout}-ms return from {OP}");
+                Err(gk_err_to_binder(OP, wire::ApiStatus::RetryTimeout as i32))
+            }
+            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
+        }
+    }
+
+    fn enroll(
+        &self,
+        user_id: i32,
+        current_handle: &[u8],
+        current_password: &[u8],
+        new_password: &[u8],
+    ) -> binder::Result<GatekeeperEnrollResponse> {
+        const OP: &str = "enroll";
+        let req = PerformOpReq::Enroll(wire::EnrollRequest {
+            user_id: wire::AndroidUserId(user_id),
+            current_handle: PasswordHandle::from_raw(current_handle),
+            current_password: Password::from_raw(current_password),
+            new_password: Password(new_password.to_vec()),
+        });
+        match self.execute_req(req)? {
+            PerformOpResponse::Ok(PerformOpRsp::Enroll(rsp)) => Ok(GatekeeperEnrollResponse {
+                statusCode: STATUS_OK,
+                timeoutMs: 0,
+                secureUserId: rsp.sid.0,
+                data: rsp.handle.0,
+            }),
+            PerformOpResponse::Ok(_) => {
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::RetryTimeout(timeout) => {
+                info!("retry-in-{timeout}-ms return from {OP}");
+                Ok(GatekeeperEnrollResponse {
+                    statusCode: ERROR_RETRY_TIMEOUT,
+                    timeoutMs: timeout,
+                    secureUserId: 0,
+                    data: Vec::new(),
+                })
+            }
+            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
+        }
+    }
+
+    fn verify(
+        &self,
+        user_id: i32,
+        challenge: i64,
+        handle: &[u8],
+        password: &[u8],
+    ) -> binder::Result<GatekeeperVerifyResponse> {
+        const OP: &str = "verify";
+        let req = PerformOpReq::Verify(wire::VerifyRequest {
+            user_id: wire::AndroidUserId(user_id),
+            challenge,
+            handle: PasswordHandle(handle.to_vec()),
+            password: Password(password.to_vec()),
+        });
+
+        match self.execute_req(req)? {
+            PerformOpResponse::Ok(PerformOpRsp::Verify(rsp)) => Ok(GatekeeperVerifyResponse {
+                statusCode: if rsp.request_reenroll { STATUS_REENROLL } else { STATUS_OK },
+                timeoutMs: 0,
+                hardwareAuthToken: token_to_aidl(rsp.auth_token),
+            }),
+            PerformOpResponse::Ok(_) => {
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::RetryTimeout(timeout) => {
+                info!("retry-in-{timeout}-ms return from {OP}");
+                Ok(GatekeeperVerifyResponse {
+                    statusCode: ERROR_RETRY_TIMEOUT,
+                    timeoutMs: timeout,
+                    hardwareAuthToken: empty_auth_token(),
+                })
+            }
+            PerformOpResponse::Err(rc) => Err(gk_err_to_binder(OP, rc)),
+        }
+    }
+}
+
+/// Convert a Gatekeeper error code into a binder error.
+pub fn gk_err_to_binder(op: &str, err: i32) -> binder::Status {
+    warn!("{op} failed: {err}");
+    binder::Status::new_service_specific_error(err, None)
+}
+
+/// Convert a [`wire::HardwareAuthToken`] into an AIDL [`HardwareAuthToken`].
+fn token_to_aidl(token: wire::HardwareAuthToken) -> HardwareAuthToken {
+    HardwareAuthToken {
+        challenge: token.challenge,
+        userId: token.user_id,
+        authenticatorId: token.authenticator_id,
+        authenticatorType: auth_type_to_aidl(token.authenticator_type),
+        timestamp: Timestamp { milliSeconds: token.timestamp.0 },
+        mac: token.mac,
+    }
+}
+
+/// Convert a [`wire::HardwareAuthenticatorType`] into an AIDL [`HardwareAuthenticatorType`].
+fn auth_type_to_aidl(auth_type: wire::HardwareAuthenticatorType) -> HardwareAuthenticatorType {
+    match auth_type {
+        wire::HardwareAuthenticatorType::None => HardwareAuthenticatorType::NONE,
+        wire::HardwareAuthenticatorType::Password => HardwareAuthenticatorType::PASSWORD,
+        wire::HardwareAuthenticatorType::Fingerprint => HardwareAuthenticatorType::FINGERPRINT,
+        wire::HardwareAuthenticatorType::Any => HardwareAuthenticatorType::ANY,
+    }
+}
+
+fn empty_auth_token() -> HardwareAuthToken {
+    HardwareAuthToken {
+        challenge: 0,
+        userId: 0,
+        authenticatorId: 0,
+        authenticatorType: HardwareAuthenticatorType::NONE,
+        timestamp: Timestamp { milliSeconds: 0 },
+        mac: Vec::new(),
+    }
+}
diff --git a/rust/hal/src/sharedsecret.rs b/rust/hal/src/sharedsecret.rs
new file mode 100644
index 0000000..8708496
--- /dev/null
+++ b/rust/hal/src/sharedsecret.rs
@@ -0,0 +1,106 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Implementation of the `ISharedSecret` HAL service, to run alongside Gatekeeper.
+
+use crate::channel::{ChannelHalService, SerializedChannel};
+use android_hardware_security_sharedsecret::aidl::android::hardware::security::sharedsecret::{
+    ISharedSecret::{BnSharedSecret, ISharedSecret},
+    SharedSecretParameters::SharedSecretParameters,
+};
+use gk_wire as wire;
+use log::{error, warn};
+use std::sync::{Arc, Mutex, MutexGuard};
+use wire::{PerformOpReq, PerformOpResponse, PerformOpRsp};
+
+/// Implementation of the `ISharedSecret` HAL service, communicating with a TA in a secure
+/// environment via a communication channel.
+pub struct SharedSecretService<T: SerializedChannel + 'static> {
+    channel: Arc<Mutex<T>>,
+}
+
+impl<T: SerializedChannel + 'static> SharedSecretService<T> {
+    /// Construct a new instance that uses the provided channel.
+    pub fn new(channel: Arc<Mutex<T>>) -> Self {
+        Self { channel }
+    }
+
+    /// Create a new instance wrapped in a proxy object.
+    pub fn new_as_binder(channel: Arc<Mutex<T>>) -> binder::Strong<dyn ISharedSecret> {
+        BnSharedSecret::new_binder(Self::new(channel), binder::BinderFeatures::default())
+    }
+}
+
+impl<T: SerializedChannel> ChannelHalService<T> for SharedSecretService<T> {
+    fn channel(&self) -> MutexGuard<T> {
+        self.channel.lock().unwrap()
+    }
+}
+
+impl<T: SerializedChannel + Send> binder::Interface for SharedSecretService<T> {}
+
+impl<T: SerializedChannel> ISharedSecret for SharedSecretService<T> {
+    fn getSharedSecretParameters(&self) -> binder::Result<SharedSecretParameters> {
+        const OP: &str = "getSharedSecretParameters";
+        let req = PerformOpReq::GetSharedSecretParams(wire::GetSharedSecretParamsRequest {});
+
+        match self.execute_req(req)? {
+            PerformOpResponse::Ok(PerformOpRsp::GetSharedSecretParams(rsp)) => {
+                Ok(wire_to_aidl(rsp.params))
+            }
+            PerformOpResponse::Ok(_) => {
+                error!("unexpected response message return from {OP}");
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::RetryTimeout(timeout) => {
+                error!("unexpected retry-in-{timeout}-ms return from {OP}");
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::Err(rc) => Err(ss_err_to_binder(OP, rc)),
+        }
+    }
+
+    fn computeSharedSecret(&self, params: &[SharedSecretParameters]) -> binder::Result<Vec<u8>> {
+        const OP: &str = "computeSharedSecret";
+        let req = PerformOpReq::ComputeSharedSecret(wire::ComputeSharedSecretRequest {
+            params: params.iter().map(aidl_to_wire).collect(),
+        });
+
+        match self.execute_req(req)? {
+            PerformOpResponse::Ok(PerformOpRsp::ComputeSharedSecret(rsp)) => Ok(rsp.sharing_check),
+            PerformOpResponse::Ok(_) => {
+                error!("unexpected response message return from {OP}");
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::RetryTimeout(timeout) => {
+                error!("unexpected retry-in-{timeout}-ms return from {OP}");
+                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
+            }
+            PerformOpResponse::Err(rc) => Err(ss_err_to_binder(OP, rc)),
+        }
+    }
+}
+
+fn aidl_to_wire(params: &SharedSecretParameters) -> wire::SharedSecretParameters {
+    wire::SharedSecretParameters { seed: params.seed.to_vec(), nonce: params.nonce.to_vec() }
+}
+
+fn wire_to_aidl(params: wire::SharedSecretParameters) -> SharedSecretParameters {
+    SharedSecretParameters { seed: params.seed, nonce: params.nonce }
+}
+
+fn ss_err_to_binder(op: &str, err: i32) -> binder::Status {
+    warn!("{op} failed: {err}");
+    binder::Status::new_service_specific_error(err, None)
+}
diff --git a/rust/rustfmt.toml b/rust/rustfmt.toml
new file mode 120000
index 0000000..475ba8f
--- /dev/null
+++ b/rust/rustfmt.toml
@@ -0,0 +1 @@
+../../../build/soong/scripts/rustfmt.toml
\ No newline at end of file
diff --git a/rust/ta/Android.bp b/rust/ta/Android.bp
new file mode 100644
index 0000000..3f8d40a
--- /dev/null
+++ b/rust/ta/Android.bp
@@ -0,0 +1,84 @@
+// Copyright 2025, The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_library {
+    name: "libgk_ta",
+    crate_name: "gk_ta",
+    srcs: ["src/lib.rs"],
+    edition: "2021",
+    lints: "android",
+    vendor_available: true,
+    host_supported: true,
+    rustlibs: [
+        "libciborium",
+        "libciborium_io",
+        "libgk_wire",
+        "libhal_wire",
+        "liblog_rust",
+        "libzeroize",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+}
+
+rust_library_rlib {
+    name: "libgk_ta_nostd",
+    crate_name: "gk_ta",
+    srcs: ["src/lib.rs"],
+    edition: "2021",
+    lints: "android",
+    vendor_available: true,
+    rustlibs: [
+        "libciborium_nostd",
+        "libciborium_io_nostd",
+        "libgk_wire_nostd",
+        "libhal_wire_nostd",
+        "liblog_rust_nostd",
+        "libzeroize_nostd",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+    prefer_rlib: true,
+    no_stdlibs: true,
+    stdlibs: [
+        "libcompiler_builtins.rust_sysroot",
+        "libcore.rust_sysroot",
+    ],
+}
+
+rust_test {
+    name: "libgk_ta_test",
+    crate_name: "gk_ta_test",
+    srcs: ["src/lib.rs"],
+    edition: "2021",
+    rustlibs: [
+        "libciborium",
+        "libciborium_io",
+        "libhex",
+        "libgk_wire",
+        "libhal_wire",
+        "liblog_rust",
+        "libzeroize",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+    test_suites: ["general-tests"],
+}
diff --git a/rust/ta/Cargo.toml b/rust/ta/Cargo.toml
new file mode 100644
index 0000000..bac9595
--- /dev/null
+++ b/rust/ta/Cargo.toml
@@ -0,0 +1,21 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "gk-ta"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+ciborium = { version = "^0.2.0", default-features = false }
+ciborium-io = "^0.2.0"
+gk-wire = "*"
+hal-wire = "*"
+hal-wire-derive = "*"
+log = "^0.4"
+zeroize = { version = "^1.5.6", features = ["alloc", "zeroize_derive"] }
+
+[dev-dependencies]
+hex = "0.4.3"
diff --git a/rust/ta/src/handle.rs b/rust/ta/src/handle.rs
new file mode 100644
index 0000000..156bb2b
--- /dev/null
+++ b/rust/ta/src/handle.rs
@@ -0,0 +1,183 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Password handle functionality.
+
+use crate::{
+    traits::{self, HmacKey, OpaqueOr},
+    Error,
+};
+use core::mem::size_of;
+use core::ops::Range;
+use gk_wire as wire;
+use hal_wire::mem;
+use log::error;
+use wire::SecureUserId;
+
+/// Current version of the [`PasswordHandle`] structure, inherited from the C++ implementation.
+pub const CURRENT_VERSION: u8 = 2;
+
+/// Minimum supported version from previous implementations.
+pub const MINIMUM_VERSION: u8 = 2;
+
+/// Reserved value for the `flags` field in [`PasswordHandle`]. Always set for historical /
+/// back-compatibility reasons.
+pub const FLAG_RESERVED: u64 = 0x01;
+
+/// Handle for an enrolled password.
+#[derive(Debug, PartialEq)]
+pub struct PasswordHandle {
+    // Fields included in the MAC input.
+    version: u8,
+    sid: SecureUserId,
+    flags: u64,
+    salt: u64,
+
+    // Un-MAC-ed fields.
+    mac: [u8; 32],
+    hw_backed: bool,
+}
+
+// Constants for the serialized length of fields (in bytes).
+const SERIALIZED_VERSION_LEN: usize = size_of::<u8>();
+const SERIALIZED_SID_LEN: usize = size_of::<SecureUserId>();
+const SERIALIZED_FLAGS_LEN: usize = size_of::<u64>();
+const SERIALIZED_SALT_LEN: usize = size_of::<u64>();
+const SERIALIZED_MAC_LEN: usize = 32;
+const SERIALIZED_HW_BACKED_LEN: usize = size_of::<u8>();
+const SERIALIZED_LEN: usize = SERIALIZED_VERSION_LEN
+    + SERIALIZED_SID_LEN
+    + SERIALIZED_FLAGS_LEN
+    + SERIALIZED_SALT_LEN
+    + SERIALIZED_MAC_LEN
+    + SERIALIZED_HW_BACKED_LEN;
+const MAC_INPUT_PREFIX_LEN: usize =
+    SERIALIZED_SALT_LEN + SERIALIZED_VERSION_LEN + SERIALIZED_SID_LEN + SERIALIZED_FLAGS_LEN;
+
+// Offsets of serialized fields.
+const VERSION_OFFSET: usize = 0;
+const SID_OFFSET: usize = VERSION_OFFSET + SERIALIZED_VERSION_LEN;
+const FLAGS_OFFSET: usize = SID_OFFSET + SERIALIZED_SID_LEN;
+const SALT_OFFSET: usize = FLAGS_OFFSET + SERIALIZED_FLAGS_LEN;
+const MAC_OFFSET: usize = SALT_OFFSET + SERIALIZED_SALT_LEN;
+const HW_BACKED_OFFSET: usize = MAC_OFFSET + SERIALIZED_MAC_LEN;
+
+// Ranges for serialized fields.
+const SID_RANGE: Range<usize> = SID_OFFSET..SID_OFFSET + SERIALIZED_SID_LEN;
+const FLAGS_RANGE: Range<usize> = FLAGS_OFFSET..FLAGS_OFFSET + SERIALIZED_FLAGS_LEN;
+const SALT_RANGE: Range<usize> = SALT_OFFSET..SALT_OFFSET + SERIALIZED_SALT_LEN;
+const MAC_RANGE: Range<usize> = MAC_OFFSET..MAC_OFFSET + SERIALIZED_MAC_LEN;
+
+impl PasswordHandle {
+    /// Create a new password handle.
+    pub fn new(
+        key: &OpaqueOr<HmacKey>,
+        hmac: &dyn traits::HmacSha256,
+        rng: &mut dyn traits::Rng,
+        password: &wire::Password,
+        sid: SecureUserId,
+    ) -> Result<Self, Error> {
+        let salt = rng.next_u64();
+        let mut handle = Self {
+            version: CURRENT_VERSION,
+            sid,
+            flags: FLAG_RESERVED,
+            salt,
+            mac: [0; 32],
+            hw_backed: true,
+        };
+        handle.mac = handle.generate_mac(key, hmac, password)?;
+        Ok(handle)
+    }
+
+    /// Create a password handle from binary data.
+    ///
+    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
+    pub fn from_wire(data: &wire::PasswordHandle) -> Result<Self, Error> {
+        let data = &data.0;
+        if data.len() != SERIALIZED_LEN {
+            error!("failure record of unexpected length {}!", data.len());
+            return Err(Error::InvalidArgument);
+        }
+        let handle = Self {
+            version: data[VERSION_OFFSET],
+            sid: SecureUserId(i64::from_ne_bytes(data[SID_RANGE].try_into().unwrap())),
+            flags: u64::from_ne_bytes(data[FLAGS_RANGE].try_into().unwrap()),
+            salt: u64::from_ne_bytes(data[SALT_RANGE].try_into().unwrap()),
+            mac: data[MAC_RANGE].try_into().unwrap(),
+            hw_backed: data[HW_BACKED_OFFSET] != 0,
+        };
+        if handle.version > CURRENT_VERSION {
+            error!("password handle from the future: {} vs {CURRENT_VERSION}", handle.version,);
+            return Err(Error::InvalidArgument);
+        }
+        if handle.version < MINIMUM_VERSION {
+            error!("password handle predates support: {} vs {MINIMUM_VERSION}", handle.version,);
+            return Err(Error::InvalidArgument);
+        }
+        Ok(handle)
+    }
+
+    /// Convert a password handle into binary data.
+    ///
+    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
+    pub fn to_wire(&self) -> Result<wire::PasswordHandle, Error> {
+        let mut result = mem::vec_try_with_capacity(SERIALIZED_LEN)?;
+        result.push(self.version);
+        result.extend_from_slice(&self.sid.0.to_ne_bytes());
+        result.extend_from_slice(&self.flags.to_ne_bytes());
+        result.extend_from_slice(&self.salt.to_ne_bytes());
+        result.extend_from_slice(&self.mac);
+        result.push(if self.hw_backed { 1 } else { 0 });
+        Ok(wire::PasswordHandle(result))
+    }
+
+    /// Return the MAC value for the handle.
+    fn generate_mac(
+        &self,
+        key: &OpaqueOr<HmacKey>,
+        hmac: &dyn traits::HmacSha256,
+        password: &wire::Password,
+    ) -> Result<[u8; 32], Error> {
+        let mut to_mac = mem::vec_try_with_capacity(MAC_INPUT_PREFIX_LEN + password.0.len())?;
+        to_mac.extend_from_slice(&self.salt.to_ne_bytes());
+        to_mac.push(self.version);
+        to_mac.extend_from_slice(&self.sid.0.to_ne_bytes());
+        to_mac.extend_from_slice(&self.flags.to_ne_bytes());
+        to_mac.extend_from_slice(&password.0);
+
+        let mac = hmac.sign(key, &to_mac)?;
+        mac.try_into().map_err(|_| Error::Internal)
+    }
+
+    /// Verify that this handle matches the given password.
+    pub fn verify(
+        &self,
+        key: &OpaqueOr<HmacKey>,
+        hmac: &dyn traits::HmacSha256,
+        compare: &dyn traits::ConstTimeEq,
+        password: &wire::Password,
+    ) -> Result<(), Error> {
+        let recalc = self.generate_mac(key, hmac, password)?;
+        if compare.eq(&recalc, &self.mac) {
+            Ok(())
+        } else {
+            Err(Error::VerifyFailed)
+        }
+    }
+
+    pub fn sid(&self) -> SecureUserId {
+        self.sid
+    }
+}
diff --git a/rust/ta/src/lib.rs b/rust/ta/src/lib.rs
new file mode 100644
index 0000000..fb0b034
--- /dev/null
+++ b/rust/ta/src/lib.rs
@@ -0,0 +1,492 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Common code implementing a Gatekeeper TA.
+
+#![no_std]
+extern crate alloc;
+
+use alloc::vec::Vec;
+use gk_wire as wire;
+use hal_wire::{mem::vec_try_with_capacity, AsCborValue};
+use log::{debug, error, info, trace, warn};
+use wire::{
+    AndroidUserId, ApiStatus, Code, ComputeSharedSecretResponse, DeleteAllUsersResponse,
+    DeleteUserResponse, EnrollResponse, GatekeeperOperation, GetSharedSecretParamsResponse,
+    HardwareAuthToken, MillisecondsSinceEpoch, Password, PerformOpReq, PerformOpResponse,
+    PerformOpRsp, SecureUserId, SharedSecretError, VerifyResponse,
+};
+
+mod handle;
+mod secret;
+#[cfg(test)]
+mod tests;
+pub mod traits;
+
+/// Errors encountered in TA processing.
+#[derive(Debug, Clone)]
+pub enum Error {
+    /// Memory allocation failure.
+    AllocationFailed,
+    /// Internal error.
+    Internal,
+    /// Cryptographic verification failed.
+    VerifyFailed,
+    /// Functionality not implemented.
+    Unimplemented,
+    /// Provided argument(s) are invalid.
+    InvalidArgument,
+    /// User not found.
+    NotFound,
+    /// Operation cannot be performed until given number of milliseconds have passed.
+    RetryTimeout(i32),
+}
+
+impl From<alloc::collections::TryReserveError> for Error {
+    fn from(_e: alloc::collections::TryReserveError) -> Self {
+        Error::AllocationFailed
+    }
+}
+
+/// Gatekeeper device implementation, running in secure environment.
+pub struct GatekeeperTa {
+    /// Device-specific trait implementation.  Fixed on construction.
+    imp: traits::Implementation,
+
+    /// Parameters for shared secret negotiation.  Set after TA start, latched thereafter.
+    shared_secret_params: Option<wire::SharedSecretParameters>,
+}
+
+impl GatekeeperTa {
+    /// Create a new [`GatekeeperTa`] instance.
+    pub fn new(imp: traits::Implementation) -> Self {
+        Self { imp, shared_secret_params: None }
+    }
+
+    /// Process a single serialized request, returning a serialized response.
+    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
+        let (req_code, rsp) = match PerformOpReq::from_slice(req_data) {
+            Ok(req) => {
+                trace!("-> TA: received request {:?}", req.code());
+                (Some(req.code()), self.process_req(req))
+            }
+            Err(e) => {
+                error!("failed to decode CBOR request: {:?}", e);
+                (None, PerformOpResponse::Err(ApiStatus::GeneralFailure as i32))
+            }
+        };
+        trace!("<- TA: send response {req_code:?} rc {:?}", rsp.error_code());
+        match rsp.into_vec() {
+            Ok(rsp_data) => rsp_data,
+            Err(e) => {
+                error!("failed to encode CBOR response: {e:?}");
+                invalid_cbor_rsp_data().to_vec()
+            }
+        }
+    }
+
+    /// Process a single request, returning a [`PerformOpResponse`].
+    ///
+    /// Select the appropriate method based on the request type, and use the
+    /// request fields as parameters to the method.  In the opposite direction,
+    /// build a response message from the values returned by the method.
+    fn process_req(&mut self, req: PerformOpReq) -> PerformOpResponse {
+        match req {
+            // IGatekeeper messages.
+            PerformOpReq::DeleteAllUsers(req) => match self.delete_all_users() {
+                Ok(_ret) => {
+                    PerformOpResponse::Ok(PerformOpRsp::DeleteAllUsers(DeleteAllUsersResponse {}))
+                }
+                Err(e) => gk_error_rsp(req.code(), e),
+            },
+            PerformOpReq::DeleteUser(req) => match self.delete_user(req.user_id) {
+                Ok(_ret) => PerformOpResponse::Ok(PerformOpRsp::DeleteUser(DeleteUserResponse {})),
+                Err(e) => gk_error_rsp(req.code(), e),
+            },
+            PerformOpReq::Enroll(req) => match self.enroll(
+                req.user_id,
+                &req.current_handle,
+                &req.current_password,
+                &req.new_password,
+            ) {
+                Ok((sid, handle)) => {
+                    PerformOpResponse::Ok(PerformOpRsp::Enroll(EnrollResponse { sid, handle }))
+                }
+                Err(e) => gk_error_rsp(req.code(), e),
+            },
+            PerformOpReq::Verify(req) => {
+                match self.verify(req.user_id, req.challenge, &req.handle, &req.password) {
+                    Ok((request_reenroll, auth_token)) => {
+                        PerformOpResponse::Ok(PerformOpRsp::Verify(VerifyResponse {
+                            request_reenroll,
+                            auth_token,
+                        }))
+                    }
+                    Err(e) => gk_error_rsp(req.code(), e),
+                }
+            }
+
+            // ISharedSecret messages.
+            PerformOpReq::GetSharedSecretParams(req) => match self.get_shared_secret_params() {
+                Ok(params) => PerformOpResponse::Ok(PerformOpRsp::GetSharedSecretParams(
+                    GetSharedSecretParamsResponse { params },
+                )),
+                Err(e) => ss_error_rsp(req.code(), e),
+            },
+            PerformOpReq::ComputeSharedSecret(req) => {
+                match self.compute_shared_secret(&req.params) {
+                    Ok(sharing_check) => PerformOpResponse::Ok(PerformOpRsp::ComputeSharedSecret(
+                        ComputeSharedSecretResponse { sharing_check },
+                    )),
+                    Err(e) => ss_error_rsp(req.code(), e),
+                }
+            }
+        }
+    }
+
+    fn delete_all_users(&mut self) -> Result<(), Error> {
+        info!("delete all users");
+        self.imp.failures.clear_all()
+    }
+
+    fn delete_user(&mut self, user_id: wire::AndroidUserId) -> Result<(), Error> {
+        info!("delete user {user_id:?}");
+        let deleted = self.imp.failures.clear(user_id)?;
+        if !deleted {
+            warn!("no record for {user_id:?} found to delete");
+            Err(Error::NotFound)
+        } else {
+            Ok(())
+        }
+    }
+
+    fn enroll(
+        &mut self,
+        user_id: AndroidUserId,
+        current_handle: &Option<wire::PasswordHandle>,
+        current_password: &Option<Password>,
+        new_password: &Password,
+    ) -> Result<(SecureUserId, wire::PasswordHandle), Error> {
+        if new_password.0.is_empty() {
+            error!("empty password for {user_id:?} not allowed");
+            return Err(Error::InvalidArgument);
+        }
+        info!(
+            "enroll user {user_id:?} (old handle provided: {}, old password provided: {})",
+            current_handle.is_some(),
+            current_password.is_some()
+        );
+
+        let now = self.imp.clock.now();
+        let sid = if let Some(current_handle) = current_handle.as_ref() {
+            let Some(current_password) = current_password else {
+                error!("old password provided without old handle!");
+                return Err(Error::InvalidArgument);
+            };
+            self.verify_handle_and_password(user_id, current_handle, current_password, now)?
+        } else {
+            let sid = self.imp.rng.next_u64() as i64;
+            info!("assigned new {sid:?} for {user_id:?}");
+            SecureUserId(sid)
+        };
+
+        // Create a fresh failure record that has no recorded failures as yet.
+        let fresh_record = FailureRecord::new(sid);
+        if let Err(err) = self.write_failure_record(user_id, &fresh_record) {
+            error!("failed to write failure record: {err:?}");
+            return Err(err);
+        }
+
+        let handle = self.new_password_handle(new_password, sid)?;
+        Ok((sid, handle.to_wire()?))
+    }
+
+    fn verify(
+        &mut self,
+        user_id: AndroidUserId,
+        challenge: i64,
+        handle: &wire::PasswordHandle,
+        password: &Password,
+    ) -> Result<(bool, HardwareAuthToken), Error> {
+        debug!("verify user {user_id:?} with challenge {challenge}");
+
+        let now = self.imp.clock.now();
+        let sid = self.verify_handle_and_password(user_id, handle, password, now)?;
+
+        // Generate a HAT and record a fresh failure record that indicates no failures as of now.
+        let hat = self.mint_auth_token(now, sid, challenge)?;
+
+        let fresh_record = FailureRecord::new(sid);
+        self.write_failure_record(user_id, &fresh_record)?;
+
+        // Request-reenroll is currently always false, but allows for forward compatibility in case
+        // a future version needs to change formats.
+        Ok((false, hat))
+    }
+
+    fn verify_handle_and_password(
+        &mut self,
+        user_id: AndroidUserId,
+        handle: &wire::PasswordHandle,
+        password: &Password,
+        now: MillisecondsSinceEpoch,
+    ) -> Result<SecureUserId, Error> {
+        let handle = handle::PasswordHandle::from_wire(handle)?;
+        let sid = handle.sid();
+
+        let mut record = self.get_failure_record(user_id, sid)?;
+
+        // May need to give up early if the user is throttled.
+        self.should_throttle(user_id, &mut record, now)?;
+
+        // Pre-increment the failure count just in case (success later will clear it).
+        self.increment_failure(user_id, &mut record, now)?;
+
+        if self.verify_password(&handle, password).is_err() {
+            warn!("password verification failed");
+            let timeout: i32 = record.compute_retry_timeout().try_into().unwrap_or(i32::MAX);
+            if timeout > 0 {
+                warn!("try again after {timeout}");
+                return Err(Error::RetryTimeout(timeout));
+            } else {
+                return Err(Error::VerifyFailed);
+            }
+        }
+        Ok(sid)
+    }
+
+    /// Retrieve the failure record for the given `user_id` and check it has the expected `sid`.
+    fn get_failure_record(
+        &self,
+        user_id: AndroidUserId,
+        sid: SecureUserId,
+    ) -> Result<FailureRecord, Error> {
+        let record = self.imp.failures.get(user_id)?.ok_or_else(|| {
+            error!("no failure record for {user_id:?} found");
+            Error::Internal
+        })?;
+        if record.sid != sid {
+            error!("failure record for {user_id:?} has {:?}, expect {sid:?}", record.sid);
+            Err(Error::Internal)
+        } else {
+            Ok(record)
+        }
+    }
+
+    /// Write (or over-write) the failure record for the given `user_id`.
+    fn write_failure_record(
+        &mut self,
+        user_id: AndroidUserId,
+        record: &FailureRecord,
+    ) -> Result<(), Error> {
+        self.imp.failures.set(user_id, record)
+    }
+
+    fn new_password_handle(
+        &mut self,
+        password: &wire::Password,
+        sid: SecureUserId,
+    ) -> Result<handle::PasswordHandle, Error> {
+        handle::PasswordHandle::new(
+            &self.imp.password.key()?,
+            &*self.imp.hmac,
+            &mut *self.imp.rng,
+            password,
+            sid,
+        )
+    }
+
+    /// Check whether the given `password` matches the `handle`.
+    fn verify_password(
+        &self,
+        handle: &handle::PasswordHandle,
+        password: &wire::Password,
+    ) -> Result<(), Error> {
+        handle.verify(&self.imp.password.key()?, &*self.imp.hmac, &*self.imp.compare, password)
+    }
+
+    /// Indicate whether an attempt to verify should be throttled.
+    ///
+    /// - If the current time is within the throttle period, return [`Error::RetryTimeout`].
+    /// - If the current time is not within a throttle period, return the next throttle period in
+    ///   milliseconds.
+    fn should_throttle(
+        &mut self,
+        user_id: AndroidUserId,
+        record: &mut FailureRecord,
+        now: MillisecondsSinceEpoch,
+    ) -> Result<(), Error> {
+        let timeout = record.compute_retry_timeout();
+        if timeout == 0 {
+            return Ok(());
+        }
+
+        // There is a pending throttle period, so see if `now` is within it.
+        let deadline = record.last_checked_timestamp + timeout;
+        if now <= record.last_checked_timestamp {
+            info!(
+                "now {now:?} appears before last check {:?} for {user_id:?}, reset timestamp",
+                record.last_checked_timestamp
+            );
+            record.last_checked_timestamp = now;
+            self.write_failure_record(user_id, record)?;
+            Err(Error::RetryTimeout(timeout as i32))
+        } else if record.last_checked_timestamp < now && now < deadline {
+            let remaining = deadline.0 - now.0;
+            info!("in throttle period for {user_id:?}, {remaining}ms remaining");
+            Err(Error::RetryTimeout(remaining.try_into().unwrap_or(i32::MAX)))
+        } else {
+            info!("throttle period for {user_id:?} expired by {now:?}");
+            Ok(())
+        }
+    }
+
+    fn increment_failure(
+        &mut self,
+        user_id: AndroidUserId,
+        record: &mut FailureRecord,
+        now: MillisecondsSinceEpoch,
+    ) -> Result<(), Error> {
+        record.failure_counter += 1;
+        record.last_checked_timestamp = now;
+        self.write_failure_record(user_id, record)
+    }
+
+    fn mint_auth_token(
+        &self,
+        now: MillisecondsSinceEpoch,
+        sid: SecureUserId,
+        challenge: i64,
+    ) -> Result<HardwareAuthToken, Error> {
+        let mut hat = HardwareAuthToken {
+            challenge,
+            user_id: sid.0,
+            authenticator_id: 0,
+            authenticator_type: wire::HardwareAuthenticatorType::Password,
+            timestamp: now,
+            mac: Vec::new(),
+        };
+        let to_mac = hat.mac_input().map_err(|_| Error::AllocationFailed)?;
+        hat.mac = self.imp.auth_key.sign(&to_mac)?;
+        Ok(hat)
+    }
+}
+
+/// Create a response structure with the given error converted to an error code for
+/// the Gatekeeper API.
+fn gk_error_rsp(op: GatekeeperOperation, err: Error) -> PerformOpResponse {
+    warn!("failing {op:?} request with error {err:?}");
+    match err {
+        Error::RetryTimeout(timeout) => PerformOpResponse::RetryTimeout(timeout),
+        Error::Unimplemented => PerformOpResponse::Err(wire::ApiStatus::NotImplemented as i32),
+        Error::NotFound
+        | Error::AllocationFailed
+        | Error::Internal
+        | Error::VerifyFailed
+        | Error::InvalidArgument => PerformOpResponse::Err(wire::ApiStatus::GeneralFailure as i32),
+    }
+}
+
+/// Create a response structure with the given error converted to an error code for the shared
+/// secret API.
+fn ss_error_rsp(op: GatekeeperOperation, err: Error) -> PerformOpResponse {
+    warn!("failing {op:?} request with error {err:?}");
+    let api_err = match err {
+        Error::RetryTimeout(_) | Error::VerifyFailed | Error::Internal | Error::NotFound => {
+            SharedSecretError::UnknownError
+        }
+        Error::Unimplemented => SharedSecretError::Unimplemented,
+        Error::InvalidArgument => SharedSecretError::InvalidArgument,
+        Error::AllocationFailed => SharedSecretError::MemoryAllocationFailed,
+    };
+    PerformOpResponse::Err(api_err as i32)
+}
+
+/// Hand-encoded [`PerformOpResponse`] data for [`ApiStatus::GeneralFailure`].
+/// Does not perform CBOR serialization (and so is suitable for error reporting if/when
+/// CBOR serialization fails).
+fn invalid_cbor_rsp_data() -> [u8; 3] {
+    [
+        0x82, // 2-arr
+        0x20, // nint, val -1 (GeneralFailure)
+        0x20, // nint, val -1 (GeneralFailure)
+    ]
+}
+
+/// Information about failures to verify.
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub struct FailureRecord {
+    /// The secure user ID for the enrolled user.
+    pub sid: SecureUserId,
+    /// The timestamp of the last check.
+    pub last_checked_timestamp: MillisecondsSinceEpoch,
+    /// Number of failed verifications.
+    pub failure_counter: u32,
+}
+
+impl FailureRecord {
+    /// Create a fresh failure record for the given sid.
+    fn new(sid: SecureUserId) -> Self {
+        Self { sid, last_checked_timestamp: MillisecondsSinceEpoch(0), failure_counter: 0 }
+    }
+
+    /// Create a failure record from binary data.
+    ///
+    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
+    fn from_slice(data: &[u8]) -> Result<Self, Error> {
+        if data.len() != 8 + 8 + 4 {
+            error!("failure record of unexpected length {}!", data.len());
+            return Err(Error::Internal);
+        }
+        Ok(Self {
+            sid: SecureUserId(i64::from_ne_bytes(data[0..8].try_into().unwrap())),
+            last_checked_timestamp: MillisecondsSinceEpoch(i64::from_ne_bytes(
+                data[8..16].try_into().unwrap(),
+            )),
+            failure_counter: u32::from_ne_bytes(data[16..20].try_into().unwrap()),
+        })
+    }
+
+    /// Convert a failure record into binary data.
+    ///
+    /// Matches the binary format from the C++ reference implementation of Gatekeeper.
+    fn to_vec(&self) -> Result<Vec<u8>, Error> {
+        let mut result = vec_try_with_capacity(8 + 8 + 4)?;
+        result.extend_from_slice(&self.sid.0.to_ne_bytes());
+        result.extend_from_slice(&self.last_checked_timestamp.0.to_ne_bytes());
+        result.extend_from_slice(&self.failure_counter.to_ne_bytes());
+        Ok(result)
+    }
+
+    /// Compute the next timeout for the failure record, in milliseconds, based on
+    /// the failure count.
+    ///
+    /// - [0, 4] => 0
+    /// - 5 => 30
+    /// - [6, 10] => 0
+    /// - [11, 29] => 30
+    /// - [30, 139] => 30 * (2^((x - 30)/10))
+    /// - [140, inf) => 1 day
+    pub fn compute_retry_timeout(&self) -> u32 {
+        const THIRTY_SECONDS: u32 = 30_000;
+        match self.failure_counter {
+            0..5 => 0,
+            5 => THIRTY_SECONDS,
+            6..11 => 0,
+            11..30 => THIRTY_SECONDS,
+            count @ 30..140 => THIRTY_SECONDS * (1 << ((count - 30) / 10)),
+            140..=u32::MAX => 1000 * 60 * 60 * 24,
+        }
+    }
+}
diff --git a/rust/ta/src/secret.rs b/rust/ta/src/secret.rs
new file mode 100644
index 0000000..1718bcd
--- /dev/null
+++ b/rust/ta/src/secret.rs
@@ -0,0 +1,97 @@
+// Copyright 2022, The Android Open Source Project
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
+//! TA functionality for shared secret negotiation.
+
+use crate::{traits::AUTH_KEY_SIZE, Error};
+use alloc::vec::Vec;
+use gk_wire as wire;
+use hal_wire::{mem::FallibleAllocExt, vec_try};
+use log::{error, info};
+use wire::SharedSecretParameters;
+
+/// Label used in CKDF derivation.
+const KEY_AGREEMENT_LABEL: &str = "KeymasterSharedMac";
+
+/// Test input used for verification of agreed key.
+const KEY_CHECK_LABEL: &str = "Keymaster HMAC Verification";
+
+impl crate::GatekeeperTa {
+    pub(crate) fn get_shared_secret_params(&mut self) -> Result<SharedSecretParameters, Error> {
+        if self.imp.shared_secret.is_none() {
+            error!("get_shared_secret_params called but not supported!");
+            return Err(Error::Unimplemented);
+        }
+        if self.shared_secret_params.is_none() {
+            info!("initialize shared secret parameters");
+            let mut nonce = vec_try![0u8; 32]?;
+            self.imp.rng.fill_bytes(&mut nonce);
+            self.shared_secret_params = Some(SharedSecretParameters { seed: Vec::new(), nonce });
+        }
+        Ok(self.shared_secret_params.as_ref().unwrap().clone()) // safe: filled above
+    }
+
+    pub(crate) fn compute_shared_secret(
+        &mut self,
+        params: &[SharedSecretParameters],
+    ) -> Result<Vec<u8>, Error> {
+        let Some(ss_imp) = self.imp.shared_secret.as_ref() else {
+            error!("compute_shared_secret called but not supported!");
+            return Err(Error::Unimplemented);
+        };
+        let Some(local_params) = self.shared_secret_params.as_ref() else {
+            error!("no local shared secret params!");
+            return Err(Error::InvalidArgument);
+        };
+
+        info!("Setting HMAC key from {} shared secret parameters", params.len());
+        let context = shared_secret_context(params, local_params)?;
+
+        let key = ss_imp.derive.derive(
+            &ss_imp.preshared_key.get(),
+            KEY_AGREEMENT_LABEL.as_bytes(),
+            &[&context],
+            AUTH_KEY_SIZE,
+        )?;
+        self.imp.auth_key.key_agreed(key)?;
+        self.imp.auth_key.sign(KEY_CHECK_LABEL.as_bytes())
+    }
+}
+
+/// Build the shared secret context from the given `params`, which
+/// is required to include `must_include` (our own parameters).
+pub fn shared_secret_context(
+    params: &[SharedSecretParameters],
+    must_include: &SharedSecretParameters,
+) -> Result<Vec<u8>, Error> {
+    let mut result = Vec::new();
+    let mut seen = false;
+    for param in params {
+        result.try_extend_from_slice(&param.seed)?;
+        if param.nonce.len() != 32 {
+            error!("nonce len {} not 32", param.nonce.len());
+            return Err(Error::InvalidArgument);
+        }
+        result.try_extend_from_slice(&param.nonce)?;
+        if param == must_include {
+            seen = true;
+        }
+    }
+    if !seen {
+        error!("shared secret params missing local value");
+        Err(Error::InvalidArgument)
+    } else {
+        Ok(result)
+    }
+}
diff --git a/rust/ta/src/tests.rs b/rust/ta/src/tests.rs
new file mode 100644
index 0000000..363cdae
--- /dev/null
+++ b/rust/ta/src/tests.rs
@@ -0,0 +1,133 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Tests
+
+use crate::{
+    handle::PasswordHandle,
+    traits::{HmacKey, HmacSha256, OpaqueOr, Rng},
+    Error, FailureRecord,
+};
+use alloc::{vec, vec::Vec};
+use gk_wire as wire;
+use hal_wire::AsCborValue;
+use wire::{MillisecondsSinceEpoch, SecureUserId};
+
+#[test]
+fn test_invalid_data() {
+    // Cross-check that the hand-encoded invalid CBOR data matches an auto-encoded equivalent.
+    let rsp = wire::PerformOpResponse::Err(wire::ApiStatus::GeneralFailure as i32);
+    let rsp_data = rsp.into_vec().unwrap();
+    assert_eq!(hex::encode(rsp_data), hex::encode(super::invalid_cbor_rsp_data()));
+}
+
+#[test]
+fn test_failure_record_roundtrip() {
+    let tests = [(1, 100, 0), (-1, -100, 5), (i64::MAX, 22593600, 5), (i64::MIN, 22593600, 5)];
+    for (sid, ts, count) in tests {
+        let want = FailureRecord {
+            sid: SecureUserId(sid),
+            last_checked_timestamp: MillisecondsSinceEpoch(ts),
+            failure_counter: count,
+        };
+        let data = want.to_vec().unwrap();
+        let got = FailureRecord::from_slice(&data).unwrap();
+        assert_eq!(got, want, "for input {want:?}");
+    }
+}
+
+#[test]
+fn test_password_handle_roundtrip() {
+    let hmac_key = OpaqueOr::Explicit(HmacKey(vec![1, 2, 3]));
+
+    struct Fakery;
+    impl HmacSha256 for Fakery {
+        fn sign(&self, _key: &OpaqueOr<HmacKey>, _data: &[u8]) -> Result<Vec<u8>, Error> {
+            Ok(vec![0xdd; 32])
+        }
+    }
+    impl Rng for Fakery {
+        fn fill_bytes(&mut self, dest: &mut [u8]) {
+            dest.fill(2);
+        }
+    }
+
+    let want = PasswordHandle::new(
+        &hmac_key,
+        &Fakery,
+        &mut Fakery,
+        &wire::Password(vec![1, 2, 3]),
+        SecureUserId(43),
+    )
+    .unwrap();
+    let data = want.to_wire().unwrap();
+    let got = PasswordHandle::from_wire(&data).unwrap();
+    assert_eq!(got, want)
+}
+
+#[test]
+fn test_retry_timeout() {
+    const ONE_DAY: u32 = 24 * 60 * 60 * 1000;
+    let tests = [
+        (0, 0),
+        (1, 0),
+        (1, 0),
+        (5, 30_000),
+        (6, 0),
+        (7, 0),
+        (8, 0),
+        (9, 0),
+        (10, 0),
+        (11, 30_000),
+        (18, 30_000),
+        (22, 30_000),
+        (29, 30_000),
+        (30, 30_000),
+        (31, 30_000),
+        (32, 30_000),
+        (39, 30_000),
+        (40, 60_000),
+        (49, 60_000),
+        (50, 120_000),
+        (59, 120_000),
+        (60, 240_000),
+        (69, 240_000),
+        (70, 480_000),
+        (79, 480_000),
+        (80, 960_000),
+        (89, 960_000),
+        (90, 1_920_000),
+        (99, 1_920_000),
+        (100, 3_840_000),
+        (109, 3_840_000),
+        (110, 7_680_000),
+        (119, 7_680_000),
+        (120, 15_360_000),
+        (129, 15_360_000),
+        (130, 30_720_000),
+        (139, 30_720_000),
+        (140, ONE_DAY),
+        (141, ONE_DAY),
+        (14100, ONE_DAY),
+    ];
+    for (count, want) in tests {
+        let record = FailureRecord {
+            sid: SecureUserId(1),
+            last_checked_timestamp: MillisecondsSinceEpoch(1),
+            failure_counter: count,
+        };
+        let got = record.compute_retry_timeout();
+        assert_eq!(got, want, "for count={count}");
+    }
+}
diff --git a/rust/ta/src/traits.rs b/rust/ta/src/traits.rs
new file mode 100644
index 0000000..604e651
--- /dev/null
+++ b/rust/ta/src/traits.rs
@@ -0,0 +1,388 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Traits representing abstractions of device-specific functionality.
+
+use crate::{Error, FailureRecord};
+use alloc::boxed::Box;
+use alloc::string::String;
+use alloc::vec::Vec;
+use gk_wire::{AndroidUserId, MillisecondsSinceEpoch};
+use hal_wire::vec_try;
+use log::{error, warn};
+use zeroize::ZeroizeOnDrop;
+
+/// Combined collection of trait implementations that must be provided.
+pub struct Implementation {
+    /// Random number generator.
+    pub rng: Box<dyn Rng>,
+
+    /// A local clock.
+    pub clock: Box<dyn MonotonicClock>,
+
+    /// A constant-time equality implementation.
+    pub compare: Box<dyn ConstTimeEq>,
+
+    /// HMAC-SHA256 implementation.
+    pub hmac: Box<dyn HmacSha256>,
+
+    /// Trait for retrieval of the password key.
+    pub password: Box<dyn PasswordKeyRetrieval>,
+
+    /// Trait for management and use of the auth key.
+    pub auth_key: Box<dyn AuthKeyManagement>,
+
+    /// Trait for storage of failure records.
+    pub failures: Box<dyn FailureRecording>,
+
+    /// Traits for shared secret negotiation.  This is only required if the TA is configured to
+    /// support the `ISharedSecret` mechanism for agreeing the auth key.
+    pub shared_secret: Option<SharedSecretImplementation>,
+}
+
+/// Size of the auth key in bytes.
+pub const AUTH_KEY_SIZE: usize = 32;
+
+/// Abstraction of device-specific mechanisms for managing and using the HMAC-SHA256 key that is
+/// used for authentication.
+pub trait AuthKeyManagement: Send {
+    /// Use the auth key to generate an HMAC-SHA256 signature of the given `data`.
+    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
+
+    /// Pass an agreed authentication key to the implementation.  This method only needs an
+    /// implementation if `ISharedSecret` support is included.
+    fn key_agreed(&mut self, _key: OpaqueOr<HmacKey>) -> Result<(), Error> {
+        Err(Error::Unimplemented)
+    }
+}
+
+/// Abstraction of persistent password key.
+pub trait PasswordKeyRetrieval: Send {
+    /// Retrieve the persistent password key.  The same key must remain available after factory
+    /// reset (as Gatekeeper authentication is required for clearing factory reset protection).
+    fn key(&self) -> Result<OpaqueOr<HmacKey>, Error>;
+}
+
+/// Abstraction of a random number generator that is cryptographically secure.
+pub trait Rng: Send {
+    /// Generate random data.
+    fn fill_bytes(&mut self, dest: &mut [u8]);
+    /// Return a random `u64` value.
+    fn next_u64(&mut self) -> u64 {
+        let mut buf = [0u8; 8];
+        self.fill_bytes(&mut buf);
+        u64::from_le_bytes(buf)
+    }
+}
+
+/// Abstraction of constant-time comparisons, for use in cryptographic contexts where timing attacks
+/// need to be avoided.
+pub trait ConstTimeEq: Send {
+    /// Indicate whether arguments are the same.
+    fn eq(&self, left: &[u8], right: &[u8]) -> bool;
+    /// Indicate whether arguments are the different.
+    fn ne(&self, left: &[u8], right: &[u8]) -> bool {
+        !self.eq(left, right)
+    }
+}
+
+/// Abstraction of a monotonic clock.
+pub trait MonotonicClock: Send {
+    /// Return the current time in milliseconds since some arbitrary point in time.  Time must be
+    /// monotonically increasing, and "current time" must not repeat until the Android device
+    /// reboots, or until at least 50 million years have elapsed.  Time must also continue to
+    /// advance while the device is suspended.  (For example, in Linux the equivalent would be to
+    /// use `CLOCK_BOOTTIME` rather than `CLOCK_MONOTONIC` in `clock_gettime`.)
+    fn now(&self) -> MillisecondsSinceEpoch;
+}
+
+/// Abstraction of HMAC-SHA256 functionality.
+pub trait HmacSha256: Send {
+    /// Generate an HMAC-SHA256 signature of the given `data` using the supplied `key`.
+    fn sign(&self, key: &OpaqueOr<HmacKey>, data: &[u8]) -> Result<Vec<u8>, Error>;
+
+    /// Verify an HMAC-SHA256 signature of the given `data` using the supplied `key`.
+    fn verify(
+        &self,
+        eq: &dyn ConstTimeEq,
+        key: &OpaqueOr<HmacKey>,
+        data: &[u8],
+        sig: &[u8],
+    ) -> Result<(), Error> {
+        let recalculated = self.sign(key, data)?;
+        if eq.ne(sig, &recalculated) {
+            Err(Error::VerifyFailed)
+        } else {
+            Ok(())
+        }
+    }
+}
+
+/// An HMAC key.
+#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
+pub struct HmacKey(pub Vec<u8>);
+
+/// Opaque key material whose structure is only known/accessible to the crypto implementation.
+/// The contents of this are assumed to be encrypted (and so are not `ZeroizeOnDrop`).
+#[derive(Clone, PartialEq, Eq)]
+pub struct OpaqueKeyMaterial(pub Vec<u8>);
+
+/// Wrapper that holds either a key of explicit type `T`, or an opaque blob of key material.
+#[derive(Clone, PartialEq, Eq)]
+pub enum OpaqueOr<T> {
+    /// Explicit key material of the given type, available in plaintext.
+    Explicit(T),
+    /// Opaque key material, either encrypted or an opaque key handle.
+    Opaque(OpaqueKeyMaterial),
+}
+
+impl From<HmacKey> for OpaqueOr<HmacKey> {
+    fn from(k: HmacKey) -> Self {
+        Self::Explicit(k)
+    }
+}
+
+/// Abstraction of the device-specific functionality for managing failure records.  These records
+/// must be persistent across boots and across factory reset (to allow for clearing factory
+/// reset protection).
+pub trait FailureRecording {
+    /// Retrieve the failure record for the specified `user_id`.
+    fn get(&self, user_id: AndroidUserId) -> Result<Option<FailureRecord>, Error>;
+
+    /// Write (or over-write) a failure record for the specified `user_id`.
+    fn set(&mut self, user_id: AndroidUserId, record: &FailureRecord) -> Result<(), Error>;
+
+    /// Delete any failure record for the specified `user_id`.
+    ///
+    /// Return code indicates whether there was a failure record.
+    fn clear(&mut self, user_id: AndroidUserId) -> Result<bool, Error>;
+
+    /// Delete all failure records.
+    fn clear_all(&mut self) -> Result<(), Error>;
+}
+
+/// Abstraction of simple flat filesystem functionality.
+pub trait SecureFilesystem {
+    /// Concrete type of iterator returned by `list`.
+    type Iter: Iterator<Item = String>;
+    /// Read the entire contents of the given file. Return `Err(Error::NotFound)` if the file does
+    /// not exist.
+    fn read(&self, filename: &str) -> Result<Vec<u8>, Error>;
+    /// Write the entire contents of the given file, overwriting any existing contents.
+    fn write(&self, filename: &str, data: &[u8]) -> Result<(), Error>;
+    /// Delete the given file.  Returns `Error::NotFound` if the file does not exist.
+    fn delete(&self, filename: &str) -> Result<(), Error>;
+    /// List all files in the flat filesystem.
+    fn list(&self) -> Result<Self::Iter, Error>;
+}
+
+/// Filename prefix for per-user failure record files.
+///
+/// Back-compatible with the previous Trusty C++ implementation.
+const GK_FILENAME_PREFIX: &str = "gatekeeper.";
+
+/// Generate the filename corresponding to a particular `user_id`.
+fn filename_for(user_id: AndroidUserId) -> String {
+    alloc::format!("{GK_FILENAME_PREFIX}{}", user_id.0 as u32)
+}
+
+/// Implementation of failure recording based on an underlying flat filesystem.
+///
+/// File contents are back-compatible with the previous Trusty C++ implementation.
+impl<T> FailureRecording for T
+where
+    T: SecureFilesystem,
+{
+    fn get(&self, user_id: AndroidUserId) -> Result<Option<FailureRecord>, Error> {
+        let data = match self.read(&filename_for(user_id)) {
+            Ok(data) => data,
+            Err(Error::NotFound) => return Ok(None),
+            Err(e) => return Err(e),
+        };
+        Ok(Some(FailureRecord::from_slice(&data)?))
+    }
+
+    fn set(&mut self, user_id: AndroidUserId, record: &FailureRecord) -> Result<(), Error> {
+        let data = record.to_vec()?;
+        self.write(&filename_for(user_id), &data)
+    }
+
+    fn clear(&mut self, user_id: AndroidUserId) -> Result<bool, Error> {
+        match self.delete(&filename_for(user_id)) {
+            Err(Error::NotFound) => Ok(false),
+            Err(e) => Err(e),
+            Ok(_) => Ok(true),
+        }
+    }
+
+    fn clear_all(&mut self) -> Result<(), Error> {
+        for filename in self.list()? {
+            if filename.starts_with(GK_FILENAME_PREFIX) {
+                if let Err(e) = self.delete(&filename) {
+                    error!("failed to delete {filename} (continuing anyway): {e:?}");
+                }
+            }
+        }
+        Ok(())
+    }
+}
+
+/// An implementation of auth key management that holds an explicit HMAC key.
+pub struct ExplicitAuthKey {
+    key: Option<OpaqueOr<HmacKey>>,
+    hmac: Box<dyn HmacSha256>,
+}
+
+impl ExplicitAuthKey {
+    /// Create a new instance based on the given HMAC-SHA256 implementation.
+    pub fn new(hmac: Box<dyn HmacSha256>) -> Self {
+        Self { key: None, hmac }
+    }
+}
+
+impl AuthKeyManagement for ExplicitAuthKey {
+    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
+        let Some(key) = self.key.as_ref() else { return Err(Error::Internal) };
+        self.hmac.sign(key, data)
+    }
+
+    fn key_agreed(&mut self, key: OpaqueOr<HmacKey>) -> Result<(), Error> {
+        if let Some(prev_key) = self.key.as_ref() {
+            if key != *prev_key {
+                warn!("replacing already-set auth key with a different one!");
+            }
+        }
+        self.key = Some(key);
+        Ok(())
+    }
+}
+
+/// Traits required for shared secret negotiation.
+pub struct SharedSecretImplementation {
+    /// Retrieve the preshared key that is used as the basis of the negotiation.
+    pub preshared_key: Box<dyn RetrievePresharedKey>,
+
+    /// Perform the derivation.
+    pub derive: Box<dyn SharedSecretDerive>,
+}
+
+/// Explicit AES-256 key.
+pub type Aes256Key = [u8; 32];
+
+/// Mechanism to retrieve the pre-shared key for HMAC key agreement.
+pub trait RetrievePresharedKey: Send {
+    /// Retrieve the pre-shared key.
+    fn get(&self) -> OpaqueOr<Aes256Key>;
+}
+
+/// Implementation of a fixed pre-shared key for HMAC key agreement.
+///
+/// This is useful for development, testing and emulators.
+///
+/// It is not generally suitable for a production device.
+pub struct FixedPresharedKey(pub Aes256Key);
+
+impl RetrievePresharedKey for FixedPresharedKey {
+    fn get(&self) -> OpaqueOr<Aes256Key> {
+        OpaqueOr::Explicit(self.0)
+    }
+}
+
+/// Abstraction of the device-specific functionality required to support shared secret negotiation.
+pub trait SharedSecretDerive: Send {
+    /// Using some pre-shared secret `key`, derive a 32-byte key (which will be used as the device
+    /// auth key, using HMAC-SHA256) using CKDF with the provided `context` and `label`.  CKDF is
+    /// defined in section 5.1 of NIST SP 800-108.
+    fn derive(
+        &self,
+        key: &OpaqueOr<Aes256Key>,
+        label: &[u8],
+        context: &[&[u8]],
+        out_len: usize,
+    ) -> Result<OpaqueOr<HmacKey>, Error>;
+}
+
+/// Abstraction of AES-CMAC.
+pub trait AesCmac: Send {
+    /// Start an AES-CMAC operation.
+    fn begin(key: &OpaqueOr<Aes256Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;
+}
+
+/// Abstraction of an in-progress operation that only emits data when it completes.
+pub trait AccumulatingOperation: Send {
+    /// Update operation with data.
+    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
+
+    /// Complete operation, consuming `self`.
+    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
+}
+
+/// Given an AES-CMAC implementation, provide an implementation of [`SharedSecretDerive`] via CKDF.
+impl<A: AesCmac> SharedSecretDerive for A {
+    fn derive(
+        &self,
+        key: &OpaqueOr<Aes256Key>,
+        label: &[u8],
+        context: &[&[u8]],
+        out_len: usize,
+    ) -> Result<OpaqueOr<HmacKey>, Error> {
+        let key = ckdf::<A>(key, label, context, out_len)?;
+        Ok(OpaqueOr::Explicit(HmacKey(key)))
+    }
+}
+
+/// Size of an AES block in bytes.
+pub const AES_BLOCK_SIZE: usize = 16;
+
+/// Perform CKDF.
+fn ckdf<A: AesCmac>(
+    key: &OpaqueOr<Aes256Key>,
+    label: &[u8],
+    chunks: &[&[u8]],
+    out_len: usize,
+) -> Result<Vec<u8>, Error> {
+    // Note: the variables i and l correspond to i and L in the standard.  See page 12 of
+    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf.
+
+    let blocks: u32 = out_len.div_ceil(AES_BLOCK_SIZE) as u32;
+    let l = (out_len * 8) as u32; // in bits
+    let net_order_l = l.to_be_bytes();
+    let zero_byte: [u8; 1] = [0];
+    let mut output = vec_try![0; out_len]?;
+    let mut output_pos = 0;
+
+    for i in 1u32..=blocks {
+        // Data to mac is (i:u32 || label || 0x00:u8 || context || L:u32), with integers in
+        // network order.
+        let mut op = A::begin(key)?;
+        let net_order_i = i.to_be_bytes();
+        op.update(&net_order_i[..])?;
+        op.update(label)?;
+        op.update(&zero_byte[..])?;
+        for chunk in chunks {
+            op.update(chunk)?;
+        }
+        op.update(&net_order_l[..])?;
+
+        let data = op.finish()?;
+        let copy_len = core::cmp::min(data.len(), output.len() - output_pos);
+        output[output_pos..output_pos + copy_len].clone_from_slice(&data[..copy_len]);
+        output_pos += copy_len;
+    }
+    if output_pos != output.len() {
+        error!("finished at {output_pos} before end of output at {}", output.len());
+        return Err(Error::InvalidArgument);
+    }
+    Ok(output)
+}
diff --git a/rust/tests/Android.bp b/rust/tests/Android.bp
new file mode 100644
index 0000000..20f721b
--- /dev/null
+++ b/rust/tests/Android.bp
@@ -0,0 +1,44 @@
+// Copyright 2022, The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_defaults {
+    name: "gk_tests_defaults",
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "libciborium",
+        "libenv_logger",
+        "libgk_ta",
+        "libgk_wire",
+        "libhex",
+        "liblog_rust",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+}
+
+rust_library {
+    name: "libgk_tests",
+    crate_name: "gk_tests",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    defaults: [
+        "gk_tests_defaults",
+    ],
+}
diff --git a/rust/tests/Cargo.toml b/rust/tests/Cargo.toml
new file mode 100644
index 0000000..7956d15
--- /dev/null
+++ b/rust/tests/Cargo.toml
@@ -0,0 +1,17 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "gk-tests"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+ciborium = { version = "^0.2.0", default-features = false }
+env_logger = "^0.9"
+gk-ta = "*"
+gk-wire = "*"
+hex = "0.4.3"
+log = "^0.4"
diff --git a/rust/tests/src/lib.rs b/rust/tests/src/lib.rs
new file mode 100644
index 0000000..2e3e155
--- /dev/null
+++ b/rust/tests/src/lib.rs
@@ -0,0 +1,307 @@
+// Copyright 2022, The Android Open Source Project
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
+//! Test methods to confirm basic functionality of trait implementations.
+
+use gk_ta::traits::{
+    Aes256Key, AesCmac, ConstTimeEq, FailureRecording, HmacKey, HmacSha256, MonotonicClock,
+    OpaqueOr, Rng, SharedSecretDerive,
+};
+use gk_ta::FailureRecord;
+use gk_wire::{AndroidUserId, MillisecondsSinceEpoch, SecureUserId};
+use std::time::Duration;
+
+/// Test basic [`Rng`] functionality.
+pub fn test_rng<R: Rng>(rng: &mut R) {
+    let u1 = rng.next_u64();
+    let u2 = rng.next_u64();
+    assert_ne!(u1, u2);
+
+    let mut b1 = [0u8; 16];
+    let mut b2 = [0u8; 16];
+    rng.fill_bytes(&mut b1);
+    rng.fill_bytes(&mut b2);
+    assert_ne!(b1, b2);
+
+    rng.fill_bytes(&mut b1);
+    assert_ne!(b1, b2);
+}
+
+/// Test basic [`ConstTimeEq`] functionality. Does not test the key constant-time property though.
+pub fn test_eq<E: ConstTimeEq>(comparator: E) {
+    let b0 = [];
+    let b1 = [0u8, 1u8, 2u8];
+    let b2 = [1u8, 1u8, 2u8];
+    let b3 = [0u8, 1u8, 3u8];
+    let b4 = [0u8, 1u8, 2u8, 3u8];
+    let b5 = [42; 4096];
+    let mut b6 = [42; 4096];
+    b6[4095] = 43;
+    assert!(comparator.eq(&b0, &b0));
+    assert!(comparator.eq(&b5, &b5));
+
+    assert!(comparator.ne(&b0, &b1));
+    assert!(comparator.ne(&b0, &b2));
+    assert!(comparator.ne(&b0, &b3));
+    assert!(comparator.ne(&b0, &b4));
+    assert!(comparator.ne(&b0, &b5));
+    assert!(comparator.eq(&b1, &b1));
+    assert!(comparator.ne(&b1, &b2));
+    assert!(comparator.ne(&b1, &b3));
+    assert!(comparator.ne(&b1, &b4));
+    assert!(comparator.ne(&b5, &b6));
+}
+
+/// Test the constant-time property for [`ConstTimeEq`] functionality.
+pub fn test_constant_time_eq<E: ConstTimeEq>(cmp: E) {
+    const LEN: usize = 128 * 1024 * 1024;
+    let base = vec![42; LEN];
+    let same = base.clone();
+
+    // Change a bit in the last byte.
+    let mut last = base.clone();
+    last[LEN - 1] ^= 0x01;
+    // Change a bit in the first byte.
+    let mut first = base.clone();
+    first[0] ^= 0x01;
+
+    assert!(cmp.eq(&base, &base));
+    assert!(cmp.ne(&base, &first));
+    assert!(cmp.ne(&base, &last));
+
+    // Benchmark comparisons with first and last bytes holding a difference.
+    let same_duration = bench(|| cmp.eq(&base, &same));
+    println!("comparing same {LEN}-byte chunk takes {same_duration:?}");
+    let first_duration = bench(|| cmp.eq(&base, &first));
+    println!("comparing {LEN}-byte chunk with differing first byte takes {first_duration:?}");
+    let last_duration = bench(|| cmp.eq(&base, &last));
+    println!("comparing {LEN}-byte chunk with differing last byte takes {last_duration:?}");
+
+    check_same("compare-same vs compare-first-byte", &same_duration, &first_duration, 20.0);
+    check_same("compare-same vs compare-last-byte", &same_duration, &last_duration, 20.0);
+    check_same("compare-first-byte vs compare-last-byte", &first_duration, &last_duration, 20.0);
+}
+
+fn check_same(msg: &str, base: &Duration, other: &Duration, max_pct_diff: f64) {
+    let delta_nanos = base.as_nanos().abs_diff(other.as_nanos());
+    let pct_diff = 100.0 * delta_nanos as f64 / base.as_nanos() as f64;
+    assert!(
+        pct_diff < max_pct_diff,
+        "{msg}: difference {pct_diff}% between {base:?} and {other:?} should be < {max_pct_diff}%"
+    );
+    println!("{msg}: {pct_diff}% between {base:?} and {other:?} is < {max_pct_diff}%");
+}
+
+/// Repeatedly run the given closure and return average iteration time.
+fn bench<F>(mut f: F) -> Duration
+where
+    F: FnMut() -> bool,
+{
+    const WARMUP_ITERATIONS: u32 = 5;
+    let mut duration = Duration::ZERO;
+    println!("  warmup for {WARMUP_ITERATIONS}...");
+    for _ in 0..WARMUP_ITERATIONS {
+        duration += time(&mut f);
+    }
+    let warmup = duration / WARMUP_ITERATIONS;
+    println!("  warmup for {WARMUP_ITERATIONS}...done in {duration:?} average {warmup:?}");
+
+    // Guess at rough number of iterations that fit in the test interval.
+    const TEST_INTERVAL: Duration = Duration::from_secs(5);
+    let iterations = if warmup > Duration::from_secs(1) {
+        3
+    } else {
+        TEST_INTERVAL.as_nanos() / warmup.as_nanos()
+    };
+    let iterations = u32::try_from(iterations).unwrap_or(u32::MAX);
+
+    println!("  iterate for {iterations}...");
+    let mut duration = Duration::ZERO;
+    for _ in 0..iterations {
+        duration += time(&mut f);
+    }
+    let result = duration / iterations;
+    println!("  warmup for {iterations}...done in {duration:?} average {result:?}");
+    result
+}
+
+#[inline]
+fn time<F>(f: &mut F) -> Duration
+where
+    F: FnMut() -> bool,
+{
+    let start = std::time::Instant::now();
+    let _ = f();
+    start.elapsed()
+}
+
+/// Test basic [`MonotonicClock`] functionality.
+pub fn test_clock<C: MonotonicClock>(clock: C) {
+    let t1 = clock.now();
+    let t2 = clock.now();
+    assert!(t2.0 >= t1.0);
+    std::thread::sleep(std::time::Duration::from_millis(400));
+    let t3 = clock.now();
+    assert!(t3.0 > (t1.0 + 200));
+}
+
+/// Test basic [`HmacSha256`] functionality.
+pub fn test_hmac<H: HmacSha256>(hmac: H) {
+    struct TestCase {
+        key: &'static [u8],
+        data: &'static [u8],
+        want: &'static str,
+    }
+
+    const HMAC_TESTS: &[TestCase] = &[
+        TestCase {
+            data: b"Hello",
+            key: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
+            want: "e0ff02553d9a619661026c7aa1ddf59b7b44eac06a9908ff9e19961d481935d4",
+        },
+        // empty data
+        TestCase {
+            data: &[],
+            key: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
+            want: "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d",
+        },
+        // Test cases from RFC 4231 Section 4.2
+        TestCase {
+            key: &[0x0b; 20],
+            data: b"Hi There",
+            want: concat!("b0344c61d8db38535ca8afceaf0bf12b", "881dc200c9833da726e9376c2e32cff7",),
+        },
+        // Test cases from RFC 4231 Section 4.3
+        TestCase {
+            key: b"Jefe",
+            data: b"what do ya want for nothing?",
+            want: concat!("5bdcc146bf60754e6a042426089575c7", "5a003f089d2739839dec58b964ec3843"),
+        },
+        // Test cases from RFC 4231 Section 4.4
+        TestCase {
+            key: &[0xaa; 20],
+            data: &[0xdd; 50],
+            want: concat!("773ea91e36800e46854db8ebd09181a7", "2959098b3ef8c122d9635514ced565fe"),
+        },
+    ];
+
+    for (i, test) in HMAC_TESTS.iter().enumerate() {
+        let key = OpaqueOr::Explicit(HmacKey(test.key.to_vec()));
+        let got = hmac.sign(&key, test.data).expect("failed to HMAC for case {i}");
+        assert_eq!(hex::encode(&got), test.want, "incorrect mac in case {i}",);
+    }
+}
+
+/// Test [`FailureRecording`] functionality.
+pub fn test_failure_recording<T: FailureRecording>(mut records: T) {
+    let record = |sid, ts, count| FailureRecord {
+        sid: SecureUserId(sid),
+        last_checked_timestamp: MillisecondsSinceEpoch(ts),
+        failure_counter: count,
+    };
+
+    records.set(AndroidUserId(100), &record(100100, 1, 0)).unwrap();
+    records.set(AndroidUserId(200), &record(100200, 100, 0)).unwrap();
+    records.set(AndroidUserId(300), &record(100300, 100, 0)).unwrap();
+
+    assert_eq!(records.get(AndroidUserId(100)).unwrap(), Some(record(100100, 1, 0)));
+    assert_eq!(records.get(AndroidUserId(200)).unwrap(), Some(record(100200, 100, 0)));
+    assert_eq!(records.get(AndroidUserId(300)).unwrap(), Some(record(100300, 100, 0)));
+
+    records.set(AndroidUserId(100), &record(100101, 101, 0)).unwrap();
+
+    assert_eq!(records.get(AndroidUserId(100)).unwrap(), Some(record(100101, 101, 0)));
+    assert_eq!(records.get(AndroidUserId(200)).unwrap(), Some(record(100200, 100, 0)));
+    assert_eq!(records.get(AndroidUserId(300)).unwrap(), Some(record(100300, 100, 0)));
+
+    assert!(records.clear(AndroidUserId(200)).unwrap());
+    assert_eq!(records.get(AndroidUserId(100)).unwrap(), Some(record(100101, 101, 0)));
+    assert_eq!(records.get(AndroidUserId(200)).unwrap(), None);
+    assert_eq!(records.get(AndroidUserId(300)).unwrap(), Some(record(100300, 100, 0)));
+
+    assert!(!records.clear(AndroidUserId(200)).unwrap());
+    assert!(!records.clear(AndroidUserId(200)).unwrap());
+
+    records.clear_all().unwrap();
+    assert_eq!(records.get(AndroidUserId(100)).unwrap(), None);
+    assert_eq!(records.get(AndroidUserId(200)).unwrap(), None);
+    assert_eq!(records.get(AndroidUserId(300)).unwrap(), None);
+}
+
+/// Test [`AesCmac`] functionality.
+pub fn test_aes_cmac<T: AesCmac>() {
+    // Test vectors from NIST 800-38B D.3.
+    let key =
+        hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
+    let key: Aes256Key = key.try_into().unwrap();
+    let data = hex::decode(concat!(
+        "6bc1bee22e409f96e93d7e117393172a",
+        "ae2d8a571e03ac9c9eb76fac45af8e51",
+        "30c81c46a35ce411e5fbc1191a0a52ef",
+        "f69f2445df4f9b17ad2b417be66c3710",
+    ))
+    .unwrap();
+    let tests = vec![
+        (0, "028962f61b7bf89efc6b551f4667d983"),
+        (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
+        (40, "aaf3d8f1de5640c232f5b169b9c911e6"),
+        (64, "e1992190549f6ed5696a2c056c315410"),
+    ];
+
+    for (len, want) in tests {
+        let mut op = T::begin(&OpaqueOr::Explicit(key)).unwrap();
+        op.update(&data[..len]).unwrap();
+        let got = op.finish().unwrap();
+
+        assert_eq!(hex::encode(&got), want, "for message len {len}");
+    }
+}
+
+/// Test [`SharedSecretDerive`] functionality for an [`AesCmac`] implementation.
+pub fn test_shared_secret_derive<T: AesCmac>(aes_cmac: T) {
+    // Test data manually generated from Android C++ implementation.
+    let key: Aes256Key = [0; 32];
+    let label = b"KeymasterSharedMac";
+    let v0 = vec![0x00, 0x00, 0x00, 0x00];
+    let v1 = vec![0x01, 0x01, 0x01, 0x01];
+    let v2 = vec![0x02, 0x02, 0x02, 0x02];
+    let v3 = vec![0x03, 0x03, 0x03, 0x03];
+
+    let result =
+        aes_cmac.derive(&OpaqueOr::Explicit(key), label, &[&v0, &v1, &v2, &v3], 32).unwrap();
+    let OpaqueOr::Explicit(result) = result else { panic!("expected explicit key") };
+    assert_eq!(
+        hex::encode(result.0.clone()),
+        "ac9af88a02241f53d43056a4676c42eef06825755e419e7bd20f4e57487717aa"
+    );
+}
+
+#[cfg(test)]
+mod tests {
+    use gk_ta::traits::ConstTimeEq;
+
+    /// Tests for the tests.
+    #[test]
+    #[should_panic]
+    fn test_non_constant_eq() {
+        struct NonConstEq;
+        impl ConstTimeEq for NonConstEq {
+            fn eq(&self, left: &[u8], right: &[u8]) -> bool {
+                left == right
+            }
+        }
+        // A naive implementation of `NonConstEq` will fail the test.
+        super::test_constant_time_eq(NonConstEq);
+    }
+}
diff --git a/rust/wire/Android.bp b/rust/wire/Android.bp
new file mode 100644
index 0000000..b34b7e6
--- /dev/null
+++ b/rust/wire/Android.bp
@@ -0,0 +1,103 @@
+// Copyright 2025, The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_library {
+    name: "libgk_wire",
+    crate_name: "gk_wire",
+    srcs: ["src/lib.rs"],
+    host_supported: true,
+    vendor_available: true,
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "libciborium",
+        "libciborium_io",
+        "libhal_wire",
+        "liblog_rust",
+        "libzeroize",
+    ],
+    proc_macros: [
+        "libenumn",
+        "libhal_wire_derive",
+    ],
+}
+
+rust_library_rlib {
+    name: "libgk_wire_nostd",
+    crate_name: "gk_wire",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "libciborium_nostd",
+        "libciborium_io_nostd",
+        "libhal_wire_nostd",
+        "liblog_rust_nostd",
+        "libzeroize_nostd",
+    ],
+    proc_macros: [
+        "libenumn",
+        "libhal_wire_derive",
+    ],
+    prefer_rlib: true,
+    no_stdlibs: true,
+    stdlibs: [
+        "libcompiler_builtins.rust_sysroot",
+        "libcore.rust_sysroot",
+    ],
+}
+
+rust_test_host {
+    name: "libgk_wire_test",
+    crate_name: "gk_wire_test",
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libciborium",
+        "libciborium_io",
+        "libhal_wire",
+        "libhex",
+        "liblog_rust",
+        "libzeroize",
+    ],
+    proc_macros: [
+        "libenumn",
+        "libhal_wire_derive",
+    ],
+    test_suites: ["general-tests"],
+}
+
+rust_fuzz {
+    name: "libgk_wire_fuzz_message",
+    srcs: ["fuzz/fuzz_targets/message.rs"],
+    rustlibs: [
+        "libgk_wire",
+        "libhal_wire",
+    ],
+    host_supported: true,
+    fuzz_config: {
+        cc: [
+            "drysdale@google.com",
+            "jbires@google.com",
+        ],
+        componentid: 1124862,
+        hotlists: ["4326440"],
+        fuzz_on_haiku_device: true,
+        fuzz_on_haiku_host: true,
+    },
+}
diff --git a/rust/wire/Cargo.toml b/rust/wire/Cargo.toml
new file mode 100644
index 0000000..a676f1e
--- /dev/null
+++ b/rust/wire/Cargo.toml
@@ -0,0 +1,20 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "gk-wire"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+ciborium = { version = "^0.2.2", default-features = false }
+ciborium-io = "^0.2.0"
+enumn = "0.1.4"
+hal-wire = "*"
+hal-wire-derive = "*"
+log = "^0.4"
+
+[dev-dependencies]
+hex = "0.4.3"
diff --git a/rust/wire/fuzz/.gitignore b/rust/wire/fuzz/.gitignore
new file mode 100644
index 0000000..a092511
--- /dev/null
+++ b/rust/wire/fuzz/.gitignore
@@ -0,0 +1,3 @@
+target
+corpus
+artifacts
diff --git a/rust/wire/fuzz/Cargo.toml b/rust/wire/fuzz/Cargo.toml
new file mode 100644
index 0000000..40c8c32
--- /dev/null
+++ b/rust/wire/fuzz/Cargo.toml
@@ -0,0 +1,28 @@
+[package]
+name = "gk-wire-fuzz"
+version = "0.0.0"
+authors = ["Automatically generated"]
+publish = false
+edition = "2018"
+
+[package.metadata]
+cargo-fuzz = true
+
+[dependencies]
+libfuzzer-sys = "0.4"
+
+[dependencies.gk-wire]
+path = ".."
+
+# Prevent this from interfering with workspaces
+[workspace]
+members = ["."]
+
+[[bin]]
+name = "message"
+path = "fuzz_targets/message.rs"
+test = false
+doc = false
+
+[patch.crates-io]
+hal-wire-derive = { path = "../../../security/hals/derive" }
diff --git a/rust/wire/fuzz/fuzz_targets/message.rs b/rust/wire/fuzz/fuzz_targets/message.rs
new file mode 100644
index 0000000..edd541a
--- /dev/null
+++ b/rust/wire/fuzz/fuzz_targets/message.rs
@@ -0,0 +1,25 @@
+// Copyright 2022, The Android Open Source Project
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
+//! Fuzzer for request message parsing.
+
+#![no_main]
+use hal_wire::AsCborValue;
+use libfuzzer_sys::fuzz_target;
+
+fuzz_target!(|data: &[u8]| {
+    // `data` allegedly holds a CBOR-serialized request message that has arrived from the HAL
+    // service in userspace.  Do we trust it? I don't think so...
+    let _ = gk_wire::PerformOpReq::from_slice(data);
+});
diff --git a/rust/wire/src/lib.rs b/rust/wire/src/lib.rs
new file mode 100644
index 0000000..728391d
--- /dev/null
+++ b/rust/wire/src/lib.rs
@@ -0,0 +1,503 @@
+// Copyright 2025, The Android Open Source Project
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
+//! Types used for communication between HAL and TA.
+//!
+//! The HAL code receives data encoded in the AIDL-defined types, but the
+//! TA code doesn't use the same types (because that would require access to
+//! the AIDL-generated code in the build system for the secure environment).
+//!
+//! So instead use types defined in this crate, which the HAL service can
+//! translate to/from.
+
+// Allow missing docs in this crate as the types here are generally 1:1 with the HAL
+// interface definitions.
+#![allow(missing_docs)]
+#![no_std]
+extern crate alloc;
+
+/// Re-export of crate used for CBOR encoding.
+pub use ciborium as cbor;
+
+use alloc::{vec, vec::Vec};
+use cbor::value::Value;
+use enumn::N;
+use hal_wire::{cbor_type_error, mem, vec_try, AsCborValue, CborError};
+use hal_wire_derive::AsCborValue;
+
+/// Milliseconds since an arbitrary epoch.  This must be monotonically increasing and not repeat
+/// before device reboot, and should also count time passing while the device is suspended.
+///
+/// Encoded as a signed 64-bit integer to match the AIDL type (`long milliSeconds` in
+/// `android.hardware.security.secureclock.Timestamp`) that it corresponds to.
+#[repr(transparent)]
+#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
+pub struct MillisecondsSinceEpoch(pub i64);
+
+impl core::ops::Add<u32> for MillisecondsSinceEpoch {
+    type Output = Self;
+    fn add(self, rhs: u32) -> Self::Output {
+        Self(self.0.saturating_add(rhs as i64))
+    }
+}
+
+/// Error codes defined in the Gatekeeper HAL.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, AsCborValue, N)]
+pub enum ApiStatus {
+    Ok = 0,
+    ReEnroll = 1,
+    GeneralFailure = -1,
+    RetryTimeout = -2,
+    NotImplemented = -3,
+}
+
+/// An Android user ID.
+///
+/// Encoded as a signed 32-bit integer to match the AIDL type (`int uid` in
+/// `android.hardware.gatekeeper.IGatekeeper`) that it corresponds to.
+#[repr(transparent)]
+#[derive(Debug, Clone, Copy, PartialEq, Eq, AsCborValue)]
+pub struct AndroidUserId(pub i32);
+
+/// A secure user ID.
+///
+/// Encoded as a signed 64-bit integer to match the AIDL type (`long userId` in
+/// `android.hardware.security.keymint.HardwareAuthToken`) that it corresponds to.
+#[repr(transparent)]
+#[derive(Debug, Clone, Copy, PartialEq, Eq, AsCborValue)]
+pub struct SecureUserId(pub i64);
+
+/// An opaque (but public) password handle.
+#[repr(transparent)]
+#[derive(Debug, Clone, PartialEq, Eq, AsCborValue)]
+pub struct PasswordHandle(pub Vec<u8>);
+
+impl PasswordHandle {
+    /// Create a `PasswordHandle` from a slice.
+    pub fn from_raw(handle: &[u8]) -> Option<PasswordHandle> {
+        if handle.is_empty() {
+            None
+        } else {
+            Some(PasswordHandle(handle.to_vec()))
+        }
+    }
+}
+
+/// A user password.
+#[repr(transparent)]
+#[derive(AsCborValue)] // deliberately not `Debug`
+pub struct Password(pub Vec<u8>);
+
+impl Password {
+    /// Create a `Password` from a slice.
+    pub fn from_raw(password: &[u8]) -> Option<Password> {
+        if password.is_empty() {
+            None
+        } else {
+            Some(Password(password.to_vec()))
+        }
+    }
+}
+
+/// The type of authentication.  Values can be used as a bitmask.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
+#[repr(i32)]
+pub enum HardwareAuthenticatorType {
+    /// No bits set.
+    None = 0x00,
+    /// Bit indicating password authentication set.
+    Password = 0x01,
+    /// Bit indicating fingerprint (or strong biometric) authentication set.
+    Fingerprint = 0x02,
+    /// `Any` includes all possible bit values.
+    Any = -1,
+}
+
+/// Auth token type representing a successful authentication.
+///
+/// Fields are encoded as signed 64-bit integers to match the AIDL types (`long` in
+/// `android.hardware.security.keymint.HardwareAuthToken`) that they correspond to.
+#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
+pub struct HardwareAuthToken {
+    pub challenge: i64,
+    pub user_id: i64,
+    pub authenticator_id: i64,
+    pub authenticator_type: HardwareAuthenticatorType,
+    pub timestamp: MillisecondsSinceEpoch,
+    pub mac: Vec<u8>,
+}
+
+impl HardwareAuthToken {
+    /// Build the HMAC input for a [`HardwareAuthToken`]
+    pub fn mac_input(&self) -> Result<Vec<u8>, CborError> {
+        const LEN: usize = size_of::<u8>() + // version=0 (BE)
+        size_of::<i64>() + // challenge (Host)
+        size_of::<i64>() + // user_id (Host)
+        size_of::<i64>() + // authenticator_id (Host)
+        size_of::<i32>() + // authenticator_type (BE)
+        size_of::<i64>(); // timestamp (BE)
+        let mut result = mem::vec_try_with_capacity(LEN)?;
+        result.extend_from_slice(&0u8.to_be_bytes()[..]);
+        result.extend_from_slice(&self.challenge.to_ne_bytes()[..]);
+        result.extend_from_slice(&self.user_id.to_ne_bytes()[..]);
+        result.extend_from_slice(&self.authenticator_id.to_ne_bytes()[..]);
+        result.extend_from_slice(&(self.authenticator_type as i32).to_be_bytes()[..]);
+        result.extend_from_slice(&self.timestamp.0.to_be_bytes()[..]);
+        Ok(result)
+    }
+}
+
+// Gatekeeper request/response structures. Contents are equivalent to the input/output parameters of
+// each AIDL entrypoint.
+
+#[derive(Debug, AsCborValue)]
+pub struct DeleteAllUsersRequest {}
+
+#[derive(Debug, AsCborValue)]
+pub struct DeleteAllUsersResponse {}
+
+#[derive(Debug, AsCborValue)]
+pub struct DeleteUserRequest {
+    pub user_id: AndroidUserId,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct DeleteUserResponse {}
+
+#[derive(AsCborValue)]
+pub struct EnrollRequest {
+    pub user_id: AndroidUserId,
+    pub current_handle: Option<PasswordHandle>,
+    pub current_password: Option<Password>,
+    pub new_password: Password,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct EnrollResponse {
+    pub sid: SecureUserId,
+    pub handle: PasswordHandle,
+}
+
+#[derive(AsCborValue)]
+pub struct VerifyRequest {
+    pub user_id: AndroidUserId,
+    pub challenge: i64,
+    pub handle: PasswordHandle,
+    pub password: Password,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct VerifyResponse {
+    pub request_reenroll: bool,
+    pub auth_token: HardwareAuthToken,
+}
+
+// Shared secret request/response structures. Contents are equivalent to the input/output parameters
+// of each AIDL entrypoint.
+
+/// Error codes used implicitly in the shared secret HAL.
+///
+/// Values are a subset of the `ErrorCode` values used in the KeyMint HAL, chosen to behave
+/// the same as the Rust reference implementation of KeyMint.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, AsCborValue, N)]
+pub enum SharedSecretError {
+    Ok = 0,
+    InvalidArgument = -38,
+    MemoryAllocationFailed = -41,
+    Unimplemented = -100,
+    UnknownError = -1000,
+}
+
+#[derive(Debug, Clone, Eq, Hash, PartialEq, Default, AsCborValue)]
+pub struct SharedSecretParameters {
+    pub seed: Vec<u8>,
+    pub nonce: Vec<u8>,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct GetSharedSecretParamsRequest {}
+
+#[derive(Debug, AsCborValue)]
+pub struct GetSharedSecretParamsResponse {
+    pub params: SharedSecretParameters,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct ComputeSharedSecretRequest {
+    pub params: Vec<SharedSecretParameters>,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct ComputeSharedSecretResponse {
+    pub sharing_check: Vec<u8>,
+}
+
+/// Trait that associates an enum value of the specified type with a type.
+///
+/// Values of the `enum` type `T` are used to identify particular message types.
+/// A message type implements `Code<T>` to indicate which `enum` value it is
+/// associated with.
+///
+/// For example, an `enum WhichMsg { Hello, Goodbye }` could be used to distinguish
+/// between `struct HelloMsg` and `struct GoodbyeMsg` instances, in which case the
+/// latter types would both implement `Code<WhichMsg>` with `CODE` values of
+/// `WhichMsg::Hello` and `WhichMsg::Goodbye` respectively.
+pub trait Code<T> {
+    /// The enum value identifying this request/response.
+    const CODE: T;
+    /// Return the enum value associated with the underlying type of this item.
+    fn code(&self) -> T {
+        Self::CODE
+    }
+}
+
+/// Declare a collection of related enums for a code and a pair of types.
+///
+/// An invocation like:
+/// ```ignore
+/// declare_req_rsp_enums! { GatekeerpOperation  => (PerformOpReq, PerformOpRsp) {
+///     Enroll = 0x11 => (EnrollRequest, EnrollResponse),
+///     Verify = 0x12 => (VerifyRequest, VerifyResponse),
+/// } }
+/// ```
+/// will emit three `enum` types all of whose variant names are the same (taken from the leftmost
+/// column), but whose contents are:
+///
+/// - the numeric values (second column)
+///   ```ignore
+///   #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
+///   enum GatekeeperOperation {
+///       Enroll = 0x11,
+///       Verify = 0x12,
+///   }
+///   ```
+///
+/// - the types from the third column:
+///   ```ignore
+///   enum PerformOpReq {
+///       Enroll(EnrollRequest),
+///       Verify(VerifyRequest),
+///   }
+///   ```
+///
+/// - the types from the fourth column:
+///   ```ignore
+///   #[derive(Debug)]
+///   enum PerformOpRsp {
+///       Enroll(EnrollResponse),
+///       Verify(VerifyResponse),
+///   }
+//   ```
+///
+/// Each of these enum types will also get an implementation of [`AsCborValue`]
+macro_rules! declare_req_rsp_enums {
+    {
+        $cenum:ident => ($reqenum:ident, $rspenum:ident) {
+            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
+        }
+    } => {
+        /// Message codes
+        #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, N)]
+        pub enum $cenum {
+            $( $cname = $cvalue, )*
+        }
+
+        impl AsCborValue for $cenum {
+            /// Create an instance of the enum from a [`Value`], checking that the
+            /// value is valid.
+            fn from_cbor_value(value: $crate::Value) ->
+                Result<Self, crate::CborError> {
+                use core::convert::TryInto;
+                // First get the int value as an `i32`.
+                let v: i32 = match value {
+                    $crate::Value::Integer(i) => i.try_into().map_err(|_| {
+                        crate::CborError::InvalidValue
+                    })?,
+                    v => return cbor_type_error(&v, &"int"),
+                };
+                // Now check it is one of the defined enum values.
+                Self::n(v).ok_or(crate::CborError::NonEnumValue(v))
+            }
+            /// Convert the enum value to a [`Value`].
+            fn to_cbor_value(self) -> Result<$crate::Value, crate::CborError> {
+                Ok($crate::Value::Integer((self as i64).into()))
+            }
+        }
+
+        /// All possible request message types.
+        pub enum $reqenum {
+            $( $cname($reqtyp), )*
+        }
+
+        impl $reqenum {
+            /// Return the message code value corresponding to a request variant.
+            pub fn code(&self) -> $cenum {
+                match self {
+                    $( Self::$cname(_) => $cenum::$cname, )*
+                }
+            }
+        }
+
+        /// All possible response message types.
+        pub enum $rspenum {
+            $( $cname($rsptyp), )*
+        }
+
+        impl AsCborValue for $reqenum {
+            fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+                let mut a = match value {
+                    Value::Array(a) => a,
+                    _ => return crate::cbor_type_error(&value, "arr"),
+                };
+                if a.len() != 2 {
+                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
+                }
+                let ret_val = a.remove(1);
+                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
+                match ret_type {
+                    $( $cenum::$cname => Ok(Self::$cname(<$reqtyp>::from_cbor_value(ret_val)?)), )*
+                }
+            }
+            fn to_cbor_value(self) -> Result<Value, CborError> {
+                Ok(Value::Array(match self {
+                    $( Self::$cname(val) => {
+                        vec![
+                            $cenum::$cname.to_cbor_value()?,
+                            val.to_cbor_value()?
+                        ]
+                    }, )*
+                }))
+            }
+        }
+
+        impl AsCborValue for $rspenum {
+            fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+                let mut a = match value {
+                    Value::Array(a) => a,
+                    _ => return cbor_type_error(&value, "arr"),
+                };
+                if a.len() != 2 {
+                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
+                }
+                let ret_val = a.remove(1);
+                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
+                match ret_type {
+                    $( $cenum::$cname => Ok(Self::$cname(<$rsptyp>::from_cbor_value(ret_val)?)), )*
+                }
+            }
+            fn to_cbor_value(self) -> Result<Value, CborError> {
+                Ok(Value::Array(match self {
+                    $( Self::$cname(val) => {
+                        vec![
+                            $cenum::$cname.to_cbor_value()?,
+                            val.to_cbor_value()?
+                        ]
+                    }, )*
+                }))
+            }
+        }
+
+        $(
+            impl Code<$cenum> for $reqtyp {
+                const CODE: $cenum = $cenum::$cname;
+            }
+        )*
+
+        $(
+            impl Code<$cenum> for $rsptyp {
+                const CODE: $cenum = $cenum::$cname;
+            }
+        )*
+    };
+}
+
+// Possible operation requests, as:
+// - an enum value with an explicit numeric value
+// - a request enum which has an operation code associated to each variant
+// - a response enum which has the same operation code associated to each variant.
+declare_req_rsp_enums! { GatekeeperOperation  =>    (PerformOpReq, PerformOpRsp) {
+    // `IGatekeeper` entrypoints
+    DeleteAllUsers = 0x10 => (DeleteAllUsersRequest, DeleteAllUsersResponse),
+    DeleteUser = 0x11 =>     (DeleteUserRequest, DeleteUserResponse),
+    Enroll = 0x20 =>         (EnrollRequest, EnrollResponse),
+    Verify = 0x21 =>         (VerifyRequest, VerifyResponse),
+
+    // `ISharedSecret` entrypoints.
+    GetSharedSecretParams = 0x40 => (GetSharedSecretParamsRequest, GetSharedSecretParamsResponse),
+    ComputeSharedSecret = 0x41   => (ComputeSharedSecretRequest, ComputeSharedSecretResponse),
+} }
+
+/// Outer response message type that allows for failure.
+pub enum PerformOpResponse {
+    /// An OK response with inner response message (equivalent to [`ApiStatus::Ok`]).
+    Ok(PerformOpRsp),
+    /// A response indicating that the request should be retried after the given number of
+    /// milliseconds (equivalent to [`ApiStatus::RetryTimeout`]).
+    RetryTimeout(i32),
+    /// General error response.  The contained error code is context-specific.
+    Err(i32),
+}
+
+impl AsCborValue for PerformOpResponse {
+    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+        let mut arr = match value {
+            Value::Array(a) if a.len() == 2 => a,
+            Value::Array(_) => return Err(CborError::UnexpectedItem("arr not len 2", "arr len 2")),
+            _ => return Err(CborError::UnexpectedItem("non-arr", "arr")),
+        };
+        let value = arr.remove(1);
+        let code = ApiStatus::from_cbor_value(arr.remove(0))?;
+        match code {
+            ApiStatus::Ok => {
+                let rsp = PerformOpRsp::from_cbor_value(value)?;
+                Ok(Self::Ok(rsp))
+            }
+            ApiStatus::RetryTimeout => {
+                let timeout = i32::from_cbor_value(value)?;
+                Ok(Self::RetryTimeout(timeout))
+            }
+            ApiStatus::GeneralFailure => {
+                let rc = i32::from_cbor_value(value)?;
+                Ok(Self::Err(rc))
+            }
+            v => Err(CborError::NonEnumValue(v as i32)),
+        }
+    }
+    fn to_cbor_value(self) -> Result<Value, CborError> {
+        // Re-use API status codes as discriminants.
+        let (code, value) = match self {
+            Self::Ok(rsp) => (Value::Integer((ApiStatus::Ok as i32).into()), rsp.to_cbor_value()?),
+            Self::RetryTimeout(timeout) => (
+                Value::Integer((ApiStatus::RetryTimeout as i32).into()),
+                Value::Integer(timeout.into()),
+            ),
+            Self::Err(rc) => (
+                Value::Integer((ApiStatus::GeneralFailure as i32).into()),
+                Value::Integer(rc.into()),
+            ),
+        };
+        Ok(Value::Array(vec_try![code, value]?))
+    }
+}
+
+impl PerformOpResponse {
+    /// Return the status code associated with the response.
+    pub fn error_code(&self) -> ApiStatus {
+        match self {
+            Self::Ok(_rsp) => ApiStatus::Ok,
+            Self::RetryTimeout(_timeout) => ApiStatus::RetryTimeout,
+            Self::Err(status) => ApiStatus::n(*status).unwrap_or(ApiStatus::GeneralFailure),
+        }
+    }
+}
```

