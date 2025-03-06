```diff
diff --git a/Android.bp b/Android.bp
index 70dabf7..07628e8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -29,3 +29,9 @@ license {
 }
 
 subdirs = ["*"]
+
+dirgroup {
+    name: "trusty_dirgroup_system_secretkeeper",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/Cargo.toml b/Cargo.toml
new file mode 100644
index 0000000..860635a
--- /dev/null
+++ b/Cargo.toml
@@ -0,0 +1,15 @@
+[workspace]
+members = [
+  "comm",
+  "core",
+  "dice_policy",
+]
+resolver = "2"
+
+[patch.crates-io]
+authgraph_core = { path = "../authgraph/core" }
+authgraph_derive = { path = "../authgraph/derive" }
+authgraph_wire = { path = "../authgraph/wire" }
+dice_policy = { path = "dice_policy" }
+secretkeeper_comm = { path = "comm" }
+secretkeeper_core = { path = "core" }
diff --git a/README.md b/README.md
index c436f62..7b1eec5 100644
--- a/README.md
+++ b/README.md
@@ -258,9 +258,9 @@ value of the `secretkeeper_public_key` property of the `/avf` node - exposed to
 userspace at `/proc/device-tree/avf/secretkeeper_public_key`.
 
 When a protected VM is started, AVF populates this property in the VM DT `/avf`
-node from the corresponding property in the `/avf/reference/avf` node in the
-host DT. pvmfw verifies that the value is correct using the VM reference DT that
-is included in the pvmfw [configuration data][pvmfwconfig].
+node by querying `ISecretekeeper::getSecretkeeperIdentity`. pvmfw verifies that
+the value is correct using the VM reference DT that is included in the pvmfw
+[configuration data][pvmfwconfig].
 
 The [Android bootloader][androidbootloader] should request the public key from
 the Secretkeeper implementation at boot time and populate it in both the host
diff --git a/comm/Cargo.toml b/comm/Cargo.toml
new file mode 100644
index 0000000..1aa9292
--- /dev/null
+++ b/comm/Cargo.toml
@@ -0,0 +1,15 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "secretkeeper_comm"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>", "Shikha Panwar <shikhapanwar@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+ciborium = { version = "0.2.2", default-features = false }
+coset = "0.3.7"
+enumn = "0.1.8"
+zeroize = { version = "^1.5.6", features = ["alloc", "zeroize_derive"] }
diff --git a/comm/src/wire.rs b/comm/src/wire.rs
index def58a2..b14c95b 100644
--- a/comm/src/wire.rs
+++ b/comm/src/wire.rs
@@ -36,6 +36,8 @@ pub enum PerformOpReq {
 
     /// A (plaintext) request to delete all data.
     DeleteAll,
+
+    GetSecretkeeperIdentity,
 }
 
 impl PerformOpReq {
@@ -44,6 +46,7 @@ impl PerformOpReq {
             Self::SecretManagement(_) => OpCode::SecretManagement,
             Self::DeleteIds(_) => OpCode::DeleteIds,
             Self::DeleteAll => OpCode::DeleteAll,
+            Self::GetSecretkeeperIdentity => OpCode::GetSecretkeeperIdentity,
         }
     }
 }
@@ -63,6 +66,9 @@ impl AsCborValue for PerformOpReq {
                 ]
             }
             Self::DeleteAll => vec![OpCode::DeleteAll.to_cbor_value()?, Value::Null],
+            Self::GetSecretkeeperIdentity => {
+                vec![OpCode::GetSecretkeeperIdentity.to_cbor_value()?, Value::Null]
+            }
         }))
     }
 
@@ -99,6 +105,12 @@ impl AsCborValue for PerformOpReq {
                 }
                 Self::DeleteAll
             }
+            OpCode::GetSecretkeeperIdentity => {
+                if !val.is_null() {
+                    return cbor_type_error(&val, "nil");
+                }
+                Self::GetSecretkeeperIdentity
+            }
         })
     }
 }
@@ -111,6 +123,7 @@ pub enum OpCode {
     SecretManagement = 0x10,
     DeleteIds = 0x11,
     DeleteAll = 0x12,
+    GetSecretkeeperIdentity = 0x13,
 }
 
 impl AsCborValue for OpCode {
diff --git a/core/Cargo.toml b/core/Cargo.toml
new file mode 100644
index 0000000..90cd589
--- /dev/null
+++ b/core/Cargo.toml
@@ -0,0 +1,21 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "secretkeeper_core"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>", "Shikha Panwar <shikhapanwar@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+authgraph_core = "*"
+authgraph_wire = "*"
+ciborium = { version = "0.2.2", default-features = false }
+coset = "0.3.7"
+dice_policy = "*"
+log = "0.4"
+secretkeeper_comm = "*"
+
+[dev-dependencies]
+hex = "0.4.3"
diff --git a/core/src/ta.rs b/core/src/ta.rs
index de8bc6b..4f4dd20 100644
--- a/core/src/ta.rs
+++ b/core/src/ta.rs
@@ -16,6 +16,7 @@
 
 //! Implementation of a Secretkeeper trusted application (TA).
 
+use crate::alloc::string::ToString;
 use crate::cipher;
 use crate::store::{KeyValueStore, PolicyGatedStorage};
 use alloc::boxed::Box;
@@ -210,6 +211,18 @@ impl SecretkeeperTa {
                 self.delete_ids(ids).map(|_| PerformOpSuccessRsp::Empty)
             }
             PerformOpReq::DeleteAll => self.delete_all().map(|_| PerformOpSuccessRsp::Empty),
+            PerformOpReq::GetSecretkeeperIdentity => {
+                let Identity { cert_chain: CertChain { root_key, .. }, .. } = &self.identity;
+                root_key
+                    .clone()
+                    .get_key()
+                    .to_vec()
+                    .map_err(|e| ApiError {
+                        err_code: AidlErrorCode::InternalError,
+                        msg: e.to_string(),
+                    })
+                    .map(PerformOpSuccessRsp::ProtectedResponse)
+            }
         };
         match result {
             Ok(rsp) => PerformOpResponse::Success(rsp),
diff --git a/dice_policy/Cargo.toml b/dice_policy/Cargo.toml
new file mode 100644
index 0000000..1e03167
--- /dev/null
+++ b/dice_policy/Cargo.toml
@@ -0,0 +1,13 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "dice_policy"
+version = "0.1.0"
+authors = ["Shikha Panwar <shikhapanwar@google.com>", "David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+ciborium = { version = "0.2.2", default-features = false }
+coset = "0.3.7"
diff --git a/hal/Android.bp b/hal/Android.bp
index f72db6b..6782def 100644
--- a/hal/Android.bp
+++ b/hal/Android.bp
@@ -16,14 +16,13 @@ package {
     default_applicable_licenses: ["system_secretkeeper_license"],
 }
 
-rust_library {
-    name: "libsecretkeeper_hal",
+rust_defaults {
+    name: "libsecretkeeper_hal_defaults",
     crate_name: "secretkeeper_hal",
     srcs: ["src/lib.rs"],
     vendor_available: true,
     defaults: [
         "authgraph_use_latest_hal_aidl_rust",
-        "secretkeeper_use_latest_hal_aidl_rust",
     ],
     rustlibs: [
         "libauthgraph_hal",
@@ -33,3 +32,24 @@ rust_library {
         "libsecretkeeper_comm_nostd",
     ],
 }
+
+rust_library {
+    name: "libsecretkeeper_hal",
+    defaults: [
+        "libsecretkeeper_hal_defaults",
+        "secretkeeper_use_latest_hal_aidl_rust",
+    ],
+    features: [
+        "hal_v2",
+    ],
+}
+
+rust_library {
+    name: "libsecretkeeper_hal_v1",
+    defaults: [
+        "libsecretkeeper_hal_defaults",
+    ],
+    rustlibs: [
+        "android.hardware.security.secretkeeper-V1-rust",
+    ],
+}
diff --git a/hal/src/lib.rs b/hal/src/lib.rs
index ec7231f..4b8db9d 100644
--- a/hal/src/lib.rs
+++ b/hal/src/lib.rs
@@ -22,6 +22,8 @@ use android_hardware_security_secretkeeper::aidl::android::hardware::security::s
     },
     SecretId::SecretId as AidlSecretId,
 };
+#[cfg(feature = "hal_v2")]
+use android_hardware_security_secretkeeper::aidl::android::hardware::security::secretkeeper::PublicKey::PublicKey;
 use android_hardware_security_authgraph::aidl::android::hardware::security::authgraph::{
     IAuthGraphKeyExchange::IAuthGraphKeyExchange,
 };
@@ -109,6 +111,21 @@ impl<T: SerializedChannel> ISecretkeeper for SecretkeeperService<T> {
             PerformOpResponse::Failure(err) => Err(service_specific_error(err)),
         }
     }
+
+    #[cfg(feature = "hal_v2")]
+    fn getSecretkeeperIdentity(&self) -> binder::Result<PublicKey> {
+        let wrapper = PerformOpReq::GetSecretkeeperIdentity;
+        let wrapper_data = wrapper.to_vec().map_err(failed_cbor)?;
+        let rsp_data = self.channel.execute(&wrapper_data)?;
+        let rsp = PerformOpResponse::from_slice(&rsp_data).map_err(failed_cbor)?;
+        match rsp {
+            PerformOpResponse::Success(PerformOpSuccessRsp::ProtectedResponse(data)) => {
+                Ok(PublicKey { keyMaterial: data })
+            }
+            PerformOpResponse::Success(_) => Err(unexpected_response_type()),
+            PerformOpResponse::Failure(err) => Err(service_specific_error(err)),
+        }
+    }
 }
 
 /// Emit a failure for a failed CBOR conversion.
```

