```diff
diff --git a/hwcryptohal/common/Android.bp b/hwcryptohal/common/Android.bp
new file mode 100644
index 0000000..bd38afa
--- /dev/null
+++ b/hwcryptohal/common/Android.bp
@@ -0,0 +1,39 @@
+// Copyright (C) 2025 The Android Open-Source Project
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
+
+rust_library {
+    name: "libhwcryptohal_common",
+    crate_name: "hwcryptohal_common",
+    enabled: false,
+    vendor_available: true,
+    srcs: [
+        "android.rs",
+    ],
+    rustlibs: [
+        "libcoset",
+        "libciborium",
+        "android.hardware.security.see.hwcrypto-V1-rust",
+    ],
+    arch: {
+        x86_64: {
+            enabled: true,
+        },
+        arm: {
+            enabled: true,
+        },
+        arm64: {
+            enabled: true,
+        },
+    },
+}
diff --git a/hwcryptohal/common/android.rs b/hwcryptohal/common/android.rs
new file mode 100644
index 0000000..4f44b75
--- /dev/null
+++ b/hwcryptohal/common/android.rs
@@ -0,0 +1,536 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+//! utilities to interact with hwcryptohal from Android
+
+extern crate alloc;
+
+use alloc::collections::btree_set::BTreeSet;
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
+    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
+};
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
+use ciborium::Value;
+use coset::{AsCborValue, CborSerializable, CoseError};
+use android_hardware_security_see_hwcrypto::binder;
+
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode;
+
+/// Macro helper to wrap an AIDL enum and provide conversion implementations for it. It could
+/// potentially be re-written using a procedural derive macro, but using a macro_rules for now for
+/// simplicity.
+/// It provides conversion helpers from u64 and from Ciborium::Integer types and should have the
+/// following form:
+///
+/// aidl_enum_wrapper! {
+///     aidl_name: AidlEnumName,
+///     wrapper_name: NewRustEnumName,
+///     fields: [AIDL_FIELD_1, AIDL_FIELD_2,...]
+/// }
+///
+#[macro_export]
+macro_rules! aidl_enum_wrapper {
+    (aidl_name: $aidl_name:ident, wrapper_name: $wrapper_name:ident, fields: [$($field:ident),+ $(,)*]$(,)?) => {
+        /// newtype wrapping the original type
+        #[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
+        pub struct $wrapper_name(pub $aidl_name);
+
+        impl From<$wrapper_name> for $aidl_name {
+            fn from(value: $wrapper_name) -> Self {
+                value.0
+            }
+        }
+
+        impl TryFrom<$aidl_name> for $wrapper_name {
+            type Error = android_hardware_security_see_hwcrypto::binder::Status;
+
+            fn try_from(value: $aidl_name) -> Result<Self, Self::Error> {
+                let val = $wrapper_name(value);
+                val.check_value()?;
+                Ok(val)
+            }
+        }
+
+        impl TryFrom<u64> for $wrapper_name {
+            type Error = android_hardware_security_see_hwcrypto::binder::Status;
+
+            fn try_from(value: u64) -> Result<Self, Self::Error> {
+                let val = match value {
+                    $(x if x == $aidl_name::$field.0 as u64 =>Ok($aidl_name::$field)),+,
+                    _ => Err(
+                        android_hardware_security_see_hwcrypto::binder::Status::new_service_specific_error(android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode::SERIALIZATION_ERROR, Some(c"unsupported COSE enum label val"))
+                    ),
+                }?;
+                Ok($wrapper_name(val))
+            }
+        }
+
+        impl TryFrom<ciborium::value::Integer> for $wrapper_name {
+            type Error = coset::CoseError;
+
+            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
+                let value: u64 = value.try_into()?;
+                value.try_into().map_err(|_| coset::CoseError::EncodeFailed)
+            }
+        }
+
+        impl From<$wrapper_name> for ciborium::value::Integer {
+            fn from(value: $wrapper_name) -> Self {
+                (value.0.0 as u64).into()
+            }
+        }
+
+        impl $wrapper_name {
+            fn check_value(&self) -> Result<(), android_hardware_security_see_hwcrypto::binder::Status>  {
+                // `TryInto` from a u64 will return an error if the enum value
+                // is not one of the declared ones in `fields`
+                let _: $wrapper_name =  (self.0.0 as u64).try_into()?;
+                Ok(())
+            }
+        }
+    }
+}
+
+/// Macro to create enums that can easily be used as cose labels for serialization
+/// It expects the macro definition to have the following form:
+///
+/// cose_enum_gen! {
+///     enum CoseEnumName {
+///         CoseEnumField1 = value1,
+///         CoseEnumField2 = value2,
+///     }
+/// }
+#[macro_export]
+macro_rules! cose_enum_gen {
+    (enum $name:ident {$($field:ident = $field_val:literal),+ $(,)*}) => {
+        enum $name {
+            $($field = $field_val),+
+        }
+
+        impl TryFrom<i64> for $name {
+            type Error = android_hardware_security_see_hwcrypto::binder::Status;
+
+            fn try_from(value: i64) -> Result<Self, Self::Error> {
+                match value {
+                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
+                    _ => Err(
+                        android_hardware_security_see_hwcrypto::binder::Status::new_service_specific_error(android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode::SERIALIZATION_ERROR, Some(c"unsupported COSE enum label val"))
+                    ),
+                }
+            }
+        }
+
+        impl TryFrom<ciborium::value::Integer> for $name {
+            type Error = coset::CoseError;
+
+            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
+                let value: i64 = value.try_into()?;
+                value.try_into().map_err(|_| coset::CoseError::EncodeFailed)
+            }
+        }
+    }
+}
+aidl_enum_wrapper! {
+    aidl_name: KeyUse,
+    wrapper_name: KeyUseSerializable,
+    fields: [ENCRYPT, DECRYPT, ENCRYPT_DECRYPT, SIGN, DERIVE, WRAP]
+}
+
+aidl_enum_wrapper! {
+    aidl_name: KeyLifetime,
+    wrapper_name: KeyLifetimeSerializable,
+    fields: [EPHEMERAL, HARDWARE, PORTABLE]
+}
+
+aidl_enum_wrapper! {
+    aidl_name: KeyType,
+    wrapper_name: KeyTypeSerializable,
+    fields: [AES_128_CBC_NO_PADDING, AES_128_CBC_PKCS7_PADDING, AES_128_CTR, AES_128_GCM, AES_128_CMAC,
+    AES_256_CBC_NO_PADDING, AES_256_CBC_PKCS7_PADDING, AES_256_CTR, AES_256_GCM, AES_256_CMAC,
+    HMAC_SHA256, HMAC_SHA512,
+    RSA2048_PKCS1_5_SHA256, RSA2048_PSS_SHA256, ECC_NIST_P256_SIGN_NO_PADDING, ECC_NIST_P256_SIGN_SHA256,
+    ECC_NIST_P521_SIGN_NO_PADDING, ECC_NIST_P521_SIGN_SHA512,
+    ECC_ED25519_SIGN]
+}
+
+aidl_enum_wrapper! {
+    aidl_name: KeyPermissions,
+    wrapper_name: KeyPermissionsSerializable,
+    fields: [ALLOW_EPHEMERAL_KEY_WRAPPING, ALLOW_HARDWARE_KEY_WRAPPING, ALLOW_PORTABLE_KEY_WRAPPING]
+}
+
+#[derive(Debug, PartialEq)]
+struct SerializableKeyPolicy {
+    key_lifetime: KeyLifetimeSerializable,
+    key_permissions: BTreeSet<KeyPermissionsSerializable>,
+    key_usage: KeyUseSerializable,
+    key_type: KeyTypeSerializable,
+    management_key: bool,
+}
+
+impl SerializableKeyPolicy {
+    fn new(key_policy: &KeyPolicy) -> Result<Self, binder::Status> {
+        let mut key_permissions = BTreeSet::new();
+        for permission in &key_policy.keyPermissions {
+            key_permissions.insert(KeyPermissionsSerializable(*permission));
+        }
+        Ok(Self {
+            key_lifetime: KeyLifetimeSerializable(key_policy.keyLifetime),
+            key_permissions,
+            key_usage: KeyUseSerializable(key_policy.usage),
+            key_type: KeyTypeSerializable(key_policy.keyType),
+            management_key: key_policy.keyManagementKey,
+        })
+    }
+}
+
+impl TryFrom<&KeyPolicy> for SerializableKeyPolicy {
+    type Error = binder::Status;
+
+    fn try_from(value: &KeyPolicy) -> Result<Self, Self::Error> {
+        Self::new(value)
+    }
+}
+
+impl TryFrom<KeyPolicy> for SerializableKeyPolicy {
+    type Error = binder::Status;
+
+    fn try_from(value: KeyPolicy) -> Result<Self, Self::Error> {
+        (&value).try_into()
+    }
+}
+
+impl TryFrom<&SerializableKeyPolicy> for KeyPolicy {
+    type Error = binder::Status;
+
+    fn try_from(value: &SerializableKeyPolicy) -> Result<Self, Self::Error> {
+        let mut key_permissions = Vec::new();
+        key_permissions.try_reserve(value.key_permissions.len()).map_err(|_| {
+            binder::Status::new_service_specific_error(
+                HalErrorCode::ALLOCATION_ERROR,
+                Some(c"couldn't allocate permissions array"),
+            )
+        })?;
+        // permissions on the returned key policy will be sorted because they are retrieved that
+        // way from the SerializableKeyPolicy
+        for permission in &value.key_permissions {
+            key_permissions.push((*permission).into());
+        }
+        Ok(Self {
+            keyLifetime: value.key_lifetime.into(),
+            keyPermissions: key_permissions,
+            usage: value.key_usage.into(),
+            keyType: value.key_type.into(),
+            keyManagementKey: value.management_key,
+        })
+    }
+}
+
+impl TryFrom<SerializableKeyPolicy> for KeyPolicy {
+    type Error = binder::Status;
+
+    fn try_from(value: SerializableKeyPolicy) -> Result<Self, Self::Error> {
+        (&value).try_into()
+    }
+}
+
+cose_enum_gen! {
+    enum HeaderCoseLabels {
+        KeyUsage = -65701,
+        KeyLifetime = -65702,
+        KeyPermissions = -65703,
+        KeyType = -65704,
+        ManagementKey = -65705,
+    }
+}
+
+impl AsCborValue for SerializableKeyPolicy {
+    fn to_cbor_value(self) -> Result<Value, CoseError> {
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        let key = Value::Integer((HeaderCoseLabels::KeyLifetime as i64).into());
+        let value = Value::Integer(self.key_lifetime.into());
+        cbor_map.try_reserve_exact(5).map_err(|_| CoseError::EncodeFailed)?;
+        cbor_map.push((key, value));
+
+        // Creating key permissions array
+        // We need this array to always be sorted so the created CBOR structure will always match
+        // if the input vector has the same permissions, this is currently provided by
+        // `BTreeSet::into_iter` always returning the elements ordered in ascending order.
+        let mut permissions = Vec::new();
+        permissions.try_reserve(self.key_permissions.len()).map_err(|_| CoseError::EncodeFailed)?;
+        for permission in self.key_permissions.into_iter() {
+            permissions.push(Value::Integer(permission.into()));
+        }
+        let key = Value::Integer((HeaderCoseLabels::KeyPermissions as i64).into());
+        let value = Value::Array(permissions);
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((HeaderCoseLabels::KeyUsage as i64).into());
+        let value = Value::Integer(self.key_usage.into());
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((HeaderCoseLabels::KeyType as i64).into());
+        let value = Value::Integer(self.key_type.into());
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((HeaderCoseLabels::ManagementKey as i64).into());
+        let value = Value::Bool(self.management_key);
+        cbor_map.push((key, value));
+
+        Ok(Value::Map(cbor_map))
+    }
+
+    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
+        let key_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
+
+        let mut key_lifetime: Option<KeyLifetimeSerializable> = None;
+        let mut key_permissions: Option<BTreeSet<KeyPermissionsSerializable>> = None;
+        let mut key_usage: Option<KeyUseSerializable> = None;
+        let mut key_type: Option<KeyTypeSerializable> = None;
+        let mut management_key: Option<bool> = None;
+
+        for (map_key, map_val) in key_policy {
+            let key = map_key.into_integer().map_err(|_| CoseError::ExtraneousData)?;
+            match key.try_into()? {
+                HeaderCoseLabels::KeyLifetime => {
+                    key_lifetime = Some(
+                        map_val
+                            .as_integer()
+                            .ok_or(CoseError::EncodeFailed)?
+                            .try_into()
+                            .map_err(|_| CoseError::EncodeFailed)?,
+                    );
+                }
+                HeaderCoseLabels::KeyPermissions => {
+                    let mut permissions = BTreeSet::new();
+                    for permission in map_val.as_array().ok_or(CoseError::EncodeFailed)? {
+                        permissions.insert(
+                            permission
+                                .as_integer()
+                                .ok_or(CoseError::EncodeFailed)?
+                                .try_into()
+                                .map_err(|_| CoseError::EncodeFailed)?,
+                        );
+                    }
+                    key_permissions = Some(permissions);
+                }
+                HeaderCoseLabels::KeyUsage => {
+                    key_usage = Some(
+                        map_val
+                            .as_integer()
+                            .ok_or(CoseError::EncodeFailed)?
+                            .try_into()
+                            .map_err(|_| CoseError::EncodeFailed)?,
+                    );
+                }
+                HeaderCoseLabels::KeyType => {
+                    key_type = Some(
+                        map_val
+                            .as_integer()
+                            .ok_or(CoseError::EncodeFailed)?
+                            .try_into()
+                            .map_err(|_| CoseError::EncodeFailed)?,
+                    );
+                }
+                HeaderCoseLabels::ManagementKey => {
+                    management_key = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
+                }
+            }
+        }
+
+        let key_lifetime = key_lifetime.ok_or(CoseError::EncodeFailed)?;
+        let key_permissions = key_permissions.ok_or(CoseError::EncodeFailed)?;
+        let key_usage = key_usage.ok_or(CoseError::EncodeFailed)?;
+        let key_type = key_type.ok_or(CoseError::EncodeFailed)?;
+        let management_key = management_key.ok_or(CoseError::EncodeFailed)?;
+
+        Ok(SerializableKeyPolicy {
+            key_lifetime,
+            key_permissions,
+            key_usage,
+            key_type,
+            management_key,
+        })
+    }
+}
+
+/// Mask used for valid AES key uses
+pub static AES_SYMMETRIC_KEY_USES_MASK: i32 = KeyUse::ENCRYPT_DECRYPT.0 | KeyUse::WRAP.0;
+/// Mask used for valid HMAC key uses
+pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0;
+
+/// checks if the values contained on `key_policy` are valid
+pub fn check_key_policy_values(key_policy: &KeyPolicy) -> Result<(), binder::Status> {
+    match key_policy.keyType {
+        KeyType::AES_128_CBC_NO_PADDING
+        | KeyType::AES_128_CBC_PKCS7_PADDING
+        | KeyType::AES_128_CTR
+        | KeyType::AES_128_GCM
+        | KeyType::AES_256_CBC_NO_PADDING
+        | KeyType::AES_256_CBC_PKCS7_PADDING
+        | KeyType::AES_256_CTR
+        | KeyType::AES_256_GCM => {
+            if (key_policy.usage.0 & !AES_SYMMETRIC_KEY_USES_MASK) != 0 {
+                Err(binder::Status::new_service_specific_error(
+                    HalErrorCode::BAD_PARAMETER,
+                    Some(c"usage not supported for AES symmetric key"),
+                ))
+            } else {
+                Ok(())
+            }
+        }
+        KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
+            if (key_policy.usage.0 & !HMAC_KEY_USES_MASK) != 0 {
+                Err(binder::Status::new_service_specific_error(
+                    HalErrorCode::BAD_PARAMETER,
+                    Some(c"usage not supported for HMAC key"),
+                ))
+            } else {
+                Ok(())
+            }
+        }
+        KeyType::AES_128_CMAC
+        | KeyType::AES_256_CMAC
+        | KeyType::RSA2048_PSS_SHA256
+        | KeyType::RSA2048_PKCS1_5_SHA256
+        | KeyType::ECC_NIST_P256_SIGN_NO_PADDING
+        | KeyType::ECC_NIST_P256_SIGN_SHA256
+        | KeyType::ECC_NIST_P521_SIGN_NO_PADDING
+        | KeyType::ECC_NIST_P521_SIGN_SHA512
+        | KeyType::ECC_ED25519_SIGN => Err(binder::Status::new_service_specific_error(
+            HalErrorCode::UNSUPPORTED,
+            Some(c"key type not supported yet"),
+        )),
+        _ => Err(binder::Status::new_service_specific_error(
+            HalErrorCode::BAD_PARAMETER,
+            Some(c"unknown keytype provided"),
+        )),
+    }
+}
+
+/// transforms an AIDL key policy into a CBOR object and returns it as a byte array
+pub fn key_policy_to_cbor(key_policy: &KeyPolicy) -> Result<Vec<u8>, binder::Status> {
+    let serializable_key_policy: SerializableKeyPolicy = key_policy.try_into()?;
+    serializable_key_policy
+        .to_cbor_value()
+        .map_err(|_| {
+            binder::Status::new_service_specific_error(
+                HalErrorCode::SERIALIZATION_ERROR,
+                Some(c"couldn't transform to cbor"),
+            )
+        })?
+        .to_vec()
+        .map_err(|_| {
+            binder::Status::new_service_specific_error(
+                HalErrorCode::SERIALIZATION_ERROR,
+                Some(c"couldn't serialize policy"),
+            )
+        })
+}
+
+/// transforms a CBOR object passed as a byte slice into an AIDL key policy
+pub fn cbor_to_key_policy(cbor_key_policy: &[u8]) -> Result<KeyPolicy, binder::Status> {
+    let policy = SerializableKeyPolicy::from_cbor_value(
+        Value::from_slice(cbor_key_policy).map_err(|_| {
+            binder::Status::new_service_specific_error(
+                HalErrorCode::SERIALIZATION_ERROR,
+                Some(c"couldn't serialize policy"),
+            )
+        })?,
+    )
+    .map_err(|_| {
+        binder::Status::new_service_specific_error(
+            HalErrorCode::SERIALIZATION_ERROR,
+            Some(c"couldn't serialize policy"),
+        )
+    })?
+    .try_into()?;
+    check_key_policy_values(&policy)?;
+    Ok(policy)
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use test::{expect, expect_eq};
+
+    #[test]
+    fn serialize_policy() {
+        let policy = KeyPolicy {
+            usage: KeyUse::ENCRYPT,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_GCM,
+            keyManagementKey: false,
+        };
+
+        let serialize_result = key_policy_to_cbor(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
+        expect!(deserialization.is_ok(), "couldn't deserialize policy");
+        let deserialized_policy = deserialization.unwrap();
+        let policy: SerializableKeyPolicy = policy.try_into().unwrap();
+        let deserialized_policy: SerializableKeyPolicy = (&deserialized_policy).try_into().unwrap();
+        expect_eq!(policy, deserialized_policy, "policies should match");
+    }
+
+    #[test]
+    fn bad_policies() {
+        let mut policy = KeyPolicy {
+            usage: KeyUse::SIGN,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_GCM,
+            keyManagementKey: false,
+        };
+        let serialize_result = key_policy_to_cbor(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.usage = KeyUse::DERIVE;
+        let serialize_result = key_policy_to_cbor(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.keyType = KeyType::HMAC_SHA256;
+        policy.usage = KeyUse::ENCRYPT;
+        let serialize_result = key_policy_to_cbor(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.usage = KeyUse::DECRYPT;
+        let serialize_result = key_policy_to_cbor(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.keyType = KeyType::HMAC_SHA512;
+        policy.usage = KeyUse::ENCRYPT_DECRYPT;
+        let serialize_result = key_policy_to_cbor(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+    }
+}
diff --git a/hwcryptohal/common/cose.rs b/hwcryptohal/common/cose.rs
deleted file mode 100644
index ef49331..0000000
--- a/hwcryptohal/common/cose.rs
+++ /dev/null
@@ -1,127 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-//! COSE/CBOR helper functions and macros
-
-/// Macro helper to wrap an AIDL enum and provide conversion implementations for it. It could
-/// potentially be re-written using a procedural derive macro, but using a macro_rules for now for
-/// simplicity.
-/// It provides conversion helpers from u64 and from Ciborium::Integer types and should have the
-/// following form:
-///
-/// aidl_enum_wrapper! {
-///     aidl_name: AidlEnumName,
-///     wrapper_name: NewRustEnumName,
-///     fields: [AIDL_FIELD_1, AIDL_FIELD_2,...]
-/// }
-///
-#[macro_export]
-macro_rules! aidl_enum_wrapper {
-    (aidl_name: $aidl_name:ident, wrapper_name: $wrapper_name:ident, fields: [$($field:ident),+ $(,)*]$(,)?) => {
-        #[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
-        pub struct $wrapper_name(pub $aidl_name);
-
-        impl From<$wrapper_name> for $aidl_name {
-            fn from(value: $wrapper_name) -> Self {
-                value.0
-            }
-        }
-
-        impl TryFrom<$aidl_name> for $wrapper_name {
-            type Error = $crate::err::HwCryptoError;
-
-            fn try_from(value: $aidl_name) -> Result<Self, Self::Error> {
-                let val = $wrapper_name(value);
-                val.check_value()?;
-                Ok(val)
-            }
-        }
-
-        impl TryFrom<u64> for $wrapper_name {
-            type Error = $crate::err::HwCryptoError;
-
-            fn try_from(value: u64) -> Result<Self, Self::Error> {
-                let val = match value {
-                    $(x if x == $aidl_name::$field.0 as u64 =>Ok($aidl_name::$field)),+,
-                    _ => Err($crate::hwcrypto_err!(SERIALIZATION_ERROR, "unsupported enum val {}", value)),
-                }?;
-                Ok($wrapper_name(val))
-            }
-        }
-
-        impl TryFrom<ciborium::value::Integer> for $wrapper_name {
-            type Error = coset::CoseError;
-
-            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
-                let value: u64 = value.try_into()?;
-                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
-            }
-        }
-
-        impl From<$wrapper_name> for ciborium::value::Integer {
-            fn from(value: $wrapper_name) -> Self {
-                (value.0.0 as u64).into()
-            }
-        }
-
-        impl $wrapper_name {
-            fn check_value(&self) -> Result<(), $crate::err::HwCryptoError>  {
-                // `TryInto` from a u64 will return an error if the enum value
-                // is not one of the declared ones in `fields`
-                let _: $wrapper_name =  (self.0.0 as u64).try_into()?;
-                Ok(())
-            }
-        }
-    }
-}
-
-/// Macro to create enums that can easily be used as cose labels for serialization
-/// It expects the macro definition to have the following form:
-///
-/// cose_enum_gen! {
-///     enum CoseEnumName {
-///         CoseEnumField1 = value1,
-///         CoseEnumField2 = value2,
-///     }
-/// }
-#[macro_export]
-macro_rules! cose_enum_gen {
-    (enum $name:ident {$($field:ident = $field_val:literal),+ $(,)*}) => {
-        enum $name {
-            $($field = $field_val),+
-        }
-
-        impl TryFrom<i64> for $name {
-            type Error = $crate::err::HwCryptoError;
-
-            fn try_from(value: i64) -> Result<Self, Self::Error> {
-                match value {
-                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
-                    _ => Err($crate::hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE enum label val {}", value)),
-                }
-            }
-        }
-
-        impl TryFrom<ciborium::value::Integer> for $name {
-            type Error = coset::CoseError;
-
-            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
-                let value: i64 = value.try_into()?;
-                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
-            }
-        }
-    }
-}
diff --git a/hwcryptohal/common/lib.rs b/hwcryptohal/common/lib.rs
index a8aa017..3ddc3c5 100644
--- a/hwcryptohal/common/lib.rs
+++ b/hwcryptohal/common/lib.rs
@@ -16,9 +16,10 @@
 
 //! Library implementing common client and server HWCrypto functionality.
 
-pub mod cose;
+mod android;
 pub mod err;
 pub mod policy;
+pub use android::{AES_SYMMETRIC_KEY_USES_MASK, HMAC_KEY_USES_MASK};
 
 // Trusty Rust unittests use a sligthly different setup and environment than
 // normal Rust unittests. The next call adds the necessary variables and code to be
diff --git a/hwcryptohal/common/policy.rs b/hwcryptohal/common/policy.rs
index 8692972..4858436 100644
--- a/hwcryptohal/common/policy.rs
+++ b/hwcryptohal/common/policy.rs
@@ -16,369 +16,23 @@
 
 //! KeyPolicy serialization facilities
 
-use alloc::collections::btree_set::BTreeSet;
-use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
-    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
-};
+use crate::android;
+use crate::{hwcrypto_err, err::HwCryptoError};
 use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
-use ciborium::Value;
-use coset::{AsCborValue, CborSerializable, CoseError};
 
-use crate::{aidl_enum_wrapper, cose_enum_gen};
-use crate::{err::HwCryptoError, hwcrypto_err};
-
-aidl_enum_wrapper! {
-    aidl_name: KeyUse,
-    wrapper_name: KeyUseSerializable,
-    fields: [ENCRYPT, DECRYPT, ENCRYPT_DECRYPT, SIGN, DERIVE, WRAP]
-}
-
-aidl_enum_wrapper! {
-    aidl_name: KeyLifetime,
-    wrapper_name: KeyLifetimeSerializable,
-    fields: [EPHEMERAL, HARDWARE, PORTABLE]
-}
-
-aidl_enum_wrapper! {
-    aidl_name: KeyType,
-    wrapper_name: KeyTypeSerializable,
-    fields: [AES_128_CBC_NO_PADDING, AES_128_CBC_PKCS7_PADDING, AES_128_CTR, AES_128_GCM, AES_128_CMAC,
-    AES_256_CBC_NO_PADDING, AES_256_CBC_PKCS7_PADDING, AES_256_CTR, AES_256_GCM, AES_256_CMAC,
-    HMAC_SHA256, HMAC_SHA512,
-    RSA2048_PKCS1_5_SHA256, RSA2048_PSS_SHA256, ECC_NIST_P256_SIGN_NO_PADDING, ECC_NIST_P256_SIGN_SHA256,
-    ECC_NIST_P521_SIGN_NO_PADDING, ECC_NIST_P521_SIGN_SHA512,
-    ECC_ED25519_SIGN]
-}
-
-aidl_enum_wrapper! {
-    aidl_name: KeyPermissions,
-    wrapper_name: KeyPermissionsSerializable,
-    fields: [ALLOW_EPHEMERAL_KEY_WRAPPING, ALLOW_HARDWARE_KEY_WRAPPING, ALLOW_PORTABLE_KEY_WRAPPING]
-}
-
-#[derive(Debug, PartialEq)]
-struct SerializableKeyPolicy {
-    key_lifetime: KeyLifetimeSerializable,
-    key_permissions: BTreeSet<KeyPermissionsSerializable>,
-    key_usage: KeyUseSerializable,
-    key_type: KeyTypeSerializable,
-    management_key: bool,
-}
-
-impl SerializableKeyPolicy {
-    fn new(key_policy: &KeyPolicy) -> Result<Self, crate::err::HwCryptoError> {
-        let mut key_permissions = BTreeSet::new();
-        for permission in &key_policy.keyPermissions {
-            key_permissions.insert(KeyPermissionsSerializable(*permission));
-        }
-        Ok(Self {
-            key_lifetime: KeyLifetimeSerializable(key_policy.keyLifetime),
-            key_permissions,
-            key_usage: KeyUseSerializable(key_policy.usage),
-            key_type: KeyTypeSerializable(key_policy.keyType),
-            management_key: key_policy.keyManagementKey,
-        })
-    }
-}
-
-impl TryFrom<&KeyPolicy> for SerializableKeyPolicy {
-    type Error = crate::err::HwCryptoError;
-
-    fn try_from(value: &KeyPolicy) -> Result<Self, Self::Error> {
-        Self::new(value)
-    }
-}
-
-impl TryFrom<KeyPolicy> for SerializableKeyPolicy {
-    type Error = crate::err::HwCryptoError;
-
-    fn try_from(value: KeyPolicy) -> Result<Self, Self::Error> {
-        (&value).try_into()
-    }
-}
-
-impl TryFrom<&SerializableKeyPolicy> for KeyPolicy {
-    type Error = crate::err::HwCryptoError;
-
-    fn try_from(value: &SerializableKeyPolicy) -> Result<Self, Self::Error> {
-        let mut key_permissions = Vec::new();
-        key_permissions.try_reserve(value.key_permissions.len())?;
-        // permissions on the returned key policy will be sorted because they are retrieved that
-        // way from the SerializableKeyPolicy
-        for permission in &value.key_permissions {
-            key_permissions.push((*permission).into());
-        }
-        Ok(Self {
-            keyLifetime: value.key_lifetime.into(),
-            keyPermissions: key_permissions,
-            usage: value.key_usage.into(),
-            keyType: value.key_type.into(),
-            keyManagementKey: value.management_key,
-        })
-    }
-}
-
-impl TryFrom<SerializableKeyPolicy> for KeyPolicy {
-    type Error = crate::err::HwCryptoError;
-
-    fn try_from(value: SerializableKeyPolicy) -> Result<Self, Self::Error> {
-        (&value).try_into()
-    }
-}
-
-cose_enum_gen! {
-    enum HeaderCoseLabels {
-        KeyUsage = -65701,
-        KeyLifetime = -65702,
-        KeyPermissions = -65703,
-        KeyType = -65704,
-        ManagementKey = -65705,
-    }
-}
-
-impl AsCborValue for SerializableKeyPolicy {
-    fn to_cbor_value(self) -> Result<Value, CoseError> {
-        let mut cbor_map = Vec::<(Value, Value)>::new();
-        let key = Value::Integer((HeaderCoseLabels::KeyLifetime as i64).into());
-        let value = Value::Integer(self.key_lifetime.into());
-        cbor_map.try_reserve_exact(5).map_err(|_| CoseError::EncodeFailed)?;
-        cbor_map.push((key, value));
-
-        // Creating key permissions array
-        // We need this array to always be sorted so the created CBOR structure will always match
-        // if the input vector has the same permissions, this is currently provided by
-        // `BTreeSet::into_iter` always returning the elements ordered in ascending order.
-        let mut permissions = Vec::new();
-        permissions.try_reserve(self.key_permissions.len()).map_err(|_| CoseError::EncodeFailed)?;
-        for permission in self.key_permissions.into_iter() {
-            permissions.push(Value::Integer(permission.into()));
-        }
-        let key = Value::Integer((HeaderCoseLabels::KeyPermissions as i64).into());
-        let value = Value::Array(permissions);
-        cbor_map.push((key, value));
-
-        let key = Value::Integer((HeaderCoseLabels::KeyUsage as i64).into());
-        let value = Value::Integer(self.key_usage.into());
-        cbor_map.push((key, value));
-
-        let key = Value::Integer((HeaderCoseLabels::KeyType as i64).into());
-        let value = Value::Integer(self.key_type.into());
-        cbor_map.push((key, value));
-
-        let key = Value::Integer((HeaderCoseLabels::ManagementKey as i64).into());
-        let value = Value::Bool(self.management_key.into());
-        cbor_map.push((key, value));
-
-        Ok(Value::Map(cbor_map))
-    }
-
-    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
-        let key_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
-
-        let mut key_lifetime: Option<KeyLifetimeSerializable> = None;
-        let mut key_permissions: Option<BTreeSet<KeyPermissionsSerializable>> = None;
-        let mut key_usage: Option<KeyUseSerializable> = None;
-        let mut key_type: Option<KeyTypeSerializable> = None;
-        let mut management_key: Option<bool> = None;
-
-        for (map_key, map_val) in key_policy {
-            let key = map_key.into_integer().map_err(|_| CoseError::ExtraneousData)?;
-            match key.try_into()? {
-                HeaderCoseLabels::KeyLifetime => {
-                    key_lifetime = Some(
-                        map_val
-                            .as_integer()
-                            .ok_or(CoseError::EncodeFailed)?
-                            .try_into()
-                            .map_err(|_| CoseError::EncodeFailed)?,
-                    );
-                }
-                HeaderCoseLabels::KeyPermissions => {
-                    let mut permissions = BTreeSet::new();
-                    for permission in map_val.as_array().ok_or(CoseError::EncodeFailed)? {
-                        permissions.insert(
-                            permission
-                                .as_integer()
-                                .ok_or(CoseError::EncodeFailed)?
-                                .try_into()
-                                .map_err(|_| CoseError::EncodeFailed)?,
-                        );
-                    }
-                    key_permissions = Some(permissions);
-                }
-                HeaderCoseLabels::KeyUsage => {
-                    key_usage = Some(
-                        map_val
-                            .as_integer()
-                            .ok_or(CoseError::EncodeFailed)?
-                            .try_into()
-                            .map_err(|_| CoseError::EncodeFailed)?,
-                    );
-                }
-                HeaderCoseLabels::KeyType => {
-                    key_type = Some(
-                        map_val
-                            .as_integer()
-                            .ok_or(CoseError::EncodeFailed)?
-                            .try_into()
-                            .map_err(|_| CoseError::EncodeFailed)?,
-                    );
-                }
-                HeaderCoseLabels::ManagementKey => {
-                    management_key = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
-                }
-            }
-        }
-
-        let key_lifetime = key_lifetime.ok_or(CoseError::EncodeFailed)?;
-        let key_permissions = key_permissions.ok_or(CoseError::EncodeFailed)?;
-        let key_usage = key_usage.ok_or(CoseError::EncodeFailed)?;
-        let key_type = key_type.ok_or(CoseError::EncodeFailed)?;
-        let management_key = management_key.ok_or(CoseError::EncodeFailed)?;
-
-        Ok(SerializableKeyPolicy {
-            key_lifetime,
-            key_permissions,
-            key_usage,
-            key_type,
-            management_key,
-        })
-    }
-}
-
-pub static AES_SYMMETRIC_KEY_USES_MASK: i32 = KeyUse::ENCRYPT_DECRYPT.0 | KeyUse::WRAP.0;
-pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0;
+pub use crate::android::{KeyLifetimeSerializable, KeyTypeSerializable, KeyUseSerializable};
 
 pub fn check_key_policy(key_policy: &KeyPolicy) -> Result<(), HwCryptoError> {
-    match key_policy.keyType {
-        KeyType::AES_128_CBC_NO_PADDING
-        | KeyType::AES_128_CBC_PKCS7_PADDING
-        | KeyType::AES_128_CTR
-        | KeyType::AES_128_GCM
-        | KeyType::AES_256_CBC_NO_PADDING
-        | KeyType::AES_256_CBC_PKCS7_PADDING
-        | KeyType::AES_256_CTR
-        | KeyType::AES_256_GCM => {
-            if (key_policy.usage.0 & !AES_SYMMETRIC_KEY_USES_MASK) != 0 {
-                Err(hwcrypto_err!(
-                    BAD_PARAMETER,
-                    "usage not supported for AES symmetric key: {}",
-                    key_policy.usage.0
-                ))
-            } else {
-                Ok(())
-            }
-        }
-        KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
-            if (key_policy.usage.0 & !HMAC_KEY_USES_MASK) != 0 {
-                Err(hwcrypto_err!(
-                    BAD_PARAMETER,
-                    "usage not supported for HMAC key: {}",
-                    key_policy.usage.0
-                ))
-            } else {
-                Ok(())
-            }
-        }
-        KeyType::AES_128_CMAC
-        | KeyType::AES_256_CMAC
-        | KeyType::RSA2048_PSS_SHA256
-        | KeyType::RSA2048_PKCS1_5_SHA256
-        | KeyType::ECC_NIST_P256_SIGN_NO_PADDING
-        | KeyType::ECC_NIST_P256_SIGN_SHA256
-        | KeyType::ECC_NIST_P521_SIGN_NO_PADDING
-        | KeyType::ECC_NIST_P521_SIGN_SHA512
-        | KeyType::ECC_ED25519_SIGN => {
-            Err(hwcrypto_err!(UNSUPPORTED, "key type not supported yet"))
-        }
-        _ => Err(hwcrypto_err!(BAD_PARAMETER, "unknown keytype provided {:?}", key_policy.keyType)),
-    }
+    android::check_key_policy_values(key_policy)
+        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "issue found when checking policy {:?}", e))
 }
 
 pub fn cbor_serialize_key_policy(key_policy: &KeyPolicy) -> Result<Vec<u8>, HwCryptoError> {
-    let serializable_key_policy: SerializableKeyPolicy = key_policy.try_into()?;
-    serializable_key_policy
-        .to_cbor_value()?
-        .to_vec()
+    android::key_policy_to_cbor(key_policy)
         .map_err(|_| hwcrypto_err!(SERIALIZATION_ERROR, "couldn't serialize policy"))
 }
 
 pub fn cbor_policy_to_aidl(cbor_key_policy: &[u8]) -> Result<KeyPolicy, HwCryptoError> {
-    let policy =
-        SerializableKeyPolicy::from_cbor_value(Value::from_slice(cbor_key_policy)?)?.try_into()?;
-    check_key_policy(&policy)?;
-    Ok(policy)
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use test::{expect, expect_eq};
-
-    #[test]
-    fn serialize_policy() {
-        let policy = KeyPolicy {
-            usage: KeyUse::ENCRYPT,
-            keyLifetime: KeyLifetime::EPHEMERAL,
-            keyPermissions: Vec::new(),
-            keyType: KeyType::AES_256_GCM,
-            keyManagementKey: false,
-        };
-
-        let serialize_result = cbor_serialize_key_policy(&policy);
-        expect!(serialize_result.is_ok(), "couldn't serialize policy");
-        let serialized_policy = serialize_result.unwrap();
-        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
-        expect!(deserialization.is_ok(), "couldn't deserialize policy");
-        let deserialized_policy = deserialization.unwrap();
-        let policy: SerializableKeyPolicy = policy.try_into().unwrap();
-        let deserialized_policy: SerializableKeyPolicy = (&deserialized_policy).try_into().unwrap();
-        expect_eq!(policy, deserialized_policy, "policies should match");
-    }
-
-    #[test]
-    fn bad_policies() {
-        let mut policy = KeyPolicy {
-            usage: KeyUse::SIGN,
-            keyLifetime: KeyLifetime::EPHEMERAL,
-            keyPermissions: Vec::new(),
-            keyType: KeyType::AES_256_GCM,
-            keyManagementKey: false,
-        };
-        let serialize_result = cbor_serialize_key_policy(&policy);
-        expect!(serialize_result.is_ok(), "couldn't serialize policy");
-        let serialized_policy = serialize_result.unwrap();
-        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
-        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
-
-        policy.usage = KeyUse::DERIVE;
-        let serialize_result = cbor_serialize_key_policy(&policy);
-        expect!(serialize_result.is_ok(), "couldn't serialize policy");
-        let serialized_policy = serialize_result.unwrap();
-        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
-        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
-
-        policy.keyType = KeyType::HMAC_SHA256;
-        policy.usage = KeyUse::ENCRYPT;
-        let serialize_result = cbor_serialize_key_policy(&policy);
-        expect!(serialize_result.is_ok(), "couldn't serialize policy");
-        let serialized_policy = serialize_result.unwrap();
-        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
-        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
-
-        policy.usage = KeyUse::DECRYPT;
-        let serialize_result = cbor_serialize_key_policy(&policy);
-        expect!(serialize_result.is_ok(), "couldn't serialize policy");
-        let serialized_policy = serialize_result.unwrap();
-        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
-        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
-
-        policy.keyType = KeyType::HMAC_SHA512;
-        policy.usage = KeyUse::ENCRYPT_DECRYPT;
-        let serialize_result = cbor_serialize_key_policy(&policy);
-        expect!(serialize_result.is_ok(), "couldn't serialize policy");
-        let serialized_policy = serialize_result.unwrap();
-        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
-        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
-    }
+    android::cbor_to_key_policy(cbor_key_policy)
+        .map_err(|_| hwcrypto_err!(SERIALIZATION_ERROR, "couldn't deserialize policy"))
 }
diff --git a/hwcryptohal/server/cmd_processing.rs b/hwcryptohal/server/cmd_processing.rs
index 93c73e1..8ed3e1f 100644
--- a/hwcryptohal/server/cmd_processing.rs
+++ b/hwcryptohal/server/cmd_processing.rs
@@ -17,7 +17,7 @@
 //! Module providing an implementation of a cryptographic command processor.
 
 use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
-    MemoryBufferReference::MemoryBufferReference, OperationData::OperationData,
+    MemoryBufferReference::MemoryBufferReference, OperationData::OperationData, Void::Void,
 };
 use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
     CryptoOperation::CryptoOperation,
@@ -632,6 +632,9 @@ impl CmdProcessorContext {
                 if !crypto_operation.is_active() {
                     return Err(hwcrypto_err!(BAD_PARAMETER, "operation is not active"));
                 }
+                if !crypto_operation.is_valid() {
+                    return Err(hwcrypto_err!(BAD_PARAMETER, "operation is no longer valid."));
+                }
                 Ok(&mut **crypto_operation)
             })?;
         let req_output_size = crypto_operation.get_operation_req_size(input.as_ref(), is_finish)?;
@@ -738,7 +741,14 @@ impl CmdProcessorContext {
                     }
                     CryptoOperation::DestroyContext(_) => self.destroy_step(&mut curr_output)?,
                     CryptoOperation::SetMemoryBuffer(step_data) => {
-                        self.set_memory_buffer_step(&step_data, &mut curr_output)?
+                        let op_result = self.set_memory_buffer_step(&step_data, &mut curr_output);
+                        // Workaround, currently trying to return with a operation step that includes
+                        // file descriptors fails on the trusty binder sw stack. We are changing
+                        // changing the operation type instead of deleting it so the client do not
+                        // need to recalculate the operations vector indexes to retrieve other data
+                        // (b/403522783).
+                        *current_step = CryptoOperation::DestroyContext(Some(Void {}));
+                        op_result?
                     }
                     CryptoOperation::SetOperationParameters(step_data) => {
                         self.current_state = CmdProcessorState::RunningOperation;
@@ -1021,18 +1031,17 @@ mod tests {
 
         cmd_list.push(CryptoOperation::SetMemoryBuffer(mem_buffer_parameters));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        cmd_list.remove(0);
         expect!(process_result.is_ok(), "Couldn't process SetMemoryBuffer command");
         let mem_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
         cmd_list
             .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));
 
-        let mut cmd_processor = CmdProcessorContext::new();
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process valid memory reference");
 
         let mem_ref = MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 1 };
-        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
-        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[0] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(
             process_result.is_err(),
@@ -1040,8 +1049,7 @@ mod tests {
         );
 
         let mem_ref = MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 0 };
-        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
-        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[0] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(
             process_result.is_err(),
@@ -1049,15 +1057,13 @@ mod tests {
         );
 
         let mem_ref = MemoryBufferReference { startOffset: 3, sizeBytes: 0 };
-        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
-        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[0] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_err(), "Shouldn't be able to process 0 size references");
 
         let mem_ref =
             MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 1 };
-        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
-        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[0] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(
             process_result.is_ok(),
@@ -1067,8 +1073,7 @@ mod tests {
 
         let mem_ref =
             MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 2 };
-        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
-        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[0] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(
             process_result.is_err(),
@@ -1220,6 +1225,7 @@ mod tests {
         expect!(process_result.is_ok(), "Couldn't process command");
         let mut read_slice_val = vec![55; 9];
         let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        cmd_list.remove(0);
         read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(
             &read_slice_val[..],
@@ -1228,7 +1234,6 @@ mod tests {
         );
 
         cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
-        let mut cmd_processor = CmdProcessorContext::new();
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(
             process_result.is_err(),
@@ -1270,23 +1275,23 @@ mod tests {
             output_reference,
         )));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        cmd_list.remove(1);
+        cmd_list.remove(0);
         expect!(process_result.is_err(), "shouldn't be able to add an output outside of range");
         let output_reference =
             MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
-        cmd_list[2] =
+        cmd_list[0] =
             CryptoOperation::DataOutput(OperationData::MemoryBufferReference(output_reference));
         let input_reference =
             MemoryBufferReference { startOffset: 0, sizeBytes: (alloc_size + 4) as i32 };
         cmd_list
             .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
-        let mut cmd_processor = CmdProcessorContext::new();
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_err(), "shouldn't be able to add an input ref outside of range");
         let input_reference =
             MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
-        cmd_list[3] =
+        cmd_list[1] =
             CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference));
-        let mut cmd_processor = CmdProcessorContext::new();
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "operation should have succeeded");
     }
@@ -1319,7 +1324,8 @@ mod tests {
         let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
         read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(&read_slice_val[..], &[0, 0, 0, 0, 0, 0, 0, 0, 0], "initial values where not 0");
-        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.remove(1);
+        cmd_list.remove(0);
         let output_reference =
             MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
         cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
@@ -1332,7 +1338,6 @@ mod tests {
         read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(&read_slice_val[..], &[1, 2, 3, 0, 0, 0, 0, 0, 0], "initial values where not 0");
         cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
-        let mut cmd_processor = CmdProcessorContext::new();
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
         let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
@@ -1341,7 +1346,6 @@ mod tests {
         let input_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
         cmd_list
             .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
-        let mut cmd_processor = CmdProcessorContext::new();
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
         cmd_list.clear();
@@ -1388,17 +1392,15 @@ mod tests {
         cmd_list
             .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
         let input_reference = MemoryBufferReference { startOffset: 3, sizeBytes: 3 as i32 };
-        //cmd_list
-        //    .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
         let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
             unreachable!("should not happen beucase we created the cmd list on the test");
         };
         expect_eq!(output, &[2, 4, 8], "values were not copied correctly");
-        let mut cmd_processor = CmdProcessorContext::new();
         cmd_list[2] =
             CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference));
+        cmd_list.remove(1);
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process second copy command");
         let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
@@ -2002,4 +2004,93 @@ mod tests {
             "couldn't retrieve original message"
         );
     }
+
+    #[test]
+    fn aes_simple_cbcs_test_non_block_multiple() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_128_CBC_NO_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 0,
+        }));
+        let input_data =
+            OperationData::DataBuffer("encryption data.0123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data =
+            OperationData::DataBuffer("fedcba98765432100123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data = OperationData::DataBuffer("unencrypted".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        let clear_encrypted_msg = String::from_utf8(
+            encrypted_data[encrypted_data.len() - "unencrypted".len()..].to_vec(),
+        )
+        .expect("couldn't decode message");
+        expect_eq!(clear_encrypted_msg, "unencrypted");
+
+        // Decrypting
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::DECRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 0,
+        }));
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode received message");
+        expect_eq!(
+            decrypted_msg,
+            "encryption data.0123456789abcdeffedcba9876543210\
+            0123456789abcdefunencrypted",
+            "couldn't retrieve original message"
+        );
+    }
 }
diff --git a/hwcryptohal/server/crypto_operation.rs b/hwcryptohal/server/crypto_operation.rs
index 8e2a61d..e6ca562 100644
--- a/hwcryptohal/server/crypto_operation.rs
+++ b/hwcryptohal/server/crypto_operation.rs
@@ -91,6 +91,8 @@ pub(crate) trait ICryptographicOperation: Send {
 
     fn is_active(&self) -> bool;
 
+    fn is_valid(&self) -> bool;
+
     #[allow(dead_code)]
     fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
         Err(hwcrypto_err!(
@@ -122,6 +124,8 @@ trait IBaseCryptoOperation: Send {
 
     fn is_active(&self) -> bool;
 
+    fn is_valid(&self) -> bool;
+
     fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
         Err(hwcrypto_err!(
             BAD_PARAMETER,
@@ -169,6 +173,10 @@ impl<T: IBaseCryptoOperation> ICryptographicOperation for T {
         self.is_active()
     }
 
+    fn is_valid(&self) -> bool {
+        self.is_valid()
+    }
+
     fn update_aad(&mut self, input: &DataToProcess) -> Result<(), HwCryptoError> {
         self.update_aad(input)
     }
@@ -221,6 +229,7 @@ impl TempBuffer {
 }
 
 pub(crate) struct HmacOperation {
+    opaque_key: OpaqueKey,
     accumulating_op: Option<Box<dyn crypto::AccumulatingOperation>>,
 }
 
@@ -235,12 +244,12 @@ impl HmacOperation {
         let digest = helpers::aidl_to_rust_digest(&opaque_key.get_key_type())?;
         let hmac = crypto_provider::HmacImpl;
         let accumulating_op = match opaque_key.key_material {
-            KeyMaterial::Hmac(key) => hmac.begin(key.clone(), digest).map_err(|e| {
+            KeyMaterial::Hmac(ref key) => hmac.begin(key.clone(), digest).map_err(|e| {
                 hwcrypto_err!(GENERIC_ERROR, "couldn't begin hmac operation: {:?}", e)
             }),
             _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
         }?;
-        Ok(HmacOperation { accumulating_op: Some(accumulating_op) })
+        Ok(HmacOperation { opaque_key, accumulating_op: Some(accumulating_op) })
     }
 
     fn check_parameters(
@@ -250,6 +259,7 @@ impl HmacOperation {
         if !opaque_key.key_usage_supported(KeyUse::SIGN) {
             return Err(hwcrypto_err!(BAD_PARAMETER, "Provided key cannot be used for signing"));
         }
+        opaque_key.expiration_time_valid()?;
         match &opaque_key.key_material {
             KeyMaterial::Hmac(_) => Ok(()),
             _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
@@ -301,6 +311,10 @@ impl IBaseCryptoOperation for HmacOperation {
         self.accumulating_op.is_some()
     }
 
+    fn is_valid(&self) -> bool {
+        self.opaque_key.expiration_time_valid().is_ok()
+    }
+
     fn set_operation_pattern(
         &mut self,
         _patter_parameter: &PatternParameters,
@@ -356,6 +370,7 @@ impl AesOperation {
         dir: SymmetricOperation,
         parameters: &SymmetricCryptoParameters,
     ) -> Result<(), HwCryptoError> {
+        opaque_key.expiration_time_valid()?;
         opaque_key.symmetric_operation_is_compatible(dir)?;
         opaque_key.parameters_are_compatible_symmetric_cipher(parameters)
     }
@@ -396,14 +411,12 @@ impl AesOperation {
         input: &mut DataToProcess<'a>,
         output: &mut DataToProcess<'a>,
     ) -> Result<usize, HwCryptoError> {
-        let total_size = input.len();
-        if (total_size % crypto::aes::BLOCK_SIZE) != 0 {
-            return Err(hwcrypto_err!(
-                BAD_PARAMETER,
-                "input size was not multiple of {}: {}",
-                crypto::aes::BLOCK_SIZE,
-                input.len()
-            ));
+        let mut total_pattern_size = input.len();
+        let unencrypted_bytes_last_block = total_pattern_size % crypto::aes::BLOCK_SIZE;
+        if unencrypted_bytes_last_block != 0 {
+            // on cbcs if there are remainders on the last block, then those need to be directly
+            // copied, they will be unencrypted
+            total_pattern_size -= unencrypted_bytes_last_block;
         }
         if output.len() != input.len() {
             return Err(hwcrypto_err!(BAD_PARAMETER, "output size was not {}", input.len()));
@@ -414,7 +427,7 @@ impl AesOperation {
             .ok_or(hwcrypto_err!(BAD_PARAMETER, "not a cbcs operation"))?;
         // TODO: refactor to remove need of input copy for memory slices
         let mut input_buff = TempBuffer::new();
-        let mut remaining_len = total_size;
+        let mut remaining_len = total_pattern_size;
         let aes_op = self
             .emitting_op
             .as_mut()
@@ -474,7 +487,10 @@ impl AesOperation {
                 }
             }
         }
-        Ok(total_size)
+        if unencrypted_bytes_last_block != 0 {
+            output.read_from_slice(input, Some(unencrypted_bytes_last_block))?;
+        }
+        Ok(total_pattern_size + unencrypted_bytes_last_block)
     }
 }
 
@@ -545,16 +561,9 @@ impl IBaseCryptoOperation for AesOperation {
 
     fn get_req_size_update(&self, input: &DataToProcess) -> Result<usize, HwCryptoError> {
         if self.cbcs_pattern.is_some() {
-            // On CBCS patterns we are currently processing a number of bytes multiple of block
-            // sizes, so the space needed is always the size of the input.
-            if (input.len() % crypto::aes::BLOCK_SIZE) != 0 {
-                return Err(hwcrypto_err!(
-                    BAD_PARAMETER,
-                    "input size was not multiple of {}: {}",
-                    crypto::aes::BLOCK_SIZE,
-                    input.len()
-                ));
-            }
+            // On CBCS patterns we are currently processing all the input at once (remaining bytes
+            // that are not multiples of a block are copied unencrypted) so the space needed is
+            // always the size of the input.
             Ok(input.len())
         } else {
             let (req_size, _) = self.get_update_req_size_with_remainder(input)?;
@@ -566,6 +575,10 @@ impl IBaseCryptoOperation for AesOperation {
         self.emitting_op.is_some()
     }
 
+    fn is_valid(&self) -> bool {
+        self.opaque_key.expiration_time_valid().is_ok()
+    }
+
     fn set_operation_pattern(
         &mut self,
         pattern_parameters: &PatternParameters,
@@ -612,6 +625,10 @@ impl ICryptographicOperation for CopyOperation {
     fn is_active(&self) -> bool {
         true
     }
+
+    fn is_valid(&self) -> bool {
+        true
+    }
 }
 
 pub(crate) struct CryptographicOperation;
@@ -665,6 +682,10 @@ impl ICryptographicOperation for () {
     fn is_active(&self) -> bool {
         false
     }
+
+    fn is_valid(&self) -> bool {
+        false
+    }
 }
 
 #[cfg(test)]
diff --git a/hwcryptohal/server/hwcrypto_device_key.rs b/hwcryptohal/server/hwcrypto_device_key.rs
index cd3ed21..b765022 100644
--- a/hwcryptohal/server/hwcrypto_device_key.rs
+++ b/hwcryptohal/server/hwcrypto_device_key.rs
@@ -212,7 +212,8 @@ impl HwCryptoKey {
         check_dice_policy_owner: bool,
     ) -> Result<DiceBoundKeyResult, HwCryptoError> {
         // Verifying provided DICE policy
-        let connection_info = ConnectionInformation { uuid: self.uuid.clone() };
+        let connection_info: ConnectionInformation =
+            ConnectionInformation { uuid: self.uuid.clone() };
         if check_dice_policy_owner {
             VersionContext::check_encrypted_context(dice_policy_for_key_version, connection_info)?;
         }
@@ -346,7 +347,7 @@ impl IHwCryptoKey for HwCryptoKey {
     }
 
     fn deriveKey(&self, parameters: &DerivedKeyParameters) -> binder::Result<DerivedKey> {
-        if let DerivedKeyPolicy::ClearKey(policy) = &parameters.keyPolicy {
+        if let DerivedKeyPolicy::ClearKeyPolicy(policy) = &parameters.keyPolicy {
             if policy.keySizeBytes <= 0 {
                 return Err(binder::Status::new_exception_str(
                     binder::ExceptionCode::UNSUPPORTED_OPERATION,
@@ -365,7 +366,7 @@ impl IHwCryptoKey for HwCryptoKey {
             .try_into()?;
 
         match &parameters.keyPolicy {
-            DerivedKeyPolicy::ClearKey(clear_policy) => {
+            DerivedKeyPolicy::ClearKeyPolicy(clear_policy) => {
                 // Adding key size to the context as well for a similar reason as to add the key
                 // policy to the context.
                 let key_size = clear_policy.keySizeBytes.try_into().map_err(|_| {
@@ -443,7 +444,6 @@ mod tests {
             SymmetricOperationParameters::SymmetricOperationParameters,
         },
         CryptoOperation::CryptoOperation,
-        CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
         CryptoOperationSet::CryptoOperationSet,
         IHwCryptoKey::ClearKeyPolicy::ClearKeyPolicy,
         OperationParameters::OperationParameters,
@@ -487,11 +487,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -515,9 +511,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -560,11 +554,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -628,7 +618,7 @@ mod tests {
         expect!(key.is_some(), "should have received a key");
         expect!(policy.len() > 0, "should have received a DICE policy");
 
-        let clear_key_policy = DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 0 });
+        let clear_key_policy = DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 0 });
         let mut params = DerivedKeyParameters {
             derivationKey: key,
             keyPolicy: clear_key_policy,
@@ -637,7 +627,8 @@ mod tests {
         let key = hw_device_key.deriveKey(&params);
         expect!(key.is_err(), "shouldn't be able to create a key of length 0");
 
-        let clear_key_policy = DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 32 });
+        let clear_key_policy =
+            DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 32 });
         params.keyPolicy = clear_key_policy;
         let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
         let key1 = match derived_key {
@@ -710,11 +701,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -745,9 +732,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
diff --git a/hwcryptohal/server/hwcrypto_ipc_server.rs b/hwcryptohal/server/hwcrypto_ipc_server.rs
index a4f0a2f..0463c42 100644
--- a/hwcryptohal/server/hwcrypto_ipc_server.rs
+++ b/hwcryptohal/server/hwcrypto_ipc_server.rs
@@ -16,58 +16,21 @@
 
 //! AIDL IPC Server code.
 use crate::hwcrypto_device_key;
-use crate::hwcrypto_operations;
-use alloc::rc::Rc;
 use binder::SpIBinder;
 use core::ffi::CStr;
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
 use rpcbinder::RpcServer;
-use tipc::{self, service_dispatcher, wrap_service, Manager, PortCfg, Uuid};
+use tipc::{self, Manager, PortCfg, Uuid};
 
-wrap_service!(HwCryptoDeviceKey(RpcServer: UnbufferedService));
-wrap_service!(HwCryptoOperations(RpcServer: UnbufferedService));
-
-service_dispatcher! {
-    enum HWCryptoHal {
-        HwCryptoOperations,
-        HwCryptoDeviceKey,
-    }
-}
-
-pub(crate) const RUST_HWCRYPTO_OPS_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.ops.V1";
 pub(crate) const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
+pub(crate) const NUM_IPC_QUEUES: u32 = 4;
 
 fn create_device_key_service(uuid: Uuid) -> Option<SpIBinder> {
     Some(hwcrypto_device_key::HwCryptoKey::new_binder(uuid).as_binder())
 }
 
 pub fn main_loop() -> Result<(), HwCryptoError> {
-    let mut dispatcher = HWCryptoHal::<2>::new().map_err(|e| {
-        hwcrypto_err!(GENERIC_ERROR, "could not create multi-service dispatcher: {:?}", e)
-    })?;
-
-    let hw_key = hwcrypto_operations::HwCryptoOperations::new_binder();
-    let hwk_rpc_server = RpcServer::new(hw_key.as_binder());
-    let hwk_service = HwCryptoOperations(hwk_rpc_server);
     let hwdk_rpc_server = RpcServer::new_per_session(create_device_key_service);
-    let hwdk_service = HwCryptoDeviceKey(hwdk_rpc_server);
-
-    let cfg =
-        PortCfg::new(RUST_HWCRYPTO_OPS_PORT.to_str().expect("should not happen, valid utf-8"))
-            .map_err(|e| {
-                hwcrypto_err!(
-                    GENERIC_ERROR,
-                    "could not create port config for {:?}: {:?}",
-                    RUST_HWCRYPTO_OPS_PORT,
-                    e
-                )
-            })?
-            .allow_ta_connect()
-            .allow_ns_connect();
-
-    dispatcher
-        .add_service(Rc::new(hwk_service), cfg)
-        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could add HWCrypto service: {:?}", e))?;
 
     let cfg = PortCfg::new(RUST_SERVICE_PORT.to_str().expect("should not happen, valid utf-8"))
         .map_err(|e| {
@@ -78,14 +41,11 @@ pub fn main_loop() -> Result<(), HwCryptoError> {
                 e
             )
         })?
+        .msg_queue_len(NUM_IPC_QUEUES)
         .allow_ta_connect()
         .allow_ns_connect();
 
-    dispatcher.add_service(Rc::new(hwdk_service), cfg).map_err(|e| {
-        hwcrypto_err!(GENERIC_ERROR, "could add HWCrypto device key service: {:?}", e)
-    })?;
-
-    let manager = Manager::<_, _, 2, 4>::new_with_dispatcher(dispatcher, [])
+    let manager = Manager::<_, _, 1, 4>::new_unbuffered(hwdk_rpc_server, cfg)
         .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not create service manager: {:?}", e))?;
 
     manager
@@ -96,7 +56,6 @@ pub fn main_loop() -> Result<(), HwCryptoError> {
 #[cfg(test)]
 mod tests {
     use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
-    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoOperations::IHwCryptoOperations;
     use rpcbinder::RpcSession;
     use binder::{IBinder, Strong};
     use test::expect_eq;
@@ -104,11 +63,6 @@ mod tests {
 
     #[test]
     fn connect_server() {
-        let session: Strong<dyn IHwCryptoOperations> = RpcSession::new()
-            .setup_trusty_client(RUST_HWCRYPTO_OPS_PORT)
-            .expect("Failed to connect");
-        expect_eq!(session.as_binder().ping_binder(), Ok(()));
-
         let session_device_key: Strong<dyn IHwCryptoKey> =
             RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
         expect_eq!(session_device_key.as_binder().ping_binder(), Ok(()));
diff --git a/hwcryptohal/server/hwcrypto_operations.rs b/hwcryptohal/server/hwcrypto_operations.rs
index 6b9769d..fe109aa 100644
--- a/hwcryptohal/server/hwcrypto_operations.rs
+++ b/hwcryptohal/server/hwcrypto_operations.rs
@@ -18,7 +18,6 @@
 //! key generation interface and to process cryptographic operations.
 
 use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
-    CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
     CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
     IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
 };
@@ -44,7 +43,6 @@ impl IHwCryptoOperations for HwCryptoOperations {
     fn processCommandList(
         &self,
         command_lists: &mut std::vec::Vec<CryptoOperationSet>,
-        _additional_error_info: &mut CryptoOperationErrorAdditionalInfo,
     ) -> binder::Result<Vec<CryptoOperationResult>> {
         let mut results = Vec::<CryptoOperationResult>::new();
         for command_list in command_lists {
@@ -155,11 +153,8 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        let mut op_result = hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        let mut op_result =
+            hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -175,9 +170,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
         else {
@@ -200,9 +193,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -236,11 +227,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
             crypto_sets.remove(0).operations.remove(0)
@@ -261,11 +248,7 @@ mod tests {
         let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        hw_crypto
-            .processCommandList(&mut crypto_sets, &mut additional_error_info)
-            .expect("couldn't process commands");
+        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
         // Extracting the vector from the command list because of ownership
         let CryptoOperation::DataOutput(OperationData::DataBuffer(mac2)) =
             crypto_sets.remove(0).operations.remove(0)
diff --git a/hwcryptohal/server/opaque_key.rs b/hwcryptohal/server/opaque_key.rs
index 8bb8564..5d1a152 100644
--- a/hwcryptohal/server/opaque_key.rs
+++ b/hwcryptohal/server/opaque_key.rs
@@ -53,10 +53,10 @@ use kmr_wire::{keymint::EcCurve, AsCborValue as _};
 use std::sync::{Mutex, OnceLock};
 use tipc::Uuid;
 
-use crate::crypto_provider;
 use crate::helpers;
 use crate::hwcrypto_device_key::HwCryptoKey;
 use crate::service_encryption_key::{EncryptedContent, EncryptionHeader, EncryptionHeaderKey};
+use crate::{crypto_provider, platform_functions};
 
 /// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
 const UNIQUE_VALUE_SIZEOF: usize = 32;
@@ -65,6 +65,8 @@ const SEALING_KEY_DERIVATION_HMAC_256_CTX: &[u8] = b"SEALING_KEY_DERIVATION_HMAC
 
 const HW_CRYPTO_WRAP_KEY_HMAC_256_CTX: &[u8] = b"HW_CRYPTO_WRAP_KEY_HMAC_256_CTX";
 
+const TOKEN_EXPORT_EXPIRATION_TIME_10S: u64 = 10;
+
 /// Struct to wrap boot unique counter. It is used to tag objects to the current boot.
 #[derive(Clone)]
 struct BootUniqueValue([u8; UNIQUE_VALUE_SIZEOF]);
@@ -217,9 +219,99 @@ fn check_protection_id_settings(
     }
 }
 
+#[derive(Copy, Clone, Debug)]
+pub(crate) struct ExpirationTime {
+    set_time_ms: u64,
+    valid_period_ms: u64,
+}
+
+impl ExpirationTime {
+    fn new(expiration_time_sec: u64) -> Result<Self, HwCryptoError> {
+        let set_time_ms = platform_functions::current_epoch_time_ms()?;
+        let valid_period_ms = expiration_time_sec
+            .checked_mul(1000)
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "validity period is too big",))?;
+        Ok(ExpirationTime { set_time_ms, valid_period_ms })
+    }
+
+    pub(crate) fn check_validity(&self) -> Result<bool, HwCryptoError> {
+        let current_time_ms = platform_functions::current_epoch_time_ms()?;
+        if current_time_ms < self.set_time_ms {
+            return Err(hwcrypto_err!(INVALID_KEY, "current time is before expiry set time",));
+        }
+        let valid_until_ms = self
+            .set_time_ms
+            .checked_add(self.valid_period_ms)
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "couldn't calculate validity period",))?;
+        Ok(current_time_ms < valid_until_ms)
+    }
+}
+
+impl AsCborValue for ExpirationTime {
+    fn to_cbor_value(self) -> Result<Value, CoseError> {
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;
+
+        let key = Value::Integer((ExpirationTimeCoseLabels::SetTime as i64).into());
+        let value = Value::Integer(self.set_time_ms.into());
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((ExpirationTimeCoseLabels::ValidPeriod as i64).into());
+        let value = Value::Integer(self.valid_period_ms.into());
+        cbor_map.push((key, value));
+
+        Ok(Value::Map(cbor_map))
+    }
+
+    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
+        //unimplemented!("sdsdsdsd")
+        let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
+        if opaque_key_map.len() != 2 {
+            return Err(CoseError::ExtraneousData);
+        }
+
+        let mut set_time_ms: Option<u64> = None;
+        let mut valid_period_ms: Option<u64> = None;
+        for (map_key, map_val) in opaque_key_map {
+            match map_key {
+                Value::Integer(key) => match key.try_into()? {
+                    ExpirationTimeCoseLabels::SetTime => {
+                        set_time_ms = Some(
+                            map_val
+                                .into_integer()
+                                .map_err(|_| {
+                                    CoseError::UnexpectedItem("not an integer", "integer")
+                                })?
+                                .try_into()
+                                .map_err(|_| CoseError::OutOfRangeIntegerValue)?,
+                        );
+                    }
+                    ExpirationTimeCoseLabels::ValidPeriod => {
+                        valid_period_ms = Some(
+                            map_val
+                                .into_integer()
+                                .map_err(|_| {
+                                    CoseError::UnexpectedItem("not an integer", "integer")
+                                })?
+                                .try_into()
+                                .map_err(|_| CoseError::OutOfRangeIntegerValue)?,
+                        );
+                    }
+                },
+                _ => return Err(CoseError::UnexpectedItem("not an integer", "integer map key")),
+            }
+        }
+
+        let set_time_ms = set_time_ms.ok_or(CoseError::EncodeFailed)?;
+        let valid_period_ms = valid_period_ms.ok_or(CoseError::EncodeFailed)?;
+
+        Ok(Self { set_time_ms, valid_period_ms })
+    }
+}
+
 #[derive(Debug)]
 struct KeyHeaderMetadata {
-    expiration_time: Option<u64>,
+    expiration_time: Option<ExpirationTime>,
     protection_id_settings: BTreeMap<ProtectionIdSerializable, ProtectionSetting>,
 }
 
@@ -229,11 +321,11 @@ impl KeyHeaderMetadata {
     }
 
     // While the current metadata definition wouldn't fail on this operation, we are doing this
-    // division to add an element to metadata that could fail while ying to clone
+    // division to add an element to metadata that could fail while trying to clone
     fn try_clone(&self) -> Result<Self, HwCryptoError> {
         let mut protection_id_settings = BTreeMap::new();
         protection_id_settings.extend(self.protection_id_settings.iter());
-        Ok(Self { expiration_time: None, protection_id_settings })
+        Ok(Self { expiration_time: self.expiration_time, protection_id_settings })
     }
 
     fn add_protection_id(
@@ -247,7 +339,9 @@ impl KeyHeaderMetadata {
                 "didn't receive any allowed operations for add_protection_id",
             ));
         }
-        let protection_id = ProtectionIdSerializable::try_from(protection_id)?;
+        let protection_id = ProtectionIdSerializable::try_from(protection_id).map_err(|e| {
+            hwcrypto_err!(GENERIC_ERROR, "couldn't convert from protection id {:?}", e,)
+        })?;
         if !self.protection_id_settings.contains_key(&protection_id) {
             return Err(hwcrypto_err!(
                 BAD_PARAMETER,
@@ -288,7 +382,9 @@ impl KeyHeaderMetadata {
 
         // Adding expiration time
         let expiration_time_value = if let Some(expiration_time) = self.expiration_time {
-            Value::Integer(expiration_time.into())
+            expiration_time.to_cbor_value().map_err(|_| {
+                hwcrypto_err!(BAD_PARAMETER, "couldn't get cbor representation of expiration time")
+            })?
         } else {
             Value::Null
         };
@@ -323,7 +419,7 @@ impl KeyHeaderMetadata {
         let mut protection_id_settings: Option<
             BTreeMap<ProtectionIdSerializable, ProtectionSetting>,
         > = None;
-        let mut expiration_time: Option<Option<u64>> = None;
+        let mut expiration_time: Option<Option<ExpirationTime>> = None;
 
         for (map_key, map_val) in metadata {
             let key = map_key
@@ -334,15 +430,12 @@ impl KeyHeaderMetadata {
                     expiration_time = if map_val.is_null() {
                         Some(None)
                     } else {
-                        let value = map_val
-                            .into_integer()
-                            .map_err(|_| {
-                                hwcrypto_err!(BAD_PARAMETER, "protection id key wasn't an integer")
-                            })?
-                            .try_into()
-                            .map_err(|_| {
-                                hwcrypto_err!(BAD_PARAMETER, "couldn't decode expiration time")
-                            })?;
+                        let value = ExpirationTime::from_cbor_value(map_val).map_err(|_| {
+                            hwcrypto_err!(
+                                BAD_PARAMETER,
+                                "couldn't transform expiration time to CBOR"
+                            )
+                        })?;
                         Some(Some(value))
                     }
                 }
@@ -384,6 +477,24 @@ impl KeyHeaderMetadata {
         ))?;
         Ok(())
     }
+
+    fn set_expiration_time(&mut self, expiration_time_sec: u64) -> Result<(), HwCryptoError> {
+        self.expiration_time = Some(ExpirationTime::new(expiration_time_sec)?);
+        Ok(())
+    }
+
+    fn expiration_time_set(&self) -> bool {
+        self.expiration_time.is_some()
+    }
+
+    fn expiration_time_valid(&self) -> Result<bool, HwCryptoError> {
+        if !self.expiration_time_set() {
+            Ok(true)
+        } else {
+            // expiration time is set, so unwrap will not panic
+            self.expiration_time.unwrap().check_validity()
+        }
+    }
 }
 
 /// Header for a `ClearKey` which contains the key policy along with some data needed to manipulate
@@ -431,6 +542,18 @@ impl KeyHeader {
     fn set_metadata_from_cbor(&mut self, metadata_as_cbor: Value) -> Result<(), HwCryptoError> {
         self.key_metadata.lock()?.set_metadata_from_cbor(metadata_as_cbor)
     }
+
+    fn set_expiration_time(&self, expiration_time_sec: u64) -> Result<(), HwCryptoError> {
+        self.key_metadata.lock()?.set_expiration_time(expiration_time_sec)
+    }
+
+    fn expiration_time_set(&self) -> Result<bool, HwCryptoError> {
+        Ok(self.key_metadata.lock()?.expiration_time_set())
+    }
+
+    fn expiration_time_valid(&self) -> Result<bool, HwCryptoError> {
+        self.key_metadata.lock()?.expiration_time_valid()
+    }
 }
 
 cose_enum_gen! {
@@ -456,6 +579,13 @@ cose_enum_gen! {
     }
 }
 
+cose_enum_gen! {
+    enum ExpirationTimeCoseLabels {
+        SetTime = -69000,
+        ValidPeriod = -69001,
+    }
+}
+
 aidl_enum_wrapper! {
     aidl_name: ProtectionId,
     wrapper_name: ProtectionIdSerializable,
@@ -684,6 +814,7 @@ impl OpaqueKey {
             return Err(hwcrypto_err!(GENERIC_ERROR, "only the owner of a key can export it"));
         }
         let key: OpaqueKey = self.try_clone()?;
+        key.set_expiration_time(TOKEN_EXPORT_EXPIRATION_TIME_10S)?;
         let token_creator = EncryptionHeader::generate(EncryptedContent::KeyMaterial)?;
 
         // This is a temporary workaround to create a DICE bound key because we will move to
@@ -734,6 +865,8 @@ impl OpaqueKey {
             EncryptedContent::WrappedKeyMaterial,
         )?;
 
+        sealing_dice_key.expiration_time_valid()?;
+
         let context = get_dice_sealing_key_derivation_context()?;
         // Preparing internal encryption DICE policy bound key
         let sealing_key = sealing_dice_key
@@ -752,6 +885,13 @@ impl OpaqueKey {
         )?;
 
         let opaque_key = Self::from_cbor_value(Value::from_slice(inner_key.as_slice())?)?;
+        if !opaque_key.expiration_time_set()? {
+            return Err(hwcrypto_err!(
+                INVALID_KEY,
+                "importer tokens should have an expiration time"
+            ));
+        }
+        opaque_key.expiration_time_valid()?;
         Ok(opaque_key)
     }
 
@@ -793,6 +933,8 @@ impl OpaqueKey {
                 &policy.keyLifetime
             ));
         }
+        // check that the key hasn't expired
+        self.expiration_time_valid()?;
         // Check that the derivation key can be used to derive keys (KeyPermissions/KeyPolicies)
         self.key_can_be_used_for_derivation()
     }
@@ -838,6 +980,7 @@ impl OpaqueKey {
         context: &[u8],
         derived_key_size: usize,
     ) -> Result<Vec<u8>, HwCryptoError> {
+        self.expiration_time_valid()?;
         let op_context = DerivationContext::new(HkdfOperationType::InternalSealingKeyDerivation)?;
         self.derive_clear_key_from_derivation_context(op_context, context, derived_key_size)
     }
@@ -847,6 +990,7 @@ impl OpaqueKey {
         context: &[u8],
         derived_key_size: usize,
     ) -> Result<Vec<u8>, HwCryptoError> {
+        self.expiration_time_valid()?;
         let op_context = DerivationContext::new(HkdfOperationType::ClearKeyDerivation)?;
         self.derive_clear_key_from_derivation_context(op_context, context, derived_key_size)
     }
@@ -857,6 +1001,7 @@ impl OpaqueKey {
         context: &[u8],
         connection_info: Uuid,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
+        self.expiration_time_valid()?;
         let aidl_policy = policy::cbor_policy_to_aidl(policy)?;
         self.check_key_derivation_parameters(&aidl_policy)?;
         let derived_key_size = get_key_size_in_bytes(&aidl_policy.keyType)?;
@@ -931,6 +1076,7 @@ impl OpaqueKey {
         &self,
         direction: SymmetricOperation,
     ) -> Result<(), HwCryptoError> {
+        self.expiration_time_valid()?;
         let dir = helpers::direction_to_key_usage(&direction)?;
         if !self.key_usage_supported(dir) {
             Err(hwcrypto_err!(BAD_PARAMETER, "provided key do not support {:?}", dir))
@@ -944,6 +1090,7 @@ impl OpaqueKey {
         &self,
         parameters: &SymmetricCryptoParameters,
     ) -> Result<(), HwCryptoError> {
+        self.expiration_time_valid()?;
         match parameters {
             SymmetricCryptoParameters::Aes(aes_parameters) => match aes_parameters {
                 AesCipherMode::Cbc(_) => match self.get_key_type() {
@@ -961,6 +1108,22 @@ impl OpaqueKey {
         }
     }
 
+    fn set_expiration_time(&self, expiration_time_sec: u64) -> Result<(), HwCryptoError> {
+        self.key_header.set_expiration_time(expiration_time_sec)
+    }
+
+    pub(crate) fn expiration_time_set(&self) -> Result<bool, HwCryptoError> {
+        self.key_header.expiration_time_set()
+    }
+
+    pub(crate) fn expiration_time_valid(&self) -> Result<(), HwCryptoError> {
+        if !self.key_header.expiration_time_valid()? {
+            Err(hwcrypto_err!(INVALID_KEY, "key is no longer valid"))
+        } else {
+            Ok(())
+        }
+    }
+
     fn add_protection_id(
         &self,
         protection_id: ProtectionId,
@@ -1003,6 +1166,7 @@ impl IOpaqueKey for OpaqueKey {
     }
 
     fn getShareableToken(&self, sealing_dice_policy: &[u8]) -> binder::Result<OpaqueKeyToken> {
+        self.expiration_time_valid()?;
         Ok(OpaqueKeyToken { keyToken: self.create_token(sealing_dice_policy)? })
     }
 
@@ -1295,6 +1459,19 @@ pub(crate) fn generate_key_material(
 mod tests {
     use super::*;
     use test::{expect, expect_eq};
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
+        types::{
+            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
+            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
+            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
+            SymmetricOperation::SymmetricOperation,
+            SymmetricOperationParameters::SymmetricOperationParameters,
+        },
+        CryptoOperation::CryptoOperation,
+        KeyPolicy::KeyPolicy,
+        OperationParameters::OperationParameters,
+    };
+    use crate::cmd_processing::CmdProcessorContext;
 
     #[test]
     fn boot_unique_values_match() {
@@ -1320,4 +1497,129 @@ mod tests {
         let check_result = check_key_material_with_policy(&key_material, &policy);
         expect!(check_result.is_ok(), "wrong key type");
     }
+
+    #[test]
+    fn expiration_time_creation() {
+        let expiration_time = ExpirationTime::new(10).expect("couldn't create expiration time");
+        expect!(
+            expiration_time.check_validity().expect("couldn't check validity"),
+            "expiration time should have been valid"
+        );
+    }
+
+    #[test]
+    fn expiration_time_serialization() {
+        let mut key_metadata = KeyHeaderMetadata::new();
+        expect!(
+            !key_metadata.expiration_time_set(),
+            "expiration time should not have been set by default"
+        );
+        expect!(
+            key_metadata.expiration_time_valid().expect("couldn't check validity"),
+            "expiration time should be valid if it has not been set"
+        );
+        let cbor_metadata =
+            key_metadata.get_metadata_as_cbor().expect("couldn't serialize metadata");
+        key_metadata.set_metadata_from_cbor(cbor_metadata).expect("couldn't set metadata back");
+        expect!(
+            !key_metadata.expiration_time_set(),
+            "expiration time should not have been set by default"
+        );
+        expect!(
+            key_metadata.expiration_time_valid().expect("couldn't check validity"),
+            "expiration time should be valid if it has not been set"
+        );
+
+        key_metadata.set_expiration_time(10).expect("couldn't set expiration time");
+        expect!(
+            key_metadata.expiration_time_set(),
+            "expiration time should have been set at this point"
+        );
+        expect!(
+            key_metadata.expiration_time_valid().expect("couldn't check validity"),
+            "expiration time should be valid"
+        );
+        let cbor_metadata =
+            key_metadata.get_metadata_as_cbor().expect("couldn't serialize metadata");
+        key_metadata.set_metadata_from_cbor(cbor_metadata).expect("couldn't set metadata back");
+        expect!(
+            key_metadata.expiration_time_set(),
+            "expiration time should have been set at this point"
+        );
+        expect!(
+            key_metadata.expiration_time_valid().expect("couldn't check validity"),
+            "expiration time should be valid"
+        );
+    }
+
+    #[test]
+    fn expiration_time_on_exported_token() {
+        let usage = KeyUse::ENCRYPT;
+        let key_type = KeyType::AES_256_GCM;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let uuid = Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap();
+        let key =
+            OpaqueKey::generate_opaque_key(&policy, uuid.clone()).expect("couldn't generate key");
+        let hw_device_key = HwCryptoKey::new_binder(uuid);
+        let sealing_dice_policy =
+            hw_device_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
+        let token =
+            key.getShareableToken(sealing_dice_policy.as_slice()).expect("couldn't generate token");
+        let imported_key_binder = hw_device_key
+            .keyTokenImport(&token, sealing_dice_policy.as_slice())
+            .expect("couldn't import back token");
+        let imported_key: OpaqueKey =
+            (&imported_key_binder).try_into().expect("couldn't cast back key");
+        expect!(
+            imported_key.expiration_time_set().expect("couldn't check if expiration time was set"),
+            "expiration time should have been set"
+        );
+        expect!(imported_key.expiration_time_valid().is_ok(), "expiration time should be valid");
+    }
+
+    #[test]
+    fn aes_simple_test_expired_key() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let uuid = Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap();
+        let key =
+            OpaqueKey::generate_opaque_key(&policy, uuid.clone()).expect("couldn't generate key");
+        let key: OpaqueKey = (&key).try_into().expect("couldn't cast back key");
+        key.set_expiration_time(0).expect("couldn't set up expiration time");
+        let binder_key = BnOpaqueKey::new_binder(key, binder::BinderFeatures::default());
+
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(binder_key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_err(),
+            "shouldn't be able to run an operation with an expired key"
+        )
+    }
 }
diff --git a/hwcryptohal/server/platform_functions.rs b/hwcryptohal/server/platform_functions.rs
index aa1ee49..8741b57 100644
--- a/hwcryptohal/server/platform_functions.rs
+++ b/hwcryptohal/server/platform_functions.rs
@@ -15,10 +15,14 @@
  */
 
 //! Module providing access to platform specific functions used by the library.
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
 use kmr_common::crypto;
+use log::error;
 
 use crate::ffi_bindings;
 
+const NANOSECONDS_IN_1_MS: u64 = 1000000;
+
 // Placeholder for function to compare VM identities. Identities will probably be based on DICE,
 // a simple comparison could be done if the DICE chains are unencrypted and the order of fields is
 // always the same.
@@ -48,3 +52,17 @@ pub fn trusty_rng_add_entropy(data: &[u8]) {
         panic!("trusty_rng_add_entropy() failed, {}", rc)
     }
 }
+
+pub fn current_epoch_time_ms() -> Result<u64, HwCryptoError> {
+    let mut secure_time_ns = 0;
+    // Safety: external syscall gets valid raw pointer to a `u64`.
+    let rc = unsafe { trusty_sys::gettime(0, 0, &mut secure_time_ns) };
+    if rc < 0 {
+        // Couldn't get time
+        error!("Error calling trusty_gettime: {:#x}", rc);
+        Err(hwcrypto_err!(GENERIC_ERROR, "error calling trusty_gettime: {:#x}", rc))
+    } else {
+        // secure_time_ns is positive, so casting is correct
+        Ok((secure_time_ns as u64) / NANOSECONDS_IN_1_MS)
+    }
+}
diff --git a/hwcryptokey-test/aes_vectors.rs b/hwcryptokey-test/aes_vectors.rs
index 4c5c5a9..5fa9213 100644
--- a/hwcryptokey-test/aes_vectors.rs
+++ b/hwcryptokey-test/aes_vectors.rs
@@ -27,7 +27,6 @@ mod tests {
             SymmetricOperationParameters::SymmetricOperationParameters,
         },
         CryptoOperation::CryptoOperation,
-        CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
         CryptoOperationSet::CryptoOperationSet,
         ICryptoOperationContext::ICryptoOperationContext,
         IHwCryptoKey::IHwCryptoKey,
@@ -312,11 +311,9 @@ mod tests {
                 CryptoOperationSet { context: context.clone(), operations: cmd_list };
             let mut crypto_sets = Vec::new();
             crypto_sets.push(crypto_op_set);
-            let mut additional_error_info =
-                CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
 
             let mut op_result = hw_crypto_ops
-                .processCommandList(&mut crypto_sets, &mut additional_error_info)
+                .processCommandList(&mut crypto_sets)
                 .expect("couldn't process commands");
 
             // Capture context to be used with CTR vectors whenever we have a new IV
diff --git a/hwcryptokey-test/versioned_keys_explicit.rs b/hwcryptokey-test/versioned_keys_explicit.rs
index 5690ffb..e7fa525 100644
--- a/hwcryptokey-test/versioned_keys_explicit.rs
+++ b/hwcryptokey-test/versioned_keys_explicit.rs
@@ -97,7 +97,7 @@ mod tests {
         // Derive a clear key from returned current policy and derivation key
         let mut params = DerivedKeyParameters {
             derivationKey: derivation_key1,
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: "context".as_bytes().to_vec(),
         };
 
@@ -195,7 +195,7 @@ mod tests {
         // Derive clear key from derivation key
         let params = DerivedKeyParameters {
             derivationKey: derivation_key,
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: "context".as_bytes().to_vec(),
         };
 
@@ -258,7 +258,7 @@ mod tests {
         // Generate derived clear keys from returned derivation keys
         let params = DerivedKeyParameters {
             derivationKey: derivation_key1,
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: "context".as_bytes().to_vec(),
         };
 
@@ -266,7 +266,7 @@ mod tests {
 
         let params = DerivedKeyParameters {
             derivationKey: derivation_key2,
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: "context".as_bytes().to_vec(),
         };
 
@@ -326,13 +326,13 @@ mod tests {
 
         let params1 = DerivedKeyParameters {
             derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: context1.as_bytes().to_vec(),
         };
 
         let params2 = DerivedKeyParameters {
             derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: context2.as_bytes().to_vec(),
         };
 
@@ -382,7 +382,7 @@ mod tests {
         // Request a zero length key
         let params = DerivedKeyParameters {
             derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 0 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 0 }),
             context: "context".as_bytes().to_vec(),
         };
 
@@ -392,7 +392,7 @@ mod tests {
         // Request a negative length key
         let params = DerivedKeyParameters {
             derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: -256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: -256 }),
             context: "context".as_bytes().to_vec(),
         };
 
@@ -426,7 +426,7 @@ mod tests {
         // Get a derived key based on large context
         let params = DerivedKeyParameters {
             derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: context.clone(),
         };
 
@@ -445,7 +445,7 @@ mod tests {
 
         let params = DerivedKeyParameters {
             derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKey(ClearKeyPolicy { keySizeBytes: 256 }),
+            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
             context: context.clone(),
         };
 
diff --git a/hwcryptokey-test/versioned_keys_opaque.rs b/hwcryptokey-test/versioned_keys_opaque.rs
index 9a40d5b..0e8dc02 100644
--- a/hwcryptokey-test/versioned_keys_opaque.rs
+++ b/hwcryptokey-test/versioned_keys_opaque.rs
@@ -25,7 +25,6 @@ mod tests {
             SymmetricOperationParameters::SymmetricOperationParameters,
         },
         CryptoOperation::CryptoOperation,
-        CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
         CryptoOperationSet::CryptoOperationSet,
         IHwCryptoKey::{
             DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
@@ -97,9 +96,7 @@ mod tests {
         let mut crypto_sets = Vec::new();
         crypto_sets.push(crypto_op_set);
 
-        let mut additional_error_info =
-            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
-        let result = hw_crypto.processCommandList(&mut crypto_sets, &mut additional_error_info);
+        let result = hw_crypto.processCommandList(&mut crypto_sets);
         match result {
             Ok(..) => {}
             Err(e) => return Err(e),
diff --git a/rust-hello-world-trusted-hal/README.md b/rust-hello-world-trusted-hal/README.md
new file mode 100644
index 0000000..715f206
--- /dev/null
+++ b/rust-hello-world-trusted-hal/README.md
@@ -0,0 +1,4 @@
+# Hello World Trusted Service
+
+This app demonstrates how to make a trusted service compliant with the AuthMgr protocol in order to
+expose the functionality to the client TAs outside the TEE environment.
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/aidl/android/trusty/trustedhal/IHelloWorld.aidl b/rust-hello-world-trusted-hal/aidl/android/trusty/trustedhal/IHelloWorld.aidl
new file mode 100644
index 0000000..260f1f1
--- /dev/null
+++ b/rust-hello-world-trusted-hal/aidl/android/trusty/trustedhal/IHelloWorld.aidl
@@ -0,0 +1,28 @@
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
+package android.trusty.trustedhal;
+
+/**
+ * This is an example service to demonstrate how to implement a Trusted HAL service to be compliant
+ * with the AuthMgr protocol.
+ */
+interface IHelloWorld {
+    /**
+     * Simply returns the string: "Hello " + name.
+     */
+    String sayHello(in String name);
+}
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/aidl/rules.mk b/rust-hello-world-trusted-hal/aidl/rules.mk
new file mode 100644
index 0000000..498d3c0
--- /dev/null
+++ b/rust-hello-world-trusted-hal/aidl/rules.mk
@@ -0,0 +1,28 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := hello_world_trusted_aidl
+
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_AIDL_PACKAGE := android/trusty/trustedhal
+
+MODULE_AIDLS := \
+    $(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/IHelloWorld.aidl \
+
+include make/aidl.mk
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/app/main.rs b/rust-hello-world-trusted-hal/app/main.rs
new file mode 100644
index 0000000..c395357
--- /dev/null
+++ b/rust-hello-world-trusted-hal/app/main.rs
@@ -0,0 +1,36 @@
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
+//! Entrypoint to the HelloWorld Trusted HAL TA
+
+use hello_world_trusted_lib::server::main_loop;
+use log::debug;
+
+fn log_formatter(record: &log::Record) -> String {
+    // line number should be present, so keeping it simple by just returning a 0.
+    let line = record.line().unwrap_or(0);
+    let file = record.file().unwrap_or("unknown file");
+    format!("{}: {}:{} {}\n", record.level(), file, line, record.args())
+}
+
+fn main() {
+    let config = trusty_log::TrustyLoggerConfig::default()
+        .with_min_level(log::Level::Info)
+        .format(&log_formatter);
+    trusty_log::init_with_config(config);
+    debug!("starting Hello World Trusted HAL...");
+    main_loop().expect("Hello World Trusted HAL TA quits unexpectedly.");
+}
diff --git a/rust-hello-world-trusted-hal/app/manifest.json b/rust-hello-world-trusted-hal/app/manifest.json
new file mode 100644
index 0000000..6695d1f
--- /dev/null
+++ b/rust-hello-world-trusted-hal/app/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "hello_world_trusted_app",
+    "uuid": "6255e37a-4f13-4575-8ae8-da7dcdfb8c27",
+    "min_heap": 20480,
+    "min_stack": 20480
+}
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/app/rules.mk b/rust-hello-world-trusted-hal/app/rules.mk
new file mode 100644
index 0000000..e594336
--- /dev/null
+++ b/rust-hello-world-trusted-hal/app/rules.mk
@@ -0,0 +1,36 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/main.rs \
+
+MODULE_CRATE_NAME := hello_world_trusted_app
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/lib \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-sys \
+	trusty/user/base/lib/trusty-std \
+	$(call FIND_CRATE,log) \
+	trusty/user/base/lib/trusty-log \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/trusted_app.mk
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/lib/manifest.json b/rust-hello-world-trusted-hal/lib/manifest.json
new file mode 100644
index 0000000..e6cf34c
--- /dev/null
+++ b/rust-hello-world-trusted-hal/lib/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "hello_world_trusted_lib",
+    "uuid": "946b5274-d3e4-43b0-8dd9-71bcbb1c548c",
+    "min_heap": 20480,
+    "min_stack": 20480
+}
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/lib/rules.mk b/rust-hello-world-trusted-hal/lib/rules.mk
new file mode 100644
index 0000000..3036dce
--- /dev/null
+++ b/rust-hello-world-trusted-hal/lib/rules.mk
@@ -0,0 +1,43 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_CRATE_NAME := hello_world_trusted_lib
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/binder_rpc_server \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/aidl \
+	trusty/user/base/interface/authmgr-handover/aidl \
+	trusty/user/base/lib/authgraph-rust/boringssl \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-sys \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/base/lib/trusty-std \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,vm-memory) \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
\ No newline at end of file
diff --git a/rust-hello-world-trusted-hal/lib/src/hand_over_service.rs b/rust-hello-world-trusted-hal/lib/src/hand_over_service.rs
new file mode 100644
index 0000000..ce313be
--- /dev/null
+++ b/rust-hello-world-trusted-hal/lib/src/hand_over_service.rs
@@ -0,0 +1,105 @@
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
+#![allow(dead_code)]
+//! Implementation of ITrustedServicesCommonsConnect.aidl
+use crate::server::HELLO_WORLD_TRUSTED_SERVICE_PORT;
+use authmgr_handover_aidl::aidl::android::trusty::handover::ITrustedServicesHandover::{
+    BnTrustedServicesHandover, ITrustedServicesHandover,
+};
+use authmgr_handover_aidl::binder;
+use binder::{ParcelFileDescriptor, SpIBinder};
+use log::error;
+use rpcbinder::RpcServer;
+use std::os::fd::AsRawFd;
+use std::sync::{Arc, Weak};
+use tipc::raw::{HandleSetWrapper, ToConnect, WorkToDo};
+use tipc::{Handle, PortCfg, Uuid};
+use trusty_std::ffi::CString;
+
+pub struct HandoverService {
+    handle_set: Weak<HandleSetWrapper<RpcServer>>,
+    trusted_service: Arc<RpcServer>,
+    // TODO b/401776482. This is temporary, until the bug is fixed.
+    uuid: Uuid,
+}
+
+impl binder::Interface for HandoverService {}
+
+impl HandoverService {
+    pub fn new_handover_session(
+        uuid: Uuid,
+        // Handleset is a weak reference to avoid potential cyclic references
+        handle_set: Weak<HandleSetWrapper<RpcServer>>,
+        trusted_service: Arc<RpcServer>,
+    ) -> Option<SpIBinder> {
+        let handover_service = HandoverService { handle_set, trusted_service, uuid };
+        Some(
+            BnTrustedServicesHandover::new_binder(
+                handover_service,
+                binder::BinderFeatures::default(),
+            )
+            .as_binder(),
+        )
+    }
+}
+
+impl ITrustedServicesHandover for HandoverService {
+    fn handoverConnection(
+        &self,
+        fd: &ParcelFileDescriptor,
+        _client_seq_num: i32,
+    ) -> binder::Result<()> {
+        let raw_fd = fd.as_raw_fd();
+        let handle = Handle::from_raw(raw_fd).map_err(|e| {
+            error!("Failed to create the handle from the raw fd: {:?}.", e);
+            binder::Status::new_exception(
+                binder::ExceptionCode::SERVICE_SPECIFIC,
+                Some(
+                    &CString::new("Could not create the handle from the raw fd.".to_string())
+                        .unwrap(),
+                ),
+            )
+        })?;
+        let dup_handle = handle.try_clone().map_err(|e| {
+            error!("Failed to clone the handle: {:?}", e);
+            binder::Status::new_exception(
+                binder::ExceptionCode::SERVICE_SPECIFIC,
+                Some(&CString::new("Failed to clone the handle.".to_string()).unwrap()),
+            )
+        })?;
+        // Prevent the destructor of the handle from calling because it will be closed by the Parcel
+        // File Descriptor which owns it.
+        core::mem::forget(handle);
+        let hello_service_port_cfg = PortCfg::new_raw(HELLO_WORLD_TRUSTED_SERVICE_PORT.into())
+            .allow_ta_connect()
+            .allow_ns_connect();
+        let to_connect = ToConnect::new(
+            dup_handle,
+            Arc::clone(&self.trusted_service),
+            hello_service_port_cfg,
+            // TODO b/401776482. We need to pass in `client_seq_num` once the bug is fixed.
+            self.uuid.clone(),
+        );
+        self.handle_set
+            .upgrade()
+            .ok_or(binder::Status::new_exception(
+                binder::ExceptionCode::SERVICE_SPECIFIC,
+                Some(&CString::new("Failed to get the handle set.".to_string()).unwrap()),
+            ))?
+            .add_work(WorkToDo::Connect(to_connect));
+        Ok(())
+    }
+}
diff --git a/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs b/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs
new file mode 100644
index 0000000..5a7ecb7
--- /dev/null
+++ b/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs
@@ -0,0 +1,43 @@
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
+//! Implementation of IHelloWorld.aidl
+
+use hello_world_trusted_aidl::aidl::android::trusty::trustedhal::IHelloWorld::{
+    BnHelloWorld, IHelloWorld,
+};
+use hello_world_trusted_aidl::binder;
+use log::info;
+
+pub struct HelloWorldService;
+
+impl binder::Interface for HelloWorldService {}
+
+impl HelloWorldService {
+    /// Creates a binder object
+    pub fn new_binder() -> binder::Strong<dyn IHelloWorld> {
+        BnHelloWorld::new_binder(HelloWorldService, binder::BinderFeatures::default())
+    }
+}
+
+impl IHelloWorld for HelloWorldService {
+    fn sayHello(&self, name: &str) -> binder::Result<String> {
+        info!("In IHelloWorld trusted service...");
+        let mut hello_string = String::from("Hello ");
+        hello_string.push_str(name);
+        Ok(hello_string)
+    }
+}
diff --git a/rust-hello-world-trusted-hal/lib/src/lib.rs b/rust-hello-world-trusted-hal/lib/src/lib.rs
new file mode 100644
index 0000000..c1240f7
--- /dev/null
+++ b/rust-hello-world-trusted-hal/lib/src/lib.rs
@@ -0,0 +1,21 @@
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
+//! Entrypoint to the HelloWorld Trusted HAL TA library
+
+mod hand_over_service;
+mod hello_world_trusted_service;
+pub mod server;
diff --git a/rust-hello-world-trusted-hal/lib/src/server.rs b/rust-hello-world-trusted-hal/lib/src/server.rs
new file mode 100644
index 0000000..222280d
--- /dev/null
+++ b/rust-hello-world-trusted-hal/lib/src/server.rs
@@ -0,0 +1,55 @@
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
+//! Setting up the server for the Hello World Trusted HAL service.
+use crate::hand_over_service::HandoverService;
+use crate::hello_world_trusted_service::HelloWorldService;
+use rpcbinder::RpcServer;
+use std::ffi::CStr;
+use std::sync::Arc;
+use tipc::raw::{EventLoop, HandleSetWrapper};
+use tipc::{PortCfg, TipcError};
+
+// Port for the handover service for the HelloWorld trusted service
+pub const HANDOVER_SERVICE_PORT: &CStr = c"com.android.trusty.rust.handover.hello.service.V1";
+
+// Port for the HelloWorld trusted service
+pub const HELLO_WORLD_TRUSTED_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hello.service.V1";
+
+pub fn main_loop() -> Result<(), TipcError> {
+    let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);
+    let handle_set_wrapper_clone = Arc::clone(&handle_set_wrapper);
+    let helloworld_binder = HelloWorldService::new_binder();
+    let helloworld_rpc_service = Arc::new(RpcServer::new(helloworld_binder.as_binder()));
+
+    // Only the AuthMgr BE TA is allowed to connect
+    let handover_service_port_cfg =
+        PortCfg::new_raw(HANDOVER_SERVICE_PORT.into()).allow_ta_connect();
+
+    let cb_per_session = move |uuid| {
+        HandoverService::new_handover_session(
+            uuid,
+            Arc::downgrade(&handle_set_wrapper),
+            Arc::clone(&helloworld_rpc_service),
+        )
+    };
+
+    let handover_rpc_service = RpcServer::new_per_session(cb_per_session);
+    let _port_wrapper = handle_set_wrapper_clone
+        .add_port(&handover_service_port_cfg, Arc::new(handover_rpc_service))?;
+    let event_loop = EventLoop::new(handle_set_wrapper_clone.clone());
+    event_loop.run()
+}
diff --git a/usertests-inc.mk b/usertests-inc.mk
index 70655aa..1ce14f9 100644
--- a/usertests-inc.mk
+++ b/usertests-inc.mk
@@ -38,6 +38,7 @@ TRUSTY_USER_TESTS += \
 endif
 
 TRUSTY_RUST_USER_TESTS += \
+	trusty/user/app/authmgr/authmgr-be/lib \
 	trusty/user/app/sample/hwcryptohal/common \
 	trusty/user/app/sample/hwcryptohal/server \
 	trusty/user/app/sample/hwcryptokey-test \
```

