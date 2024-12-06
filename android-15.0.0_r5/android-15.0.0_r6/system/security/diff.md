```diff
diff --git a/keystore-engine/Android.bp b/keystore-engine/Android.bp
index 7fbfe53a..d7634459 100644
--- a/keystore-engine/Android.bp
+++ b/keystore-engine/Android.bp
@@ -27,7 +27,8 @@ cc_library {
     name: "libkeystore-engine",
 
     defaults: [
-        "keystore2_use_latest_aidl_ndk_shared",
+        "keymint_use_latest_hal_aidl_ndk_static",
+        "keystore2_use_latest_aidl_ndk_static",
     ],
     srcs: [
         "android_engine.cpp",
@@ -41,7 +42,6 @@ cc_library {
     ],
 
     shared_libs: [
-        "android.system.keystore2-V4-ndk",
         "libbinder_ndk",
         "libcrypto",
         "libcutils",
diff --git a/keystore/Android.bp b/keystore/Android.bp
index c79d00ba..2d78f336 100644
--- a/keystore/Android.bp
+++ b/keystore/Android.bp
@@ -20,14 +20,14 @@ cc_defaults {
 
     sanitize: {
         misc_undefined: [
-             "signed-integer-overflow",
-             "unsigned-integer-overflow",
-             "shift",
-             "integer-divide-by-zero",
-             "implicit-unsigned-integer-truncation",
-             // BUG: 123630767
-             //"implicit-signed-integer-truncation",
-             "implicit-integer-sign-change",
+            "signed-integer-overflow",
+            "unsigned-integer-overflow",
+            "shift",
+            "integer-divide-by-zero",
+            "implicit-unsigned-integer-truncation",
+            // BUG: 123630767
+            //"implicit-signed-integer-truncation",
+            "implicit-integer-sign-change",
         ],
     },
 
@@ -66,7 +66,10 @@ cc_binary {
 // in Tag::ATTESTATION_APPLICATION_ID
 cc_library {
     name: "libkeystore-attestation-application-id",
-    defaults: ["keystore_defaults"],
+    defaults: [
+        "keystore_defaults",
+        "keystore2_use_latest_aidl_ndk_shared",
+    ],
 
     srcs: [
         "keystore_attestation_id.cpp",
diff --git a/keystore/keystore_attestation_id.cpp b/keystore/keystore_attestation_id.cpp
index 1534be16..c91f86fd 100644
--- a/keystore/keystore_attestation_id.cpp
+++ b/keystore/keystore_attestation_id.cpp
@@ -21,6 +21,7 @@
 #include <log/log.h>
 
 #include <memory>
+#include <mutex>
 #include <string>
 #include <vector>
 
@@ -29,6 +30,7 @@
 #include <binder/Parcelable.h>
 #include <binder/PersistableBundle.h>
 
+#include <aidl/android/system/keystore2/ResponseCode.h>
 #include <android/security/keystore/BpKeyAttestationApplicationIdProvider.h>
 #include <android/security/keystore/IKeyAttestationApplicationIdProvider.h>
 #include <android/security/keystore/KeyAttestationApplicationId.h>
@@ -48,7 +50,9 @@ namespace android {
 namespace {
 
 constexpr const char* kAttestationSystemPackageName = "AndroidSystem";
-constexpr const char* kUnknownPackageName = "UnknownPackage";
+constexpr const size_t kMaxAttempts = 3;
+constexpr const unsigned long kRetryIntervalUsecs = 500000;  // sleep for 500 ms
+constexpr const char* kProviderServiceName = "sec_key_att_app_id_provider";
 
 std::vector<uint8_t> signature2SHA256(const security::keystore::Signature& sig) {
     std::vector<uint8_t> digest_buffer(SHA256_DIGEST_LENGTH);
@@ -56,26 +60,27 @@ std::vector<uint8_t> signature2SHA256(const security::keystore::Signature& sig)
     return digest_buffer;
 }
 
+using ::aidl::android::system::keystore2::ResponseCode;
 using ::android::security::keystore::BpKeyAttestationApplicationIdProvider;
 
-class KeyAttestationApplicationIdProvider : public BpKeyAttestationApplicationIdProvider {
-  public:
-    KeyAttestationApplicationIdProvider();
+[[clang::no_destroy]] std::mutex gServiceMu;
+[[clang::no_destroy]] std::shared_ptr<BpKeyAttestationApplicationIdProvider>
+    gService;  // GUARDED_BY gServiceMu
 
-    static KeyAttestationApplicationIdProvider& get();
-
-  private:
-    android::sp<android::IServiceManager> service_manager_;
-};
-
-KeyAttestationApplicationIdProvider& KeyAttestationApplicationIdProvider::get() {
-    static KeyAttestationApplicationIdProvider mpm;
-    return mpm;
+std::shared_ptr<BpKeyAttestationApplicationIdProvider> get_service() {
+    std::lock_guard<std::mutex> guard(gServiceMu);
+    if (gService.get() == nullptr) {
+        gService = std::make_shared<BpKeyAttestationApplicationIdProvider>(
+            android::defaultServiceManager()->waitForService(String16(kProviderServiceName)));
+    }
+    return gService;
 }
 
-KeyAttestationApplicationIdProvider::KeyAttestationApplicationIdProvider()
-    : BpKeyAttestationApplicationIdProvider(android::defaultServiceManager()->waitForService(
-          String16("sec_key_att_app_id_provider"))) {}
+void reset_service() {
+    std::lock_guard<std::mutex> guard(gServiceMu);
+    // Drop the global reference; any thread that already has a reference can keep using it.
+    gService.reset();
+}
 
 DECLARE_STACK_OF(ASN1_OCTET_STRING);
 
@@ -270,7 +275,7 @@ build_attestation_application_id(const KeyAttestationApplicationId& key_attestat
 StatusOr<std::vector<uint8_t>> gather_attestation_application_id(uid_t uid) {
     KeyAttestationApplicationId key_attestation_id;
 
-    if (uid == AID_SYSTEM) {
+    if (uid == AID_SYSTEM || uid == AID_ROOT) {
         /* Use a fixed ID for system callers */
         auto pinfo = KeyAttestationPackageInfo();
         pinfo.packageName = String16(kAttestationSystemPackageName);
@@ -278,18 +283,38 @@ StatusOr<std::vector<uint8_t>> gather_attestation_application_id(uid_t uid) {
         key_attestation_id.packageInfos.push_back(std::move(pinfo));
     } else {
         /* Get the attestation application ID from package manager */
-        auto& pm = KeyAttestationApplicationIdProvider::get();
-        auto status = pm.getKeyAttestationApplicationId(uid, &key_attestation_id);
-        // Package Manager call has failed, perform attestation but indicate that the
-        // caller is unknown.
+        ::android::binder::Status status;
+
+        // Retry on failure.
+        for (size_t attempt{0}; attempt < kMaxAttempts; ++attempt) {
+            auto pm = get_service();
+            status = pm->getKeyAttestationApplicationId(uid, &key_attestation_id);
+            if (status.isOk()) {
+                break;
+            }
+
+            if (status.exceptionCode() == binder::Status::EX_SERVICE_SPECIFIC) {
+                ALOGW("Retry: get attestation ID for %d failed with service specific error: %s %d",
+                      uid, status.exceptionMessage().c_str(), status.serviceSpecificErrorCode());
+            } else if (status.exceptionCode() == binder::Status::EX_TRANSACTION_FAILED) {
+                // If the transaction failed, drop the package manager connection so that the next
+                // attempt will try again.
+                ALOGW(
+                    "Retry: get attestation ID for %d transaction failed, reset connection: %s %d",
+                    uid, status.exceptionMessage().c_str(), status.exceptionCode());
+                reset_service();
+            } else {
+                ALOGW("Retry: get attestation ID for %d failed with error: %s %d", uid,
+                      status.exceptionMessage().c_str(), status.exceptionCode());
+            }
+            usleep(kRetryIntervalUsecs);
+        }
+
         if (!status.isOk()) {
             ALOGW("package manager request for key attestation ID failed with: %s %d",
                   status.exceptionMessage().c_str(), status.exceptionCode());
 
-            auto pinfo = KeyAttestationPackageInfo();
-            pinfo.packageName = String16(kUnknownPackageName);
-            pinfo.versionCode = 1;
-            key_attestation_id.packageInfos.push_back(std::move(pinfo));
+            return int32_t(ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED);
         }
     }
 
diff --git a/keystore2/Android.bp b/keystore2/Android.bp
index ed9cd880..7bba6870 100644
--- a/keystore2/Android.bp
+++ b/keystore2/Android.bp
@@ -30,7 +30,10 @@ rust_defaults {
         "keystore2_use_latest_aidl_rust",
         "structured_log_rust_defaults",
     ],
-
+    cfgs: select(release_flag("RELEASE_AVF_ENABLE_EARLY_VM"), {
+        true: ["early_vm"],
+        default: [],
+    }),
     rustlibs: [
         "android.hardware.security.rkp-V3-rust",
         "android.hardware.security.secureclock-V1-rust",
@@ -53,7 +56,6 @@ rust_defaults {
         "libkeystore2_hal_names_rust",
         "libkeystore2_km_compat",
         "libkeystore2_selinux",
-        "liblazy_static",
         "liblibc",
         "liblog_rust",
         "libmessage_macro",
@@ -111,6 +113,7 @@ rust_test {
         "liblibsqlite3_sys",
         "libnix",
         "librusqlite",
+        "libtempfile",
     ],
     // The test should always include watchdog.
     features: [
@@ -162,6 +165,11 @@ aconfig_declarations {
     srcs: ["aconfig/flags.aconfig"],
 }
 
+java_aconfig_library {
+    name: "keystore2_flags_java",
+    aconfig_declarations: "keystore2_flags",
+}
+
 rust_aconfig_library {
     name: "libkeystore2_flags_rust",
     crate_name: "keystore2_flags",
diff --git a/keystore2/TEST_MAPPING b/keystore2/TEST_MAPPING
index 57ce78cc..f12a301f 100644
--- a/keystore2/TEST_MAPPING
+++ b/keystore2/TEST_MAPPING
@@ -1,5 +1,8 @@
 {
   "presubmit": [
+    {
+      "name": "keystore2_client_tests"
+    },
     {
       "name": "keystore2_crypto_test"
     },
@@ -31,9 +34,6 @@
     {
       "name": "CtsKeystorePerformanceTestCases"
     },
-    {
-      "name": "keystore2_client_tests"
-    },
     {
       "name": "librkpd_client.test"
     },
diff --git a/keystore2/aconfig/flags.aconfig b/keystore2/aconfig/flags.aconfig
index 856b42e2..ff817b77 100644
--- a/keystore2/aconfig/flags.aconfig
+++ b/keystore2/aconfig/flags.aconfig
@@ -18,17 +18,25 @@ flag {
 }
 
 flag {
-  name: "import_previously_emulated_keys"
+  name: "disable_legacy_keystore_get"
   namespace: "hardware_backed_security"
-  description: "Include support for importing keys that were previously software-emulated into KeyMint"
-  bug: "283077822"
+  description: "This flag disables legacy keystore get and makes it so that get returns an error"
+  bug: "307460850"
   is_fixed_read_only: true
 }
 
 flag {
-  name: "database_loop_timeout"
+  name: "enable_dump"
   namespace: "hardware_backed_security"
-  description: "Abandon Keystore database retry loop after an interval"
-  bug: "319563050"
+  description: "Include support for dump() on the IKeystoreMaintenance service"
+  bug: "344987718"
   is_fixed_read_only: true
-}
\ No newline at end of file
+}
+
+flag {
+  name: "import_previously_emulated_keys"
+  namespace: "hardware_backed_security"
+  description: "Include support for importing keys that were previously software-emulated into KeyMint"
+  bug: "283077822"
+  is_fixed_read_only: true
+}
diff --git a/keystore2/aidl/android/security/maintenance/IKeystoreMaintenance.aidl b/keystore2/aidl/android/security/maintenance/IKeystoreMaintenance.aidl
index 50e98286..ecc1f4b1 100644
--- a/keystore2/aidl/android/security/maintenance/IKeystoreMaintenance.aidl
+++ b/keystore2/aidl/android/security/maintenance/IKeystoreMaintenance.aidl
@@ -76,21 +76,6 @@ interface IKeystoreMaintenance {
      */
     void onUserLskfRemoved(in int userId);
 
-    /**
-     * Allows LockSettingsService to inform keystore about password change of a user.
-     * Callers require 'ChangePassword' permission.
-     *
-     * ## Error conditions:
-     * `ResponseCode::PERMISSION_DENIED` - if the callers does not have the 'ChangePassword'
-     *                                     permission.
-     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the super encrypted keys of the user.
-     * `ResponseCode::Locked' -  if the keystore is locked for the given user.
-     *
-     * @param userId - Android user id
-     * @param password - a secret derived from the synthetic password of the user
-     */
-    void onUserPasswordChanged(in int userId, in @nullable byte[] password);
-
     /**
      * This function deletes all keys within a namespace. It mainly gets called when an app gets
      * removed and all resources of this app need to be cleaned up.
diff --git a/keystore2/legacykeystore/lib.rs b/keystore2/legacykeystore/lib.rs
index 8e6040b8..b173da83 100644
--- a/keystore2/legacykeystore/lib.rs
+++ b/keystore2/legacykeystore/lib.rs
@@ -134,6 +134,7 @@ impl DB {
     }
 
     fn get(&mut self, caller_uid: u32, alias: &str) -> Result<Option<Vec<u8>>> {
+        ensure_keystore_get_is_enabled()?;
         self.with_transaction(TransactionBehavior::Deferred, |tx| {
             tx.query_row(
                 "SELECT profile FROM profiles WHERE owner = ? AND alias = ?;",
@@ -239,6 +240,17 @@ fn ensure_keystore_put_is_enabled() -> Result<()> {
     }
 }
 
+fn ensure_keystore_get_is_enabled() -> Result<()> {
+    if keystore2_flags::disable_legacy_keystore_get() {
+        Err(Error::deprecated()).context(concat!(
+            "Retrieving from Keystore's legacy database is ",
+            "no longer supported, store in an app-specific database instead"
+        ))
+    } else {
+        Ok(())
+    }
+}
+
 struct LegacyKeystoreDeleteListener {
     legacy_keystore: Arc<LegacyKeystore>,
 }
@@ -313,6 +325,7 @@ impl LegacyKeystore {
     }
 
     fn get(&self, alias: &str, uid: i32) -> Result<Vec<u8>> {
+        ensure_keystore_get_is_enabled()?;
         let mut db = self.open_db().context("In get.")?;
         let uid = Self::get_effective_uid(uid).context("In get.")?;
 
diff --git a/keystore2/rkpd_client/src/lib.rs b/keystore2/rkpd_client/src/lib.rs
index d8a5276c..936fe3d6 100644
--- a/keystore2/rkpd_client/src/lib.rs
+++ b/keystore2/rkpd_client/src/lib.rs
@@ -310,331 +310,4 @@ pub fn store_rkpd_attestation_key(
 }
 
 #[cfg(test)]
-mod tests {
-    use super::*;
-    use android_security_rkp_aidl::aidl::android::security::rkp::IRegistration::BnRegistration;
-    use std::sync::atomic::{AtomicU32, Ordering};
-    use std::sync::{Arc, Mutex};
-
-    const DEFAULT_RPC_SERVICE_NAME: &str =
-        "android.hardware.security.keymint.IRemotelyProvisionedComponent/default";
-
-    struct MockRegistrationValues {
-        key: RemotelyProvisionedKey,
-        latency: Option<Duration>,
-        thread_join_handles: Vec<Option<std::thread::JoinHandle<()>>>,
-    }
-
-    struct MockRegistration(Arc<Mutex<MockRegistrationValues>>);
-
-    impl MockRegistration {
-        pub fn new_native_binder(
-            key: &RemotelyProvisionedKey,
-            latency: Option<Duration>,
-        ) -> Strong<dyn IRegistration> {
-            let result = Self(Arc::new(Mutex::new(MockRegistrationValues {
-                key: RemotelyProvisionedKey {
-                    keyBlob: key.keyBlob.clone(),
-                    encodedCertChain: key.encodedCertChain.clone(),
-                },
-                latency,
-                thread_join_handles: Vec::new(),
-            })));
-            BnRegistration::new_binder(result, BinderFeatures::default())
-        }
-    }
-
-    impl Drop for MockRegistration {
-        fn drop(&mut self) {
-            let mut values = self.0.lock().unwrap();
-            for handle in values.thread_join_handles.iter_mut() {
-                // These are test threads. So, no need to worry too much about error handling.
-                handle.take().unwrap().join().unwrap();
-            }
-        }
-    }
-
-    impl Interface for MockRegistration {}
-
-    impl IRegistration for MockRegistration {
-        fn getKey(&self, _: i32, cb: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
-            let mut values = self.0.lock().unwrap();
-            let key = RemotelyProvisionedKey {
-                keyBlob: values.key.keyBlob.clone(),
-                encodedCertChain: values.key.encodedCertChain.clone(),
-            };
-            let latency = values.latency;
-            let get_key_cb = cb.clone();
-
-            // Need a separate thread to trigger timeout in the caller.
-            let join_handle = std::thread::spawn(move || {
-                if let Some(duration) = latency {
-                    std::thread::sleep(duration);
-                }
-                get_key_cb.onSuccess(&key).unwrap();
-            });
-            values.thread_join_handles.push(Some(join_handle));
-            Ok(())
-        }
-
-        fn cancelGetKey(&self, _: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
-            Ok(())
-        }
-
-        fn storeUpgradedKeyAsync(
-            &self,
-            _: &[u8],
-            _: &[u8],
-            cb: &Strong<dyn IStoreUpgradedKeyCallback>,
-        ) -> binder::Result<()> {
-            // We are primarily concerned with timing out correctly. Storing the key in this mock
-            // registration isn't particularly interesting, so skip that part.
-            let values = self.0.lock().unwrap();
-            let store_cb = cb.clone();
-            let latency = values.latency;
-
-            std::thread::spawn(move || {
-                if let Some(duration) = latency {
-                    std::thread::sleep(duration);
-                }
-                store_cb.onSuccess().unwrap();
-            });
-            Ok(())
-        }
-    }
-
-    fn get_mock_registration(
-        key: &RemotelyProvisionedKey,
-        latency: Option<Duration>,
-    ) -> Result<binder::Strong<dyn IRegistration>> {
-        let (tx, rx) = oneshot::channel();
-        let cb = GetRegistrationCallback::new_native_binder(tx);
-        let mock_registration = MockRegistration::new_native_binder(key, latency);
-
-        assert!(cb.onSuccess(&mock_registration).is_ok());
-        tokio_rt().block_on(rx).unwrap()
-    }
-
-    // Using the same key ID makes test cases race with each other. So, we use separate key IDs for
-    // different test cases.
-    fn get_next_key_id() -> u32 {
-        static ID: AtomicU32 = AtomicU32::new(0);
-        ID.fetch_add(1, Ordering::Relaxed)
-    }
-
-    #[test]
-    fn test_get_registration_cb_success() {
-        let key: RemotelyProvisionedKey = Default::default();
-        let registration = get_mock_registration(&key, /*latency=*/ None);
-        assert!(registration.is_ok());
-    }
-
-    #[test]
-    fn test_get_registration_cb_cancel() {
-        let (tx, rx) = oneshot::channel();
-        let cb = GetRegistrationCallback::new_native_binder(tx);
-        assert!(cb.onCancel().is_ok());
-
-        let result = tokio_rt().block_on(rx).unwrap();
-        assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RequestCancelled);
-    }
-
-    #[test]
-    fn test_get_registration_cb_error() {
-        let (tx, rx) = oneshot::channel();
-        let cb = GetRegistrationCallback::new_native_binder(tx);
-        assert!(cb.onError("error").is_ok());
-
-        let result = tokio_rt().block_on(rx).unwrap();
-        assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::GetRegistrationFailed);
-    }
-
-    #[test]
-    fn test_get_key_cb_success() {
-        let mock_key =
-            RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
-        let (tx, rx) = oneshot::channel();
-        let cb = GetKeyCallback::new_native_binder(tx);
-        assert!(cb.onSuccess(&mock_key).is_ok());
-
-        let key = tokio_rt().block_on(rx).unwrap().unwrap();
-        assert_eq!(key, mock_key);
-    }
-
-    #[test]
-    fn test_get_key_cb_cancel() {
-        let (tx, rx) = oneshot::channel();
-        let cb = GetKeyCallback::new_native_binder(tx);
-        assert!(cb.onCancel().is_ok());
-
-        let result = tokio_rt().block_on(rx).unwrap();
-        assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RequestCancelled);
-    }
-
-    #[test]
-    fn test_get_key_cb_error() {
-        for get_key_error in GetKeyErrorCode::enum_values() {
-            let (tx, rx) = oneshot::channel();
-            let cb = GetKeyCallback::new_native_binder(tx);
-            assert!(cb.onError(get_key_error, "error").is_ok());
-
-            let result = tokio_rt().block_on(rx).unwrap();
-            assert_eq!(
-                result.unwrap_err().downcast::<Error>().unwrap(),
-                Error::GetKeyFailed(get_key_error),
-            );
-        }
-    }
-
-    #[test]
-    fn test_store_upgraded_cb_success() {
-        let (tx, rx) = oneshot::channel();
-        let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
-        assert!(cb.onSuccess().is_ok());
-
-        tokio_rt().block_on(rx).unwrap().unwrap();
-    }
-
-    #[test]
-    fn test_store_upgraded_key_cb_error() {
-        let (tx, rx) = oneshot::channel();
-        let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
-        assert!(cb.onError("oh no! it failed").is_ok());
-
-        let result = tokio_rt().block_on(rx).unwrap();
-        assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::StoreUpgradedKeyFailed);
-    }
-
-    #[test]
-    fn test_get_mock_key_success() {
-        let mock_key =
-            RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
-        let registration = get_mock_registration(&mock_key, /*latency=*/ None).unwrap();
-
-        let key = tokio_rt()
-            .block_on(get_rkpd_attestation_key_from_registration_async(&registration, 0))
-            .unwrap();
-        assert_eq!(key, mock_key);
-    }
-
-    #[test]
-    fn test_get_mock_key_timeout() {
-        let mock_key =
-            RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
-        let latency = RKPD_TIMEOUT + Duration::from_secs(1);
-        let registration = get_mock_registration(&mock_key, Some(latency)).unwrap();
-
-        let result =
-            tokio_rt().block_on(get_rkpd_attestation_key_from_registration_async(&registration, 0));
-        assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RetryableTimeout);
-    }
-
-    #[test]
-    fn test_store_mock_key_success() {
-        let mock_key =
-            RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
-        let registration = get_mock_registration(&mock_key, /*latency=*/ None).unwrap();
-        tokio_rt()
-            .block_on(store_rkpd_attestation_key_with_registration_async(&registration, &[], &[]))
-            .unwrap();
-    }
-
-    #[test]
-    fn test_store_mock_key_timeout() {
-        let mock_key =
-            RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
-        let latency = RKPD_TIMEOUT + Duration::from_secs(1);
-        let registration = get_mock_registration(&mock_key, Some(latency)).unwrap();
-
-        let result = tokio_rt().block_on(store_rkpd_attestation_key_with_registration_async(
-            &registration,
-            &[],
-            &[],
-        ));
-        assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::Timeout);
-    }
-
-    #[test]
-    fn test_get_rkpd_attestation_key() {
-        binder::ProcessState::start_thread_pool();
-        let key_id = get_next_key_id();
-        let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
-        assert!(!key.keyBlob.is_empty());
-        assert!(!key.encodedCertChain.is_empty());
-    }
-
-    #[test]
-    fn test_get_rkpd_attestation_key_same_caller() {
-        binder::ProcessState::start_thread_pool();
-        let key_id = get_next_key_id();
-
-        // Multiple calls should return the same key.
-        let first_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
-        let second_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
-
-        assert_eq!(first_key.keyBlob, second_key.keyBlob);
-        assert_eq!(first_key.encodedCertChain, second_key.encodedCertChain);
-    }
-
-    #[test]
-    fn test_get_rkpd_attestation_key_different_caller() {
-        binder::ProcessState::start_thread_pool();
-        let first_key_id = get_next_key_id();
-        let second_key_id = get_next_key_id();
-
-        // Different callers should be getting different keys.
-        let first_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, first_key_id).unwrap();
-        let second_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, second_key_id).unwrap();
-
-        assert_ne!(first_key.keyBlob, second_key.keyBlob);
-        assert_ne!(first_key.encodedCertChain, second_key.encodedCertChain);
-    }
-
-    #[test]
-    // Couple of things to note:
-    // 1. This test must never run with UID of keystore. Otherwise, it can mess up keys stored by
-    //    keystore.
-    // 2. Storing and reading the stored key is prone to race condition. So, we only do this in one
-    //    test case.
-    fn test_store_rkpd_attestation_key() {
-        binder::ProcessState::start_thread_pool();
-        let key_id = get_next_key_id();
-        let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
-        let new_blob: [u8; 8] = rand::random();
-
-        assert!(
-            store_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, &key.keyBlob, &new_blob).is_ok()
-        );
-
-        let new_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
-
-        // Restore original key so that we don't leave RKPD with invalid blobs.
-        assert!(
-            store_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, &new_blob, &key.keyBlob).is_ok()
-        );
-        assert_eq!(new_key.keyBlob, new_blob);
-    }
-
-    #[test]
-    fn test_stress_get_rkpd_attestation_key() {
-        binder::ProcessState::start_thread_pool();
-        let key_id = get_next_key_id();
-        let mut threads = vec![];
-        const NTHREADS: u32 = 10;
-        const NCALLS: u32 = 1000;
-
-        for _ in 0..NTHREADS {
-            threads.push(std::thread::spawn(move || {
-                for _ in 0..NCALLS {
-                    let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
-                    assert!(!key.keyBlob.is_empty());
-                    assert!(!key.encodedCertChain.is_empty());
-                }
-            }));
-        }
-
-        for t in threads {
-            assert!(t.join().is_ok());
-        }
-    }
-}
+mod tests;
diff --git a/keystore2/rkpd_client/src/tests.rs b/keystore2/rkpd_client/src/tests.rs
new file mode 100644
index 00000000..fd0468f7
--- /dev/null
+++ b/keystore2/rkpd_client/src/tests.rs
@@ -0,0 +1,338 @@
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
+//! RKPD tests.
+
+use super::*;
+use android_security_rkp_aidl::aidl::android::security::rkp::IRegistration::BnRegistration;
+use std::sync::atomic::{AtomicU32, Ordering};
+use std::sync::{Arc, Mutex};
+
+const DEFAULT_RPC_SERVICE_NAME: &str =
+    "android.hardware.security.keymint.IRemotelyProvisionedComponent/default";
+
+struct MockRegistrationValues {
+    key: RemotelyProvisionedKey,
+    latency: Option<Duration>,
+    thread_join_handles: Vec<Option<std::thread::JoinHandle<()>>>,
+}
+
+struct MockRegistration(Arc<Mutex<MockRegistrationValues>>);
+
+impl MockRegistration {
+    pub fn new_native_binder(
+        key: &RemotelyProvisionedKey,
+        latency: Option<Duration>,
+    ) -> Strong<dyn IRegistration> {
+        let result = Self(Arc::new(Mutex::new(MockRegistrationValues {
+            key: RemotelyProvisionedKey {
+                keyBlob: key.keyBlob.clone(),
+                encodedCertChain: key.encodedCertChain.clone(),
+            },
+            latency,
+            thread_join_handles: Vec::new(),
+        })));
+        BnRegistration::new_binder(result, BinderFeatures::default())
+    }
+}
+
+impl Drop for MockRegistration {
+    fn drop(&mut self) {
+        let mut values = self.0.lock().unwrap();
+        for handle in values.thread_join_handles.iter_mut() {
+            // These are test threads. So, no need to worry too much about error handling.
+            handle.take().unwrap().join().unwrap();
+        }
+    }
+}
+
+impl Interface for MockRegistration {}
+
+impl IRegistration for MockRegistration {
+    fn getKey(&self, _: i32, cb: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
+        let mut values = self.0.lock().unwrap();
+        let key = RemotelyProvisionedKey {
+            keyBlob: values.key.keyBlob.clone(),
+            encodedCertChain: values.key.encodedCertChain.clone(),
+        };
+        let latency = values.latency;
+        let get_key_cb = cb.clone();
+
+        // Need a separate thread to trigger timeout in the caller.
+        let join_handle = std::thread::spawn(move || {
+            if let Some(duration) = latency {
+                std::thread::sleep(duration);
+            }
+            get_key_cb.onSuccess(&key).unwrap();
+        });
+        values.thread_join_handles.push(Some(join_handle));
+        Ok(())
+    }
+
+    fn cancelGetKey(&self, _: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
+        Ok(())
+    }
+
+    fn storeUpgradedKeyAsync(
+        &self,
+        _: &[u8],
+        _: &[u8],
+        cb: &Strong<dyn IStoreUpgradedKeyCallback>,
+    ) -> binder::Result<()> {
+        // We are primarily concerned with timing out correctly. Storing the key in this mock
+        // registration isn't particularly interesting, so skip that part.
+        let values = self.0.lock().unwrap();
+        let store_cb = cb.clone();
+        let latency = values.latency;
+
+        std::thread::spawn(move || {
+            if let Some(duration) = latency {
+                std::thread::sleep(duration);
+            }
+            store_cb.onSuccess().unwrap();
+        });
+        Ok(())
+    }
+}
+
+fn get_mock_registration(
+    key: &RemotelyProvisionedKey,
+    latency: Option<Duration>,
+) -> Result<binder::Strong<dyn IRegistration>> {
+    let (tx, rx) = oneshot::channel();
+    let cb = GetRegistrationCallback::new_native_binder(tx);
+    let mock_registration = MockRegistration::new_native_binder(key, latency);
+
+    assert!(cb.onSuccess(&mock_registration).is_ok());
+    tokio_rt().block_on(rx).unwrap()
+}
+
+// Using the same key ID makes test cases race with each other. So, we use separate key IDs for
+// different test cases.
+fn get_next_key_id() -> u32 {
+    static ID: AtomicU32 = AtomicU32::new(0);
+    ID.fetch_add(1, Ordering::Relaxed)
+}
+
+#[test]
+fn test_get_registration_cb_success() {
+    let key: RemotelyProvisionedKey = Default::default();
+    let registration = get_mock_registration(&key, /*latency=*/ None);
+    assert!(registration.is_ok());
+}
+
+#[test]
+fn test_get_registration_cb_cancel() {
+    let (tx, rx) = oneshot::channel();
+    let cb = GetRegistrationCallback::new_native_binder(tx);
+    assert!(cb.onCancel().is_ok());
+
+    let result = tokio_rt().block_on(rx).unwrap();
+    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RequestCancelled);
+}
+
+#[test]
+fn test_get_registration_cb_error() {
+    let (tx, rx) = oneshot::channel();
+    let cb = GetRegistrationCallback::new_native_binder(tx);
+    assert!(cb.onError("error").is_ok());
+
+    let result = tokio_rt().block_on(rx).unwrap();
+    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::GetRegistrationFailed);
+}
+
+#[test]
+fn test_get_key_cb_success() {
+    let mock_key =
+        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
+    let (tx, rx) = oneshot::channel();
+    let cb = GetKeyCallback::new_native_binder(tx);
+    assert!(cb.onSuccess(&mock_key).is_ok());
+
+    let key = tokio_rt().block_on(rx).unwrap().unwrap();
+    assert_eq!(key, mock_key);
+}
+
+#[test]
+fn test_get_key_cb_cancel() {
+    let (tx, rx) = oneshot::channel();
+    let cb = GetKeyCallback::new_native_binder(tx);
+    assert!(cb.onCancel().is_ok());
+
+    let result = tokio_rt().block_on(rx).unwrap();
+    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RequestCancelled);
+}
+
+#[test]
+fn test_get_key_cb_error() {
+    for get_key_error in GetKeyErrorCode::enum_values() {
+        let (tx, rx) = oneshot::channel();
+        let cb = GetKeyCallback::new_native_binder(tx);
+        assert!(cb.onError(get_key_error, "error").is_ok());
+
+        let result = tokio_rt().block_on(rx).unwrap();
+        assert_eq!(
+            result.unwrap_err().downcast::<Error>().unwrap(),
+            Error::GetKeyFailed(get_key_error),
+        );
+    }
+}
+
+#[test]
+fn test_store_upgraded_cb_success() {
+    let (tx, rx) = oneshot::channel();
+    let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
+    assert!(cb.onSuccess().is_ok());
+
+    tokio_rt().block_on(rx).unwrap().unwrap();
+}
+
+#[test]
+fn test_store_upgraded_key_cb_error() {
+    let (tx, rx) = oneshot::channel();
+    let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
+    assert!(cb.onError("oh no! it failed").is_ok());
+
+    let result = tokio_rt().block_on(rx).unwrap();
+    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::StoreUpgradedKeyFailed);
+}
+
+#[test]
+fn test_get_mock_key_success() {
+    let mock_key =
+        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
+    let registration = get_mock_registration(&mock_key, /*latency=*/ None).unwrap();
+
+    let key = tokio_rt()
+        .block_on(get_rkpd_attestation_key_from_registration_async(&registration, 0))
+        .unwrap();
+    assert_eq!(key, mock_key);
+}
+
+#[test]
+fn test_get_mock_key_timeout() {
+    let mock_key =
+        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
+    let latency = RKPD_TIMEOUT + Duration::from_secs(1);
+    let registration = get_mock_registration(&mock_key, Some(latency)).unwrap();
+
+    let result =
+        tokio_rt().block_on(get_rkpd_attestation_key_from_registration_async(&registration, 0));
+    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RetryableTimeout);
+}
+
+#[test]
+fn test_store_mock_key_success() {
+    let mock_key =
+        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
+    let registration = get_mock_registration(&mock_key, /*latency=*/ None).unwrap();
+    tokio_rt()
+        .block_on(store_rkpd_attestation_key_with_registration_async(&registration, &[], &[]))
+        .unwrap();
+}
+
+#[test]
+fn test_store_mock_key_timeout() {
+    let mock_key =
+        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
+    let latency = RKPD_TIMEOUT + Duration::from_secs(1);
+    let registration = get_mock_registration(&mock_key, Some(latency)).unwrap();
+
+    let result = tokio_rt().block_on(store_rkpd_attestation_key_with_registration_async(
+        &registration,
+        &[],
+        &[],
+    ));
+    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::Timeout);
+}
+
+#[test]
+fn test_get_rkpd_attestation_key() {
+    binder::ProcessState::start_thread_pool();
+    let key_id = get_next_key_id();
+    let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
+    assert!(!key.keyBlob.is_empty());
+    assert!(!key.encodedCertChain.is_empty());
+}
+
+#[test]
+fn test_get_rkpd_attestation_key_same_caller() {
+    binder::ProcessState::start_thread_pool();
+    let key_id = get_next_key_id();
+
+    // Multiple calls should return the same key.
+    let first_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
+    let second_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
+
+    assert_eq!(first_key.keyBlob, second_key.keyBlob);
+    assert_eq!(first_key.encodedCertChain, second_key.encodedCertChain);
+}
+
+#[test]
+fn test_get_rkpd_attestation_key_different_caller() {
+    binder::ProcessState::start_thread_pool();
+    let first_key_id = get_next_key_id();
+    let second_key_id = get_next_key_id();
+
+    // Different callers should be getting different keys.
+    let first_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, first_key_id).unwrap();
+    let second_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, second_key_id).unwrap();
+
+    assert_ne!(first_key.keyBlob, second_key.keyBlob);
+    assert_ne!(first_key.encodedCertChain, second_key.encodedCertChain);
+}
+
+#[test]
+// Couple of things to note:
+// 1. This test must never run with UID of keystore. Otherwise, it can mess up keys stored by
+//    keystore.
+// 2. Storing and reading the stored key is prone to race condition. So, we only do this in one
+//    test case.
+fn test_store_rkpd_attestation_key() {
+    binder::ProcessState::start_thread_pool();
+    let key_id = get_next_key_id();
+    let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
+    let new_blob: [u8; 8] = rand::random();
+
+    assert!(store_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, &key.keyBlob, &new_blob).is_ok());
+
+    let new_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
+
+    // Restore original key so that we don't leave RKPD with invalid blobs.
+    assert!(store_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, &new_blob, &key.keyBlob).is_ok());
+    assert_eq!(new_key.keyBlob, new_blob);
+}
+
+#[test]
+fn test_stress_get_rkpd_attestation_key() {
+    binder::ProcessState::start_thread_pool();
+    let key_id = get_next_key_id();
+    let mut threads = vec![];
+    const NTHREADS: u32 = 10;
+    const NCALLS: u32 = 1000;
+
+    for _ in 0..NTHREADS {
+        threads.push(std::thread::spawn(move || {
+            for _ in 0..NCALLS {
+                let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
+                assert!(!key.keyBlob.is_empty());
+                assert!(!key.encodedCertChain.is_empty());
+            }
+        }));
+    }
+
+    for t in threads {
+        assert!(t.join().is_ok());
+    }
+}
diff --git a/keystore2/selinux/Android.bp b/keystore2/selinux/Android.bp
index 254f95e7..8e644e64 100644
--- a/keystore2/selinux/Android.bp
+++ b/keystore2/selinux/Android.bp
@@ -34,7 +34,6 @@ rust_library {
 
     rustlibs: [
         "libanyhow",
-        "liblazy_static",
         "liblog_rust",
         "libselinux_bindgen",
         "libthiserror",
@@ -57,7 +56,6 @@ rust_test {
     rustlibs: [
         "libandroid_logger",
         "libanyhow",
-        "liblazy_static",
         "liblog_rust",
         "libselinux_bindgen",
         "libthiserror",
@@ -77,7 +75,6 @@ rust_test {
         "libandroid_logger",
         "libanyhow",
         "libkeystore2_selinux",
-        "liblazy_static",
         "liblog_rust",
         "libnix",
         "libnum_cpus",
diff --git a/keystore2/selinux/src/lib.rs b/keystore2/selinux/src/lib.rs
index 695e0291..d57a99af 100644
--- a/keystore2/selinux/src/lib.rs
+++ b/keystore2/selinux/src/lib.rs
@@ -18,6 +18,7 @@
 //!  * getcon
 //!  * selinux_check_access
 //!  * selabel_lookup for the keystore2_key backend.
+//!
 //! And it provides an owning wrapper around context strings `Context`.
 
 // TODO(b/290018030): Remove this and add proper safety comments.
@@ -25,7 +26,6 @@
 
 use anyhow::Context as AnyhowContext;
 use anyhow::{anyhow, Result};
-use lazy_static::lazy_static;
 pub use selinux::pid_t;
 use selinux::SELABEL_CTX_ANDROID_KEYSTORE2_KEY;
 use selinux::SELINUX_CB_LOG;
@@ -41,15 +41,13 @@ use std::sync;
 
 static SELINUX_LOG_INIT: sync::Once = sync::Once::new();
 
-lazy_static! {
-    /// `selinux_check_access` is only thread safe if avc_init was called with lock callbacks.
-    /// However, avc_init is deprecated and not exported by androids version of libselinux.
-    /// `selinux_set_callbacks` does not allow setting lock callbacks. So the only option
-    /// that remains right now is to put a big lock around calls into libselinux.
-    /// TODO b/188079221 It should suffice to protect `selinux_check_access` but until we are
-    /// certain of that, we leave the extra locks in place
-    static ref LIB_SELINUX_LOCK: sync::Mutex<()> = Default::default();
-}
+/// `selinux_check_access` is only thread safe if avc_init was called with lock callbacks.
+/// However, avc_init is deprecated and not exported by androids version of libselinux.
+/// `selinux_set_callbacks` does not allow setting lock callbacks. So the only option
+/// that remains right now is to put a big lock around calls into libselinux.
+/// TODO b/188079221 It should suffice to protect `selinux_check_access` but until we are
+/// certain of that, we leave the extra locks in place
+static LIB_SELINUX_LOCK: sync::Mutex<()> = sync::Mutex::new(());
 
 fn redirect_selinux_logs_to_logcat() {
     // `selinux_set_callback` assigns the static lifetime function pointer
diff --git a/keystore2/src/async_task.rs b/keystore2/src/async_task.rs
index 6548445f..16401a4e 100644
--- a/keystore2/src/async_task.rs
+++ b/keystore2/src/async_task.rs
@@ -27,6 +27,9 @@ use std::{
     thread,
 };
 
+#[cfg(test)]
+mod tests;
+
 #[derive(Debug, PartialEq, Eq)]
 enum State {
     Exiting,
@@ -256,279 +259,3 @@ impl AsyncTask {
         state.state = State::Running;
     }
 }
-
-#[cfg(test)]
-mod tests {
-    use super::{AsyncTask, Shelf};
-    use std::sync::{
-        mpsc::{channel, sync_channel, RecvTimeoutError},
-        Arc,
-    };
-    use std::time::Duration;
-
-    #[test]
-    fn test_shelf() {
-        let mut shelf = Shelf::default();
-
-        let s = "A string".to_string();
-        assert_eq!(shelf.put(s), None);
-
-        let s2 = "Another string".to_string();
-        assert_eq!(shelf.put(s2), Some("A string".to_string()));
-
-        // Put something of a different type on the shelf.
-        #[derive(Debug, PartialEq, Eq)]
-        struct Elf {
-            pub name: String,
-        }
-        let e1 = Elf { name: "Glorfindel".to_string() };
-        assert_eq!(shelf.put(e1), None);
-
-        // The String value is still on the shelf.
-        let s3 = shelf.get_downcast_ref::<String>().unwrap();
-        assert_eq!(s3, "Another string");
-
-        // As is the Elf.
-        {
-            let e2 = shelf.get_downcast_mut::<Elf>().unwrap();
-            assert_eq!(e2.name, "Glorfindel");
-            e2.name = "Celeborn".to_string();
-        }
-
-        // Take the Elf off the shelf.
-        let e3 = shelf.remove_downcast_ref::<Elf>().unwrap();
-        assert_eq!(e3.name, "Celeborn");
-
-        assert_eq!(shelf.remove_downcast_ref::<Elf>(), None);
-
-        // No u64 value has been put on the shelf, so getting one gives the default value.
-        {
-            let i = shelf.get_mut::<u64>();
-            assert_eq!(*i, 0);
-            *i = 42;
-        }
-        let i2 = shelf.get_downcast_ref::<u64>().unwrap();
-        assert_eq!(*i2, 42);
-
-        // No i32 value has ever been seen near the shelf.
-        assert_eq!(shelf.get_downcast_ref::<i32>(), None);
-        assert_eq!(shelf.get_downcast_mut::<i32>(), None);
-        assert_eq!(shelf.remove_downcast_ref::<i32>(), None);
-    }
-
-    #[test]
-    fn test_async_task() {
-        let at = AsyncTask::default();
-
-        // First queue up a job that blocks until we release it, to avoid
-        // unpredictable synchronization.
-        let (start_sender, start_receiver) = channel();
-        at.queue_hi(move |shelf| {
-            start_receiver.recv().unwrap();
-            // Put a trace vector on the shelf
-            shelf.put(Vec::<String>::new());
-        });
-
-        // Queue up some high-priority and low-priority jobs.
-        for i in 0..3 {
-            let j = i;
-            at.queue_lo(move |shelf| {
-                let trace = shelf.get_mut::<Vec<String>>();
-                trace.push(format!("L{}", j));
-            });
-            let j = i;
-            at.queue_hi(move |shelf| {
-                let trace = shelf.get_mut::<Vec<String>>();
-                trace.push(format!("H{}", j));
-            });
-        }
-
-        // Finally queue up a low priority job that emits the trace.
-        let (trace_sender, trace_receiver) = channel();
-        at.queue_lo(move |shelf| {
-            let trace = shelf.get_downcast_ref::<Vec<String>>().unwrap();
-            trace_sender.send(trace.clone()).unwrap();
-        });
-
-        // Ready, set, go.
-        start_sender.send(()).unwrap();
-        let trace = trace_receiver.recv().unwrap();
-
-        assert_eq!(trace, vec!["H0", "H1", "H2", "L0", "L1", "L2"]);
-    }
-
-    #[test]
-    fn test_async_task_chain() {
-        let at = Arc::new(AsyncTask::default());
-        let (sender, receiver) = channel();
-        // Queue up a job that will queue up another job. This confirms
-        // that the job is not invoked with any internal AsyncTask locks held.
-        let at_clone = at.clone();
-        at.queue_hi(move |_shelf| {
-            at_clone.queue_lo(move |_shelf| {
-                sender.send(()).unwrap();
-            });
-        });
-        receiver.recv().unwrap();
-    }
-
-    #[test]
-    #[should_panic]
-    fn test_async_task_panic() {
-        let at = AsyncTask::default();
-        at.queue_hi(|_shelf| {
-            panic!("Panic from queued job");
-        });
-        // Queue another job afterwards to ensure that the async thread gets joined.
-        let (done_sender, done_receiver) = channel();
-        at.queue_hi(move |_shelf| {
-            done_sender.send(()).unwrap();
-        });
-        done_receiver.recv().unwrap();
-    }
-
-    #[test]
-    fn test_async_task_idle() {
-        let at = AsyncTask::new(Duration::from_secs(3));
-        // Need a SyncSender as it is Send+Sync.
-        let (idle_done_sender, idle_done_receiver) = sync_channel::<()>(3);
-        at.add_idle(move |_shelf| {
-            idle_done_sender.send(()).unwrap();
-        });
-
-        // Queue up some high-priority and low-priority jobs that take time.
-        for _i in 0..3 {
-            at.queue_lo(|_shelf| {
-                std::thread::sleep(Duration::from_millis(500));
-            });
-            at.queue_hi(|_shelf| {
-                std::thread::sleep(Duration::from_millis(500));
-            });
-        }
-        // Final low-priority job.
-        let (done_sender, done_receiver) = channel();
-        at.queue_lo(move |_shelf| {
-            done_sender.send(()).unwrap();
-        });
-
-        // Nothing happens until the last job completes.
-        assert_eq!(
-            idle_done_receiver.recv_timeout(Duration::from_secs(1)),
-            Err(RecvTimeoutError::Timeout)
-        );
-        done_receiver.recv().unwrap();
-        // Now that the last low-priority job has completed, the idle task should
-        // fire pretty much immediately.
-        idle_done_receiver.recv_timeout(Duration::from_millis(50)).unwrap();
-
-        // Idle callback not executed again even if we wait for a while.
-        assert_eq!(
-            idle_done_receiver.recv_timeout(Duration::from_secs(3)),
-            Err(RecvTimeoutError::Timeout)
-        );
-
-        // However, if more work is done then there's another chance to go idle.
-        let (done_sender, done_receiver) = channel();
-        at.queue_hi(move |_shelf| {
-            std::thread::sleep(Duration::from_millis(500));
-            done_sender.send(()).unwrap();
-        });
-        // Idle callback not immediately executed, because the high priority
-        // job is taking a while.
-        assert_eq!(
-            idle_done_receiver.recv_timeout(Duration::from_millis(1)),
-            Err(RecvTimeoutError::Timeout)
-        );
-        done_receiver.recv().unwrap();
-        idle_done_receiver.recv_timeout(Duration::from_millis(50)).unwrap();
-    }
-
-    #[test]
-    fn test_async_task_multiple_idle() {
-        let at = AsyncTask::new(Duration::from_secs(3));
-        let (idle_sender, idle_receiver) = sync_channel::<i32>(5);
-        // Queue a high priority job to start things off
-        at.queue_hi(|_shelf| {
-            std::thread::sleep(Duration::from_millis(500));
-        });
-
-        // Multiple idle callbacks.
-        for i in 0..3 {
-            let idle_sender = idle_sender.clone();
-            at.add_idle(move |_shelf| {
-                idle_sender.send(i).unwrap();
-            });
-        }
-
-        // Nothing happens immediately.
-        assert_eq!(
-            idle_receiver.recv_timeout(Duration::from_millis(1)),
-            Err(RecvTimeoutError::Timeout)
-        );
-        // Wait for a moment and the idle jobs should have run.
-        std::thread::sleep(Duration::from_secs(1));
-
-        let mut results = Vec::new();
-        while let Ok(i) = idle_receiver.recv_timeout(Duration::from_millis(1)) {
-            results.push(i);
-        }
-        assert_eq!(results, [0, 1, 2]);
-    }
-
-    #[test]
-    fn test_async_task_idle_queues_job() {
-        let at = Arc::new(AsyncTask::new(Duration::from_secs(1)));
-        let at_clone = at.clone();
-        let (idle_sender, idle_receiver) = sync_channel::<i32>(100);
-        // Add an idle callback that queues a low-priority job.
-        at.add_idle(move |shelf| {
-            at_clone.queue_lo(|_shelf| {
-                // Slow things down so the channel doesn't fill up.
-                std::thread::sleep(Duration::from_millis(50));
-            });
-            let i = shelf.get_mut::<i32>();
-            idle_sender.send(*i).unwrap();
-            *i += 1;
-        });
-
-        // Nothing happens immediately.
-        assert_eq!(
-            idle_receiver.recv_timeout(Duration::from_millis(1500)),
-            Err(RecvTimeoutError::Timeout)
-        );
-
-        // Once we queue a normal job, things start.
-        at.queue_hi(|_shelf| {});
-        assert_eq!(0, idle_receiver.recv_timeout(Duration::from_millis(200)).unwrap());
-
-        // The idle callback queues a job, and completion of that job
-        // means the task is going idle again...so the idle callback will
-        // be called repeatedly.
-        assert_eq!(1, idle_receiver.recv_timeout(Duration::from_millis(100)).unwrap());
-        assert_eq!(2, idle_receiver.recv_timeout(Duration::from_millis(100)).unwrap());
-        assert_eq!(3, idle_receiver.recv_timeout(Duration::from_millis(100)).unwrap());
-    }
-
-    #[test]
-    #[should_panic]
-    fn test_async_task_idle_panic() {
-        let at = AsyncTask::new(Duration::from_secs(1));
-        let (idle_sender, idle_receiver) = sync_channel::<()>(3);
-        // Add an idle callback that panics.
-        at.add_idle(move |_shelf| {
-            idle_sender.send(()).unwrap();
-            panic!("Panic from idle callback");
-        });
-        // Queue a job to trigger idleness and ensuing panic.
-        at.queue_hi(|_shelf| {});
-        idle_receiver.recv().unwrap();
-
-        // Queue another job afterwards to ensure that the async thread gets joined
-        // and the panic detected.
-        let (done_sender, done_receiver) = channel();
-        at.queue_hi(move |_shelf| {
-            done_sender.send(()).unwrap();
-        });
-        done_receiver.recv().unwrap();
-    }
-}
diff --git a/keystore2/src/async_task/tests.rs b/keystore2/src/async_task/tests.rs
new file mode 100644
index 00000000..e67303e6
--- /dev/null
+++ b/keystore2/src/async_task/tests.rs
@@ -0,0 +1,287 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Async task tests.
+use super::{AsyncTask, Shelf};
+use std::sync::{
+    mpsc::{channel, sync_channel, RecvTimeoutError},
+    Arc,
+};
+use std::time::Duration;
+
+#[test]
+fn test_shelf() {
+    let mut shelf = Shelf::default();
+
+    let s = "A string".to_string();
+    assert_eq!(shelf.put(s), None);
+
+    let s2 = "Another string".to_string();
+    assert_eq!(shelf.put(s2), Some("A string".to_string()));
+
+    // Put something of a different type on the shelf.
+    #[derive(Debug, PartialEq, Eq)]
+    struct Elf {
+        pub name: String,
+    }
+    let e1 = Elf { name: "Glorfindel".to_string() };
+    assert_eq!(shelf.put(e1), None);
+
+    // The String value is still on the shelf.
+    let s3 = shelf.get_downcast_ref::<String>().unwrap();
+    assert_eq!(s3, "Another string");
+
+    // As is the Elf.
+    {
+        let e2 = shelf.get_downcast_mut::<Elf>().unwrap();
+        assert_eq!(e2.name, "Glorfindel");
+        e2.name = "Celeborn".to_string();
+    }
+
+    // Take the Elf off the shelf.
+    let e3 = shelf.remove_downcast_ref::<Elf>().unwrap();
+    assert_eq!(e3.name, "Celeborn");
+
+    assert_eq!(shelf.remove_downcast_ref::<Elf>(), None);
+
+    // No u64 value has been put on the shelf, so getting one gives the default value.
+    {
+        let i = shelf.get_mut::<u64>();
+        assert_eq!(*i, 0);
+        *i = 42;
+    }
+    let i2 = shelf.get_downcast_ref::<u64>().unwrap();
+    assert_eq!(*i2, 42);
+
+    // No i32 value has ever been seen near the shelf.
+    assert_eq!(shelf.get_downcast_ref::<i32>(), None);
+    assert_eq!(shelf.get_downcast_mut::<i32>(), None);
+    assert_eq!(shelf.remove_downcast_ref::<i32>(), None);
+}
+
+#[test]
+fn test_async_task() {
+    let at = AsyncTask::default();
+
+    // First queue up a job that blocks until we release it, to avoid
+    // unpredictable synchronization.
+    let (start_sender, start_receiver) = channel();
+    at.queue_hi(move |shelf| {
+        start_receiver.recv().unwrap();
+        // Put a trace vector on the shelf
+        shelf.put(Vec::<String>::new());
+    });
+
+    // Queue up some high-priority and low-priority jobs.
+    for i in 0..3 {
+        let j = i;
+        at.queue_lo(move |shelf| {
+            let trace = shelf.get_mut::<Vec<String>>();
+            trace.push(format!("L{}", j));
+        });
+        let j = i;
+        at.queue_hi(move |shelf| {
+            let trace = shelf.get_mut::<Vec<String>>();
+            trace.push(format!("H{}", j));
+        });
+    }
+
+    // Finally queue up a low priority job that emits the trace.
+    let (trace_sender, trace_receiver) = channel();
+    at.queue_lo(move |shelf| {
+        let trace = shelf.get_downcast_ref::<Vec<String>>().unwrap();
+        trace_sender.send(trace.clone()).unwrap();
+    });
+
+    // Ready, set, go.
+    start_sender.send(()).unwrap();
+    let trace = trace_receiver.recv().unwrap();
+
+    assert_eq!(trace, vec!["H0", "H1", "H2", "L0", "L1", "L2"]);
+}
+
+#[test]
+fn test_async_task_chain() {
+    let at = Arc::new(AsyncTask::default());
+    let (sender, receiver) = channel();
+    // Queue up a job that will queue up another job. This confirms
+    // that the job is not invoked with any internal AsyncTask locks held.
+    let at_clone = at.clone();
+    at.queue_hi(move |_shelf| {
+        at_clone.queue_lo(move |_shelf| {
+            sender.send(()).unwrap();
+        });
+    });
+    receiver.recv().unwrap();
+}
+
+#[test]
+#[should_panic]
+fn test_async_task_panic() {
+    let at = AsyncTask::default();
+    at.queue_hi(|_shelf| {
+        panic!("Panic from queued job");
+    });
+    // Queue another job afterwards to ensure that the async thread gets joined.
+    let (done_sender, done_receiver) = channel();
+    at.queue_hi(move |_shelf| {
+        done_sender.send(()).unwrap();
+    });
+    done_receiver.recv().unwrap();
+}
+
+#[test]
+fn test_async_task_idle() {
+    let at = AsyncTask::new(Duration::from_secs(3));
+    // Need a SyncSender as it is Send+Sync.
+    let (idle_done_sender, idle_done_receiver) = sync_channel::<()>(3);
+    at.add_idle(move |_shelf| {
+        idle_done_sender.send(()).unwrap();
+    });
+
+    // Queue up some high-priority and low-priority jobs that take time.
+    for _i in 0..3 {
+        at.queue_lo(|_shelf| {
+            std::thread::sleep(Duration::from_millis(500));
+        });
+        at.queue_hi(|_shelf| {
+            std::thread::sleep(Duration::from_millis(500));
+        });
+    }
+    // Final low-priority job.
+    let (done_sender, done_receiver) = channel();
+    at.queue_lo(move |_shelf| {
+        done_sender.send(()).unwrap();
+    });
+
+    // Nothing happens until the last job completes.
+    assert_eq!(
+        idle_done_receiver.recv_timeout(Duration::from_secs(1)),
+        Err(RecvTimeoutError::Timeout)
+    );
+    done_receiver.recv().unwrap();
+    // Now that the last low-priority job has completed, the idle task should
+    // fire pretty much immediately.
+    idle_done_receiver.recv_timeout(Duration::from_millis(50)).unwrap();
+
+    // Idle callback not executed again even if we wait for a while.
+    assert_eq!(
+        idle_done_receiver.recv_timeout(Duration::from_secs(3)),
+        Err(RecvTimeoutError::Timeout)
+    );
+
+    // However, if more work is done then there's another chance to go idle.
+    let (done_sender, done_receiver) = channel();
+    at.queue_hi(move |_shelf| {
+        std::thread::sleep(Duration::from_millis(500));
+        done_sender.send(()).unwrap();
+    });
+    // Idle callback not immediately executed, because the high priority
+    // job is taking a while.
+    assert_eq!(
+        idle_done_receiver.recv_timeout(Duration::from_millis(1)),
+        Err(RecvTimeoutError::Timeout)
+    );
+    done_receiver.recv().unwrap();
+    idle_done_receiver.recv_timeout(Duration::from_millis(50)).unwrap();
+}
+
+#[test]
+fn test_async_task_multiple_idle() {
+    let at = AsyncTask::new(Duration::from_secs(3));
+    let (idle_sender, idle_receiver) = sync_channel::<i32>(5);
+    // Queue a high priority job to start things off
+    at.queue_hi(|_shelf| {
+        std::thread::sleep(Duration::from_millis(500));
+    });
+
+    // Multiple idle callbacks.
+    for i in 0..3 {
+        let idle_sender = idle_sender.clone();
+        at.add_idle(move |_shelf| {
+            idle_sender.send(i).unwrap();
+        });
+    }
+
+    // Nothing happens immediately.
+    assert_eq!(
+        idle_receiver.recv_timeout(Duration::from_millis(1)),
+        Err(RecvTimeoutError::Timeout)
+    );
+    // Wait for a moment and the idle jobs should have run.
+    std::thread::sleep(Duration::from_secs(1));
+
+    let mut results = Vec::new();
+    while let Ok(i) = idle_receiver.recv_timeout(Duration::from_millis(1)) {
+        results.push(i);
+    }
+    assert_eq!(results, [0, 1, 2]);
+}
+
+#[test]
+fn test_async_task_idle_queues_job() {
+    let at = Arc::new(AsyncTask::new(Duration::from_secs(1)));
+    let at_clone = at.clone();
+    let (idle_sender, idle_receiver) = sync_channel::<i32>(100);
+    // Add an idle callback that queues a low-priority job.
+    at.add_idle(move |shelf| {
+        at_clone.queue_lo(|_shelf| {
+            // Slow things down so the channel doesn't fill up.
+            std::thread::sleep(Duration::from_millis(50));
+        });
+        let i = shelf.get_mut::<i32>();
+        idle_sender.send(*i).unwrap();
+        *i += 1;
+    });
+
+    // Nothing happens immediately.
+    assert_eq!(
+        idle_receiver.recv_timeout(Duration::from_millis(1500)),
+        Err(RecvTimeoutError::Timeout)
+    );
+
+    // Once we queue a normal job, things start.
+    at.queue_hi(|_shelf| {});
+    assert_eq!(0, idle_receiver.recv_timeout(Duration::from_millis(200)).unwrap());
+
+    // The idle callback queues a job, and completion of that job
+    // means the task is going idle again...so the idle callback will
+    // be called repeatedly.
+    assert_eq!(1, idle_receiver.recv_timeout(Duration::from_millis(100)).unwrap());
+    assert_eq!(2, idle_receiver.recv_timeout(Duration::from_millis(100)).unwrap());
+    assert_eq!(3, idle_receiver.recv_timeout(Duration::from_millis(100)).unwrap());
+}
+
+#[test]
+#[should_panic]
+fn test_async_task_idle_panic() {
+    let at = AsyncTask::new(Duration::from_secs(1));
+    let (idle_sender, idle_receiver) = sync_channel::<()>(3);
+    // Add an idle callback that panics.
+    at.add_idle(move |_shelf| {
+        idle_sender.send(()).unwrap();
+        panic!("Panic from idle callback");
+    });
+    // Queue a job to trigger idleness and ensuing panic.
+    at.queue_hi(|_shelf| {});
+    idle_receiver.recv().unwrap();
+
+    // Queue another job afterwards to ensure that the async thread gets joined
+    // and the panic detected.
+    let (done_sender, done_receiver) = channel();
+    at.queue_hi(move |_shelf| {
+        done_sender.send(()).unwrap();
+    });
+    done_receiver.recv().unwrap();
+}
diff --git a/keystore2/src/audit_log.rs b/keystore2/src/audit_log.rs
index 8d9735e2..4952b3bf 100644
--- a/keystore2/src/audit_log.rs
+++ b/keystore2/src/audit_log.rs
@@ -34,8 +34,8 @@ fn key_owner(domain: Domain, nspace: i64, uid: i32) -> i32 {
     match domain {
         Domain::APP => uid,
         Domain::SELINUX => (nspace | FLAG_NAMESPACE) as i32,
-        _ => {
-            log::info!("Not logging audit event for key with unexpected domain");
+        d => {
+            log::info!("Not logging audit event for key with domain {d:?}");
             0
         }
     }
diff --git a/keystore2/src/authorization.rs b/keystore2/src/authorization.rs
index 5a3fdbcb..c76f86b0 100644
--- a/keystore2/src/authorization.rs
+++ b/keystore2/src/authorization.rs
@@ -150,7 +150,7 @@ impl AuthorizationManager {
         &self,
         user_id: i32,
         unlocking_sids: &[i64],
-        mut weak_unlock_enabled: bool,
+        weak_unlock_enabled: bool,
     ) -> Result<()> {
         log::info!(
             "on_device_locked(user_id={}, unlocking_sids={:?}, weak_unlock_enabled={})",
@@ -158,9 +158,6 @@ impl AuthorizationManager {
             unlocking_sids,
             weak_unlock_enabled
         );
-        if !android_security_flags::fix_unlocked_device_required_keys_v2() {
-            weak_unlock_enabled = false;
-        }
         check_keystore_permission(KeystorePerm::Lock)
             .context(ks_err!("caller missing Lock permission"))?;
         ENFORCEMENTS.set_device_locked(user_id, true);
@@ -178,9 +175,6 @@ impl AuthorizationManager {
 
     fn on_weak_unlock_methods_expired(&self, user_id: i32) -> Result<()> {
         log::info!("on_weak_unlock_methods_expired(user_id={})", user_id);
-        if !android_security_flags::fix_unlocked_device_required_keys_v2() {
-            return Ok(());
-        }
         check_keystore_permission(KeystorePerm::Lock)
             .context(ks_err!("caller missing Lock permission"))?;
         SUPER_KEY.write().unwrap().wipe_plaintext_unlocked_device_required_keys(user_id as u32);
@@ -189,9 +183,6 @@ impl AuthorizationManager {
 
     fn on_non_lskf_unlock_methods_expired(&self, user_id: i32) -> Result<()> {
         log::info!("on_non_lskf_unlock_methods_expired(user_id={})", user_id);
-        if !android_security_flags::fix_unlocked_device_required_keys_v2() {
-            return Ok(());
-        }
         check_keystore_permission(KeystorePerm::Lock)
             .context(ks_err!("caller missing Lock permission"))?;
         SUPER_KEY.write().unwrap().wipe_all_unlocked_device_required_keys(user_id as u32);
diff --git a/keystore2/src/crypto/tests/certificate_utils_test.cpp b/keystore2/src/crypto/tests/certificate_utils_test.cpp
index a8517987..e2f7cdb8 100644
--- a/keystore2/src/crypto/tests/certificate_utils_test.cpp
+++ b/keystore2/src/crypto/tests/certificate_utils_test.cpp
@@ -14,9 +14,8 @@
  * limitations under the License.
  */
 
-#include <gtest/gtest.h>
-
 #include "certificate_utils.h"
+#include <gtest/gtest.h>
 
 #include <openssl/err.h>
 #include <openssl/evp.h>
@@ -231,6 +230,72 @@ static std::string paramsToStringRsa(testing::TestParamInfo<RsaParams> param) {
     return s.str();
 }
 
+static std::optional<std::vector<uint8_t>> EncodeX509Algor(const X509_ALGOR* alg) {
+    uint8_t* der = nullptr;
+    int der_len = i2d_X509_ALGOR(alg, &der);
+    if (der_len < 0) {
+        return std::nullopt;
+    }
+    std::vector<uint8_t> ret(der, der + der_len);
+    OPENSSL_free(der);
+    return ret;
+}
+
+// `x509_verify` not working with RSA-PSS & SHA1/SHA224 digests. so, manually
+// verify the certificate with RSA-PSS & SHA1/SHA224 digests.
+// BoringSSL after https://boringssl-review.googlesource.com/c/boringssl/+/53865
+// does not support RSA-PSS with SHA1/SHA224 digests.
+static void verifyCertFieldsExplicitly(X509* cert, Digest digest) {
+    // RSA-PSS-SHA1 AlgorithmIdentifier DER encoded value
+    const std::vector<uint8_t> expected_rsa_pss_sha1 = {
+        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x00,
+    };
+    // RSA-PSS-SHA224 AlgorithmIdentifier DER encoded value
+    const std::vector<uint8_t> expected_rsa_pss_sha224 = {
+        0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
+        0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
+        0x02, 0x04, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
+        0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
+        0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x1c,
+    };
+    const X509_ALGOR* alg;
+    const ASN1_BIT_STRING* sig;
+    const EVP_MD* evp_digest;
+    X509_get0_signature(&sig, &alg, cert);
+    auto encoded = EncodeX509Algor(alg);
+    ASSERT_TRUE(encoded);
+
+    // Check the AlgorithmIdentifiers.
+    if (digest == Digest::SHA1) {
+        evp_digest = EVP_sha1();
+        EXPECT_EQ(encoded.value(), expected_rsa_pss_sha1);
+    } else if (digest == Digest::SHA224) {
+        evp_digest = EVP_sha224();
+        EXPECT_EQ(encoded.value(), expected_rsa_pss_sha224);
+    } else {
+        GTEST_FAIL()
+            << "Error: This is expected to be used only for RSA-PSS with SHA1/SHA224 as digests";
+    }
+
+    // Check the signature.
+    EVP_PKEY_Ptr pubkey(X509_get_pubkey(cert));
+    ASSERT_TRUE(pubkey);
+
+    uint8_t* tbs = nullptr;
+    int tbs_len = i2d_X509_tbs(cert, &tbs);
+    ASSERT_GT(tbs_len, 0);
+
+    size_t sig_len;
+    ASSERT_TRUE(ASN1_BIT_STRING_num_bytes(sig, &sig_len));
+    EVP_PKEY_CTX* pctx;
+    bssl::ScopedEVP_MD_CTX ctx;
+    ASSERT_TRUE(EVP_DigestVerifyInit(ctx.get(), &pctx, evp_digest, nullptr, pubkey.get()));
+    ASSERT_TRUE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING));
+    // The salt length should match the digest length.
+    ASSERT_TRUE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1));
+    EXPECT_TRUE(EVP_DigestVerify(ctx.get(), ASN1_STRING_get0_data(sig), sig_len, tbs, tbs_len));
+}
+
 INSTANTIATE_TEST_SUITE_P(CertSigningWithCallbackRsa, CertificateUtilsWithRsa,
                          testing::Combine(testing::ValuesIn(rsa_key_sizes),
                                           testing::ValuesIn(rsa_paddings),
@@ -315,10 +380,10 @@ TEST_P(CertificateUtilsWithRsa, CertSigningWithCallbackRsa) {
     EVP_PKEY_Ptr decoded_pkey(X509_get_pubkey(decoded_cert.get()));
     if ((padding == Padding::PSS) && (digest == Digest::SHA1 || digest == Digest::SHA224)) {
         // BoringSSL after https://boringssl-review.googlesource.com/c/boringssl/+/53865
-        // does not support these PSS combinations, so skip certificate verification for them
-        // and just check _something_ was returned.
+        // does not support these PSS combinations, so verify these certificates manually.
         EXPECT_NE(decoded_cert.get(), nullptr);
         EXPECT_NE(decoded_pkey.get(), nullptr);
+        verifyCertFieldsExplicitly(decoded_cert.get(), digest);
     } else {
         ASSERT_TRUE(X509_verify(decoded_cert.get(), decoded_pkey.get()));
     }
diff --git a/keystore2/src/database.rs b/keystore2/src/database.rs
index 50cd3ba8..84576034 100644
--- a/keystore2/src/database.rs
+++ b/keystore2/src/database.rs
@@ -45,8 +45,11 @@ mod perboot;
 pub(crate) mod utils;
 mod versioning;
 
+#[cfg(test)]
+pub mod tests;
+
 use crate::gc::Gc;
-use crate::impl_metadata; // This is in db_utils.rs
+use crate::impl_metadata; // This is in database/utils.rs
 use crate::key_parameter::{KeyParameter, KeyParameterValue, Tag};
 use crate::ks_err;
 use crate::permission::KeyPermSet;
@@ -67,12 +70,11 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 };
 use anyhow::{anyhow, Context, Result};
 use keystore2_flags;
-use std::{convert::TryFrom, convert::TryInto, ops::Deref, time::SystemTimeError};
+use std::{convert::TryFrom, convert::TryInto, ops::Deref, sync::LazyLock, time::SystemTimeError};
 use utils as db_utils;
 use utils::SqlField;
 
 use keystore2_crypto::ZVec;
-use lazy_static::lazy_static;
 use log::error;
 #[cfg(not(test))]
 use rand::prelude::random;
@@ -125,21 +127,6 @@ impl TransactionBehavior {
 
 /// If the database returns a busy error code, retry after this interval.
 const DB_BUSY_RETRY_INTERVAL: Duration = Duration::from_micros(500);
-/// If the database returns a busy error code, keep retrying for this long.
-const MAX_DB_BUSY_RETRY_PERIOD: Duration = Duration::from_secs(15);
-
-/// Check whether a database lock has timed out.
-fn check_lock_timeout(start: &std::time::Instant, timeout: Duration) -> Result<()> {
-    if keystore2_flags::database_loop_timeout() {
-        let elapsed = start.elapsed();
-        if elapsed >= timeout {
-            error!("Abandon locked DB after {elapsed:?}");
-            return Err(&KsError::Rc(ResponseCode::BACKEND_BUSY))
-                .context(ks_err!("Abandon locked DB after {elapsed:?}",));
-        }
-    }
-    Ok(())
-}
 
 impl_metadata!(
     /// A set of metadata for key entries.
@@ -541,9 +528,7 @@ impl KeyEntryLoadBits {
     }
 }
 
-lazy_static! {
-    static ref KEY_ID_LOCK: KeyIdLockDb = KeyIdLockDb::new();
-}
+static KEY_ID_LOCK: LazyLock<KeyIdLockDb> = LazyLock::new(KeyIdLockDb::new);
 
 struct KeyIdLockDb {
     locked_keys: Mutex<HashSet<i64>>,
@@ -871,6 +856,18 @@ impl AuthTokenEntry {
     }
 }
 
+/// Information about a superseded blob (a blob that is no longer the
+/// most recent blob of that type for a given key, due to upgrade or
+/// replacement).
+pub struct SupersededBlob {
+    /// ID
+    pub blob_id: i64,
+    /// Contents.
+    pub blob: Vec<u8>,
+    /// Metadata.
+    pub metadata: BlobMetaData,
+}
+
 impl KeystoreDB {
     const UNASSIGNED_KEY_ID: i64 = -1i64;
     const CURRENT_DB_VERSION: u32 = 1;
@@ -1116,7 +1113,7 @@ impl KeystoreDB {
         )
     }
 
-    /// Fetches a storage statisitics atom for a given storage type. For storage
+    /// Fetches a storage statistics atom for a given storage type. For storage
     /// types that map to a table, information about the table's storage is
     /// returned. Requests for storage types that are not DB tables return None.
     pub fn get_storage_stat(&mut self, storage_type: MetricsStorage) -> Result<StorageStats> {
@@ -1182,7 +1179,7 @@ impl KeystoreDB {
         &mut self,
         blob_ids_to_delete: &[i64],
         max_blobs: usize,
-    ) -> Result<Vec<(i64, Vec<u8>, BlobMetaData)>> {
+    ) -> Result<Vec<SupersededBlob>> {
         let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob");
         self.with_transaction(Immediate("TX_handle_next_superseded_blob"), |tx| {
             // Delete the given blobs.
@@ -1198,8 +1195,9 @@ impl KeystoreDB {
 
             Self::cleanup_unreferenced(tx).context("Trying to cleanup unreferenced.")?;
 
-            // Find up to max_blobx more superseded key blobs, load their metadata and return it.
+            // Find up to `max_blobs` more superseded key blobs, load their metadata and return it.
             let result: Vec<(i64, Vec<u8>)> = {
+                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next");
                 let mut stmt = tx
                     .prepare(
                         "SELECT id, blob FROM persistent.blobentry
@@ -1230,12 +1228,17 @@ impl KeystoreDB {
                     .context("Trying to extract superseded blobs.")?
             };
 
+            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob load_metadata");
             let result = result
                 .into_iter()
                 .map(|(blob_id, blob)| {
-                    Ok((blob_id, blob, BlobMetaData::load_from_db(blob_id, tx)?))
+                    Ok(SupersededBlob {
+                        blob_id,
+                        blob,
+                        metadata: BlobMetaData::load_from_db(blob_id, tx)?,
+                    })
                 })
-                .collect::<Result<Vec<(i64, Vec<u8>, BlobMetaData)>>>()
+                .collect::<Result<Vec<_>>>()
                 .context("Trying to load blob metadata.")?;
             if !result.is_empty() {
                 return Ok(result).no_gc();
@@ -1243,6 +1246,7 @@ impl KeystoreDB {
 
             // We did not find any superseded key blob, so let's remove other superseded blob in
             // one transaction.
+            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete");
             tx.execute(
                 "DELETE FROM persistent.blobentry
                  WHERE NOT subcomponent_type = ?
@@ -1397,18 +1401,6 @@ impl KeystoreDB {
     where
         F: Fn(&Transaction) -> Result<(bool, T)>,
     {
-        self.with_transaction_timeout(behavior, MAX_DB_BUSY_RETRY_PERIOD, f)
-    }
-    fn with_transaction_timeout<T, F>(
-        &mut self,
-        behavior: TransactionBehavior,
-        timeout: Duration,
-        f: F,
-    ) -> Result<T>
-    where
-        F: Fn(&Transaction) -> Result<(bool, T)>,
-    {
-        let start = std::time::Instant::now();
         let name = behavior.name();
         loop {
             let result = self
@@ -1427,7 +1419,6 @@ impl KeystoreDB {
                 Ok(result) => break Ok(result),
                 Err(e) => {
                     if Self::is_locked_error(&e) {
-                        check_lock_timeout(&start, timeout)?;
                         std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                         continue;
                     } else {
@@ -1908,6 +1899,7 @@ impl KeystoreDB {
     ///       `access_vector`.
     /// * Domain::KEY_ID: The keyentry table is queried for the owning `domain` and
     ///       `namespace`.
+    ///
     /// In each case the information returned is sufficient to perform the access
     /// check and the key id can be used to load further key artifacts.
     fn load_access_tuple(
@@ -2156,7 +2148,6 @@ impl KeystoreDB {
         check_permission: impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
     ) -> Result<(KeyIdGuard, KeyEntry)> {
         let _wp = wd::watch("KeystoreDB::load_key_entry");
-        let start = std::time::Instant::now();
 
         loop {
             match self.load_key_entry_internal(
@@ -2169,7 +2160,6 @@ impl KeystoreDB {
                 Ok(result) => break Ok(result),
                 Err(e) => {
                     if Self::is_locked_error(&e) {
-                        check_lock_timeout(&start, MAX_DB_BUSY_RETRY_PERIOD)?;
                         std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                         continue;
                     } else {
@@ -2401,15 +2391,8 @@ impl KeystoreDB {
         .context(ks_err!())
     }
 
-    /// Delete the keys created on behalf of the user, denoted by the user id.
-    /// Delete all the keys unless 'keep_non_super_encrypted_keys' set to true.
-    /// Returned boolean is to hint the garbage collector to delete the unbound keys.
-    /// The caller of this function should notify the gc if the returned value is true.
-    pub fn unbind_keys_for_user(
-        &mut self,
-        user_id: u32,
-        keep_non_super_encrypted_keys: bool,
-    ) -> Result<()> {
+    /// Deletes all keys for the given user, including both client keys and super keys.
+    pub fn unbind_keys_for_user(&mut self, user_id: u32) -> Result<()> {
         let _wp = wd::watch("KeystoreDB::unbind_keys_for_user");
 
         self.with_transaction(Immediate("TX_unbind_keys_for_user"), |tx| {
@@ -2457,17 +2440,6 @@ impl KeystoreDB {
 
             let mut notify_gc = false;
             for key_id in key_ids {
-                if keep_non_super_encrypted_keys {
-                    // Load metadata and filter out non-super-encrypted keys.
-                    if let (_, Some((_, blob_metadata)), _, _) =
-                        Self::load_blob_components(key_id, KeyEntryLoadBits::KM, tx)
-                            .context(ks_err!("Trying to load blob info."))?
-                    {
-                        if blob_metadata.encrypted_by().is_none() {
-                            continue;
-                        }
-                    }
-                }
                 notify_gc = Self::mark_unreferenced(tx, key_id)
                     .context("In unbind_keys_for_user.")?
                     || notify_gc;
@@ -2893,2711 +2865,3 @@ impl KeystoreDB {
         Ok(app_uids_vec)
     }
 }
-
-#[cfg(test)]
-pub mod tests {
-
-    use super::*;
-    use crate::key_parameter::{
-        Algorithm, BlockMode, Digest, EcCurve, HardwareAuthenticatorType, KeyOrigin, KeyParameter,
-        KeyParameterValue, KeyPurpose, PaddingMode, SecurityLevel,
-    };
-    use crate::key_perm_set;
-    use crate::permission::{KeyPerm, KeyPermSet};
-    use crate::super_key::{SuperKeyManager, USER_AFTER_FIRST_UNLOCK_SUPER_KEY, SuperEncryptionAlgorithm, SuperKeyType};
-    use keystore2_test_utils::TempDir;
-    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-        HardwareAuthToken::HardwareAuthToken,
-        HardwareAuthenticatorType::HardwareAuthenticatorType as kmhw_authenticator_type,
-    };
-    use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
-        Timestamp::Timestamp,
-    };
-    use std::cell::RefCell;
-    use std::collections::BTreeMap;
-    use std::fmt::Write;
-    use std::sync::atomic::{AtomicU8, Ordering};
-    use std::sync::Arc;
-    use std::thread;
-    use std::time::{Duration, SystemTime};
-    use crate::utils::AesGcm;
-    #[cfg(disabled)]
-    use std::time::Instant;
-
-    pub fn new_test_db() -> Result<KeystoreDB> {
-        let conn = KeystoreDB::make_connection("file::memory:")?;
-
-        let mut db = KeystoreDB { conn, gc: None, perboot: Arc::new(perboot::PerbootDB::new()) };
-        db.with_transaction(Immediate("TX_new_test_db"), |tx| {
-            KeystoreDB::init_tables(tx).context("Failed to initialize tables.").no_gc()
-        })?;
-        Ok(db)
-    }
-
-    fn rebind_alias(
-        db: &mut KeystoreDB,
-        newid: &KeyIdGuard,
-        alias: &str,
-        domain: Domain,
-        namespace: i64,
-    ) -> Result<bool> {
-        db.with_transaction(Immediate("TX_rebind_alias"), |tx| {
-            KeystoreDB::rebind_alias(tx, newid, alias, &domain, &namespace, KeyType::Client).no_gc()
-        })
-        .context(ks_err!())
-    }
-
-    #[test]
-    fn datetime() -> Result<()> {
-        let conn = Connection::open_in_memory()?;
-        conn.execute("CREATE TABLE test (ts DATETIME);", [])?;
-        let now = SystemTime::now();
-        let duration = Duration::from_secs(1000);
-        let then = now.checked_sub(duration).unwrap();
-        let soon = now.checked_add(duration).unwrap();
-        conn.execute(
-            "INSERT INTO test (ts) VALUES (?), (?), (?);",
-            params![DateTime::try_from(now)?, DateTime::try_from(then)?, DateTime::try_from(soon)?],
-        )?;
-        let mut stmt = conn.prepare("SELECT ts FROM test ORDER BY ts ASC;")?;
-        let mut rows = stmt.query([])?;
-        assert_eq!(DateTime::try_from(then)?, rows.next()?.unwrap().get(0)?);
-        assert_eq!(DateTime::try_from(now)?, rows.next()?.unwrap().get(0)?);
-        assert_eq!(DateTime::try_from(soon)?, rows.next()?.unwrap().get(0)?);
-        assert!(rows.next()?.is_none());
-        assert!(DateTime::try_from(then)? < DateTime::try_from(now)?);
-        assert!(DateTime::try_from(then)? < DateTime::try_from(soon)?);
-        assert!(DateTime::try_from(now)? < DateTime::try_from(soon)?);
-        Ok(())
-    }
-
-    // Ensure that we're using the "injected" random function, not the real one.
-    #[test]
-    fn test_mocked_random() {
-        let rand1 = random();
-        let rand2 = random();
-        let rand3 = random();
-        if rand1 == rand2 {
-            assert_eq!(rand2 + 1, rand3);
-        } else {
-            assert_eq!(rand1 + 1, rand2);
-            assert_eq!(rand2, rand3);
-        }
-    }
-
-    // Test that we have the correct tables.
-    #[test]
-    fn test_tables() -> Result<()> {
-        let db = new_test_db()?;
-        let tables = db
-            .conn
-            .prepare("SELECT name from persistent.sqlite_master WHERE type='table' ORDER BY name;")?
-            .query_map(params![], |row| row.get(0))?
-            .collect::<rusqlite::Result<Vec<String>>>()?;
-        assert_eq!(tables.len(), 6);
-        assert_eq!(tables[0], "blobentry");
-        assert_eq!(tables[1], "blobmetadata");
-        assert_eq!(tables[2], "grant");
-        assert_eq!(tables[3], "keyentry");
-        assert_eq!(tables[4], "keymetadata");
-        assert_eq!(tables[5], "keyparameter");
-        Ok(())
-    }
-
-    #[test]
-    fn test_auth_token_table_invariant() -> Result<()> {
-        let mut db = new_test_db()?;
-        let auth_token1 = HardwareAuthToken {
-            challenge: i64::MAX,
-            userId: 200,
-            authenticatorId: 200,
-            authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
-            timestamp: Timestamp { milliSeconds: 500 },
-            mac: String::from("mac").into_bytes(),
-        };
-        db.insert_auth_token(&auth_token1);
-        let auth_tokens_returned = get_auth_tokens(&db);
-        assert_eq!(auth_tokens_returned.len(), 1);
-
-        // insert another auth token with the same values for the columns in the UNIQUE constraint
-        // of the auth token table and different value for timestamp
-        let auth_token2 = HardwareAuthToken {
-            challenge: i64::MAX,
-            userId: 200,
-            authenticatorId: 200,
-            authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
-            timestamp: Timestamp { milliSeconds: 600 },
-            mac: String::from("mac").into_bytes(),
-        };
-
-        db.insert_auth_token(&auth_token2);
-        let mut auth_tokens_returned = get_auth_tokens(&db);
-        assert_eq!(auth_tokens_returned.len(), 1);
-
-        if let Some(auth_token) = auth_tokens_returned.pop() {
-            assert_eq!(auth_token.auth_token.timestamp.milliSeconds, 600);
-        }
-
-        // insert another auth token with the different values for the columns in the UNIQUE
-        // constraint of the auth token table
-        let auth_token3 = HardwareAuthToken {
-            challenge: i64::MAX,
-            userId: 201,
-            authenticatorId: 200,
-            authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
-            timestamp: Timestamp { milliSeconds: 600 },
-            mac: String::from("mac").into_bytes(),
-        };
-
-        db.insert_auth_token(&auth_token3);
-        let auth_tokens_returned = get_auth_tokens(&db);
-        assert_eq!(auth_tokens_returned.len(), 2);
-
-        Ok(())
-    }
-
-    // utility function for test_auth_token_table_invariant()
-    fn get_auth_tokens(db: &KeystoreDB) -> Vec<AuthTokenEntry> {
-        db.perboot.get_all_auth_token_entries()
-    }
-
-    fn create_key_entry(
-        db: &mut KeystoreDB,
-        domain: &Domain,
-        namespace: &i64,
-        key_type: KeyType,
-        km_uuid: &Uuid,
-    ) -> Result<KeyIdGuard> {
-        db.with_transaction(Immediate("TX_create_key_entry"), |tx| {
-            KeystoreDB::create_key_entry_internal(tx, domain, namespace, key_type, km_uuid).no_gc()
-        })
-    }
-
-    #[test]
-    fn test_persistence_for_files() -> Result<()> {
-        let temp_dir = TempDir::new("persistent_db_test")?;
-        let mut db = KeystoreDB::new(temp_dir.path(), None)?;
-
-        create_key_entry(&mut db, &Domain::APP, &100, KeyType::Client, &KEYSTORE_UUID)?;
-        let entries = get_keyentry(&db)?;
-        assert_eq!(entries.len(), 1);
-
-        let db = KeystoreDB::new(temp_dir.path(), None)?;
-
-        let entries_new = get_keyentry(&db)?;
-        assert_eq!(entries, entries_new);
-        Ok(())
-    }
-
-    #[test]
-    fn test_create_key_entry() -> Result<()> {
-        fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>, Uuid) {
-            (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref(), ke.km_uuid.unwrap())
-        }
-
-        let mut db = new_test_db()?;
-
-        create_key_entry(&mut db, &Domain::APP, &100, KeyType::Client, &KEYSTORE_UUID)?;
-        create_key_entry(&mut db, &Domain::SELINUX, &101, KeyType::Client, &KEYSTORE_UUID)?;
-
-        let entries = get_keyentry(&db)?;
-        assert_eq!(entries.len(), 2);
-        assert_eq!(extractor(&entries[0]), (Domain::APP, 100, None, KEYSTORE_UUID));
-        assert_eq!(extractor(&entries[1]), (Domain::SELINUX, 101, None, KEYSTORE_UUID));
-
-        // Test that we must pass in a valid Domain.
-        check_result_is_error_containing_string(
-            create_key_entry(&mut db, &Domain::GRANT, &102, KeyType::Client, &KEYSTORE_UUID),
-            &format!("Domain {:?} must be either App or SELinux.", Domain::GRANT),
-        );
-        check_result_is_error_containing_string(
-            create_key_entry(&mut db, &Domain::BLOB, &103, KeyType::Client, &KEYSTORE_UUID),
-            &format!("Domain {:?} must be either App or SELinux.", Domain::BLOB),
-        );
-        check_result_is_error_containing_string(
-            create_key_entry(&mut db, &Domain::KEY_ID, &104, KeyType::Client, &KEYSTORE_UUID),
-            &format!("Domain {:?} must be either App or SELinux.", Domain::KEY_ID),
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_rebind_alias() -> Result<()> {
-        fn extractor(
-            ke: &KeyEntryRow,
-        ) -> (Option<Domain>, Option<i64>, Option<&str>, Option<Uuid>) {
-            (ke.domain, ke.namespace, ke.alias.as_deref(), ke.km_uuid)
-        }
-
-        let mut db = new_test_db()?;
-        create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
-        create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
-        let entries = get_keyentry(&db)?;
-        assert_eq!(entries.len(), 2);
-        assert_eq!(
-            extractor(&entries[0]),
-            (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID))
-        );
-        assert_eq!(
-            extractor(&entries[1]),
-            (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID))
-        );
-
-        // Test that the first call to rebind_alias sets the alias.
-        rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[0].id), "foo", Domain::APP, 42)?;
-        let entries = get_keyentry(&db)?;
-        assert_eq!(entries.len(), 2);
-        assert_eq!(
-            extractor(&entries[0]),
-            (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
-        );
-        assert_eq!(
-            extractor(&entries[1]),
-            (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID))
-        );
-
-        // Test that the second call to rebind_alias also empties the old one.
-        rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[1].id), "foo", Domain::APP, 42)?;
-        let entries = get_keyentry(&db)?;
-        assert_eq!(entries.len(), 2);
-        assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
-        assert_eq!(
-            extractor(&entries[1]),
-            (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
-        );
-
-        // Test that we must pass in a valid Domain.
-        check_result_is_error_containing_string(
-            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::GRANT, 42),
-            &format!("Domain {:?} must be either App or SELinux.", Domain::GRANT),
-        );
-        check_result_is_error_containing_string(
-            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::BLOB, 42),
-            &format!("Domain {:?} must be either App or SELinux.", Domain::BLOB),
-        );
-        check_result_is_error_containing_string(
-            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::KEY_ID, 42),
-            &format!("Domain {:?} must be either App or SELinux.", Domain::KEY_ID),
-        );
-
-        // Test that we correctly handle setting an alias for something that does not exist.
-        check_result_is_error_containing_string(
-            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::SELINUX, 42),
-            "Expected to update a single entry but instead updated 0",
-        );
-        // Test that we correctly abort the transaction in this case.
-        let entries = get_keyentry(&db)?;
-        assert_eq!(entries.len(), 2);
-        assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
-        assert_eq!(
-            extractor(&entries[1]),
-            (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_grant_ungrant() -> Result<()> {
-        const CALLER_UID: u32 = 15;
-        const GRANTEE_UID: u32 = 12;
-        const SELINUX_NAMESPACE: i64 = 7;
-
-        let mut db = new_test_db()?;
-        db.conn.execute(
-            "INSERT INTO persistent.keyentry (id, key_type, domain, namespace, alias, state, km_uuid)
-                VALUES (1, 0, 0, 15, 'key', 1, ?), (2, 0, 2, 7, 'yek', 1, ?);",
-            params![KEYSTORE_UUID, KEYSTORE_UUID],
-        )?;
-        let app_key = KeyDescriptor {
-            domain: super::Domain::APP,
-            nspace: 0,
-            alias: Some("key".to_string()),
-            blob: None,
-        };
-        const PVEC1: KeyPermSet = key_perm_set![KeyPerm::Use, KeyPerm::GetInfo];
-        const PVEC2: KeyPermSet = key_perm_set![KeyPerm::Use];
-
-        // Reset totally predictable random number generator in case we
-        // are not the first test running on this thread.
-        reset_random();
-        let next_random = 0i64;
-
-        let app_granted_key = db
-            .grant(&app_key, CALLER_UID, GRANTEE_UID, PVEC1, |k, a| {
-                assert_eq!(*a, PVEC1);
-                assert_eq!(
-                    *k,
-                    KeyDescriptor {
-                        domain: super::Domain::APP,
-                        // namespace must be set to the caller_uid.
-                        nspace: CALLER_UID as i64,
-                        alias: Some("key".to_string()),
-                        blob: None,
-                    }
-                );
-                Ok(())
-            })
-            .unwrap();
-
-        assert_eq!(
-            app_granted_key,
-            KeyDescriptor {
-                domain: super::Domain::GRANT,
-                // The grantid is next_random due to the mock random number generator.
-                nspace: next_random,
-                alias: None,
-                blob: None,
-            }
-        );
-
-        let selinux_key = KeyDescriptor {
-            domain: super::Domain::SELINUX,
-            nspace: SELINUX_NAMESPACE,
-            alias: Some("yek".to_string()),
-            blob: None,
-        };
-
-        let selinux_granted_key = db
-            .grant(&selinux_key, CALLER_UID, 12, PVEC1, |k, a| {
-                assert_eq!(*a, PVEC1);
-                assert_eq!(
-                    *k,
-                    KeyDescriptor {
-                        domain: super::Domain::SELINUX,
-                        // namespace must be the supplied SELinux
-                        // namespace.
-                        nspace: SELINUX_NAMESPACE,
-                        alias: Some("yek".to_string()),
-                        blob: None,
-                    }
-                );
-                Ok(())
-            })
-            .unwrap();
-
-        assert_eq!(
-            selinux_granted_key,
-            KeyDescriptor {
-                domain: super::Domain::GRANT,
-                // The grantid is next_random + 1 due to the mock random number generator.
-                nspace: next_random + 1,
-                alias: None,
-                blob: None,
-            }
-        );
-
-        // This should update the existing grant with PVEC2.
-        let selinux_granted_key = db
-            .grant(&selinux_key, CALLER_UID, 12, PVEC2, |k, a| {
-                assert_eq!(*a, PVEC2);
-                assert_eq!(
-                    *k,
-                    KeyDescriptor {
-                        domain: super::Domain::SELINUX,
-                        // namespace must be the supplied SELinux
-                        // namespace.
-                        nspace: SELINUX_NAMESPACE,
-                        alias: Some("yek".to_string()),
-                        blob: None,
-                    }
-                );
-                Ok(())
-            })
-            .unwrap();
-
-        assert_eq!(
-            selinux_granted_key,
-            KeyDescriptor {
-                domain: super::Domain::GRANT,
-                // Same grant id as before. The entry was only updated.
-                nspace: next_random + 1,
-                alias: None,
-                blob: None,
-            }
-        );
-
-        {
-            // Limiting scope of stmt, because it borrows db.
-            let mut stmt = db
-                .conn
-                .prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
-            let mut rows = stmt.query_map::<(i64, u32, i64, KeyPermSet), _, _>([], |row| {
-                Ok((row.get(0)?, row.get(1)?, row.get(2)?, KeyPermSet::from(row.get::<_, i32>(3)?)))
-            })?;
-
-            let r = rows.next().unwrap().unwrap();
-            assert_eq!(r, (next_random, GRANTEE_UID, 1, PVEC1));
-            let r = rows.next().unwrap().unwrap();
-            assert_eq!(r, (next_random + 1, GRANTEE_UID, 2, PVEC2));
-            assert!(rows.next().is_none());
-        }
-
-        debug_dump_keyentry_table(&mut db)?;
-        println!("app_key {:?}", app_key);
-        println!("selinux_key {:?}", selinux_key);
-
-        db.ungrant(&app_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
-        db.ungrant(&selinux_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
-
-        Ok(())
-    }
-
-    static TEST_KEY_BLOB: &[u8] = b"my test blob";
-    static TEST_CERT_BLOB: &[u8] = b"my test cert";
-    static TEST_CERT_CHAIN_BLOB: &[u8] = b"my test cert_chain";
-
-    #[test]
-    fn test_set_blob() -> Result<()> {
-        let key_id = KEY_ID_LOCK.get(3000);
-        let mut db = new_test_db()?;
-        let mut blob_metadata = BlobMetaData::new();
-        blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
-        db.set_blob(
-            &key_id,
-            SubComponentType::KEY_BLOB,
-            Some(TEST_KEY_BLOB),
-            Some(&blob_metadata),
-        )?;
-        db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
-        db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
-        drop(key_id);
-
-        let mut stmt = db.conn.prepare(
-            "SELECT subcomponent_type, keyentryid, blob, id FROM persistent.blobentry
-                ORDER BY subcomponent_type ASC;",
-        )?;
-        let mut rows = stmt
-            .query_map::<((SubComponentType, i64, Vec<u8>), i64), _, _>([], |row| {
-                Ok(((row.get(0)?, row.get(1)?, row.get(2)?), row.get(3)?))
-            })?;
-        let (r, id) = rows.next().unwrap().unwrap();
-        assert_eq!(r, (SubComponentType::KEY_BLOB, 3000, TEST_KEY_BLOB.to_vec()));
-        let (r, _) = rows.next().unwrap().unwrap();
-        assert_eq!(r, (SubComponentType::CERT, 3000, TEST_CERT_BLOB.to_vec()));
-        let (r, _) = rows.next().unwrap().unwrap();
-        assert_eq!(r, (SubComponentType::CERT_CHAIN, 3000, TEST_CERT_CHAIN_BLOB.to_vec()));
-
-        drop(rows);
-        drop(stmt);
-
-        assert_eq!(
-            db.with_transaction(Immediate("TX_test"), |tx| {
-                BlobMetaData::load_from_db(id, tx).no_gc()
-            })
-            .expect("Should find blob metadata."),
-            blob_metadata
-        );
-        Ok(())
-    }
-
-    static TEST_ALIAS: &str = "my super duper key";
-
-    #[test]
-    fn test_insert_and_load_full_keyentry_domain_app() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
-            .context("test_insert_and_load_full_keyentry_domain_app")?
-            .0;
-        let (_key_guard, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: 0,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        db.unbind_key(
-            &KeyDescriptor {
-                domain: Domain::APP,
-                nspace: 0,
-                alias: Some(TEST_ALIAS.to_string()),
-                blob: None,
-            },
-            KeyType::Client,
-            1,
-            |_, _| Ok(()),
-        )
-        .unwrap();
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: 0,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_insert_and_load_certificate_entry_domain_app() -> Result<()> {
-        let mut db = new_test_db()?;
-
-        db.store_new_certificate(
-            &KeyDescriptor {
-                domain: Domain::APP,
-                nspace: 1,
-                alias: Some(TEST_ALIAS.to_string()),
-                blob: None,
-            },
-            KeyType::Client,
-            TEST_CERT_BLOB,
-            &KEYSTORE_UUID,
-        )
-        .expect("Trying to insert cert.");
-
-        let (_key_guard, mut key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: 1,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::PUBLIC,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .expect("Trying to read certificate entry.");
-
-        assert!(key_entry.pure_cert());
-        assert!(key_entry.cert().is_none());
-        assert_eq!(key_entry.take_cert_chain(), Some(TEST_CERT_BLOB.to_vec()));
-
-        db.unbind_key(
-            &KeyDescriptor {
-                domain: Domain::APP,
-                nspace: 1,
-                alias: Some(TEST_ALIAS.to_string()),
-                blob: None,
-            },
-            KeyType::Client,
-            1,
-            |_, _| Ok(()),
-        )
-        .unwrap();
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: 1,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_insert_and_load_full_keyentry_domain_selinux() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
-            .context("test_insert_and_load_full_keyentry_domain_selinux")?
-            .0;
-        let (_key_guard, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::SELINUX,
-                    nspace: 1,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        db.unbind_key(
-            &KeyDescriptor {
-                domain: Domain::SELINUX,
-                nspace: 1,
-                alias: Some(TEST_ALIAS.to_string()),
-                blob: None,
-            },
-            KeyType::Client,
-            1,
-            |_, _| Ok(()),
-        )
-        .unwrap();
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::SELINUX,
-                    nspace: 1,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_insert_and_load_full_keyentry_domain_key_id() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
-            .context("test_insert_and_load_full_keyentry_domain_key_id")?
-            .0;
-        let (_, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap();
-
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        db.unbind_key(
-            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
-            KeyType::Client,
-            1,
-            |_, _| Ok(()),
-        )
-        .unwrap();
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                1,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_check_and_update_key_usage_count_with_limited_use_key() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(123))
-            .context("test_check_and_update_key_usage_count_with_limited_use_key")?
-            .0;
-        // Update the usage count of the limited use key.
-        db.check_and_update_key_usage_count(key_id)?;
-
-        let (_key_guard, key_entry) = db.load_key_entry(
-            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
-            KeyType::Client,
-            KeyEntryLoadBits::BOTH,
-            1,
-            |_k, _av| Ok(()),
-        )?;
-
-        // The usage count is decremented now.
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, Some(122)));
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_check_and_update_key_usage_count_with_exhausted_limited_use_key() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(1))
-            .context("test_check_and_update_key_usage_count_with_exhausted_limited_use_key")?
-            .0;
-        // Update the usage count of the limited use key.
-        db.check_and_update_key_usage_count(key_id).expect(concat!(
-            "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
-            "This should succeed."
-        ));
-
-        // Try to update the exhausted limited use key.
-        let e = db.check_and_update_key_usage_count(key_id).expect_err(concat!(
-            "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
-            "This should fail."
-        ));
-        assert_eq!(
-            &KsError::Km(ErrorCode::INVALID_KEY_BLOB),
-            e.root_cause().downcast_ref::<KsError>().unwrap()
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_insert_and_load_full_keyentry_from_grant() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
-            .context("test_insert_and_load_full_keyentry_from_grant")?
-            .0;
-
-        let granted_key = db
-            .grant(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: 0,
-                    alias: Some(TEST_ALIAS.to_string()),
-                    blob: None,
-                },
-                1,
-                2,
-                key_perm_set![KeyPerm::Use],
-                |_k, _av| Ok(()),
-            )
-            .unwrap();
-
-        debug_dump_grant_table(&mut db)?;
-
-        let (_key_guard, key_entry) = db
-            .load_key_entry(&granted_key, KeyType::Client, KeyEntryLoadBits::BOTH, 2, |k, av| {
-                assert_eq!(Domain::GRANT, k.domain);
-                assert!(av.unwrap().includes(KeyPerm::Use));
-                Ok(())
-            })
-            .unwrap();
-
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        db.unbind_key(&granted_key, KeyType::Client, 2, |_, _| Ok(())).unwrap();
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &granted_key,
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                2,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    // This test attempts to load a key by key id while the caller is not the owner
-    // but a grant exists for the given key and the caller.
-    #[test]
-    fn test_insert_and_load_full_keyentry_from_grant_by_key_id() -> Result<()> {
-        let mut db = new_test_db()?;
-        const OWNER_UID: u32 = 1u32;
-        const GRANTEE_UID: u32 = 2u32;
-        const SOMEONE_ELSE_UID: u32 = 3u32;
-        let key_id = make_test_key_entry(&mut db, Domain::APP, OWNER_UID as i64, TEST_ALIAS, None)
-            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?
-            .0;
-
-        db.grant(
-            &KeyDescriptor {
-                domain: Domain::APP,
-                nspace: 0,
-                alias: Some(TEST_ALIAS.to_string()),
-                blob: None,
-            },
-            OWNER_UID,
-            GRANTEE_UID,
-            key_perm_set![KeyPerm::Use],
-            |_k, _av| Ok(()),
-        )
-        .unwrap();
-
-        debug_dump_grant_table(&mut db)?;
-
-        let id_descriptor =
-            KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, ..Default::default() };
-
-        let (_, key_entry) = db
-            .load_key_entry(
-                &id_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                GRANTEE_UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(OWNER_UID as i64, k.nspace);
-                    assert!(av.unwrap().includes(KeyPerm::Use));
-                    Ok(())
-                },
-            )
-            .unwrap();
-
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        let (_, key_entry) = db
-            .load_key_entry(
-                &id_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                SOMEONE_ELSE_UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(OWNER_UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        db.unbind_key(&id_descriptor, KeyType::Client, OWNER_UID, |_, _| Ok(())).unwrap();
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &id_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                GRANTEE_UID,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    // Creates a key migrates it to a different location and then tries to access it by the old
-    // and new location.
-    #[test]
-    fn test_migrate_key_app_to_app() -> Result<()> {
-        let mut db = new_test_db()?;
-        const SOURCE_UID: u32 = 1u32;
-        const DESTINATION_UID: u32 = 2u32;
-        static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
-        static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
-        let key_id_guard =
-            make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
-                .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
-
-        let source_descriptor: KeyDescriptor = KeyDescriptor {
-            domain: Domain::APP,
-            nspace: -1,
-            alias: Some(SOURCE_ALIAS.to_string()),
-            blob: None,
-        };
-
-        let destination_descriptor: KeyDescriptor = KeyDescriptor {
-            domain: Domain::APP,
-            nspace: -1,
-            alias: Some(DESTINATION_ALIAS.to_string()),
-            blob: None,
-        };
-
-        let key_id = key_id_guard.id();
-
-        db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| {
-            Ok(())
-        })
-        .unwrap();
-
-        let (_, key_entry) = db
-            .load_key_entry(
-                &destination_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                DESTINATION_UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(DESTINATION_UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &source_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                SOURCE_UID,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    // Creates a key migrates it to a different location and then tries to access it by the old
-    // and new location.
-    #[test]
-    fn test_migrate_key_app_to_selinux() -> Result<()> {
-        let mut db = new_test_db()?;
-        const SOURCE_UID: u32 = 1u32;
-        const DESTINATION_UID: u32 = 2u32;
-        const DESTINATION_NAMESPACE: i64 = 1000i64;
-        static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
-        static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
-        let key_id_guard =
-            make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
-                .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
-
-        let source_descriptor: KeyDescriptor = KeyDescriptor {
-            domain: Domain::APP,
-            nspace: -1,
-            alias: Some(SOURCE_ALIAS.to_string()),
-            blob: None,
-        };
-
-        let destination_descriptor: KeyDescriptor = KeyDescriptor {
-            domain: Domain::SELINUX,
-            nspace: DESTINATION_NAMESPACE,
-            alias: Some(DESTINATION_ALIAS.to_string()),
-            blob: None,
-        };
-
-        let key_id = key_id_guard.id();
-
-        db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| {
-            Ok(())
-        })
-        .unwrap();
-
-        let (_, key_entry) = db
-            .load_key_entry(
-                &destination_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                DESTINATION_UID,
-                |k, av| {
-                    assert_eq!(Domain::SELINUX, k.domain);
-                    assert_eq!(DESTINATION_NAMESPACE, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &source_descriptor,
-                KeyType::Client,
-                KeyEntryLoadBits::NONE,
-                SOURCE_UID,
-                |_k, _av| Ok(()),
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    // Creates two keys and tries to migrate the first to the location of the second which
-    // is expected to fail.
-    #[test]
-    fn test_migrate_key_destination_occupied() -> Result<()> {
-        let mut db = new_test_db()?;
-        const SOURCE_UID: u32 = 1u32;
-        const DESTINATION_UID: u32 = 2u32;
-        static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
-        static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
-        let key_id_guard =
-            make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
-                .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
-        make_test_key_entry(&mut db, Domain::APP, DESTINATION_UID as i64, DESTINATION_ALIAS, None)
-            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
-
-        let destination_descriptor: KeyDescriptor = KeyDescriptor {
-            domain: Domain::APP,
-            nspace: -1,
-            alias: Some(DESTINATION_ALIAS.to_string()),
-            blob: None,
-        };
-
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::INVALID_ARGUMENT)),
-            db.migrate_key_namespace(
-                key_id_guard,
-                &destination_descriptor,
-                DESTINATION_UID,
-                |_k| Ok(())
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_upgrade_0_to_1() {
-        const ALIAS1: &str = "test_upgrade_0_to_1_1";
-        const ALIAS2: &str = "test_upgrade_0_to_1_2";
-        const ALIAS3: &str = "test_upgrade_0_to_1_3";
-        const UID: u32 = 33;
-        let temp_dir = Arc::new(TempDir::new("test_upgrade_0_to_1").unwrap());
-        let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
-        let key_id_untouched1 =
-            make_test_key_entry(&mut db, Domain::APP, UID as i64, ALIAS1, None).unwrap().id();
-        let key_id_untouched2 =
-            make_bootlevel_key_entry(&mut db, Domain::APP, UID as i64, ALIAS2, false).unwrap().id();
-        let key_id_deleted =
-            make_bootlevel_key_entry(&mut db, Domain::APP, UID as i64, ALIAS3, true).unwrap().id();
-
-        let (_, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS1.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id_untouched1, None));
-        let (_, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS2.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_untouched2, false));
-        let (_, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS3.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_deleted, true));
-
-        db.with_transaction(Immediate("TX_test"), |tx| KeystoreDB::from_0_to_1(tx).no_gc())
-            .unwrap();
-
-        let (_, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS1.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id_untouched1, None));
-        let (_, key_entry) = db
-            .load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS2.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap();
-        assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_untouched2, false));
-        assert_eq!(
-            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
-            db.load_key_entry(
-                &KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(ALIAS3.to_string()),
-                    blob: None,
-                },
-                KeyType::Client,
-                KeyEntryLoadBits::BOTH,
-                UID,
-                |k, av| {
-                    assert_eq!(Domain::APP, k.domain);
-                    assert_eq!(UID as i64, k.nspace);
-                    assert!(av.is_none());
-                    Ok(())
-                },
-            )
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-    }
-
-    static KEY_LOCK_TEST_ALIAS: &str = "my super duper locked key";
-
-    #[test]
-    fn test_insert_and_load_full_keyentry_domain_app_concurrently() -> Result<()> {
-        let handle = {
-            let temp_dir = Arc::new(TempDir::new("id_lock_test")?);
-            let temp_dir_clone = temp_dir.clone();
-            let mut db = KeystoreDB::new(temp_dir.path(), None)?;
-            let key_id = make_test_key_entry(&mut db, Domain::APP, 33, KEY_LOCK_TEST_ALIAS, None)
-                .context("test_insert_and_load_full_keyentry_domain_app")?
-                .0;
-            let (_key_guard, key_entry) = db
-                .load_key_entry(
-                    &KeyDescriptor {
-                        domain: Domain::APP,
-                        nspace: 0,
-                        alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
-                        blob: None,
-                    },
-                    KeyType::Client,
-                    KeyEntryLoadBits::BOTH,
-                    33,
-                    |_k, _av| Ok(()),
-                )
-                .unwrap();
-            assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
-            let state = Arc::new(AtomicU8::new(1));
-            let state2 = state.clone();
-
-            // Spawning a second thread that attempts to acquire the key id lock
-            // for the same key as the primary thread. The primary thread then
-            // waits, thereby forcing the secondary thread into the second stage
-            // of acquiring the lock (see KEY ID LOCK 2/2 above).
-            // The test succeeds if the secondary thread observes the transition
-            // of `state` from 1 to 2, despite having a whole second to overtake
-            // the primary thread.
-            let handle = thread::spawn(move || {
-                let temp_dir = temp_dir_clone;
-                let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
-                assert!(db
-                    .load_key_entry(
-                        &KeyDescriptor {
-                            domain: Domain::APP,
-                            nspace: 0,
-                            alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
-                            blob: None,
-                        },
-                        KeyType::Client,
-                        KeyEntryLoadBits::BOTH,
-                        33,
-                        |_k, _av| Ok(()),
-                    )
-                    .is_ok());
-                // We should only see a 2 here because we can only return
-                // from load_key_entry when the `_key_guard` expires,
-                // which happens at the end of the scope.
-                assert_eq!(2, state2.load(Ordering::Relaxed));
-            });
-
-            thread::sleep(std::time::Duration::from_millis(1000));
-
-            assert_eq!(Ok(1), state.compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed));
-
-            // Return the handle from this scope so we can join with the
-            // secondary thread after the key id lock has expired.
-            handle
-            // This is where the `_key_guard` goes out of scope,
-            // which is the reason for concurrent load_key_entry on the same key
-            // to unblock.
-        };
-        // Join with the secondary thread and unwrap, to propagate failing asserts to the
-        // main test thread. We will not see failing asserts in secondary threads otherwise.
-        handle.join().unwrap();
-        Ok(())
-    }
-
-    #[test]
-    fn test_database_busy_error_code() {
-        let temp_dir =
-            TempDir::new("test_database_busy_error_code_").expect("Failed to create temp dir.");
-
-        let mut db1 = KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database1.");
-        let mut db2 = KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database2.");
-
-        let _tx1 = db1
-            .conn
-            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
-            .expect("Failed to create first transaction.");
-
-        let error = db2
-            .conn
-            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
-            .context("Transaction begin failed.")
-            .expect_err("This should fail.");
-        let root_cause = error.root_cause();
-        if let Some(rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, .. }) =
-            root_cause.downcast_ref::<rusqlite::ffi::Error>()
-        {
-            return;
-        }
-        panic!(
-            "Unexpected error {:?} \n{:?} \n{:?}",
-            error,
-            root_cause,
-            root_cause.downcast_ref::<rusqlite::ffi::Error>()
-        )
-    }
-
-    #[cfg(disabled)]
-    #[test]
-    fn test_large_number_of_concurrent_db_manipulations() -> Result<()> {
-        let temp_dir = Arc::new(
-            TempDir::new("test_large_number_of_concurrent_db_manipulations_")
-                .expect("Failed to create temp dir."),
-        );
-
-        let test_begin = Instant::now();
-
-        const KEY_COUNT: u32 = 500u32;
-        let mut db =
-            new_test_db_with_gc(temp_dir.path(), |_, _| Ok(())).expect("Failed to open database.");
-        const OPEN_DB_COUNT: u32 = 50u32;
-
-        let mut actual_key_count = KEY_COUNT;
-        // First insert KEY_COUNT keys.
-        for count in 0..KEY_COUNT {
-            if Instant::now().duration_since(test_begin) >= Duration::from_secs(15) {
-                actual_key_count = count;
-                break;
-            }
-            let alias = format!("test_alias_{}", count);
-            make_test_key_entry(&mut db, Domain::APP, 1, &alias, None)
-                .expect("Failed to make key entry.");
-        }
-
-        // Insert more keys from a different thread and into a different namespace.
-        let temp_dir1 = temp_dir.clone();
-        let handle1 = thread::spawn(move || {
-            let mut db = new_test_db_with_gc(temp_dir1.path(), |_, _| Ok(()))
-                .expect("Failed to open database.");
-
-            for count in 0..actual_key_count {
-                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
-                    return;
-                }
-                let alias = format!("test_alias_{}", count);
-                make_test_key_entry(&mut db, Domain::APP, 2, &alias, None)
-                    .expect("Failed to make key entry.");
-            }
-
-            // then unbind them again.
-            for count in 0..actual_key_count {
-                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
-                    return;
-                }
-                let key = KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(format!("test_alias_{}", count)),
-                    blob: None,
-                };
-                db.unbind_key(&key, KeyType::Client, 2, |_, _| Ok(())).expect("Unbind Failed.");
-            }
-        });
-
-        // And start unbinding the first set of keys.
-        let temp_dir2 = temp_dir.clone();
-        let handle2 = thread::spawn(move || {
-            let mut db = new_test_db_with_gc(temp_dir2.path(), |_, _| Ok(()))
-                .expect("Failed to open database.");
-
-            for count in 0..actual_key_count {
-                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
-                    return;
-                }
-                let key = KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(format!("test_alias_{}", count)),
-                    blob: None,
-                };
-                db.unbind_key(&key, KeyType::Client, 1, |_, _| Ok(())).expect("Unbind Failed.");
-            }
-        });
-
-        // While a lot of inserting and deleting is going on we have to open database connections
-        // successfully and use them.
-        // This clone is not redundant, because temp_dir needs to be kept alive until db goes
-        // out of scope.
-        #[allow(clippy::redundant_clone)]
-        let temp_dir4 = temp_dir.clone();
-        let handle4 = thread::spawn(move || {
-            for count in 0..OPEN_DB_COUNT {
-                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
-                    return;
-                }
-                let mut db = new_test_db_with_gc(temp_dir4.path(), |_, _| Ok(()))
-                    .expect("Failed to open database.");
-
-                let alias = format!("test_alias_{}", count);
-                make_test_key_entry(&mut db, Domain::APP, 3, &alias, None)
-                    .expect("Failed to make key entry.");
-                let key = KeyDescriptor {
-                    domain: Domain::APP,
-                    nspace: -1,
-                    alias: Some(alias),
-                    blob: None,
-                };
-                db.unbind_key(&key, KeyType::Client, 3, |_, _| Ok(())).expect("Unbind Failed.");
-            }
-        });
-
-        handle1.join().expect("Thread 1 panicked.");
-        handle2.join().expect("Thread 2 panicked.");
-        handle4.join().expect("Thread 4 panicked.");
-
-        Ok(())
-    }
-
-    #[test]
-    fn list() -> Result<()> {
-        let temp_dir = TempDir::new("list_test")?;
-        let mut db = KeystoreDB::new(temp_dir.path(), None)?;
-        static LIST_O_ENTRIES: &[(Domain, i64, &str)] = &[
-            (Domain::APP, 1, "test1"),
-            (Domain::APP, 1, "test2"),
-            (Domain::APP, 1, "test3"),
-            (Domain::APP, 1, "test4"),
-            (Domain::APP, 1, "test5"),
-            (Domain::APP, 1, "test6"),
-            (Domain::APP, 1, "test7"),
-            (Domain::APP, 2, "test1"),
-            (Domain::APP, 2, "test2"),
-            (Domain::APP, 2, "test3"),
-            (Domain::APP, 2, "test4"),
-            (Domain::APP, 2, "test5"),
-            (Domain::APP, 2, "test6"),
-            (Domain::APP, 2, "test8"),
-            (Domain::SELINUX, 100, "test1"),
-            (Domain::SELINUX, 100, "test2"),
-            (Domain::SELINUX, 100, "test3"),
-            (Domain::SELINUX, 100, "test4"),
-            (Domain::SELINUX, 100, "test5"),
-            (Domain::SELINUX, 100, "test6"),
-            (Domain::SELINUX, 100, "test9"),
-        ];
-
-        let list_o_keys: Vec<(i64, i64)> = LIST_O_ENTRIES
-            .iter()
-            .map(|(domain, ns, alias)| {
-                let entry =
-                    make_test_key_entry(&mut db, *domain, *ns, alias, None).unwrap_or_else(|e| {
-                        panic!("Failed to insert {:?} {} {}. Error {:?}", domain, ns, alias, e)
-                    });
-                (entry.id(), *ns)
-            })
-            .collect();
-
-        for (domain, namespace) in
-            &[(Domain::APP, 1i64), (Domain::APP, 2i64), (Domain::SELINUX, 100i64)]
-        {
-            let mut list_o_descriptors: Vec<KeyDescriptor> = LIST_O_ENTRIES
-                .iter()
-                .filter_map(|(domain, ns, alias)| match ns {
-                    ns if *ns == *namespace => Some(KeyDescriptor {
-                        domain: *domain,
-                        nspace: *ns,
-                        alias: Some(alias.to_string()),
-                        blob: None,
-                    }),
-                    _ => None,
-                })
-                .collect();
-            list_o_descriptors.sort();
-            let mut list_result = db.list_past_alias(*domain, *namespace, KeyType::Client, None)?;
-            list_result.sort();
-            assert_eq!(list_o_descriptors, list_result);
-
-            let mut list_o_ids: Vec<i64> = list_o_descriptors
-                .into_iter()
-                .map(|d| {
-                    let (_, entry) = db
-                        .load_key_entry(
-                            &d,
-                            KeyType::Client,
-                            KeyEntryLoadBits::NONE,
-                            *namespace as u32,
-                            |_, _| Ok(()),
-                        )
-                        .unwrap();
-                    entry.id()
-                })
-                .collect();
-            list_o_ids.sort_unstable();
-            let mut loaded_entries: Vec<i64> = list_o_keys
-                .iter()
-                .filter_map(|(id, ns)| match ns {
-                    ns if *ns == *namespace => Some(*id),
-                    _ => None,
-                })
-                .collect();
-            loaded_entries.sort_unstable();
-            assert_eq!(list_o_ids, loaded_entries);
-        }
-        assert_eq!(
-            Vec::<KeyDescriptor>::new(),
-            db.list_past_alias(Domain::SELINUX, 101, KeyType::Client, None)?
-        );
-
-        Ok(())
-    }
-
-    // Helpers
-
-    // Checks that the given result is an error containing the given string.
-    fn check_result_is_error_containing_string<T>(result: Result<T>, target: &str) {
-        let error_str = format!(
-            "{:#?}",
-            result.err().unwrap_or_else(|| panic!("Expected the error: {}", target))
-        );
-        assert!(
-            error_str.contains(target),
-            "The string \"{}\" should contain \"{}\"",
-            error_str,
-            target
-        );
-    }
-
-    #[derive(Debug, PartialEq)]
-    struct KeyEntryRow {
-        id: i64,
-        key_type: KeyType,
-        domain: Option<Domain>,
-        namespace: Option<i64>,
-        alias: Option<String>,
-        state: KeyLifeCycle,
-        km_uuid: Option<Uuid>,
-    }
-
-    fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
-        db.conn
-            .prepare("SELECT * FROM persistent.keyentry;")?
-            .query_map([], |row| {
-                Ok(KeyEntryRow {
-                    id: row.get(0)?,
-                    key_type: row.get(1)?,
-                    domain: row.get::<_, Option<_>>(2)?.map(Domain),
-                    namespace: row.get(3)?,
-                    alias: row.get(4)?,
-                    state: row.get(5)?,
-                    km_uuid: row.get(6)?,
-                })
-            })?
-            .map(|r| r.context("Could not read keyentry row."))
-            .collect::<Result<Vec<_>>>()
-    }
-
-    fn make_test_params(max_usage_count: Option<i32>) -> Vec<KeyParameter> {
-        make_test_params_with_sids(max_usage_count, &[42])
-    }
-
-    // Note: The parameters and SecurityLevel associations are nonsensical. This
-    // collection is only used to check if the parameters are preserved as expected by the
-    // database.
-    fn make_test_params_with_sids(
-        max_usage_count: Option<i32>,
-        user_secure_ids: &[i64],
-    ) -> Vec<KeyParameter> {
-        let mut params = vec![
-            KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::TRUSTED_ENVIRONMENT),
-            KeyParameter::new(
-                KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::Algorithm(Algorithm::RSA),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::TRUSTED_ENVIRONMENT),
-            KeyParameter::new(
-                KeyParameterValue::BlockMode(BlockMode::ECB),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::BlockMode(BlockMode::GCM),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::Digest(Digest::NONE), SecurityLevel::STRONGBOX),
-            KeyParameter::new(
-                KeyParameterValue::Digest(Digest::MD5),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::Digest(Digest::SHA_2_224),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::Digest(Digest::SHA_2_256),
-                SecurityLevel::STRONGBOX,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::PaddingMode(PaddingMode::NONE),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::PaddingMode(PaddingMode::RSA_PSS),
-                SecurityLevel::STRONGBOX,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::PaddingMode(PaddingMode::RSA_PKCS1_1_5_SIGN),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::TRUSTED_ENVIRONMENT),
-            KeyParameter::new(KeyParameterValue::MinMacLength(256), SecurityLevel::STRONGBOX),
-            KeyParameter::new(
-                KeyParameterValue::EcCurve(EcCurve::P_224),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::EcCurve(EcCurve::P_256), SecurityLevel::STRONGBOX),
-            KeyParameter::new(
-                KeyParameterValue::EcCurve(EcCurve::P_384),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::EcCurve(EcCurve::P_521),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::RSAPublicExponent(3),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::IncludeUniqueID,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::BootLoaderOnly, SecurityLevel::STRONGBOX),
-            KeyParameter::new(KeyParameterValue::RollbackResistance, SecurityLevel::STRONGBOX),
-            KeyParameter::new(
-                KeyParameterValue::ActiveDateTime(1234567890),
-                SecurityLevel::STRONGBOX,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::OriginationExpireDateTime(1234567890),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::UsageExpireDateTime(1234567890),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::MinSecondsBetweenOps(1234567890),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::MaxUsesPerBoot(1234567890),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::UserID(1), SecurityLevel::STRONGBOX),
-            KeyParameter::new(
-                KeyParameterValue::NoAuthRequired,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::PASSWORD),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::AuthTimeout(1234567890), SecurityLevel::SOFTWARE),
-            KeyParameter::new(KeyParameterValue::AllowWhileOnBody, SecurityLevel::SOFTWARE),
-            KeyParameter::new(
-                KeyParameterValue::TrustedUserPresenceRequired,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::TrustedConfirmationRequired,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::UnlockedDeviceRequired,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::ApplicationID(vec![1u8, 2u8, 3u8, 4u8]),
-                SecurityLevel::SOFTWARE,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::ApplicationData(vec![4u8, 3u8, 2u8, 1u8]),
-                SecurityLevel::SOFTWARE,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::CreationDateTime(12345677890),
-                SecurityLevel::SOFTWARE,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::KeyOrigin(KeyOrigin::GENERATED),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::RootOfTrust(vec![3u8, 2u8, 1u8, 4u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(KeyParameterValue::OSVersion(1), SecurityLevel::TRUSTED_ENVIRONMENT),
-            KeyParameter::new(KeyParameterValue::OSPatchLevel(2), SecurityLevel::SOFTWARE),
-            KeyParameter::new(
-                KeyParameterValue::UniqueID(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::SOFTWARE,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationChallenge(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationApplicationID(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdBrand(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdDevice(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdProduct(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdSerial(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdIMEI(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdSecondIMEI(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdMEID(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdManufacturer(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AttestationIdModel(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::VendorPatchLevel(3),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::BootPatchLevel(4),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::AssociatedData(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::Nonce(vec![4u8, 3u8, 1u8, 2u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::MacLength(256),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::ResetSinceIdRotation,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-            KeyParameter::new(
-                KeyParameterValue::ConfirmationToken(vec![5u8, 5u8, 5u8, 5u8]),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ),
-        ];
-        if let Some(value) = max_usage_count {
-            params.push(KeyParameter::new(
-                KeyParameterValue::UsageCountLimit(value),
-                SecurityLevel::SOFTWARE,
-            ));
-        }
-
-        for sid in user_secure_ids.iter() {
-            params.push(KeyParameter::new(
-                KeyParameterValue::UserSecureID(*sid),
-                SecurityLevel::STRONGBOX,
-            ));
-        }
-        params
-    }
-
-    pub fn make_test_key_entry(
-        db: &mut KeystoreDB,
-        domain: Domain,
-        namespace: i64,
-        alias: &str,
-        max_usage_count: Option<i32>,
-    ) -> Result<KeyIdGuard> {
-        make_test_key_entry_with_sids(db, domain, namespace, alias, max_usage_count, &[42])
-    }
-
-    pub fn make_test_key_entry_with_sids(
-        db: &mut KeystoreDB,
-        domain: Domain,
-        namespace: i64,
-        alias: &str,
-        max_usage_count: Option<i32>,
-        sids: &[i64],
-    ) -> Result<KeyIdGuard> {
-        let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
-        let mut blob_metadata = BlobMetaData::new();
-        blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
-        blob_metadata.add(BlobMetaEntry::Salt(vec![1, 2, 3]));
-        blob_metadata.add(BlobMetaEntry::Iv(vec![2, 3, 1]));
-        blob_metadata.add(BlobMetaEntry::AeadTag(vec![3, 1, 2]));
-        blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
-
-        db.set_blob(
-            &key_id,
-            SubComponentType::KEY_BLOB,
-            Some(TEST_KEY_BLOB),
-            Some(&blob_metadata),
-        )?;
-        db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
-        db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
-
-        let params = make_test_params_with_sids(max_usage_count, sids);
-        db.insert_keyparameter(&key_id, &params)?;
-
-        let mut metadata = KeyMetaData::new();
-        metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
-        db.insert_key_metadata(&key_id, &metadata)?;
-        rebind_alias(db, &key_id, alias, domain, namespace)?;
-        Ok(key_id)
-    }
-
-    fn make_test_key_entry_test_vector(key_id: i64, max_usage_count: Option<i32>) -> KeyEntry {
-        let params = make_test_params(max_usage_count);
-
-        let mut blob_metadata = BlobMetaData::new();
-        blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
-        blob_metadata.add(BlobMetaEntry::Salt(vec![1, 2, 3]));
-        blob_metadata.add(BlobMetaEntry::Iv(vec![2, 3, 1]));
-        blob_metadata.add(BlobMetaEntry::AeadTag(vec![3, 1, 2]));
-        blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
-
-        let mut metadata = KeyMetaData::new();
-        metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
-
-        KeyEntry {
-            id: key_id,
-            key_blob_info: Some((TEST_KEY_BLOB.to_vec(), blob_metadata)),
-            cert: Some(TEST_CERT_BLOB.to_vec()),
-            cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
-            km_uuid: KEYSTORE_UUID,
-            parameters: params,
-            metadata,
-            pure_cert: false,
-        }
-    }
-
-    pub fn make_bootlevel_key_entry(
-        db: &mut KeystoreDB,
-        domain: Domain,
-        namespace: i64,
-        alias: &str,
-        logical_only: bool,
-    ) -> Result<KeyIdGuard> {
-        let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
-        let mut blob_metadata = BlobMetaData::new();
-        if !logical_only {
-            blob_metadata.add(BlobMetaEntry::MaxBootLevel(3));
-        }
-        blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
-
-        db.set_blob(
-            &key_id,
-            SubComponentType::KEY_BLOB,
-            Some(TEST_KEY_BLOB),
-            Some(&blob_metadata),
-        )?;
-        db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
-        db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
-
-        let mut params = make_test_params(None);
-        params.push(KeyParameter::new(KeyParameterValue::MaxBootLevel(3), SecurityLevel::KEYSTORE));
-
-        db.insert_keyparameter(&key_id, &params)?;
-
-        let mut metadata = KeyMetaData::new();
-        metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
-        db.insert_key_metadata(&key_id, &metadata)?;
-        rebind_alias(db, &key_id, alias, domain, namespace)?;
-        Ok(key_id)
-    }
-
-    // Creates an app key that is marked as being superencrypted by the given
-    // super key ID and that has the given authentication and unlocked device
-    // parameters. This does not actually superencrypt the key blob.
-    fn make_superencrypted_key_entry(
-        db: &mut KeystoreDB,
-        namespace: i64,
-        alias: &str,
-        requires_authentication: bool,
-        requires_unlocked_device: bool,
-        super_key_id: i64,
-    ) -> Result<KeyIdGuard> {
-        let domain = Domain::APP;
-        let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
-
-        let mut blob_metadata = BlobMetaData::new();
-        blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
-        blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(super_key_id)));
-        db.set_blob(
-            &key_id,
-            SubComponentType::KEY_BLOB,
-            Some(TEST_KEY_BLOB),
-            Some(&blob_metadata),
-        )?;
-
-        let mut params = vec![];
-        if requires_unlocked_device {
-            params.push(KeyParameter::new(
-                KeyParameterValue::UnlockedDeviceRequired,
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ));
-        }
-        if requires_authentication {
-            params.push(KeyParameter::new(
-                KeyParameterValue::UserSecureID(42),
-                SecurityLevel::TRUSTED_ENVIRONMENT,
-            ));
-        }
-        db.insert_keyparameter(&key_id, &params)?;
-
-        let mut metadata = KeyMetaData::new();
-        metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
-        db.insert_key_metadata(&key_id, &metadata)?;
-
-        rebind_alias(db, &key_id, alias, domain, namespace)?;
-        Ok(key_id)
-    }
-
-    fn make_bootlevel_test_key_entry_test_vector(key_id: i64, logical_only: bool) -> KeyEntry {
-        let mut params = make_test_params(None);
-        params.push(KeyParameter::new(KeyParameterValue::MaxBootLevel(3), SecurityLevel::KEYSTORE));
-
-        let mut blob_metadata = BlobMetaData::new();
-        if !logical_only {
-            blob_metadata.add(BlobMetaEntry::MaxBootLevel(3));
-        }
-        blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
-
-        let mut metadata = KeyMetaData::new();
-        metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
-
-        KeyEntry {
-            id: key_id,
-            key_blob_info: Some((TEST_KEY_BLOB.to_vec(), blob_metadata)),
-            cert: Some(TEST_CERT_BLOB.to_vec()),
-            cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
-            km_uuid: KEYSTORE_UUID,
-            parameters: params,
-            metadata,
-            pure_cert: false,
-        }
-    }
-
-    fn debug_dump_keyentry_table(db: &mut KeystoreDB) -> Result<()> {
-        let mut stmt = db.conn.prepare(
-            "SELECT id, key_type, domain, namespace, alias, state, km_uuid FROM persistent.keyentry;",
-        )?;
-        let rows = stmt.query_map::<(i64, KeyType, i32, i64, String, KeyLifeCycle, Uuid), _, _>(
-            [],
-            |row| {
-                Ok((
-                    row.get(0)?,
-                    row.get(1)?,
-                    row.get(2)?,
-                    row.get(3)?,
-                    row.get(4)?,
-                    row.get(5)?,
-                    row.get(6)?,
-                ))
-            },
-        )?;
-
-        println!("Key entry table rows:");
-        for r in rows {
-            let (id, key_type, domain, namespace, alias, state, km_uuid) = r.unwrap();
-            println!(
-                "    id: {} KeyType: {:?} Domain: {} Namespace: {} Alias: {} State: {:?} KmUuid: {:?}",
-                id, key_type, domain, namespace, alias, state, km_uuid
-            );
-        }
-        Ok(())
-    }
-
-    fn debug_dump_grant_table(db: &mut KeystoreDB) -> Result<()> {
-        let mut stmt = db
-            .conn
-            .prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
-        let rows = stmt.query_map::<(i64, i64, i64, i64), _, _>([], |row| {
-            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
-        })?;
-
-        println!("Grant table rows:");
-        for r in rows {
-            let (id, gt, ki, av) = r.unwrap();
-            println!("    id: {} grantee: {} key_id: {} access_vector: {}", id, gt, ki, av);
-        }
-        Ok(())
-    }
-
-    // Use a custom random number generator that repeats each number once.
-    // This allows us to test repeated elements.
-
-    thread_local! {
-        static RANDOM_COUNTER: RefCell<i64> = const { RefCell::new(0) };
-    }
-
-    fn reset_random() {
-        RANDOM_COUNTER.with(|counter| {
-            *counter.borrow_mut() = 0;
-        })
-    }
-
-    pub fn random() -> i64 {
-        RANDOM_COUNTER.with(|counter| {
-            let result = *counter.borrow() / 2;
-            *counter.borrow_mut() += 1;
-            result
-        })
-    }
-
-    #[test]
-    fn test_unbind_keys_for_user() -> Result<()> {
-        let mut db = new_test_db()?;
-        db.unbind_keys_for_user(1, false)?;
-
-        make_test_key_entry(&mut db, Domain::APP, 210000, TEST_ALIAS, None)?;
-        make_test_key_entry(&mut db, Domain::APP, 110000, TEST_ALIAS, None)?;
-        db.unbind_keys_for_user(2, false)?;
-
-        assert_eq!(1, db.list_past_alias(Domain::APP, 110000, KeyType::Client, None)?.len());
-        assert_eq!(0, db.list_past_alias(Domain::APP, 210000, KeyType::Client, None)?.len());
-
-        db.unbind_keys_for_user(1, true)?;
-        assert_eq!(0, db.list_past_alias(Domain::APP, 110000, KeyType::Client, None)?.len());
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_unbind_keys_for_user_removes_superkeys() -> Result<()> {
-        let mut db = new_test_db()?;
-        let super_key = keystore2_crypto::generate_aes256_key()?;
-        let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
-        let (encrypted_super_key, metadata) =
-            SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
-
-        let key_name_enc = SuperKeyType {
-            alias: "test_super_key_1",
-            algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
-            name: "test_super_key_1",
-        };
-
-        let key_name_nonenc = SuperKeyType {
-            alias: "test_super_key_2",
-            algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
-            name: "test_super_key_2",
-        };
-
-        // Install two super keys.
-        db.store_super_key(
-            1,
-            &key_name_nonenc,
-            &super_key,
-            &BlobMetaData::new(),
-            &KeyMetaData::new(),
-        )?;
-        db.store_super_key(1, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;
-
-        // Check that both can be found in the database.
-        assert!(db.load_super_key(&key_name_enc, 1)?.is_some());
-        assert!(db.load_super_key(&key_name_nonenc, 1)?.is_some());
-
-        // Install the same keys for a different user.
-        db.store_super_key(
-            2,
-            &key_name_nonenc,
-            &super_key,
-            &BlobMetaData::new(),
-            &KeyMetaData::new(),
-        )?;
-        db.store_super_key(2, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;
-
-        // Check that the second pair of keys can be found in the database.
-        assert!(db.load_super_key(&key_name_enc, 2)?.is_some());
-        assert!(db.load_super_key(&key_name_nonenc, 2)?.is_some());
-
-        // Delete only encrypted keys.
-        db.unbind_keys_for_user(1, true)?;
-
-        // The encrypted superkey should be gone now.
-        assert!(db.load_super_key(&key_name_enc, 1)?.is_none());
-        assert!(db.load_super_key(&key_name_nonenc, 1)?.is_some());
-
-        // Reinsert the encrypted key.
-        db.store_super_key(1, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;
-
-        // Check that both can be found in the database, again..
-        assert!(db.load_super_key(&key_name_enc, 1)?.is_some());
-        assert!(db.load_super_key(&key_name_nonenc, 1)?.is_some());
-
-        // Delete all even unencrypted keys.
-        db.unbind_keys_for_user(1, false)?;
-
-        // Both should be gone now.
-        assert!(db.load_super_key(&key_name_enc, 1)?.is_none());
-        assert!(db.load_super_key(&key_name_nonenc, 1)?.is_none());
-
-        // Check that the second pair of keys was untouched.
-        assert!(db.load_super_key(&key_name_enc, 2)?.is_some());
-        assert!(db.load_super_key(&key_name_nonenc, 2)?.is_some());
-
-        Ok(())
-    }
-
-    fn app_key_exists(db: &mut KeystoreDB, nspace: i64, alias: &str) -> Result<bool> {
-        db.key_exists(Domain::APP, nspace, alias, KeyType::Client)
-    }
-
-    // Tests the unbind_auth_bound_keys_for_user() function.
-    #[test]
-    fn test_unbind_auth_bound_keys_for_user() -> Result<()> {
-        let mut db = new_test_db()?;
-        let user_id = 1;
-        let nspace: i64 = (user_id * AID_USER_OFFSET).into();
-        let other_user_id = 2;
-        let other_user_nspace: i64 = (other_user_id * AID_USER_OFFSET).into();
-        let super_key_type = &USER_AFTER_FIRST_UNLOCK_SUPER_KEY;
-
-        // Create a superencryption key.
-        let super_key = keystore2_crypto::generate_aes256_key()?;
-        let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
-        let (encrypted_super_key, blob_metadata) =
-            SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
-        db.store_super_key(
-            user_id,
-            super_key_type,
-            &encrypted_super_key,
-            &blob_metadata,
-            &KeyMetaData::new(),
-        )?;
-        let super_key_id = db.load_super_key(super_key_type, user_id)?.unwrap().0 .0;
-
-        // Store 4 superencrypted app keys, one for each possible combination of
-        // (authentication required, unlocked device required).
-        make_superencrypted_key_entry(&mut db, nspace, "noauth_noud", false, false, super_key_id)?;
-        make_superencrypted_key_entry(&mut db, nspace, "noauth_ud", false, true, super_key_id)?;
-        make_superencrypted_key_entry(&mut db, nspace, "auth_noud", true, false, super_key_id)?;
-        make_superencrypted_key_entry(&mut db, nspace, "auth_ud", true, true, super_key_id)?;
-        assert!(app_key_exists(&mut db, nspace, "noauth_noud")?);
-        assert!(app_key_exists(&mut db, nspace, "noauth_ud")?);
-        assert!(app_key_exists(&mut db, nspace, "auth_noud")?);
-        assert!(app_key_exists(&mut db, nspace, "auth_ud")?);
-
-        // Also store a key for a different user that requires authentication.
-        make_superencrypted_key_entry(
-            &mut db,
-            other_user_nspace,
-            "auth_ud",
-            true,
-            true,
-            super_key_id,
-        )?;
-
-        db.unbind_auth_bound_keys_for_user(user_id)?;
-
-        // Verify that only the user's app keys that require authentication were
-        // deleted. Keys that require an unlocked device but not authentication
-        // should *not* have been deleted, nor should the super key have been
-        // deleted, nor should other users' keys have been deleted.
-        assert!(db.load_super_key(super_key_type, user_id)?.is_some());
-        assert!(app_key_exists(&mut db, nspace, "noauth_noud")?);
-        assert!(app_key_exists(&mut db, nspace, "noauth_ud")?);
-        assert!(!app_key_exists(&mut db, nspace, "auth_noud")?);
-        assert!(!app_key_exists(&mut db, nspace, "auth_ud")?);
-        assert!(app_key_exists(&mut db, other_user_nspace, "auth_ud")?);
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_store_super_key() -> Result<()> {
-        let mut db = new_test_db()?;
-        let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
-        let super_key = keystore2_crypto::generate_aes256_key()?;
-        let secret_bytes = b"keystore2 is great.";
-        let (encrypted_secret, iv, tag) =
-            keystore2_crypto::aes_gcm_encrypt(secret_bytes, &super_key)?;
-
-        let (encrypted_super_key, metadata) =
-            SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
-        db.store_super_key(
-            1,
-            &USER_AFTER_FIRST_UNLOCK_SUPER_KEY,
-            &encrypted_super_key,
-            &metadata,
-            &KeyMetaData::new(),
-        )?;
-
-        // Check if super key exists.
-        assert!(db.key_exists(
-            Domain::APP,
-            1,
-            USER_AFTER_FIRST_UNLOCK_SUPER_KEY.alias,
-            KeyType::Super
-        )?);
-
-        let (_, key_entry) = db.load_super_key(&USER_AFTER_FIRST_UNLOCK_SUPER_KEY, 1)?.unwrap();
-        let loaded_super_key = SuperKeyManager::extract_super_key_from_key_entry(
-            USER_AFTER_FIRST_UNLOCK_SUPER_KEY.algorithm,
-            key_entry,
-            &pw,
-            None,
-        )?;
-
-        let decrypted_secret_bytes = loaded_super_key.decrypt(&encrypted_secret, &iv, &tag)?;
-        assert_eq!(secret_bytes, &*decrypted_secret_bytes);
-
-        Ok(())
-    }
-
-    fn get_valid_statsd_storage_types() -> Vec<MetricsStorage> {
-        vec![
-            MetricsStorage::KEY_ENTRY,
-            MetricsStorage::KEY_ENTRY_ID_INDEX,
-            MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX,
-            MetricsStorage::BLOB_ENTRY,
-            MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX,
-            MetricsStorage::KEY_PARAMETER,
-            MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX,
-            MetricsStorage::KEY_METADATA,
-            MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX,
-            MetricsStorage::GRANT,
-            MetricsStorage::AUTH_TOKEN,
-            MetricsStorage::BLOB_METADATA,
-            MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX,
-        ]
-    }
-
-    /// Perform a simple check to ensure that we can query all the storage types
-    /// that are supported by the DB. Check for reasonable values.
-    #[test]
-    fn test_query_all_valid_table_sizes() -> Result<()> {
-        const PAGE_SIZE: i32 = 4096;
-
-        let mut db = new_test_db()?;
-
-        for t in get_valid_statsd_storage_types() {
-            let stat = db.get_storage_stat(t)?;
-            // AuthToken can be less than a page since it's in a btree, not sqlite
-            // TODO(b/187474736) stop using if-let here
-            if let MetricsStorage::AUTH_TOKEN = t {
-            } else {
-                assert!(stat.size >= PAGE_SIZE);
-            }
-            assert!(stat.size >= stat.unused_size);
-        }
-
-        Ok(())
-    }
-
-    fn get_storage_stats_map(db: &mut KeystoreDB) -> BTreeMap<i32, StorageStats> {
-        get_valid_statsd_storage_types()
-            .into_iter()
-            .map(|t| (t.0, db.get_storage_stat(t).unwrap()))
-            .collect()
-    }
-
-    fn assert_storage_increased(
-        db: &mut KeystoreDB,
-        increased_storage_types: Vec<MetricsStorage>,
-        baseline: &mut BTreeMap<i32, StorageStats>,
-    ) {
-        for storage in increased_storage_types {
-            // Verify the expected storage increased.
-            let new = db.get_storage_stat(storage).unwrap();
-            let old = &baseline[&storage.0];
-            assert!(new.size >= old.size, "{}: {} >= {}", storage.0, new.size, old.size);
-            assert!(
-                new.unused_size <= old.unused_size,
-                "{}: {} <= {}",
-                storage.0,
-                new.unused_size,
-                old.unused_size
-            );
-
-            // Update the baseline with the new value so that it succeeds in the
-            // later comparison.
-            baseline.insert(storage.0, new);
-        }
-
-        // Get an updated map of the storage and verify there were no unexpected changes.
-        let updated_stats = get_storage_stats_map(db);
-        assert_eq!(updated_stats.len(), baseline.len());
-
-        for &k in baseline.keys() {
-            let stringify = |map: &BTreeMap<i32, StorageStats>| -> String {
-                let mut s = String::new();
-                for &k in map.keys() {
-                    writeln!(&mut s, "  {}: {}, {}", &k, map[&k].size, map[&k].unused_size)
-                        .expect("string concat failed");
-                }
-                s
-            };
-
-            assert!(
-                updated_stats[&k].size == baseline[&k].size
-                    && updated_stats[&k].unused_size == baseline[&k].unused_size,
-                "updated_stats:\n{}\nbaseline:\n{}",
-                stringify(&updated_stats),
-                stringify(baseline)
-            );
-        }
-    }
-
-    #[test]
-    fn test_verify_key_table_size_reporting() -> Result<()> {
-        let mut db = new_test_db()?;
-        let mut working_stats = get_storage_stats_map(&mut db);
-
-        let key_id = create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
-        assert_storage_increased(
-            &mut db,
-            vec![
-                MetricsStorage::KEY_ENTRY,
-                MetricsStorage::KEY_ENTRY_ID_INDEX,
-                MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX,
-            ],
-            &mut working_stats,
-        );
-
-        let mut blob_metadata = BlobMetaData::new();
-        blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
-        db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), None)?;
-        assert_storage_increased(
-            &mut db,
-            vec![
-                MetricsStorage::BLOB_ENTRY,
-                MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX,
-                MetricsStorage::BLOB_METADATA,
-                MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX,
-            ],
-            &mut working_stats,
-        );
-
-        let params = make_test_params(None);
-        db.insert_keyparameter(&key_id, &params)?;
-        assert_storage_increased(
-            &mut db,
-            vec![MetricsStorage::KEY_PARAMETER, MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX],
-            &mut working_stats,
-        );
-
-        let mut metadata = KeyMetaData::new();
-        metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
-        db.insert_key_metadata(&key_id, &metadata)?;
-        assert_storage_increased(
-            &mut db,
-            vec![MetricsStorage::KEY_METADATA, MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX],
-            &mut working_stats,
-        );
-
-        let mut sum = 0;
-        for stat in working_stats.values() {
-            sum += stat.size;
-        }
-        let total = db.get_storage_stat(MetricsStorage::DATABASE)?.size;
-        assert!(sum <= total, "Expected sum <= total. sum: {}, total: {}", sum, total);
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_verify_auth_table_size_reporting() -> Result<()> {
-        let mut db = new_test_db()?;
-        let mut working_stats = get_storage_stats_map(&mut db);
-        db.insert_auth_token(&HardwareAuthToken {
-            challenge: 123,
-            userId: 456,
-            authenticatorId: 789,
-            authenticatorType: kmhw_authenticator_type::ANY,
-            timestamp: Timestamp { milliSeconds: 10 },
-            mac: b"mac".to_vec(),
-        });
-        assert_storage_increased(&mut db, vec![MetricsStorage::AUTH_TOKEN], &mut working_stats);
-        Ok(())
-    }
-
-    #[test]
-    fn test_verify_grant_table_size_reporting() -> Result<()> {
-        const OWNER: i64 = 1;
-        let mut db = new_test_db()?;
-        make_test_key_entry(&mut db, Domain::APP, OWNER, TEST_ALIAS, None)?;
-
-        let mut working_stats = get_storage_stats_map(&mut db);
-        db.grant(
-            &KeyDescriptor {
-                domain: Domain::APP,
-                nspace: 0,
-                alias: Some(TEST_ALIAS.to_string()),
-                blob: None,
-            },
-            OWNER as u32,
-            123,
-            key_perm_set![KeyPerm::Use],
-            |_, _| Ok(()),
-        )?;
-
-        assert_storage_increased(&mut db, vec![MetricsStorage::GRANT], &mut working_stats);
-
-        Ok(())
-    }
-
-    #[test]
-    fn find_auth_token_entry_returns_latest() -> Result<()> {
-        let mut db = new_test_db()?;
-        db.insert_auth_token(&HardwareAuthToken {
-            challenge: 123,
-            userId: 456,
-            authenticatorId: 789,
-            authenticatorType: kmhw_authenticator_type::ANY,
-            timestamp: Timestamp { milliSeconds: 10 },
-            mac: b"mac0".to_vec(),
-        });
-        std::thread::sleep(std::time::Duration::from_millis(1));
-        db.insert_auth_token(&HardwareAuthToken {
-            challenge: 123,
-            userId: 457,
-            authenticatorId: 789,
-            authenticatorType: kmhw_authenticator_type::ANY,
-            timestamp: Timestamp { milliSeconds: 12 },
-            mac: b"mac1".to_vec(),
-        });
-        std::thread::sleep(std::time::Duration::from_millis(1));
-        db.insert_auth_token(&HardwareAuthToken {
-            challenge: 123,
-            userId: 458,
-            authenticatorId: 789,
-            authenticatorType: kmhw_authenticator_type::ANY,
-            timestamp: Timestamp { milliSeconds: 3 },
-            mac: b"mac2".to_vec(),
-        });
-        // All three entries are in the database
-        assert_eq!(db.perboot.auth_tokens_len(), 3);
-        // It selected the most recent timestamp
-        assert_eq!(db.find_auth_token_entry(|_| true).unwrap().auth_token.mac, b"mac2".to_vec());
-        Ok(())
-    }
-
-    #[test]
-    fn test_load_key_descriptor() -> Result<()> {
-        let mut db = new_test_db()?;
-        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)?.0;
-
-        let key = db.load_key_descriptor(key_id)?.unwrap();
-
-        assert_eq!(key.domain, Domain::APP);
-        assert_eq!(key.nspace, 1);
-        assert_eq!(key.alias, Some(TEST_ALIAS.to_string()));
-
-        // No such id
-        assert_eq!(db.load_key_descriptor(key_id + 1)?, None);
-        Ok(())
-    }
-
-    #[test]
-    fn test_get_list_app_uids_for_sid() -> Result<()> {
-        let uid: i32 = 1;
-        let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
-        let first_sid = 667;
-        let second_sid = 669;
-        let first_app_id: i64 = 123 + uid_offset;
-        let second_app_id: i64 = 456 + uid_offset;
-        let third_app_id: i64 = 789 + uid_offset;
-        let unrelated_app_id: i64 = 1011 + uid_offset;
-        let mut db = new_test_db()?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            first_app_id,
-            TEST_ALIAS,
-            None,
-            &[first_sid],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            second_app_id,
-            "alias2",
-            None,
-            &[first_sid],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            second_app_id,
-            TEST_ALIAS,
-            None,
-            &[second_sid],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            third_app_id,
-            "alias3",
-            None,
-            &[second_sid],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            unrelated_app_id,
-            TEST_ALIAS,
-            None,
-            &[],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-
-        let mut first_sid_apps = db.get_app_uids_affected_by_sid(uid, first_sid)?;
-        first_sid_apps.sort();
-        assert_eq!(first_sid_apps, vec![first_app_id, second_app_id]);
-        let mut second_sid_apps = db.get_app_uids_affected_by_sid(uid, second_sid)?;
-        second_sid_apps.sort();
-        assert_eq!(second_sid_apps, vec![second_app_id, third_app_id]);
-        Ok(())
-    }
-
-    #[test]
-    fn test_get_list_app_uids_with_multiple_sids() -> Result<()> {
-        let uid: i32 = 1;
-        let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
-        let first_sid = 667;
-        let second_sid = 669;
-        let third_sid = 772;
-        let first_app_id: i64 = 123 + uid_offset;
-        let second_app_id: i64 = 456 + uid_offset;
-        let mut db = new_test_db()?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            first_app_id,
-            TEST_ALIAS,
-            None,
-            &[first_sid, second_sid],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-        make_test_key_entry_with_sids(
-            &mut db,
-            Domain::APP,
-            second_app_id,
-            "alias2",
-            None,
-            &[second_sid, third_sid],
-        )
-        .context("test_get_list_app_uids_for_sid")?;
-
-        let first_sid_apps = db.get_app_uids_affected_by_sid(uid, first_sid)?;
-        assert_eq!(first_sid_apps, vec![first_app_id]);
-
-        let mut second_sid_apps = db.get_app_uids_affected_by_sid(uid, second_sid)?;
-        second_sid_apps.sort();
-        assert_eq!(second_sid_apps, vec![first_app_id, second_app_id]);
-
-        let third_sid_apps = db.get_app_uids_affected_by_sid(uid, third_sid)?;
-        assert_eq!(third_sid_apps, vec![second_app_id]);
-        Ok(())
-    }
-
-    #[test]
-    fn test_key_id_guard_immediate() -> Result<()> {
-        if !keystore2_flags::database_loop_timeout() {
-            eprintln!("Skipping test as loop timeout flag disabled");
-            return Ok(());
-        }
-        // Emit logging from test.
-        android_logger::init_once(
-            android_logger::Config::default()
-                .with_tag("keystore_database_tests")
-                .with_max_level(log::LevelFilter::Debug),
-        );
-
-        // Preparation: put a single entry into a test DB.
-        let temp_dir = Arc::new(TempDir::new("key_id_guard_immediate")?);
-        let temp_dir_clone_a = temp_dir.clone();
-        let temp_dir_clone_b = temp_dir.clone();
-        let mut db = KeystoreDB::new(temp_dir.path(), None)?;
-        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)?.0;
-
-        let (a_sender, b_receiver) = std::sync::mpsc::channel();
-        let (b_sender, a_receiver) = std::sync::mpsc::channel();
-
-        // First thread starts an immediate transaction, then waits on a synchronization channel
-        // before trying to get the `KeyIdGuard`.
-        let handle_a = thread::spawn(move || {
-            let temp_dir = temp_dir_clone_a;
-            let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
-
-            // Make sure the other thread has initialized its database access before we lock it out.
-            a_receiver.recv().unwrap();
-
-            let _result =
-                db.with_transaction_timeout(Immediate("TX_test"), Duration::from_secs(3), |_tx| {
-                    // Notify the other thread that we're inside the immediate transaction...
-                    a_sender.send(()).unwrap();
-                    // ...then wait to be sure that the other thread has the `KeyIdGuard` before
-                    // this thread also tries to get it.
-                    a_receiver.recv().unwrap();
-
-                    let _guard = KEY_ID_LOCK.get(key_id);
-                    Ok(()).no_gc()
-                });
-        });
-
-        // Second thread gets the `KeyIdGuard`, then waits before trying to perform an immediate
-        // transaction.
-        let handle_b = thread::spawn(move || {
-            let temp_dir = temp_dir_clone_b;
-            let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
-            // Notify the other thread that we are initialized (so it can lock the immediate
-            // transaction).
-            b_sender.send(()).unwrap();
-
-            let _guard = KEY_ID_LOCK.get(key_id);
-            // Notify the other thread that we have the `KeyIdGuard`...
-            b_sender.send(()).unwrap();
-            // ...then wait to be sure that the other thread is in the immediate transaction before
-            // this thread also tries to do one.
-            b_receiver.recv().unwrap();
-
-            let result =
-                db.with_transaction_timeout(Immediate("TX_test"), Duration::from_secs(3), |_tx| {
-                    Ok(()).no_gc()
-                });
-            // Expect the attempt to get an immediate transaction to fail, and then this thread will
-            // exit and release the `KeyIdGuard`, allowing the other thread to complete.
-            assert!(result.is_err());
-            check_result_is_error_containing_string(result, "BACKEND_BUSY");
-        });
-
-        let _ = handle_a.join();
-        let _ = handle_b.join();
-
-        Ok(())
-    }
-}
diff --git a/keystore2/src/database/perboot.rs b/keystore2/src/database/perboot.rs
index 4727015f..a1890a66 100644
--- a/keystore2/src/database/perboot.rs
+++ b/keystore2/src/database/perboot.rs
@@ -19,9 +19,9 @@ use super::AuthTokenEntry;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
 };
-use lazy_static::lazy_static;
 use std::collections::HashSet;
 use std::sync::Arc;
+use std::sync::LazyLock;
 use std::sync::RwLock;
 
 #[derive(PartialEq, PartialOrd, Ord, Eq, Hash)]
@@ -70,11 +70,9 @@ pub struct PerbootDB {
     auth_tokens: RwLock<HashSet<AuthTokenEntryWrap>>,
 }
 
-lazy_static! {
-    /// The global instance of the perboot DB. Located here rather than in globals
-    /// in order to restrict access to the database module.
-    pub static ref PERBOOT_DB: Arc<PerbootDB> = Arc::new(PerbootDB::new());
-}
+/// The global instance of the perboot DB. Located here rather than in globals
+/// in order to restrict access to the database module.
+pub static PERBOOT_DB: LazyLock<Arc<PerbootDB>> = LazyLock::new(|| Arc::new(PerbootDB::new()));
 
 impl PerbootDB {
     /// Construct a new perboot database. Currently just uses default values.
diff --git a/keystore2/src/database/tests.rs b/keystore2/src/database/tests.rs
new file mode 100644
index 00000000..5f882cda
--- /dev/null
+++ b/keystore2/src/database/tests.rs
@@ -0,0 +1,2755 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Database tests.
+
+use super::*;
+use crate::key_parameter::{
+    Algorithm, BlockMode, Digest, EcCurve, HardwareAuthenticatorType, KeyOrigin, KeyParameter,
+    KeyParameterValue, KeyPurpose, PaddingMode, SecurityLevel,
+};
+use crate::key_perm_set;
+use crate::permission::{KeyPerm, KeyPermSet};
+use crate::super_key::{SuperKeyManager, USER_AFTER_FIRST_UNLOCK_SUPER_KEY, SuperEncryptionAlgorithm, SuperKeyType};
+use keystore2_test_utils::TempDir;
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    HardwareAuthToken::HardwareAuthToken,
+    HardwareAuthenticatorType::HardwareAuthenticatorType as kmhw_authenticator_type,
+};
+use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
+    Timestamp::Timestamp,
+};
+use std::cell::RefCell;
+use std::collections::BTreeMap;
+use std::fmt::Write;
+use std::sync::atomic::{AtomicU8, Ordering};
+use std::sync::Arc;
+use std::thread;
+use std::time::{Duration, SystemTime};
+use crate::utils::AesGcm;
+#[cfg(disabled)]
+use std::time::Instant;
+
+pub fn new_test_db() -> Result<KeystoreDB> {
+    new_test_db_at("file::memory:")
+}
+
+fn new_test_db_at(path: &str) -> Result<KeystoreDB> {
+    let conn = KeystoreDB::make_connection(path)?;
+
+    let mut db = KeystoreDB { conn, gc: None, perboot: Arc::new(perboot::PerbootDB::new()) };
+    db.with_transaction(Immediate("TX_new_test_db"), |tx| {
+        KeystoreDB::init_tables(tx).context("Failed to initialize tables.").no_gc()
+    })?;
+    Ok(db)
+}
+
+fn rebind_alias(
+    db: &mut KeystoreDB,
+    newid: &KeyIdGuard,
+    alias: &str,
+    domain: Domain,
+    namespace: i64,
+) -> Result<bool> {
+    db.with_transaction(Immediate("TX_rebind_alias"), |tx| {
+        KeystoreDB::rebind_alias(tx, newid, alias, &domain, &namespace, KeyType::Client).no_gc()
+    })
+    .context(ks_err!())
+}
+
+#[test]
+fn datetime() -> Result<()> {
+    let conn = Connection::open_in_memory()?;
+    conn.execute("CREATE TABLE test (ts DATETIME);", [])?;
+    let now = SystemTime::now();
+    let duration = Duration::from_secs(1000);
+    let then = now.checked_sub(duration).unwrap();
+    let soon = now.checked_add(duration).unwrap();
+    conn.execute(
+        "INSERT INTO test (ts) VALUES (?), (?), (?);",
+        params![DateTime::try_from(now)?, DateTime::try_from(then)?, DateTime::try_from(soon)?],
+    )?;
+    let mut stmt = conn.prepare("SELECT ts FROM test ORDER BY ts ASC;")?;
+    let mut rows = stmt.query([])?;
+    assert_eq!(DateTime::try_from(then)?, rows.next()?.unwrap().get(0)?);
+    assert_eq!(DateTime::try_from(now)?, rows.next()?.unwrap().get(0)?);
+    assert_eq!(DateTime::try_from(soon)?, rows.next()?.unwrap().get(0)?);
+    assert!(rows.next()?.is_none());
+    assert!(DateTime::try_from(then)? < DateTime::try_from(now)?);
+    assert!(DateTime::try_from(then)? < DateTime::try_from(soon)?);
+    assert!(DateTime::try_from(now)? < DateTime::try_from(soon)?);
+    Ok(())
+}
+
+// Ensure that we're using the "injected" random function, not the real one.
+#[test]
+fn test_mocked_random() {
+    let rand1 = random();
+    let rand2 = random();
+    let rand3 = random();
+    if rand1 == rand2 {
+        assert_eq!(rand2 + 1, rand3);
+    } else {
+        assert_eq!(rand1 + 1, rand2);
+        assert_eq!(rand2, rand3);
+    }
+}
+
+// Test that we have the correct tables.
+#[test]
+fn test_tables() -> Result<()> {
+    let db = new_test_db()?;
+    let tables = db
+        .conn
+        .prepare("SELECT name from persistent.sqlite_master WHERE type='table' ORDER BY name;")?
+        .query_map(params![], |row| row.get(0))?
+        .collect::<rusqlite::Result<Vec<String>>>()?;
+    assert_eq!(tables.len(), 6);
+    assert_eq!(tables[0], "blobentry");
+    assert_eq!(tables[1], "blobmetadata");
+    assert_eq!(tables[2], "grant");
+    assert_eq!(tables[3], "keyentry");
+    assert_eq!(tables[4], "keymetadata");
+    assert_eq!(tables[5], "keyparameter");
+    Ok(())
+}
+
+#[test]
+fn test_auth_token_table_invariant() -> Result<()> {
+    let mut db = new_test_db()?;
+    let auth_token1 = HardwareAuthToken {
+        challenge: i64::MAX,
+        userId: 200,
+        authenticatorId: 200,
+        authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
+        timestamp: Timestamp { milliSeconds: 500 },
+        mac: String::from("mac").into_bytes(),
+    };
+    db.insert_auth_token(&auth_token1);
+    let auth_tokens_returned = get_auth_tokens(&db);
+    assert_eq!(auth_tokens_returned.len(), 1);
+
+    // insert another auth token with the same values for the columns in the UNIQUE constraint
+    // of the auth token table and different value for timestamp
+    let auth_token2 = HardwareAuthToken {
+        challenge: i64::MAX,
+        userId: 200,
+        authenticatorId: 200,
+        authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
+        timestamp: Timestamp { milliSeconds: 600 },
+        mac: String::from("mac").into_bytes(),
+    };
+
+    db.insert_auth_token(&auth_token2);
+    let mut auth_tokens_returned = get_auth_tokens(&db);
+    assert_eq!(auth_tokens_returned.len(), 1);
+
+    if let Some(auth_token) = auth_tokens_returned.pop() {
+        assert_eq!(auth_token.auth_token.timestamp.milliSeconds, 600);
+    }
+
+    // insert another auth token with the different values for the columns in the UNIQUE
+    // constraint of the auth token table
+    let auth_token3 = HardwareAuthToken {
+        challenge: i64::MAX,
+        userId: 201,
+        authenticatorId: 200,
+        authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
+        timestamp: Timestamp { milliSeconds: 600 },
+        mac: String::from("mac").into_bytes(),
+    };
+
+    db.insert_auth_token(&auth_token3);
+    let auth_tokens_returned = get_auth_tokens(&db);
+    assert_eq!(auth_tokens_returned.len(), 2);
+
+    Ok(())
+}
+
+// utility function for test_auth_token_table_invariant()
+fn get_auth_tokens(db: &KeystoreDB) -> Vec<AuthTokenEntry> {
+    db.perboot.get_all_auth_token_entries()
+}
+
+fn create_key_entry(
+    db: &mut KeystoreDB,
+    domain: &Domain,
+    namespace: &i64,
+    key_type: KeyType,
+    km_uuid: &Uuid,
+) -> Result<KeyIdGuard> {
+    db.with_transaction(Immediate("TX_create_key_entry"), |tx| {
+        KeystoreDB::create_key_entry_internal(tx, domain, namespace, key_type, km_uuid).no_gc()
+    })
+}
+
+#[test]
+fn test_persistence_for_files() -> Result<()> {
+    let temp_dir = TempDir::new("persistent_db_test")?;
+    let mut db = KeystoreDB::new(temp_dir.path(), None)?;
+
+    create_key_entry(&mut db, &Domain::APP, &100, KeyType::Client, &KEYSTORE_UUID)?;
+    let entries = get_keyentry(&db)?;
+    assert_eq!(entries.len(), 1);
+
+    let db = KeystoreDB::new(temp_dir.path(), None)?;
+
+    let entries_new = get_keyentry(&db)?;
+    assert_eq!(entries, entries_new);
+    Ok(())
+}
+
+#[test]
+fn test_create_key_entry() -> Result<()> {
+    fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>, Uuid) {
+        (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref(), ke.km_uuid.unwrap())
+    }
+
+    let mut db = new_test_db()?;
+
+    create_key_entry(&mut db, &Domain::APP, &100, KeyType::Client, &KEYSTORE_UUID)?;
+    create_key_entry(&mut db, &Domain::SELINUX, &101, KeyType::Client, &KEYSTORE_UUID)?;
+
+    let entries = get_keyentry(&db)?;
+    assert_eq!(entries.len(), 2);
+    assert_eq!(extractor(&entries[0]), (Domain::APP, 100, None, KEYSTORE_UUID));
+    assert_eq!(extractor(&entries[1]), (Domain::SELINUX, 101, None, KEYSTORE_UUID));
+
+    // Test that we must pass in a valid Domain.
+    check_result_is_error_containing_string(
+        create_key_entry(&mut db, &Domain::GRANT, &102, KeyType::Client, &KEYSTORE_UUID),
+        &format!("Domain {:?} must be either App or SELinux.", Domain::GRANT),
+    );
+    check_result_is_error_containing_string(
+        create_key_entry(&mut db, &Domain::BLOB, &103, KeyType::Client, &KEYSTORE_UUID),
+        &format!("Domain {:?} must be either App or SELinux.", Domain::BLOB),
+    );
+    check_result_is_error_containing_string(
+        create_key_entry(&mut db, &Domain::KEY_ID, &104, KeyType::Client, &KEYSTORE_UUID),
+        &format!("Domain {:?} must be either App or SELinux.", Domain::KEY_ID),
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_rebind_alias() -> Result<()> {
+    fn extractor(ke: &KeyEntryRow) -> (Option<Domain>, Option<i64>, Option<&str>, Option<Uuid>) {
+        (ke.domain, ke.namespace, ke.alias.as_deref(), ke.km_uuid)
+    }
+
+    let mut db = new_test_db()?;
+    create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
+    create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
+    let entries = get_keyentry(&db)?;
+    assert_eq!(entries.len(), 2);
+    assert_eq!(extractor(&entries[0]), (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID)));
+    assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID)));
+
+    // Test that the first call to rebind_alias sets the alias.
+    rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[0].id), "foo", Domain::APP, 42)?;
+    let entries = get_keyentry(&db)?;
+    assert_eq!(entries.len(), 2);
+    assert_eq!(
+        extractor(&entries[0]),
+        (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
+    );
+    assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID)));
+
+    // Test that the second call to rebind_alias also empties the old one.
+    rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[1].id), "foo", Domain::APP, 42)?;
+    let entries = get_keyentry(&db)?;
+    assert_eq!(entries.len(), 2);
+    assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
+    assert_eq!(
+        extractor(&entries[1]),
+        (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
+    );
+
+    // Test that we must pass in a valid Domain.
+    check_result_is_error_containing_string(
+        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::GRANT, 42),
+        &format!("Domain {:?} must be either App or SELinux.", Domain::GRANT),
+    );
+    check_result_is_error_containing_string(
+        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::BLOB, 42),
+        &format!("Domain {:?} must be either App or SELinux.", Domain::BLOB),
+    );
+    check_result_is_error_containing_string(
+        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::KEY_ID, 42),
+        &format!("Domain {:?} must be either App or SELinux.", Domain::KEY_ID),
+    );
+
+    // Test that we correctly handle setting an alias for something that does not exist.
+    check_result_is_error_containing_string(
+        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::SELINUX, 42),
+        "Expected to update a single entry but instead updated 0",
+    );
+    // Test that we correctly abort the transaction in this case.
+    let entries = get_keyentry(&db)?;
+    assert_eq!(entries.len(), 2);
+    assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
+    assert_eq!(
+        extractor(&entries[1]),
+        (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_grant_ungrant() -> Result<()> {
+    const CALLER_UID: u32 = 15;
+    const GRANTEE_UID: u32 = 12;
+    const SELINUX_NAMESPACE: i64 = 7;
+
+    let mut db = new_test_db()?;
+    db.conn.execute(
+        "INSERT INTO persistent.keyentry (id, key_type, domain, namespace, alias, state, km_uuid)
+                VALUES (1, 0, 0, 15, 'key', 1, ?), (2, 0, 2, 7, 'yek', 1, ?);",
+        params![KEYSTORE_UUID, KEYSTORE_UUID],
+    )?;
+    let app_key = KeyDescriptor {
+        domain: super::Domain::APP,
+        nspace: 0,
+        alias: Some("key".to_string()),
+        blob: None,
+    };
+    const PVEC1: KeyPermSet = key_perm_set![KeyPerm::Use, KeyPerm::GetInfo];
+    const PVEC2: KeyPermSet = key_perm_set![KeyPerm::Use];
+
+    // Reset totally predictable random number generator in case we
+    // are not the first test running on this thread.
+    reset_random();
+    let next_random = 0i64;
+
+    let app_granted_key = db
+        .grant(&app_key, CALLER_UID, GRANTEE_UID, PVEC1, |k, a| {
+            assert_eq!(*a, PVEC1);
+            assert_eq!(
+                *k,
+                KeyDescriptor {
+                    domain: super::Domain::APP,
+                    // namespace must be set to the caller_uid.
+                    nspace: CALLER_UID as i64,
+                    alias: Some("key".to_string()),
+                    blob: None,
+                }
+            );
+            Ok(())
+        })
+        .unwrap();
+
+    assert_eq!(
+        app_granted_key,
+        KeyDescriptor {
+            domain: super::Domain::GRANT,
+            // The grantid is next_random due to the mock random number generator.
+            nspace: next_random,
+            alias: None,
+            blob: None,
+        }
+    );
+
+    let selinux_key = KeyDescriptor {
+        domain: super::Domain::SELINUX,
+        nspace: SELINUX_NAMESPACE,
+        alias: Some("yek".to_string()),
+        blob: None,
+    };
+
+    let selinux_granted_key = db
+        .grant(&selinux_key, CALLER_UID, 12, PVEC1, |k, a| {
+            assert_eq!(*a, PVEC1);
+            assert_eq!(
+                *k,
+                KeyDescriptor {
+                    domain: super::Domain::SELINUX,
+                    // namespace must be the supplied SELinux
+                    // namespace.
+                    nspace: SELINUX_NAMESPACE,
+                    alias: Some("yek".to_string()),
+                    blob: None,
+                }
+            );
+            Ok(())
+        })
+        .unwrap();
+
+    assert_eq!(
+        selinux_granted_key,
+        KeyDescriptor {
+            domain: super::Domain::GRANT,
+            // The grantid is next_random + 1 due to the mock random number generator.
+            nspace: next_random + 1,
+            alias: None,
+            blob: None,
+        }
+    );
+
+    // This should update the existing grant with PVEC2.
+    let selinux_granted_key = db
+        .grant(&selinux_key, CALLER_UID, 12, PVEC2, |k, a| {
+            assert_eq!(*a, PVEC2);
+            assert_eq!(
+                *k,
+                KeyDescriptor {
+                    domain: super::Domain::SELINUX,
+                    // namespace must be the supplied SELinux
+                    // namespace.
+                    nspace: SELINUX_NAMESPACE,
+                    alias: Some("yek".to_string()),
+                    blob: None,
+                }
+            );
+            Ok(())
+        })
+        .unwrap();
+
+    assert_eq!(
+        selinux_granted_key,
+        KeyDescriptor {
+            domain: super::Domain::GRANT,
+            // Same grant id as before. The entry was only updated.
+            nspace: next_random + 1,
+            alias: None,
+            blob: None,
+        }
+    );
+
+    {
+        // Limiting scope of stmt, because it borrows db.
+        let mut stmt = db
+            .conn
+            .prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
+        let mut rows = stmt.query_map::<(i64, u32, i64, KeyPermSet), _, _>([], |row| {
+            Ok((row.get(0)?, row.get(1)?, row.get(2)?, KeyPermSet::from(row.get::<_, i32>(3)?)))
+        })?;
+
+        let r = rows.next().unwrap().unwrap();
+        assert_eq!(r, (next_random, GRANTEE_UID, 1, PVEC1));
+        let r = rows.next().unwrap().unwrap();
+        assert_eq!(r, (next_random + 1, GRANTEE_UID, 2, PVEC2));
+        assert!(rows.next().is_none());
+    }
+
+    debug_dump_keyentry_table(&mut db)?;
+    println!("app_key {:?}", app_key);
+    println!("selinux_key {:?}", selinux_key);
+
+    db.ungrant(&app_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
+    db.ungrant(&selinux_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
+
+    Ok(())
+}
+
+static TEST_KEY_BLOB: &[u8] = b"my test blob";
+static TEST_CERT_BLOB: &[u8] = b"my test cert";
+static TEST_CERT_CHAIN_BLOB: &[u8] = b"my test cert_chain";
+
+#[test]
+fn test_set_blob() -> Result<()> {
+    let key_id = KEY_ID_LOCK.get(3000);
+    let mut db = new_test_db()?;
+    let mut blob_metadata = BlobMetaData::new();
+    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
+    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
+    db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
+    db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
+    drop(key_id);
+
+    let mut stmt = db.conn.prepare(
+        "SELECT subcomponent_type, keyentryid, blob, id FROM persistent.blobentry
+                ORDER BY subcomponent_type ASC;",
+    )?;
+    let mut rows = stmt.query_map::<((SubComponentType, i64, Vec<u8>), i64), _, _>([], |row| {
+        Ok(((row.get(0)?, row.get(1)?, row.get(2)?), row.get(3)?))
+    })?;
+    let (r, id) = rows.next().unwrap().unwrap();
+    assert_eq!(r, (SubComponentType::KEY_BLOB, 3000, TEST_KEY_BLOB.to_vec()));
+    let (r, _) = rows.next().unwrap().unwrap();
+    assert_eq!(r, (SubComponentType::CERT, 3000, TEST_CERT_BLOB.to_vec()));
+    let (r, _) = rows.next().unwrap().unwrap();
+    assert_eq!(r, (SubComponentType::CERT_CHAIN, 3000, TEST_CERT_CHAIN_BLOB.to_vec()));
+
+    drop(rows);
+    drop(stmt);
+
+    assert_eq!(
+        db.with_transaction(Immediate("TX_test"), |tx| {
+            BlobMetaData::load_from_db(id, tx).no_gc()
+        })
+        .expect("Should find blob metadata."),
+        blob_metadata
+    );
+    Ok(())
+}
+
+static TEST_ALIAS: &str = "my super duper key";
+
+#[test]
+fn test_insert_and_load_full_keyentry_domain_app() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
+        .context("test_insert_and_load_full_keyentry_domain_app")?
+        .0;
+    let (_key_guard, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: 0,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    db.unbind_key(
+        &KeyDescriptor {
+            domain: Domain::APP,
+            nspace: 0,
+            alias: Some(TEST_ALIAS.to_string()),
+            blob: None,
+        },
+        KeyType::Client,
+        1,
+        |_, _| Ok(()),
+    )
+    .unwrap();
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: 0,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_insert_and_load_certificate_entry_domain_app() -> Result<()> {
+    let mut db = new_test_db()?;
+
+    db.store_new_certificate(
+        &KeyDescriptor {
+            domain: Domain::APP,
+            nspace: 1,
+            alias: Some(TEST_ALIAS.to_string()),
+            blob: None,
+        },
+        KeyType::Client,
+        TEST_CERT_BLOB,
+        &KEYSTORE_UUID,
+    )
+    .expect("Trying to insert cert.");
+
+    let (_key_guard, mut key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: 1,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::PUBLIC,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .expect("Trying to read certificate entry.");
+
+    assert!(key_entry.pure_cert());
+    assert!(key_entry.cert().is_none());
+    assert_eq!(key_entry.take_cert_chain(), Some(TEST_CERT_BLOB.to_vec()));
+
+    db.unbind_key(
+        &KeyDescriptor {
+            domain: Domain::APP,
+            nspace: 1,
+            alias: Some(TEST_ALIAS.to_string()),
+            blob: None,
+        },
+        KeyType::Client,
+        1,
+        |_, _| Ok(()),
+    )
+    .unwrap();
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: 1,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_insert_and_load_full_keyentry_domain_selinux() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
+        .context("test_insert_and_load_full_keyentry_domain_selinux")?
+        .0;
+    let (_key_guard, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::SELINUX,
+                nspace: 1,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    db.unbind_key(
+        &KeyDescriptor {
+            domain: Domain::SELINUX,
+            nspace: 1,
+            alias: Some(TEST_ALIAS.to_string()),
+            blob: None,
+        },
+        KeyType::Client,
+        1,
+        |_, _| Ok(()),
+    )
+    .unwrap();
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::SELINUX,
+                nspace: 1,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_insert_and_load_full_keyentry_domain_key_id() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
+        .context("test_insert_and_load_full_keyentry_domain_key_id")?
+        .0;
+    let (_, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap();
+
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    db.unbind_key(
+        &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
+        KeyType::Client,
+        1,
+        |_, _| Ok(()),
+    )
+    .unwrap();
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            1,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_check_and_update_key_usage_count_with_limited_use_key() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(123))
+        .context("test_check_and_update_key_usage_count_with_limited_use_key")?
+        .0;
+    // Update the usage count of the limited use key.
+    db.check_and_update_key_usage_count(key_id)?;
+
+    let (_key_guard, key_entry) = db.load_key_entry(
+        &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
+        KeyType::Client,
+        KeyEntryLoadBits::BOTH,
+        1,
+        |_k, _av| Ok(()),
+    )?;
+
+    // The usage count is decremented now.
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, Some(122)));
+
+    Ok(())
+}
+
+#[test]
+fn test_check_and_update_key_usage_count_with_exhausted_limited_use_key() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(1))
+        .context("test_check_and_update_key_usage_count_with_exhausted_limited_use_key")?
+        .0;
+    // Update the usage count of the limited use key.
+    db.check_and_update_key_usage_count(key_id).expect(concat!(
+        "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
+        "This should succeed."
+    ));
+
+    // Try to update the exhausted limited use key.
+    let e = db.check_and_update_key_usage_count(key_id).expect_err(concat!(
+        "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
+        "This should fail."
+    ));
+    assert_eq!(
+        &KsError::Km(ErrorCode::INVALID_KEY_BLOB),
+        e.root_cause().downcast_ref::<KsError>().unwrap()
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_insert_and_load_full_keyentry_from_grant() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
+        .context("test_insert_and_load_full_keyentry_from_grant")?
+        .0;
+
+    let granted_key = db
+        .grant(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: 0,
+                alias: Some(TEST_ALIAS.to_string()),
+                blob: None,
+            },
+            1,
+            2,
+            key_perm_set![KeyPerm::Use],
+            |_k, _av| Ok(()),
+        )
+        .unwrap();
+
+    debug_dump_grant_table(&mut db)?;
+
+    let (_key_guard, key_entry) = db
+        .load_key_entry(&granted_key, KeyType::Client, KeyEntryLoadBits::BOTH, 2, |k, av| {
+            assert_eq!(Domain::GRANT, k.domain);
+            assert!(av.unwrap().includes(KeyPerm::Use));
+            Ok(())
+        })
+        .unwrap();
+
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    db.unbind_key(&granted_key, KeyType::Client, 2, |_, _| Ok(())).unwrap();
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(&granted_key, KeyType::Client, KeyEntryLoadBits::NONE, 2, |_k, _av| Ok(
+            ()
+        ),)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+// This test attempts to load a key by key id while the caller is not the owner
+// but a grant exists for the given key and the caller.
+#[test]
+fn test_insert_and_load_full_keyentry_from_grant_by_key_id() -> Result<()> {
+    let mut db = new_test_db()?;
+    const OWNER_UID: u32 = 1u32;
+    const GRANTEE_UID: u32 = 2u32;
+    const SOMEONE_ELSE_UID: u32 = 3u32;
+    let key_id = make_test_key_entry(&mut db, Domain::APP, OWNER_UID as i64, TEST_ALIAS, None)
+        .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?
+        .0;
+
+    db.grant(
+        &KeyDescriptor {
+            domain: Domain::APP,
+            nspace: 0,
+            alias: Some(TEST_ALIAS.to_string()),
+            blob: None,
+        },
+        OWNER_UID,
+        GRANTEE_UID,
+        key_perm_set![KeyPerm::Use],
+        |_k, _av| Ok(()),
+    )
+    .unwrap();
+
+    debug_dump_grant_table(&mut db)?;
+
+    let id_descriptor =
+        KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, ..Default::default() };
+
+    let (_, key_entry) = db
+        .load_key_entry(
+            &id_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            GRANTEE_UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(OWNER_UID as i64, k.nspace);
+                assert!(av.unwrap().includes(KeyPerm::Use));
+                Ok(())
+            },
+        )
+        .unwrap();
+
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    let (_, key_entry) = db
+        .load_key_entry(
+            &id_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            SOMEONE_ELSE_UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(OWNER_UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    db.unbind_key(&id_descriptor, KeyType::Client, OWNER_UID, |_, _| Ok(())).unwrap();
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &id_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            GRANTEE_UID,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+// Creates a key migrates it to a different location and then tries to access it by the old
+// and new location.
+#[test]
+fn test_migrate_key_app_to_app() -> Result<()> {
+    let mut db = new_test_db()?;
+    const SOURCE_UID: u32 = 1u32;
+    const DESTINATION_UID: u32 = 2u32;
+    static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
+    static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
+    let key_id_guard =
+        make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
+            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
+
+    let source_descriptor: KeyDescriptor = KeyDescriptor {
+        domain: Domain::APP,
+        nspace: -1,
+        alias: Some(SOURCE_ALIAS.to_string()),
+        blob: None,
+    };
+
+    let destination_descriptor: KeyDescriptor = KeyDescriptor {
+        domain: Domain::APP,
+        nspace: -1,
+        alias: Some(DESTINATION_ALIAS.to_string()),
+        blob: None,
+    };
+
+    let key_id = key_id_guard.id();
+
+    db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| Ok(()))
+        .unwrap();
+
+    let (_, key_entry) = db
+        .load_key_entry(
+            &destination_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            DESTINATION_UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(DESTINATION_UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &source_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            SOURCE_UID,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+// Creates a key migrates it to a different location and then tries to access it by the old
+// and new location.
+#[test]
+fn test_migrate_key_app_to_selinux() -> Result<()> {
+    let mut db = new_test_db()?;
+    const SOURCE_UID: u32 = 1u32;
+    const DESTINATION_UID: u32 = 2u32;
+    const DESTINATION_NAMESPACE: i64 = 1000i64;
+    static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
+    static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
+    let key_id_guard =
+        make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
+            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
+
+    let source_descriptor: KeyDescriptor = KeyDescriptor {
+        domain: Domain::APP,
+        nspace: -1,
+        alias: Some(SOURCE_ALIAS.to_string()),
+        blob: None,
+    };
+
+    let destination_descriptor: KeyDescriptor = KeyDescriptor {
+        domain: Domain::SELINUX,
+        nspace: DESTINATION_NAMESPACE,
+        alias: Some(DESTINATION_ALIAS.to_string()),
+        blob: None,
+    };
+
+    let key_id = key_id_guard.id();
+
+    db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| Ok(()))
+        .unwrap();
+
+    let (_, key_entry) = db
+        .load_key_entry(
+            &destination_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            DESTINATION_UID,
+            |k, av| {
+                assert_eq!(Domain::SELINUX, k.domain);
+                assert_eq!(DESTINATION_NAMESPACE, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &source_descriptor,
+            KeyType::Client,
+            KeyEntryLoadBits::NONE,
+            SOURCE_UID,
+            |_k, _av| Ok(()),
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+// Creates two keys and tries to migrate the first to the location of the second which
+// is expected to fail.
+#[test]
+fn test_migrate_key_destination_occupied() -> Result<()> {
+    let mut db = new_test_db()?;
+    const SOURCE_UID: u32 = 1u32;
+    const DESTINATION_UID: u32 = 2u32;
+    static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
+    static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
+    let key_id_guard =
+        make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
+            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
+    make_test_key_entry(&mut db, Domain::APP, DESTINATION_UID as i64, DESTINATION_ALIAS, None)
+        .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
+
+    let destination_descriptor: KeyDescriptor = KeyDescriptor {
+        domain: Domain::APP,
+        nspace: -1,
+        alias: Some(DESTINATION_ALIAS.to_string()),
+        blob: None,
+    };
+
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::INVALID_ARGUMENT)),
+        db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| Ok(
+            ()
+        ))
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_upgrade_0_to_1() {
+    const ALIAS1: &str = "test_upgrade_0_to_1_1";
+    const ALIAS2: &str = "test_upgrade_0_to_1_2";
+    const ALIAS3: &str = "test_upgrade_0_to_1_3";
+    const UID: u32 = 33;
+    let temp_dir = Arc::new(TempDir::new("test_upgrade_0_to_1").unwrap());
+    let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
+    let key_id_untouched1 =
+        make_test_key_entry(&mut db, Domain::APP, UID as i64, ALIAS1, None).unwrap().id();
+    let key_id_untouched2 =
+        make_bootlevel_key_entry(&mut db, Domain::APP, UID as i64, ALIAS2, false).unwrap().id();
+    let key_id_deleted =
+        make_bootlevel_key_entry(&mut db, Domain::APP, UID as i64, ALIAS3, true).unwrap().id();
+
+    let (_, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(ALIAS1.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id_untouched1, None));
+    let (_, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(ALIAS2.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_untouched2, false));
+    let (_, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(ALIAS3.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_deleted, true));
+
+    db.with_transaction(Immediate("TX_test"), |tx| KeystoreDB::from_0_to_1(tx).no_gc()).unwrap();
+
+    let (_, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(ALIAS1.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id_untouched1, None));
+    let (_, key_entry) = db
+        .load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(ALIAS2.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap();
+    assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_untouched2, false));
+    assert_eq!(
+        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
+        db.load_key_entry(
+            &KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(ALIAS3.to_string()),
+                blob: None,
+            },
+            KeyType::Client,
+            KeyEntryLoadBits::BOTH,
+            UID,
+            |k, av| {
+                assert_eq!(Domain::APP, k.domain);
+                assert_eq!(UID as i64, k.nspace);
+                assert!(av.is_none());
+                Ok(())
+            },
+        )
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+}
+
+static KEY_LOCK_TEST_ALIAS: &str = "my super duper locked key";
+
+#[test]
+fn test_insert_and_load_full_keyentry_domain_app_concurrently() -> Result<()> {
+    let handle = {
+        let temp_dir = Arc::new(TempDir::new("id_lock_test")?);
+        let temp_dir_clone = temp_dir.clone();
+        let mut db = KeystoreDB::new(temp_dir.path(), None)?;
+        let key_id = make_test_key_entry(&mut db, Domain::APP, 33, KEY_LOCK_TEST_ALIAS, None)
+            .context("test_insert_and_load_full_keyentry_domain_app")?
+            .0;
+        let (_key_guard, key_entry) = db
+            .load_key_entry(
+                &KeyDescriptor {
+                    domain: Domain::APP,
+                    nspace: 0,
+                    alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
+                    blob: None,
+                },
+                KeyType::Client,
+                KeyEntryLoadBits::BOTH,
+                33,
+                |_k, _av| Ok(()),
+            )
+            .unwrap();
+        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
+        let state = Arc::new(AtomicU8::new(1));
+        let state2 = state.clone();
+
+        // Spawning a second thread that attempts to acquire the key id lock
+        // for the same key as the primary thread. The primary thread then
+        // waits, thereby forcing the secondary thread into the second stage
+        // of acquiring the lock (see KEY ID LOCK 2/2 above).
+        // The test succeeds if the secondary thread observes the transition
+        // of `state` from 1 to 2, despite having a whole second to overtake
+        // the primary thread.
+        let handle = thread::spawn(move || {
+            let temp_dir = temp_dir_clone;
+            let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
+            assert!(db
+                .load_key_entry(
+                    &KeyDescriptor {
+                        domain: Domain::APP,
+                        nspace: 0,
+                        alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
+                        blob: None,
+                    },
+                    KeyType::Client,
+                    KeyEntryLoadBits::BOTH,
+                    33,
+                    |_k, _av| Ok(()),
+                )
+                .is_ok());
+            // We should only see a 2 here because we can only return
+            // from load_key_entry when the `_key_guard` expires,
+            // which happens at the end of the scope.
+            assert_eq!(2, state2.load(Ordering::Relaxed));
+        });
+
+        thread::sleep(std::time::Duration::from_millis(1000));
+
+        assert_eq!(Ok(1), state.compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed));
+
+        // Return the handle from this scope so we can join with the
+        // secondary thread after the key id lock has expired.
+        handle
+        // This is where the `_key_guard` goes out of scope,
+        // which is the reason for concurrent load_key_entry on the same key
+        // to unblock.
+    };
+    // Join with the secondary thread and unwrap, to propagate failing asserts to the
+    // main test thread. We will not see failing asserts in secondary threads otherwise.
+    handle.join().unwrap();
+    Ok(())
+}
+
+#[test]
+fn test_database_busy_error_code() {
+    let temp_dir =
+        TempDir::new("test_database_busy_error_code_").expect("Failed to create temp dir.");
+
+    let mut db1 = KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database1.");
+    let mut db2 = KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database2.");
+
+    let _tx1 = db1
+        .conn
+        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
+        .expect("Failed to create first transaction.");
+
+    let error = db2
+        .conn
+        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
+        .context("Transaction begin failed.")
+        .expect_err("This should fail.");
+    let root_cause = error.root_cause();
+    if let Some(rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, .. }) =
+        root_cause.downcast_ref::<rusqlite::ffi::Error>()
+    {
+        return;
+    }
+    panic!(
+        "Unexpected error {:?} \n{:?} \n{:?}",
+        error,
+        root_cause,
+        root_cause.downcast_ref::<rusqlite::ffi::Error>()
+    )
+}
+
+#[cfg(disabled)]
+#[test]
+fn test_large_number_of_concurrent_db_manipulations() -> Result<()> {
+    let temp_dir = Arc::new(
+        TempDir::new("test_large_number_of_concurrent_db_manipulations_")
+            .expect("Failed to create temp dir."),
+    );
+
+    let test_begin = Instant::now();
+
+    const KEY_COUNT: u32 = 500u32;
+    let mut db =
+        new_test_db_with_gc(temp_dir.path(), |_, _| Ok(())).expect("Failed to open database.");
+    const OPEN_DB_COUNT: u32 = 50u32;
+
+    let mut actual_key_count = KEY_COUNT;
+    // First insert KEY_COUNT keys.
+    for count in 0..KEY_COUNT {
+        if Instant::now().duration_since(test_begin) >= Duration::from_secs(15) {
+            actual_key_count = count;
+            break;
+        }
+        let alias = format!("test_alias_{}", count);
+        make_test_key_entry(&mut db, Domain::APP, 1, &alias, None)
+            .expect("Failed to make key entry.");
+    }
+
+    // Insert more keys from a different thread and into a different namespace.
+    let temp_dir1 = temp_dir.clone();
+    let handle1 = thread::spawn(move || {
+        let mut db =
+            new_test_db_with_gc(temp_dir1.path(), |_, _| Ok(())).expect("Failed to open database.");
+
+        for count in 0..actual_key_count {
+            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
+                return;
+            }
+            let alias = format!("test_alias_{}", count);
+            make_test_key_entry(&mut db, Domain::APP, 2, &alias, None)
+                .expect("Failed to make key entry.");
+        }
+
+        // then unbind them again.
+        for count in 0..actual_key_count {
+            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
+                return;
+            }
+            let key = KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(format!("test_alias_{}", count)),
+                blob: None,
+            };
+            db.unbind_key(&key, KeyType::Client, 2, |_, _| Ok(())).expect("Unbind Failed.");
+        }
+    });
+
+    // And start unbinding the first set of keys.
+    let temp_dir2 = temp_dir.clone();
+    let handle2 = thread::spawn(move || {
+        let mut db =
+            new_test_db_with_gc(temp_dir2.path(), |_, _| Ok(())).expect("Failed to open database.");
+
+        for count in 0..actual_key_count {
+            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
+                return;
+            }
+            let key = KeyDescriptor {
+                domain: Domain::APP,
+                nspace: -1,
+                alias: Some(format!("test_alias_{}", count)),
+                blob: None,
+            };
+            db.unbind_key(&key, KeyType::Client, 1, |_, _| Ok(())).expect("Unbind Failed.");
+        }
+    });
+
+    // While a lot of inserting and deleting is going on we have to open database connections
+    // successfully and use them.
+    // This clone is not redundant, because temp_dir needs to be kept alive until db goes
+    // out of scope.
+    #[allow(clippy::redundant_clone)]
+    let temp_dir4 = temp_dir.clone();
+    let handle4 = thread::spawn(move || {
+        for count in 0..OPEN_DB_COUNT {
+            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
+                return;
+            }
+            let mut db = new_test_db_with_gc(temp_dir4.path(), |_, _| Ok(()))
+                .expect("Failed to open database.");
+
+            let alias = format!("test_alias_{}", count);
+            make_test_key_entry(&mut db, Domain::APP, 3, &alias, None)
+                .expect("Failed to make key entry.");
+            let key =
+                KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None };
+            db.unbind_key(&key, KeyType::Client, 3, |_, _| Ok(())).expect("Unbind Failed.");
+        }
+    });
+
+    handle1.join().expect("Thread 1 panicked.");
+    handle2.join().expect("Thread 2 panicked.");
+    handle4.join().expect("Thread 4 panicked.");
+
+    Ok(())
+}
+
+#[test]
+fn list() -> Result<()> {
+    let temp_dir = TempDir::new("list_test")?;
+    let mut db = KeystoreDB::new(temp_dir.path(), None)?;
+    static LIST_O_ENTRIES: &[(Domain, i64, &str)] = &[
+        (Domain::APP, 1, "test1"),
+        (Domain::APP, 1, "test2"),
+        (Domain::APP, 1, "test3"),
+        (Domain::APP, 1, "test4"),
+        (Domain::APP, 1, "test5"),
+        (Domain::APP, 1, "test6"),
+        (Domain::APP, 1, "test7"),
+        (Domain::APP, 2, "test1"),
+        (Domain::APP, 2, "test2"),
+        (Domain::APP, 2, "test3"),
+        (Domain::APP, 2, "test4"),
+        (Domain::APP, 2, "test5"),
+        (Domain::APP, 2, "test6"),
+        (Domain::APP, 2, "test8"),
+        (Domain::SELINUX, 100, "test1"),
+        (Domain::SELINUX, 100, "test2"),
+        (Domain::SELINUX, 100, "test3"),
+        (Domain::SELINUX, 100, "test4"),
+        (Domain::SELINUX, 100, "test5"),
+        (Domain::SELINUX, 100, "test6"),
+        (Domain::SELINUX, 100, "test9"),
+    ];
+
+    let list_o_keys: Vec<(i64, i64)> = LIST_O_ENTRIES
+        .iter()
+        .map(|(domain, ns, alias)| {
+            let entry =
+                make_test_key_entry(&mut db, *domain, *ns, alias, None).unwrap_or_else(|e| {
+                    panic!("Failed to insert {:?} {} {}. Error {:?}", domain, ns, alias, e)
+                });
+            (entry.id(), *ns)
+        })
+        .collect();
+
+    for (domain, namespace) in
+        &[(Domain::APP, 1i64), (Domain::APP, 2i64), (Domain::SELINUX, 100i64)]
+    {
+        let mut list_o_descriptors: Vec<KeyDescriptor> = LIST_O_ENTRIES
+            .iter()
+            .filter_map(|(domain, ns, alias)| match ns {
+                ns if *ns == *namespace => Some(KeyDescriptor {
+                    domain: *domain,
+                    nspace: *ns,
+                    alias: Some(alias.to_string()),
+                    blob: None,
+                }),
+                _ => None,
+            })
+            .collect();
+        list_o_descriptors.sort();
+        let mut list_result = db.list_past_alias(*domain, *namespace, KeyType::Client, None)?;
+        list_result.sort();
+        assert_eq!(list_o_descriptors, list_result);
+
+        let mut list_o_ids: Vec<i64> = list_o_descriptors
+            .into_iter()
+            .map(|d| {
+                let (_, entry) = db
+                    .load_key_entry(
+                        &d,
+                        KeyType::Client,
+                        KeyEntryLoadBits::NONE,
+                        *namespace as u32,
+                        |_, _| Ok(()),
+                    )
+                    .unwrap();
+                entry.id()
+            })
+            .collect();
+        list_o_ids.sort_unstable();
+        let mut loaded_entries: Vec<i64> = list_o_keys
+            .iter()
+            .filter_map(|(id, ns)| match ns {
+                ns if *ns == *namespace => Some(*id),
+                _ => None,
+            })
+            .collect();
+        loaded_entries.sort_unstable();
+        assert_eq!(list_o_ids, loaded_entries);
+    }
+    assert_eq!(
+        Vec::<KeyDescriptor>::new(),
+        db.list_past_alias(Domain::SELINUX, 101, KeyType::Client, None)?
+    );
+
+    Ok(())
+}
+
+// Helpers
+
+// Checks that the given result is an error containing the given string.
+fn check_result_is_error_containing_string<T>(result: Result<T>, target: &str) {
+    let error_str =
+        format!("{:#?}", result.err().unwrap_or_else(|| panic!("Expected the error: {}", target)));
+    assert!(
+        error_str.contains(target),
+        "The string \"{}\" should contain \"{}\"",
+        error_str,
+        target
+    );
+}
+
+#[derive(Debug, PartialEq)]
+struct KeyEntryRow {
+    id: i64,
+    key_type: KeyType,
+    domain: Option<Domain>,
+    namespace: Option<i64>,
+    alias: Option<String>,
+    state: KeyLifeCycle,
+    km_uuid: Option<Uuid>,
+}
+
+fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
+    db.conn
+        .prepare("SELECT * FROM persistent.keyentry;")?
+        .query_map([], |row| {
+            Ok(KeyEntryRow {
+                id: row.get(0)?,
+                key_type: row.get(1)?,
+                domain: row.get::<_, Option<_>>(2)?.map(Domain),
+                namespace: row.get(3)?,
+                alias: row.get(4)?,
+                state: row.get(5)?,
+                km_uuid: row.get(6)?,
+            })
+        })?
+        .map(|r| r.context("Could not read keyentry row."))
+        .collect::<Result<Vec<_>>>()
+}
+
+fn make_test_params(max_usage_count: Option<i32>) -> Vec<KeyParameter> {
+    make_test_params_with_sids(max_usage_count, &[42])
+}
+
+// Note: The parameters and SecurityLevel associations are nonsensical. This
+// collection is only used to check if the parameters are preserved as expected by the
+// database.
+fn make_test_params_with_sids(
+    max_usage_count: Option<i32>,
+    user_secure_ids: &[i64],
+) -> Vec<KeyParameter> {
+    let mut params = vec![
+        KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(
+            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::Algorithm(Algorithm::RSA),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(
+            KeyParameterValue::BlockMode(BlockMode::ECB),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::BlockMode(BlockMode::GCM),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::Digest(Digest::NONE), SecurityLevel::STRONGBOX),
+        KeyParameter::new(
+            KeyParameterValue::Digest(Digest::MD5),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::Digest(Digest::SHA_2_224),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::Digest(Digest::SHA_2_256), SecurityLevel::STRONGBOX),
+        KeyParameter::new(
+            KeyParameterValue::PaddingMode(PaddingMode::NONE),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::PaddingMode(PaddingMode::RSA_PSS),
+            SecurityLevel::STRONGBOX,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::PaddingMode(PaddingMode::RSA_PKCS1_1_5_SIGN),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(KeyParameterValue::MinMacLength(256), SecurityLevel::STRONGBOX),
+        KeyParameter::new(
+            KeyParameterValue::EcCurve(EcCurve::P_224),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::EcCurve(EcCurve::P_256), SecurityLevel::STRONGBOX),
+        KeyParameter::new(
+            KeyParameterValue::EcCurve(EcCurve::P_384),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::EcCurve(EcCurve::P_521),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::RSAPublicExponent(3),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::IncludeUniqueID, SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(KeyParameterValue::BootLoaderOnly, SecurityLevel::STRONGBOX),
+        KeyParameter::new(KeyParameterValue::RollbackResistance, SecurityLevel::STRONGBOX),
+        KeyParameter::new(KeyParameterValue::ActiveDateTime(1234567890), SecurityLevel::STRONGBOX),
+        KeyParameter::new(
+            KeyParameterValue::OriginationExpireDateTime(1234567890),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::UsageExpireDateTime(1234567890),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::MinSecondsBetweenOps(1234567890),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::MaxUsesPerBoot(1234567890),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::UserID(1), SecurityLevel::STRONGBOX),
+        KeyParameter::new(KeyParameterValue::NoAuthRequired, SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(
+            KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::PASSWORD),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::AuthTimeout(1234567890), SecurityLevel::SOFTWARE),
+        KeyParameter::new(KeyParameterValue::AllowWhileOnBody, SecurityLevel::SOFTWARE),
+        KeyParameter::new(
+            KeyParameterValue::TrustedUserPresenceRequired,
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::TrustedConfirmationRequired,
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::UnlockedDeviceRequired,
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::ApplicationID(vec![1u8, 2u8, 3u8, 4u8]),
+            SecurityLevel::SOFTWARE,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::ApplicationData(vec![4u8, 3u8, 2u8, 1u8]),
+            SecurityLevel::SOFTWARE,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::CreationDateTime(12345677890),
+            SecurityLevel::SOFTWARE,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::KeyOrigin(KeyOrigin::GENERATED),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::RootOfTrust(vec![3u8, 2u8, 1u8, 4u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::OSVersion(1), SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(KeyParameterValue::OSPatchLevel(2), SecurityLevel::SOFTWARE),
+        KeyParameter::new(
+            KeyParameterValue::UniqueID(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::SOFTWARE,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationChallenge(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationApplicationID(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdBrand(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdDevice(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdProduct(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdSerial(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdIMEI(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdSecondIMEI(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdMEID(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdManufacturer(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::AttestationIdModel(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::VendorPatchLevel(3),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::BootPatchLevel(4), SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(
+            KeyParameterValue::AssociatedData(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::Nonce(vec![4u8, 3u8, 1u8, 2u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(KeyParameterValue::MacLength(256), SecurityLevel::TRUSTED_ENVIRONMENT),
+        KeyParameter::new(
+            KeyParameterValue::ResetSinceIdRotation,
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+        KeyParameter::new(
+            KeyParameterValue::ConfirmationToken(vec![5u8, 5u8, 5u8, 5u8]),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ),
+    ];
+    if let Some(value) = max_usage_count {
+        params.push(KeyParameter::new(
+            KeyParameterValue::UsageCountLimit(value),
+            SecurityLevel::SOFTWARE,
+        ));
+    }
+
+    for sid in user_secure_ids.iter() {
+        params.push(KeyParameter::new(
+            KeyParameterValue::UserSecureID(*sid),
+            SecurityLevel::STRONGBOX,
+        ));
+    }
+    params
+}
+
+pub fn make_test_key_entry(
+    db: &mut KeystoreDB,
+    domain: Domain,
+    namespace: i64,
+    alias: &str,
+    max_usage_count: Option<i32>,
+) -> Result<KeyIdGuard> {
+    make_test_key_entry_with_sids(db, domain, namespace, alias, max_usage_count, &[42])
+}
+
+pub fn make_test_key_entry_with_sids(
+    db: &mut KeystoreDB,
+    domain: Domain,
+    namespace: i64,
+    alias: &str,
+    max_usage_count: Option<i32>,
+    sids: &[i64],
+) -> Result<KeyIdGuard> {
+    let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
+    let mut blob_metadata = BlobMetaData::new();
+    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
+    blob_metadata.add(BlobMetaEntry::Salt(vec![1, 2, 3]));
+    blob_metadata.add(BlobMetaEntry::Iv(vec![2, 3, 1]));
+    blob_metadata.add(BlobMetaEntry::AeadTag(vec![3, 1, 2]));
+    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
+
+    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
+    db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
+    db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
+
+    let params = make_test_params_with_sids(max_usage_count, sids);
+    db.insert_keyparameter(&key_id, &params)?;
+
+    let mut metadata = KeyMetaData::new();
+    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
+    db.insert_key_metadata(&key_id, &metadata)?;
+    rebind_alias(db, &key_id, alias, domain, namespace)?;
+    Ok(key_id)
+}
+
+fn make_test_key_entry_test_vector(key_id: i64, max_usage_count: Option<i32>) -> KeyEntry {
+    let params = make_test_params(max_usage_count);
+
+    let mut blob_metadata = BlobMetaData::new();
+    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
+    blob_metadata.add(BlobMetaEntry::Salt(vec![1, 2, 3]));
+    blob_metadata.add(BlobMetaEntry::Iv(vec![2, 3, 1]));
+    blob_metadata.add(BlobMetaEntry::AeadTag(vec![3, 1, 2]));
+    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
+
+    let mut metadata = KeyMetaData::new();
+    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
+
+    KeyEntry {
+        id: key_id,
+        key_blob_info: Some((TEST_KEY_BLOB.to_vec(), blob_metadata)),
+        cert: Some(TEST_CERT_BLOB.to_vec()),
+        cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
+        km_uuid: KEYSTORE_UUID,
+        parameters: params,
+        metadata,
+        pure_cert: false,
+    }
+}
+
+pub fn make_bootlevel_key_entry(
+    db: &mut KeystoreDB,
+    domain: Domain,
+    namespace: i64,
+    alias: &str,
+    logical_only: bool,
+) -> Result<KeyIdGuard> {
+    let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
+    let mut blob_metadata = BlobMetaData::new();
+    if !logical_only {
+        blob_metadata.add(BlobMetaEntry::MaxBootLevel(3));
+    }
+    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
+
+    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
+    db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
+    db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
+
+    let mut params = make_test_params(None);
+    params.push(KeyParameter::new(KeyParameterValue::MaxBootLevel(3), SecurityLevel::KEYSTORE));
+
+    db.insert_keyparameter(&key_id, &params)?;
+
+    let mut metadata = KeyMetaData::new();
+    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
+    db.insert_key_metadata(&key_id, &metadata)?;
+    rebind_alias(db, &key_id, alias, domain, namespace)?;
+    Ok(key_id)
+}
+
+// Creates an app key that is marked as being superencrypted by the given
+// super key ID and that has the given authentication and unlocked device
+// parameters. This does not actually superencrypt the key blob.
+fn make_superencrypted_key_entry(
+    db: &mut KeystoreDB,
+    namespace: i64,
+    alias: &str,
+    requires_authentication: bool,
+    requires_unlocked_device: bool,
+    super_key_id: i64,
+) -> Result<KeyIdGuard> {
+    let domain = Domain::APP;
+    let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
+
+    let mut blob_metadata = BlobMetaData::new();
+    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
+    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(super_key_id)));
+    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
+
+    let mut params = vec![];
+    if requires_unlocked_device {
+        params.push(KeyParameter::new(
+            KeyParameterValue::UnlockedDeviceRequired,
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ));
+    }
+    if requires_authentication {
+        params.push(KeyParameter::new(
+            KeyParameterValue::UserSecureID(42),
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+        ));
+    }
+    db.insert_keyparameter(&key_id, &params)?;
+
+    let mut metadata = KeyMetaData::new();
+    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
+    db.insert_key_metadata(&key_id, &metadata)?;
+
+    rebind_alias(db, &key_id, alias, domain, namespace)?;
+    Ok(key_id)
+}
+
+fn make_bootlevel_test_key_entry_test_vector(key_id: i64, logical_only: bool) -> KeyEntry {
+    let mut params = make_test_params(None);
+    params.push(KeyParameter::new(KeyParameterValue::MaxBootLevel(3), SecurityLevel::KEYSTORE));
+
+    let mut blob_metadata = BlobMetaData::new();
+    if !logical_only {
+        blob_metadata.add(BlobMetaEntry::MaxBootLevel(3));
+    }
+    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
+
+    let mut metadata = KeyMetaData::new();
+    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
+
+    KeyEntry {
+        id: key_id,
+        key_blob_info: Some((TEST_KEY_BLOB.to_vec(), blob_metadata)),
+        cert: Some(TEST_CERT_BLOB.to_vec()),
+        cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
+        km_uuid: KEYSTORE_UUID,
+        parameters: params,
+        metadata,
+        pure_cert: false,
+    }
+}
+
+fn debug_dump_keyentry_table(db: &mut KeystoreDB) -> Result<()> {
+    let mut stmt = db.conn.prepare(
+        "SELECT id, key_type, domain, namespace, alias, state, km_uuid FROM persistent.keyentry;",
+    )?;
+    let rows =
+        stmt.query_map::<(i64, KeyType, i32, i64, String, KeyLifeCycle, Uuid), _, _>([], |row| {
+            Ok((
+                row.get(0)?,
+                row.get(1)?,
+                row.get(2)?,
+                row.get(3)?,
+                row.get(4)?,
+                row.get(5)?,
+                row.get(6)?,
+            ))
+        })?;
+
+    println!("Key entry table rows:");
+    for r in rows {
+        let (id, key_type, domain, namespace, alias, state, km_uuid) = r.unwrap();
+        println!(
+            "    id: {} KeyType: {:?} Domain: {} Namespace: {} Alias: {} State: {:?} KmUuid: {:?}",
+            id, key_type, domain, namespace, alias, state, km_uuid
+        );
+    }
+    Ok(())
+}
+
+fn debug_dump_grant_table(db: &mut KeystoreDB) -> Result<()> {
+    let mut stmt =
+        db.conn.prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
+    let rows = stmt.query_map::<(i64, i64, i64, i64), _, _>([], |row| {
+        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
+    })?;
+
+    println!("Grant table rows:");
+    for r in rows {
+        let (id, gt, ki, av) = r.unwrap();
+        println!("    id: {} grantee: {} key_id: {} access_vector: {}", id, gt, ki, av);
+    }
+    Ok(())
+}
+
+// Use a custom random number generator that repeats each number once.
+// This allows us to test repeated elements.
+
+thread_local! {
+    static RANDOM_COUNTER: RefCell<i64> = const { RefCell::new(0) };
+}
+
+fn reset_random() {
+    RANDOM_COUNTER.with(|counter| {
+        *counter.borrow_mut() = 0;
+    })
+}
+
+pub fn random() -> i64 {
+    RANDOM_COUNTER.with(|counter| {
+        let result = *counter.borrow() / 2;
+        *counter.borrow_mut() += 1;
+        result
+    })
+}
+
+#[test]
+fn test_unbind_keys_for_user() -> Result<()> {
+    let mut db = new_test_db()?;
+    db.unbind_keys_for_user(1)?;
+
+    make_test_key_entry(&mut db, Domain::APP, 210000, TEST_ALIAS, None)?;
+    make_test_key_entry(&mut db, Domain::APP, 110000, TEST_ALIAS, None)?;
+    db.unbind_keys_for_user(2)?;
+
+    assert_eq!(1, db.list_past_alias(Domain::APP, 110000, KeyType::Client, None)?.len());
+    assert_eq!(0, db.list_past_alias(Domain::APP, 210000, KeyType::Client, None)?.len());
+
+    db.unbind_keys_for_user(1)?;
+    assert_eq!(0, db.list_past_alias(Domain::APP, 110000, KeyType::Client, None)?.len());
+
+    Ok(())
+}
+
+#[test]
+fn test_unbind_keys_for_user_removes_superkeys() -> Result<()> {
+    let mut db = new_test_db()?;
+    let super_key = keystore2_crypto::generate_aes256_key()?;
+    let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
+    let (encrypted_super_key, metadata) = SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
+
+    let key_name_enc = SuperKeyType {
+        alias: "test_super_key_1",
+        algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
+        name: "test_super_key_1",
+    };
+
+    let key_name_nonenc = SuperKeyType {
+        alias: "test_super_key_2",
+        algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
+        name: "test_super_key_2",
+    };
+
+    // Install two super keys.
+    db.store_super_key(1, &key_name_nonenc, &super_key, &BlobMetaData::new(), &KeyMetaData::new())?;
+    db.store_super_key(1, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;
+
+    // Check that both can be found in the database.
+    assert!(db.load_super_key(&key_name_enc, 1)?.is_some());
+    assert!(db.load_super_key(&key_name_nonenc, 1)?.is_some());
+
+    // Install the same keys for a different user.
+    db.store_super_key(2, &key_name_nonenc, &super_key, &BlobMetaData::new(), &KeyMetaData::new())?;
+    db.store_super_key(2, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;
+
+    // Check that the second pair of keys can be found in the database.
+    assert!(db.load_super_key(&key_name_enc, 2)?.is_some());
+    assert!(db.load_super_key(&key_name_nonenc, 2)?.is_some());
+
+    // Delete all keys for user 1.
+    db.unbind_keys_for_user(1)?;
+
+    // All of user 1's keys should be gone.
+    assert!(db.load_super_key(&key_name_enc, 1)?.is_none());
+    assert!(db.load_super_key(&key_name_nonenc, 1)?.is_none());
+
+    // User 2's keys should not have been touched.
+    assert!(db.load_super_key(&key_name_enc, 2)?.is_some());
+    assert!(db.load_super_key(&key_name_nonenc, 2)?.is_some());
+
+    Ok(())
+}
+
+fn app_key_exists(db: &mut KeystoreDB, nspace: i64, alias: &str) -> Result<bool> {
+    db.key_exists(Domain::APP, nspace, alias, KeyType::Client)
+}
+
+// Tests the unbind_auth_bound_keys_for_user() function.
+#[test]
+fn test_unbind_auth_bound_keys_for_user() -> Result<()> {
+    let mut db = new_test_db()?;
+    let user_id = 1;
+    let nspace: i64 = (user_id * AID_USER_OFFSET).into();
+    let other_user_id = 2;
+    let other_user_nspace: i64 = (other_user_id * AID_USER_OFFSET).into();
+    let super_key_type = &USER_AFTER_FIRST_UNLOCK_SUPER_KEY;
+
+    // Create a superencryption key.
+    let super_key = keystore2_crypto::generate_aes256_key()?;
+    let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
+    let (encrypted_super_key, blob_metadata) =
+        SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
+    db.store_super_key(
+        user_id,
+        super_key_type,
+        &encrypted_super_key,
+        &blob_metadata,
+        &KeyMetaData::new(),
+    )?;
+    let super_key_id = db.load_super_key(super_key_type, user_id)?.unwrap().0 .0;
+
+    // Store 4 superencrypted app keys, one for each possible combination of
+    // (authentication required, unlocked device required).
+    make_superencrypted_key_entry(&mut db, nspace, "noauth_noud", false, false, super_key_id)?;
+    make_superencrypted_key_entry(&mut db, nspace, "noauth_ud", false, true, super_key_id)?;
+    make_superencrypted_key_entry(&mut db, nspace, "auth_noud", true, false, super_key_id)?;
+    make_superencrypted_key_entry(&mut db, nspace, "auth_ud", true, true, super_key_id)?;
+    assert!(app_key_exists(&mut db, nspace, "noauth_noud")?);
+    assert!(app_key_exists(&mut db, nspace, "noauth_ud")?);
+    assert!(app_key_exists(&mut db, nspace, "auth_noud")?);
+    assert!(app_key_exists(&mut db, nspace, "auth_ud")?);
+
+    // Also store a key for a different user that requires authentication.
+    make_superencrypted_key_entry(&mut db, other_user_nspace, "auth_ud", true, true, super_key_id)?;
+
+    db.unbind_auth_bound_keys_for_user(user_id)?;
+
+    // Verify that only the user's app keys that require authentication were
+    // deleted. Keys that require an unlocked device but not authentication
+    // should *not* have been deleted, nor should the super key have been
+    // deleted, nor should other users' keys have been deleted.
+    assert!(db.load_super_key(super_key_type, user_id)?.is_some());
+    assert!(app_key_exists(&mut db, nspace, "noauth_noud")?);
+    assert!(app_key_exists(&mut db, nspace, "noauth_ud")?);
+    assert!(!app_key_exists(&mut db, nspace, "auth_noud")?);
+    assert!(!app_key_exists(&mut db, nspace, "auth_ud")?);
+    assert!(app_key_exists(&mut db, other_user_nspace, "auth_ud")?);
+
+    Ok(())
+}
+
+#[test]
+fn test_store_super_key() -> Result<()> {
+    let mut db = new_test_db()?;
+    let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
+    let super_key = keystore2_crypto::generate_aes256_key()?;
+    let secret_bytes = b"keystore2 is great.";
+    let (encrypted_secret, iv, tag) = keystore2_crypto::aes_gcm_encrypt(secret_bytes, &super_key)?;
+
+    let (encrypted_super_key, metadata) = SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
+    db.store_super_key(
+        1,
+        &USER_AFTER_FIRST_UNLOCK_SUPER_KEY,
+        &encrypted_super_key,
+        &metadata,
+        &KeyMetaData::new(),
+    )?;
+
+    // Check if super key exists.
+    assert!(db.key_exists(
+        Domain::APP,
+        1,
+        USER_AFTER_FIRST_UNLOCK_SUPER_KEY.alias,
+        KeyType::Super
+    )?);
+
+    let (_, key_entry) = db.load_super_key(&USER_AFTER_FIRST_UNLOCK_SUPER_KEY, 1)?.unwrap();
+    let loaded_super_key = SuperKeyManager::extract_super_key_from_key_entry(
+        USER_AFTER_FIRST_UNLOCK_SUPER_KEY.algorithm,
+        key_entry,
+        &pw,
+        None,
+    )?;
+
+    let decrypted_secret_bytes = loaded_super_key.decrypt(&encrypted_secret, &iv, &tag)?;
+    assert_eq!(secret_bytes, &*decrypted_secret_bytes);
+
+    Ok(())
+}
+
+fn get_valid_statsd_storage_types() -> Vec<MetricsStorage> {
+    vec![
+        MetricsStorage::KEY_ENTRY,
+        MetricsStorage::KEY_ENTRY_ID_INDEX,
+        MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX,
+        MetricsStorage::BLOB_ENTRY,
+        MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX,
+        MetricsStorage::KEY_PARAMETER,
+        MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX,
+        MetricsStorage::KEY_METADATA,
+        MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX,
+        MetricsStorage::GRANT,
+        MetricsStorage::AUTH_TOKEN,
+        MetricsStorage::BLOB_METADATA,
+        MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX,
+    ]
+}
+
+/// Perform a simple check to ensure that we can query all the storage types
+/// that are supported by the DB. Check for reasonable values.
+#[test]
+fn test_query_all_valid_table_sizes() -> Result<()> {
+    const PAGE_SIZE: i32 = 4096;
+
+    let mut db = new_test_db()?;
+
+    for t in get_valid_statsd_storage_types() {
+        let stat = db.get_storage_stat(t)?;
+        // AuthToken can be less than a page since it's in a btree, not sqlite
+        // TODO(b/187474736) stop using if-let here
+        if let MetricsStorage::AUTH_TOKEN = t {
+        } else {
+            assert!(stat.size >= PAGE_SIZE);
+        }
+        assert!(stat.size >= stat.unused_size);
+    }
+
+    Ok(())
+}
+
+fn get_storage_stats_map(db: &mut KeystoreDB) -> BTreeMap<i32, StorageStats> {
+    get_valid_statsd_storage_types()
+        .into_iter()
+        .map(|t| (t.0, db.get_storage_stat(t).unwrap()))
+        .collect()
+}
+
+fn assert_storage_increased(
+    db: &mut KeystoreDB,
+    increased_storage_types: Vec<MetricsStorage>,
+    baseline: &mut BTreeMap<i32, StorageStats>,
+) {
+    for storage in increased_storage_types {
+        // Verify the expected storage increased.
+        let new = db.get_storage_stat(storage).unwrap();
+        let old = &baseline[&storage.0];
+        assert!(new.size >= old.size, "{}: {} >= {}", storage.0, new.size, old.size);
+        assert!(
+            new.unused_size <= old.unused_size,
+            "{}: {} <= {}",
+            storage.0,
+            new.unused_size,
+            old.unused_size
+        );
+
+        // Update the baseline with the new value so that it succeeds in the
+        // later comparison.
+        baseline.insert(storage.0, new);
+    }
+
+    // Get an updated map of the storage and verify there were no unexpected changes.
+    let updated_stats = get_storage_stats_map(db);
+    assert_eq!(updated_stats.len(), baseline.len());
+
+    for &k in baseline.keys() {
+        let stringify = |map: &BTreeMap<i32, StorageStats>| -> String {
+            let mut s = String::new();
+            for &k in map.keys() {
+                writeln!(&mut s, "  {}: {}, {}", &k, map[&k].size, map[&k].unused_size)
+                    .expect("string concat failed");
+            }
+            s
+        };
+
+        assert!(
+            updated_stats[&k].size == baseline[&k].size
+                && updated_stats[&k].unused_size == baseline[&k].unused_size,
+            "updated_stats:\n{}\nbaseline:\n{}",
+            stringify(&updated_stats),
+            stringify(baseline)
+        );
+    }
+}
+
+#[test]
+fn test_verify_key_table_size_reporting() -> Result<()> {
+    let mut db = new_test_db()?;
+    let mut working_stats = get_storage_stats_map(&mut db);
+
+    let key_id = create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
+    assert_storage_increased(
+        &mut db,
+        vec![
+            MetricsStorage::KEY_ENTRY,
+            MetricsStorage::KEY_ENTRY_ID_INDEX,
+            MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX,
+        ],
+        &mut working_stats,
+    );
+
+    let mut blob_metadata = BlobMetaData::new();
+    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
+    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), None)?;
+    assert_storage_increased(
+        &mut db,
+        vec![
+            MetricsStorage::BLOB_ENTRY,
+            MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX,
+            MetricsStorage::BLOB_METADATA,
+            MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX,
+        ],
+        &mut working_stats,
+    );
+
+    let params = make_test_params(None);
+    db.insert_keyparameter(&key_id, &params)?;
+    assert_storage_increased(
+        &mut db,
+        vec![MetricsStorage::KEY_PARAMETER, MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX],
+        &mut working_stats,
+    );
+
+    let mut metadata = KeyMetaData::new();
+    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
+    db.insert_key_metadata(&key_id, &metadata)?;
+    assert_storage_increased(
+        &mut db,
+        vec![MetricsStorage::KEY_METADATA, MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX],
+        &mut working_stats,
+    );
+
+    let mut sum = 0;
+    for stat in working_stats.values() {
+        sum += stat.size;
+    }
+    let total = db.get_storage_stat(MetricsStorage::DATABASE)?.size;
+    assert!(sum <= total, "Expected sum <= total. sum: {}, total: {}", sum, total);
+
+    Ok(())
+}
+
+#[test]
+fn test_verify_auth_table_size_reporting() -> Result<()> {
+    let mut db = new_test_db()?;
+    let mut working_stats = get_storage_stats_map(&mut db);
+    db.insert_auth_token(&HardwareAuthToken {
+        challenge: 123,
+        userId: 456,
+        authenticatorId: 789,
+        authenticatorType: kmhw_authenticator_type::ANY,
+        timestamp: Timestamp { milliSeconds: 10 },
+        mac: b"mac".to_vec(),
+    });
+    assert_storage_increased(&mut db, vec![MetricsStorage::AUTH_TOKEN], &mut working_stats);
+    Ok(())
+}
+
+#[test]
+fn test_verify_grant_table_size_reporting() -> Result<()> {
+    const OWNER: i64 = 1;
+    let mut db = new_test_db()?;
+    make_test_key_entry(&mut db, Domain::APP, OWNER, TEST_ALIAS, None)?;
+
+    let mut working_stats = get_storage_stats_map(&mut db);
+    db.grant(
+        &KeyDescriptor {
+            domain: Domain::APP,
+            nspace: 0,
+            alias: Some(TEST_ALIAS.to_string()),
+            blob: None,
+        },
+        OWNER as u32,
+        123,
+        key_perm_set![KeyPerm::Use],
+        |_, _| Ok(()),
+    )?;
+
+    assert_storage_increased(&mut db, vec![MetricsStorage::GRANT], &mut working_stats);
+
+    Ok(())
+}
+
+#[test]
+fn find_auth_token_entry_returns_latest() -> Result<()> {
+    let mut db = new_test_db()?;
+    db.insert_auth_token(&HardwareAuthToken {
+        challenge: 123,
+        userId: 456,
+        authenticatorId: 789,
+        authenticatorType: kmhw_authenticator_type::ANY,
+        timestamp: Timestamp { milliSeconds: 10 },
+        mac: b"mac0".to_vec(),
+    });
+    std::thread::sleep(std::time::Duration::from_millis(1));
+    db.insert_auth_token(&HardwareAuthToken {
+        challenge: 123,
+        userId: 457,
+        authenticatorId: 789,
+        authenticatorType: kmhw_authenticator_type::ANY,
+        timestamp: Timestamp { milliSeconds: 12 },
+        mac: b"mac1".to_vec(),
+    });
+    std::thread::sleep(std::time::Duration::from_millis(1));
+    db.insert_auth_token(&HardwareAuthToken {
+        challenge: 123,
+        userId: 458,
+        authenticatorId: 789,
+        authenticatorType: kmhw_authenticator_type::ANY,
+        timestamp: Timestamp { milliSeconds: 3 },
+        mac: b"mac2".to_vec(),
+    });
+    // All three entries are in the database
+    assert_eq!(db.perboot.auth_tokens_len(), 3);
+    // It selected the most recent timestamp
+    assert_eq!(db.find_auth_token_entry(|_| true).unwrap().auth_token.mac, b"mac2".to_vec());
+    Ok(())
+}
+
+fn blob_count(db: &mut KeystoreDB, sc_type: SubComponentType) -> usize {
+    db.with_transaction(TransactionBehavior::Deferred, |tx| {
+        tx.query_row(
+            "SELECT COUNT(*) FROM persistent.blobentry
+                     WHERE subcomponent_type = ?;",
+            params![sc_type],
+            |row| row.get(0),
+        )
+        .context(ks_err!("Failed to count number of {sc_type:?} blobs"))
+        .no_gc()
+    })
+    .unwrap()
+}
+
+#[test]
+fn test_blobentry_gc() -> Result<()> {
+    let mut db = new_test_db()?;
+    let _key_id1 = make_test_key_entry(&mut db, Domain::APP, 1, "key1", None)?.0;
+    let key_guard2 = make_test_key_entry(&mut db, Domain::APP, 2, "key2", None)?;
+    let key_guard3 = make_test_key_entry(&mut db, Domain::APP, 3, "key3", None)?;
+    let key_id4 = make_test_key_entry(&mut db, Domain::APP, 4, "key4", None)?.0;
+    let key_id5 = make_test_key_entry(&mut db, Domain::APP, 5, "key5", None)?.0;
+
+    assert_eq!(5, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // Replace the keyblobs for keys 2 and 3.  The previous blobs will still exist.
+    db.set_blob(&key_guard2, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
+    db.set_blob(&key_guard3, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
+
+    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // Delete keys 4 and 5.  The keyblobs aren't removed yet.
+    db.with_transaction(Immediate("TX_delete_test_keys"), |tx| {
+        KeystoreDB::mark_unreferenced(tx, key_id4)?;
+        KeystoreDB::mark_unreferenced(tx, key_id5)?;
+        Ok(()).no_gc()
+    })
+    .unwrap();
+
+    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // First garbage collection should return all 4 blobentry rows that are no longer current for
+    // their key.
+    let superseded = db.handle_next_superseded_blobs(&[], 20).unwrap();
+    let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
+    assert_eq!(4, superseded.len());
+    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // Feed the superseded blob IDs back in, to trigger removal of the old KEY_BLOB entries.  As no
+    // new superseded KEY_BLOBs are found, the unreferenced CERT/CERT_CHAIN blobs are removed.
+    let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
+    let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
+    assert_eq!(0, superseded.len());
+    assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // Nothing left to garbage collect.
+    let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
+    assert_eq!(0, superseded.len());
+    assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
+    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    Ok(())
+}
+
+#[test]
+fn test_load_key_descriptor() -> Result<()> {
+    let mut db = new_test_db()?;
+    let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)?.0;
+
+    let key = db.load_key_descriptor(key_id)?.unwrap();
+
+    assert_eq!(key.domain, Domain::APP);
+    assert_eq!(key.nspace, 1);
+    assert_eq!(key.alias, Some(TEST_ALIAS.to_string()));
+
+    // No such id
+    assert_eq!(db.load_key_descriptor(key_id + 1)?, None);
+    Ok(())
+}
+
+#[test]
+fn test_get_list_app_uids_for_sid() -> Result<()> {
+    let uid: i32 = 1;
+    let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
+    let first_sid = 667;
+    let second_sid = 669;
+    let first_app_id: i64 = 123 + uid_offset;
+    let second_app_id: i64 = 456 + uid_offset;
+    let third_app_id: i64 = 789 + uid_offset;
+    let unrelated_app_id: i64 = 1011 + uid_offset;
+    let mut db = new_test_db()?;
+    make_test_key_entry_with_sids(
+        &mut db,
+        Domain::APP,
+        first_app_id,
+        TEST_ALIAS,
+        None,
+        &[first_sid],
+    )
+    .context("test_get_list_app_uids_for_sid")?;
+    make_test_key_entry_with_sids(
+        &mut db,
+        Domain::APP,
+        second_app_id,
+        "alias2",
+        None,
+        &[first_sid],
+    )
+    .context("test_get_list_app_uids_for_sid")?;
+    make_test_key_entry_with_sids(
+        &mut db,
+        Domain::APP,
+        second_app_id,
+        TEST_ALIAS,
+        None,
+        &[second_sid],
+    )
+    .context("test_get_list_app_uids_for_sid")?;
+    make_test_key_entry_with_sids(
+        &mut db,
+        Domain::APP,
+        third_app_id,
+        "alias3",
+        None,
+        &[second_sid],
+    )
+    .context("test_get_list_app_uids_for_sid")?;
+    make_test_key_entry_with_sids(&mut db, Domain::APP, unrelated_app_id, TEST_ALIAS, None, &[])
+        .context("test_get_list_app_uids_for_sid")?;
+
+    let mut first_sid_apps = db.get_app_uids_affected_by_sid(uid, first_sid)?;
+    first_sid_apps.sort();
+    assert_eq!(first_sid_apps, vec![first_app_id, second_app_id]);
+    let mut second_sid_apps = db.get_app_uids_affected_by_sid(uid, second_sid)?;
+    second_sid_apps.sort();
+    assert_eq!(second_sid_apps, vec![second_app_id, third_app_id]);
+    Ok(())
+}
+
+#[test]
+fn test_get_list_app_uids_with_multiple_sids() -> Result<()> {
+    let uid: i32 = 1;
+    let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
+    let first_sid = 667;
+    let second_sid = 669;
+    let third_sid = 772;
+    let first_app_id: i64 = 123 + uid_offset;
+    let second_app_id: i64 = 456 + uid_offset;
+    let mut db = new_test_db()?;
+    make_test_key_entry_with_sids(
+        &mut db,
+        Domain::APP,
+        first_app_id,
+        TEST_ALIAS,
+        None,
+        &[first_sid, second_sid],
+    )
+    .context("test_get_list_app_uids_for_sid")?;
+    make_test_key_entry_with_sids(
+        &mut db,
+        Domain::APP,
+        second_app_id,
+        "alias2",
+        None,
+        &[second_sid, third_sid],
+    )
+    .context("test_get_list_app_uids_for_sid")?;
+
+    let first_sid_apps = db.get_app_uids_affected_by_sid(uid, first_sid)?;
+    assert_eq!(first_sid_apps, vec![first_app_id]);
+
+    let mut second_sid_apps = db.get_app_uids_affected_by_sid(uid, second_sid)?;
+    second_sid_apps.sort();
+    assert_eq!(second_sid_apps, vec![first_app_id, second_app_id]);
+
+    let third_sid_apps = db.get_app_uids_affected_by_sid(uid, third_sid)?;
+    assert_eq!(third_sid_apps, vec![second_app_id]);
+    Ok(())
+}
+
+// Starting from `next_keyid`, add keys to the database until the count reaches
+// `key_count`.  (`next_keyid` is assumed to indicate how many rows already exist.)
+fn db_populate_keys(db: &mut KeystoreDB, next_keyid: usize, key_count: usize) {
+    db.with_transaction(Immediate("test_keyentry"), |tx| {
+        for next_keyid in next_keyid..key_count {
+            tx.execute(
+                "INSERT into persistent.keyentry
+                        (id, key_type, domain, namespace, alias, state, km_uuid)
+                        VALUES(?, ?, ?, ?, ?, ?, ?);",
+                params![
+                    next_keyid,
+                    KeyType::Client,
+                    Domain::APP.0 as u32,
+                    10001,
+                    &format!("alias-{next_keyid}"),
+                    KeyLifeCycle::Live,
+                    KEYSTORE_UUID,
+                ],
+            )?;
+            tx.execute(
+                "INSERT INTO persistent.blobentry
+                         (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
+                params![SubComponentType::KEY_BLOB, next_keyid, TEST_KEY_BLOB],
+            )?;
+            tx.execute(
+                "INSERT INTO persistent.blobentry
+                         (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
+                params![SubComponentType::CERT, next_keyid, TEST_CERT_BLOB],
+            )?;
+            tx.execute(
+                "INSERT INTO persistent.blobentry
+                         (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
+                params![SubComponentType::CERT_CHAIN, next_keyid, TEST_CERT_CHAIN_BLOB],
+            )?;
+        }
+        Ok(()).no_gc()
+    })
+    .unwrap()
+}
+
+/// Run the provided `test_fn` against the database at various increasing stages of
+/// database population.
+fn run_with_many_keys<F, T>(max_count: usize, test_fn: F) -> Result<()>
+where
+    F: Fn(&mut KeystoreDB) -> T,
+{
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_test")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+    // Put the test database on disk for a more realistic result.
+    let db_root = tempfile::Builder::new().prefix("ks2db-test-").tempdir().unwrap();
+    let mut db_path = db_root.path().to_owned();
+    db_path.push("ks2-test.sqlite");
+    let mut db = new_test_db_at(&db_path.to_string_lossy())?;
+
+    println!("\nNumber_of_keys,time_in_s");
+    let mut key_count = 10;
+    let mut next_keyid = 0;
+    while key_count < max_count {
+        db_populate_keys(&mut db, next_keyid, key_count);
+        assert_eq!(db_key_count(&mut db), key_count);
+
+        let start = std::time::Instant::now();
+        let _result = test_fn(&mut db);
+        println!("{key_count}, {}", start.elapsed().as_secs_f64());
+
+        next_keyid = key_count;
+        key_count *= 2;
+    }
+
+    Ok(())
+}
+
+fn db_key_count(db: &mut KeystoreDB) -> usize {
+    db.with_transaction(TransactionBehavior::Deferred, |tx| {
+        tx.query_row(
+            "SELECT COUNT(*) FROM persistent.keyentry
+                         WHERE domain = ? AND state = ? AND key_type = ?;",
+            params![Domain::APP.0 as u32, KeyLifeCycle::Live, KeyType::Client],
+            |row| row.get::<usize, usize>(0),
+        )
+        .context(ks_err!("Failed to count number of keys."))
+        .no_gc()
+    })
+    .unwrap()
+}
+
+#[test]
+fn test_handle_superseded_with_many_keys() -> Result<()> {
+    run_with_many_keys(1_000_000, |db| db.handle_next_superseded_blobs(&[], 20))
+}
+
+#[test]
+fn test_get_storage_stats_with_many_keys() -> Result<()> {
+    use android_security_metrics::aidl::android::security::metrics::Storage::Storage as MetricsStorage;
+    run_with_many_keys(1_000_000, |db| {
+        db.get_storage_stat(MetricsStorage::DATABASE).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_ENTRY).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_ENTRY_ID_INDEX).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX).unwrap();
+        db.get_storage_stat(MetricsStorage::BLOB_ENTRY).unwrap();
+        db.get_storage_stat(MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_PARAMETER).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_METADATA).unwrap();
+        db.get_storage_stat(MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX).unwrap();
+        db.get_storage_stat(MetricsStorage::GRANT).unwrap();
+        db.get_storage_stat(MetricsStorage::AUTH_TOKEN).unwrap();
+        db.get_storage_stat(MetricsStorage::BLOB_METADATA).unwrap();
+        db.get_storage_stat(MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX).unwrap();
+    })
+}
+
+#[test]
+fn test_list_keys_with_many_keys() -> Result<()> {
+    run_with_many_keys(1_000_000, |db: &mut KeystoreDB| -> Result<()> {
+        // Behave equivalently to how clients list aliases.
+        let domain = Domain::APP;
+        let namespace = 10001;
+        let mut start_past: Option<String> = None;
+        let mut count = 0;
+        let mut batches = 0;
+        loop {
+            let keys = db
+                .list_past_alias(domain, namespace, KeyType::Client, start_past.as_deref())
+                .unwrap();
+            let batch_size = crate::utils::estimate_safe_amount_to_return(
+                domain,
+                namespace,
+                &keys,
+                crate::utils::RESPONSE_SIZE_LIMIT,
+            );
+            let batch = &keys[..batch_size];
+            count += batch.len();
+            match batch.last() {
+                Some(key) => start_past.clone_from(&key.alias),
+                None => {
+                    log::info!("got {count} keys in {batches} non-empty batches");
+                    return Ok(());
+                }
+            }
+            batches += 1;
+        }
+    })
+}
diff --git a/keystore2/src/database/versioning.rs b/keystore2/src/database/versioning.rs
index 2c816f44..bc68f159 100644
--- a/keystore2/src/database/versioning.rs
+++ b/keystore2/src/database/versioning.rs
@@ -15,7 +15,7 @@
 use anyhow::{anyhow, Context, Result};
 use rusqlite::{params, OptionalExtension, Transaction};
 
-pub fn create_or_get_version(tx: &Transaction, current_version: u32) -> Result<u32> {
+fn create_or_get_version(tx: &Transaction, current_version: u32) -> Result<u32> {
     tx.execute(
         "CREATE TABLE IF NOT EXISTS persistent.version (
                 id INTEGER PRIMARY KEY,
@@ -61,7 +61,7 @@ pub fn create_or_get_version(tx: &Transaction, current_version: u32) -> Result<u
     Ok(version)
 }
 
-pub fn update_version(tx: &Transaction, new_version: u32) -> Result<()> {
+fn update_version(tx: &Transaction, new_version: u32) -> Result<()> {
     let updated = tx
         .execute("UPDATE persistent.version SET version = ? WHERE id = 0;", params![new_version])
         .context("In update_version: Failed to update row.")?;
diff --git a/keystore2/src/enforcements.rs b/keystore2/src/enforcements.rs
index 95dd026d..70383237 100644
--- a/keystore2/src/enforcements.rs
+++ b/keystore2/src/enforcements.rs
@@ -50,8 +50,6 @@ use std::{
 enum AuthRequestState {
     /// An outstanding per operation authorization request.
     OpAuth,
-    /// An outstanding request for per operation authorization and secure timestamp.
-    TimeStampedOpAuth(Mutex<Receiver<Result<TimeStampToken, Error>>>),
     /// An outstanding request for a timestamp token.
     TimeStamp(Mutex<Receiver<Result<TimeStampToken, Error>>>),
 }
@@ -59,8 +57,7 @@ enum AuthRequestState {
 #[derive(Debug)]
 struct AuthRequest {
     state: AuthRequestState,
-    /// This need to be set to Some to fulfill a AuthRequestState::OpAuth or
-    /// AuthRequestState::TimeStampedOpAuth.
+    /// This need to be set to Some to fulfill an AuthRequestState::OpAuth.
     hat: Mutex<Option<HardwareAuthToken>>,
 }
 
@@ -69,13 +66,6 @@ impl AuthRequest {
         Arc::new(Self { state: AuthRequestState::OpAuth, hat: Mutex::new(None) })
     }
 
-    fn timestamped_op_auth(receiver: Receiver<Result<TimeStampToken, Error>>) -> Arc<Self> {
-        Arc::new(Self {
-            state: AuthRequestState::TimeStampedOpAuth(Mutex::new(receiver)),
-            hat: Mutex::new(None),
-        })
-    }
-
     fn timestamp(
         hat: HardwareAuthToken,
         receiver: Receiver<Result<TimeStampToken, Error>>,
@@ -100,7 +90,7 @@ impl AuthRequest {
             .context(ks_err!("No operation auth token received."))?;
 
         let tst = match &self.state {
-            AuthRequestState::TimeStampedOpAuth(recv) | AuthRequestState::TimeStamp(recv) => {
+            AuthRequestState::TimeStamp(recv) => {
                 let result = recv
                     .lock()
                     .unwrap()
@@ -132,9 +122,6 @@ enum DeferredAuthState {
     /// loaded from the database, but it has to be accompanied by a time stamp token to inform
     /// the target KM with a different clock about the time on the authenticators.
     TimeStampRequired(HardwareAuthToken),
-    /// Indicates that both an operation bound auth token and a verification token are
-    /// before the operation can commence.
-    TimeStampedOpAuthRequired,
     /// In this state the auth info is waiting for the deferred authorizations to come in.
     /// We block on timestamp tokens, because we can always make progress on these requests.
     /// The per-op auth tokens might never come, which means we fail if the client calls
@@ -254,16 +241,6 @@ impl AuthInfo {
                 self.state = DeferredAuthState::Waiting(auth_request);
                 Some(OperationChallenge { challenge })
             }
-            DeferredAuthState::TimeStampedOpAuthRequired => {
-                let (sender, receiver) = channel::<Result<TimeStampToken, Error>>();
-                let auth_request = AuthRequest::timestamped_op_auth(receiver);
-                let token_receiver = TokenReceiver(Arc::downgrade(&auth_request));
-                ENFORCEMENTS.register_op_auth_receiver(challenge, token_receiver);
-
-                ASYNC_TASK.queue_hi(move |_| timestamp_token_request(challenge, sender));
-                self.state = DeferredAuthState::Waiting(auth_request);
-                Some(OperationChallenge { challenge })
-            }
             DeferredAuthState::TimeStampRequired(hat) => {
                 let hat = (*hat).clone();
                 let (sender, receiver) = channel::<Result<TimeStampToken, Error>>();
@@ -349,9 +326,7 @@ impl AuthInfo {
         match &self.state {
             DeferredAuthState::NoAuthRequired => Ok((None, None)),
             DeferredAuthState::Token(hat, tst) => Ok((Some((*hat).clone()), (*tst).clone())),
-            DeferredAuthState::OpAuthRequired
-            | DeferredAuthState::TimeStampedOpAuthRequired
-            | DeferredAuthState::TimeStampRequired(_) => {
+            DeferredAuthState::OpAuthRequired | DeferredAuthState::TimeStampRequired(_) => {
                 Err(Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
                     "No operation auth token requested??? \
                     This should not happen."
@@ -599,123 +574,36 @@ impl Enforcements {
             }
         }
 
-        if android_security_flags::fix_unlocked_device_required_keys_v2() {
-            let (hat, state) = if user_secure_ids.is_empty() {
-                (None, DeferredAuthState::NoAuthRequired)
-            } else if let Some(key_time_out) = key_time_out {
-                let hat = Self::find_auth_token(|hat: &AuthTokenEntry| match user_auth_type {
-                    Some(auth_type) => hat.satisfies(&user_secure_ids, auth_type),
-                    None => false, // not reachable due to earlier check
-                })
-                .ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
-                .context(ks_err!("No suitable auth token found."))?;
-                let now = BootTime::now();
-                let token_age = now
-                    .checked_sub(&hat.time_received())
-                    .ok_or_else(Error::sys)
-                    .context(ks_err!(
-                        "Overflow while computing Auth token validity. \
-                    Validity cannot be established."
-                    ))?;
-
-                if token_age.seconds() > key_time_out {
-                    return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
-                        .context(ks_err!("matching auth token is expired."));
-                }
-                let state = if requires_timestamp {
-                    DeferredAuthState::TimeStampRequired(hat.auth_token().clone())
-                } else {
-                    DeferredAuthState::NoAuthRequired
-                };
-                (Some(hat.take_auth_token()), state)
+        let (hat, state) = if user_secure_ids.is_empty() {
+            (None, DeferredAuthState::NoAuthRequired)
+        } else if let Some(key_time_out) = key_time_out {
+            let hat = Self::find_auth_token(|hat: &AuthTokenEntry| match user_auth_type {
+                Some(auth_type) => hat.satisfies(&user_secure_ids, auth_type),
+                None => false, // not reachable due to earlier check
+            })
+            .ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
+            .context(ks_err!("No suitable auth token found."))?;
+            let now = BootTime::now();
+            let token_age =
+                now.checked_sub(&hat.time_received()).ok_or_else(Error::sys).context(ks_err!(
+                    "Overflow while computing Auth token validity. \
+                Validity cannot be established."
+                ))?;
+
+            if token_age.seconds() > key_time_out {
+                return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
+                    .context(ks_err!("matching auth token is expired."));
+            }
+            let state = if requires_timestamp {
+                DeferredAuthState::TimeStampRequired(hat.auth_token().clone())
             } else {
-                (None, DeferredAuthState::OpAuthRequired)
+                DeferredAuthState::NoAuthRequired
             };
-            return Ok((hat, AuthInfo { state, key_usage_limited, confirmation_token_receiver }));
-        }
-
-        if !unlocked_device_required && no_auth_required {
-            return Ok((
-                None,
-                AuthInfo {
-                    state: DeferredAuthState::NoAuthRequired,
-                    key_usage_limited,
-                    confirmation_token_receiver,
-                },
-            ));
-        }
-
-        let has_sids = !user_secure_ids.is_empty();
-
-        let timeout_bound = key_time_out.is_some() && has_sids;
-
-        let per_op_bound = key_time_out.is_none() && has_sids;
-
-        let need_auth_token = timeout_bound || unlocked_device_required;
-
-        let hat = if need_auth_token {
-            let hat = Self::find_auth_token(|hat: &AuthTokenEntry| {
-                if let (Some(auth_type), true) = (user_auth_type, timeout_bound) {
-                    hat.satisfies(&user_secure_ids, auth_type)
-                } else {
-                    unlocked_device_required
-                }
-            });
-            Some(
-                hat.ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
-                    .context(ks_err!("No suitable auth token found."))?,
-            )
+            (Some(hat.take_auth_token()), state)
         } else {
-            None
+            (None, DeferredAuthState::OpAuthRequired)
         };
-
-        // Now check the validity of the auth token if the key is timeout bound.
-        let hat = match (hat, key_time_out) {
-            (Some(hat), Some(key_time_out)) => {
-                let now = BootTime::now();
-                let token_age = now
-                    .checked_sub(&hat.time_received())
-                    .ok_or_else(Error::sys)
-                    .context(ks_err!(
-                        "Overflow while computing Auth token validity. \
-                    Validity cannot be established."
-                    ))?;
-
-                if token_age.seconds() > key_time_out {
-                    return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
-                        .context(ks_err!("matching auth token is expired."));
-                }
-                Some(hat)
-            }
-            (Some(hat), None) => Some(hat),
-            // If timeout_bound is true, above code must have retrieved a HAT or returned with
-            // KEY_USER_NOT_AUTHENTICATED. This arm should not be reachable.
-            (None, Some(_)) => panic!("Logical error."),
-            _ => None,
-        };
-
-        Ok(match (hat, requires_timestamp, per_op_bound) {
-            // Per-op-bound and Some(hat) can only happen if we are both per-op bound and unlocked
-            // device required. In addition, this KM instance needs a timestamp token.
-            // So the HAT cannot be presented on create. So on update/finish we present both
-            // an per-op-bound auth token and a timestamp token.
-            (Some(_), true, true) => (None, DeferredAuthState::TimeStampedOpAuthRequired),
-            (Some(hat), true, false) => (
-                Some(hat.auth_token().clone()),
-                DeferredAuthState::TimeStampRequired(hat.take_auth_token()),
-            ),
-            (Some(hat), false, true) => {
-                (Some(hat.take_auth_token()), DeferredAuthState::OpAuthRequired)
-            }
-            (Some(hat), false, false) => {
-                (Some(hat.take_auth_token()), DeferredAuthState::NoAuthRequired)
-            }
-            (None, _, true) => (None, DeferredAuthState::OpAuthRequired),
-            (None, _, false) => (None, DeferredAuthState::NoAuthRequired),
-        })
-        .map(|(hat, state)| {
-            (hat, AuthInfo { state, key_usage_limited, confirmation_token_receiver })
-        })
+        Ok((hat, AuthInfo { state, key_usage_limited, confirmation_token_receiver }))
     }
 
     fn find_auth_token<F>(p: F) -> Option<AuthTokenEntry>
diff --git a/keystore2/src/error.rs b/keystore2/src/error.rs
index cea4d6be..5e80266e 100644
--- a/keystore2/src/error.rs
+++ b/keystore2/src/error.rs
@@ -38,6 +38,9 @@ use rkpd_client::Error as RkpdError;
 use std::cmp::PartialEq;
 use std::ffi::CString;
 
+#[cfg(test)]
+pub mod tests;
+
 /// This is the main Keystore error type. It wraps the Keystore `ResponseCode` generated
 /// from AIDL in the `Rc` variant and Keymint `ErrorCode` in the Km variant.
 #[derive(Debug, thiserror::Error, PartialEq, Eq)]
@@ -232,210 +235,3 @@ pub fn anyhow_error_to_serialized_error(e: &anyhow::Error) -> SerializedError {
         },
     }
 }
-
-#[cfg(test)]
-pub mod tests {
-
-    use super::*;
-    use android_system_keystore2::binder::{
-        ExceptionCode, Result as BinderResult, Status as BinderStatus,
-    };
-    use anyhow::{anyhow, Context};
-
-    fn nested_nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
-        Err(anyhow!(Error::Rc(rc))).context("nested nested rc")
-    }
-
-    fn nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
-        nested_nested_rc(rc).context("nested rc")
-    }
-
-    fn nested_nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
-        Err(anyhow!(Error::Km(ec))).context("nested nested ec")
-    }
-
-    fn nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
-        nested_nested_ec(ec).context("nested ec")
-    }
-
-    fn nested_nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
-        Ok(rc)
-    }
-
-    fn nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
-        nested_nested_ok(rc).context("nested ok")
-    }
-
-    fn nested_nested_selinux_perm() -> anyhow::Result<()> {
-        Err(anyhow!(selinux::Error::perm())).context("nested nexted selinux permission denied")
-    }
-
-    fn nested_selinux_perm() -> anyhow::Result<()> {
-        nested_nested_selinux_perm().context("nested selinux permission denied")
-    }
-
-    #[derive(Debug, thiserror::Error)]
-    enum TestError {
-        #[error("TestError::Fail")]
-        Fail = 0,
-    }
-
-    fn nested_nested_other_error() -> anyhow::Result<()> {
-        Err(anyhow!(TestError::Fail)).context("nested nested other error")
-    }
-
-    fn nested_other_error() -> anyhow::Result<()> {
-        nested_nested_other_error().context("nested other error")
-    }
-
-    fn binder_sse_error(sse: i32) -> BinderResult<()> {
-        Err(BinderStatus::new_service_specific_error(sse, None))
-    }
-
-    fn binder_exception(ex: ExceptionCode) -> BinderResult<()> {
-        Err(BinderStatus::new_exception(ex, None))
-    }
-
-    #[test]
-    fn keystore_error_test() -> anyhow::Result<(), String> {
-        android_logger::init_once(
-            android_logger::Config::default()
-                .with_tag("keystore_error_tests")
-                .with_max_level(log::LevelFilter::Debug),
-        );
-        // All Error::Rc(x) get mapped on a service specific error
-        // code of x.
-        for rc in ResponseCode::LOCKED.0..ResponseCode::BACKEND_BUSY.0 {
-            assert_eq!(
-                Result::<(), i32>::Err(rc),
-                nested_rc(ResponseCode(rc))
-                    .map_err(into_logged_binder)
-                    .map_err(|s| s.service_specific_error())
-            );
-        }
-
-        // All Keystore Error::Km(x) get mapped on a service
-        // specific error of x.
-        for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
-            assert_eq!(
-                Result::<(), i32>::Err(ec),
-                nested_ec(ErrorCode(ec))
-                    .map_err(into_logged_binder)
-                    .map_err(|s| s.service_specific_error())
-            );
-        }
-
-        // All Keymint errors x received through a Binder Result get mapped on
-        // a service specific error of x.
-        for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
-            assert_eq!(
-                Result::<(), i32>::Err(ec),
-                map_km_error(binder_sse_error(ec))
-                    .with_context(|| format!("Km error code: {}.", ec))
-                    .map_err(into_logged_binder)
-                    .map_err(|s| s.service_specific_error())
-            );
-        }
-
-        // map_km_error creates an Error::Binder variant storing
-        // ExceptionCode::SERVICE_SPECIFIC and the given
-        // service specific error.
-        let sse = map_km_error(binder_sse_error(1));
-        assert_eq!(Err(Error::Binder(ExceptionCode::SERVICE_SPECIFIC, 1)), sse);
-        // into_binder then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
-        assert_eq!(
-            Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
-            sse.context("Non negative service specific error.")
-                .map_err(into_logged_binder)
-                .map_err(|s| ResponseCode(s.service_specific_error()))
-        );
-
-        // map_km_error creates a Error::Binder variant storing the given exception code.
-        let binder_exception = map_km_error(binder_exception(ExceptionCode::TRANSACTION_FAILED));
-        assert_eq!(Err(Error::Binder(ExceptionCode::TRANSACTION_FAILED, 0)), binder_exception);
-        // into_binder then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
-        assert_eq!(
-            Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
-            binder_exception
-                .context("Binder Exception.")
-                .map_err(into_logged_binder)
-                .map_err(|s| ResponseCode(s.service_specific_error()))
-        );
-
-        // selinux::Error::Perm() needs to be mapped to ResponseCode::PERMISSION_DENIED
-        assert_eq!(
-            Result::<(), ResponseCode>::Err(ResponseCode::PERMISSION_DENIED),
-            nested_selinux_perm()
-                .map_err(into_logged_binder)
-                .map_err(|s| ResponseCode(s.service_specific_error()))
-        );
-
-        // All other errors get mapped on System Error.
-        assert_eq!(
-            Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
-            nested_other_error()
-                .map_err(into_logged_binder)
-                .map_err(|s| ResponseCode(s.service_specific_error()))
-        );
-
-        // Result::Ok variants get passed to the ok handler.
-        assert_eq!(
-            Ok(ResponseCode::LOCKED),
-            nested_ok(ResponseCode::LOCKED).map_err(into_logged_binder)
-        );
-        assert_eq!(
-            Ok(ResponseCode::SYSTEM_ERROR),
-            nested_ok(ResponseCode::SYSTEM_ERROR).map_err(into_logged_binder)
-        );
-
-        Ok(())
-    }
-
-    //Helper function to test whether error cases are handled as expected.
-    pub fn check_result_contains_error_string<T>(
-        result: anyhow::Result<T>,
-        expected_error_string: &str,
-    ) {
-        let error_str = format!(
-            "{:#?}",
-            result.err().unwrap_or_else(|| panic!("Expected the error: {}", expected_error_string))
-        );
-        assert!(
-            error_str.contains(expected_error_string),
-            "The string \"{}\" should contain \"{}\"",
-            error_str,
-            expected_error_string
-        );
-    }
-
-    #[test]
-    fn rkpd_error_is_in_sync_with_response_code() {
-        let error_mapping = [
-            (RkpdError::RequestCancelled, ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
-            (RkpdError::GetRegistrationFailed, ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
-            (
-                RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_UNKNOWN),
-                ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR,
-            ),
-            (
-                RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_PERMANENT),
-                ResponseCode::OUT_OF_KEYS_PERMANENT_ERROR,
-            ),
-            (
-                RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_PENDING_INTERNET_CONNECTIVITY),
-                ResponseCode::OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY,
-            ),
-            (
-                RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_REQUIRES_SECURITY_PATCH),
-                ResponseCode::OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE,
-            ),
-            (RkpdError::StoreUpgradedKeyFailed, ResponseCode::SYSTEM_ERROR),
-            (RkpdError::RetryableTimeout, ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
-            (RkpdError::Timeout, ResponseCode::SYSTEM_ERROR),
-        ];
-        for (rkpd_error, expected_response_code) in error_mapping {
-            let e: Error = rkpd_error.into();
-            assert_eq!(e, Error::Rc(expected_response_code));
-        }
-    }
-} // mod tests
diff --git a/keystore2/src/error/tests.rs b/keystore2/src/error/tests.rs
new file mode 100644
index 00000000..d50091b0
--- /dev/null
+++ b/keystore2/src/error/tests.rs
@@ -0,0 +1,218 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Error handling tests.
+
+use super::*;
+use android_system_keystore2::binder::{
+    ExceptionCode, Result as BinderResult, Status as BinderStatus,
+};
+use anyhow::{anyhow, Context};
+
+fn nested_nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
+    Err(anyhow!(Error::Rc(rc))).context("nested nested rc")
+}
+
+fn nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
+    nested_nested_rc(rc).context("nested rc")
+}
+
+fn nested_nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
+    Err(anyhow!(Error::Km(ec))).context("nested nested ec")
+}
+
+fn nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
+    nested_nested_ec(ec).context("nested ec")
+}
+
+fn nested_nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
+    Ok(rc)
+}
+
+fn nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
+    nested_nested_ok(rc).context("nested ok")
+}
+
+fn nested_nested_selinux_perm() -> anyhow::Result<()> {
+    Err(anyhow!(selinux::Error::perm())).context("nested nexted selinux permission denied")
+}
+
+fn nested_selinux_perm() -> anyhow::Result<()> {
+    nested_nested_selinux_perm().context("nested selinux permission denied")
+}
+
+#[derive(Debug, thiserror::Error)]
+enum TestError {
+    #[error("TestError::Fail")]
+    Fail = 0,
+}
+
+fn nested_nested_other_error() -> anyhow::Result<()> {
+    Err(anyhow!(TestError::Fail)).context("nested nested other error")
+}
+
+fn nested_other_error() -> anyhow::Result<()> {
+    nested_nested_other_error().context("nested other error")
+}
+
+fn binder_sse_error(sse: i32) -> BinderResult<()> {
+    Err(BinderStatus::new_service_specific_error(sse, None))
+}
+
+fn binder_exception(ex: ExceptionCode) -> BinderResult<()> {
+    Err(BinderStatus::new_exception(ex, None))
+}
+
+#[test]
+fn keystore_error_test() -> anyhow::Result<(), String> {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore_error_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+    // All Error::Rc(x) get mapped on a service specific error
+    // code of x.
+    for rc in ResponseCode::LOCKED.0..ResponseCode::BACKEND_BUSY.0 {
+        assert_eq!(
+            Result::<(), i32>::Err(rc),
+            nested_rc(ResponseCode(rc))
+                .map_err(into_logged_binder)
+                .map_err(|s| s.service_specific_error())
+        );
+    }
+
+    // All Keystore Error::Km(x) get mapped on a service
+    // specific error of x.
+    for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
+        assert_eq!(
+            Result::<(), i32>::Err(ec),
+            nested_ec(ErrorCode(ec))
+                .map_err(into_logged_binder)
+                .map_err(|s| s.service_specific_error())
+        );
+    }
+
+    // All Keymint errors x received through a Binder Result get mapped on
+    // a service specific error of x.
+    for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
+        assert_eq!(
+            Result::<(), i32>::Err(ec),
+            map_km_error(binder_sse_error(ec))
+                .with_context(|| format!("Km error code: {}.", ec))
+                .map_err(into_logged_binder)
+                .map_err(|s| s.service_specific_error())
+        );
+    }
+
+    // map_km_error creates an Error::Binder variant storing
+    // ExceptionCode::SERVICE_SPECIFIC and the given
+    // service specific error.
+    let sse = map_km_error(binder_sse_error(1));
+    assert_eq!(Err(Error::Binder(ExceptionCode::SERVICE_SPECIFIC, 1)), sse);
+    // into_binder then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
+    assert_eq!(
+        Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
+        sse.context("Non negative service specific error.")
+            .map_err(into_logged_binder)
+            .map_err(|s| ResponseCode(s.service_specific_error()))
+    );
+
+    // map_km_error creates a Error::Binder variant storing the given exception code.
+    let binder_exception = map_km_error(binder_exception(ExceptionCode::TRANSACTION_FAILED));
+    assert_eq!(Err(Error::Binder(ExceptionCode::TRANSACTION_FAILED, 0)), binder_exception);
+    // into_binder then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
+    assert_eq!(
+        Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
+        binder_exception
+            .context("Binder Exception.")
+            .map_err(into_logged_binder)
+            .map_err(|s| ResponseCode(s.service_specific_error()))
+    );
+
+    // selinux::Error::Perm() needs to be mapped to ResponseCode::PERMISSION_DENIED
+    assert_eq!(
+        Result::<(), ResponseCode>::Err(ResponseCode::PERMISSION_DENIED),
+        nested_selinux_perm()
+            .map_err(into_logged_binder)
+            .map_err(|s| ResponseCode(s.service_specific_error()))
+    );
+
+    // All other errors get mapped on System Error.
+    assert_eq!(
+        Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
+        nested_other_error()
+            .map_err(into_logged_binder)
+            .map_err(|s| ResponseCode(s.service_specific_error()))
+    );
+
+    // Result::Ok variants get passed to the ok handler.
+    assert_eq!(
+        Ok(ResponseCode::LOCKED),
+        nested_ok(ResponseCode::LOCKED).map_err(into_logged_binder)
+    );
+    assert_eq!(
+        Ok(ResponseCode::SYSTEM_ERROR),
+        nested_ok(ResponseCode::SYSTEM_ERROR).map_err(into_logged_binder)
+    );
+
+    Ok(())
+}
+
+//Helper function to test whether error cases are handled as expected.
+pub fn check_result_contains_error_string<T>(
+    result: anyhow::Result<T>,
+    expected_error_string: &str,
+) {
+    let error_str = format!(
+        "{:#?}",
+        result.err().unwrap_or_else(|| panic!("Expected the error: {}", expected_error_string))
+    );
+    assert!(
+        error_str.contains(expected_error_string),
+        "The string \"{}\" should contain \"{}\"",
+        error_str,
+        expected_error_string
+    );
+}
+
+#[test]
+fn rkpd_error_is_in_sync_with_response_code() {
+    let error_mapping = [
+        (RkpdError::RequestCancelled, ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
+        (RkpdError::GetRegistrationFailed, ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
+        (
+            RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_UNKNOWN),
+            ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR,
+        ),
+        (
+            RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_PERMANENT),
+            ResponseCode::OUT_OF_KEYS_PERMANENT_ERROR,
+        ),
+        (
+            RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_PENDING_INTERNET_CONNECTIVITY),
+            ResponseCode::OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY,
+        ),
+        (
+            RkpdError::GetKeyFailed(GetKeyErrorCode::ERROR_REQUIRES_SECURITY_PATCH),
+            ResponseCode::OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE,
+        ),
+        (RkpdError::StoreUpgradedKeyFailed, ResponseCode::SYSTEM_ERROR),
+        (RkpdError::RetryableTimeout, ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
+        (RkpdError::Timeout, ResponseCode::SYSTEM_ERROR),
+    ];
+    for (rkpd_error, expected_response_code) in error_mapping {
+        let e: Error = rkpd_error.into();
+        assert_eq!(e, Error::Rc(expected_response_code));
+    }
+}
diff --git a/keystore2/src/gc.rs b/keystore2/src/gc.rs
index a0333568..f2341e3c 100644
--- a/keystore2/src/gc.rs
+++ b/keystore2/src/gc.rs
@@ -21,7 +21,7 @@
 use crate::ks_err;
 use crate::{
     async_task,
-    database::{BlobMetaData, KeystoreDB, Uuid},
+    database::{KeystoreDB, SupersededBlob, Uuid},
     super_key::SuperKeyManager,
 };
 use anyhow::{Context, Result};
@@ -84,7 +84,7 @@ impl Gc {
 
 struct GcInternal {
     deleted_blob_ids: Vec<i64>,
-    superseded_blobs: Vec<(i64, Vec<u8>, BlobMetaData)>,
+    superseded_blobs: Vec<SupersededBlob>,
     invalidate_key: Box<dyn Fn(&Uuid, &[u8]) -> Result<()> + Send + 'static>,
     db: KeystoreDB,
     async_task: std::sync::Weak<AsyncTask>,
@@ -109,7 +109,7 @@ impl GcInternal {
             self.superseded_blobs = blobs;
         }
 
-        if let Some((blob_id, blob, blob_metadata)) = self.superseded_blobs.pop() {
+        if let Some(SupersededBlob { blob_id, blob, metadata }) = self.superseded_blobs.pop() {
             // Add the next blob_id to the deleted blob ids list. So it will be
             // removed from the database regardless of whether the following
             // succeeds or not.
@@ -119,12 +119,12 @@ impl GcInternal {
             // and delete the key, unwrapping if necessary and possible.
             // (At this time keys may get deleted without having the super encryption
             // key in this case we can only delete the key from the database.)
-            if let Some(uuid) = blob_metadata.km_uuid() {
+            if let Some(uuid) = metadata.km_uuid() {
                 let blob = self
                     .super_key
                     .read()
                     .unwrap()
-                    .unwrap_key_if_required(&blob_metadata, &blob)
+                    .unwrap_key_if_required(&metadata, &blob)
                     .context(ks_err!("Trying to unwrap to-be-deleted blob.",))?;
                 (self.invalidate_key)(uuid, &blob).context(ks_err!("Trying to invalidate key."))?;
             }
diff --git a/keystore2/src/globals.rs b/keystore2/src/globals.rs
index c7b495df..39d6f9c1 100644
--- a/keystore2/src/globals.rs
+++ b/keystore2/src/globals.rs
@@ -23,7 +23,7 @@ use crate::ks_err;
 use crate::legacy_blob::LegacyBlobLoader;
 use crate::legacy_importer::LegacyImporter;
 use crate::super_key::SuperKeyManager;
-use crate::utils::watchdog as wd;
+use crate::utils::{retry_get_interface, watchdog as wd};
 use crate::{
     database::KeystoreDB,
     database::Uuid,
@@ -46,8 +46,7 @@ use android_security_compat::aidl::android::security::compat::IKeystoreCompatSer
 use anyhow::{Context, Result};
 use binder::FromIBinder;
 use binder::{get_declared_instances, is_declared};
-use lazy_static::lazy_static;
-use std::sync::{Arc, Mutex, RwLock};
+use std::sync::{Arc, LazyLock, Mutex, RwLock};
 use std::{cell::RefCell, sync::Once};
 use std::{collections::HashMap, path::Path, path::PathBuf};
 
@@ -62,21 +61,25 @@ static DB_INIT: Once = Once::new();
 /// is run only once, as long as the ASYNC_TASK instance is the same. So only one additional
 /// database connection is created for the garbage collector worker.
 pub fn create_thread_local_db() -> KeystoreDB {
-    let db_path = DB_PATH.read().expect("Could not get the database directory.");
-
-    let mut db = KeystoreDB::new(&db_path, Some(GC.clone())).expect("Failed to open database.");
+    let db_path = DB_PATH.read().expect("Could not get the database directory");
+
+    let result = KeystoreDB::new(&db_path, Some(GC.clone()));
+    let mut db = match result {
+        Ok(db) => db,
+        Err(e) => {
+            log::error!("Failed to open Keystore database at {db_path:?}: {e:?}");
+            log::error!("Has /data been mounted correctly?");
+            panic!("Failed to open database for Keystore, cannot continue: {e:?}")
+        }
+    };
 
     DB_INIT.call_once(|| {
         log::info!("Touching Keystore 2.0 database for this first time since boot.");
         log::info!("Calling cleanup leftovers.");
-        let n = db.cleanup_leftovers().expect("Failed to cleanup database on startup.");
+        let n = db.cleanup_leftovers().expect("Failed to cleanup database on startup");
         if n != 0 {
             log::info!(
-                concat!(
-                    "Cleaned up {} failed entries. ",
-                    "This indicates keystore crashed during key generation."
-                ),
-                n
+                "Cleaned up {n} failed entries, indicating keystore crash on key generation"
             );
         }
     });
@@ -88,8 +91,7 @@ thread_local! {
     /// same database multiple times is safe as long as each connection is
     /// used by only one thread. So we store one database connection per
     /// thread in this thread local key.
-    pub static DB: RefCell<KeystoreDB> =
-            RefCell::new(create_thread_local_db());
+    pub static DB: RefCell<KeystoreDB> = RefCell::new(create_thread_local_db());
 }
 
 struct DevicesMap<T: FromIBinder + ?Sized> {
@@ -136,45 +138,52 @@ impl<T: FromIBinder + ?Sized> Default for DevicesMap<T> {
     }
 }
 
-lazy_static! {
-    /// The path where keystore stores all its keys.
-    pub static ref DB_PATH: RwLock<PathBuf> = RwLock::new(
-        Path::new("/data/misc/keystore").to_path_buf());
-    /// Runtime database of unwrapped super keys.
-    pub static ref SUPER_KEY: Arc<RwLock<SuperKeyManager>> = Default::default();
-    /// Map of KeyMint devices.
-    static ref KEY_MINT_DEVICES: Mutex<DevicesMap<dyn IKeyMintDevice>> = Default::default();
-    /// Timestamp service.
-    static ref TIME_STAMP_DEVICE: Mutex<Option<Strong<dyn ISecureClock>>> = Default::default();
-    /// A single on-demand worker thread that handles deferred tasks with two different
-    /// priorities.
-    pub static ref ASYNC_TASK: Arc<AsyncTask> = Default::default();
-    /// Singleton for enforcements.
-    pub static ref ENFORCEMENTS: Enforcements = Default::default();
-    /// LegacyBlobLoader is initialized and exists globally.
-    /// The same directory used by the database is used by the LegacyBlobLoader as well.
-    pub static ref LEGACY_BLOB_LOADER: Arc<LegacyBlobLoader> = Arc::new(LegacyBlobLoader::new(
-        &DB_PATH.read().expect("Could not get the database path for legacy blob loader.")));
-    /// Legacy migrator. Atomically migrates legacy blobs to the database.
-    pub static ref LEGACY_IMPORTER: Arc<LegacyImporter> =
-        Arc::new(LegacyImporter::new(Arc::new(Default::default())));
-    /// Background thread which handles logging via statsd and logd
-    pub static ref LOGS_HANDLER: Arc<AsyncTask> = Default::default();
-
-    static ref GC: Arc<Gc> = Arc::new(Gc::new_init_with(ASYNC_TASK.clone(), || {
+/// The path where keystore stores all its keys.
+pub static DB_PATH: LazyLock<RwLock<PathBuf>> =
+    LazyLock::new(|| RwLock::new(Path::new("/data/misc/keystore").to_path_buf()));
+/// Runtime database of unwrapped super keys.
+pub static SUPER_KEY: LazyLock<Arc<RwLock<SuperKeyManager>>> = LazyLock::new(Default::default);
+/// Map of KeyMint devices.
+static KEY_MINT_DEVICES: LazyLock<Mutex<DevicesMap<dyn IKeyMintDevice>>> =
+    LazyLock::new(Default::default);
+/// Timestamp service.
+static TIME_STAMP_DEVICE: Mutex<Option<Strong<dyn ISecureClock>>> = Mutex::new(None);
+/// A single on-demand worker thread that handles deferred tasks with two different
+/// priorities.
+pub static ASYNC_TASK: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);
+/// Singleton for enforcements.
+pub static ENFORCEMENTS: LazyLock<Enforcements> = LazyLock::new(Default::default);
+/// LegacyBlobLoader is initialized and exists globally.
+/// The same directory used by the database is used by the LegacyBlobLoader as well.
+pub static LEGACY_BLOB_LOADER: LazyLock<Arc<LegacyBlobLoader>> = LazyLock::new(|| {
+    Arc::new(LegacyBlobLoader::new(
+        &DB_PATH.read().expect("Could not determine database path for legacy blob loader"),
+    ))
+});
+/// Legacy migrator. Atomically migrates legacy blobs to the database.
+pub static LEGACY_IMPORTER: LazyLock<Arc<LegacyImporter>> =
+    LazyLock::new(|| Arc::new(LegacyImporter::new(Arc::new(Default::default()))));
+/// Background thread which handles logging via statsd and logd
+pub static LOGS_HANDLER: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);
+
+static GC: LazyLock<Arc<Gc>> = LazyLock::new(|| {
+    Arc::new(Gc::new_init_with(ASYNC_TASK.clone(), || {
         (
             Box::new(|uuid, blob| {
                 let km_dev = get_keymint_dev_by_uuid(uuid).map(|(dev, _)| dev)?;
-                let _wp = wd::watch("In invalidate key closure: calling deleteKey");
+                let _wp = wd::watch("invalidate key closure: calling IKeyMintDevice::deleteKey");
                 map_km_error(km_dev.deleteKey(blob))
                     .context(ks_err!("Trying to invalidate key blob."))
             }),
-            KeystoreDB::new(&DB_PATH.read().expect("Could not get the database directory."), None)
-                .expect("Failed to open database."),
+            KeystoreDB::new(
+                &DB_PATH.read().expect("Could not determine database path for GC"),
+                None,
+            )
+            .expect("Failed to open database"),
             SUPER_KEY.clone(),
         )
-    }));
-}
+    }))
+});
 
 /// Determine the service name for a KeyMint device of the given security level
 /// gotten by binder service from the device and determining what services
@@ -222,8 +231,12 @@ fn connect_keymint(
 
     let (keymint, hal_version) = if let Some(service_name) = service_name {
         let km: Strong<dyn IKeyMintDevice> =
-            map_binder_status_code(binder::get_interface(&service_name))
-                .context(ks_err!("Trying to connect to genuine KeyMint service."))?;
+            if SecurityLevel::TRUSTED_ENVIRONMENT == *security_level {
+                map_binder_status_code(retry_get_interface(&service_name))
+            } else {
+                map_binder_status_code(binder::get_interface(&service_name))
+            }
+            .context(ks_err!("Trying to connect to genuine KeyMint service."))?;
         // Map the HAL version code for KeyMint to be <AIDL version> * 100, so
         // - V1 is 100
         // - V2 is 200
@@ -306,7 +319,7 @@ fn connect_keymint(
         }
     };
 
-    let wp = wd::watch("In connect_keymint: calling getHardwareInfo()");
+    let wp = wd::watch("connect_keymint: calling IKeyMintDevice::getHardwareInfo()");
     let mut hw_info =
         map_km_error(keymint.getHardwareInfo()).context(ks_err!("Failed to get hardware info."))?;
     drop(wp);
diff --git a/keystore2/src/key_parameter.rs b/keystore2/src/key_parameter.rs
index bd452073..466fb505 100644
--- a/keystore2/src/key_parameter.rs
+++ b/keystore2/src/key_parameter.rs
@@ -111,6 +111,18 @@ use serde::de::Deserializer;
 use serde::ser::Serializer;
 use serde::{Deserialize, Serialize};
 
+#[cfg(test)]
+mod generated_key_parameter_tests;
+
+#[cfg(test)]
+mod basic_tests;
+
+#[cfg(test)]
+mod storage_tests;
+
+#[cfg(test)]
+mod wire_tests;
+
 /// This trait is used to associate a primitive to any type that can be stored inside a
 /// KeyParameterValue, especially the AIDL enum types, e.g., keymint::{Algorithm, Digest, ...}.
 /// This allows for simplifying the macro rules, e.g., for reading from the SQL database.
@@ -1091,490 +1103,3 @@ impl KeyParameter {
         Authorization { securityLevel: self.security_level, keyParameter: self.value.into() }
     }
 }
-
-#[cfg(test)]
-mod generated_key_parameter_tests {
-    use super::*;
-    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::TagType::TagType;
-
-    fn get_field_by_tag_type(tag: Tag) -> KmKeyParameterValue {
-        let tag_type = TagType((tag.0 as u32 & 0xF0000000) as i32);
-        match tag {
-            Tag::ALGORITHM => return KmKeyParameterValue::Algorithm(Default::default()),
-            Tag::BLOCK_MODE => return KmKeyParameterValue::BlockMode(Default::default()),
-            Tag::PADDING => return KmKeyParameterValue::PaddingMode(Default::default()),
-            Tag::DIGEST => return KmKeyParameterValue::Digest(Default::default()),
-            Tag::RSA_OAEP_MGF_DIGEST => return KmKeyParameterValue::Digest(Default::default()),
-            Tag::EC_CURVE => return KmKeyParameterValue::EcCurve(Default::default()),
-            Tag::ORIGIN => return KmKeyParameterValue::Origin(Default::default()),
-            Tag::PURPOSE => return KmKeyParameterValue::KeyPurpose(Default::default()),
-            Tag::USER_AUTH_TYPE => {
-                return KmKeyParameterValue::HardwareAuthenticatorType(Default::default())
-            }
-            Tag::HARDWARE_TYPE => return KmKeyParameterValue::SecurityLevel(Default::default()),
-            _ => {}
-        }
-        match tag_type {
-            TagType::INVALID => return KmKeyParameterValue::Invalid(Default::default()),
-            TagType::ENUM | TagType::ENUM_REP => {}
-            TagType::UINT | TagType::UINT_REP => {
-                return KmKeyParameterValue::Integer(Default::default())
-            }
-            TagType::ULONG | TagType::ULONG_REP => {
-                return KmKeyParameterValue::LongInteger(Default::default())
-            }
-            TagType::DATE => return KmKeyParameterValue::DateTime(Default::default()),
-            TagType::BOOL => return KmKeyParameterValue::BoolValue(Default::default()),
-            TagType::BIGNUM | TagType::BYTES => {
-                return KmKeyParameterValue::Blob(Default::default())
-            }
-            _ => {}
-        }
-        panic!("Unknown tag/tag_type: {:?} {:?}", tag, tag_type);
-    }
-
-    fn check_field_matches_tag_type(list_o_parameters: &[KmKeyParameter]) {
-        for kp in list_o_parameters.iter() {
-            match (&kp.value, get_field_by_tag_type(kp.tag)) {
-                (&KmKeyParameterValue::Algorithm(_), KmKeyParameterValue::Algorithm(_))
-                | (&KmKeyParameterValue::BlockMode(_), KmKeyParameterValue::BlockMode(_))
-                | (&KmKeyParameterValue::PaddingMode(_), KmKeyParameterValue::PaddingMode(_))
-                | (&KmKeyParameterValue::Digest(_), KmKeyParameterValue::Digest(_))
-                | (&KmKeyParameterValue::EcCurve(_), KmKeyParameterValue::EcCurve(_))
-                | (&KmKeyParameterValue::Origin(_), KmKeyParameterValue::Origin(_))
-                | (&KmKeyParameterValue::KeyPurpose(_), KmKeyParameterValue::KeyPurpose(_))
-                | (
-                    &KmKeyParameterValue::HardwareAuthenticatorType(_),
-                    KmKeyParameterValue::HardwareAuthenticatorType(_),
-                )
-                | (&KmKeyParameterValue::SecurityLevel(_), KmKeyParameterValue::SecurityLevel(_))
-                | (&KmKeyParameterValue::Invalid(_), KmKeyParameterValue::Invalid(_))
-                | (&KmKeyParameterValue::Integer(_), KmKeyParameterValue::Integer(_))
-                | (&KmKeyParameterValue::LongInteger(_), KmKeyParameterValue::LongInteger(_))
-                | (&KmKeyParameterValue::DateTime(_), KmKeyParameterValue::DateTime(_))
-                | (&KmKeyParameterValue::BoolValue(_), KmKeyParameterValue::BoolValue(_))
-                | (&KmKeyParameterValue::Blob(_), KmKeyParameterValue::Blob(_)) => {}
-                (actual, expected) => panic!(
-                    "Tag {:?} associated with variant {:?} expected {:?}",
-                    kp.tag, actual, expected
-                ),
-            }
-        }
-    }
-
-    #[test]
-    fn key_parameter_value_field_matches_tag_type() {
-        check_field_matches_tag_type(&KeyParameterValue::make_field_matches_tag_type_test_vector());
-    }
-
-    #[test]
-    fn key_parameter_serialization_test() {
-        let params = KeyParameterValue::make_key_parameter_defaults_vector();
-        let mut out_buffer: Vec<u8> = Default::default();
-        serde_cbor::to_writer(&mut out_buffer, &params)
-            .expect("Failed to serialize key parameters.");
-        let deserialized_params: Vec<KeyParameter> =
-            serde_cbor::from_reader(&mut out_buffer.as_slice())
-                .expect("Failed to deserialize key parameters.");
-        assert_eq!(params, deserialized_params);
-    }
-}
-
-#[cfg(test)]
-mod basic_tests {
-    use crate::key_parameter::*;
-
-    // Test basic functionality of KeyParameter.
-    #[test]
-    fn test_key_parameter() {
-        let key_parameter = KeyParameter::new(
-            KeyParameterValue::Algorithm(Algorithm::RSA),
-            SecurityLevel::STRONGBOX,
-        );
-
-        assert_eq!(key_parameter.get_tag(), Tag::ALGORITHM);
-
-        assert_eq!(
-            *key_parameter.key_parameter_value(),
-            KeyParameterValue::Algorithm(Algorithm::RSA)
-        );
-
-        assert_eq!(*key_parameter.security_level(), SecurityLevel::STRONGBOX);
-    }
-}
-
-/// The storage_tests module first tests the 'new_from_sql' method for KeyParameters of different
-/// data types and then tests 'to_sql' method for KeyParameters of those
-/// different data types. The five different data types for KeyParameter values are:
-/// i) enums of u32
-/// ii) u32
-/// iii) u64
-/// iv) Vec<u8>
-/// v) bool
-#[cfg(test)]
-mod storage_tests {
-    use crate::error::*;
-    use crate::key_parameter::*;
-    use anyhow::Result;
-    use rusqlite::types::ToSql;
-    use rusqlite::{params, Connection};
-
-    /// Test initializing a KeyParameter (with key parameter value corresponding to an enum of i32)
-    /// from a database table row.
-    #[test]
-    fn test_new_from_sql_enum_i32() -> Result<()> {
-        let db = init_db()?;
-        insert_into_keyparameter(
-            &db,
-            1,
-            Tag::ALGORITHM.0,
-            &Algorithm::RSA.0,
-            SecurityLevel::STRONGBOX.0,
-        )?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::ALGORITHM, key_param.get_tag());
-        assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::Algorithm(Algorithm::RSA));
-        assert_eq!(*key_param.security_level(), SecurityLevel::STRONGBOX);
-        Ok(())
-    }
-
-    /// Test initializing a KeyParameter (with key parameter value which is of i32)
-    /// from a database table row.
-    #[test]
-    fn test_new_from_sql_i32() -> Result<()> {
-        let db = init_db()?;
-        insert_into_keyparameter(&db, 1, Tag::KEY_SIZE.0, &1024, SecurityLevel::STRONGBOX.0)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::KEY_SIZE, key_param.get_tag());
-        assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::KeySize(1024));
-        Ok(())
-    }
-
-    /// Test initializing a KeyParameter (with key parameter value which is of i64)
-    /// from a database table row.
-    #[test]
-    fn test_new_from_sql_i64() -> Result<()> {
-        let db = init_db()?;
-        // max value for i64, just to test corner cases
-        insert_into_keyparameter(
-            &db,
-            1,
-            Tag::RSA_PUBLIC_EXPONENT.0,
-            &(i64::MAX),
-            SecurityLevel::STRONGBOX.0,
-        )?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::RSA_PUBLIC_EXPONENT, key_param.get_tag());
-        assert_eq!(
-            *key_param.key_parameter_value(),
-            KeyParameterValue::RSAPublicExponent(i64::MAX)
-        );
-        Ok(())
-    }
-
-    /// Test initializing a KeyParameter (with key parameter value which is of bool)
-    /// from a database table row.
-    #[test]
-    fn test_new_from_sql_bool() -> Result<()> {
-        let db = init_db()?;
-        insert_into_keyparameter(&db, 1, Tag::CALLER_NONCE.0, &Null, SecurityLevel::STRONGBOX.0)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::CALLER_NONCE, key_param.get_tag());
-        assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::CallerNonce);
-        Ok(())
-    }
-
-    /// Test initializing a KeyParameter (with key parameter value which is of Vec<u8>)
-    /// from a database table row.
-    #[test]
-    fn test_new_from_sql_vec_u8() -> Result<()> {
-        let db = init_db()?;
-        let app_id = String::from("MyAppID");
-        let app_id_bytes = app_id.into_bytes();
-        insert_into_keyparameter(
-            &db,
-            1,
-            Tag::APPLICATION_ID.0,
-            &app_id_bytes,
-            SecurityLevel::STRONGBOX.0,
-        )?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::APPLICATION_ID, key_param.get_tag());
-        assert_eq!(
-            *key_param.key_parameter_value(),
-            KeyParameterValue::ApplicationID(app_id_bytes)
-        );
-        Ok(())
-    }
-
-    /// Test storing a KeyParameter (with key parameter value which corresponds to an enum of i32)
-    /// in the database
-    #[test]
-    fn test_to_sql_enum_i32() -> Result<()> {
-        let db = init_db()?;
-        let kp = KeyParameter::new(
-            KeyParameterValue::Algorithm(Algorithm::RSA),
-            SecurityLevel::STRONGBOX,
-        );
-        store_keyparameter(&db, 1, &kp)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(kp.get_tag(), key_param.get_tag());
-        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
-        assert_eq!(kp.security_level(), key_param.security_level());
-        Ok(())
-    }
-
-    /// Test storing a KeyParameter (with key parameter value which is of i32) in the database
-    #[test]
-    fn test_to_sql_i32() -> Result<()> {
-        let db = init_db()?;
-        let kp = KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::STRONGBOX);
-        store_keyparameter(&db, 1, &kp)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(kp.get_tag(), key_param.get_tag());
-        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
-        assert_eq!(kp.security_level(), key_param.security_level());
-        Ok(())
-    }
-
-    /// Test storing a KeyParameter (with key parameter value which is of i64) in the database
-    #[test]
-    fn test_to_sql_i64() -> Result<()> {
-        let db = init_db()?;
-        // max value for i64, just to test corner cases
-        let kp = KeyParameter::new(
-            KeyParameterValue::RSAPublicExponent(i64::MAX),
-            SecurityLevel::STRONGBOX,
-        );
-        store_keyparameter(&db, 1, &kp)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(kp.get_tag(), key_param.get_tag());
-        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
-        assert_eq!(kp.security_level(), key_param.security_level());
-        Ok(())
-    }
-
-    /// Test storing a KeyParameter (with key parameter value which is of Vec<u8>) in the database
-    #[test]
-    fn test_to_sql_vec_u8() -> Result<()> {
-        let db = init_db()?;
-        let kp = KeyParameter::new(
-            KeyParameterValue::ApplicationID(String::from("MyAppID").into_bytes()),
-            SecurityLevel::STRONGBOX,
-        );
-        store_keyparameter(&db, 1, &kp)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(kp.get_tag(), key_param.get_tag());
-        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
-        assert_eq!(kp.security_level(), key_param.security_level());
-        Ok(())
-    }
-
-    /// Test storing a KeyParameter (with key parameter value which is of i32) in the database
-    #[test]
-    fn test_to_sql_bool() -> Result<()> {
-        let db = init_db()?;
-        let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
-        store_keyparameter(&db, 1, &kp)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(kp.get_tag(), key_param.get_tag());
-        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
-        assert_eq!(kp.security_level(), key_param.security_level());
-        Ok(())
-    }
-
-    #[test]
-    /// Test Tag::Invalid
-    fn test_invalid_tag() -> Result<()> {
-        let db = init_db()?;
-        insert_into_keyparameter(&db, 1, 0, &123, 1)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::INVALID, key_param.get_tag());
-        Ok(())
-    }
-
-    #[test]
-    fn test_non_existing_enum_variant() -> Result<()> {
-        let db = init_db()?;
-        insert_into_keyparameter(&db, 1, 100, &123, 1)?;
-        let key_param = query_from_keyparameter(&db)?;
-        assert_eq!(Tag::INVALID, key_param.get_tag());
-        Ok(())
-    }
-
-    #[test]
-    fn test_invalid_conversion_from_sql() -> Result<()> {
-        let db = init_db()?;
-        insert_into_keyparameter(&db, 1, Tag::ALGORITHM.0, &Null, 1)?;
-        tests::check_result_contains_error_string(
-            query_from_keyparameter(&db),
-            "Failed to read sql data for tag: ALGORITHM.",
-        );
-        Ok(())
-    }
-
-    /// Helper method to init database table for key parameter
-    fn init_db() -> Result<Connection> {
-        let db = Connection::open_in_memory().context("Failed to initialize sqlite connection.")?;
-        db.execute("ATTACH DATABASE ? as 'persistent';", params![""])
-            .context("Failed to attach databases.")?;
-        db.execute(
-            "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
-                                keyentryid INTEGER,
-                                tag INTEGER,
-                                data ANY,
-                                security_level INTEGER);",
-            [],
-        )
-        .context("Failed to initialize \"keyparameter\" table.")?;
-        Ok(db)
-    }
-
-    /// Helper method to insert an entry into key parameter table, with individual parameters
-    fn insert_into_keyparameter<T: ToSql>(
-        db: &Connection,
-        key_id: i64,
-        tag: i32,
-        value: &T,
-        security_level: i32,
-    ) -> Result<()> {
-        db.execute(
-            "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
-                VALUES(?, ?, ?, ?);",
-            params![key_id, tag, *value, security_level],
-        )?;
-        Ok(())
-    }
-
-    /// Helper method to store a key parameter instance.
-    fn store_keyparameter(db: &Connection, key_id: i64, kp: &KeyParameter) -> Result<()> {
-        db.execute(
-            "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
-                VALUES(?, ?, ?, ?);",
-            params![key_id, kp.get_tag().0, kp.key_parameter_value(), kp.security_level().0],
-        )?;
-        Ok(())
-    }
-
-    /// Helper method to query a row from keyparameter table
-    fn query_from_keyparameter(db: &Connection) -> Result<KeyParameter> {
-        let mut stmt =
-            db.prepare("SELECT tag, data, security_level FROM persistent.keyparameter")?;
-        let mut rows = stmt.query([])?;
-        let row = rows.next()?.unwrap();
-        KeyParameter::new_from_sql(
-            Tag(row.get(0)?),
-            &SqlField::new(1, row),
-            SecurityLevel(row.get(2)?),
-        )
-    }
-}
-
-/// The wire_tests module tests the 'convert_to_wire' and 'convert_from_wire' methods for
-/// KeyParameter, for the four different types used in KmKeyParameter, in addition to Invalid
-/// key parameter.
-/// i) bool
-/// ii) integer
-/// iii) longInteger
-/// iv) blob
-#[cfg(test)]
-mod wire_tests {
-    use crate::key_parameter::*;
-    /// unit tests for to conversions
-    #[test]
-    fn test_convert_to_wire_invalid() {
-        let kp = KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::STRONGBOX);
-        assert_eq!(
-            KmKeyParameter { tag: Tag::INVALID, value: KmKeyParameterValue::Invalid(0) },
-            kp.value.into()
-        );
-    }
-    #[test]
-    fn test_convert_to_wire_bool() {
-        let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
-        assert_eq!(
-            KmKeyParameter { tag: Tag::CALLER_NONCE, value: KmKeyParameterValue::BoolValue(true) },
-            kp.value.into()
-        );
-    }
-    #[test]
-    fn test_convert_to_wire_integer() {
-        let kp = KeyParameter::new(
-            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
-            SecurityLevel::STRONGBOX,
-        );
-        assert_eq!(
-            KmKeyParameter {
-                tag: Tag::PURPOSE,
-                value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT)
-            },
-            kp.value.into()
-        );
-    }
-    #[test]
-    fn test_convert_to_wire_long_integer() {
-        let kp =
-            KeyParameter::new(KeyParameterValue::UserSecureID(i64::MAX), SecurityLevel::STRONGBOX);
-        assert_eq!(
-            KmKeyParameter {
-                tag: Tag::USER_SECURE_ID,
-                value: KmKeyParameterValue::LongInteger(i64::MAX)
-            },
-            kp.value.into()
-        );
-    }
-    #[test]
-    fn test_convert_to_wire_blob() {
-        let kp = KeyParameter::new(
-            KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
-            SecurityLevel::STRONGBOX,
-        );
-        assert_eq!(
-            KmKeyParameter {
-                tag: Tag::CONFIRMATION_TOKEN,
-                value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes())
-            },
-            kp.value.into()
-        );
-    }
-
-    /// unit tests for from conversion
-    #[test]
-    fn test_convert_from_wire_invalid() {
-        let aidl_kp = KmKeyParameter { tag: Tag::INVALID, ..Default::default() };
-        assert_eq!(KeyParameterValue::Invalid, aidl_kp.into());
-    }
-    #[test]
-    fn test_convert_from_wire_bool() {
-        let aidl_kp =
-            KmKeyParameter { tag: Tag::CALLER_NONCE, value: KmKeyParameterValue::BoolValue(true) };
-        assert_eq!(KeyParameterValue::CallerNonce, aidl_kp.into());
-    }
-    #[test]
-    fn test_convert_from_wire_integer() {
-        let aidl_kp = KmKeyParameter {
-            tag: Tag::PURPOSE,
-            value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
-        };
-        assert_eq!(KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT), aidl_kp.into());
-    }
-    #[test]
-    fn test_convert_from_wire_long_integer() {
-        let aidl_kp = KmKeyParameter {
-            tag: Tag::USER_SECURE_ID,
-            value: KmKeyParameterValue::LongInteger(i64::MAX),
-        };
-        assert_eq!(KeyParameterValue::UserSecureID(i64::MAX), aidl_kp.into());
-    }
-    #[test]
-    fn test_convert_from_wire_blob() {
-        let aidl_kp = KmKeyParameter {
-            tag: Tag::CONFIRMATION_TOKEN,
-            value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes()),
-        };
-        assert_eq!(
-            KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
-            aidl_kp.into()
-        );
-    }
-}
diff --git a/prng_seeder/cutils_wrapper.h b/keystore2/src/key_parameter/basic_tests.rs
similarity index 51%
rename from prng_seeder/cutils_wrapper.h
rename to keystore2/src/key_parameter/basic_tests.rs
index 9c1fe565..2bb37246 100644
--- a/prng_seeder/cutils_wrapper.h
+++ b/keystore2/src/key_parameter/basic_tests.rs
@@ -1,4 +1,4 @@
-// Copyright (C) 2022 The Android Open Source Project
+// Copyright 2020, The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -12,4 +12,17 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#include <cutils/sockets.h>
+use crate::key_parameter::*;
+
+// Test basic functionality of KeyParameter.
+#[test]
+fn test_key_parameter() {
+    let key_parameter =
+        KeyParameter::new(KeyParameterValue::Algorithm(Algorithm::RSA), SecurityLevel::STRONGBOX);
+
+    assert_eq!(key_parameter.get_tag(), Tag::ALGORITHM);
+
+    assert_eq!(*key_parameter.key_parameter_value(), KeyParameterValue::Algorithm(Algorithm::RSA));
+
+    assert_eq!(*key_parameter.security_level(), SecurityLevel::STRONGBOX);
+}
diff --git a/keystore2/src/key_parameter/generated_key_parameter_tests.rs b/keystore2/src/key_parameter/generated_key_parameter_tests.rs
new file mode 100644
index 00000000..a5c0a8ba
--- /dev/null
+++ b/keystore2/src/key_parameter/generated_key_parameter_tests.rs
@@ -0,0 +1,95 @@
+// Copyright 2020, The Android Open Source Project
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
+use super::*;
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::TagType::TagType;
+
+fn get_field_by_tag_type(tag: Tag) -> KmKeyParameterValue {
+    let tag_type = TagType((tag.0 as u32 & 0xF0000000) as i32);
+    match tag {
+        Tag::ALGORITHM => return KmKeyParameterValue::Algorithm(Default::default()),
+        Tag::BLOCK_MODE => return KmKeyParameterValue::BlockMode(Default::default()),
+        Tag::PADDING => return KmKeyParameterValue::PaddingMode(Default::default()),
+        Tag::DIGEST => return KmKeyParameterValue::Digest(Default::default()),
+        Tag::RSA_OAEP_MGF_DIGEST => return KmKeyParameterValue::Digest(Default::default()),
+        Tag::EC_CURVE => return KmKeyParameterValue::EcCurve(Default::default()),
+        Tag::ORIGIN => return KmKeyParameterValue::Origin(Default::default()),
+        Tag::PURPOSE => return KmKeyParameterValue::KeyPurpose(Default::default()),
+        Tag::USER_AUTH_TYPE => {
+            return KmKeyParameterValue::HardwareAuthenticatorType(Default::default())
+        }
+        Tag::HARDWARE_TYPE => return KmKeyParameterValue::SecurityLevel(Default::default()),
+        _ => {}
+    }
+    match tag_type {
+        TagType::INVALID => return KmKeyParameterValue::Invalid(Default::default()),
+        TagType::ENUM | TagType::ENUM_REP => {}
+        TagType::UINT | TagType::UINT_REP => {
+            return KmKeyParameterValue::Integer(Default::default())
+        }
+        TagType::ULONG | TagType::ULONG_REP => {
+            return KmKeyParameterValue::LongInteger(Default::default())
+        }
+        TagType::DATE => return KmKeyParameterValue::DateTime(Default::default()),
+        TagType::BOOL => return KmKeyParameterValue::BoolValue(Default::default()),
+        TagType::BIGNUM | TagType::BYTES => return KmKeyParameterValue::Blob(Default::default()),
+        _ => {}
+    }
+    panic!("Unknown tag/tag_type: {:?} {:?}", tag, tag_type);
+}
+
+fn check_field_matches_tag_type(list_o_parameters: &[KmKeyParameter]) {
+    for kp in list_o_parameters.iter() {
+        match (&kp.value, get_field_by_tag_type(kp.tag)) {
+            (&KmKeyParameterValue::Algorithm(_), KmKeyParameterValue::Algorithm(_))
+            | (&KmKeyParameterValue::BlockMode(_), KmKeyParameterValue::BlockMode(_))
+            | (&KmKeyParameterValue::PaddingMode(_), KmKeyParameterValue::PaddingMode(_))
+            | (&KmKeyParameterValue::Digest(_), KmKeyParameterValue::Digest(_))
+            | (&KmKeyParameterValue::EcCurve(_), KmKeyParameterValue::EcCurve(_))
+            | (&KmKeyParameterValue::Origin(_), KmKeyParameterValue::Origin(_))
+            | (&KmKeyParameterValue::KeyPurpose(_), KmKeyParameterValue::KeyPurpose(_))
+            | (
+                &KmKeyParameterValue::HardwareAuthenticatorType(_),
+                KmKeyParameterValue::HardwareAuthenticatorType(_),
+            )
+            | (&KmKeyParameterValue::SecurityLevel(_), KmKeyParameterValue::SecurityLevel(_))
+            | (&KmKeyParameterValue::Invalid(_), KmKeyParameterValue::Invalid(_))
+            | (&KmKeyParameterValue::Integer(_), KmKeyParameterValue::Integer(_))
+            | (&KmKeyParameterValue::LongInteger(_), KmKeyParameterValue::LongInteger(_))
+            | (&KmKeyParameterValue::DateTime(_), KmKeyParameterValue::DateTime(_))
+            | (&KmKeyParameterValue::BoolValue(_), KmKeyParameterValue::BoolValue(_))
+            | (&KmKeyParameterValue::Blob(_), KmKeyParameterValue::Blob(_)) => {}
+            (actual, expected) => panic!(
+                "Tag {:?} associated with variant {:?} expected {:?}",
+                kp.tag, actual, expected
+            ),
+        }
+    }
+}
+
+#[test]
+fn key_parameter_value_field_matches_tag_type() {
+    check_field_matches_tag_type(&KeyParameterValue::make_field_matches_tag_type_test_vector());
+}
+
+#[test]
+fn key_parameter_serialization_test() {
+    let params = KeyParameterValue::make_key_parameter_defaults_vector();
+    let mut out_buffer: Vec<u8> = Default::default();
+    serde_cbor::to_writer(&mut out_buffer, &params).expect("Failed to serialize key parameters.");
+    let deserialized_params: Vec<KeyParameter> =
+        serde_cbor::from_reader(&mut out_buffer.as_slice())
+            .expect("Failed to deserialize key parameters.");
+    assert_eq!(params, deserialized_params);
+}
diff --git a/keystore2/src/key_parameter/storage_tests.rs b/keystore2/src/key_parameter/storage_tests.rs
new file mode 100644
index 00000000..38a57e41
--- /dev/null
+++ b/keystore2/src/key_parameter/storage_tests.rs
@@ -0,0 +1,263 @@
+// Copyright 2020, The Android Open Source Project
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
+//! The storage_tests module first tests the 'new_from_sql' method for KeyParameters of different
+//! data types and then tests 'to_sql' method for KeyParameters of those
+//! different data types. The five different data types for KeyParameter values are:
+//! i) enums of u32
+//! ii) u32
+//! iii) u64
+//! iv) Vec<u8>
+//! v) bool
+
+use crate::error::*;
+use crate::key_parameter::*;
+use anyhow::Result;
+use rusqlite::types::ToSql;
+use rusqlite::{params, Connection};
+
+/// Test initializing a KeyParameter (with key parameter value corresponding to an enum of i32)
+/// from a database table row.
+#[test]
+fn test_new_from_sql_enum_i32() -> Result<()> {
+    let db = init_db()?;
+    insert_into_keyparameter(
+        &db,
+        1,
+        Tag::ALGORITHM.0,
+        &Algorithm::RSA.0,
+        SecurityLevel::STRONGBOX.0,
+    )?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::ALGORITHM, key_param.get_tag());
+    assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::Algorithm(Algorithm::RSA));
+    assert_eq!(*key_param.security_level(), SecurityLevel::STRONGBOX);
+    Ok(())
+}
+
+/// Test initializing a KeyParameter (with key parameter value which is of i32)
+/// from a database table row.
+#[test]
+fn test_new_from_sql_i32() -> Result<()> {
+    let db = init_db()?;
+    insert_into_keyparameter(&db, 1, Tag::KEY_SIZE.0, &1024, SecurityLevel::STRONGBOX.0)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::KEY_SIZE, key_param.get_tag());
+    assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::KeySize(1024));
+    Ok(())
+}
+
+/// Test initializing a KeyParameter (with key parameter value which is of i64)
+/// from a database table row.
+#[test]
+fn test_new_from_sql_i64() -> Result<()> {
+    let db = init_db()?;
+    // max value for i64, just to test corner cases
+    insert_into_keyparameter(
+        &db,
+        1,
+        Tag::RSA_PUBLIC_EXPONENT.0,
+        &(i64::MAX),
+        SecurityLevel::STRONGBOX.0,
+    )?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::RSA_PUBLIC_EXPONENT, key_param.get_tag());
+    assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::RSAPublicExponent(i64::MAX));
+    Ok(())
+}
+
+/// Test initializing a KeyParameter (with key parameter value which is of bool)
+/// from a database table row.
+#[test]
+fn test_new_from_sql_bool() -> Result<()> {
+    let db = init_db()?;
+    insert_into_keyparameter(&db, 1, Tag::CALLER_NONCE.0, &Null, SecurityLevel::STRONGBOX.0)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::CALLER_NONCE, key_param.get_tag());
+    assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::CallerNonce);
+    Ok(())
+}
+
+/// Test initializing a KeyParameter (with key parameter value which is of Vec<u8>)
+/// from a database table row.
+#[test]
+fn test_new_from_sql_vec_u8() -> Result<()> {
+    let db = init_db()?;
+    let app_id = String::from("MyAppID");
+    let app_id_bytes = app_id.into_bytes();
+    insert_into_keyparameter(
+        &db,
+        1,
+        Tag::APPLICATION_ID.0,
+        &app_id_bytes,
+        SecurityLevel::STRONGBOX.0,
+    )?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::APPLICATION_ID, key_param.get_tag());
+    assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::ApplicationID(app_id_bytes));
+    Ok(())
+}
+
+/// Test storing a KeyParameter (with key parameter value which corresponds to an enum of i32)
+/// in the database
+#[test]
+fn test_to_sql_enum_i32() -> Result<()> {
+    let db = init_db()?;
+    let kp =
+        KeyParameter::new(KeyParameterValue::Algorithm(Algorithm::RSA), SecurityLevel::STRONGBOX);
+    store_keyparameter(&db, 1, &kp)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(kp.get_tag(), key_param.get_tag());
+    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
+    assert_eq!(kp.security_level(), key_param.security_level());
+    Ok(())
+}
+
+/// Test storing a KeyParameter (with key parameter value which is of i32) in the database
+#[test]
+fn test_to_sql_i32() -> Result<()> {
+    let db = init_db()?;
+    let kp = KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::STRONGBOX);
+    store_keyparameter(&db, 1, &kp)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(kp.get_tag(), key_param.get_tag());
+    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
+    assert_eq!(kp.security_level(), key_param.security_level());
+    Ok(())
+}
+
+/// Test storing a KeyParameter (with key parameter value which is of i64) in the database
+#[test]
+fn test_to_sql_i64() -> Result<()> {
+    let db = init_db()?;
+    // max value for i64, just to test corner cases
+    let kp =
+        KeyParameter::new(KeyParameterValue::RSAPublicExponent(i64::MAX), SecurityLevel::STRONGBOX);
+    store_keyparameter(&db, 1, &kp)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(kp.get_tag(), key_param.get_tag());
+    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
+    assert_eq!(kp.security_level(), key_param.security_level());
+    Ok(())
+}
+
+/// Test storing a KeyParameter (with key parameter value which is of Vec<u8>) in the database
+#[test]
+fn test_to_sql_vec_u8() -> Result<()> {
+    let db = init_db()?;
+    let kp = KeyParameter::new(
+        KeyParameterValue::ApplicationID(String::from("MyAppID").into_bytes()),
+        SecurityLevel::STRONGBOX,
+    );
+    store_keyparameter(&db, 1, &kp)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(kp.get_tag(), key_param.get_tag());
+    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
+    assert_eq!(kp.security_level(), key_param.security_level());
+    Ok(())
+}
+
+/// Test storing a KeyParameter (with key parameter value which is of i32) in the database
+#[test]
+fn test_to_sql_bool() -> Result<()> {
+    let db = init_db()?;
+    let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
+    store_keyparameter(&db, 1, &kp)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(kp.get_tag(), key_param.get_tag());
+    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
+    assert_eq!(kp.security_level(), key_param.security_level());
+    Ok(())
+}
+
+#[test]
+/// Test Tag::Invalid
+fn test_invalid_tag() -> Result<()> {
+    let db = init_db()?;
+    insert_into_keyparameter(&db, 1, 0, &123, 1)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::INVALID, key_param.get_tag());
+    Ok(())
+}
+
+#[test]
+fn test_non_existing_enum_variant() -> Result<()> {
+    let db = init_db()?;
+    insert_into_keyparameter(&db, 1, 100, &123, 1)?;
+    let key_param = query_from_keyparameter(&db)?;
+    assert_eq!(Tag::INVALID, key_param.get_tag());
+    Ok(())
+}
+
+#[test]
+fn test_invalid_conversion_from_sql() -> Result<()> {
+    let db = init_db()?;
+    insert_into_keyparameter(&db, 1, Tag::ALGORITHM.0, &Null, 1)?;
+    tests::check_result_contains_error_string(
+        query_from_keyparameter(&db),
+        "Failed to read sql data for tag: ALGORITHM.",
+    );
+    Ok(())
+}
+
+/// Helper method to init database table for key parameter
+fn init_db() -> Result<Connection> {
+    let db = Connection::open_in_memory().context("Failed to initialize sqlite connection.")?;
+    db.execute("ATTACH DATABASE ? as 'persistent';", params![""])
+        .context("Failed to attach databases.")?;
+    db.execute(
+        "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
+                                keyentryid INTEGER,
+                                tag INTEGER,
+                                data ANY,
+                                security_level INTEGER);",
+        [],
+    )
+    .context("Failed to initialize \"keyparameter\" table.")?;
+    Ok(db)
+}
+
+/// Helper method to insert an entry into key parameter table, with individual parameters
+fn insert_into_keyparameter<T: ToSql>(
+    db: &Connection,
+    key_id: i64,
+    tag: i32,
+    value: &T,
+    security_level: i32,
+) -> Result<()> {
+    db.execute(
+        "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
+                VALUES(?, ?, ?, ?);",
+        params![key_id, tag, *value, security_level],
+    )?;
+    Ok(())
+}
+
+/// Helper method to store a key parameter instance.
+fn store_keyparameter(db: &Connection, key_id: i64, kp: &KeyParameter) -> Result<()> {
+    db.execute(
+        "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
+                VALUES(?, ?, ?, ?);",
+        params![key_id, kp.get_tag().0, kp.key_parameter_value(), kp.security_level().0],
+    )?;
+    Ok(())
+}
+
+/// Helper method to query a row from keyparameter table
+fn query_from_keyparameter(db: &Connection) -> Result<KeyParameter> {
+    let mut stmt = db.prepare("SELECT tag, data, security_level FROM persistent.keyparameter")?;
+    let mut rows = stmt.query([])?;
+    let row = rows.next()?.unwrap();
+    KeyParameter::new_from_sql(Tag(row.get(0)?), &SqlField::new(1, row), SecurityLevel(row.get(2)?))
+}
diff --git a/keystore2/src/key_parameter/wire_tests.rs b/keystore2/src/key_parameter/wire_tests.rs
new file mode 100644
index 00000000..278b7669
--- /dev/null
+++ b/keystore2/src/key_parameter/wire_tests.rs
@@ -0,0 +1,119 @@
+// Copyright 2020, The Android Open Source Project
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
+//! The wire_tests module tests the 'convert_to_wire' and 'convert_from_wire' methods for
+//! KeyParameter, for the four different types used in KmKeyParameter, in addition to Invalid
+//! key parameter.
+//! i) bool
+//! ii) integer
+//! iii) longInteger
+//! iv) blob
+
+use crate::key_parameter::*;
+/// unit tests for to conversions
+#[test]
+fn test_convert_to_wire_invalid() {
+    let kp = KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::STRONGBOX);
+    assert_eq!(
+        KmKeyParameter { tag: Tag::INVALID, value: KmKeyParameterValue::Invalid(0) },
+        kp.value.into()
+    );
+}
+#[test]
+fn test_convert_to_wire_bool() {
+    let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
+    assert_eq!(
+        KmKeyParameter { tag: Tag::CALLER_NONCE, value: KmKeyParameterValue::BoolValue(true) },
+        kp.value.into()
+    );
+}
+#[test]
+fn test_convert_to_wire_integer() {
+    let kp = KeyParameter::new(
+        KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
+        SecurityLevel::STRONGBOX,
+    );
+    assert_eq!(
+        KmKeyParameter {
+            tag: Tag::PURPOSE,
+            value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT)
+        },
+        kp.value.into()
+    );
+}
+#[test]
+fn test_convert_to_wire_long_integer() {
+    let kp = KeyParameter::new(KeyParameterValue::UserSecureID(i64::MAX), SecurityLevel::STRONGBOX);
+    assert_eq!(
+        KmKeyParameter {
+            tag: Tag::USER_SECURE_ID,
+            value: KmKeyParameterValue::LongInteger(i64::MAX)
+        },
+        kp.value.into()
+    );
+}
+#[test]
+fn test_convert_to_wire_blob() {
+    let kp = KeyParameter::new(
+        KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
+        SecurityLevel::STRONGBOX,
+    );
+    assert_eq!(
+        KmKeyParameter {
+            tag: Tag::CONFIRMATION_TOKEN,
+            value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes())
+        },
+        kp.value.into()
+    );
+}
+
+/// unit tests for from conversion
+#[test]
+fn test_convert_from_wire_invalid() {
+    let aidl_kp = KmKeyParameter { tag: Tag::INVALID, ..Default::default() };
+    assert_eq!(KeyParameterValue::Invalid, aidl_kp.into());
+}
+#[test]
+fn test_convert_from_wire_bool() {
+    let aidl_kp =
+        KmKeyParameter { tag: Tag::CALLER_NONCE, value: KmKeyParameterValue::BoolValue(true) };
+    assert_eq!(KeyParameterValue::CallerNonce, aidl_kp.into());
+}
+#[test]
+fn test_convert_from_wire_integer() {
+    let aidl_kp = KmKeyParameter {
+        tag: Tag::PURPOSE,
+        value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
+    };
+    assert_eq!(KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT), aidl_kp.into());
+}
+#[test]
+fn test_convert_from_wire_long_integer() {
+    let aidl_kp = KmKeyParameter {
+        tag: Tag::USER_SECURE_ID,
+        value: KmKeyParameterValue::LongInteger(i64::MAX),
+    };
+    assert_eq!(KeyParameterValue::UserSecureID(i64::MAX), aidl_kp.into());
+}
+#[test]
+fn test_convert_from_wire_blob() {
+    let aidl_kp = KmKeyParameter {
+        tag: Tag::CONFIRMATION_TOKEN,
+        value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes()),
+    };
+    assert_eq!(
+        KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
+        aidl_kp.into()
+    );
+}
diff --git a/keystore2/src/legacy_blob.rs b/keystore2/src/legacy_blob.rs
index 2bb7f27b..e05e6865 100644
--- a/keystore2/src/legacy_blob.rs
+++ b/keystore2/src/legacy_blob.rs
@@ -36,6 +36,9 @@ use std::{
 
 const SUPPORTED_LEGACY_BLOB_VERSION: u8 = 3;
 
+#[cfg(test)]
+mod tests;
+
 mod flags {
     /// This flag is deprecated. It is here to support keys that have been written with this flag
     /// set, but we don't create any new keys with this flag.
@@ -958,7 +961,7 @@ impl LegacyBlobLoader {
 
     fn make_user_path_name(&self, user_id: u32) -> PathBuf {
         let mut path = self.path.clone();
-        path.push(&format!("user_{}", user_id));
+        path.push(format!("user_{}", user_id));
         path
     }
 
@@ -1645,675 +1648,3 @@ pub mod test_utils {
         Ok(())
     }
 }
-
-#[cfg(test)]
-mod test {
-    #![allow(dead_code)]
-    use super::*;
-    use crate::legacy_blob::test_utils::legacy_blob_test_vectors::*;
-    use crate::legacy_blob::test_utils::*;
-    use anyhow::{anyhow, Result};
-    use keystore2_crypto::aes_gcm_decrypt;
-    use keystore2_test_utils::TempDir;
-    use rand::Rng;
-    use std::convert::TryInto;
-    use std::ops::Deref;
-    use std::string::FromUtf8Error;
-
-    #[test]
-    fn decode_encode_alias_test() {
-        static ALIAS: &str = "#({}test[])😗";
-        static ENCODED_ALIAS: &str = "+S+X{}test[]+Y.`-O-H-G";
-        // Second multi byte out of range ------v
-        static ENCODED_ALIAS_ERROR1: &str = "+S+{}test[]+Y";
-        // Incomplete multi byte ------------------------v
-        static ENCODED_ALIAS_ERROR2: &str = "+S+X{}test[]+";
-        // Our encoding: ".`-O-H-G"
-        // is UTF-8: 0xF0 0x9F 0x98 0x97
-        // is UNICODE: U+1F617
-        // is 😗
-        // But +H below is a valid encoding for 0x18 making this sequence invalid UTF-8.
-        static ENCODED_ALIAS_ERROR_UTF8: &str = ".`-O+H-G";
-
-        assert_eq!(ENCODED_ALIAS, &LegacyBlobLoader::encode_alias(ALIAS));
-        assert_eq!(ALIAS, &LegacyBlobLoader::decode_alias(ENCODED_ALIAS).unwrap());
-        assert_eq!(
-            Some(&Error::BadEncoding),
-            LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR1)
-                .unwrap_err()
-                .root_cause()
-                .downcast_ref::<Error>()
-        );
-        assert_eq!(
-            Some(&Error::BadEncoding),
-            LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR2)
-                .unwrap_err()
-                .root_cause()
-                .downcast_ref::<Error>()
-        );
-        assert!(LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR_UTF8)
-            .unwrap_err()
-            .root_cause()
-            .downcast_ref::<FromUtf8Error>()
-            .is_some());
-
-        for _i in 0..100 {
-            // Any valid UTF-8 string should be en- and decoded without loss.
-            let alias_str = rand::thread_rng().gen::<[char; 20]>().iter().collect::<String>();
-            let random_alias = alias_str.as_bytes();
-            let encoded = LegacyBlobLoader::encode_alias(&alias_str);
-            let decoded = match LegacyBlobLoader::decode_alias(&encoded) {
-                Ok(d) => d,
-                Err(_) => panic!("random_alias: {:x?}\nencoded {}", random_alias, encoded),
-            };
-            assert_eq!(random_alias.to_vec(), decoded.bytes().collect::<Vec<u8>>());
-        }
-    }
-
-    #[test]
-    fn read_golden_key_blob_test() -> anyhow::Result<()> {
-        let blob = LegacyBlobLoader::new_from_stream_decrypt_with(&mut &*BLOB, |_, _, _, _, _| {
-            Err(anyhow!("should not be called"))
-        })
-        .unwrap();
-        assert!(!blob.is_encrypted());
-        assert!(!blob.is_fallback());
-        assert!(!blob.is_strongbox());
-        assert!(!blob.is_critical_to_device_encryption());
-        assert_eq!(blob.value(), &BlobValue::Generic([0xde, 0xed, 0xbe, 0xef].to_vec()));
-
-        let blob = LegacyBlobLoader::new_from_stream_decrypt_with(
-            &mut &*REAL_LEGACY_BLOB,
-            |_, _, _, _, _| Err(anyhow!("should not be called")),
-        )
-        .unwrap();
-        assert!(!blob.is_encrypted());
-        assert!(!blob.is_fallback());
-        assert!(!blob.is_strongbox());
-        assert!(!blob.is_critical_to_device_encryption());
-        assert_eq!(
-            blob.value(),
-            &BlobValue::Decrypted(REAL_LEGACY_BLOB_PAYLOAD.try_into().unwrap())
-        );
-        Ok(())
-    }
-
-    #[test]
-    fn read_aes_gcm_encrypted_key_blob_test() {
-        let blob = LegacyBlobLoader::new_from_stream_decrypt_with(
-            &mut &*AES_GCM_ENCRYPTED_BLOB,
-            |d, iv, tag, salt, key_size| {
-                assert_eq!(salt, None);
-                assert_eq!(key_size, None);
-                assert_eq!(
-                    iv,
-                    &[
-                        0xbd, 0xdb, 0x8d, 0x69, 0x72, 0x56, 0xf0, 0xf5, 0xa4, 0x02, 0x88, 0x7f,
-                        0x00, 0x00, 0x00, 0x00,
-                    ]
-                );
-                assert_eq!(
-                    tag,
-                    &[
-                        0x50, 0xd9, 0x97, 0x95, 0x37, 0x6e, 0x28, 0x6a, 0x28, 0x9d, 0x51, 0xb9,
-                        0xb9, 0xe0, 0x0b, 0xc3
-                    ][..]
-                );
-                aes_gcm_decrypt(d, iv, tag, AES_KEY).context("Trying to decrypt blob.")
-            },
-        )
-        .unwrap();
-        assert!(blob.is_encrypted());
-        assert!(!blob.is_fallback());
-        assert!(!blob.is_strongbox());
-        assert!(!blob.is_critical_to_device_encryption());
-
-        assert_eq!(blob.value(), &BlobValue::Decrypted(DECRYPTED_PAYLOAD.try_into().unwrap()));
-    }
-
-    #[test]
-    fn read_golden_key_blob_too_short_test() {
-        let error =
-            LegacyBlobLoader::new_from_stream_decrypt_with(&mut &BLOB[0..15], |_, _, _, _, _| {
-                Err(anyhow!("should not be called"))
-            })
-            .unwrap_err();
-        assert_eq!(Some(&Error::BadLen), error.root_cause().downcast_ref::<Error>());
-    }
-
-    #[test]
-    fn test_is_empty() {
-        let temp_dir = TempDir::new("test_is_empty").expect("Failed to create temp dir.");
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty."));
-
-        let _db = crate::database::KeystoreDB::new(temp_dir.path(), None)
-            .expect("Failed to open database.");
-
-        assert!(legacy_blob_loader.is_empty().expect("Should succeed and still be empty."));
-
-        std::fs::create_dir(&*temp_dir.build().push("user_0")).expect("Failed to create user_0.");
-
-        assert!(!legacy_blob_loader.is_empty().expect("Should succeed but not be empty."));
-
-        std::fs::create_dir(&*temp_dir.build().push("user_10")).expect("Failed to create user_10.");
-
-        assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));
-
-        std::fs::remove_dir_all(&*temp_dir.build().push("user_0"))
-            .expect("Failed to remove user_0.");
-
-        assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));
-
-        std::fs::remove_dir_all(&*temp_dir.build().push("user_10"))
-            .expect("Failed to remove user_10.");
-
-        assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty again."));
-    }
-
-    #[test]
-    fn test_legacy_blobs() -> anyhow::Result<()> {
-        let temp_dir = TempDir::new("legacy_blob_test").unwrap();
-        std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
-
-        std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
-
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND_CHR,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
-            USRCERT_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
-            CACERT_AUTHBOUND,
-        )
-        .unwrap();
-
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRPKEY_non_authbound"),
-            USRPKEY_NON_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_non_authbound"),
-            USRPKEY_NON_AUTHBOUND_CHR,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRCERT_non_authbound"),
-            USRCERT_NON_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_CACERT_non_authbound"),
-            CACERT_NON_AUTHBOUND,
-        )
-        .unwrap();
-
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
-        {
-            assert_eq!(flags, 4);
-            assert_eq!(
-                value,
-                BlobValue::Encrypted {
-                    data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
-                    iv: USRPKEY_AUTHBOUND_IV.to_vec(),
-                    tag: USRPKEY_AUTHBOUND_TAG.to_vec()
-                }
-            );
-            assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
-            assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
-        } else {
-            panic!("");
-        }
-
-        if let (Some((Blob { flags, value: _ }, _params)), Some(cert), Some(chain)) =
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
-        {
-            assert_eq!(flags, 4);
-            //assert_eq!(value, BlobValue::Encrypted(..));
-            assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
-            assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
-        } else {
-            panic!("");
-        }
-        if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
-            legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", &None)?
-        {
-            assert_eq!(flags, 0);
-            assert_eq!(value, BlobValue::Decrypted(LOADED_USRPKEY_NON_AUTHBOUND.try_into()?));
-            assert_eq!(&cert[..], LOADED_CERT_NON_AUTHBOUND);
-            assert_eq!(&chain[..], LOADED_CACERT_NON_AUTHBOUND);
-        } else {
-            panic!("");
-        }
-
-        legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
-        legacy_blob_loader
-            .remove_keystore_entry(10223, "non_authbound")
-            .expect("This should succeed.");
-
-        assert_eq!(
-            (None, None, None),
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
-        );
-        assert_eq!(
-            (None, None, None),
-            legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", &None)?
-        );
-
-        // The database should not be empty due to the super key.
-        assert!(!legacy_blob_loader.is_empty()?);
-        assert!(!legacy_blob_loader.is_empty_user(0)?);
-
-        // The database should be considered empty for user 1.
-        assert!(legacy_blob_loader.is_empty_user(1)?);
-
-        legacy_blob_loader.remove_super_key(0);
-
-        // Now it should be empty.
-        assert!(legacy_blob_loader.is_empty_user(0)?);
-        assert!(legacy_blob_loader.is_empty()?);
-
-        Ok(())
-    }
-
-    struct TestKey(ZVec);
-
-    impl crate::utils::AesGcmKey for TestKey {
-        fn key(&self) -> &[u8] {
-            &self.0
-        }
-    }
-
-    impl Deref for TestKey {
-        type Target = [u8];
-        fn deref(&self) -> &Self::Target {
-            &self.0
-        }
-    }
-
-    #[test]
-    fn test_with_encrypted_characteristics() -> anyhow::Result<()> {
-        let temp_dir = TempDir::new("test_with_encrypted_characteristics").unwrap();
-        std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
-
-        let pw: Password = PASSWORD.into();
-        let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
-        let super_key =
-            Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));
-
-        std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
-
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND,
-        )
-        .unwrap();
-        make_encrypted_characteristics_file(
-            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
-            &super_key,
-            KEY_PARAMETERS,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
-            USRCERT_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
-            CACERT_AUTHBOUND,
-        )
-        .unwrap();
-
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        assert_eq!(
-            legacy_blob_loader
-                .load_by_uid_alias(10223, "authbound", &None)
-                .unwrap_err()
-                .root_cause()
-                .downcast_ref::<Error>(),
-            Some(&Error::LockedComponent)
-        );
-
-        assert_eq!(
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &Some(super_key)).unwrap(),
-            (
-                Some((
-                    Blob {
-                        flags: 4,
-                        value: BlobValue::Encrypted {
-                            data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
-                            iv: USRPKEY_AUTHBOUND_IV.to_vec(),
-                            tag: USRPKEY_AUTHBOUND_TAG.to_vec()
-                        }
-                    },
-                    structured_test_params()
-                )),
-                Some(LOADED_CERT_AUTHBOUND.to_vec()),
-                Some(LOADED_CACERT_AUTHBOUND.to_vec())
-            )
-        );
-
-        legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
-
-        assert_eq!(
-            (None, None, None),
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None).unwrap()
-        );
-
-        // The database should not be empty due to the super key.
-        assert!(!legacy_blob_loader.is_empty().unwrap());
-        assert!(!legacy_blob_loader.is_empty_user(0).unwrap());
-
-        // The database should be considered empty for user 1.
-        assert!(legacy_blob_loader.is_empty_user(1).unwrap());
-
-        legacy_blob_loader.remove_super_key(0);
-
-        // Now it should be empty.
-        assert!(legacy_blob_loader.is_empty_user(0).unwrap());
-        assert!(legacy_blob_loader.is_empty().unwrap());
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_with_encrypted_certificates() -> anyhow::Result<()> {
-        let temp_dir = TempDir::new("test_with_encrypted_certificates").unwrap();
-        std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
-
-        let pw: Password = PASSWORD.into();
-        let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
-        let super_key =
-            Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));
-
-        std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
-
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND_CHR,
-        )
-        .unwrap();
-        make_encrypted_usr_cert_file(
-            &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
-            &super_key,
-            LOADED_CERT_AUTHBOUND,
-        )
-        .unwrap();
-        make_encrypted_ca_cert_file(
-            &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
-            &super_key,
-            LOADED_CACERT_AUTHBOUND,
-        )
-        .unwrap();
-
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        assert_eq!(
-            legacy_blob_loader
-                .load_by_uid_alias(10223, "authbound", &None)
-                .unwrap_err()
-                .root_cause()
-                .downcast_ref::<Error>(),
-            Some(&Error::LockedComponent)
-        );
-
-        assert_eq!(
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &Some(super_key)).unwrap(),
-            (
-                Some((
-                    Blob {
-                        flags: 4,
-                        value: BlobValue::Encrypted {
-                            data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
-                            iv: USRPKEY_AUTHBOUND_IV.to_vec(),
-                            tag: USRPKEY_AUTHBOUND_TAG.to_vec()
-                        }
-                    },
-                    structured_test_params_cache()
-                )),
-                Some(LOADED_CERT_AUTHBOUND.to_vec()),
-                Some(LOADED_CACERT_AUTHBOUND.to_vec())
-            )
-        );
-
-        legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
-
-        assert_eq!(
-            (None, None, None),
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None).unwrap()
-        );
-
-        // The database should not be empty due to the super key.
-        assert!(!legacy_blob_loader.is_empty().unwrap());
-        assert!(!legacy_blob_loader.is_empty_user(0).unwrap());
-
-        // The database should be considered empty for user 1.
-        assert!(legacy_blob_loader.is_empty_user(1).unwrap());
-
-        legacy_blob_loader.remove_super_key(0);
-
-        // Now it should be empty.
-        assert!(legacy_blob_loader.is_empty_user(0).unwrap());
-        assert!(legacy_blob_loader.is_empty().unwrap());
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_in_place_key_migration() -> anyhow::Result<()> {
-        let temp_dir = TempDir::new("test_in_place_key_migration").unwrap();
-        std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
-
-        let pw: Password = PASSWORD.into();
-        let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
-        let super_key =
-            Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));
-
-        std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
-
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND,
-        )
-        .unwrap();
-        std::fs::write(
-            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
-            USRPKEY_AUTHBOUND_CHR,
-        )
-        .unwrap();
-        make_encrypted_usr_cert_file(
-            &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
-            &super_key,
-            LOADED_CERT_AUTHBOUND,
-        )
-        .unwrap();
-        make_encrypted_ca_cert_file(
-            &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
-            &super_key,
-            LOADED_CACERT_AUTHBOUND,
-        )
-        .unwrap();
-
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        assert_eq!(
-            legacy_blob_loader
-                .load_by_uid_alias(10223, "authbound", &None)
-                .unwrap_err()
-                .root_cause()
-                .downcast_ref::<Error>(),
-            Some(&Error::LockedComponent)
-        );
-
-        let super_key: Option<Arc<dyn AesGcm>> = Some(super_key);
-
-        assert_eq!(
-            legacy_blob_loader.load_by_uid_alias(10223, "authbound", &super_key).unwrap(),
-            (
-                Some((
-                    Blob {
-                        flags: 4,
-                        value: BlobValue::Encrypted {
-                            data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
-                            iv: USRPKEY_AUTHBOUND_IV.to_vec(),
-                            tag: USRPKEY_AUTHBOUND_TAG.to_vec()
-                        }
-                    },
-                    structured_test_params_cache()
-                )),
-                Some(LOADED_CERT_AUTHBOUND.to_vec()),
-                Some(LOADED_CACERT_AUTHBOUND.to_vec())
-            )
-        );
-
-        legacy_blob_loader.move_keystore_entry(10223, 10224, "authbound", "boundauth").unwrap();
-
-        assert_eq!(
-            legacy_blob_loader
-                .load_by_uid_alias(10224, "boundauth", &None)
-                .unwrap_err()
-                .root_cause()
-                .downcast_ref::<Error>(),
-            Some(&Error::LockedComponent)
-        );
-
-        assert_eq!(
-            legacy_blob_loader.load_by_uid_alias(10224, "boundauth", &super_key).unwrap(),
-            (
-                Some((
-                    Blob {
-                        flags: 4,
-                        value: BlobValue::Encrypted {
-                            data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
-                            iv: USRPKEY_AUTHBOUND_IV.to_vec(),
-                            tag: USRPKEY_AUTHBOUND_TAG.to_vec()
-                        }
-                    },
-                    structured_test_params_cache()
-                )),
-                Some(LOADED_CERT_AUTHBOUND.to_vec()),
-                Some(LOADED_CACERT_AUTHBOUND.to_vec())
-            )
-        );
-
-        legacy_blob_loader.remove_keystore_entry(10224, "boundauth").expect("This should succeed.");
-
-        assert_eq!(
-            (None, None, None),
-            legacy_blob_loader.load_by_uid_alias(10224, "boundauth", &None).unwrap()
-        );
-
-        // The database should not be empty due to the super key.
-        assert!(!legacy_blob_loader.is_empty().unwrap());
-        assert!(!legacy_blob_loader.is_empty_user(0).unwrap());
-
-        // The database should be considered empty for user 1.
-        assert!(legacy_blob_loader.is_empty_user(1).unwrap());
-
-        legacy_blob_loader.remove_super_key(0);
-
-        // Now it should be empty.
-        assert!(legacy_blob_loader.is_empty_user(0).unwrap());
-        assert!(legacy_blob_loader.is_empty().unwrap());
-
-        Ok(())
-    }
-
-    #[test]
-    fn list_non_existing_user() -> Result<()> {
-        let temp_dir = TempDir::new("list_non_existing_user").unwrap();
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        assert!(legacy_blob_loader.list_user(20)?.is_empty());
-
-        Ok(())
-    }
-
-    #[test]
-    fn list_legacy_keystore_entries_on_non_existing_user() -> Result<()> {
-        let temp_dir = TempDir::new("list_legacy_keystore_entries_on_non_existing_user").unwrap();
-        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
-
-        assert!(legacy_blob_loader.list_legacy_keystore_entries_for_user(20)?.is_empty());
-
-        Ok(())
-    }
-
-    #[test]
-    fn test_move_keystore_entry() {
-        let temp_dir = TempDir::new("test_move_keystore_entry").unwrap();
-        std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
-
-        const SOME_CONTENT: &[u8] = b"some content";
-        const ANOTHER_CONTENT: &[u8] = b"another content";
-        const SOME_FILENAME: &str = "some_file";
-        const ANOTHER_FILENAME: &str = "another_file";
-
-        std::fs::write(&*temp_dir.build().push("user_0").push(SOME_FILENAME), SOME_CONTENT)
-            .unwrap();
-
-        std::fs::write(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME), ANOTHER_CONTENT)
-            .unwrap();
-
-        // Non existent source id silently ignored.
-        assert!(LegacyBlobLoader::move_keystore_file_if_exists(
-            1,
-            2,
-            "non_existent",
-            ANOTHER_FILENAME,
-            "ignored",
-            |_, alias, _| temp_dir.build().push("user_0").push(alias).to_path_buf()
-        )
-        .is_ok());
-
-        // Content of another_file has not changed.
-        let another_content =
-            std::fs::read(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME)).unwrap();
-        assert_eq!(&another_content, ANOTHER_CONTENT);
-
-        // Check that some_file still exists.
-        assert!(temp_dir.build().push("user_0").push(SOME_FILENAME).exists());
-        // Existing target files are silently overwritten.
-
-        assert!(LegacyBlobLoader::move_keystore_file_if_exists(
-            1,
-            2,
-            SOME_FILENAME,
-            ANOTHER_FILENAME,
-            "ignored",
-            |_, alias, _| temp_dir.build().push("user_0").push(alias).to_path_buf()
-        )
-        .is_ok());
-
-        // Content of another_file is now "some content".
-        let another_content =
-            std::fs::read(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME)).unwrap();
-        assert_eq!(&another_content, SOME_CONTENT);
-
-        // Check that some_file no longer exists.
-        assert!(!temp_dir.build().push("user_0").push(SOME_FILENAME).exists());
-    }
-}
diff --git a/keystore2/src/legacy_blob/tests.rs b/keystore2/src/legacy_blob/tests.rs
new file mode 100644
index 00000000..53fe03ff
--- /dev/null
+++ b/keystore2/src/legacy_blob/tests.rs
@@ -0,0 +1,676 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Tests for legacy keyblob processing.
+
+#![allow(dead_code)]
+use super::*;
+use crate::legacy_blob::test_utils::legacy_blob_test_vectors::*;
+use crate::legacy_blob::test_utils::*;
+use anyhow::{anyhow, Result};
+use keystore2_crypto::aes_gcm_decrypt;
+use keystore2_test_utils::TempDir;
+use rand::Rng;
+use std::convert::TryInto;
+use std::ops::Deref;
+use std::string::FromUtf8Error;
+
+#[test]
+fn decode_encode_alias_test() {
+    static ALIAS: &str = "#({}test[])😗";
+    static ENCODED_ALIAS: &str = "+S+X{}test[]+Y.`-O-H-G";
+    // Second multi byte out of range ------v
+    static ENCODED_ALIAS_ERROR1: &str = "+S+{}test[]+Y";
+    // Incomplete multi byte ------------------------v
+    static ENCODED_ALIAS_ERROR2: &str = "+S+X{}test[]+";
+    // Our encoding: ".`-O-H-G"
+    // is UTF-8: 0xF0 0x9F 0x98 0x97
+    // is UNICODE: U+1F617
+    // is 😗
+    // But +H below is a valid encoding for 0x18 making this sequence invalid UTF-8.
+    static ENCODED_ALIAS_ERROR_UTF8: &str = ".`-O+H-G";
+
+    assert_eq!(ENCODED_ALIAS, &LegacyBlobLoader::encode_alias(ALIAS));
+    assert_eq!(ALIAS, &LegacyBlobLoader::decode_alias(ENCODED_ALIAS).unwrap());
+    assert_eq!(
+        Some(&Error::BadEncoding),
+        LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR1)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<Error>()
+    );
+    assert_eq!(
+        Some(&Error::BadEncoding),
+        LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR2)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<Error>()
+    );
+    assert!(LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR_UTF8)
+        .unwrap_err()
+        .root_cause()
+        .downcast_ref::<FromUtf8Error>()
+        .is_some());
+
+    for _i in 0..100 {
+        // Any valid UTF-8 string should be en- and decoded without loss.
+        let alias_str = rand::thread_rng().gen::<[char; 20]>().iter().collect::<String>();
+        let random_alias = alias_str.as_bytes();
+        let encoded = LegacyBlobLoader::encode_alias(&alias_str);
+        let decoded = match LegacyBlobLoader::decode_alias(&encoded) {
+            Ok(d) => d,
+            Err(_) => panic!("random_alias: {:x?}\nencoded {}", random_alias, encoded),
+        };
+        assert_eq!(random_alias.to_vec(), decoded.bytes().collect::<Vec<u8>>());
+    }
+}
+
+#[test]
+fn read_golden_key_blob_test() -> anyhow::Result<()> {
+    let blob = LegacyBlobLoader::new_from_stream_decrypt_with(&mut &*BLOB, |_, _, _, _, _| {
+        Err(anyhow!("should not be called"))
+    })
+    .unwrap();
+    assert!(!blob.is_encrypted());
+    assert!(!blob.is_fallback());
+    assert!(!blob.is_strongbox());
+    assert!(!blob.is_critical_to_device_encryption());
+    assert_eq!(blob.value(), &BlobValue::Generic([0xde, 0xed, 0xbe, 0xef].to_vec()));
+
+    let blob =
+        LegacyBlobLoader::new_from_stream_decrypt_with(&mut &*REAL_LEGACY_BLOB, |_, _, _, _, _| {
+            Err(anyhow!("should not be called"))
+        })
+        .unwrap();
+    assert!(!blob.is_encrypted());
+    assert!(!blob.is_fallback());
+    assert!(!blob.is_strongbox());
+    assert!(!blob.is_critical_to_device_encryption());
+    assert_eq!(blob.value(), &BlobValue::Decrypted(REAL_LEGACY_BLOB_PAYLOAD.try_into().unwrap()));
+    Ok(())
+}
+
+#[test]
+fn read_aes_gcm_encrypted_key_blob_test() {
+    let blob = LegacyBlobLoader::new_from_stream_decrypt_with(
+        &mut &*AES_GCM_ENCRYPTED_BLOB,
+        |d, iv, tag, salt, key_size| {
+            assert_eq!(salt, None);
+            assert_eq!(key_size, None);
+            assert_eq!(
+                iv,
+                &[
+                    0xbd, 0xdb, 0x8d, 0x69, 0x72, 0x56, 0xf0, 0xf5, 0xa4, 0x02, 0x88, 0x7f, 0x00,
+                    0x00, 0x00, 0x00,
+                ]
+            );
+            assert_eq!(
+                tag,
+                &[
+                    0x50, 0xd9, 0x97, 0x95, 0x37, 0x6e, 0x28, 0x6a, 0x28, 0x9d, 0x51, 0xb9, 0xb9,
+                    0xe0, 0x0b, 0xc3
+                ][..]
+            );
+            aes_gcm_decrypt(d, iv, tag, AES_KEY).context("Trying to decrypt blob.")
+        },
+    )
+    .unwrap();
+    assert!(blob.is_encrypted());
+    assert!(!blob.is_fallback());
+    assert!(!blob.is_strongbox());
+    assert!(!blob.is_critical_to_device_encryption());
+
+    assert_eq!(blob.value(), &BlobValue::Decrypted(DECRYPTED_PAYLOAD.try_into().unwrap()));
+}
+
+#[test]
+fn read_golden_key_blob_too_short_test() {
+    let error =
+        LegacyBlobLoader::new_from_stream_decrypt_with(&mut &BLOB[0..15], |_, _, _, _, _| {
+            Err(anyhow!("should not be called"))
+        })
+        .unwrap_err();
+    assert_eq!(Some(&Error::BadLen), error.root_cause().downcast_ref::<Error>());
+}
+
+#[test]
+fn test_is_empty() {
+    let temp_dir = TempDir::new("test_is_empty").expect("Failed to create temp dir.");
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty."));
+
+    let _db =
+        crate::database::KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database.");
+
+    assert!(legacy_blob_loader.is_empty().expect("Should succeed and still be empty."));
+
+    std::fs::create_dir(&*temp_dir.build().push("user_0")).expect("Failed to create user_0.");
+
+    assert!(!legacy_blob_loader.is_empty().expect("Should succeed but not be empty."));
+
+    std::fs::create_dir(&*temp_dir.build().push("user_10")).expect("Failed to create user_10.");
+
+    assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));
+
+    std::fs::remove_dir_all(&*temp_dir.build().push("user_0")).expect("Failed to remove user_0.");
+
+    assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));
+
+    std::fs::remove_dir_all(&*temp_dir.build().push("user_10")).expect("Failed to remove user_10.");
+
+    assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty again."));
+}
+
+#[test]
+fn test_legacy_blobs() -> anyhow::Result<()> {
+    let temp_dir = TempDir::new("legacy_blob_test").unwrap();
+    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
+
+    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
+
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND_CHR,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
+        USRCERT_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
+        CACERT_AUTHBOUND,
+    )
+    .unwrap();
+
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRPKEY_non_authbound"),
+        USRPKEY_NON_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_non_authbound"),
+        USRPKEY_NON_AUTHBOUND_CHR,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRCERT_non_authbound"),
+        USRCERT_NON_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_CACERT_non_authbound"),
+        CACERT_NON_AUTHBOUND,
+    )
+    .unwrap();
+
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
+    {
+        assert_eq!(flags, 4);
+        assert_eq!(
+            value,
+            BlobValue::Encrypted {
+                data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
+                iv: USRPKEY_AUTHBOUND_IV.to_vec(),
+                tag: USRPKEY_AUTHBOUND_TAG.to_vec()
+            }
+        );
+        assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
+        assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
+    } else {
+        panic!("");
+    }
+
+    if let (Some((Blob { flags, value: _ }, _params)), Some(cert), Some(chain)) =
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
+    {
+        assert_eq!(flags, 4);
+        //assert_eq!(value, BlobValue::Encrypted(..));
+        assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
+        assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
+    } else {
+        panic!("");
+    }
+    if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
+        legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", &None)?
+    {
+        assert_eq!(flags, 0);
+        assert_eq!(value, BlobValue::Decrypted(LOADED_USRPKEY_NON_AUTHBOUND.try_into()?));
+        assert_eq!(&cert[..], LOADED_CERT_NON_AUTHBOUND);
+        assert_eq!(&chain[..], LOADED_CACERT_NON_AUTHBOUND);
+    } else {
+        panic!("");
+    }
+
+    legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
+    legacy_blob_loader.remove_keystore_entry(10223, "non_authbound").expect("This should succeed.");
+
+    assert_eq!(
+        (None, None, None),
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
+    );
+    assert_eq!(
+        (None, None, None),
+        legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", &None)?
+    );
+
+    // The database should not be empty due to the super key.
+    assert!(!legacy_blob_loader.is_empty()?);
+    assert!(!legacy_blob_loader.is_empty_user(0)?);
+
+    // The database should be considered empty for user 1.
+    assert!(legacy_blob_loader.is_empty_user(1)?);
+
+    legacy_blob_loader.remove_super_key(0);
+
+    // Now it should be empty.
+    assert!(legacy_blob_loader.is_empty_user(0)?);
+    assert!(legacy_blob_loader.is_empty()?);
+
+    Ok(())
+}
+
+struct TestKey(ZVec);
+
+impl crate::utils::AesGcmKey for TestKey {
+    fn key(&self) -> &[u8] {
+        &self.0
+    }
+}
+
+impl Deref for TestKey {
+    type Target = [u8];
+    fn deref(&self) -> &Self::Target {
+        &self.0
+    }
+}
+
+#[test]
+fn test_with_encrypted_characteristics() -> anyhow::Result<()> {
+    let temp_dir = TempDir::new("test_with_encrypted_characteristics").unwrap();
+    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
+
+    let pw: Password = PASSWORD.into();
+    let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
+    let super_key =
+        Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));
+
+    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
+
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND,
+    )
+    .unwrap();
+    make_encrypted_characteristics_file(
+        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
+        &super_key,
+        KEY_PARAMETERS,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
+        USRCERT_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
+        CACERT_AUTHBOUND,
+    )
+    .unwrap();
+
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    assert_eq!(
+        legacy_blob_loader
+            .load_by_uid_alias(10223, "authbound", &None)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<Error>(),
+        Some(&Error::LockedComponent)
+    );
+
+    assert_eq!(
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &Some(super_key)).unwrap(),
+        (
+            Some((
+                Blob {
+                    flags: 4,
+                    value: BlobValue::Encrypted {
+                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
+                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
+                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
+                    }
+                },
+                structured_test_params()
+            )),
+            Some(LOADED_CERT_AUTHBOUND.to_vec()),
+            Some(LOADED_CACERT_AUTHBOUND.to_vec())
+        )
+    );
+
+    legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
+
+    assert_eq!(
+        (None, None, None),
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None).unwrap()
+    );
+
+    // The database should not be empty due to the super key.
+    assert!(!legacy_blob_loader.is_empty().unwrap());
+    assert!(!legacy_blob_loader.is_empty_user(0).unwrap());
+
+    // The database should be considered empty for user 1.
+    assert!(legacy_blob_loader.is_empty_user(1).unwrap());
+
+    legacy_blob_loader.remove_super_key(0);
+
+    // Now it should be empty.
+    assert!(legacy_blob_loader.is_empty_user(0).unwrap());
+    assert!(legacy_blob_loader.is_empty().unwrap());
+
+    Ok(())
+}
+
+#[test]
+fn test_with_encrypted_certificates() -> anyhow::Result<()> {
+    let temp_dir = TempDir::new("test_with_encrypted_certificates").unwrap();
+    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
+
+    let pw: Password = PASSWORD.into();
+    let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
+    let super_key =
+        Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));
+
+    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
+
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND_CHR,
+    )
+    .unwrap();
+    make_encrypted_usr_cert_file(
+        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
+        &super_key,
+        LOADED_CERT_AUTHBOUND,
+    )
+    .unwrap();
+    make_encrypted_ca_cert_file(
+        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
+        &super_key,
+        LOADED_CACERT_AUTHBOUND,
+    )
+    .unwrap();
+
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    assert_eq!(
+        legacy_blob_loader
+            .load_by_uid_alias(10223, "authbound", &None)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<Error>(),
+        Some(&Error::LockedComponent)
+    );
+
+    assert_eq!(
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &Some(super_key)).unwrap(),
+        (
+            Some((
+                Blob {
+                    flags: 4,
+                    value: BlobValue::Encrypted {
+                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
+                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
+                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
+                    }
+                },
+                structured_test_params_cache()
+            )),
+            Some(LOADED_CERT_AUTHBOUND.to_vec()),
+            Some(LOADED_CACERT_AUTHBOUND.to_vec())
+        )
+    );
+
+    legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
+
+    assert_eq!(
+        (None, None, None),
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None).unwrap()
+    );
+
+    // The database should not be empty due to the super key.
+    assert!(!legacy_blob_loader.is_empty().unwrap());
+    assert!(!legacy_blob_loader.is_empty_user(0).unwrap());
+
+    // The database should be considered empty for user 1.
+    assert!(legacy_blob_loader.is_empty_user(1).unwrap());
+
+    legacy_blob_loader.remove_super_key(0);
+
+    // Now it should be empty.
+    assert!(legacy_blob_loader.is_empty_user(0).unwrap());
+    assert!(legacy_blob_loader.is_empty().unwrap());
+
+    Ok(())
+}
+
+#[test]
+fn test_in_place_key_migration() -> anyhow::Result<()> {
+    let temp_dir = TempDir::new("test_in_place_key_migration").unwrap();
+    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
+
+    let pw: Password = PASSWORD.into();
+    let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
+    let super_key =
+        Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));
+
+    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();
+
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND,
+    )
+    .unwrap();
+    std::fs::write(
+        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
+        USRPKEY_AUTHBOUND_CHR,
+    )
+    .unwrap();
+    make_encrypted_usr_cert_file(
+        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
+        &super_key,
+        LOADED_CERT_AUTHBOUND,
+    )
+    .unwrap();
+    make_encrypted_ca_cert_file(
+        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
+        &super_key,
+        LOADED_CACERT_AUTHBOUND,
+    )
+    .unwrap();
+
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    assert_eq!(
+        legacy_blob_loader
+            .load_by_uid_alias(10223, "authbound", &None)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<Error>(),
+        Some(&Error::LockedComponent)
+    );
+
+    let super_key: Option<Arc<dyn AesGcm>> = Some(super_key);
+
+    assert_eq!(
+        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &super_key).unwrap(),
+        (
+            Some((
+                Blob {
+                    flags: 4,
+                    value: BlobValue::Encrypted {
+                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
+                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
+                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
+                    }
+                },
+                structured_test_params_cache()
+            )),
+            Some(LOADED_CERT_AUTHBOUND.to_vec()),
+            Some(LOADED_CACERT_AUTHBOUND.to_vec())
+        )
+    );
+
+    legacy_blob_loader.move_keystore_entry(10223, 10224, "authbound", "boundauth").unwrap();
+
+    assert_eq!(
+        legacy_blob_loader
+            .load_by_uid_alias(10224, "boundauth", &None)
+            .unwrap_err()
+            .root_cause()
+            .downcast_ref::<Error>(),
+        Some(&Error::LockedComponent)
+    );
+
+    assert_eq!(
+        legacy_blob_loader.load_by_uid_alias(10224, "boundauth", &super_key).unwrap(),
+        (
+            Some((
+                Blob {
+                    flags: 4,
+                    value: BlobValue::Encrypted {
+                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
+                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
+                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
+                    }
+                },
+                structured_test_params_cache()
+            )),
+            Some(LOADED_CERT_AUTHBOUND.to_vec()),
+            Some(LOADED_CACERT_AUTHBOUND.to_vec())
+        )
+    );
+
+    legacy_blob_loader.remove_keystore_entry(10224, "boundauth").expect("This should succeed.");
+
+    assert_eq!(
+        (None, None, None),
+        legacy_blob_loader.load_by_uid_alias(10224, "boundauth", &None).unwrap()
+    );
+
+    // The database should not be empty due to the super key.
+    assert!(!legacy_blob_loader.is_empty().unwrap());
+    assert!(!legacy_blob_loader.is_empty_user(0).unwrap());
+
+    // The database should be considered empty for user 1.
+    assert!(legacy_blob_loader.is_empty_user(1).unwrap());
+
+    legacy_blob_loader.remove_super_key(0);
+
+    // Now it should be empty.
+    assert!(legacy_blob_loader.is_empty_user(0).unwrap());
+    assert!(legacy_blob_loader.is_empty().unwrap());
+
+    Ok(())
+}
+
+#[test]
+fn list_non_existing_user() -> Result<()> {
+    let temp_dir = TempDir::new("list_non_existing_user").unwrap();
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    assert!(legacy_blob_loader.list_user(20)?.is_empty());
+
+    Ok(())
+}
+
+#[test]
+fn list_legacy_keystore_entries_on_non_existing_user() -> Result<()> {
+    let temp_dir = TempDir::new("list_legacy_keystore_entries_on_non_existing_user").unwrap();
+    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());
+
+    assert!(legacy_blob_loader.list_legacy_keystore_entries_for_user(20)?.is_empty());
+
+    Ok(())
+}
+
+#[test]
+fn test_move_keystore_entry() {
+    let temp_dir = TempDir::new("test_move_keystore_entry").unwrap();
+    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();
+
+    const SOME_CONTENT: &[u8] = b"some content";
+    const ANOTHER_CONTENT: &[u8] = b"another content";
+    const SOME_FILENAME: &str = "some_file";
+    const ANOTHER_FILENAME: &str = "another_file";
+
+    std::fs::write(&*temp_dir.build().push("user_0").push(SOME_FILENAME), SOME_CONTENT).unwrap();
+
+    std::fs::write(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME), ANOTHER_CONTENT)
+        .unwrap();
+
+    // Non existent source id silently ignored.
+    assert!(LegacyBlobLoader::move_keystore_file_if_exists(
+        1,
+        2,
+        "non_existent",
+        ANOTHER_FILENAME,
+        "ignored",
+        |_, alias, _| temp_dir.build().push("user_0").push(alias).to_path_buf()
+    )
+    .is_ok());
+
+    // Content of another_file has not changed.
+    let another_content =
+        std::fs::read(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME)).unwrap();
+    assert_eq!(&another_content, ANOTHER_CONTENT);
+
+    // Check that some_file still exists.
+    assert!(temp_dir.build().push("user_0").push(SOME_FILENAME).exists());
+    // Existing target files are silently overwritten.
+
+    assert!(LegacyBlobLoader::move_keystore_file_if_exists(
+        1,
+        2,
+        SOME_FILENAME,
+        ANOTHER_FILENAME,
+        "ignored",
+        |_, alias, _| temp_dir.build().push("user_0").push(alias).to_path_buf()
+    )
+    .is_ok());
+
+    // Content of another_file is now "some content".
+    let another_content =
+        std::fs::read(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME)).unwrap();
+    assert_eq!(&another_content, SOME_CONTENT);
+
+    // Check that some_file no longer exists.
+    assert!(!temp_dir.build().push("user_0").push(SOME_FILENAME).exists());
+}
diff --git a/keystore2/src/legacy_importer.rs b/keystore2/src/legacy_importer.rs
index f64af0b5..24f32637 100644
--- a/keystore2/src/legacy_importer.rs
+++ b/keystore2/src/legacy_importer.rs
@@ -923,11 +923,11 @@ fn get_key_characteristics_without_app_data(
         blob,
         &[],
         |blob| {
-            let _wd = wd::watch("Calling GetKeyCharacteristics.");
+            let _wd = wd::watch("get_key_characteristics_without_app_data: calling IKeyMintDevice::getKeyCharacteristics");
             map_km_error(km_dev.getKeyCharacteristics(blob, &[], &[]))
         },
         |_| Ok(()),
     )
-    .context(ks_err!())?;
+    .context(ks_err!("getKeyCharacteristics failed: possibly invalid keyblob for uuid {uuid:?}"))?;
     Ok((key_characteristics_to_internal(characteristics), upgraded_blob))
 }
diff --git a/keystore2/src/maintenance.rs b/keystore2/src/maintenance.rs
index ba92399b..4c895aed 100644
--- a/keystore2/src/maintenance.rs
+++ b/keystore2/src/maintenance.rs
@@ -22,13 +22,13 @@ use crate::globals::get_keymint_device;
 use crate::globals::{DB, LEGACY_IMPORTER, SUPER_KEY};
 use crate::ks_err;
 use crate::permission::{KeyPerm, KeystorePerm};
-use crate::super_key::{SuperKeyManager, UserState};
+use crate::super_key::SuperKeyManager;
 use crate::utils::{
-    check_get_app_uids_affected_by_sid_permissions, check_key_permission,
+    check_dump_permission, check_get_app_uids_affected_by_sid_permissions, check_key_permission,
     check_keystore_permission, uid_to_android_user, watchdog as wd,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
+    ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
 };
 use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::{
     BnKeystoreMaintenance, IKeystoreMaintenance,
@@ -36,6 +36,9 @@ use android_security_maintenance::aidl::android::security::maintenance::IKeystor
 use android_security_maintenance::binder::{
     BinderFeatures, Interface, Result as BinderResult, Strong, ThreadState,
 };
+use android_security_metrics::aidl::android::security::metrics::{
+    KeystoreAtomPayload::KeystoreAtomPayload::StorageStats
+};
 use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
 use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
 use anyhow::{Context, Result};
@@ -69,40 +72,6 @@ impl Maintenance {
         ))
     }
 
-    fn on_user_password_changed(user_id: i32, password: Option<Password>) -> Result<()> {
-        // Check permission. Function should return if this failed. Therefore having '?' at the end
-        // is very important.
-        check_keystore_permission(KeystorePerm::ChangePassword).context(ks_err!())?;
-
-        let mut skm = SUPER_KEY.write().unwrap();
-
-        if let Some(pw) = password.as_ref() {
-            DB.with(|db| {
-                skm.unlock_unlocked_device_required_keys(&mut db.borrow_mut(), user_id as u32, pw)
-            })
-            .context(ks_err!("unlock_unlocked_device_required_keys failed"))?;
-        }
-
-        if let UserState::BeforeFirstUnlock = DB
-            .with(|db| skm.get_user_state(&mut db.borrow_mut(), &LEGACY_IMPORTER, user_id as u32))
-            .context(ks_err!("Could not get user state while changing password!"))?
-        {
-            // Error - password can not be changed when the device is locked
-            return Err(Error::Rc(ResponseCode::LOCKED)).context(ks_err!("Device is locked."));
-        }
-
-        DB.with(|db| match password {
-            Some(pass) => {
-                skm.init_user(&mut db.borrow_mut(), &LEGACY_IMPORTER, user_id as u32, &pass)
-            }
-            None => {
-                // User transitioned to swipe.
-                skm.reset_user(&mut db.borrow_mut(), &LEGACY_IMPORTER, user_id as u32)
-            }
-        })
-        .context(ks_err!("Failed to change user password!"))
-    }
-
     fn add_or_remove_user(&self, user_id: i32) -> Result<()> {
         // Check permission. Function should return if this failed. Therefore having '?' at the end
         // is very important.
@@ -177,9 +146,7 @@ impl Maintenance {
         let (km_dev, _, _) =
             get_keymint_device(&sec_level).context(ks_err!("getting keymint device"))?;
 
-        let _wp = wd::watch_millis_with("In call_with_watchdog", 500, move || {
-            format!("Seclevel: {:?} Op: {}", sec_level, name)
-        });
+        let _wp = wd::watch_millis_with("Maintenance::call_with_watchdog", 500, (sec_level, name));
         map_km_error(op(km_dev)).with_context(|| ks_err!("calling {}", name))?;
         Ok(())
     }
@@ -200,12 +167,21 @@ impl Maintenance {
                     name,
                     &sec_level_string
                 ),
-                Err(ref e) => log::error!(
-                    "Call to {} failed for security level {}: {}.",
-                    name,
-                    &sec_level_string,
-                    e
-                ),
+                Err(ref e) => {
+                    if *sec_level == SecurityLevel::STRONGBOX
+                        && e.downcast_ref::<Error>()
+                            == Some(&Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
+                    {
+                        log::info!("Call to {} failed for StrongBox as it is not available", name,)
+                    } else {
+                        log::error!(
+                            "Call to {} failed for security level {}: {}.",
+                            name,
+                            &sec_level_string,
+                            e
+                        )
+                    }
+                }
             }
             curr_result
         })
@@ -291,22 +267,86 @@ impl Maintenance {
         DB.with(|db| db.borrow_mut().get_app_uids_affected_by_sid(user_id, secure_user_id))
             .context(ks_err!("Failed to get app UIDs affected by SID"))
     }
-}
 
-impl Interface for Maintenance {}
+    fn dump_state(&self, f: &mut dyn std::io::Write) -> std::io::Result<()> {
+        writeln!(f, "keystore2 running")?;
+        writeln!(f)?;
 
-impl IKeystoreMaintenance for Maintenance {
-    fn onUserPasswordChanged(&self, user_id: i32, password: Option<&[u8]>) -> BinderResult<()> {
-        log::info!(
-            "onUserPasswordChanged(user={}, password.is_some()={})",
-            user_id,
-            password.is_some()
-        );
-        let _wp = wd::watch("IKeystoreMaintenance::onUserPasswordChanged");
-        Self::on_user_password_changed(user_id, password.map(|pw| pw.into()))
-            .map_err(into_logged_binder)
+        // Display underlying device information
+        for sec_level in &[SecurityLevel::TRUSTED_ENVIRONMENT, SecurityLevel::STRONGBOX] {
+            let Ok((_dev, hw_info, uuid)) = get_keymint_device(sec_level) else { continue };
+
+            writeln!(f, "Device info for {sec_level:?} with {uuid:?}")?;
+            writeln!(f, "  HAL version:              {}", hw_info.versionNumber)?;
+            writeln!(f, "  Implementation name:      {}", hw_info.keyMintName)?;
+            writeln!(f, "  Implementation author:    {}", hw_info.keyMintAuthorName)?;
+            writeln!(f, "  Timestamp token required: {}", hw_info.timestampTokenRequired)?;
+        }
+        writeln!(f)?;
+
+        // Display database size information.
+        match crate::metrics_store::pull_storage_stats() {
+            Ok(atoms) => {
+                writeln!(f, "Database size information (in bytes):")?;
+                for atom in atoms {
+                    if let StorageStats(stats) = &atom.payload {
+                        let stype = format!("{:?}", stats.storage_type);
+                        if stats.unused_size == 0 {
+                            writeln!(f, "  {:<40}: {:>12}", stype, stats.size)?;
+                        } else {
+                            writeln!(
+                                f,
+                                "  {:<40}: {:>12} (unused {})",
+                                stype, stats.size, stats.unused_size
+                            )?;
+                        }
+                    }
+                }
+            }
+            Err(e) => {
+                writeln!(f, "Failed to retrieve storage stats: {e:?}")?;
+            }
+        }
+        writeln!(f)?;
+
+        // Display accumulated metrics.
+        writeln!(f, "Metrics information:")?;
+        writeln!(f)?;
+        write!(f, "{:?}", *crate::metrics_store::METRICS_STORE)?;
+        writeln!(f)?;
+
+        // Reminder: any additional information added to the `dump_state()` output needs to be
+        // careful not to include confidential information (e.g. key material).
+
+        Ok(())
     }
+}
 
+impl Interface for Maintenance {
+    fn dump(
+        &self,
+        f: &mut dyn std::io::Write,
+        _args: &[&std::ffi::CStr],
+    ) -> Result<(), binder::StatusCode> {
+        if !keystore2_flags::enable_dump() {
+            log::info!("skipping dump() as flag not enabled");
+            return Ok(());
+        }
+        log::info!("dump()");
+        let _wp = wd::watch("IKeystoreMaintenance::dump");
+        check_dump_permission().map_err(|_e| {
+            log::error!("dump permission denied");
+            binder::StatusCode::PERMISSION_DENIED
+        })?;
+
+        self.dump_state(f).map_err(|e| {
+            log::error!("dump_state failed: {e:?}");
+            binder::StatusCode::UNKNOWN_ERROR
+        })
+    }
+}
+
+impl IKeystoreMaintenance for Maintenance {
     fn onUserAdded(&self, user_id: i32) -> BinderResult<()> {
         log::info!("onUserAdded(user={user_id})");
         let _wp = wd::watch("IKeystoreMaintenance::onUserAdded");
@@ -360,7 +400,7 @@ impl IKeystoreMaintenance for Maintenance {
     }
 
     fn deleteAllKeys(&self) -> BinderResult<()> {
-        log::warn!("deleteAllKeys()");
+        log::warn!("deleteAllKeys() invoked, indicating initial setup or post-factory reset");
         let _wp = wd::watch("IKeystoreMaintenance::deleteAllKeys");
         Self::delete_all_keys().map_err(into_logged_binder)
     }
diff --git a/keystore2/src/metrics_store.rs b/keystore2/src/metrics_store.rs
index 5a76d04e..7149d128 100644
--- a/keystore2/src/metrics_store.rs
+++ b/keystore2/src/metrics_store.rs
@@ -44,18 +44,15 @@ use android_security_metrics::aidl::android::security::metrics::{
     SecurityLevel::SecurityLevel as MetricsSecurityLevel, Storage::Storage as MetricsStorage,
 };
 use anyhow::{anyhow, Context, Result};
-use lazy_static::lazy_static;
 use std::collections::HashMap;
-use std::sync::Mutex;
+use std::sync::{LazyLock, Mutex};
 
 // Note: Crash events are recorded at keystore restarts, based on the assumption that keystore only
 // gets restarted after a crash, during a boot cycle.
 const KEYSTORE_CRASH_COUNT_PROPERTY: &str = "keystore.crash_count";
 
-lazy_static! {
-    /// Singleton for MetricsStore.
-    pub static ref METRICS_STORE: MetricsStore = Default::default();
-}
+/// Singleton for MetricsStore.
+pub static METRICS_STORE: LazyLock<MetricsStore> = LazyLock::new(Default::default);
 
 /// MetricsStore stores the <atom object, count> as <key, value> in the inner hash map,
 /// indexed by the atom id, in the outer hash map.
@@ -72,6 +69,26 @@ pub struct MetricsStore {
     metrics_store: Mutex<HashMap<AtomID, HashMap<KeystoreAtomPayload, i32>>>,
 }
 
+impl std::fmt::Debug for MetricsStore {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
+        let store = self.metrics_store.lock().unwrap();
+        let mut atom_ids: Vec<&AtomID> = store.keys().collect();
+        atom_ids.sort();
+        for atom_id in atom_ids {
+            writeln!(f, "  {} : [", atom_id.show())?;
+            let data = store.get(atom_id).unwrap();
+            let mut payloads: Vec<&KeystoreAtomPayload> = data.keys().collect();
+            payloads.sort();
+            for payload in payloads {
+                let count = data.get(payload).unwrap();
+                writeln!(f, "    {} => count={count}", payload.show())?;
+            }
+            writeln!(f, "  ]")?;
+        }
+        Ok(())
+    }
+}
+
 impl MetricsStore {
     /// There are some atoms whose maximum cardinality exceeds the cardinality limits tolerated
     /// by statsd. Statsd tolerates cardinality between 200-300. Therefore, the in-memory storage
@@ -85,7 +102,7 @@ impl MetricsStore {
     /// empty vector.
     pub fn get_atoms(&self, atom_id: AtomID) -> Result<Vec<KeystoreAtom>> {
         // StorageStats is an original pulled atom (i.e. not a pushed atom converted to a
-        // pulledd atom). Therefore, it is handled separately.
+        // pulled atom). Therefore, it is handled separately.
         if AtomID::STORAGE_STATS == atom_id {
             return pull_storage_stats();
         }
@@ -519,7 +536,7 @@ fn compute_purpose_bitmap(purpose_bitmap: &mut i32, purpose: KeyPurpose) {
     }
 }
 
-fn pull_storage_stats() -> Result<Vec<KeystoreAtom>> {
+pub(crate) fn pull_storage_stats() -> Result<Vec<KeystoreAtom>> {
     let mut atom_vec: Vec<KeystoreAtom> = Vec::new();
     let mut append = |stat| {
         match stat {
@@ -680,3 +697,309 @@ enum KeyPurposeBitPosition {
     ///Bit position in the KeyPurpose bitmap for Attest Key.
     ATTEST_KEY_BIT_POS = 7,
 }
+
+/// The various metrics-related types are not defined in this crate, so the orphan
+/// trait rule means that `std::fmt::Debug` cannot be implemented for them.
+/// Instead, create our own local trait that generates a debug string for a type.
+trait Summary {
+    fn show(&self) -> String;
+}
+
+/// Implement the [`Summary`] trait for AIDL-derived pseudo-enums, mapping named enum values to
+/// specified short names, all padded with spaces to the specified width (to allow improved
+/// readability when printed in a group).
+macro_rules! impl_summary_enum {
+    {  $enum:ident, $width:literal, $( $variant:ident => $short:literal ),+ $(,)? } => {
+        impl Summary for $enum{
+            fn show(&self) -> String {
+                match self.0 {
+                    $(
+                        x if x == Self::$variant.0 => format!(concat!("{:",
+                                                                      stringify!($width),
+                                                                      "}"),
+                                                              $short),
+                    )*
+                    v => format!("Unknown({})", v),
+                }
+            }
+        }
+    }
+}
+
+impl_summary_enum!(AtomID, 14,
+    STORAGE_STATS => "STORAGE",
+    KEYSTORE2_ATOM_WITH_OVERFLOW => "OVERFLOW",
+    KEY_CREATION_WITH_GENERAL_INFO => "KEYGEN_GENERAL",
+    KEY_CREATION_WITH_AUTH_INFO => "KEYGEN_AUTH",
+    KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO => "KEYGEN_MODES",
+    KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO => "KEYOP_MODES",
+    KEY_OPERATION_WITH_GENERAL_INFO => "KEYOP_GENERAL",
+    RKP_ERROR_STATS => "RKP_ERR",
+    CRASH_STATS => "CRASH",
+);
+
+impl_summary_enum!(MetricsStorage, 28,
+    STORAGE_UNSPECIFIED => "UNSPECIFIED",
+    KEY_ENTRY => "KEY_ENTRY",
+    KEY_ENTRY_ID_INDEX => "KEY_ENTRY_ID_IDX" ,
+    KEY_ENTRY_DOMAIN_NAMESPACE_INDEX => "KEY_ENTRY_DOMAIN_NS_IDX" ,
+    BLOB_ENTRY => "BLOB_ENTRY",
+    BLOB_ENTRY_KEY_ENTRY_ID_INDEX => "BLOB_ENTRY_KEY_ENTRY_ID_IDX" ,
+    KEY_PARAMETER => "KEY_PARAMETER",
+    KEY_PARAMETER_KEY_ENTRY_ID_INDEX => "KEY_PARAM_KEY_ENTRY_ID_IDX" ,
+    KEY_METADATA => "KEY_METADATA",
+    KEY_METADATA_KEY_ENTRY_ID_INDEX => "KEY_META_KEY_ENTRY_ID_IDX" ,
+    GRANT => "GRANT",
+    AUTH_TOKEN => "AUTH_TOKEN",
+    BLOB_METADATA => "BLOB_METADATA",
+    BLOB_METADATA_BLOB_ENTRY_ID_INDEX => "BLOB_META_BLOB_ENTRY_ID_IDX" ,
+    METADATA => "METADATA",
+    DATABASE => "DATABASE",
+    LEGACY_STORAGE => "LEGACY_STORAGE",
+);
+
+impl_summary_enum!(MetricsAlgorithm, 4,
+    ALGORITHM_UNSPECIFIED => "NONE",
+    RSA => "RSA",
+    EC => "EC",
+    AES => "AES",
+    TRIPLE_DES => "DES",
+    HMAC => "HMAC",
+);
+
+impl_summary_enum!(MetricsEcCurve, 5,
+    EC_CURVE_UNSPECIFIED => "NONE",
+    P_224 => "P-224",
+    P_256 => "P-256",
+    P_384 => "P-384",
+    P_521 => "P-521",
+    CURVE_25519 => "25519",
+);
+
+impl_summary_enum!(MetricsKeyOrigin, 10,
+    ORIGIN_UNSPECIFIED => "UNSPEC",
+    GENERATED => "GENERATED",
+    DERIVED => "DERIVED",
+    IMPORTED => "IMPORTED",
+    RESERVED => "RESERVED",
+    SECURELY_IMPORTED => "SEC-IMPORT",
+);
+
+impl_summary_enum!(MetricsSecurityLevel, 9,
+    SECURITY_LEVEL_UNSPECIFIED => "UNSPEC",
+    SECURITY_LEVEL_SOFTWARE => "SOFTWARE",
+    SECURITY_LEVEL_TRUSTED_ENVIRONMENT => "TEE",
+    SECURITY_LEVEL_STRONGBOX => "STRONGBOX",
+    SECURITY_LEVEL_KEYSTORE => "KEYSTORE",
+);
+
+// Metrics values for HardwareAuthenticatorType are broken -- the AIDL type is a bitmask
+// not an enum, so offseting the enum values by 1 doesn't work.
+impl_summary_enum!(MetricsHardwareAuthenticatorType, 6,
+    AUTH_TYPE_UNSPECIFIED => "UNSPEC",
+    NONE => "NONE",
+    PASSWORD => "PASSWD",
+    FINGERPRINT => "FPRINT",
+    ANY => "ANY",
+);
+
+impl_summary_enum!(MetricsPurpose, 7,
+    KEY_PURPOSE_UNSPECIFIED => "UNSPEC",
+    ENCRYPT => "ENCRYPT",
+    DECRYPT => "DECRYPT",
+    SIGN => "SIGN",
+    VERIFY => "VERIFY",
+    WRAP_KEY => "WRAPKEY",
+    AGREE_KEY => "AGREEKY",
+    ATTEST_KEY => "ATTESTK",
+);
+
+impl_summary_enum!(MetricsOutcome, 7,
+    OUTCOME_UNSPECIFIED => "UNSPEC",
+    DROPPED => "DROPPED",
+    SUCCESS => "SUCCESS",
+    ABORT => "ABORT",
+    PRUNED => "PRUNED",
+    ERROR => "ERROR",
+);
+
+impl_summary_enum!(MetricsRkpError, 6,
+    RKP_ERROR_UNSPECIFIED => "UNSPEC",
+    OUT_OF_KEYS => "OOKEYS",
+    FALL_BACK_DURING_HYBRID => "FALLBK",
+);
+
+/// Convert an argument into a corresponding format clause.  (This is needed because
+/// macro expansion text for repeated inputs needs to mention one of the repeated
+/// inputs.)
+macro_rules! format_clause {
+    {  $ignored:ident } => { "{}" }
+}
+
+/// Generate code to print a string corresponding to a bitmask, where the given
+/// enum identifies which bits mean what.  If additional bits (not included in
+/// the enum variants) are set, include the whole bitmask in the output so no
+/// information is lost.
+macro_rules! show_enum_bitmask {
+    {  $v:expr, $enum:ident, $( $variant:ident => $short:literal ),+ $(,)? } => {
+        {
+            let v: i32 = $v;
+            let mut displayed_mask = 0i32;
+            $(
+                displayed_mask |= 1 << $enum::$variant as i32;
+            )*
+            let undisplayed_mask = !displayed_mask;
+            let undisplayed = v & undisplayed_mask;
+            let extra = if undisplayed == 0 {
+                "".to_string()
+            } else {
+                format!("(full:{v:#010x})")
+            };
+            format!(
+                concat!( $( format_clause!($variant), )* "{}"),
+                $(
+                    if v & 1 << $enum::$variant as i32 != 0 { $short } else { "-" },
+                )*
+                extra
+            )
+        }
+    }
+}
+
+fn show_purpose(v: i32) -> String {
+    show_enum_bitmask!(v, KeyPurposeBitPosition,
+        ATTEST_KEY_BIT_POS => "A",
+        AGREE_KEY_BIT_POS => "G",
+        WRAP_KEY_BIT_POS => "W",
+        VERIFY_BIT_POS => "V",
+        SIGN_BIT_POS => "S",
+        DECRYPT_BIT_POS => "D",
+        ENCRYPT_BIT_POS => "E",
+    )
+}
+
+fn show_padding(v: i32) -> String {
+    show_enum_bitmask!(v, PaddingModeBitPosition,
+        PKCS7_BIT_POS => "7",
+        RSA_PKCS1_1_5_SIGN_BIT_POS => "S",
+        RSA_PKCS1_1_5_ENCRYPT_BIT_POS => "E",
+        RSA_PSS_BIT_POS => "P",
+        RSA_OAEP_BIT_POS => "O",
+        NONE_BIT_POSITION => "N",
+    )
+}
+
+fn show_digest(v: i32) -> String {
+    show_enum_bitmask!(v, DigestBitPosition,
+        SHA_2_512_BIT_POS => "5",
+        SHA_2_384_BIT_POS => "3",
+        SHA_2_256_BIT_POS => "2",
+        SHA_2_224_BIT_POS => "4",
+        SHA_1_BIT_POS => "1",
+        MD5_BIT_POS => "M",
+        NONE_BIT_POSITION => "N",
+    )
+}
+
+fn show_blockmode(v: i32) -> String {
+    show_enum_bitmask!(v, BlockModeBitPosition,
+        GCM_BIT_POS => "G",
+        CTR_BIT_POS => "T",
+        CBC_BIT_POS => "C",
+        ECB_BIT_POS => "E",
+    )
+}
+
+impl Summary for KeystoreAtomPayload {
+    fn show(&self) -> String {
+        match self {
+            KeystoreAtomPayload::StorageStats(v) => {
+                format!("{} sz={} unused={}", v.storage_type.show(), v.size, v.unused_size)
+            }
+            KeystoreAtomPayload::KeyCreationWithGeneralInfo(v) => {
+                format!(
+                    "{} ksz={:>4} crv={} {} rc={:4} attest? {}",
+                    v.algorithm.show(),
+                    v.key_size,
+                    v.ec_curve.show(),
+                    v.key_origin.show(),
+                    v.error_code,
+                    if v.attestation_requested { "Y" } else { "N" }
+                )
+            }
+            KeystoreAtomPayload::KeyCreationWithAuthInfo(v) => {
+                format!(
+                    "auth={} log(time)={:3} sec={}",
+                    v.user_auth_type.show(),
+                    v.log10_auth_key_timeout_seconds,
+                    v.security_level.show()
+                )
+            }
+            KeystoreAtomPayload::KeyCreationWithPurposeAndModesInfo(v) => {
+                format!(
+                    "{} purpose={} padding={} digest={} blockmode={}",
+                    v.algorithm.show(),
+                    show_purpose(v.purpose_bitmap),
+                    show_padding(v.padding_mode_bitmap),
+                    show_digest(v.digest_bitmap),
+                    show_blockmode(v.block_mode_bitmap),
+                )
+            }
+            KeystoreAtomPayload::KeyOperationWithGeneralInfo(v) => {
+                format!(
+                    "{} {:>8} upgraded? {} sec={}",
+                    v.outcome.show(),
+                    v.error_code,
+                    if v.key_upgraded { "Y" } else { "N" },
+                    v.security_level.show()
+                )
+            }
+            KeystoreAtomPayload::KeyOperationWithPurposeAndModesInfo(v) => {
+                format!(
+                    "{} padding={} digest={} blockmode={}",
+                    v.purpose.show(),
+                    show_padding(v.padding_mode_bitmap),
+                    show_digest(v.digest_bitmap),
+                    show_blockmode(v.block_mode_bitmap)
+                )
+            }
+            KeystoreAtomPayload::RkpErrorStats(v) => {
+                format!("{} sec={}", v.rkpError.show(), v.security_level.show())
+            }
+            KeystoreAtomPayload::CrashStats(v) => {
+                format!("count={}", v.count_of_crash_events)
+            }
+            KeystoreAtomPayload::Keystore2AtomWithOverflow(v) => {
+                format!("atom={}", v.atom_id.show())
+            }
+        }
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_enum_show() {
+        let algo = MetricsAlgorithm::RSA;
+        assert_eq!("RSA ", algo.show());
+        let algo = MetricsAlgorithm(42);
+        assert_eq!("Unknown(42)", algo.show());
+    }
+
+    #[test]
+    fn test_enum_bitmask_show() {
+        let mut modes = 0i32;
+        compute_block_mode_bitmap(&mut modes, BlockMode::ECB);
+        compute_block_mode_bitmap(&mut modes, BlockMode::CTR);
+
+        assert_eq!(show_blockmode(modes), "-T-E");
+
+        // Add some bits not covered by the enum of valid bit positions.
+        modes |= 0xa0;
+        assert_eq!(show_blockmode(modes), "-T-E(full:0x000000aa)");
+        modes |= 0x300;
+        assert_eq!(show_blockmode(modes), "-T-E(full:0x000003aa)");
+    }
+}
diff --git a/keystore2/src/operation.rs b/keystore2/src/operation.rs
index 7d988e1a..9ae8ccfc 100644
--- a/keystore2/src/operation.rs
+++ b/keystore2/src/operation.rs
@@ -31,6 +31,7 @@
 //!  * `abort` is called.
 //!  * The operation gets dropped.
 //!  * The operation gets pruned.
+//!
 //! `Operation` has an `Outcome` member. While the outcome is `Outcome::Unknown`,
 //! the operation is active and in a good state. Any of the above conditions may
 //! change the outcome to one of the defined outcomes Success, Abort, Dropped,
@@ -286,7 +287,7 @@ impl Operation {
         }
         *locked_outcome = Outcome::Pruned;
 
-        let _wp = wd::watch("In Operation::prune: calling abort()");
+        let _wp = wd::watch("Operation::prune: calling IKeyMintOperation::abort()");
 
         // We abort the operation. If there was an error we log it but ignore it.
         if let Err(e) = map_km_error(self.km_op.abort()) {
@@ -362,7 +363,7 @@ impl Operation {
             .context(ks_err!("Trying to get auth tokens."))?;
 
         self.update_outcome(&mut outcome, {
-            let _wp = wd::watch("Operation::update_aad: calling updateAad");
+            let _wp = wd::watch("Operation::update_aad: calling IKeyMintOperation::updateAad");
             map_km_error(self.km_op.updateAad(aad_input, hat.as_ref(), tst.as_ref()))
         })
         .context(ks_err!("Update failed."))?;
@@ -386,7 +387,7 @@ impl Operation {
 
         let output = self
             .update_outcome(&mut outcome, {
-                let _wp = wd::watch("Operation::update: calling update");
+                let _wp = wd::watch("Operation::update: calling IKeyMintOperation::update");
                 map_km_error(self.km_op.update(input, hat.as_ref(), tst.as_ref()))
             })
             .context(ks_err!("Update failed."))?;
@@ -416,7 +417,7 @@ impl Operation {
 
         let output = self
             .update_outcome(&mut outcome, {
-                let _wp = wd::watch("Operation::finish: calling finish");
+                let _wp = wd::watch("Operation::finish: calling IKeyMintOperation::finish");
                 map_km_error(self.km_op.finish(
                     input,
                     signature,
@@ -447,7 +448,7 @@ impl Operation {
         *locked_outcome = outcome;
 
         {
-            let _wp = wd::watch("Operation::abort: calling abort");
+            let _wp = wd::watch("Operation::abort: calling IKeyMintOperation::abort");
             map_km_error(self.km_op.abort()).context(ks_err!("KeyMint::abort failed."))
         }
     }
diff --git a/keystore2/src/permission.rs b/keystore2/src/permission.rs
index 982bc821..7bf17b59 100644
--- a/keystore2/src/permission.rs
+++ b/keystore2/src/permission.rs
@@ -26,11 +26,11 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 };
 use anyhow::Context as AnyhowContext;
 use keystore2_selinux as selinux;
-use lazy_static::lazy_static;
 use selinux::{implement_class, Backend, ClassPermission};
 use std::cmp::PartialEq;
 use std::convert::From;
 use std::ffi::CStr;
+use std::sync::LazyLock;
 
 // Replace getcon with a mock in the test situation
 #[cfg(not(test))]
@@ -38,12 +38,13 @@ use selinux::getcon;
 #[cfg(test)]
 use tests::test_getcon as getcon;
 
-lazy_static! {
-    // Panicking here is allowed because keystore cannot function without this backend
-    // and it would happen early and indicate a gross misconfiguration of the device.
-    static ref KEYSTORE2_KEY_LABEL_BACKEND: selinux::KeystoreKeyBackend =
-            selinux::KeystoreKeyBackend::new().unwrap();
-}
+#[cfg(test)]
+mod tests;
+
+// Panicking here is allowed because keystore cannot function without this backend
+// and it would happen early and indicate a gross misconfiguration of the device.
+static KEYSTORE2_KEY_LABEL_BACKEND: LazyLock<selinux::KeystoreKeyBackend> =
+    LazyLock::new(|| selinux::KeystoreKeyBackend::new().unwrap());
 
 fn lookup_keystore2_key_context(namespace: i64) -> anyhow::Result<selinux::Context> {
     KEYSTORE2_KEY_LABEL_BACKEND.lookup(&namespace.to_string())
@@ -397,433 +398,3 @@ pub fn check_key_permission(
 
     selinux::check_permission(caller_ctx, &target_context, perm)
 }
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use anyhow::anyhow;
-    use anyhow::Result;
-    use keystore2_selinux::*;
-
-    const ALL_PERMS: KeyPermSet = key_perm_set![
-        KeyPerm::ManageBlob,
-        KeyPerm::Delete,
-        KeyPerm::UseDevId,
-        KeyPerm::ReqForcedOp,
-        KeyPerm::GenUniqueId,
-        KeyPerm::Grant,
-        KeyPerm::GetInfo,
-        KeyPerm::Rebind,
-        KeyPerm::Update,
-        KeyPerm::Use,
-        KeyPerm::ConvertStorageKeyToEphemeral,
-    ];
-
-    const SYSTEM_SERVER_PERMISSIONS_NO_GRANT: KeyPermSet = key_perm_set![
-        KeyPerm::Delete,
-        KeyPerm::UseDevId,
-        // No KeyPerm::Grant
-        KeyPerm::GetInfo,
-        KeyPerm::Rebind,
-        KeyPerm::Update,
-        KeyPerm::Use,
-    ];
-
-    const NOT_GRANT_PERMS: KeyPermSet = key_perm_set![
-        KeyPerm::ManageBlob,
-        KeyPerm::Delete,
-        KeyPerm::UseDevId,
-        KeyPerm::ReqForcedOp,
-        KeyPerm::GenUniqueId,
-        // No KeyPerm::Grant
-        KeyPerm::GetInfo,
-        KeyPerm::Rebind,
-        KeyPerm::Update,
-        KeyPerm::Use,
-        KeyPerm::ConvertStorageKeyToEphemeral,
-    ];
-
-    const UNPRIV_PERMS: KeyPermSet = key_perm_set![
-        KeyPerm::Delete,
-        KeyPerm::GetInfo,
-        KeyPerm::Rebind,
-        KeyPerm::Update,
-        KeyPerm::Use,
-    ];
-
-    /// The su_key namespace as defined in su.te and keystore_key_contexts of the
-    /// SePolicy (system/sepolicy).
-    const SU_KEY_NAMESPACE: i32 = 0;
-    /// The shell_key namespace as defined in shell.te and keystore_key_contexts of the
-    /// SePolicy (system/sepolicy).
-    const SHELL_KEY_NAMESPACE: i32 = 1;
-
-    pub fn test_getcon() -> Result<Context> {
-        Context::new("u:object_r:keystore:s0")
-    }
-
-    // This macro evaluates the given expression and checks that
-    // a) evaluated to Result::Err() and that
-    // b) the wrapped error is selinux::Error::perm() (permission denied).
-    // We use a macro here because a function would mask which invocation caused the failure.
-    //
-    // TODO b/164121720 Replace this macro with a function when `track_caller` is available.
-    macro_rules! assert_perm_failed {
-        ($test_function:expr) => {
-            let result = $test_function;
-            assert!(result.is_err(), "Permission check should have failed.");
-            assert_eq!(
-                Some(&selinux::Error::perm()),
-                result.err().unwrap().root_cause().downcast_ref::<selinux::Error>()
-            );
-        };
-    }
-
-    fn check_context() -> Result<(selinux::Context, i32, bool)> {
-        // Calling the non mocked selinux::getcon here intended.
-        let context = selinux::getcon()?;
-        match context.to_str().unwrap() {
-            "u:r:su:s0" => Ok((context, SU_KEY_NAMESPACE, true)),
-            "u:r:shell:s0" => Ok((context, SHELL_KEY_NAMESPACE, false)),
-            c => Err(anyhow!(format!(
-                "This test must be run as \"su\" or \"shell\". Current context: \"{}\"",
-                c
-            ))),
-        }
-    }
-
-    #[test]
-    fn check_keystore_permission_test() -> Result<()> {
-        let system_server_ctx = Context::new("u:r:system_server:s0")?;
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::AddAuth).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ClearNs).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Lock).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Reset).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Unlock).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ChangeUser).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ChangePassword).is_ok());
-        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ClearUID).is_ok());
-        let shell_ctx = Context::new("u:r:shell:s0")?;
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::AddAuth));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ClearNs));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::List));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Lock));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Reset));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Unlock));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ChangeUser));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ChangePassword));
-        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ClearUID));
-        Ok(())
-    }
-
-    #[test]
-    fn check_grant_permission_app() -> Result<()> {
-        let system_server_ctx = Context::new("u:r:system_server:s0")?;
-        let shell_ctx = Context::new("u:r:shell:s0")?;
-        let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
-        check_grant_permission(&system_server_ctx, SYSTEM_SERVER_PERMISSIONS_NO_GRANT, &key)
-            .expect("Grant permission check failed.");
-
-        // attempts to grant the grant permission must always fail even when privileged.
-        assert_perm_failed!(check_grant_permission(
-            &system_server_ctx,
-            KeyPerm::Grant.into(),
-            &key
-        ));
-        // unprivileged grant attempts always fail. shell does not have the grant permission.
-        assert_perm_failed!(check_grant_permission(&shell_ctx, UNPRIV_PERMS, &key));
-        Ok(())
-    }
-
-    #[test]
-    fn check_grant_permission_selinux() -> Result<()> {
-        let (sctx, namespace, is_su) = check_context()?;
-        let key = KeyDescriptor {
-            domain: Domain::SELINUX,
-            nspace: namespace as i64,
-            alias: None,
-            blob: None,
-        };
-        if is_su {
-            assert!(check_grant_permission(&sctx, NOT_GRANT_PERMS, &key).is_ok());
-            // attempts to grant the grant permission must always fail even when privileged.
-            assert_perm_failed!(check_grant_permission(&sctx, KeyPerm::Grant.into(), &key));
-        } else {
-            // unprivileged grant attempts always fail. shell does not have the grant permission.
-            assert_perm_failed!(check_grant_permission(&sctx, UNPRIV_PERMS, &key));
-        }
-        Ok(())
-    }
-
-    #[test]
-    fn check_key_permission_domain_grant() -> Result<()> {
-        let key = KeyDescriptor { domain: Domain::GRANT, nspace: 0, alias: None, blob: None };
-
-        assert_perm_failed!(check_key_permission(
-            0,
-            &selinux::Context::new("ignored").unwrap(),
-            KeyPerm::Grant,
-            &key,
-            &Some(UNPRIV_PERMS)
-        ));
-
-        check_key_permission(
-            0,
-            &selinux::Context::new("ignored").unwrap(),
-            KeyPerm::Use,
-            &key,
-            &Some(ALL_PERMS),
-        )
-    }
-
-    #[test]
-    fn check_key_permission_domain_app() -> Result<()> {
-        let system_server_ctx = Context::new("u:r:system_server:s0")?;
-        let shell_ctx = Context::new("u:r:shell:s0")?;
-        let gmscore_app = Context::new("u:r:gmscore_app:s0")?;
-
-        let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
-
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Use, &key, &None).is_ok());
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Delete, &key, &None).is_ok());
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Rebind, &key, &None).is_ok());
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Update, &key, &None).is_ok());
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Grant, &key, &None).is_ok());
-        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::UseDevId, &key, &None).is_ok());
-        assert!(check_key_permission(0, &gmscore_app, KeyPerm::GenUniqueId, &key, &None).is_ok());
-
-        assert!(check_key_permission(0, &shell_ctx, KeyPerm::Use, &key, &None).is_ok());
-        assert!(check_key_permission(0, &shell_ctx, KeyPerm::Delete, &key, &None).is_ok());
-        assert!(check_key_permission(0, &shell_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
-        assert!(check_key_permission(0, &shell_ctx, KeyPerm::Rebind, &key, &None).is_ok());
-        assert!(check_key_permission(0, &shell_ctx, KeyPerm::Update, &key, &None).is_ok());
-        assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::Grant, &key, &None));
-        assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ReqForcedOp, &key, &None));
-        assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ManageBlob, &key, &None));
-        assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::UseDevId, &key, &None));
-        assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::GenUniqueId, &key, &None));
-
-        // Also make sure that the permission fails if the caller is not the owner.
-        assert_perm_failed!(check_key_permission(
-            1, // the owner is 0
-            &system_server_ctx,
-            KeyPerm::Use,
-            &key,
-            &None
-        ));
-        // Unless there was a grant.
-        assert!(check_key_permission(
-            1,
-            &system_server_ctx,
-            KeyPerm::Use,
-            &key,
-            &Some(key_perm_set![KeyPerm::Use])
-        )
-        .is_ok());
-        // But fail if the grant did not cover the requested permission.
-        assert_perm_failed!(check_key_permission(
-            1,
-            &system_server_ctx,
-            KeyPerm::Use,
-            &key,
-            &Some(key_perm_set![KeyPerm::GetInfo])
-        ));
-
-        Ok(())
-    }
-
-    #[test]
-    fn check_key_permission_domain_selinux() -> Result<()> {
-        let (sctx, namespace, is_su) = check_context()?;
-        let key = KeyDescriptor {
-            domain: Domain::SELINUX,
-            nspace: namespace as i64,
-            alias: None,
-            blob: None,
-        };
-
-        assert!(check_key_permission(0, &sctx, KeyPerm::Use, &key, &None).is_ok());
-        assert!(check_key_permission(0, &sctx, KeyPerm::Delete, &key, &None).is_ok());
-        assert!(check_key_permission(0, &sctx, KeyPerm::GetInfo, &key, &None).is_ok());
-        assert!(check_key_permission(0, &sctx, KeyPerm::Rebind, &key, &None).is_ok());
-        assert!(check_key_permission(0, &sctx, KeyPerm::Update, &key, &None).is_ok());
-
-        if is_su {
-            assert!(check_key_permission(0, &sctx, KeyPerm::Grant, &key, &None).is_ok());
-            assert!(check_key_permission(0, &sctx, KeyPerm::ManageBlob, &key, &None).is_ok());
-            assert!(check_key_permission(0, &sctx, KeyPerm::UseDevId, &key, &None).is_ok());
-            assert!(check_key_permission(0, &sctx, KeyPerm::GenUniqueId, &key, &None).is_ok());
-            assert!(check_key_permission(0, &sctx, KeyPerm::ReqForcedOp, &key, &None).is_ok());
-        } else {
-            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::Grant, &key, &None));
-            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::ReqForcedOp, &key, &None));
-            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::ManageBlob, &key, &None));
-            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::UseDevId, &key, &None));
-            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::GenUniqueId, &key, &None));
-        }
-        Ok(())
-    }
-
-    #[test]
-    fn check_key_permission_domain_blob() -> Result<()> {
-        let (sctx, namespace, is_su) = check_context()?;
-        let key = KeyDescriptor {
-            domain: Domain::BLOB,
-            nspace: namespace as i64,
-            alias: None,
-            blob: None,
-        };
-
-        if is_su {
-            check_key_permission(0, &sctx, KeyPerm::Use, &key, &None)
-        } else {
-            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::Use, &key, &None));
-            Ok(())
-        }
-    }
-
-    #[test]
-    fn check_key_permission_domain_key_id() -> Result<()> {
-        let key = KeyDescriptor { domain: Domain::KEY_ID, nspace: 0, alias: None, blob: None };
-
-        assert_eq!(
-            Some(&KsError::sys()),
-            check_key_permission(
-                0,
-                &selinux::Context::new("ignored").unwrap(),
-                KeyPerm::Use,
-                &key,
-                &None
-            )
-            .err()
-            .unwrap()
-            .root_cause()
-            .downcast_ref::<KsError>()
-        );
-        Ok(())
-    }
-
-    #[test]
-    fn key_perm_set_all_test() {
-        let v = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::UseDevId,
-            KeyPerm::ReqForcedOp,
-            KeyPerm::GenUniqueId,
-            KeyPerm::Grant,
-            KeyPerm::GetInfo,
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use // Test if the macro accepts missing comma at the end of the list.
-        ];
-        let mut i = v.into_iter();
-        assert_eq!(i.next().unwrap().name(), "delete");
-        assert_eq!(i.next().unwrap().name(), "gen_unique_id");
-        assert_eq!(i.next().unwrap().name(), "get_info");
-        assert_eq!(i.next().unwrap().name(), "grant");
-        assert_eq!(i.next().unwrap().name(), "manage_blob");
-        assert_eq!(i.next().unwrap().name(), "rebind");
-        assert_eq!(i.next().unwrap().name(), "req_forced_op");
-        assert_eq!(i.next().unwrap().name(), "update");
-        assert_eq!(i.next().unwrap().name(), "use");
-        assert_eq!(i.next().unwrap().name(), "use_dev_id");
-        assert_eq!(None, i.next());
-    }
-    #[test]
-    fn key_perm_set_sparse_test() {
-        let v = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::ReqForcedOp,
-            KeyPerm::GenUniqueId,
-            KeyPerm::Update,
-            KeyPerm::Use, // Test if macro accepts the comma at the end of the list.
-        ];
-        let mut i = v.into_iter();
-        assert_eq!(i.next().unwrap().name(), "gen_unique_id");
-        assert_eq!(i.next().unwrap().name(), "manage_blob");
-        assert_eq!(i.next().unwrap().name(), "req_forced_op");
-        assert_eq!(i.next().unwrap().name(), "update");
-        assert_eq!(i.next().unwrap().name(), "use");
-        assert_eq!(None, i.next());
-    }
-    #[test]
-    fn key_perm_set_empty_test() {
-        let v = key_perm_set![];
-        let mut i = v.into_iter();
-        assert_eq!(None, i.next());
-    }
-    #[test]
-    fn key_perm_set_include_subset_test() {
-        let v1 = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::UseDevId,
-            KeyPerm::ReqForcedOp,
-            KeyPerm::GenUniqueId,
-            KeyPerm::Grant,
-            KeyPerm::GetInfo,
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use,
-        ];
-        let v2 = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use,
-        ];
-        assert!(v1.includes(v2));
-        assert!(!v2.includes(v1));
-    }
-    #[test]
-    fn key_perm_set_include_equal_test() {
-        let v1 = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use,
-        ];
-        let v2 = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use,
-        ];
-        assert!(v1.includes(v2));
-        assert!(v2.includes(v1));
-    }
-    #[test]
-    fn key_perm_set_include_overlap_test() {
-        let v1 = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::Grant, // only in v1
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use,
-        ];
-        let v2 = key_perm_set![
-            KeyPerm::ManageBlob,
-            KeyPerm::Delete,
-            KeyPerm::ReqForcedOp, // only in v2
-            KeyPerm::Rebind,
-            KeyPerm::Update,
-            KeyPerm::Use,
-        ];
-        assert!(!v1.includes(v2));
-        assert!(!v2.includes(v1));
-    }
-    #[test]
-    fn key_perm_set_include_no_overlap_test() {
-        let v1 = key_perm_set![KeyPerm::ManageBlob, KeyPerm::Delete, KeyPerm::Grant,];
-        let v2 =
-            key_perm_set![KeyPerm::ReqForcedOp, KeyPerm::Rebind, KeyPerm::Update, KeyPerm::Use,];
-        assert!(!v1.includes(v2));
-        assert!(!v2.includes(v1));
-    }
-}
diff --git a/keystore2/src/permission/tests.rs b/keystore2/src/permission/tests.rs
new file mode 100644
index 00000000..f555c12c
--- /dev/null
+++ b/keystore2/src/permission/tests.rs
@@ -0,0 +1,434 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Access control tests.
+
+use super::*;
+use crate::key_perm_set;
+use anyhow::anyhow;
+use anyhow::Result;
+use keystore2_selinux::*;
+
+const ALL_PERMS: KeyPermSet = key_perm_set![
+    KeyPerm::ManageBlob,
+    KeyPerm::Delete,
+    KeyPerm::UseDevId,
+    KeyPerm::ReqForcedOp,
+    KeyPerm::GenUniqueId,
+    KeyPerm::Grant,
+    KeyPerm::GetInfo,
+    KeyPerm::Rebind,
+    KeyPerm::Update,
+    KeyPerm::Use,
+    KeyPerm::ConvertStorageKeyToEphemeral,
+];
+
+const SYSTEM_SERVER_PERMISSIONS_NO_GRANT: KeyPermSet = key_perm_set![
+    KeyPerm::Delete,
+    KeyPerm::UseDevId,
+    // No KeyPerm::Grant
+    KeyPerm::GetInfo,
+    KeyPerm::Rebind,
+    KeyPerm::Update,
+    KeyPerm::Use,
+];
+
+const NOT_GRANT_PERMS: KeyPermSet = key_perm_set![
+    KeyPerm::ManageBlob,
+    KeyPerm::Delete,
+    KeyPerm::UseDevId,
+    KeyPerm::ReqForcedOp,
+    KeyPerm::GenUniqueId,
+    // No KeyPerm::Grant
+    KeyPerm::GetInfo,
+    KeyPerm::Rebind,
+    KeyPerm::Update,
+    KeyPerm::Use,
+    KeyPerm::ConvertStorageKeyToEphemeral,
+];
+
+const UNPRIV_PERMS: KeyPermSet = key_perm_set![
+    KeyPerm::Delete,
+    KeyPerm::GetInfo,
+    KeyPerm::Rebind,
+    KeyPerm::Update,
+    KeyPerm::Use,
+];
+
+/// The su_key namespace as defined in su.te and keystore_key_contexts of the
+/// SePolicy (system/sepolicy).
+const SU_KEY_NAMESPACE: i32 = 0;
+/// The shell_key namespace as defined in shell.te and keystore_key_contexts of the
+/// SePolicy (system/sepolicy).
+const SHELL_KEY_NAMESPACE: i32 = 1;
+
+pub fn test_getcon() -> Result<Context> {
+    Context::new("u:object_r:keystore:s0")
+}
+
+// This macro evaluates the given expression and checks that
+// a) evaluated to Result::Err() and that
+// b) the wrapped error is selinux::Error::perm() (permission denied).
+// We use a macro here because a function would mask which invocation caused the failure.
+//
+// TODO b/164121720 Replace this macro with a function when `track_caller` is available.
+macro_rules! assert_perm_failed {
+    ($test_function:expr) => {
+        let result = $test_function;
+        assert!(result.is_err(), "Permission check should have failed.");
+        assert_eq!(
+            Some(&selinux::Error::perm()),
+            result.err().unwrap().root_cause().downcast_ref::<selinux::Error>()
+        );
+    };
+}
+
+fn check_context() -> Result<(selinux::Context, i32, bool)> {
+    // Calling the non mocked selinux::getcon here intended.
+    let context = selinux::getcon()?;
+    match context.to_str().unwrap() {
+        "u:r:su:s0" => Ok((context, SU_KEY_NAMESPACE, true)),
+        "u:r:shell:s0" => Ok((context, SHELL_KEY_NAMESPACE, false)),
+        c => Err(anyhow!(format!(
+            "This test must be run as \"su\" or \"shell\". Current context: \"{}\"",
+            c
+        ))),
+    }
+}
+
+#[test]
+fn check_keystore_permission_test() -> Result<()> {
+    let system_server_ctx = Context::new("u:r:system_server:s0")?;
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::AddAuth).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ClearNs).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Lock).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Reset).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Unlock).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ChangeUser).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ChangePassword).is_ok());
+    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ClearUID).is_ok());
+    let shell_ctx = Context::new("u:r:shell:s0")?;
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::AddAuth));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ClearNs));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::List));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Lock));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Reset));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Unlock));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ChangeUser));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ChangePassword));
+    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ClearUID));
+    Ok(())
+}
+
+#[test]
+fn check_grant_permission_app() -> Result<()> {
+    let system_server_ctx = Context::new("u:r:system_server:s0")?;
+    let shell_ctx = Context::new("u:r:shell:s0")?;
+    let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
+    check_grant_permission(&system_server_ctx, SYSTEM_SERVER_PERMISSIONS_NO_GRANT, &key)
+        .expect("Grant permission check failed.");
+
+    // attempts to grant the grant permission must always fail even when privileged.
+    assert_perm_failed!(check_grant_permission(&system_server_ctx, KeyPerm::Grant.into(), &key));
+    // unprivileged grant attempts always fail. shell does not have the grant permission.
+    assert_perm_failed!(check_grant_permission(&shell_ctx, UNPRIV_PERMS, &key));
+    Ok(())
+}
+
+#[test]
+fn check_grant_permission_selinux() -> Result<()> {
+    let (sctx, namespace, is_su) = check_context()?;
+    let key = KeyDescriptor {
+        domain: Domain::SELINUX,
+        nspace: namespace as i64,
+        alias: None,
+        blob: None,
+    };
+    if is_su {
+        assert!(check_grant_permission(&sctx, NOT_GRANT_PERMS, &key).is_ok());
+        // attempts to grant the grant permission must always fail even when privileged.
+        assert_perm_failed!(check_grant_permission(&sctx, KeyPerm::Grant.into(), &key));
+    } else {
+        // unprivileged grant attempts always fail. shell does not have the grant permission.
+        assert_perm_failed!(check_grant_permission(&sctx, UNPRIV_PERMS, &key));
+    }
+    Ok(())
+}
+
+#[test]
+fn check_key_permission_domain_grant() -> Result<()> {
+    let key = KeyDescriptor { domain: Domain::GRANT, nspace: 0, alias: None, blob: None };
+
+    assert_perm_failed!(check_key_permission(
+        0,
+        &selinux::Context::new("ignored").unwrap(),
+        KeyPerm::Grant,
+        &key,
+        &Some(UNPRIV_PERMS)
+    ));
+
+    check_key_permission(
+        0,
+        &selinux::Context::new("ignored").unwrap(),
+        KeyPerm::Use,
+        &key,
+        &Some(ALL_PERMS),
+    )
+}
+
+#[test]
+fn check_key_permission_domain_app() -> Result<()> {
+    let system_server_ctx = Context::new("u:r:system_server:s0")?;
+    let shell_ctx = Context::new("u:r:shell:s0")?;
+    let gmscore_app = Context::new("u:r:gmscore_app:s0")?;
+
+    let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
+
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Use, &key, &None).is_ok());
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Delete, &key, &None).is_ok());
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Rebind, &key, &None).is_ok());
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Update, &key, &None).is_ok());
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Grant, &key, &None).is_ok());
+    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::UseDevId, &key, &None).is_ok());
+    assert!(check_key_permission(0, &gmscore_app, KeyPerm::GenUniqueId, &key, &None).is_ok());
+
+    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Use, &key, &None).is_ok());
+    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Delete, &key, &None).is_ok());
+    assert!(check_key_permission(0, &shell_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
+    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Rebind, &key, &None).is_ok());
+    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Update, &key, &None).is_ok());
+    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::Grant, &key, &None));
+    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ReqForcedOp, &key, &None));
+    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ManageBlob, &key, &None));
+    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::UseDevId, &key, &None));
+    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::GenUniqueId, &key, &None));
+
+    // Also make sure that the permission fails if the caller is not the owner.
+    assert_perm_failed!(check_key_permission(
+        1, // the owner is 0
+        &system_server_ctx,
+        KeyPerm::Use,
+        &key,
+        &None
+    ));
+    // Unless there was a grant.
+    assert!(check_key_permission(
+        1,
+        &system_server_ctx,
+        KeyPerm::Use,
+        &key,
+        &Some(key_perm_set![KeyPerm::Use])
+    )
+    .is_ok());
+    // But fail if the grant did not cover the requested permission.
+    assert_perm_failed!(check_key_permission(
+        1,
+        &system_server_ctx,
+        KeyPerm::Use,
+        &key,
+        &Some(key_perm_set![KeyPerm::GetInfo])
+    ));
+
+    Ok(())
+}
+
+#[test]
+fn check_key_permission_domain_selinux() -> Result<()> {
+    let (sctx, namespace, is_su) = check_context()?;
+    let key = KeyDescriptor {
+        domain: Domain::SELINUX,
+        nspace: namespace as i64,
+        alias: None,
+        blob: None,
+    };
+
+    assert!(check_key_permission(0, &sctx, KeyPerm::Use, &key, &None).is_ok());
+    assert!(check_key_permission(0, &sctx, KeyPerm::Delete, &key, &None).is_ok());
+    assert!(check_key_permission(0, &sctx, KeyPerm::GetInfo, &key, &None).is_ok());
+    assert!(check_key_permission(0, &sctx, KeyPerm::Rebind, &key, &None).is_ok());
+    assert!(check_key_permission(0, &sctx, KeyPerm::Update, &key, &None).is_ok());
+
+    if is_su {
+        assert!(check_key_permission(0, &sctx, KeyPerm::Grant, &key, &None).is_ok());
+        assert!(check_key_permission(0, &sctx, KeyPerm::ManageBlob, &key, &None).is_ok());
+        assert!(check_key_permission(0, &sctx, KeyPerm::UseDevId, &key, &None).is_ok());
+        assert!(check_key_permission(0, &sctx, KeyPerm::GenUniqueId, &key, &None).is_ok());
+        assert!(check_key_permission(0, &sctx, KeyPerm::ReqForcedOp, &key, &None).is_ok());
+    } else {
+        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::Grant, &key, &None));
+        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::ReqForcedOp, &key, &None));
+        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::ManageBlob, &key, &None));
+        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::UseDevId, &key, &None));
+        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::GenUniqueId, &key, &None));
+    }
+    Ok(())
+}
+
+#[test]
+fn check_key_permission_domain_blob() -> Result<()> {
+    let (sctx, namespace, is_su) = check_context()?;
+    let key =
+        KeyDescriptor { domain: Domain::BLOB, nspace: namespace as i64, alias: None, blob: None };
+
+    if is_su {
+        check_key_permission(0, &sctx, KeyPerm::Use, &key, &None)
+    } else {
+        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::Use, &key, &None));
+        Ok(())
+    }
+}
+
+#[test]
+fn check_key_permission_domain_key_id() -> Result<()> {
+    let key = KeyDescriptor { domain: Domain::KEY_ID, nspace: 0, alias: None, blob: None };
+
+    assert_eq!(
+        Some(&KsError::sys()),
+        check_key_permission(
+            0,
+            &selinux::Context::new("ignored").unwrap(),
+            KeyPerm::Use,
+            &key,
+            &None
+        )
+        .err()
+        .unwrap()
+        .root_cause()
+        .downcast_ref::<KsError>()
+    );
+    Ok(())
+}
+
+#[test]
+fn key_perm_set_all_test() {
+    let v = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::UseDevId,
+        KeyPerm::ReqForcedOp,
+        KeyPerm::GenUniqueId,
+        KeyPerm::Grant,
+        KeyPerm::GetInfo,
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use // Test if the macro accepts missing comma at the end of the list.
+    ];
+    let mut i = v.into_iter();
+    assert_eq!(i.next().unwrap().name(), "delete");
+    assert_eq!(i.next().unwrap().name(), "gen_unique_id");
+    assert_eq!(i.next().unwrap().name(), "get_info");
+    assert_eq!(i.next().unwrap().name(), "grant");
+    assert_eq!(i.next().unwrap().name(), "manage_blob");
+    assert_eq!(i.next().unwrap().name(), "rebind");
+    assert_eq!(i.next().unwrap().name(), "req_forced_op");
+    assert_eq!(i.next().unwrap().name(), "update");
+    assert_eq!(i.next().unwrap().name(), "use");
+    assert_eq!(i.next().unwrap().name(), "use_dev_id");
+    assert_eq!(None, i.next());
+}
+#[test]
+fn key_perm_set_sparse_test() {
+    let v = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::ReqForcedOp,
+        KeyPerm::GenUniqueId,
+        KeyPerm::Update,
+        KeyPerm::Use, // Test if macro accepts the comma at the end of the list.
+    ];
+    let mut i = v.into_iter();
+    assert_eq!(i.next().unwrap().name(), "gen_unique_id");
+    assert_eq!(i.next().unwrap().name(), "manage_blob");
+    assert_eq!(i.next().unwrap().name(), "req_forced_op");
+    assert_eq!(i.next().unwrap().name(), "update");
+    assert_eq!(i.next().unwrap().name(), "use");
+    assert_eq!(None, i.next());
+}
+#[test]
+fn key_perm_set_empty_test() {
+    let v = key_perm_set![];
+    let mut i = v.into_iter();
+    assert_eq!(None, i.next());
+}
+#[test]
+fn key_perm_set_include_subset_test() {
+    let v1 = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::UseDevId,
+        KeyPerm::ReqForcedOp,
+        KeyPerm::GenUniqueId,
+        KeyPerm::Grant,
+        KeyPerm::GetInfo,
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use,
+    ];
+    let v2 = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use,
+    ];
+    assert!(v1.includes(v2));
+    assert!(!v2.includes(v1));
+}
+#[test]
+fn key_perm_set_include_equal_test() {
+    let v1 = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use,
+    ];
+    let v2 = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use,
+    ];
+    assert!(v1.includes(v2));
+    assert!(v2.includes(v1));
+}
+#[test]
+fn key_perm_set_include_overlap_test() {
+    let v1 = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::Grant, // only in v1
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use,
+    ];
+    let v2 = key_perm_set![
+        KeyPerm::ManageBlob,
+        KeyPerm::Delete,
+        KeyPerm::ReqForcedOp, // only in v2
+        KeyPerm::Rebind,
+        KeyPerm::Update,
+        KeyPerm::Use,
+    ];
+    assert!(!v1.includes(v2));
+    assert!(!v2.includes(v1));
+}
+#[test]
+fn key_perm_set_include_no_overlap_test() {
+    let v1 = key_perm_set![KeyPerm::ManageBlob, KeyPerm::Delete, KeyPerm::Grant,];
+    let v2 = key_perm_set![KeyPerm::ReqForcedOp, KeyPerm::Rebind, KeyPerm::Update, KeyPerm::Use,];
+    assert!(!v1.includes(v2));
+    assert!(!v2.includes(v1));
+}
diff --git a/keystore2/src/raw_device.rs b/keystore2/src/raw_device.rs
index a8a88d25..bf1149c1 100644
--- a/keystore2/src/raw_device.rs
+++ b/keystore2/src/raw_device.rs
@@ -212,8 +212,8 @@ impl KeyMintDevice {
                         |key_blob| {
                             map_km_error({
                                 let _wp = wd::watch(concat!(
-                                    "In KeyMintDevice::lookup_or_generate_key: ",
-                                    "calling getKeyCharacteristics."
+                                    "KeyMintDevice::lookup_or_generate_key: ",
+                                    "calling IKeyMintDevice::getKeyCharacteristics."
                                 ));
                                 self.km_dev.getKeyCharacteristics(key_blob, &[], &[])
                             })
@@ -305,7 +305,9 @@ impl KeyMintDevice {
         let (begin_result, _) = self
             .upgrade_keyblob_if_required_with(db, key_id_guard, key_blob, |blob| {
                 map_km_error({
-                    let _wp = wd::watch("In use_key_in_one_step: calling: begin");
+                    let _wp = wd::watch(
+                        "KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::begin",
+                    );
                     self.km_dev.begin(purpose, blob, operation_parameters, auth_token)
                 })
             })
@@ -313,7 +315,8 @@ impl KeyMintDevice {
         let operation: Strong<dyn IKeyMintOperation> =
             begin_result.operation.ok_or_else(Error::sys).context(ks_err!("Operation missing"))?;
         map_km_error({
-            let _wp = wd::watch("In use_key_in_one_step: calling: finish");
+            let _wp =
+                wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::finish");
             operation.finish(Some(input), None, None, None, None)
         })
         .context(ks_err!("Failed to finish operation."))
diff --git a/keystore2/src/security_level.rs b/keystore2/src/security_level.rs
index 00e0480a..bd20afb7 100644
--- a/keystore2/src/security_level.rs
+++ b/keystore2/src/security_level.rs
@@ -34,7 +34,8 @@ use crate::super_key::{KeyBlob, SuperKeyManager};
 use crate::utils::{
     check_device_attestation_permissions, check_key_permission,
     check_unique_id_attestation_permissions, is_device_id_attestation_tag,
-    key_characteristics_to_internal, uid_to_android_user, watchdog as wd, UNDEFINED_NOT_AFTER,
+    key_characteristics_to_internal, log_security_safe_params, uid_to_android_user, watchdog as wd,
+    UNDEFINED_NOT_AFTER,
 };
 use crate::{
     database::{
@@ -109,14 +110,12 @@ impl KeystoreSecurityLevel {
 
     fn watch_millis(&self, id: &'static str, millis: u64) -> Option<wd::WatchPoint> {
         let sec_level = self.security_level;
-        wd::watch_millis_with(id, millis, move || format!("SecurityLevel {:?}", sec_level))
+        wd::watch_millis_with(id, millis, sec_level)
     }
 
     fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
         let sec_level = self.security_level;
-        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, move || {
-            format!("SecurityLevel {:?}", sec_level)
-        })
+        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, sec_level)
     }
 
     fn store_new_key(
@@ -330,8 +329,9 @@ impl KeystoreSecurityLevel {
                 operation_parameters,
                 |blob| loop {
                     match map_km_error({
-                        let _wp =
-                            self.watch("In KeystoreSecurityLevel::create_operation: calling begin");
+                        let _wp = self.watch(
+                            "KeystoreSecurityLevel::create_operation: calling IKeyMintDevice::begin",
+                        );
                         self.keymint.begin(
                             purpose,
                             blob,
@@ -444,17 +444,23 @@ impl KeystoreSecurityLevel {
 
         // If there is an attestation challenge we need to get an application id.
         if params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE) {
-            let aaid = {
-                let _wp = self
-                    .watch("In KeystoreSecurityLevel::add_required_parameters calling: get_aaid");
-                keystore2_aaid::get_aaid(uid)
-                    .map_err(|e| anyhow!(ks_err!("get_aaid returned status {}.", e)))
-            }?;
-
-            result.push(KeyParameter {
-                tag: Tag::ATTESTATION_APPLICATION_ID,
-                value: KeyParameterValue::Blob(aaid),
-            });
+            let _wp =
+                self.watch(" KeystoreSecurityLevel::add_required_parameters: calling get_aaid");
+            match keystore2_aaid::get_aaid(uid) {
+                Ok(aaid_ok) => {
+                    result.push(KeyParameter {
+                        tag: Tag::ATTESTATION_APPLICATION_ID,
+                        value: KeyParameterValue::Blob(aaid_ok),
+                    });
+                }
+                Err(e) if e == ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED.0 as u32 => {
+                    return Err(Error::Rc(ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED))
+                        .context(ks_err!("Attestation ID retrieval failed."));
+                }
+                Err(e) => {
+                    return Err(anyhow!(e)).context(ks_err!("Attestation ID retrieval error."))
+                }
+            }
         }
 
         if params.iter().any(|kp| kp.tag == Tag::INCLUDE_UNIQUE_ID) {
@@ -576,8 +582,8 @@ impl KeystoreSecurityLevel {
                         map_km_error({
                             let _wp = self.watch_millis(
                                 concat!(
-                                    "In KeystoreSecurityLevel::generate_key (UserGenerated): ",
-                                    "calling generate_key."
+                                    "KeystoreSecurityLevel::generate_key (UserGenerated): ",
+                                    "calling IKeyMintDevice::generate_key"
                                 ),
                                 5000, // Generate can take a little longer.
                             );
@@ -585,15 +591,19 @@ impl KeystoreSecurityLevel {
                         })
                     },
                 )
-                .context(ks_err!("Using user generated attestation key."))
+                .context(ks_err!(
+                    "While generating with a user-generated \
+                      attestation key, params: {:?}.",
+                    log_security_safe_params(&params)
+                ))
                 .map(|(result, _)| result),
             Some(AttestationKeyInfo::RkpdProvisioned { attestation_key, attestation_certs }) => {
                 self.upgrade_rkpd_keyblob_if_required_with(&attestation_key.keyBlob, &[], |blob| {
                     map_km_error({
                         let _wp = self.watch_millis(
                             concat!(
-                                "In KeystoreSecurityLevel::generate_key (RkpdProvisioned): ",
-                                "calling generate_key.",
+                                "KeystoreSecurityLevel::generate_key (RkpdProvisioned): ",
+                                "calling IKeyMintDevice::generate_key",
                             ),
                             5000, // Generate can take a little longer.
                         );
@@ -605,7 +615,12 @@ impl KeystoreSecurityLevel {
                         self.keymint.generateKey(&params, dynamic_attest_key.as_ref())
                     })
                 })
-                .context(ks_err!("While generating Key with remote provisioned attestation key."))
+                .context(ks_err!(
+                    "While generating Key {:?} with remote \
+                    provisioned attestation key and params: {:?}.",
+                    key.alias,
+                    log_security_safe_params(&params)
+                ))
                 .map(|(mut result, _)| {
                     result.certificateChain.push(attestation_certs);
                     result
@@ -614,14 +629,18 @@ impl KeystoreSecurityLevel {
             None => map_km_error({
                 let _wp = self.watch_millis(
                     concat!(
-                        "In KeystoreSecurityLevel::generate_key (No attestation): ",
-                        "calling generate_key.",
+                        "KeystoreSecurityLevel::generate_key (No attestation key): ",
+                        "calling IKeyMintDevice::generate_key",
                     ),
                     5000, // Generate can take a little longer.
                 );
                 self.keymint.generateKey(&params, None)
             })
-            .context(ks_err!("While generating Key without explicit attestation key.")),
+            .context(ks_err!(
+                "While generating without a provided \
+                 attestation key and params: {:?}.",
+                log_security_safe_params(&params)
+            )),
         }
         .context(ks_err!())?;
 
@@ -678,7 +697,8 @@ impl KeystoreSecurityLevel {
 
         let km_dev = &self.keymint;
         let creation_result = map_km_error({
-            let _wp = self.watch("In KeystoreSecurityLevel::import_key: calling importKey.");
+            let _wp =
+                self.watch("KeystoreSecurityLevel::import_key: calling IKeyMintDevice::importKey.");
             km_dev.importKey(&params, format, key_data, None /* attestKey */)
         })
         .context(ks_err!("Trying to call importKey"))?;
@@ -792,7 +812,7 @@ impl KeystoreSecurityLevel {
                 &[],
                 |wrapping_blob| {
                     let _wp = self.watch(
-                        "In KeystoreSecurityLevel::import_wrapped_key: calling importWrappedKey.",
+                        "KeystoreSecurityLevel::import_wrapped_key: calling IKeyMintDevice::importWrappedKey.",
                     );
                     let creation_result = map_km_error(self.keymint.importWrappedKey(
                         wrapped_data,
@@ -866,7 +886,7 @@ impl KeystoreSecurityLevel {
                 }
             },
         )
-        .context(ks_err!())?;
+        .context(ks_err!("upgrade_keyblob_if_required_with(key_id={:?})", key_id_guard))?;
 
         // If no upgrade was needed, use the opportunity to reencrypt the blob if required
         // and if the a key_id_guard is held. Note: key_id_guard can only be Some if no
@@ -906,7 +926,10 @@ impl KeystoreSecurityLevel {
                 }
             },
         )
-        .context(ks_err!())
+        .context(ks_err!(
+            "upgrade_rkpd_keyblob_if_required_with(params={:?})",
+            log_security_safe_params(params)
+        ))
     }
 
     fn convert_storage_key_to_ephemeral(
@@ -930,8 +953,8 @@ impl KeystoreSecurityLevel {
         let km_dev = &self.keymint;
         let res = {
             let _wp = self.watch(concat!(
-                "In IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
-                "calling convertStorageKeyToEphemeral (1)"
+                "IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
+                "calling IKeyMintDevice::convertStorageKeyToEphemeral (1)"
             ));
             map_km_error(km_dev.convertStorageKeyToEphemeral(key_blob))
         };
@@ -941,19 +964,18 @@ impl KeystoreSecurityLevel {
             }
             Err(error::Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                 let upgraded_blob = {
-                    let _wp = self.watch("In convert_storage_key_to_ephemeral: calling upgradeKey");
+                    let _wp = self.watch("IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: calling IKeyMintDevice::upgradeKey");
                     map_km_error(km_dev.upgradeKey(key_blob, &[]))
                 }
                 .context(ks_err!("Failed to upgrade key blob."))?;
                 let ephemeral_key = {
-                    let _wp = self.watch(
-                        "In convert_storage_key_to_ephemeral: calling convertStorageKeyToEphemeral (2)",
-                    );
+                    let _wp = self.watch(concat!(
+                        "IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
+                        "calling IKeyMintDevice::convertStorageKeyToEphemeral (2)"
+                    ));
                     map_km_error(km_dev.convertStorageKeyToEphemeral(&upgraded_blob))
                 }
-                    .context(ks_err!(
-                        "Failed to retrieve ephemeral key (after upgrade)."
-                    ))?;
+                .context(ks_err!("Failed to retrieve ephemeral key (after upgrade)."))?;
                 Ok(EphemeralStorageKeyResponse {
                     ephemeralKey: ephemeral_key,
                     upgradedBlob: Some(upgraded_blob),
@@ -980,7 +1002,8 @@ impl KeystoreSecurityLevel {
 
         let km_dev = &self.keymint;
         {
-            let _wp = self.watch("In KeystoreSecuritylevel::delete_key: calling deleteKey");
+            let _wp =
+                self.watch("KeystoreSecuritylevel::delete_key: calling IKeyMintDevice::deleteKey");
             map_km_error(km_dev.deleteKey(key_blob)).context(ks_err!("keymint device deleteKey"))
         }
     }
diff --git a/keystore2/src/service.rs b/keystore2/src/service.rs
index 37263580..95e17445 100644
--- a/keystore2/src/service.rs
+++ b/keystore2/src/service.rs
@@ -62,11 +62,18 @@ impl KeystoreService {
         id_rotation_state: IdRotationState,
     ) -> Result<Strong<dyn IKeystoreService>> {
         let mut result: Self = Default::default();
-        let (dev, uuid) = KeystoreSecurityLevel::new_native_binder(
+        let (dev, uuid) = match KeystoreSecurityLevel::new_native_binder(
             SecurityLevel::TRUSTED_ENVIRONMENT,
             id_rotation_state.clone(),
-        )
-        .context(ks_err!("Trying to construct mandatory security level TEE."))?;
+        ) {
+            Ok(v) => v,
+            Err(e) => {
+                log::error!("Failed to construct mandatory security level TEE: {e:?}");
+                log::error!("Does the device have a /default Keymaster or KeyMint instance?");
+                return Err(e.context(ks_err!("Trying to construct mandatory security level TEE")));
+            }
+        };
+
         result.i_sec_level_by_uuid.insert(uuid, dev);
         result.uuid_by_sec_level.insert(SecurityLevel::TRUSTED_ENVIRONMENT, uuid);
 
@@ -381,9 +388,7 @@ impl IKeystoreService for KeystoreService {
         &self,
         security_level: SecurityLevel,
     ) -> binder::Result<Strong<dyn IKeystoreSecurityLevel>> {
-        let _wp = wd::watch_millis_with("IKeystoreService::getSecurityLevel", 500, move || {
-            format!("security_level: {}", security_level.0)
-        });
+        let _wp = wd::watch_millis_with("IKeystoreService::getSecurityLevel", 500, security_level);
         self.get_security_level(security_level).map_err(into_logged_binder)
     }
     fn getKeyEntry(&self, key: &KeyDescriptor) -> binder::Result<KeyEntryResponse> {
diff --git a/keystore2/src/super_key.rs b/keystore2/src/super_key.rs
index 1f9f5f89..42fd7645 100644
--- a/keystore2/src/super_key.rs
+++ b/keystore2/src/super_key.rs
@@ -52,6 +52,9 @@ use std::{
 };
 use std::{convert::TryFrom, ops::Deref};
 
+#[cfg(test)]
+mod tests;
+
 const MAX_MAX_BOOT_LEVEL: usize = 1_000_000_000;
 /// Allow up to 15 seconds between the user unlocking using a biometric, and the auth
 /// token being used to unlock in [`SuperKeyManager::try_unlock_user_with_biometric`].
@@ -576,13 +579,9 @@ impl SuperKeyManager {
         pw: &Password,
     ) -> Result<(Vec<u8>, BlobMetaData)> {
         let salt = generate_salt().context("In encrypt_with_password: Failed to generate salt.")?;
-        let derived_key = if android_security_flags::fix_unlocked_device_required_keys_v2() {
-            pw.derive_key_hkdf(&salt, AES_256_KEY_LENGTH)
-                .context(ks_err!("Failed to derive key from password."))?
-        } else {
-            pw.derive_key_pbkdf2(&salt, AES_256_KEY_LENGTH)
-                .context(ks_err!("Failed to derive password."))?
-        };
+        let derived_key = pw
+            .derive_key_hkdf(&salt, AES_256_KEY_LENGTH)
+            .context(ks_err!("Failed to derive key from password."))?;
         let mut metadata = BlobMetaData::new();
         metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
         metadata.add(BlobMetaEntry::Salt(salt));
@@ -879,9 +878,7 @@ impl SuperKeyManager {
     ) {
         let entry = self.data.user_keys.entry(user_id).or_default();
         if unlocking_sids.is_empty() {
-            if android_security_flags::fix_unlocked_device_required_keys_v2() {
-                entry.biometric_unlock = None;
-            }
+            entry.biometric_unlock = None;
         } else if let (Some(aes), Some(ecdh)) = (
             entry.unlocked_device_required_symmetric.as_ref().cloned(),
             entry.unlocked_device_required_private.as_ref().cloned(),
@@ -920,7 +917,7 @@ impl SuperKeyManager {
                     KeyType::Client, /* TODO Should be Super b/189470584 */
                     |dev| {
                         let _wp =
-                            wd::watch("In lock_unlocked_device_required_keys: calling importKey.");
+                            wd::watch("SKM::lock_unlocked_device_required_keys: calling IKeyMintDevice::importKey.");
                         dev.importKey(key_params.as_slice(), KeyFormat::RAW, &encrypting_key, None)
                     },
                 )?;
@@ -984,8 +981,7 @@ impl SuperKeyManager {
         user_id: UserId,
     ) -> Result<()> {
         let entry = self.data.user_keys.entry(user_id).or_default();
-        if android_security_flags::fix_unlocked_device_required_keys_v2()
-            && entry.unlocked_device_required_symmetric.is_some()
+        if entry.unlocked_device_required_symmetric.is_some()
             && entry.unlocked_device_required_private.is_some()
         {
             // If the keys are already cached in plaintext, then there is no need to decrypt the
@@ -1096,92 +1092,13 @@ impl SuperKeyManager {
         legacy_importer
             .bulk_delete_user(user_id, false)
             .context(ks_err!("Trying to delete legacy keys."))?;
-        db.unbind_keys_for_user(user_id, false).context(ks_err!("Error in unbinding keys."))?;
+        db.unbind_keys_for_user(user_id).context(ks_err!("Error in unbinding keys."))?;
 
         // Delete super key in cache, if exists.
         self.forget_all_keys_for_user(user_id);
         Ok(())
     }
 
-    /// Deletes all authentication bound keys and super keys for the given user.  The user must be
-    /// unlocked before this function is called.  This function is used to transition a user to
-    /// swipe.
-    pub fn reset_user(
-        &mut self,
-        db: &mut KeystoreDB,
-        legacy_importer: &LegacyImporter,
-        user_id: UserId,
-    ) -> Result<()> {
-        log::info!("reset_user(user={user_id})");
-        match self.get_user_state(db, legacy_importer, user_id)? {
-            UserState::Uninitialized => {
-                Err(Error::sys()).context(ks_err!("Tried to reset an uninitialized user!"))
-            }
-            UserState::BeforeFirstUnlock => {
-                Err(Error::sys()).context(ks_err!("Tried to reset a locked user's password!"))
-            }
-            UserState::AfterFirstUnlock(_) => {
-                // Mark keys created on behalf of the user as unreferenced.
-                legacy_importer
-                    .bulk_delete_user(user_id, true)
-                    .context(ks_err!("Trying to delete legacy keys."))?;
-                db.unbind_keys_for_user(user_id, true)
-                    .context(ks_err!("Error in unbinding keys."))?;
-
-                // Delete super key in cache, if exists.
-                self.forget_all_keys_for_user(user_id);
-                Ok(())
-            }
-        }
-    }
-
-    /// If the user hasn't been initialized yet, then this function generates the user's
-    /// AfterFirstUnlock super key and sets the user's state to AfterFirstUnlock. Otherwise this
-    /// function returns an error.
-    pub fn init_user(
-        &mut self,
-        db: &mut KeystoreDB,
-        legacy_importer: &LegacyImporter,
-        user_id: UserId,
-        password: &Password,
-    ) -> Result<()> {
-        log::info!("init_user(user={user_id})");
-        match self.get_user_state(db, legacy_importer, user_id)? {
-            UserState::AfterFirstUnlock(_) | UserState::BeforeFirstUnlock => {
-                Err(Error::sys()).context(ks_err!("Tried to re-init an initialized user!"))
-            }
-            UserState::Uninitialized => {
-                // Generate a new super key.
-                let super_key =
-                    generate_aes256_key().context(ks_err!("Failed to generate AES 256 key."))?;
-                // Derive an AES256 key from the password and re-encrypt the super key
-                // before we insert it in the database.
-                let (encrypted_super_key, blob_metadata) =
-                    Self::encrypt_with_password(&super_key, password)
-                        .context(ks_err!("Failed to encrypt super key with password!"))?;
-
-                let key_entry = db
-                    .store_super_key(
-                        user_id,
-                        &USER_AFTER_FIRST_UNLOCK_SUPER_KEY,
-                        &encrypted_super_key,
-                        &blob_metadata,
-                        &KeyMetaData::new(),
-                    )
-                    .context(ks_err!("Failed to store super key."))?;
-
-                self.populate_cache_from_super_key_blob(
-                    user_id,
-                    USER_AFTER_FIRST_UNLOCK_SUPER_KEY.algorithm,
-                    key_entry,
-                    password,
-                )
-                .context(ks_err!("Failed to initialize user!"))?;
-                Ok(())
-            }
-        }
-    }
-
     /// Initializes the given user by creating their super keys, both AfterFirstUnlock and
     /// UnlockedDeviceRequired. If allow_existing is true, then the user already being initialized
     /// is not considered an error.
@@ -1323,390 +1240,3 @@ impl<'a> Deref for KeyBlob<'a> {
         }
     }
 }
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use crate::database::tests::make_bootlevel_key_entry;
-    use crate::database::tests::make_test_key_entry;
-    use crate::database::tests::new_test_db;
-    use rand::prelude::*;
-    const USER_ID: u32 = 0;
-    const TEST_KEY_ALIAS: &str = "TEST_KEY";
-    const TEST_BOOT_KEY_ALIAS: &str = "TEST_BOOT_KEY";
-
-    pub fn generate_password_blob() -> Password<'static> {
-        let mut rng = rand::thread_rng();
-        let mut password = vec![0u8; 64];
-        rng.fill_bytes(&mut password);
-
-        let mut zvec = ZVec::new(64).expect("Failed to create ZVec");
-        zvec[..].copy_from_slice(&password[..]);
-
-        Password::Owned(zvec)
-    }
-
-    fn setup_test(pw: &Password) -> (Arc<RwLock<SuperKeyManager>>, KeystoreDB, LegacyImporter) {
-        let mut keystore_db = new_test_db().unwrap();
-        let mut legacy_importer = LegacyImporter::new(Arc::new(Default::default()));
-        legacy_importer.set_empty();
-        let skm: Arc<RwLock<SuperKeyManager>> = Default::default();
-        assert!(skm
-            .write()
-            .unwrap()
-            .init_user(&mut keystore_db, &legacy_importer, USER_ID, pw)
-            .is_ok());
-        (skm, keystore_db, legacy_importer)
-    }
-
-    fn assert_unlocked(
-        skm: &Arc<RwLock<SuperKeyManager>>,
-        keystore_db: &mut KeystoreDB,
-        legacy_importer: &LegacyImporter,
-        user_id: u32,
-        err_msg: &str,
-    ) {
-        let user_state =
-            skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
-        match user_state {
-            UserState::AfterFirstUnlock(_) => {}
-            _ => panic!("{}", err_msg),
-        }
-    }
-
-    fn assert_locked(
-        skm: &Arc<RwLock<SuperKeyManager>>,
-        keystore_db: &mut KeystoreDB,
-        legacy_importer: &LegacyImporter,
-        user_id: u32,
-        err_msg: &str,
-    ) {
-        let user_state =
-            skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
-        match user_state {
-            UserState::BeforeFirstUnlock => {}
-            _ => panic!("{}", err_msg),
-        }
-    }
-
-    fn assert_uninitialized(
-        skm: &Arc<RwLock<SuperKeyManager>>,
-        keystore_db: &mut KeystoreDB,
-        legacy_importer: &LegacyImporter,
-        user_id: u32,
-        err_msg: &str,
-    ) {
-        let user_state =
-            skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
-        match user_state {
-            UserState::Uninitialized => {}
-            _ => panic!("{}", err_msg),
-        }
-    }
-
-    #[test]
-    fn test_init_user() {
-        let pw: Password = generate_password_blob();
-        let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not unlocked after initialization!",
-        );
-    }
-
-    #[test]
-    fn test_unlock_user() {
-        let pw: Password = generate_password_blob();
-        let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not unlocked after initialization!",
-        );
-
-        skm.write().unwrap().data.user_keys.clear();
-        assert_locked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "Clearing the cache did not lock the user!",
-        );
-
-        assert!(skm
-            .write()
-            .unwrap()
-            .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &pw)
-            .is_ok());
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user did not unlock!",
-        );
-    }
-
-    #[test]
-    fn test_unlock_wrong_password() {
-        let pw: Password = generate_password_blob();
-        let wrong_pw: Password = generate_password_blob();
-        let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not unlocked after initialization!",
-        );
-
-        skm.write().unwrap().data.user_keys.clear();
-        assert_locked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "Clearing the cache did not lock the user!",
-        );
-
-        assert!(skm
-            .write()
-            .unwrap()
-            .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &wrong_pw)
-            .is_err());
-        assert_locked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was unlocked with an incorrect password!",
-        );
-    }
-
-    #[test]
-    fn test_unlock_user_idempotent() {
-        let pw: Password = generate_password_blob();
-        let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not unlocked after initialization!",
-        );
-
-        skm.write().unwrap().data.user_keys.clear();
-        assert_locked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "Clearing the cache did not lock the user!",
-        );
-
-        for _ in 0..5 {
-            assert!(skm
-                .write()
-                .unwrap()
-                .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &pw)
-                .is_ok());
-            assert_unlocked(
-                &skm,
-                &mut keystore_db,
-                &legacy_importer,
-                USER_ID,
-                "The user did not unlock!",
-            );
-        }
-    }
-
-    fn test_user_removal(locked: bool) {
-        let pw: Password = generate_password_blob();
-        let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not unlocked after initialization!",
-        );
-
-        assert!(make_test_key_entry(
-            &mut keystore_db,
-            Domain::APP,
-            USER_ID.into(),
-            TEST_KEY_ALIAS,
-            None
-        )
-        .is_ok());
-        assert!(make_bootlevel_key_entry(
-            &mut keystore_db,
-            Domain::APP,
-            USER_ID.into(),
-            TEST_BOOT_KEY_ALIAS,
-            false
-        )
-        .is_ok());
-
-        assert!(keystore_db
-            .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
-            .unwrap());
-        assert!(keystore_db
-            .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
-            .unwrap());
-
-        if locked {
-            skm.write().unwrap().data.user_keys.clear();
-            assert_locked(
-                &skm,
-                &mut keystore_db,
-                &legacy_importer,
-                USER_ID,
-                "Clearing the cache did not lock the user!",
-            );
-        }
-
-        assert!(skm
-            .write()
-            .unwrap()
-            .remove_user(&mut keystore_db, &legacy_importer, USER_ID)
-            .is_ok());
-        assert_uninitialized(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not removed!",
-        );
-
-        assert!(!skm
-            .write()
-            .unwrap()
-            .super_key_exists_in_db_for_user(&mut keystore_db, &legacy_importer, USER_ID)
-            .unwrap());
-
-        assert!(!keystore_db
-            .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
-            .unwrap());
-        assert!(!keystore_db
-            .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
-            .unwrap());
-    }
-
-    fn test_user_reset(locked: bool) {
-        let pw: Password = generate_password_blob();
-        let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
-        assert_unlocked(
-            &skm,
-            &mut keystore_db,
-            &legacy_importer,
-            USER_ID,
-            "The user was not unlocked after initialization!",
-        );
-
-        assert!(make_test_key_entry(
-            &mut keystore_db,
-            Domain::APP,
-            USER_ID.into(),
-            TEST_KEY_ALIAS,
-            None
-        )
-        .is_ok());
-        assert!(make_bootlevel_key_entry(
-            &mut keystore_db,
-            Domain::APP,
-            USER_ID.into(),
-            TEST_BOOT_KEY_ALIAS,
-            false
-        )
-        .is_ok());
-        assert!(keystore_db
-            .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
-            .unwrap());
-        assert!(keystore_db
-            .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
-            .unwrap());
-
-        if locked {
-            skm.write().unwrap().data.user_keys.clear();
-            assert_locked(
-                &skm,
-                &mut keystore_db,
-                &legacy_importer,
-                USER_ID,
-                "Clearing the cache did not lock the user!",
-            );
-            assert!(skm
-                .write()
-                .unwrap()
-                .reset_user(&mut keystore_db, &legacy_importer, USER_ID)
-                .is_err());
-            assert_locked(
-                &skm,
-                &mut keystore_db,
-                &legacy_importer,
-                USER_ID,
-                "User state should not have changed!",
-            );
-
-            // Keys should still exist.
-            assert!(keystore_db
-                .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
-                .unwrap());
-            assert!(keystore_db
-                .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
-                .unwrap());
-        } else {
-            assert!(skm
-                .write()
-                .unwrap()
-                .reset_user(&mut keystore_db, &legacy_importer, USER_ID)
-                .is_ok());
-            assert_uninitialized(
-                &skm,
-                &mut keystore_db,
-                &legacy_importer,
-                USER_ID,
-                "The user was not reset!",
-            );
-            assert!(!skm
-                .write()
-                .unwrap()
-                .super_key_exists_in_db_for_user(&mut keystore_db, &legacy_importer, USER_ID)
-                .unwrap());
-
-            // Auth bound key should no longer exist.
-            assert!(!keystore_db
-                .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
-                .unwrap());
-            assert!(keystore_db
-                .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
-                .unwrap());
-        }
-    }
-
-    #[test]
-    fn test_remove_unlocked_user() {
-        test_user_removal(false);
-    }
-
-    #[test]
-    fn test_remove_locked_user() {
-        test_user_removal(true);
-    }
-
-    #[test]
-    fn test_reset_unlocked_user() {
-        test_user_reset(false);
-    }
-
-    #[test]
-    fn test_reset_locked_user() {
-        test_user_reset(true);
-    }
-}
diff --git a/keystore2/src/super_key/tests.rs b/keystore2/src/super_key/tests.rs
new file mode 100644
index 00000000..76a96a71
--- /dev/null
+++ b/keystore2/src/super_key/tests.rs
@@ -0,0 +1,287 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Super-key tests.
+
+use super::*;
+use crate::database::tests::make_bootlevel_key_entry;
+use crate::database::tests::make_test_key_entry;
+use crate::database::tests::new_test_db;
+use rand::prelude::*;
+const USER_ID: u32 = 0;
+const TEST_KEY_ALIAS: &str = "TEST_KEY";
+const TEST_BOOT_KEY_ALIAS: &str = "TEST_BOOT_KEY";
+
+pub fn generate_password_blob() -> Password<'static> {
+    let mut rng = rand::thread_rng();
+    let mut password = vec![0u8; 64];
+    rng.fill_bytes(&mut password);
+
+    let mut zvec = ZVec::new(64).expect("Failed to create ZVec");
+    zvec[..].copy_from_slice(&password[..]);
+
+    Password::Owned(zvec)
+}
+
+fn setup_test(pw: &Password) -> (Arc<RwLock<SuperKeyManager>>, KeystoreDB, LegacyImporter) {
+    let mut keystore_db = new_test_db().unwrap();
+    let mut legacy_importer = LegacyImporter::new(Arc::new(Default::default()));
+    legacy_importer.set_empty();
+    let skm: Arc<RwLock<SuperKeyManager>> = Default::default();
+    assert!(skm
+        .write()
+        .unwrap()
+        .initialize_user(&mut keystore_db, &legacy_importer, USER_ID, pw, false)
+        .is_ok());
+    (skm, keystore_db, legacy_importer)
+}
+
+fn assert_unlocked(
+    skm: &Arc<RwLock<SuperKeyManager>>,
+    keystore_db: &mut KeystoreDB,
+    legacy_importer: &LegacyImporter,
+    user_id: u32,
+    err_msg: &str,
+) {
+    let user_state =
+        skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
+    match user_state {
+        UserState::AfterFirstUnlock(_) => {}
+        _ => panic!("{}", err_msg),
+    }
+}
+
+fn assert_locked(
+    skm: &Arc<RwLock<SuperKeyManager>>,
+    keystore_db: &mut KeystoreDB,
+    legacy_importer: &LegacyImporter,
+    user_id: u32,
+    err_msg: &str,
+) {
+    let user_state =
+        skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
+    match user_state {
+        UserState::BeforeFirstUnlock => {}
+        _ => panic!("{}", err_msg),
+    }
+}
+
+fn assert_uninitialized(
+    skm: &Arc<RwLock<SuperKeyManager>>,
+    keystore_db: &mut KeystoreDB,
+    legacy_importer: &LegacyImporter,
+    user_id: u32,
+    err_msg: &str,
+) {
+    let user_state =
+        skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
+    match user_state {
+        UserState::Uninitialized => {}
+        _ => panic!("{}", err_msg),
+    }
+}
+
+#[test]
+fn test_initialize_user() {
+    let pw: Password = generate_password_blob();
+    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
+    assert_unlocked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was not unlocked after initialization!",
+    );
+}
+
+#[test]
+fn test_unlock_user() {
+    let pw: Password = generate_password_blob();
+    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
+    assert_unlocked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was not unlocked after initialization!",
+    );
+
+    skm.write().unwrap().data.user_keys.clear();
+    assert_locked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "Clearing the cache did not lock the user!",
+    );
+
+    assert!(skm
+        .write()
+        .unwrap()
+        .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &pw)
+        .is_ok());
+    assert_unlocked(&skm, &mut keystore_db, &legacy_importer, USER_ID, "The user did not unlock!");
+}
+
+#[test]
+fn test_unlock_wrong_password() {
+    let pw: Password = generate_password_blob();
+    let wrong_pw: Password = generate_password_blob();
+    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
+    assert_unlocked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was not unlocked after initialization!",
+    );
+
+    skm.write().unwrap().data.user_keys.clear();
+    assert_locked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "Clearing the cache did not lock the user!",
+    );
+
+    assert!(skm
+        .write()
+        .unwrap()
+        .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &wrong_pw)
+        .is_err());
+    assert_locked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was unlocked with an incorrect password!",
+    );
+}
+
+#[test]
+fn test_unlock_user_idempotent() {
+    let pw: Password = generate_password_blob();
+    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
+    assert_unlocked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was not unlocked after initialization!",
+    );
+
+    skm.write().unwrap().data.user_keys.clear();
+    assert_locked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "Clearing the cache did not lock the user!",
+    );
+
+    for _ in 0..5 {
+        assert!(skm
+            .write()
+            .unwrap()
+            .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &pw)
+            .is_ok());
+        assert_unlocked(
+            &skm,
+            &mut keystore_db,
+            &legacy_importer,
+            USER_ID,
+            "The user did not unlock!",
+        );
+    }
+}
+
+fn test_user_removal(locked: bool) {
+    let pw: Password = generate_password_blob();
+    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
+    assert_unlocked(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was not unlocked after initialization!",
+    );
+
+    assert!(make_test_key_entry(
+        &mut keystore_db,
+        Domain::APP,
+        USER_ID.into(),
+        TEST_KEY_ALIAS,
+        None
+    )
+    .is_ok());
+    assert!(make_bootlevel_key_entry(
+        &mut keystore_db,
+        Domain::APP,
+        USER_ID.into(),
+        TEST_BOOT_KEY_ALIAS,
+        false
+    )
+    .is_ok());
+
+    assert!(keystore_db
+        .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
+        .unwrap());
+    assert!(keystore_db
+        .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
+        .unwrap());
+
+    if locked {
+        skm.write().unwrap().data.user_keys.clear();
+        assert_locked(
+            &skm,
+            &mut keystore_db,
+            &legacy_importer,
+            USER_ID,
+            "Clearing the cache did not lock the user!",
+        );
+    }
+
+    assert!(skm.write().unwrap().remove_user(&mut keystore_db, &legacy_importer, USER_ID).is_ok());
+    assert_uninitialized(
+        &skm,
+        &mut keystore_db,
+        &legacy_importer,
+        USER_ID,
+        "The user was not removed!",
+    );
+
+    assert!(!skm
+        .write()
+        .unwrap()
+        .super_key_exists_in_db_for_user(&mut keystore_db, &legacy_importer, USER_ID)
+        .unwrap());
+
+    assert!(!keystore_db
+        .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
+        .unwrap());
+    assert!(!keystore_db
+        .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
+        .unwrap());
+}
+
+#[test]
+fn test_remove_unlocked_user() {
+    test_user_removal(false);
+}
+
+#[test]
+fn test_remove_locked_user() {
+    test_user_removal(true);
+}
diff --git a/keystore2/src/sw_keyblob.rs b/keystore2/src/sw_keyblob.rs
index 47ab49fd..c0173b52 100644
--- a/keystore2/src/sw_keyblob.rs
+++ b/keystore2/src/sw_keyblob.rs
@@ -28,6 +28,9 @@ use anyhow::Result;
 use keystore2_crypto::hmac_sha256;
 use std::mem::size_of;
 
+#[cfg(test)]
+mod tests;
+
 /// Root of trust value.
 const SOFTWARE_ROOT_OF_TRUST: &[u8] = b"SW";
 
@@ -556,481 +559,3 @@ fn serialize_params(params: &[KeyParameter]) -> Result<Vec<u8>> {
         .clone_from_slice(&serialized_size.to_ne_bytes());
     Ok(result)
 }
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-        Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
-        KeyOrigin::KeyOrigin, KeyParameter::KeyParameter,
-        KeyParameterValue::KeyParameterValue as KPV, KeyPurpose::KeyPurpose,
-        PaddingMode::PaddingMode, Tag::Tag,
-    };
-
-    macro_rules! expect_err {
-        ($result:expr, $err_msg:expr) => {
-            assert!(
-                $result.is_err(),
-                "Expected error containing '{}', got success {:?}",
-                $err_msg,
-                $result
-            );
-            let err = $result.err();
-            assert!(
-                format!("{:?}", err).contains($err_msg),
-                "Unexpected error {:?}, doesn't contain '{}'",
-                err,
-                $err_msg
-            );
-        };
-    }
-
-    #[test]
-    fn test_consume_u8() {
-        let buffer = [1, 2];
-        let mut data = &buffer[..];
-        assert_eq!(1u8, consume_u8(&mut data).unwrap());
-        assert_eq!(2u8, consume_u8(&mut data).unwrap());
-        let result = consume_u8(&mut data);
-        expect_err!(result, "failed to find 1 byte");
-    }
-
-    #[test]
-    fn test_consume_u32() {
-        // All supported platforms are little-endian.
-        let buffer = [
-            0x01, 0x02, 0x03, 0x04, // little-endian u32
-            0x04, 0x03, 0x02, 0x01, // little-endian u32
-            0x11, 0x12, 0x13,
-        ];
-        let mut data = &buffer[..];
-        assert_eq!(0x04030201u32, consume_u32(&mut data).unwrap());
-        assert_eq!(0x01020304u32, consume_u32(&mut data).unwrap());
-        let result = consume_u32(&mut data);
-        expect_err!(result, "failed to find 4 bytes");
-    }
-
-    #[test]
-    fn test_consume_i64() {
-        // All supported platforms are little-endian.
-        let buffer = [
-            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // little-endian i64
-            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // little-endian i64
-            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
-        ];
-        let mut data = &buffer[..];
-        assert_eq!(0x0807060504030201i64, consume_i64(&mut data).unwrap());
-        assert_eq!(0x0102030405060708i64, consume_i64(&mut data).unwrap());
-        let result = consume_i64(&mut data);
-        expect_err!(result, "failed to find 8 bytes");
-    }
-
-    #[test]
-    fn test_consume_vec() {
-        let buffer = [
-            0x01, 0x00, 0x00, 0x00, 0xaa, //
-            0x00, 0x00, 0x00, 0x00, //
-            0x01, 0x00, 0x00, 0x00, 0xbb, //
-            0x07, 0x00, 0x00, 0x00, 0xbb, // not enough data
-        ];
-        let mut data = &buffer[..];
-        assert_eq!(vec![0xaa], consume_vec(&mut data).unwrap());
-        assert_eq!(Vec::<u8>::new(), consume_vec(&mut data).unwrap());
-        assert_eq!(vec![0xbb], consume_vec(&mut data).unwrap());
-        let result = consume_vec(&mut data);
-        expect_err!(result, "failed to find 7 bytes");
-
-        let buffer = [
-            0x01, 0x00, 0x00, //
-        ];
-        let mut data = &buffer[..];
-        let result = consume_vec(&mut data);
-        expect_err!(result, "failed to find 4 bytes");
-    }
-
-    #[test]
-    fn test_key_new_from_serialized() {
-        let hidden = hidden_params(&[], &[SOFTWARE_ROOT_OF_TRUST]);
-        // Test data originally generated by instrumenting Cuttlefish C++ KeyMint while running VTS
-        // tests.
-        let tests = [
-            (
-                concat!(
-                    "0010000000d43c2f04f948521b81bdbf001310f5920000000000000000000000",
-                    "00000000000c0000006400000002000010200000000300003080000000010000",
-                    "2000000000010000200100000004000020020000000600002001000000be0200",
-                    "1000000000c1020030b0ad0100c20200307b150300bd020060a8bb52407b0100",
-                    "00ce02003011643401cf020030000000003b06b13ae6ae6671",
-                ),
-                KeyBlob {
-                    key_material: hex::decode("d43c2f04f948521b81bdbf001310f592").unwrap(),
-                    hw_enforced: vec![],
-                    sw_enforced: vec![
-                        KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::AES) },
-                        KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(128) },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::ENCRYPT),
-                        },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::DECRYPT),
-                        },
-                        KeyParameter {
-                            tag: Tag::BLOCK_MODE,
-                            value: KPV::BlockMode(BlockMode::CBC),
-                        },
-                        KeyParameter {
-                            tag: Tag::PADDING,
-                            value: KPV::PaddingMode(PaddingMode::NONE),
-                        },
-                        KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
-                        KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
-                        KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
-                        KeyParameter {
-                            tag: Tag::CREATION_DATETIME,
-                            value: KPV::DateTime(1628871769000),
-                        },
-                        KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
-                        KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
-                    ],
-                },
-                Some(KeyFormat::RAW),
-            ),
-            (
-                concat!(
-                    "00df0000003081dc020101044200b6ce876b947e263d61b8e3998d50dc0afb6b",
-                    "a14e46ab7ca532fbe2a379b155d0a5bb99265402857b1601fb20be6c244bf654",
-                    "e9e79413cd503eae3d9cf68ed24f47a00706052b81040023a181890381860004",
-                    "006b840f0db0b12f074ab916c7773cfa7d42967c9e5b4fae09cf999f7e116d14",
-                    "0743bdd028db0a3fcc670e721b9f00bc7fb70aa401c7d6de6582fc26962a29b7",
-                    "45e30142e90685646661550344113aaf28bdee6cb02d19df1faab4398556a909",
-                    "7d6f64b95209601a549389a311231c6cce78354f2cdbc3a904abf70686f5f0c3",
-                    "b877984d000000000000000000000000000000000c0000006400000002000010",
-                    "030000000a000010030000000100002002000000010000200300000005000020",
-                    "000000000300003009020000be02001000000000c1020030b0ad0100c2020030",
-                    "7b150300bd02006018d352407b010000ce02003011643401cf02003000000000",
-                    "2f69002e55e9b0a3"
-                ),
-                KeyBlob {
-                    key_material: hex::decode(concat!(
-                        "3081dc020101044200b6ce876b947e263d61b8e3998d50dc0afb6ba14e46ab7c",
-                        "a532fbe2a379b155d0a5bb99265402857b1601fb20be6c244bf654e9e79413cd",
-                        "503eae3d9cf68ed24f47a00706052b81040023a181890381860004006b840f0d",
-                        "b0b12f074ab916c7773cfa7d42967c9e5b4fae09cf999f7e116d140743bdd028",
-                        "db0a3fcc670e721b9f00bc7fb70aa401c7d6de6582fc26962a29b745e30142e9",
-                        "0685646661550344113aaf28bdee6cb02d19df1faab4398556a9097d6f64b952",
-                        "09601a549389a311231c6cce78354f2cdbc3a904abf70686f5f0c3b877984d",
-                    ))
-                    .unwrap(),
-                    hw_enforced: vec![],
-                    sw_enforced: vec![
-                        KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::EC) },
-                        KeyParameter { tag: Tag::EC_CURVE, value: KPV::EcCurve(EcCurve::P_521) },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::SIGN),
-                        },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::VERIFY),
-                        },
-                        KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::NONE) },
-                        KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(521) },
-                        KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
-                        KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
-                        KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
-                        KeyParameter {
-                            tag: Tag::CREATION_DATETIME,
-                            value: KPV::DateTime(1628871775000),
-                        },
-                        KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
-                        KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
-                    ],
-                },
-                Some(KeyFormat::PKCS8),
-            ),
-            (
-                concat!(
-                    "0037000000541d4c440223650d5f51753c1abd80c725034485551e874d62327c",
-                    "65f6247a057f1218bd6c8cd7d319103ddb823fc11fb6c2c7268b5acc00000000",
-                    "0000000000000000000000000c00000064000000020000108000000003000030",
-                    "b801000001000020020000000100002003000000050000200400000008000030",
-                    "00010000be02001000000000c1020030b0ad0100c20200307b150300bd020060",
-                    "00d752407b010000ce02003011643401cf0200300000000036e6986ffc45fbb0",
-                ),
-                KeyBlob {
-                    key_material: hex::decode(concat!(
-                        "541d4c440223650d5f51753c1abd80c725034485551e874d62327c65f6247a05",
-                        "7f1218bd6c8cd7d319103ddb823fc11fb6c2c7268b5acc"
-                    ))
-                    .unwrap(),
-                    hw_enforced: vec![],
-                    sw_enforced: vec![
-                        KeyParameter {
-                            tag: Tag::ALGORITHM,
-                            value: KPV::Algorithm(Algorithm::HMAC),
-                        },
-                        KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(440) },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::SIGN),
-                        },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::VERIFY),
-                        },
-                        KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::SHA_2_256) },
-                        KeyParameter { tag: Tag::MIN_MAC_LENGTH, value: KPV::Integer(256) },
-                        KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
-                        KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
-                        KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
-                        KeyParameter {
-                            tag: Tag::CREATION_DATETIME,
-                            value: KPV::DateTime(1628871776000),
-                        },
-                        KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
-                        KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
-                    ],
-                },
-                Some(KeyFormat::RAW),
-            ),
-            (
-                concat!(
-                    "00a8040000308204a40201000282010100bc47b5c71116766669b91fa747df87",
-                    "a1963df83956569d4ac232aeba8a246c0ec73bf606374a6d07f30c2162f97082",
-                    "825c7c6e482a2841dfeaec1429d84e52c54a6b2f760dec952c9c44a3c3a80f31",
-                    "c1ced84878edd4858059071c4d20d9ab0aae978bd68c1eb448e174a9736c3973",
-                    "6838151642eda8215107375865a99a57f29467c74c40f37b0221b93ec3f4f22d",
-                    "5337c8bf9245d56936196a92b1dea315ecce8785f9fa9b7d159ca207612cc0de",
-                    "b0957d61dbba5d9bd38784f4fecbf233b04e686a340528665ecd03db8e8a09b2",
-                    "540c84e45c4a99fb338b76bba7722856b5113341c349708937228f167d238ed8",
-                    "efb9cc19547dd620f6a90d95f07e50bfe102030100010282010002f91b69d9af",
-                    "59fe87421af9ba60f15c77f9c1c90effd6634332876f8ee5a116b126f55d3703",
-                    "8bf9f588ae20c8d951d842e35c9ef35a7822d3ebf72c0b7c3e229b289ae2e178",
-                    "a848e06d558c2e03d26871ee98a35f370d461ff1c4acc39d684de680a25ec88e",
-                    "e610260e406c400bdeb2893b2d0330cb483e662fa5abd24c2b82143e85dfe30a",
-                    "e7a31f8262da2903d882b35a34a26b699ff2d812bad4b126a0065ec0e101d73a",
-                    "e6f8b29a9144eb83f54940a371fc7416c2c0370df6a41cb5391f17ba33239e1b",
-                    "4217c8db50db5c6bf77ccf621354ecc652a4f7196054c254566fd7b3bc0f3817",
-                    "d9380b190bd382aaffa37785759f285194c11a188bccde0e2e2902818100fb23",
-                    "3335770c9f3cbd4b6ede5f12d03c449b1997bce06a8249bc3de99972fd0d0a63",
-                    "3f7790d1011bf5eedee16fa45a9107a910656ecaee364ce9edb4369843be71f2",
-                    "7a74852d6c7215a6cc60d9803bcac544922f806d8e5844e0ddd914bd78009490",
-                    "4c2856d2b944fade3fb1d67d4a33fb7663a9ab660ab372c2e4868a0f45990281",
-                    "8100bfecf2bb4012e880fd065a0b088f2d757af2878d3f1305f21ce7a7158458",
-                    "18e01181ff06b2f406239fc50808ce3dbe7b68ec01174913c0f237feb3c8c7eb",
-                    "0078b77fb5b8f214b72f6d3835b1a7ebe8b132feb6cb34ab09ce22b98160fc84",
-                    "20fcbf48d1eee49f874e902f049b206a61a095f0405a4935e7c5e49757ab7b57",
-                    "298902818100ec0049383e16f3716de5fc5b2677148efe5dceb02483b43399bd",
-                    "3765559994a9f3900eed7a7e9e8f3b0eee0e660eca392e3cb736cae612f39e55",
-                    "dad696d3821def10d1f8bbca52f5e6d8e7893ffbdcb491aafdc17bebf86f84d2",
-                    "d8480ed07a7bf9209d20ef6e79429489d4cb7768281a2f7e32ec1830fd6f6332",
-                    "38f521ba764902818100b2c3ce5751580b4e51df3fb175387f5c24b79040a4d6",
-                    "603c6265f70018b441ff3aef7d8e4cd2f480ec0906f1c4c0481304e8861f9d46",
-                    "93fa48e3a9abc362859eeb343e1c5507ac94b5439ce7ac04154a2fb886a4819b",
-                    "2a57e18a2e131b412ac4a09b004766959cdf357745f003e272aab3de02e2d5bc",
-                    "2af4ed75760858ab181902818061d19c2a8dcacde104b97f7c4fae11216157c1",
-                    "c0a258d882984d12383a73dc56fe2ac93512bb321df9706ecdb2f70a44c949c4",
-                    "340a9fae64a0646cf51f37c58c08bebde91667b3b2fa7c895f7983d4786c5526",
-                    "1941b3654533b0598383ebbcffcdf28b6cf13d376e3a70b49b14d8d06e8563a2",
-                    "47f56a337e3b9845b4f2b61356000000000000000000000000000000000d0000",
-                    "007000000002000010010000000300003000080000c800005001000100000000",
-                    "0001000020020000000100002003000000050000200000000006000020010000",
-                    "00be02001000000000c1020030b0ad0100c20200307b150300bd020060a8bb52",
-                    "407b010000ce02003011643401cf02003000000000544862e9c961e857",
-                ),
-                KeyBlob {
-                    key_material: hex::decode(concat!(
-                        "308204a40201000282010100bc47b5c71116766669b91fa747df87a1963df839",
-                        "56569d4ac232aeba8a246c0ec73bf606374a6d07f30c2162f97082825c7c6e48",
-                        "2a2841dfeaec1429d84e52c54a6b2f760dec952c9c44a3c3a80f31c1ced84878",
-                        "edd4858059071c4d20d9ab0aae978bd68c1eb448e174a9736c39736838151642",
-                        "eda8215107375865a99a57f29467c74c40f37b0221b93ec3f4f22d5337c8bf92",
-                        "45d56936196a92b1dea315ecce8785f9fa9b7d159ca207612cc0deb0957d61db",
-                        "ba5d9bd38784f4fecbf233b04e686a340528665ecd03db8e8a09b2540c84e45c",
-                        "4a99fb338b76bba7722856b5113341c349708937228f167d238ed8efb9cc1954",
-                        "7dd620f6a90d95f07e50bfe102030100010282010002f91b69d9af59fe87421a",
-                        "f9ba60f15c77f9c1c90effd6634332876f8ee5a116b126f55d37038bf9f588ae",
-                        "20c8d951d842e35c9ef35a7822d3ebf72c0b7c3e229b289ae2e178a848e06d55",
-                        "8c2e03d26871ee98a35f370d461ff1c4acc39d684de680a25ec88ee610260e40",
-                        "6c400bdeb2893b2d0330cb483e662fa5abd24c2b82143e85dfe30ae7a31f8262",
-                        "da2903d882b35a34a26b699ff2d812bad4b126a0065ec0e101d73ae6f8b29a91",
-                        "44eb83f54940a371fc7416c2c0370df6a41cb5391f17ba33239e1b4217c8db50",
-                        "db5c6bf77ccf621354ecc652a4f7196054c254566fd7b3bc0f3817d9380b190b",
-                        "d382aaffa37785759f285194c11a188bccde0e2e2902818100fb233335770c9f",
-                        "3cbd4b6ede5f12d03c449b1997bce06a8249bc3de99972fd0d0a633f7790d101",
-                        "1bf5eedee16fa45a9107a910656ecaee364ce9edb4369843be71f27a74852d6c",
-                        "7215a6cc60d9803bcac544922f806d8e5844e0ddd914bd780094904c2856d2b9",
-                        "44fade3fb1d67d4a33fb7663a9ab660ab372c2e4868a0f459902818100bfecf2",
-                        "bb4012e880fd065a0b088f2d757af2878d3f1305f21ce7a715845818e01181ff",
-                        "06b2f406239fc50808ce3dbe7b68ec01174913c0f237feb3c8c7eb0078b77fb5",
-                        "b8f214b72f6d3835b1a7ebe8b132feb6cb34ab09ce22b98160fc8420fcbf48d1",
-                        "eee49f874e902f049b206a61a095f0405a4935e7c5e49757ab7b572989028181",
-                        "00ec0049383e16f3716de5fc5b2677148efe5dceb02483b43399bd3765559994",
-                        "a9f3900eed7a7e9e8f3b0eee0e660eca392e3cb736cae612f39e55dad696d382",
-                        "1def10d1f8bbca52f5e6d8e7893ffbdcb491aafdc17bebf86f84d2d8480ed07a",
-                        "7bf9209d20ef6e79429489d4cb7768281a2f7e32ec1830fd6f633238f521ba76",
-                        "4902818100b2c3ce5751580b4e51df3fb175387f5c24b79040a4d6603c6265f7",
-                        "0018b441ff3aef7d8e4cd2f480ec0906f1c4c0481304e8861f9d4693fa48e3a9",
-                        "abc362859eeb343e1c5507ac94b5439ce7ac04154a2fb886a4819b2a57e18a2e",
-                        "131b412ac4a09b004766959cdf357745f003e272aab3de02e2d5bc2af4ed7576",
-                        "0858ab181902818061d19c2a8dcacde104b97f7c4fae11216157c1c0a258d882",
-                        "984d12383a73dc56fe2ac93512bb321df9706ecdb2f70a44c949c4340a9fae64",
-                        "a0646cf51f37c58c08bebde91667b3b2fa7c895f7983d4786c55261941b36545",
-                        "33b0598383ebbcffcdf28b6cf13d376e3a70b49b14d8d06e8563a247f56a337e",
-                        "3b9845b4f2b61356",
-                    ))
-                    .unwrap(),
-                    hw_enforced: vec![],
-                    sw_enforced: vec![
-                        KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::RSA) },
-                        KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(2048) },
-                        KeyParameter {
-                            tag: Tag::RSA_PUBLIC_EXPONENT,
-                            value: KPV::LongInteger(65537),
-                        },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::SIGN),
-                        },
-                        KeyParameter {
-                            tag: Tag::PURPOSE,
-                            value: KPV::KeyPurpose(KeyPurpose::VERIFY),
-                        },
-                        KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::NONE) },
-                        KeyParameter {
-                            tag: Tag::PADDING,
-                            value: KPV::PaddingMode(PaddingMode::NONE),
-                        },
-                        KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
-                        KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
-                        KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
-                        KeyParameter {
-                            tag: Tag::CREATION_DATETIME,
-                            value: KPV::DateTime(1628871769000),
-                        },
-                        KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
-                        KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
-                    ],
-                },
-                // No support for RSA keys in export_key().
-                None,
-            ),
-        ];
-
-        for (input, want, want_format) in tests {
-            let input = hex::decode(input).unwrap();
-            let got = KeyBlob::new_from_serialized(&input, &hidden).expect("invalid keyblob!");
-            assert!(got == want);
-
-            if let Some(want_format) = want_format {
-                let (got_format, _key_material, params) =
-                    export_key(&input, &[]).expect("invalid keyblob!");
-                assert_eq!(got_format, want_format);
-                // All the test cases are software-only keys.
-                assert_eq!(params, got.sw_enforced);
-            }
-        }
-    }
-
-    #[test]
-    fn test_add_der_len() {
-        let tests = [
-            (0, "00"),
-            (1, "01"),
-            (126, "7e"),
-            (127, "7f"),
-            (128, "8180"),
-            (129, "8181"),
-            (255, "81ff"),
-            (256, "820100"),
-            (257, "820101"),
-            (65535, "82ffff"),
-        ];
-        for (input, want) in tests {
-            let mut got = Vec::new();
-            add_der_len(&mut got, input).unwrap();
-            assert_eq!(hex::encode(got), want, " for input length {input}");
-        }
-    }
-
-    #[test]
-    fn test_pkcs8_wrap_key_p256() {
-        // Key material taken from `ec_256_key` in
-        // hardware/interfaces/security/keymint/aidl/vts/function/KeyMintTest.cpp
-        let input = hex::decode(concat!(
-            "3025",   // SEQUENCE (ECPrivateKey)
-            "020101", // INTEGER length 1 value 1 (version)
-            "0420",   // OCTET STRING (privateKey)
-            "737c2ecd7b8d1940bf2930aa9b4ed3ff",
-            "941eed09366bc03299986481f3a4d859",
-        ))
-        .unwrap();
-        let want = hex::decode(concat!(
-            // RFC 5208 s5
-            "3041",             // SEQUENCE (PrivateKeyInfo) {
-            "020100",           // INTEGER length 1 value 0 (version)
-            "3013",             // SEQUENCE length 0x13 (AlgorithmIdentifier) {
-            "0607",             // OBJECT IDENTIFIER length 7 (algorithm)
-            "2a8648ce3d0201",   // 1.2.840.10045.2.1 (ecPublicKey)
-            "0608",             // OBJECT IDENTIFIER length 8 (param)
-            "2a8648ce3d030107", //  1.2.840.10045.3.1.7 (secp256r1)
-            // } end SEQUENCE (AlgorithmIdentifier)
-            "0427",   // OCTET STRING (privateKey) holding...
-            "3025",   // SEQUENCE (ECPrivateKey)
-            "020101", // INTEGER length 1 value 1 (version)
-            "0420",   // OCTET STRING length 0x20 (privateKey)
-            "737c2ecd7b8d1940bf2930aa9b4ed3ff",
-            "941eed09366bc03299986481f3a4d859",
-            // } end SEQUENCE (ECPrivateKey)
-            // } end SEQUENCE (PrivateKeyInfo)
-        ))
-        .unwrap();
-        let got = pkcs8_wrap_nist_key(&input, EcCurve::P_256).unwrap();
-        assert_eq!(hex::encode(got), hex::encode(want), " for input {}", hex::encode(input));
-    }
-
-    #[test]
-    fn test_pkcs8_wrap_key_p521() {
-        // Key material taken from `ec_521_key` in
-        // hardware/interfaces/security/keymint/aidl/vts/function/KeyMintTest.cpp
-        let input = hex::decode(concat!(
-            "3047",   // SEQUENCE length 0xd3 (ECPrivateKey)
-            "020101", // INTEGER length 1 value 1 (version)
-            "0442",   // OCTET STRING length 0x42 (privateKey)
-            "0011458c586db5daa92afab03f4fe46a",
-            "a9d9c3ce9a9b7a006a8384bec4c78e8e",
-            "9d18d7d08b5bcfa0e53c75b064ad51c4",
-            "49bae0258d54b94b1e885ded08ed4fb2",
-            "5ce9",
-            // } end SEQUENCE (ECPrivateKey)
-        ))
-        .unwrap();
-        let want = hex::decode(concat!(
-            // RFC 5208 s5
-            "3060",           // SEQUENCE (PrivateKeyInfo) {
-            "020100",         // INTEGER length 1 value 0 (version)
-            "3010",           // SEQUENCE length 0x10 (AlgorithmIdentifier) {
-            "0607",           // OBJECT IDENTIFIER length 7 (algorithm)
-            "2a8648ce3d0201", // 1.2.840.10045.2.1 (ecPublicKey)
-            "0605",           // OBJECT IDENTIFIER length 5 (param)
-            "2b81040023",     //  1.3.132.0.35 (secp521r1)
-            // } end SEQUENCE (AlgorithmIdentifier)
-            "0449",   // OCTET STRING (privateKey) holding...
-            "3047",   // SEQUENCE (ECPrivateKey)
-            "020101", // INTEGER length 1 value 1 (version)
-            "0442",   // OCTET STRING length 0x42 (privateKey)
-            "0011458c586db5daa92afab03f4fe46a",
-            "a9d9c3ce9a9b7a006a8384bec4c78e8e",
-            "9d18d7d08b5bcfa0e53c75b064ad51c4",
-            "49bae0258d54b94b1e885ded08ed4fb2",
-            "5ce9",
-            // } end SEQUENCE (ECPrivateKey)
-            // } end SEQUENCE (PrivateKeyInfo)
-        ))
-        .unwrap();
-        let got = pkcs8_wrap_nist_key(&input, EcCurve::P_521).unwrap();
-        assert_eq!(hex::encode(got), hex::encode(want), " for input {}", hex::encode(input));
-    }
-}
diff --git a/keystore2/src/sw_keyblob/tests.rs b/keystore2/src/sw_keyblob/tests.rs
new file mode 100644
index 00000000..fe01112c
--- /dev/null
+++ b/keystore2/src/sw_keyblob/tests.rs
@@ -0,0 +1,449 @@
+// Copyright 2023, The Android Open Source Project
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
+//! Tests for software-backed keyblobs.
+use super::*;
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
+    KeyOrigin::KeyOrigin, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue as KPV,
+    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, Tag::Tag,
+};
+
+macro_rules! expect_err {
+    ($result:expr, $err_msg:expr) => {
+        assert!(
+            $result.is_err(),
+            "Expected error containing '{}', got success {:?}",
+            $err_msg,
+            $result
+        );
+        let err = $result.err();
+        assert!(
+            format!("{:?}", err).contains($err_msg),
+            "Unexpected error {:?}, doesn't contain '{}'",
+            err,
+            $err_msg
+        );
+    };
+}
+
+#[test]
+fn test_consume_u8() {
+    let buffer = [1, 2];
+    let mut data = &buffer[..];
+    assert_eq!(1u8, consume_u8(&mut data).unwrap());
+    assert_eq!(2u8, consume_u8(&mut data).unwrap());
+    let result = consume_u8(&mut data);
+    expect_err!(result, "failed to find 1 byte");
+}
+
+#[test]
+fn test_consume_u32() {
+    // All supported platforms are little-endian.
+    let buffer = [
+        0x01, 0x02, 0x03, 0x04, // little-endian u32
+        0x04, 0x03, 0x02, 0x01, // little-endian u32
+        0x11, 0x12, 0x13,
+    ];
+    let mut data = &buffer[..];
+    assert_eq!(0x04030201u32, consume_u32(&mut data).unwrap());
+    assert_eq!(0x01020304u32, consume_u32(&mut data).unwrap());
+    let result = consume_u32(&mut data);
+    expect_err!(result, "failed to find 4 bytes");
+}
+
+#[test]
+fn test_consume_i64() {
+    // All supported platforms are little-endian.
+    let buffer = [
+        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // little-endian i64
+        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // little-endian i64
+        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
+    ];
+    let mut data = &buffer[..];
+    assert_eq!(0x0807060504030201i64, consume_i64(&mut data).unwrap());
+    assert_eq!(0x0102030405060708i64, consume_i64(&mut data).unwrap());
+    let result = consume_i64(&mut data);
+    expect_err!(result, "failed to find 8 bytes");
+}
+
+#[test]
+fn test_consume_vec() {
+    let buffer = [
+        0x01, 0x00, 0x00, 0x00, 0xaa, //
+        0x00, 0x00, 0x00, 0x00, //
+        0x01, 0x00, 0x00, 0x00, 0xbb, //
+        0x07, 0x00, 0x00, 0x00, 0xbb, // not enough data
+    ];
+    let mut data = &buffer[..];
+    assert_eq!(vec![0xaa], consume_vec(&mut data).unwrap());
+    assert_eq!(Vec::<u8>::new(), consume_vec(&mut data).unwrap());
+    assert_eq!(vec![0xbb], consume_vec(&mut data).unwrap());
+    let result = consume_vec(&mut data);
+    expect_err!(result, "failed to find 7 bytes");
+
+    let buffer = [
+        0x01, 0x00, 0x00, //
+    ];
+    let mut data = &buffer[..];
+    let result = consume_vec(&mut data);
+    expect_err!(result, "failed to find 4 bytes");
+}
+
+#[test]
+fn test_key_new_from_serialized() {
+    let hidden = hidden_params(&[], &[SOFTWARE_ROOT_OF_TRUST]);
+    // Test data originally generated by instrumenting Cuttlefish C++ KeyMint while running VTS
+    // tests.
+    let tests = [
+        (
+            concat!(
+                "0010000000d43c2f04f948521b81bdbf001310f5920000000000000000000000",
+                "00000000000c0000006400000002000010200000000300003080000000010000",
+                "2000000000010000200100000004000020020000000600002001000000be0200",
+                "1000000000c1020030b0ad0100c20200307b150300bd020060a8bb52407b0100",
+                "00ce02003011643401cf020030000000003b06b13ae6ae6671",
+            ),
+            KeyBlob {
+                key_material: hex::decode("d43c2f04f948521b81bdbf001310f592").unwrap(),
+                hw_enforced: vec![],
+                sw_enforced: vec![
+                    KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::AES) },
+                    KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(128) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::ENCRYPT) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::DECRYPT) },
+                    KeyParameter { tag: Tag::BLOCK_MODE, value: KPV::BlockMode(BlockMode::CBC) },
+                    KeyParameter { tag: Tag::PADDING, value: KPV::PaddingMode(PaddingMode::NONE) },
+                    KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
+                    KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
+                    KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
+                    KeyParameter {
+                        tag: Tag::CREATION_DATETIME,
+                        value: KPV::DateTime(1628871769000),
+                    },
+                    KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
+                    KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
+                ],
+            },
+            Some(KeyFormat::RAW),
+        ),
+        (
+            concat!(
+                "00df0000003081dc020101044200b6ce876b947e263d61b8e3998d50dc0afb6b",
+                "a14e46ab7ca532fbe2a379b155d0a5bb99265402857b1601fb20be6c244bf654",
+                "e9e79413cd503eae3d9cf68ed24f47a00706052b81040023a181890381860004",
+                "006b840f0db0b12f074ab916c7773cfa7d42967c9e5b4fae09cf999f7e116d14",
+                "0743bdd028db0a3fcc670e721b9f00bc7fb70aa401c7d6de6582fc26962a29b7",
+                "45e30142e90685646661550344113aaf28bdee6cb02d19df1faab4398556a909",
+                "7d6f64b95209601a549389a311231c6cce78354f2cdbc3a904abf70686f5f0c3",
+                "b877984d000000000000000000000000000000000c0000006400000002000010",
+                "030000000a000010030000000100002002000000010000200300000005000020",
+                "000000000300003009020000be02001000000000c1020030b0ad0100c2020030",
+                "7b150300bd02006018d352407b010000ce02003011643401cf02003000000000",
+                "2f69002e55e9b0a3"
+            ),
+            KeyBlob {
+                key_material: hex::decode(concat!(
+                    "3081dc020101044200b6ce876b947e263d61b8e3998d50dc0afb6ba14e46ab7c",
+                    "a532fbe2a379b155d0a5bb99265402857b1601fb20be6c244bf654e9e79413cd",
+                    "503eae3d9cf68ed24f47a00706052b81040023a181890381860004006b840f0d",
+                    "b0b12f074ab916c7773cfa7d42967c9e5b4fae09cf999f7e116d140743bdd028",
+                    "db0a3fcc670e721b9f00bc7fb70aa401c7d6de6582fc26962a29b745e30142e9",
+                    "0685646661550344113aaf28bdee6cb02d19df1faab4398556a9097d6f64b952",
+                    "09601a549389a311231c6cce78354f2cdbc3a904abf70686f5f0c3b877984d",
+                ))
+                .unwrap(),
+                hw_enforced: vec![],
+                sw_enforced: vec![
+                    KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::EC) },
+                    KeyParameter { tag: Tag::EC_CURVE, value: KPV::EcCurve(EcCurve::P_521) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::SIGN) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::VERIFY) },
+                    KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::NONE) },
+                    KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(521) },
+                    KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
+                    KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
+                    KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
+                    KeyParameter {
+                        tag: Tag::CREATION_DATETIME,
+                        value: KPV::DateTime(1628871775000),
+                    },
+                    KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
+                    KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
+                ],
+            },
+            Some(KeyFormat::PKCS8),
+        ),
+        (
+            concat!(
+                "0037000000541d4c440223650d5f51753c1abd80c725034485551e874d62327c",
+                "65f6247a057f1218bd6c8cd7d319103ddb823fc11fb6c2c7268b5acc00000000",
+                "0000000000000000000000000c00000064000000020000108000000003000030",
+                "b801000001000020020000000100002003000000050000200400000008000030",
+                "00010000be02001000000000c1020030b0ad0100c20200307b150300bd020060",
+                "00d752407b010000ce02003011643401cf0200300000000036e6986ffc45fbb0",
+            ),
+            KeyBlob {
+                key_material: hex::decode(concat!(
+                    "541d4c440223650d5f51753c1abd80c725034485551e874d62327c65f6247a05",
+                    "7f1218bd6c8cd7d319103ddb823fc11fb6c2c7268b5acc"
+                ))
+                .unwrap(),
+                hw_enforced: vec![],
+                sw_enforced: vec![
+                    KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::HMAC) },
+                    KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(440) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::SIGN) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::VERIFY) },
+                    KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::SHA_2_256) },
+                    KeyParameter { tag: Tag::MIN_MAC_LENGTH, value: KPV::Integer(256) },
+                    KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
+                    KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
+                    KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
+                    KeyParameter {
+                        tag: Tag::CREATION_DATETIME,
+                        value: KPV::DateTime(1628871776000),
+                    },
+                    KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
+                    KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
+                ],
+            },
+            Some(KeyFormat::RAW),
+        ),
+        (
+            concat!(
+                "00a8040000308204a40201000282010100bc47b5c71116766669b91fa747df87",
+                "a1963df83956569d4ac232aeba8a246c0ec73bf606374a6d07f30c2162f97082",
+                "825c7c6e482a2841dfeaec1429d84e52c54a6b2f760dec952c9c44a3c3a80f31",
+                "c1ced84878edd4858059071c4d20d9ab0aae978bd68c1eb448e174a9736c3973",
+                "6838151642eda8215107375865a99a57f29467c74c40f37b0221b93ec3f4f22d",
+                "5337c8bf9245d56936196a92b1dea315ecce8785f9fa9b7d159ca207612cc0de",
+                "b0957d61dbba5d9bd38784f4fecbf233b04e686a340528665ecd03db8e8a09b2",
+                "540c84e45c4a99fb338b76bba7722856b5113341c349708937228f167d238ed8",
+                "efb9cc19547dd620f6a90d95f07e50bfe102030100010282010002f91b69d9af",
+                "59fe87421af9ba60f15c77f9c1c90effd6634332876f8ee5a116b126f55d3703",
+                "8bf9f588ae20c8d951d842e35c9ef35a7822d3ebf72c0b7c3e229b289ae2e178",
+                "a848e06d558c2e03d26871ee98a35f370d461ff1c4acc39d684de680a25ec88e",
+                "e610260e406c400bdeb2893b2d0330cb483e662fa5abd24c2b82143e85dfe30a",
+                "e7a31f8262da2903d882b35a34a26b699ff2d812bad4b126a0065ec0e101d73a",
+                "e6f8b29a9144eb83f54940a371fc7416c2c0370df6a41cb5391f17ba33239e1b",
+                "4217c8db50db5c6bf77ccf621354ecc652a4f7196054c254566fd7b3bc0f3817",
+                "d9380b190bd382aaffa37785759f285194c11a188bccde0e2e2902818100fb23",
+                "3335770c9f3cbd4b6ede5f12d03c449b1997bce06a8249bc3de99972fd0d0a63",
+                "3f7790d1011bf5eedee16fa45a9107a910656ecaee364ce9edb4369843be71f2",
+                "7a74852d6c7215a6cc60d9803bcac544922f806d8e5844e0ddd914bd78009490",
+                "4c2856d2b944fade3fb1d67d4a33fb7663a9ab660ab372c2e4868a0f45990281",
+                "8100bfecf2bb4012e880fd065a0b088f2d757af2878d3f1305f21ce7a7158458",
+                "18e01181ff06b2f406239fc50808ce3dbe7b68ec01174913c0f237feb3c8c7eb",
+                "0078b77fb5b8f214b72f6d3835b1a7ebe8b132feb6cb34ab09ce22b98160fc84",
+                "20fcbf48d1eee49f874e902f049b206a61a095f0405a4935e7c5e49757ab7b57",
+                "298902818100ec0049383e16f3716de5fc5b2677148efe5dceb02483b43399bd",
+                "3765559994a9f3900eed7a7e9e8f3b0eee0e660eca392e3cb736cae612f39e55",
+                "dad696d3821def10d1f8bbca52f5e6d8e7893ffbdcb491aafdc17bebf86f84d2",
+                "d8480ed07a7bf9209d20ef6e79429489d4cb7768281a2f7e32ec1830fd6f6332",
+                "38f521ba764902818100b2c3ce5751580b4e51df3fb175387f5c24b79040a4d6",
+                "603c6265f70018b441ff3aef7d8e4cd2f480ec0906f1c4c0481304e8861f9d46",
+                "93fa48e3a9abc362859eeb343e1c5507ac94b5439ce7ac04154a2fb886a4819b",
+                "2a57e18a2e131b412ac4a09b004766959cdf357745f003e272aab3de02e2d5bc",
+                "2af4ed75760858ab181902818061d19c2a8dcacde104b97f7c4fae11216157c1",
+                "c0a258d882984d12383a73dc56fe2ac93512bb321df9706ecdb2f70a44c949c4",
+                "340a9fae64a0646cf51f37c58c08bebde91667b3b2fa7c895f7983d4786c5526",
+                "1941b3654533b0598383ebbcffcdf28b6cf13d376e3a70b49b14d8d06e8563a2",
+                "47f56a337e3b9845b4f2b61356000000000000000000000000000000000d0000",
+                "007000000002000010010000000300003000080000c800005001000100000000",
+                "0001000020020000000100002003000000050000200000000006000020010000",
+                "00be02001000000000c1020030b0ad0100c20200307b150300bd020060a8bb52",
+                "407b010000ce02003011643401cf02003000000000544862e9c961e857",
+            ),
+            KeyBlob {
+                key_material: hex::decode(concat!(
+                    "308204a40201000282010100bc47b5c71116766669b91fa747df87a1963df839",
+                    "56569d4ac232aeba8a246c0ec73bf606374a6d07f30c2162f97082825c7c6e48",
+                    "2a2841dfeaec1429d84e52c54a6b2f760dec952c9c44a3c3a80f31c1ced84878",
+                    "edd4858059071c4d20d9ab0aae978bd68c1eb448e174a9736c39736838151642",
+                    "eda8215107375865a99a57f29467c74c40f37b0221b93ec3f4f22d5337c8bf92",
+                    "45d56936196a92b1dea315ecce8785f9fa9b7d159ca207612cc0deb0957d61db",
+                    "ba5d9bd38784f4fecbf233b04e686a340528665ecd03db8e8a09b2540c84e45c",
+                    "4a99fb338b76bba7722856b5113341c349708937228f167d238ed8efb9cc1954",
+                    "7dd620f6a90d95f07e50bfe102030100010282010002f91b69d9af59fe87421a",
+                    "f9ba60f15c77f9c1c90effd6634332876f8ee5a116b126f55d37038bf9f588ae",
+                    "20c8d951d842e35c9ef35a7822d3ebf72c0b7c3e229b289ae2e178a848e06d55",
+                    "8c2e03d26871ee98a35f370d461ff1c4acc39d684de680a25ec88ee610260e40",
+                    "6c400bdeb2893b2d0330cb483e662fa5abd24c2b82143e85dfe30ae7a31f8262",
+                    "da2903d882b35a34a26b699ff2d812bad4b126a0065ec0e101d73ae6f8b29a91",
+                    "44eb83f54940a371fc7416c2c0370df6a41cb5391f17ba33239e1b4217c8db50",
+                    "db5c6bf77ccf621354ecc652a4f7196054c254566fd7b3bc0f3817d9380b190b",
+                    "d382aaffa37785759f285194c11a188bccde0e2e2902818100fb233335770c9f",
+                    "3cbd4b6ede5f12d03c449b1997bce06a8249bc3de99972fd0d0a633f7790d101",
+                    "1bf5eedee16fa45a9107a910656ecaee364ce9edb4369843be71f27a74852d6c",
+                    "7215a6cc60d9803bcac544922f806d8e5844e0ddd914bd780094904c2856d2b9",
+                    "44fade3fb1d67d4a33fb7663a9ab660ab372c2e4868a0f459902818100bfecf2",
+                    "bb4012e880fd065a0b088f2d757af2878d3f1305f21ce7a715845818e01181ff",
+                    "06b2f406239fc50808ce3dbe7b68ec01174913c0f237feb3c8c7eb0078b77fb5",
+                    "b8f214b72f6d3835b1a7ebe8b132feb6cb34ab09ce22b98160fc8420fcbf48d1",
+                    "eee49f874e902f049b206a61a095f0405a4935e7c5e49757ab7b572989028181",
+                    "00ec0049383e16f3716de5fc5b2677148efe5dceb02483b43399bd3765559994",
+                    "a9f3900eed7a7e9e8f3b0eee0e660eca392e3cb736cae612f39e55dad696d382",
+                    "1def10d1f8bbca52f5e6d8e7893ffbdcb491aafdc17bebf86f84d2d8480ed07a",
+                    "7bf9209d20ef6e79429489d4cb7768281a2f7e32ec1830fd6f633238f521ba76",
+                    "4902818100b2c3ce5751580b4e51df3fb175387f5c24b79040a4d6603c6265f7",
+                    "0018b441ff3aef7d8e4cd2f480ec0906f1c4c0481304e8861f9d4693fa48e3a9",
+                    "abc362859eeb343e1c5507ac94b5439ce7ac04154a2fb886a4819b2a57e18a2e",
+                    "131b412ac4a09b004766959cdf357745f003e272aab3de02e2d5bc2af4ed7576",
+                    "0858ab181902818061d19c2a8dcacde104b97f7c4fae11216157c1c0a258d882",
+                    "984d12383a73dc56fe2ac93512bb321df9706ecdb2f70a44c949c4340a9fae64",
+                    "a0646cf51f37c58c08bebde91667b3b2fa7c895f7983d4786c55261941b36545",
+                    "33b0598383ebbcffcdf28b6cf13d376e3a70b49b14d8d06e8563a247f56a337e",
+                    "3b9845b4f2b61356",
+                ))
+                .unwrap(),
+                hw_enforced: vec![],
+                sw_enforced: vec![
+                    KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::RSA) },
+                    KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(2048) },
+                    KeyParameter { tag: Tag::RSA_PUBLIC_EXPONENT, value: KPV::LongInteger(65537) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::SIGN) },
+                    KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::VERIFY) },
+                    KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::NONE) },
+                    KeyParameter { tag: Tag::PADDING, value: KPV::PaddingMode(PaddingMode::NONE) },
+                    KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
+                    KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(110000) },
+                    KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202107) },
+                    KeyParameter {
+                        tag: Tag::CREATION_DATETIME,
+                        value: KPV::DateTime(1628871769000),
+                    },
+                    KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20210705) },
+                    KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(0) },
+                ],
+            },
+            // No support for RSA keys in export_key().
+            None,
+        ),
+    ];
+
+    for (input, want, want_format) in tests {
+        let input = hex::decode(input).unwrap();
+        let got = KeyBlob::new_from_serialized(&input, &hidden).expect("invalid keyblob!");
+        assert!(got == want);
+
+        if let Some(want_format) = want_format {
+            let (got_format, _key_material, params) =
+                export_key(&input, &[]).expect("invalid keyblob!");
+            assert_eq!(got_format, want_format);
+            // All the test cases are software-only keys.
+            assert_eq!(params, got.sw_enforced);
+        }
+    }
+}
+
+#[test]
+fn test_add_der_len() {
+    let tests = [
+        (0, "00"),
+        (1, "01"),
+        (126, "7e"),
+        (127, "7f"),
+        (128, "8180"),
+        (129, "8181"),
+        (255, "81ff"),
+        (256, "820100"),
+        (257, "820101"),
+        (65535, "82ffff"),
+    ];
+    for (input, want) in tests {
+        let mut got = Vec::new();
+        add_der_len(&mut got, input).unwrap();
+        assert_eq!(hex::encode(got), want, " for input length {input}");
+    }
+}
+
+#[test]
+fn test_pkcs8_wrap_key_p256() {
+    // Key material taken from `ec_256_key` in
+    // hardware/interfaces/security/keymint/aidl/vts/function/KeyMintTest.cpp
+    let input = hex::decode(concat!(
+        "3025",   // SEQUENCE (ECPrivateKey)
+        "020101", // INTEGER length 1 value 1 (version)
+        "0420",   // OCTET STRING (privateKey)
+        "737c2ecd7b8d1940bf2930aa9b4ed3ff",
+        "941eed09366bc03299986481f3a4d859",
+    ))
+    .unwrap();
+    let want = hex::decode(concat!(
+        // RFC 5208 s5
+        "3041",             // SEQUENCE (PrivateKeyInfo) {
+        "020100",           // INTEGER length 1 value 0 (version)
+        "3013",             // SEQUENCE length 0x13 (AlgorithmIdentifier) {
+        "0607",             // OBJECT IDENTIFIER length 7 (algorithm)
+        "2a8648ce3d0201",   // 1.2.840.10045.2.1 (ecPublicKey)
+        "0608",             // OBJECT IDENTIFIER length 8 (param)
+        "2a8648ce3d030107", //  1.2.840.10045.3.1.7 (secp256r1)
+        // } end SEQUENCE (AlgorithmIdentifier)
+        "0427",   // OCTET STRING (privateKey) holding...
+        "3025",   // SEQUENCE (ECPrivateKey)
+        "020101", // INTEGER length 1 value 1 (version)
+        "0420",   // OCTET STRING length 0x20 (privateKey)
+        "737c2ecd7b8d1940bf2930aa9b4ed3ff",
+        "941eed09366bc03299986481f3a4d859",
+        // } end SEQUENCE (ECPrivateKey)
+        // } end SEQUENCE (PrivateKeyInfo)
+    ))
+    .unwrap();
+    let got = pkcs8_wrap_nist_key(&input, EcCurve::P_256).unwrap();
+    assert_eq!(hex::encode(got), hex::encode(want), " for input {}", hex::encode(input));
+}
+
+#[test]
+fn test_pkcs8_wrap_key_p521() {
+    // Key material taken from `ec_521_key` in
+    // hardware/interfaces/security/keymint/aidl/vts/function/KeyMintTest.cpp
+    let input = hex::decode(concat!(
+        "3047",   // SEQUENCE length 0xd3 (ECPrivateKey)
+        "020101", // INTEGER length 1 value 1 (version)
+        "0442",   // OCTET STRING length 0x42 (privateKey)
+        "0011458c586db5daa92afab03f4fe46a",
+        "a9d9c3ce9a9b7a006a8384bec4c78e8e",
+        "9d18d7d08b5bcfa0e53c75b064ad51c4",
+        "49bae0258d54b94b1e885ded08ed4fb2",
+        "5ce9",
+        // } end SEQUENCE (ECPrivateKey)
+    ))
+    .unwrap();
+    let want = hex::decode(concat!(
+        // RFC 5208 s5
+        "3060",           // SEQUENCE (PrivateKeyInfo) {
+        "020100",         // INTEGER length 1 value 0 (version)
+        "3010",           // SEQUENCE length 0x10 (AlgorithmIdentifier) {
+        "0607",           // OBJECT IDENTIFIER length 7 (algorithm)
+        "2a8648ce3d0201", // 1.2.840.10045.2.1 (ecPublicKey)
+        "0605",           // OBJECT IDENTIFIER length 5 (param)
+        "2b81040023",     //  1.3.132.0.35 (secp521r1)
+        // } end SEQUENCE (AlgorithmIdentifier)
+        "0449",   // OCTET STRING (privateKey) holding...
+        "3047",   // SEQUENCE (ECPrivateKey)
+        "020101", // INTEGER length 1 value 1 (version)
+        "0442",   // OCTET STRING length 0x42 (privateKey)
+        "0011458c586db5daa92afab03f4fe46a",
+        "a9d9c3ce9a9b7a006a8384bec4c78e8e",
+        "9d18d7d08b5bcfa0e53c75b064ad51c4",
+        "49bae0258d54b94b1e885ded08ed4fb2",
+        "5ce9",
+        // } end SEQUENCE (ECPrivateKey)
+        // } end SEQUENCE (PrivateKeyInfo)
+    ))
+    .unwrap();
+    let got = pkcs8_wrap_nist_key(&input, EcCurve::P_521).unwrap();
+    assert_eq!(hex::encode(got), hex::encode(want), " for input {}", hex::encode(input));
+}
diff --git a/keystore2/src/utils.rs b/keystore2/src/utils.rs
index 196cac55..2b69d1ef 100644
--- a/keystore2/src/utils.rs
+++ b/keystore2/src/utils.rs
@@ -38,16 +38,23 @@ use android_security_apc::aidl::android::security::apc::{
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     Authorization::Authorization, Domain::Domain, KeyDescriptor::KeyDescriptor,
+    ResponseCode::ResponseCode,
 };
 use anyhow::{Context, Result};
-use binder::{Strong, ThreadState};
+use binder::{FromIBinder, StatusCode, Strong, ThreadState};
 use keystore2_apc_compat::{
     ApcCompatUiOptions, APC_COMPAT_ERROR_ABORTED, APC_COMPAT_ERROR_CANCELLED,
     APC_COMPAT_ERROR_IGNORED, APC_COMPAT_ERROR_OK, APC_COMPAT_ERROR_OPERATION_PENDING,
     APC_COMPAT_ERROR_SYSTEM_ERROR,
 };
 use keystore2_crypto::{aes_gcm_decrypt, aes_gcm_encrypt, ZVec};
+use log::{info, warn};
 use std::iter::IntoIterator;
+use std::thread::sleep;
+use std::time::Duration;
+
+#[cfg(test)]
+mod tests;
 
 /// Per RFC 5280 4.1.2.5, an undefined expiration (not-after) field should be set to GeneralizedTime
 /// 999912312359559, which is 253402300799000 ms from Jan 1, 1970.
@@ -119,14 +126,20 @@ pub fn is_device_id_attestation_tag(tag: Tag) -> bool {
 /// identifiers. It throws an error if the permissions cannot be verified or if the caller doesn't
 /// have the right permissions. Otherwise it returns silently.
 pub fn check_device_attestation_permissions() -> anyhow::Result<()> {
-    check_android_permission("android.permission.READ_PRIVILEGED_PHONE_STATE")
+    check_android_permission(
+        "android.permission.READ_PRIVILEGED_PHONE_STATE",
+        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
+    )
 }
 
 /// This function checks whether the calling app has the Android permissions needed to attest the
 /// device-unique identifier. It throws an error if the permissions cannot be verified or if the
 /// caller doesn't have the right permissions. Otherwise it returns silently.
 pub fn check_unique_id_attestation_permissions() -> anyhow::Result<()> {
-    check_android_permission("android.permission.REQUEST_UNIQUE_ID_ATTESTATION")
+    check_android_permission(
+        "android.permission.REQUEST_UNIQUE_ID_ATTESTATION",
+        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
+    )
 }
 
 /// This function checks whether the calling app has the Android permissions needed to manage
@@ -135,16 +148,24 @@ pub fn check_unique_id_attestation_permissions() -> anyhow::Result<()> {
 /// It throws an error if the permissions cannot be verified or if the caller doesn't
 /// have the right permissions. Otherwise it returns silently.
 pub fn check_get_app_uids_affected_by_sid_permissions() -> anyhow::Result<()> {
-    check_android_permission("android.permission.MANAGE_USERS")
+    check_android_permission(
+        "android.permission.MANAGE_USERS",
+        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
+    )
 }
 
-fn check_android_permission(permission: &str) -> anyhow::Result<()> {
+/// This function checks whether the calling app has the Android permission needed to dump
+/// Keystore state to logcat.
+pub fn check_dump_permission() -> anyhow::Result<()> {
+    check_android_permission("android.permission.DUMP", Error::Rc(ResponseCode::PERMISSION_DENIED))
+}
+
+fn check_android_permission(permission: &str, err: Error) -> anyhow::Result<()> {
     let permission_controller: Strong<dyn IPermissionController::IPermissionController> =
         binder::get_interface("permission")?;
 
     let binder_result = {
-        let _wp =
-            watchdog::watch("In check_device_attestation_permissions: calling checkPermission.");
+        let _wp = watchdog::watch("check_android_permission: calling checkPermission");
         permission_controller.checkPermission(
             permission,
             ThreadState::get_calling_pid(),
@@ -155,8 +176,7 @@ fn check_android_permission(permission: &str) -> anyhow::Result<()> {
         map_binder_status(binder_result).context(ks_err!("checkPermission failed"))?;
     match has_permissions {
         true => Ok(()),
-        false => Err(Error::Km(ErrorCode::CANNOT_ATTEST_IDS))
-            .context(ks_err!("caller does not have the permission to attest device IDs")),
+        false => Err(err).context(ks_err!("caller does not have the '{permission}' permission")),
     }
 }
 
@@ -261,7 +281,9 @@ where
     log::debug!("import parameters={import_params:?}");
 
     let creation_result = {
-        let _wp = watchdog::watch("In utils::import_keyblob_and_perform_op: calling importKey.");
+        let _wp = watchdog::watch(
+            "utils::import_keyblob_and_perform_op: calling IKeyMintDevice::importKey",
+        );
         map_km_error(km_dev.importKey(&import_params, format, &key_material, None))
     }
     .context(ks_err!("Upgrade failed."))?;
@@ -301,7 +323,9 @@ where
     NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
 {
     let upgraded_blob = {
-        let _wp = watchdog::watch("In utils::upgrade_keyblob_and_perform_op: calling upgradeKey.");
+        let _wp = watchdog::watch(
+            "utils::upgrade_keyblob_and_perform_op: calling IKeyMintDevice::upgradeKey.",
+        );
         map_km_error(km_dev.upgradeKey(key_blob, upgrade_params))
     }
     .context(ks_err!("Upgrade failed."))?;
@@ -513,7 +537,9 @@ fn merge_and_filter_key_entry_lists(
     result
 }
 
-fn estimate_safe_amount_to_return(
+pub(crate) fn estimate_safe_amount_to_return(
+    domain: Domain,
+    namespace: i64,
     key_descriptors: &[KeyDescriptor],
     response_size_limit: usize,
 ) -> usize {
@@ -538,11 +564,9 @@ fn estimate_safe_amount_to_return(
         // 350KB and return a partial list.
         if returned_bytes > response_size_limit {
             log::warn!(
-                "Key descriptors list ({} items) may exceed binder \
-                       size, returning {} items est {} bytes.",
+                "{domain:?}:{namespace}: Key descriptors list ({} items) may exceed binder \
+                       size, returning {items_to_return} items est {returned_bytes} bytes.",
                 key_descriptors.len(),
-                items_to_return,
-                returned_bytes
             );
             break;
         }
@@ -551,6 +575,9 @@ fn estimate_safe_amount_to_return(
     items_to_return
 }
 
+/// Estimate for maximum size of a Binder response in bytes.
+pub(crate) const RESPONSE_SIZE_LIMIT: usize = 358400;
+
 /// List all key aliases for a given domain + namespace. whose alias is greater
 /// than start_past_alias (if provided).
 pub fn list_key_entries(
@@ -574,9 +601,8 @@ pub fn list_key_entries(
         start_past_alias,
     );
 
-    const RESPONSE_SIZE_LIMIT: usize = 358400;
     let safe_amount_to_return =
-        estimate_safe_amount_to_return(&merged_key_entries, RESPONSE_SIZE_LIMIT);
+        estimate_safe_amount_to_return(domain, namespace, &merged_key_entries, RESPONSE_SIZE_LIMIT);
     Ok(merged_key_entries[..safe_amount_to_return].to_vec())
 }
 
@@ -591,6 +617,15 @@ pub fn count_key_entries(db: &mut KeystoreDB, domain: Domain, namespace: i64) ->
     Ok((legacy_keys.len() + num_keys_in_db) as i32)
 }
 
+/// For params remove sensitive data before returning a string for logging
+pub fn log_security_safe_params(params: &[KmKeyParameter]) -> Vec<KmKeyParameter> {
+    params
+        .iter()
+        .filter(|kp| (kp.tag != Tag::APPLICATION_ID && kp.tag != Tag::APPLICATION_DATA))
+        .cloned()
+        .collect::<Vec<KmKeyParameter>>()
+}
+
 /// Trait implemented by objects that can be used to decrypt cipher text using AES-GCM.
 pub trait AesGcm {
     /// Deciphers `data` using the initialization vector `iv` and AEAD tag `tag`
@@ -620,100 +655,24 @@ impl<T: AesGcmKey> AesGcm for T {
     }
 }
 
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use anyhow::Result;
-
-    #[test]
-    fn check_device_attestation_permissions_test() -> Result<()> {
-        check_device_attestation_permissions().or_else(|error| {
-            match error.root_cause().downcast_ref::<Error>() {
-                // Expected: the context for this test might not be allowed to attest device IDs.
-                Some(Error::Km(ErrorCode::CANNOT_ATTEST_IDS)) => Ok(()),
-                // Other errors are unexpected
-                _ => Err(error),
+pub(crate) fn retry_get_interface<T: FromIBinder + ?Sized>(
+    name: &str,
+) -> Result<Strong<T>, StatusCode> {
+    let retry_count = if cfg!(early_vm) { 5 } else { 1 };
+
+    let mut wait_time = Duration::from_secs(5);
+    for i in 1..retry_count {
+        match binder::get_interface(name) {
+            Ok(res) => return Ok(res),
+            Err(e) => {
+                warn!("failed to get interface {name}. Retry {i}/{retry_count}: {e:?}");
+                sleep(wait_time);
+                wait_time *= 2;
             }
-        })
-    }
-
-    fn create_key_descriptors_from_aliases(key_aliases: &[&str]) -> Vec<KeyDescriptor> {
-        key_aliases
-            .iter()
-            .map(|key_alias| KeyDescriptor {
-                domain: Domain::APP,
-                nspace: 0,
-                alias: Some(key_alias.to_string()),
-                blob: None,
-            })
-            .collect::<Vec<KeyDescriptor>>()
-    }
-
-    fn aliases_from_key_descriptors(key_descriptors: &[KeyDescriptor]) -> Vec<String> {
-        key_descriptors
-            .iter()
-            .map(
-                |kd| {
-                    if let Some(alias) = &kd.alias {
-                        String::from(alias)
-                    } else {
-                        String::from("")
-                    }
-                },
-            )
-            .collect::<Vec<String>>()
-    }
-
-    #[test]
-    fn test_safe_amount_to_return() -> Result<()> {
-        let key_aliases = vec!["key1", "key2", "key3"];
-        let key_descriptors = create_key_descriptors_from_aliases(&key_aliases);
-
-        assert_eq!(estimate_safe_amount_to_return(&key_descriptors, 20), 1);
-        assert_eq!(estimate_safe_amount_to_return(&key_descriptors, 50), 2);
-        assert_eq!(estimate_safe_amount_to_return(&key_descriptors, 100), 3);
-        Ok(())
-    }
-
-    #[test]
-    fn test_merge_and_sort_lists_without_filtering() -> Result<()> {
-        let legacy_key_aliases = vec!["key_c", "key_a", "key_b"];
-        let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
-        let db_key_aliases = vec!["key_a", "key_d"];
-        let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
-        let result =
-            merge_and_filter_key_entry_lists(&legacy_key_descriptors, &db_key_descriptors, None);
-        assert_eq!(aliases_from_key_descriptors(&result), vec!["key_a", "key_b", "key_c", "key_d"]);
-        Ok(())
-    }
-
-    #[test]
-    fn test_merge_and_sort_lists_with_filtering() -> Result<()> {
-        let legacy_key_aliases = vec!["key_f", "key_a", "key_e", "key_b"];
-        let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
-        let db_key_aliases = vec!["key_c", "key_g"];
-        let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
-        let result = merge_and_filter_key_entry_lists(
-            &legacy_key_descriptors,
-            &db_key_descriptors,
-            Some("key_b"),
-        );
-        assert_eq!(aliases_from_key_descriptors(&result), vec!["key_c", "key_e", "key_f", "key_g"]);
-        Ok(())
+        }
     }
-
-    #[test]
-    fn test_merge_and_sort_lists_with_filtering_and_dups() -> Result<()> {
-        let legacy_key_aliases = vec!["key_f", "key_a", "key_e", "key_b"];
-        let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
-        let db_key_aliases = vec!["key_d", "key_e", "key_g"];
-        let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
-        let result = merge_and_filter_key_entry_lists(
-            &legacy_key_descriptors,
-            &db_key_descriptors,
-            Some("key_c"),
-        );
-        assert_eq!(aliases_from_key_descriptors(&result), vec!["key_d", "key_e", "key_f", "key_g"]);
-        Ok(())
+    if retry_count > 1 {
+        info!("{retry_count}-th (last) retry to get interface: {name}");
     }
+    binder::get_interface(name)
 }
diff --git a/keystore2/src/utils/tests.rs b/keystore2/src/utils/tests.rs
new file mode 100644
index 00000000..618ea472
--- /dev/null
+++ b/keystore2/src/utils/tests.rs
@@ -0,0 +1,125 @@
+// Copyright 2020, The Android Open Source Project
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
+//! Utility functions tests.
+
+use super::*;
+use anyhow::Result;
+
+#[test]
+fn check_device_attestation_permissions_test() -> Result<()> {
+    check_device_attestation_permissions().or_else(|error| {
+        match error.root_cause().downcast_ref::<Error>() {
+            // Expected: the context for this test might not be allowed to attest device IDs.
+            Some(Error::Km(ErrorCode::CANNOT_ATTEST_IDS)) => Ok(()),
+            // Other errors are unexpected
+            _ => Err(error),
+        }
+    })
+}
+
+fn create_key_descriptors_from_aliases(key_aliases: &[&str]) -> Vec<KeyDescriptor> {
+    key_aliases
+        .iter()
+        .map(|key_alias| KeyDescriptor {
+            domain: Domain::APP,
+            nspace: 0,
+            alias: Some(key_alias.to_string()),
+            blob: None,
+        })
+        .collect::<Vec<KeyDescriptor>>()
+}
+
+fn aliases_from_key_descriptors(key_descriptors: &[KeyDescriptor]) -> Vec<String> {
+    key_descriptors
+        .iter()
+        .map(|kd| if let Some(alias) = &kd.alias { String::from(alias) } else { String::from("") })
+        .collect::<Vec<String>>()
+}
+
+#[test]
+fn test_safe_amount_to_return() -> Result<()> {
+    let key_aliases = vec!["key1", "key2", "key3"];
+    let key_descriptors = create_key_descriptors_from_aliases(&key_aliases);
+
+    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, &key_descriptors, 20), 1);
+    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, &key_descriptors, 50), 2);
+    assert_eq!(estimate_safe_amount_to_return(Domain::APP, 1017, &key_descriptors, 100), 3);
+    Ok(())
+}
+
+#[test]
+fn test_merge_and_sort_lists_without_filtering() -> Result<()> {
+    let legacy_key_aliases = vec!["key_c", "key_a", "key_b"];
+    let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
+    let db_key_aliases = vec!["key_a", "key_d"];
+    let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
+    let result =
+        merge_and_filter_key_entry_lists(&legacy_key_descriptors, &db_key_descriptors, None);
+    assert_eq!(aliases_from_key_descriptors(&result), vec!["key_a", "key_b", "key_c", "key_d"]);
+    Ok(())
+}
+
+#[test]
+fn test_merge_and_sort_lists_with_filtering() -> Result<()> {
+    let legacy_key_aliases = vec!["key_f", "key_a", "key_e", "key_b"];
+    let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
+    let db_key_aliases = vec!["key_c", "key_g"];
+    let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
+    let result = merge_and_filter_key_entry_lists(
+        &legacy_key_descriptors,
+        &db_key_descriptors,
+        Some("key_b"),
+    );
+    assert_eq!(aliases_from_key_descriptors(&result), vec!["key_c", "key_e", "key_f", "key_g"]);
+    Ok(())
+}
+
+#[test]
+fn test_merge_and_sort_lists_with_filtering_and_dups() -> Result<()> {
+    let legacy_key_aliases = vec!["key_f", "key_a", "key_e", "key_b"];
+    let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
+    let db_key_aliases = vec!["key_d", "key_e", "key_g"];
+    let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
+    let result = merge_and_filter_key_entry_lists(
+        &legacy_key_descriptors,
+        &db_key_descriptors,
+        Some("key_c"),
+    );
+    assert_eq!(aliases_from_key_descriptors(&result), vec!["key_d", "key_e", "key_f", "key_g"]);
+    Ok(())
+}
+
+#[test]
+fn test_list_key_parameters_with_filter_on_security_sensitive_info() -> Result<()> {
+    let params = vec![
+        KmKeyParameter { tag: Tag::APPLICATION_ID, value: KeyParameterValue::Integer(0) },
+        KmKeyParameter { tag: Tag::APPLICATION_DATA, value: KeyParameterValue::Integer(0) },
+        KmKeyParameter {
+            tag: Tag::CERTIFICATE_NOT_AFTER,
+            value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
+        },
+        KmKeyParameter { tag: Tag::CERTIFICATE_NOT_BEFORE, value: KeyParameterValue::DateTime(0) },
+    ];
+    let wanted = vec![
+        KmKeyParameter {
+            tag: Tag::CERTIFICATE_NOT_AFTER,
+            value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
+        },
+        KmKeyParameter { tag: Tag::CERTIFICATE_NOT_BEFORE, value: KeyParameterValue::DateTime(0) },
+    ];
+
+    assert_eq!(log_security_safe_params(&params), wanted);
+    Ok(())
+}
diff --git a/keystore2/src/watchdog_helper.rs b/keystore2/src/watchdog_helper.rs
index 03c77400..63383aab 100644
--- a/keystore2/src/watchdog_helper.rs
+++ b/keystore2/src/watchdog_helper.rs
@@ -17,8 +17,7 @@
 /// This module provides helpers for simplified use of the watchdog module.
 #[cfg(feature = "watchdog")]
 pub mod watchdog {
-    use lazy_static::lazy_static;
-    use std::sync::Arc;
+    use std::sync::{Arc, LazyLock};
     use std::time::Duration;
     pub use watchdog_rs::WatchPoint;
     use watchdog_rs::Watchdog;
@@ -28,10 +27,8 @@ pub mod watchdog {
 
     const DEFAULT_TIMEOUT: Duration = Duration::from_millis(DEFAULT_TIMEOUT_MS);
 
-    lazy_static! {
-        /// A Watchdog thread, that can be used to create watch points.
-        static ref WD: Arc<Watchdog> = Watchdog::new(Duration::from_secs(10));
-    }
+    /// A Watchdog thread, that can be used to create watch points.
+    static WD: LazyLock<Arc<Watchdog>> = LazyLock::new(|| Watchdog::new(Duration::from_secs(10)));
 
     /// Sets a watch point with `id` and a timeout of `millis` milliseconds.
     pub fn watch_millis(id: &'static str, millis: u64) -> Option<WatchPoint> {
@@ -43,14 +40,14 @@ pub mod watchdog {
         Watchdog::watch(&WD, id, DEFAULT_TIMEOUT)
     }
 
-    /// Like `watch_millis` but with a callback that is called every time a report
-    /// is printed about this watch point.
+    /// Like `watch_millis` but with context that is included every time a report is printed about
+    /// this watch point.
     pub fn watch_millis_with(
         id: &'static str,
         millis: u64,
-        callback: impl Fn() -> String + Send + 'static,
+        context: impl std::fmt::Debug + Send + 'static,
     ) -> Option<WatchPoint> {
-        Watchdog::watch_with(&WD, id, Duration::from_millis(millis), callback)
+        Watchdog::watch_with(&WD, id, Duration::from_millis(millis), context)
     }
 }
 
@@ -71,7 +68,7 @@ pub mod watchdog {
     pub fn watch_millis_with(
         _: &'static str,
         _: u64,
-        _: impl Fn() -> String + Send + 'static,
+        _: impl std::fmt::Debug + Send + 'static,
     ) -> Option<WatchPoint> {
         None
     }
diff --git a/keystore2/test_utils/Android.bp b/keystore2/test_utils/Android.bp
index 4c7c18a4..d0b55401 100644
--- a/keystore2/test_utils/Android.bp
+++ b/keystore2/test_utils/Android.bp
@@ -42,15 +42,15 @@ rust_defaults {
         "libthiserror",
     ],
     static_libs: [
+        "libcppbor",
+        "libkeymaster_portable",
+        "libkeymint_support",
         "libkeystore-engine",
         "libkeystore2_ffi_test_utils",
     ],
     shared_libs: [
-        "android.system.keystore2-V4-ndk",
         "libbase",
         "libcrypto",
-        "libkeymaster_portable",
-        "libkeymint_support",
     ],
 }
 
@@ -59,6 +59,12 @@ rust_library {
     crate_name: "keystore2_test_utils",
     srcs: ["lib.rs"],
     defaults: ["libkeystore2_test_utils_defaults"],
+    static_libs: [
+        // Also include static_libs for the NDK variants so that they are available
+        // for dependencies.
+        "android.system.keystore2-V4-ndk",
+        "android.hardware.security.keymint-V3-ndk",
+    ],
 }
 
 rust_test {
@@ -75,20 +81,22 @@ cc_library_static {
     name: "libkeystore2_ffi_test_utils",
     srcs: ["ffi_test_utils.cpp"],
     defaults: [
-        "keymint_use_latest_hal_aidl_ndk_shared",
-        "keystore2_use_latest_aidl_ndk_shared",
+        "keymint_use_latest_hal_aidl_ndk_static",
+        "keystore2_use_latest_aidl_ndk_static",
     ],
     generated_headers: [
         "cxx-bridge-header",
         "libkeystore2_ffi_test_utils_bridge_header",
     ],
     generated_sources: ["libkeystore2_ffi_test_utils_bridge_code"],
-    static_libs: ["libkeystore-engine"],
+    static_libs: [
+        "libkeymaster_portable",
+        "libkeymint_support",
+        "libkeystore-engine",
+    ],
     shared_libs: [
         "libbase",
         "libcrypto",
-        "libkeymaster_portable",
-        "libkeymint_support",
     ],
 }
 
diff --git a/keystore2/test_utils/authorizations.rs b/keystore2/test_utils/authorizations.rs
index 2cb2aaf6..a96d9946 100644
--- a/keystore2/test_utils/authorizations.rs
+++ b/keystore2/test_utils/authorizations.rs
@@ -360,6 +360,15 @@ impl AuthSetBuilder {
         });
         self
     }
+
+    /// Set unlocked-device-required
+    pub fn unlocked_device_required(mut self) -> Self {
+        self.0.push(KeyParameter {
+            tag: Tag::UNLOCKED_DEVICE_REQUIRED,
+            value: KeyParameterValue::BoolValue(true),
+        });
+        self
+    }
 }
 
 impl Deref for AuthSetBuilder {
diff --git a/keystore2/test_utils/key_generations.rs b/keystore2/test_utils/key_generations.rs
index a733be39..e63ee60f 100644
--- a/keystore2/test_utils/key_generations.rs
+++ b/keystore2/test_utils/key_generations.rs
@@ -14,14 +14,12 @@
 
 //! This module implements test utils to generate various types of keys.
 
-use anyhow::Result;
-use core::ops::Range;
-use nix::unistd::getuid;
-use std::collections::HashSet;
-use std::fmt::Write;
-
-use binder::ThreadState;
-
+use crate::authorizations::AuthSetBuilder;
+use crate::ffi_test_utils::{
+    get_os_patchlevel, get_os_version, get_value_from_attest_record, get_vendor_patchlevel,
+    validate_certchain_with_strict_issuer_check,
+};
+use crate::SecLevel;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
     ErrorCode::ErrorCode, HardwareAuthenticatorType::HardwareAuthenticatorType,
@@ -30,18 +28,17 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     AuthenticatorSpec::AuthenticatorSpec, Authorization::Authorization,
-    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
-    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
+    CreateOperationResponse::CreateOperationResponse, Domain::Domain, KeyDescriptor::KeyDescriptor,
     KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
 };
-
-use crate::authorizations::AuthSetBuilder;
 use android_system_keystore2::binder::{ExceptionCode, Result as BinderResult};
-
-use crate::ffi_test_utils::{
-    get_os_patchlevel, get_os_version, get_value_from_attest_record, get_vendor_patchlevel,
-    validate_certchain_with_strict_issuer_check,
-};
+use anyhow::Result;
+use binder::ThreadState;
+use core::ops::Range;
+use nix::unistd::getuid;
+use std::collections::HashSet;
+use std::fmt::Write;
+use std::path::PathBuf;
 
 /// Shell namespace.
 pub const SELINUX_SHELL_NAMESPACE: i64 = 1;
@@ -54,6 +51,10 @@ pub const TARGET_SU_CTX: &str = "u:r:su:s0";
 /// Vold context
 pub const TARGET_VOLD_CTX: &str = "u:r:vold:s0";
 
+const TEE_KEYMINT_RKP_ONLY: &str = "remote_provisioning.tee.rkp_only";
+
+const STRONGBOX_KEYMINT_RKP_ONLY: &str = "remote_provisioning.strongbox.rkp_only";
+
 /// Allowed tags in generated/imported key authorizations.
 /// See hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl for the
 /// list feature tags.
@@ -391,10 +392,31 @@ pub fn map_ks_error<T>(r: BinderResult<T>) -> Result<T, Error> {
     })
 }
 
-/// Indicate whether the default device is KeyMint (rather than Keymaster).
-pub fn has_default_keymint() -> bool {
-    binder::is_declared("android.hardware.security.keymint.IKeyMintDevice/default")
-        .expect("Could not check for declared keymint interface")
+/// Get the value of the given system property, if the given system property doesn't exist
+/// then returns an empty byte vector.
+pub fn get_system_prop(name: &str) -> Vec<u8> {
+    match rustutils::system_properties::read(name) {
+        Ok(Some(value)) => value.as_bytes().to_vec(),
+        _ => vec![],
+    }
+}
+
+/// Determines whether test is running on GSI.
+pub fn is_gsi() -> bool {
+    // This file is only present on GSI builds.
+    PathBuf::from("/system/system_ext/etc/init/init.gsi.rc").as_path().is_file()
+}
+
+/// Determines whether the test is on a GSI build where the rkp-only status of the device is
+/// unknown. GSI replaces the values for remote_prov_prop properties (since they’re
+/// system_internal_prop properties), so on GSI the properties are not reliable indicators of
+/// whether StrongBox/TEE is RKP-only or not.
+pub fn is_rkp_only_unknown_on_gsi(sec_level: SecurityLevel) -> bool {
+    if sec_level == SecurityLevel::TRUSTED_ENVIRONMENT {
+        is_gsi() && get_system_prop(TEE_KEYMINT_RKP_ONLY).is_empty()
+    } else {
+        is_gsi() && get_system_prop(STRONGBOX_KEYMINT_RKP_ONLY).is_empty()
+    }
 }
 
 /// Verify that given key param is listed in given authorizations list.
@@ -404,15 +426,15 @@ pub fn check_key_param(authorizations: &[Authorization], key_param: &KeyParamete
 
 /// Verify the given key authorizations with the expected authorizations.
 pub fn check_key_authorizations(
+    sl: &SecLevel,
     authorizations: &[Authorization],
     expected_params: &[KeyParameter],
     expected_key_origin: KeyOrigin,
 ) {
     // Make sure key authorizations contains only `ALLOWED_TAGS_IN_KEY_AUTHS`
     authorizations.iter().all(|auth| {
-        // Ignore `INVALID` tag if the backend is Keymaster and not KeyMint.
-        // Keymaster allows INVALID tag for unsupported key parameters.
-        if !has_default_keymint() && auth.keyParameter.tag == Tag::INVALID {
+        // Ignore `INVALID` tag
+        if auth.keyParameter.tag == Tag::INVALID {
             return true;
         }
         assert!(
@@ -423,7 +445,7 @@ pub fn check_key_authorizations(
         true
     });
 
-    //Check allowed-expected-key-parameters are present in given key authorizations list.
+    // Check allowed-expected-key-parameters are present in given key authorizations list.
     expected_params.iter().all(|key_param| {
         // `INCLUDE_UNIQUE_ID` is not strictly expected to be in key authorizations but has been
         // put there by some implementations so cope with that.
@@ -433,13 +455,30 @@ pub fn check_key_authorizations(
             return true;
         }
 
-        // Ignore below parameters if the backend is Keymaster and not KeyMint.
-        // Keymaster does not support these parameters. These key parameters are introduced in
-        // KeyMint1.0.
-        if !has_default_keymint() {
-            if matches!(key_param.tag, Tag::RSA_OAEP_MGF_DIGEST | Tag::USAGE_COUNT_LIMIT) {
+        // `Tag::RSA_OAEP_MGF_DIGEST` was added in KeyMint 1.0, but the KeyMint VTS tests didn't
+        // originally check for its presence and so some implementations of early versions (< 3) of
+        // the KeyMint HAL don't include it (cf. b/297306437 and aosp/2758513).
+        //
+        // Given that Keymaster implementations will also omit this tag, skip the check for it
+        // altogether (and rely on the updated KeyMint VTS tests to ensure that up-level KeyMint
+        // implementations correctly populate this tag).
+        if matches!(key_param.tag, Tag::RSA_OAEP_MGF_DIGEST) {
+            return true;
+        }
+
+        // Don't check these parameters if the underlying device is a Keymaster implementation.
+        if sl.is_keymaster() {
+            if matches!(
+                key_param.tag,
+                // `Tag::USAGE_COUNT_LIMIT` was added in KeyMint 1.0.
+                Tag::USAGE_COUNT_LIMIT |
+                // Keymaster implementations may not consistently include `Tag::VENDOR_PATCHLEVEL`
+                // in generated key characteristics.
+                Tag::VENDOR_PATCHLEVEL
+            ) {
                 return true;
             }
+            // `KeyPurpose::ATTEST_KEY` was added in KeyMint 1.0.
             if key_param.tag == Tag::PURPOSE
                 && key_param.value == KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY)
             {
@@ -457,11 +496,15 @@ pub fn check_key_authorizations(
         true
     });
 
-    check_common_auths(authorizations, expected_key_origin);
+    check_common_auths(sl, authorizations, expected_key_origin);
 }
 
 /// Verify common key authorizations.
-fn check_common_auths(authorizations: &[Authorization], expected_key_origin: KeyOrigin) {
+fn check_common_auths(
+    sl: &SecLevel,
+    authorizations: &[Authorization],
+    expected_key_origin: KeyOrigin,
+) {
     assert!(check_key_param(
         authorizations,
         &KeyParameter {
@@ -477,18 +520,6 @@ fn check_common_auths(authorizations: &[Authorization], expected_key_origin: Key
         }
     ));
 
-    // Access denied for finding vendor-patch-level ("ro.vendor.build.security_patch") property
-    // in a test running with `untrusted_app` context. Keeping this check to verify
-    // vendor-patch-level in tests running with `su` context.
-    if getuid().is_root() {
-        assert!(check_key_param(
-            authorizations,
-            &KeyParameter {
-                tag: Tag::VENDOR_PATCHLEVEL,
-                value: KeyParameterValue::Integer(get_vendor_patchlevel().try_into().unwrap())
-            }
-        ));
-    }
     assert!(check_key_param(
         authorizations,
         &KeyParameter { tag: Tag::ORIGIN, value: KeyParameterValue::Origin(expected_key_origin) }
@@ -505,11 +536,27 @@ fn check_common_auths(authorizations: &[Authorization], expected_key_origin: Key
         }
     ));
 
-    if has_default_keymint() {
+    if sl.is_keymint() {
         assert!(authorizations
             .iter()
             .map(|auth| &auth.keyParameter)
             .any(|key_param| key_param.tag == Tag::CREATION_DATETIME));
+
+        // Access denied for finding vendor-patch-level ("ro.vendor.build.security_patch") property
+        // in a test running with `untrusted_app` context. Keeping this check to verify
+        // vendor-patch-level in tests running with `su` context.
+        if getuid().is_root() {
+            // Keymaster implementations may not consistently include `Tag::VENDOR_PATCHLEVEL`
+            // in generated key characteristics. So, checking this if the underlying device is a
+            // KeyMint implementation.
+            assert!(check_key_param(
+                authorizations,
+                &KeyParameter {
+                    tag: Tag::VENDOR_PATCHLEVEL,
+                    value: KeyParameterValue::Integer(get_vendor_patchlevel().try_into().unwrap())
+                }
+            ));
+        }
     }
 }
 
@@ -532,7 +579,7 @@ pub fn get_key_auth(authorizations: &[Authorization], tag: Tag) -> Option<&Autho
 ///     Digest: SHA_2_256
 ///     Curve: P_256
 pub fn generate_ec_p256_signing_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
@@ -552,7 +599,7 @@ pub fn generate_ec_p256_signing_key(
         gen_params = gen_params.clone().attestation_challenge(challenge.to_vec());
     }
 
-    match sec_level.generateKey(
+    match sl.binder.generateKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         None,
         &gen_params,
@@ -569,6 +616,7 @@ pub fn generate_ec_p256_signing_key(
             }
 
             check_key_authorizations(
+                sl,
                 &key_metadata.authorizations,
                 &gen_params,
                 KeyOrigin::GENERATED,
@@ -581,7 +629,7 @@ pub fn generate_ec_p256_signing_key(
 
 /// Generate EC signing key.
 pub fn generate_ec_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
@@ -596,7 +644,7 @@ pub fn generate_ec_key(
         .digest(digest)
         .ec_curve(ec_curve);
 
-    let key_metadata = sec_level.generateKey(
+    let key_metadata = sl.binder.generateKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         None,
         &gen_params,
@@ -615,19 +663,19 @@ pub fn generate_ec_key(
     } else {
         assert!(key_metadata.key.blob.is_none());
     }
-    check_key_authorizations(&key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
     Ok(key_metadata)
 }
 
 /// Generate a RSA key with the given key parameters, alias, domain and namespace.
 pub fn generate_rsa_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
     key_params: &KeyParams,
     attest_key: Option<&KeyDescriptor>,
-) -> binder::Result<KeyMetadata> {
+) -> binder::Result<Option<KeyMetadata>> {
     let mut gen_params = AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::RSA)
@@ -653,13 +701,29 @@ pub fn generate_rsa_key(
         gen_params = gen_params.attestation_challenge(value.to_vec())
     }
 
-    let key_metadata = sec_level.generateKey(
+    let key_metadata = match sl.binder.generateKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         attest_key,
         &gen_params,
         0,
         b"entropy",
-    )?;
+    ) {
+        Ok(metadata) => metadata,
+        Err(e) => {
+            return if is_rkp_only_unknown_on_gsi(sl.level)
+                && e.service_specific_error() == ErrorCode::ATTESTATION_KEYS_NOT_PROVISIONED.0
+            {
+                // GSI replaces the values for remote_prov_prop properties (since they’re
+                // system_internal_prop properties), so on GSI the properties are not
+                // reliable indicators of whether StrongBox/TEE are RKP-only or not.
+                // Test can be skipped if it generates a key with attestation but doesn't provide
+                // an ATTEST_KEY and rkp-only property is undetermined.
+                Ok(None)
+            } else {
+                Err(e)
+            };
+        }
+    };
 
     // Must have a public key.
     assert!(key_metadata.certificate.is_some());
@@ -677,7 +741,7 @@ pub fn generate_rsa_key(
             || key_metadata.key.blob.is_none()
     );
 
-    check_key_authorizations(&key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
     // If `RSA_OAEP_MGF_DIGEST` tag is not mentioned explicitly while generating/importing a key,
     // then make sure `RSA_OAEP_MGF_DIGEST` tag with default value (SHA1) must not be included in
     // key authorization list.
@@ -690,12 +754,12 @@ pub fn generate_rsa_key(
             }
         ));
     }
-    Ok(key_metadata)
+    Ok(Some(key_metadata))
 }
 
 /// Generate AES/3DES key.
 pub fn generate_sym_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     algorithm: Algorithm,
     size: i32,
     alias: &str,
@@ -716,7 +780,7 @@ pub fn generate_sym_key(
         gen_params = gen_params.min_mac_length(val);
     }
 
-    let key_metadata = sec_level.generateKey(
+    let key_metadata = sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -734,13 +798,13 @@ pub fn generate_sym_key(
 
     // Should not have an attestation record.
     assert!(key_metadata.certificateChain.is_none());
-    check_key_authorizations(&key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
     Ok(key_metadata)
 }
 
 /// Generate HMAC key.
 pub fn generate_hmac_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: &str,
     key_size: i32,
     min_mac_len: i32,
@@ -755,7 +819,7 @@ pub fn generate_hmac_key(
         .min_mac_length(min_mac_len)
         .digest(digest);
 
-    let key_metadata = sec_level.generateKey(
+    let key_metadata = sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -774,7 +838,7 @@ pub fn generate_hmac_key(
     // Should not have an attestation record.
     assert!(key_metadata.certificateChain.is_none());
 
-    check_key_authorizations(&key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &gen_params, KeyOrigin::GENERATED);
     Ok(key_metadata)
 }
 
@@ -785,16 +849,16 @@ pub fn generate_hmac_key(
 ///     RSA-Key-Size: 2048
 ///     EC-Curve: EcCurve::P_256
 pub fn generate_attestation_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     algorithm: Algorithm,
     att_challenge: &[u8],
-) -> binder::Result<KeyMetadata> {
+) -> binder::Result<Option<KeyMetadata>> {
     assert!(algorithm == Algorithm::RSA || algorithm == Algorithm::EC);
 
     if algorithm == Algorithm::RSA {
         let alias = "ks_rsa_attest_test_key";
-        let metadata = generate_rsa_key(
-            sec_level,
+        generate_rsa_key(
+            sl,
             Domain::APP,
             -1,
             Some(alias.to_string()),
@@ -809,29 +873,19 @@ pub fn generate_attestation_key(
             },
             None,
         )
-        .unwrap();
-        Ok(metadata)
     } else {
-        let metadata = generate_ec_attestation_key(
-            sec_level,
-            att_challenge,
-            Digest::SHA_2_256,
-            EcCurve::P_256,
-        )
-        .unwrap();
-
-        Ok(metadata)
+        generate_ec_attestation_key(sl, att_challenge, Digest::SHA_2_256, EcCurve::P_256)
     }
 }
 
 /// Generate EC attestation key with the given
 ///    curve, attestation-challenge and attestation-app-id.
 pub fn generate_ec_attestation_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     att_challenge: &[u8],
     digest: Digest,
     ec_curve: EcCurve,
-) -> binder::Result<KeyMetadata> {
+) -> binder::Result<Option<KeyMetadata>> {
     let alias = "ks_attest_ec_test_key";
     let gen_params = AuthSetBuilder::new()
         .no_auth_required()
@@ -841,7 +895,7 @@ pub fn generate_ec_attestation_key(
         .digest(digest)
         .attestation_challenge(att_challenge.to_vec());
 
-    let attestation_key_metadata = sec_level.generateKey(
+    let attestation_key_metadata = match sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -852,7 +906,23 @@ pub fn generate_ec_attestation_key(
         &gen_params,
         0,
         b"entropy",
-    )?;
+    ) {
+        Ok(metadata) => metadata,
+        Err(e) => {
+            return if is_rkp_only_unknown_on_gsi(sl.level)
+                && e.service_specific_error() == ErrorCode::ATTESTATION_KEYS_NOT_PROVISIONED.0
+            {
+                // GSI replaces the values for remote_prov_prop properties (since they’re
+                // system_internal_prop properties), so on GSI the properties are not
+                // reliable indicators of whether StrongBox/TEE are RKP-only or not.
+                // Test can be skipped if it generates a key with attestation but doesn't provide
+                // an ATTEST_KEY and rkp-only property is undetermined.
+                Ok(None)
+            } else {
+                Err(e)
+            };
+        }
+    };
 
     // Should have public certificate.
     assert!(attestation_key_metadata.certificate.is_some());
@@ -860,16 +930,17 @@ pub fn generate_ec_attestation_key(
     assert!(attestation_key_metadata.certificateChain.is_some());
 
     check_key_authorizations(
+        sl,
         &attestation_key_metadata.authorizations,
         &gen_params,
         KeyOrigin::GENERATED,
     );
-    Ok(attestation_key_metadata)
+    Ok(Some(attestation_key_metadata))
 }
 
 /// Generate EC-P-256 key and attest it with given attestation key.
 pub fn generate_ec_256_attested_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: Option<String>,
     att_challenge: &[u8],
     attest_key: &KeyDescriptor,
@@ -883,7 +954,8 @@ pub fn generate_ec_256_attested_key(
         .ec_curve(EcCurve::P_256)
         .attestation_challenge(att_challenge.to_vec());
 
-    let ec_key_metadata = sec_level
+    let ec_key_metadata = sl
+        .binder
         .generateKey(
             &KeyDescriptor { domain: Domain::APP, nspace: -1, alias, blob: None },
             Some(attest_key),
@@ -898,19 +970,25 @@ pub fn generate_ec_256_attested_key(
     // Shouldn't have an attestation record.
     assert!(ec_key_metadata.certificateChain.is_none());
 
-    check_key_authorizations(&ec_key_metadata.authorizations, &ec_gen_params, KeyOrigin::GENERATED);
+    check_key_authorizations(
+        sl,
+        &ec_key_metadata.authorizations,
+        &ec_gen_params,
+        KeyOrigin::GENERATED,
+    );
     Ok(ec_key_metadata)
 }
 
 /// Imports above defined RSA key - `RSA_2048_KEY` and validates imported key parameters.
 pub fn import_rsa_2048_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
     import_params: AuthSetBuilder,
 ) -> binder::Result<KeyMetadata> {
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .importKey(
             &KeyDescriptor { domain, nspace, alias, blob: None },
             None,
@@ -923,7 +1001,7 @@ pub fn import_rsa_2048_key(
     assert!(key_metadata.certificate.is_some());
     assert!(key_metadata.certificateChain.is_none());
 
-    check_key_authorizations(&key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
 
     // Check below auths explicitly, they might not be addd in import parameters.
     assert!(check_key_param(
@@ -967,13 +1045,14 @@ pub fn import_rsa_2048_key(
 
 /// Imports above defined EC key - `EC_P_256_KEY` and validates imported key parameters.
 pub fn import_ec_p_256_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
     import_params: AuthSetBuilder,
 ) -> binder::Result<KeyMetadata> {
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .importKey(
             &KeyDescriptor { domain, nspace, alias, blob: None },
             None,
@@ -986,7 +1065,7 @@ pub fn import_ec_p_256_key(
     assert!(key_metadata.certificate.is_some());
     assert!(key_metadata.certificateChain.is_none());
 
-    check_key_authorizations(&key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
 
     // Check below auths explicitly, they might not be addd in import parameters.
     assert!(check_key_param(
@@ -1013,7 +1092,7 @@ pub fn import_ec_p_256_key(
 
 /// Import sample AES key and validate its key parameters.
 pub fn import_aes_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
@@ -1030,7 +1109,7 @@ pub fn import_aes_key(
         .purpose(KeyPurpose::DECRYPT)
         .padding_mode(PaddingMode::PKCS7);
 
-    let key_metadata = sec_level.importKey(
+    let key_metadata = sl.binder.importKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         None,
         &import_params,
@@ -1038,7 +1117,7 @@ pub fn import_aes_key(
         AES_KEY,
     )?;
 
-    check_key_authorizations(&key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
 
     // Check below auths explicitly, they might not be addd in import parameters.
     assert!(check_key_param(
@@ -1070,7 +1149,7 @@ pub fn import_aes_key(
 
 /// Import sample 3DES key and validate its key parameters.
 pub fn import_3des_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
@@ -1089,7 +1168,7 @@ pub fn import_3des_key(
         .purpose(KeyPurpose::DECRYPT)
         .padding_mode(PaddingMode::PKCS7);
 
-    let key_metadata = sec_level.importKey(
+    let key_metadata = sl.binder.importKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         None,
         &import_params,
@@ -1097,7 +1176,7 @@ pub fn import_3des_key(
         TRIPLE_DES_KEY,
     )?;
 
-    check_key_authorizations(&key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
 
     // Check below auths explicitly, they might not be addd in import parameters.
     assert!(check_key_param(
@@ -1132,7 +1211,7 @@ pub fn import_3des_key(
 
 /// Import sample HMAC key and validate its key parameters.
 pub fn import_hmac_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
@@ -1149,7 +1228,7 @@ pub fn import_hmac_key(
         .digest(Digest::SHA_2_256)
         .min_mac_length(256);
 
-    let key_metadata = sec_level.importKey(
+    let key_metadata = sl.binder.importKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         None,
         &import_params,
@@ -1157,7 +1236,7 @@ pub fn import_hmac_key(
         HMAC_KEY,
     )?;
 
-    check_key_authorizations(&key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
+    check_key_authorizations(sl, &key_metadata.authorizations, &import_params, KeyOrigin::IMPORTED);
 
     // Check below auths explicitly, they might not be addd in import parameters.
     assert!(check_key_param(
@@ -1182,7 +1261,7 @@ pub fn import_hmac_key(
 
 /// Imports RSA encryption key with WRAP_KEY purpose.
 pub fn import_wrapping_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     wrapping_key_data: &[u8],
     wrapping_key_alias: Option<String>,
 ) -> binder::Result<KeyMetadata> {
@@ -1199,7 +1278,7 @@ pub fn import_wrapping_key(
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    sec_level.importKey(
+    sl.binder.importKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: wrapping_key_alias, blob: None },
         None,
         &wrapping_key_params,
@@ -1210,7 +1289,7 @@ pub fn import_wrapping_key(
 
 /// Import wrapped key using given wrapping key.
 pub fn import_wrapped_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: Option<String>,
     wrapping_key_metadata: &KeyMetadata,
     wrapped_key: Option<Vec<u8>>,
@@ -1223,7 +1302,7 @@ pub fn import_wrapped_key(
         authenticatorId: 0,
     }];
 
-    let key_metadata = sec_level.importWrappedKey(
+    let key_metadata = sl.binder.importWrappedKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias, blob: wrapped_key },
         &wrapping_key_metadata.key,
         None,
@@ -1236,14 +1315,14 @@ pub fn import_wrapped_key(
 
 /// Import wrapping key and then import wrapped key using wrapping key.
 pub fn import_wrapping_key_and_wrapped_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
     wrapping_key_alias: Option<String>,
     wrapping_key_params: AuthSetBuilder,
 ) -> binder::Result<KeyMetadata> {
-    let wrapping_key_metadata = sec_level.importKey(
+    let wrapping_key_metadata = sl.binder.importKey(
         &KeyDescriptor { domain, nspace, alias: wrapping_key_alias, blob: None },
         None,
         &wrapping_key_params,
@@ -1251,12 +1330,12 @@ pub fn import_wrapping_key_and_wrapped_key(
         WRAPPING_KEY,
     )?;
 
-    import_wrapped_key(sec_level, alias, &wrapping_key_metadata, Some(WRAPPED_KEY.to_vec()))
+    import_wrapped_key(sl, alias, &wrapping_key_metadata, Some(WRAPPED_KEY.to_vec()))
 }
 
 /// Import given key material as AES-256-GCM-NONE transport key.
 pub fn import_transport_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     transport_key_alias: Option<String>,
     transport_key: &[u8],
 ) -> binder::Result<KeyMetadata> {
@@ -1271,7 +1350,7 @@ pub fn import_transport_key(
         .purpose(KeyPurpose::ENCRYPT)
         .purpose(KeyPurpose::DECRYPT);
 
-    sec_level.importKey(
+    sl.binder.importKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: transport_key_alias, blob: None },
         None,
         &transport_key_params,
@@ -1282,7 +1361,7 @@ pub fn import_transport_key(
 
 /// Generate EC key with purpose AGREE_KEY.
 pub fn generate_ec_agree_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     ec_curve: EcCurve,
     digest: Digest,
     domain: Domain,
@@ -1296,7 +1375,7 @@ pub fn generate_ec_agree_key(
         .digest(digest)
         .ec_curve(ec_curve);
 
-    match sec_level.generateKey(
+    match sl.binder.generateKey(
         &KeyDescriptor { domain, nspace, alias, blob: None },
         None,
         &gen_params,
@@ -1310,6 +1389,7 @@ pub fn generate_ec_agree_key(
             }
 
             check_key_authorizations(
+                sl,
                 &key_metadata.authorizations,
                 &gen_params,
                 KeyOrigin::GENERATED,
@@ -1322,7 +1402,7 @@ pub fn generate_ec_agree_key(
 
 /// Helper method to import AES keys `total_count` of times.
 pub fn import_aes_keys(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias_prefix: String,
     total_count: Range<i32>,
 ) -> binder::Result<HashSet<String>> {
@@ -1334,7 +1414,7 @@ pub fn import_aes_keys(
         write!(alias, "{}_{}", alias_prefix, count).unwrap();
         imported_key_aliases.insert(alias.clone());
 
-        import_aes_key(sec_level, Domain::APP, -1, Some(alias))?;
+        import_aes_key(sl, Domain::APP, -1, Some(alias))?;
     }
 
     Ok(imported_key_aliases)
@@ -1342,7 +1422,7 @@ pub fn import_aes_keys(
 
 /// Generate attested EC-P_256 key with device id attestation.
 pub fn generate_key_with_attest_id(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     algorithm: Algorithm,
     alias: Option<String>,
     att_challenge: &[u8],
@@ -1405,7 +1485,7 @@ pub fn generate_key_with_attest_id(
         }
     }
 
-    sec_level.generateKey(
+    sl.binder.generateKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias, blob: None },
         Some(attest_key),
         &ec_gen_params,
@@ -1416,11 +1496,11 @@ pub fn generate_key_with_attest_id(
 
 /// Generate Key and validate key characteristics.
 pub fn generate_key(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     gen_params: &AuthSetBuilder,
     alias: &str,
-) -> binder::Result<KeyMetadata> {
-    let key_metadata = sec_level.generateKey(
+) -> binder::Result<Option<KeyMetadata>> {
+    let key_metadata = match sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -1431,7 +1511,23 @@ pub fn generate_key(
         gen_params,
         0,
         b"entropy",
-    )?;
+    ) {
+        Ok(metadata) => metadata,
+        Err(e) => {
+            return if is_rkp_only_unknown_on_gsi(sl.level)
+                && e.service_specific_error() == ErrorCode::ATTESTATION_KEYS_NOT_PROVISIONED.0
+            {
+                // GSI replaces the values for remote_prov_prop properties (since they’re
+                // system_internal_prop properties), so on GSI the properties are not
+                // reliable indicators of whether StrongBox/TEE are RKP-only or not.
+                // Test can be skipped if it generates a key with attestation but doesn't provide
+                // an ATTEST_KEY and rkp-only property is undetermined.
+                Ok(None)
+            } else {
+                Err(e)
+            };
+        }
+    };
 
     if gen_params.iter().any(|kp| {
         matches!(
@@ -1474,19 +1570,21 @@ pub fn generate_key(
             assert!(!att_app_id.is_empty());
         }
     }
-    check_key_authorizations(&key_metadata.authorizations, gen_params, KeyOrigin::GENERATED);
+    check_key_authorizations(sl, &key_metadata.authorizations, gen_params, KeyOrigin::GENERATED);
 
-    Ok(key_metadata)
+    Ok(Some(key_metadata))
 }
 
 /// Generate a key using given authorizations and create an operation using the generated key.
 pub fn create_key_and_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     gen_params: &AuthSetBuilder,
     op_params: &AuthSetBuilder,
     alias: &str,
-) -> binder::Result<CreateOperationResponse> {
-    let key_metadata = generate_key(sec_level, gen_params, alias)?;
+) -> binder::Result<Option<CreateOperationResponse>> {
+    let Some(key_metadata) = generate_key(sl, gen_params, alias)? else {
+        return Ok(None);
+    };
 
-    sec_level.createOperation(&key_metadata.key, op_params, false)
+    sl.binder.createOperation(&key_metadata.key, op_params, false).map(Some)
 }
diff --git a/keystore2/test_utils/lib.rs b/keystore2/test_utils/lib.rs
index 8394ca1c..825657fd 100644
--- a/keystore2/test_utils/lib.rs
+++ b/keystore2/test_utils/lib.rs
@@ -19,7 +19,13 @@ use std::io::ErrorKind;
 use std::path::{Path, PathBuf};
 use std::{env::temp_dir, ops::Deref};
 
-use android_system_keystore2::aidl::android::system::keystore2::IKeystoreService::IKeystoreService;
+use android_system_keystore2::aidl::android::system::keystore2::{
+    IKeystoreService::IKeystoreService,
+    IKeystoreSecurityLevel::IKeystoreSecurityLevel,
+};
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
+};
 use android_security_authorization::aidl::android::security::authorization::IKeystoreAuthorization::IKeystoreAuthorization;
 
 pub mod authorizations;
@@ -123,3 +129,68 @@ pub fn get_keystore_service() -> binder::Strong<dyn IKeystoreService> {
 pub fn get_keystore_auth_service() -> binder::Strong<dyn IKeystoreAuthorization> {
     binder::get_interface(AUTH_SERVICE_NAME).unwrap()
 }
+
+/// Security level-specific data.
+pub struct SecLevel {
+    /// Binder connection for the top-level service.
+    pub keystore2: binder::Strong<dyn IKeystoreService>,
+    /// Binder connection for the security level.
+    pub binder: binder::Strong<dyn IKeystoreSecurityLevel>,
+    /// Security level.
+    pub level: SecurityLevel,
+}
+
+impl SecLevel {
+    /// Return security level data for TEE.
+    pub fn tee() -> Self {
+        let level = SecurityLevel::TRUSTED_ENVIRONMENT;
+        let keystore2 = get_keystore_service();
+        let binder =
+            keystore2.getSecurityLevel(level).expect("TEE security level should always be present");
+        Self { keystore2, binder, level }
+    }
+    /// Return security level data for StrongBox, if present.
+    pub fn strongbox() -> Option<Self> {
+        let level = SecurityLevel::STRONGBOX;
+        let keystore2 = get_keystore_service();
+        match key_generations::map_ks_error(keystore2.getSecurityLevel(level)) {
+            Ok(binder) => Some(Self { keystore2, binder, level }),
+            Err(e) => {
+                assert_eq!(e, key_generations::Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE));
+                None
+            }
+        }
+    }
+    /// Indicate whether this security level is a KeyMint implementation (not Keymaster).
+    pub fn is_keymint(&self) -> bool {
+        let instance = match self.level {
+            SecurityLevel::TRUSTED_ENVIRONMENT => "default",
+            SecurityLevel::STRONGBOX => "strongbox",
+            l => panic!("unexpected level {l:?}"),
+        };
+        let name = format!("android.hardware.security.keymint.IKeyMintDevice/{instance}");
+        binder::is_declared(&name).expect("Could not check for declared keymint interface")
+    }
+
+    /// Indicate whether this security level is a Keymaster implementation (not KeyMint).
+    pub fn is_keymaster(&self) -> bool {
+        !self.is_keymint()
+    }
+
+    /// Get KeyMint version.
+    /// Returns 0 if the underlying device is Keymaster not KeyMint.
+    pub fn get_keymint_version(&self) -> i32 {
+        let instance = match self.level {
+            SecurityLevel::TRUSTED_ENVIRONMENT => "default",
+            SecurityLevel::STRONGBOX => "strongbox",
+            l => panic!("unexpected level {l:?}"),
+        };
+        let name = format!("android.hardware.security.keymint.IKeyMintDevice/{instance}");
+        if binder::is_declared(&name).expect("Could not check for declared keymint interface") {
+            let km: binder::Strong<dyn IKeyMintDevice> = binder::get_interface(&name).unwrap();
+            km.getInterfaceVersion().unwrap()
+        } else {
+            0
+        }
+    }
+}
diff --git a/keystore2/test_utils/run_as.rs b/keystore2/test_utils/run_as.rs
index d39d0697..2cd9fec3 100644
--- a/keystore2/test_utils/run_as.rs
+++ b/keystore2/test_utils/run_as.rs
@@ -357,9 +357,12 @@ mod test {
         // Safety: run_as must be called from a single threaded process.
         // This device test is run as a separate single threaded process.
         unsafe {
-            run_as(selinux::getcon().unwrap().to_str().unwrap(), getuid(), getgid(), || {
-                panic!("Closure must panic.")
-            })
+            run_as::<_, ()>(
+                selinux::getcon().unwrap().to_str().unwrap(),
+                getuid(),
+                getgid(),
+                || panic!("Closure must panic."),
+            )
         };
     }
 
diff --git a/keystore2/tests/Android.bp b/keystore2/tests/Android.bp
index 01ea7465..dbef46c9 100644
--- a/keystore2/tests/Android.bp
+++ b/keystore2/tests/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_hardware_backed_security",
     // See: http://go/android-license-faq
     // A large-scale-change added 'default_applicable_licenses' to import
     // all of the 'license_kinds' from "system_security_license"
@@ -23,11 +24,16 @@ package {
 
 rust_test {
     name: "keystore2_client_tests",
-    compile_multilib: "first",
     defaults: [
         "keymint_use_latest_hal_aidl_rust",
         "keystore2_use_latest_aidl_rust",
     ],
+    static_libs: [
+        // Also include static_libs for the NDK variants so that they are available
+        // for dependencies.
+        "android.system.keystore2-V4-ndk",
+        "android.hardware.security.keymint-V3-ndk",
+    ],
     srcs: ["keystore2_client_tests.rs"],
     test_suites: [
         "general-tests",
@@ -38,9 +44,13 @@ rust_test {
     rustlibs: [
         "android.hardware.security.secureclock-V1-rust",
         "android.security.authorization-rust",
+        "android.security.maintenance-rust",
         "libaconfig_android_hardware_biometrics_rust",
+        "libandroid_logger",
+        "libandroid_security_flags_rust",
         "libbinder_rs",
         "libkeystore2_test_utils",
+        "liblog_rust",
         "libnix",
         "libopenssl",
         "librustutils",
diff --git a/keystore2/tests/AndroidTest.xml b/keystore2/tests/AndroidTest.xml
index dde18a9b..7db36f7e 100644
--- a/keystore2/tests/AndroidTest.xml
+++ b/keystore2/tests/AndroidTest.xml
@@ -14,7 +14,6 @@
      limitations under the License.
 -->
 <configuration description="Config to run keystore2_client_tests device tests.">
-    <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi" />
 
     <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer">
     </target_preparer>
diff --git a/keystore2/tests/keystore2_client_3des_key_tests.rs b/keystore2/tests/keystore2_client_3des_key_tests.rs
index eda24db0..4cb81d14 100644
--- a/keystore2/tests/keystore2_client_3des_key_tests.rs
+++ b/keystore2/tests/keystore2_client_3des_key_tests.rs
@@ -12,26 +12,21 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::keystore2_client_test_utils::{
+    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
-    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
+    PaddingMode::PaddingMode,
 };
-
 use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
-};
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
-
-use crate::keystore2_client_test_utils::{
-    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+    Domain::Domain, KeyDescriptor::KeyDescriptor,
 };
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
 
 /// Generate a 3DES key. Create encryption and decryption operations using the generated key.
 fn create_3des_key_and_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     padding_mode: PaddingMode,
     block_mode: BlockMode,
     nonce: &mut Option<Vec<u8>>,
@@ -39,7 +34,7 @@ fn create_3des_key_and_operation(
     let alias = format!("ks_3des_test_key_{}{}", block_mode.0, padding_mode.0);
 
     let key_metadata = key_generations::generate_sym_key(
-        sec_level,
+        sl,
         Algorithm::TRIPLE_DES,
         168,
         &alias,
@@ -50,7 +45,7 @@ fn create_3des_key_and_operation(
 
     // Encrypts `SAMPLE_PLAIN_TEXT` whose length is multiple of DES block size.
     let cipher_text = perform_sample_sym_key_encrypt_op(
-        sec_level,
+        &sl.binder,
         padding_mode,
         block_mode,
         nonce,
@@ -60,7 +55,7 @@ fn create_3des_key_and_operation(
     assert!(cipher_text.is_some());
 
     let plain_text = perform_sample_sym_key_decrypt_op(
-        sec_level,
+        &sl.binder,
         &cipher_text.unwrap(),
         padding_mode,
         block_mode,
@@ -77,19 +72,19 @@ fn create_3des_key_and_operation(
 /// Generate 3DES keys with various block modes and paddings.
 ///  - Block Modes: ECB, CBC
 ///  - Padding Modes: NONE, PKCS7
+///
 /// Test should generate keys and perform operation successfully.
 #[test]
 fn keystore2_3des_ecb_cbc_generate_key_success() {
-    let keystore2 = get_keystore_service();
     let block_modes = [BlockMode::ECB, BlockMode::CBC];
     let padding_modes = [PaddingMode::PKCS7, PaddingMode::NONE];
 
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     for block_mode in block_modes {
         for padding_mode in padding_modes {
             assert_eq!(
                 Ok(()),
-                create_3des_key_and_operation(&sec_level, padding_mode, block_mode, &mut None)
+                create_3des_key_and_operation(&sl, padding_mode, block_mode, &mut None)
             );
         }
     }
@@ -99,13 +94,12 @@ fn keystore2_3des_ecb_cbc_generate_key_success() {
 /// an error code `UNSUPPORTED_KEY_SIZE`.
 #[test]
 fn keystore2_3des_key_fails_unsupported_key_size() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "3des_key_test_invalid_1";
     let invalid_key_size = 128;
 
     let result = key_generations::map_ks_error(key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::TRIPLE_DES,
         invalid_key_size,
         alias,
@@ -122,8 +116,7 @@ fn keystore2_3des_key_fails_unsupported_key_size() {
 /// `UNSUPPORTED_PADDING_MODE`.
 #[test]
 fn keystore2_3des_key_fails_missing_padding() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "3des_key_test_missing_padding";
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -134,7 +127,8 @@ fn keystore2_3des_key_fails_missing_padding() {
         .key_size(168)
         .block_mode(BlockMode::ECB);
 
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .generateKey(
             &KeyDescriptor {
                 domain: Domain::APP,
@@ -153,7 +147,7 @@ fn keystore2_3des_key_fails_missing_padding() {
         .purpose(KeyPurpose::ENCRYPT)
         .block_mode(BlockMode::ECB);
 
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &op_params,
         false,
@@ -166,12 +160,11 @@ fn keystore2_3des_key_fails_missing_padding() {
 /// multiple of the DES block size.
 #[test]
 fn keystore2_3des_key_encrypt_fails_invalid_input_length() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "3des_key_test_invalid_input_len";
 
     let key_metadata = key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::TRIPLE_DES,
         168,
         alias,
@@ -186,7 +179,8 @@ fn keystore2_3des_key_encrypt_fails_invalid_input_length() {
         .padding_mode(PaddingMode::NONE)
         .block_mode(BlockMode::ECB);
 
-    let op_response = sec_level
+    let op_response = sl
+        .binder
         .createOperation(&key_metadata.key, &op_params, false)
         .expect("Error in creation of operation using rebound key.");
     assert!(op_response.iOperation.is_some());
@@ -204,11 +198,10 @@ fn keystore2_3des_key_encrypt_fails_invalid_input_length() {
 /// error code `UNSUPPORTED_BLOCK_MODE`.
 #[test]
 fn keystore2_3des_key_fails_unsupported_block_mode() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let result = key_generations::map_ks_error(create_3des_key_and_operation(
-        &sec_level,
+        &sl,
         PaddingMode::NONE,
         BlockMode::CTR,
         &mut None,
diff --git a/keystore2/tests/keystore2_client_aes_key_tests.rs b/keystore2/tests/keystore2_client_aes_key_tests.rs
index 313f596f..3c5fda50 100644
--- a/keystore2/tests/keystore2_client_aes_key_tests.rs
+++ b/keystore2/tests/keystore2_client_aes_key_tests.rs
@@ -12,26 +12,21 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::keystore2_client_test_utils::{
+    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
-    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
+    PaddingMode::PaddingMode,
 };
-
 use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
-};
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
-
-use crate::keystore2_client_test_utils::{
-    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+    Domain::Domain, KeyDescriptor::KeyDescriptor,
 };
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
 
 /// Generate a AES key. Create encrypt and decrypt operations using the generated key.
 fn create_aes_key_and_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     key_size: i32,
     padding_mode: PaddingMode,
     block_mode: BlockMode,
@@ -42,7 +37,7 @@ fn create_aes_key_and_operation(
     let alias = format!("ks_aes_test_key_{}{}{}", key_size, block_mode.0, padding_mode.0);
 
     let key_metadata = key_generations::generate_sym_key(
-        sec_level,
+        sl,
         Algorithm::AES,
         key_size,
         &alias,
@@ -52,7 +47,7 @@ fn create_aes_key_and_operation(
     )?;
 
     let cipher_text = perform_sample_sym_key_encrypt_op(
-        sec_level,
+        &sl.binder,
         padding_mode,
         block_mode,
         nonce,
@@ -63,7 +58,7 @@ fn create_aes_key_and_operation(
     assert!(cipher_text.is_some());
 
     let plain_text = perform_sample_sym_key_decrypt_op(
-        sec_level,
+        &sl.binder,
         &cipher_text.unwrap(),
         padding_mode,
         block_mode,
@@ -80,22 +75,22 @@ fn create_aes_key_and_operation(
 /// Generate AES keys with various block modes and paddings.
 ///  - Block Modes: ECB, CBC
 ///  - Padding Modes: NONE, PKCS7
+///
 /// Test should generate keys and perform operation successfully.
 #[test]
 fn keystore2_aes_ecb_cbc_generate_key() {
-    let keystore2 = get_keystore_service();
     let key_sizes = [128, 256];
     let block_modes = [BlockMode::ECB, BlockMode::CBC];
     let padding_modes = [PaddingMode::PKCS7, PaddingMode::NONE];
 
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     for key_size in key_sizes {
         for block_mode in block_modes {
             for padding_mode in padding_modes {
                 assert_eq!(
                     Ok(()),
                     create_aes_key_and_operation(
-                        &sec_level,
+                        &sl,
                         key_size,
                         padding_mode,
                         block_mode,
@@ -112,19 +107,18 @@ fn keystore2_aes_ecb_cbc_generate_key() {
 /// Generate AES keys with -
 ///  - Block Modes: `CTR, GCM`
 ///  - Padding Modes: `NONE`
+///
 /// Test should generate keys and perform operation successfully.
 #[test]
 fn keystore2_aes_ctr_gcm_generate_key_success() {
-    let keystore2 = get_keystore_service();
     let key_sizes = [128, 256];
     let key_params = [(BlockMode::CTR, None, None), (BlockMode::GCM, Some(128), Some(128))];
-
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for key_size in key_sizes {
         for (block_mode, mac_len, min_mac_len) in key_params {
             let result = key_generations::map_ks_error(create_aes_key_and_operation(
-                &sec_level,
+                &sl,
                 key_size,
                 PaddingMode::NONE,
                 block_mode,
@@ -141,20 +135,19 @@ fn keystore2_aes_ctr_gcm_generate_key_success() {
 /// Generate AES keys with -
 ///  - Block Modes: `CTR, GCM`
 ///  - Padding Modes: `PKCS7`
+///
 /// Try to create an operation using generated keys, test should fail to create an operation
 /// with an error code `INCOMPATIBLE_PADDING_MODE`.
 #[test]
 fn keystore2_aes_ctr_gcm_generate_key_fails_incompatible() {
-    let keystore2 = get_keystore_service();
     let key_sizes = [128, 256];
     let key_params = [(BlockMode::CTR, None, None), (BlockMode::GCM, Some(128), Some(128))];
-
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for key_size in key_sizes {
         for (block_mode, mac_len, min_mac_len) in key_params {
             let result = key_generations::map_ks_error(create_aes_key_and_operation(
-                &sec_level,
+                &sl,
                 key_size,
                 PaddingMode::PKCS7,
                 block_mode,
@@ -173,12 +166,11 @@ fn keystore2_aes_ctr_gcm_generate_key_fails_incompatible() {
 /// an error code `UNSUPPORTED_KEY_SIZE`.
 #[test]
 fn keystore2_aes_key_fails_unsupported_key_size() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_invalid_1";
 
     let result = key_generations::map_ks_error(key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::AES,
         1024,
         alias,
@@ -194,12 +186,11 @@ fn keystore2_aes_key_fails_unsupported_key_size() {
 /// Test should fail to generate a key with an error code `MISSING_MIN_MAC_LENGTH`.
 #[test]
 fn keystore2_aes_gcm_key_fails_missing_min_mac_len() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_invalid_1";
 
     let result = key_generations::map_ks_error(key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::AES,
         128,
         alias,
@@ -215,8 +206,7 @@ fn keystore2_aes_gcm_key_fails_missing_min_mac_len() {
 /// an operation with `UNSUPPORTED_BLOCK_MODE` error code.
 #[test]
 fn keystore2_aes_key_op_fails_multi_block_modes() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_invalid_1";
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -229,7 +219,8 @@ fn keystore2_aes_key_op_fails_multi_block_modes() {
         .block_mode(BlockMode::CBC)
         .padding_mode(PaddingMode::NONE);
 
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .generateKey(
             &KeyDescriptor {
                 domain: Domain::APP,
@@ -250,7 +241,7 @@ fn keystore2_aes_key_op_fails_multi_block_modes() {
         .block_mode(BlockMode::CBC)
         .padding_mode(PaddingMode::NONE);
 
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &op_params,
         false,
@@ -260,11 +251,10 @@ fn keystore2_aes_key_op_fails_multi_block_modes() {
 }
 
 /// Try to create an operation using AES key with multiple padding modes. Test should fail to create
-/// an operation with `UNSUPPORTED_PADDING_MODE` error code.
+/// an operation.
 #[test]
 fn keystore2_aes_key_op_fails_multi_padding_modes() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_invalid_1";
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -277,7 +267,8 @@ fn keystore2_aes_key_op_fails_multi_padding_modes() {
         .padding_mode(PaddingMode::PKCS7)
         .padding_mode(PaddingMode::NONE);
 
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .generateKey(
             &KeyDescriptor {
                 domain: Domain::APP,
@@ -298,13 +289,18 @@ fn keystore2_aes_key_op_fails_multi_padding_modes() {
         .padding_mode(PaddingMode::PKCS7)
         .padding_mode(PaddingMode::NONE);
 
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &op_params,
         false,
     ));
     assert!(result.is_err());
-    assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
+    assert!(matches!(
+        result.unwrap_err(),
+        Error::Km(ErrorCode::INCOMPATIBLE_PADDING_MODE)
+            | Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE)
+            | Error::Km(ErrorCode::INVALID_ARGUMENT)
+    ));
 }
 
 /// Generate a AES-ECB key with unpadded mode. Try to create an operation using generated key
@@ -312,12 +308,11 @@ fn keystore2_aes_key_op_fails_multi_padding_modes() {
 /// `INCOMPATIBLE_PADDING_MODE` error code.
 #[test]
 fn keystore2_aes_key_op_fails_incompatible_padding() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_invalid_1";
 
     let key_metadata = key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::AES,
         128,
         alias,
@@ -328,7 +323,7 @@ fn keystore2_aes_key_op_fails_incompatible_padding() {
     .unwrap();
 
     let result = key_generations::map_ks_error(perform_sample_sym_key_encrypt_op(
-        &sec_level,
+        &sl.binder,
         PaddingMode::PKCS7,
         BlockMode::ECB,
         &mut None,
@@ -344,12 +339,11 @@ fn keystore2_aes_key_op_fails_incompatible_padding() {
 /// `INCOMPATIBLE_BLOCK_MODE` error code.
 #[test]
 fn keystore2_aes_key_op_fails_incompatible_blockmode() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_invalid_1";
 
     let key_metadata = key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::AES,
         128,
         alias,
@@ -360,7 +354,7 @@ fn keystore2_aes_key_op_fails_incompatible_blockmode() {
     .unwrap();
 
     let result = key_generations::map_ks_error(perform_sample_sym_key_encrypt_op(
-        &sec_level,
+        &sl.binder,
         PaddingMode::NONE,
         BlockMode::CBC,
         &mut None,
@@ -376,13 +370,12 @@ fn keystore2_aes_key_op_fails_incompatible_blockmode() {
 /// `MISSING_MAC_LENGTH` error code.
 #[test]
 fn keystore2_aes_gcm_op_fails_missing_mac_len() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let mac_len = None;
     let min_mac_len = Some(128);
 
     let result = key_generations::map_ks_error(create_aes_key_and_operation(
-        &sec_level,
+        &sl,
         128,
         PaddingMode::NONE,
         BlockMode::GCM,
@@ -404,13 +397,12 @@ fn keystore2_aes_gcm_op_fails_missing_mac_len() {
 /// an operation with `INVALID_MAC_LENGTH` error code.
 #[test]
 fn keystore2_aes_gcm_op_fails_invalid_mac_len() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let mac_len = Some(96);
     let min_mac_len = Some(104);
 
     let result = key_generations::map_ks_error(create_aes_key_and_operation(
-        &sec_level,
+        &sl,
         128,
         PaddingMode::NONE,
         BlockMode::GCM,
@@ -427,11 +419,10 @@ fn keystore2_aes_gcm_op_fails_invalid_mac_len() {
 /// `UNSUPPORTED_MAC_LENGTH` error code.
 #[test]
 fn keystore2_aes_gcm_op_fails_unsupported_mac_len() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let result = key_generations::map_ks_error(create_aes_key_and_operation(
-        &sec_level,
+        &sl,
         128,
         PaddingMode::NONE,
         BlockMode::GCM,
@@ -448,13 +439,12 @@ fn keystore2_aes_gcm_op_fails_unsupported_mac_len() {
 /// `CALLER_NONCE_PROHIBITED` error code.
 #[test]
 fn keystore2_aes_key_op_fails_nonce_prohibited() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "aes_key_test_nonce_1";
     let mut nonce = Some(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
 
     let key_metadata = key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::AES,
         128,
         alias,
@@ -465,7 +455,7 @@ fn keystore2_aes_key_op_fails_nonce_prohibited() {
     .unwrap();
 
     let result = key_generations::map_ks_error(perform_sample_sym_key_encrypt_op(
-        &sec_level,
+        &sl.binder,
         PaddingMode::NONE,
         BlockMode::CBC,
         &mut nonce,
diff --git a/keystore2/tests/keystore2_client_attest_key_tests.rs b/keystore2/tests/keystore2_client_attest_key_tests.rs
index 454248a3..f723d023 100644
--- a/keystore2/tests/keystore2_client_attest_key_tests.rs
+++ b/keystore2/tests/keystore2_client_attest_key_tests.rs
@@ -12,8 +12,14 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::getuid;
-
+use crate::keystore2_client_test_utils::{
+    app_attest_key_feature_exists, device_id_attestation_feature_exists, get_attest_id_value,
+    is_second_imei_id_attestation_required, skip_device_id_attest_tests,
+};
+use crate::{
+    skip_device_id_attestation_tests, skip_test_if_no_app_attest_key_feature,
+    skip_test_if_no_device_id_attestation_feature,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
     ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
@@ -23,22 +29,12 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
     ResponseCode::ResponseCode,
 };
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
-
 use keystore2_test_utils::ffi_test_utils::{get_value_from_attest_record, validate_certchain};
-
-use crate::{
-    skip_device_id_attestation_tests, skip_test_if_no_app_attest_key_feature,
-    skip_test_if_no_device_id_attestation_feature,
-};
-
-use crate::keystore2_client_test_utils::{
-    app_attest_key_feature_exists, device_id_attestation_feature_exists, get_attest_id_value,
-    is_second_imei_id_attestation_required, skip_device_id_attest_tests,
+use keystore2_test_utils::{
+    authorizations, key_generations, key_generations::Error, run_as, SecLevel,
 };
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
 
 /// Generate RSA and EC attestation keys and use them for signing RSA-signing keys.
 /// Test should be able to generate attestation keys and use them successfully.
@@ -46,14 +42,17 @@ use crate::keystore2_client_test_utils::{
 fn keystore2_attest_rsa_signing_key_success() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let att_challenge: &[u8] = b"foo";
 
     for algo in [Algorithm::RSA, Algorithm::EC] {
         // Create attestation key.
-        let attestation_key_metadata =
-            key_generations::generate_attestation_key(&sec_level, algo, att_challenge).unwrap();
+        let Some(attestation_key_metadata) = key_generations::map_ks_error(
+            key_generations::generate_attestation_key(&sl, algo, att_challenge),
+        )
+        .unwrap() else {
+            return;
+        };
 
         let mut cert_chain: Vec<u8> = Vec::new();
         cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
@@ -62,8 +61,8 @@ fn keystore2_attest_rsa_signing_key_success() {
 
         // Create RSA signing key and use attestation key to sign it.
         let sign_key_alias = format!("ks_attest_rsa_signing_key_{}", getuid());
-        let sign_key_metadata = key_generations::generate_rsa_key(
-            &sec_level,
+        let Some(sign_key_metadata) = key_generations::generate_rsa_key(
+            &sl,
             Domain::APP,
             -1,
             Some(sign_key_alias),
@@ -78,7 +77,9 @@ fn keystore2_attest_rsa_signing_key_success() {
             },
             Some(&attestation_key_metadata.key),
         )
-        .unwrap();
+        .unwrap() else {
+            return;
+        };
 
         let mut cert_chain: Vec<u8> = Vec::new();
         cert_chain.extend(sign_key_metadata.certificate.as_ref().unwrap());
@@ -94,14 +95,17 @@ fn keystore2_attest_rsa_signing_key_success() {
 fn keystore2_attest_rsa_encrypt_key_success() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let att_challenge: &[u8] = b"foo";
 
     for algo in [Algorithm::RSA, Algorithm::EC] {
         // Create attestation key.
-        let attestation_key_metadata =
-            key_generations::generate_attestation_key(&sec_level, algo, att_challenge).unwrap();
+        let Some(attestation_key_metadata) = key_generations::map_ks_error(
+            key_generations::generate_attestation_key(&sl, algo, att_challenge),
+        )
+        .unwrap() else {
+            return;
+        };
 
         let mut cert_chain: Vec<u8> = Vec::new();
         cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
@@ -110,8 +114,8 @@ fn keystore2_attest_rsa_encrypt_key_success() {
 
         // Create RSA encrypt/decrypt key and use attestation key to sign it.
         let decrypt_key_alias = format!("ks_attest_rsa_encrypt_key_{}", getuid());
-        let decrypt_key_metadata = key_generations::generate_rsa_key(
-            &sec_level,
+        let Some(decrypt_key_metadata) = key_generations::generate_rsa_key(
+            &sl,
             Domain::APP,
             -1,
             Some(decrypt_key_alias),
@@ -126,7 +130,9 @@ fn keystore2_attest_rsa_encrypt_key_success() {
             },
             Some(&attestation_key_metadata.key),
         )
-        .unwrap();
+        .unwrap() else {
+            return;
+        };
 
         let mut cert_chain: Vec<u8> = Vec::new();
         cert_chain.extend(decrypt_key_metadata.certificate.as_ref().unwrap());
@@ -143,14 +149,17 @@ fn keystore2_attest_rsa_encrypt_key_success() {
 fn keystore2_attest_ec_key_success() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let att_challenge: &[u8] = b"foo";
 
     for algo in [Algorithm::RSA, Algorithm::EC] {
         // Create attestation key.
-        let attestation_key_metadata =
-            key_generations::generate_attestation_key(&sec_level, algo, att_challenge).unwrap();
+        let Some(attestation_key_metadata) = key_generations::map_ks_error(
+            key_generations::generate_attestation_key(&sl, algo, att_challenge),
+        )
+        .unwrap() else {
+            return;
+        };
 
         let mut cert_chain: Vec<u8> = Vec::new();
         cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
@@ -160,7 +169,7 @@ fn keystore2_attest_ec_key_success() {
         // Create EC key and use attestation key to sign it.
         let ec_key_alias = format!("ks_ec_attested_test_key_{}", getuid());
         let ec_key_metadata = key_generations::generate_ec_256_attested_key(
-            &sec_level,
+            &sl,
             Some(ec_key_alias),
             att_challenge,
             &attestation_key_metadata.key,
@@ -183,18 +192,28 @@ fn keystore2_attest_ec_key_success() {
 fn keystore2_attest_rsa_signing_key_with_ec_25519_key_success() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
+    if sl.get_keymint_version() < 2 {
+        // Curve 25519 was included in version 2 of the KeyMint interface.
+        // For device with KeyMint-V1 or Keymaster in backend, emulated Ed25519 key can't attest
+        // to a "real" RSA key.
+        return;
+    }
+
     let att_challenge: &[u8] = b"foo";
 
     // Create EcCurve::CURVE_25519 attestation key.
-    let attestation_key_metadata = key_generations::generate_ec_attestation_key(
-        &sec_level,
-        att_challenge,
-        Digest::NONE,
-        EcCurve::CURVE_25519,
-    )
-    .unwrap();
+    let Some(attestation_key_metadata) =
+        key_generations::map_ks_error(key_generations::generate_ec_attestation_key(
+            &sl,
+            att_challenge,
+            Digest::NONE,
+            EcCurve::CURVE_25519,
+        ))
+        .unwrap()
+    else {
+        return;
+    };
 
     let mut cert_chain: Vec<u8> = Vec::new();
     cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
@@ -203,8 +222,8 @@ fn keystore2_attest_rsa_signing_key_with_ec_25519_key_success() {
 
     // Create RSA signing key and use attestation key to sign it.
     let sign_key_alias = format!("ksrsa_attested_sign_test_key_{}", getuid());
-    let sign_key_metadata = key_generations::generate_rsa_key(
-        &sec_level,
+    let Some(sign_key_metadata) = key_generations::generate_rsa_key(
+        &sl,
         Domain::APP,
         -1,
         Some(sign_key_alias),
@@ -219,7 +238,9 @@ fn keystore2_attest_rsa_signing_key_with_ec_25519_key_success() {
         },
         Some(&attestation_key_metadata.key),
     )
-    .unwrap();
+    .unwrap() else {
+        return;
+    };
 
     let mut cert_chain: Vec<u8> = Vec::new();
     cert_chain.extend(sign_key_metadata.certificate.as_ref().unwrap());
@@ -233,9 +254,14 @@ fn keystore2_attest_rsa_signing_key_with_ec_25519_key_success() {
 #[test]
 fn keystore2_generate_rsa_attest_key_with_multi_purpose_fail() {
     skip_test_if_no_app_attest_key_feature!();
-
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
+    if sl.get_keymint_version() < 2 {
+        // The KeyMint v1 spec required that KeyPurpose::ATTEST_KEY not be combined
+        // with other key purposes.  However, this was not checked at the time
+        // so we can only be strict about checking this for implementations of KeyMint
+        // version 2 and above.
+        return;
+    }
 
     let digest = Digest::SHA_2_256;
     let padding = PaddingMode::RSA_PKCS1_1_5_SIGN;
@@ -255,7 +281,7 @@ fn keystore2_generate_rsa_attest_key_with_multi_purpose_fail() {
         .rsa_public_exponent(65537)
         .padding_mode(padding);
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -276,9 +302,14 @@ fn keystore2_generate_rsa_attest_key_with_multi_purpose_fail() {
 #[test]
 fn keystore2_ec_attest_key_with_multi_purpose_fail() {
     skip_test_if_no_app_attest_key_feature!();
-
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
+    if sl.get_keymint_version() < 2 {
+        // The KeyMint v1 spec required that KeyPurpose::ATTEST_KEY not be combined
+        // with other key purposes.  However, this was not checked at the time
+        // so we can only be strict about checking this for implementations of KeyMint
+        // version 2 and above.
+        return;
+    }
 
     let attest_key_alias = format!("ks_ec_attest_multipurpose_key_{}", getuid());
 
@@ -291,7 +322,7 @@ fn keystore2_ec_attest_key_with_multi_purpose_fail() {
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256);
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -314,14 +345,16 @@ fn keystore2_ec_attest_key_with_multi_purpose_fail() {
 fn keystore2_attest_key_fails_missing_challenge() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let att_challenge: &[u8] = b"foo";
 
     // Create RSA attestation key.
-    let attestation_key_metadata =
-        key_generations::generate_attestation_key(&sec_level, Algorithm::RSA, att_challenge)
-            .unwrap();
+    let Some(attestation_key_metadata) = key_generations::map_ks_error(
+        key_generations::generate_attestation_key(&sl, Algorithm::RSA, att_challenge),
+    )
+    .unwrap() else {
+        return;
+    };
 
     let mut cert_chain: Vec<u8> = Vec::new();
     cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
@@ -331,7 +364,7 @@ fn keystore2_attest_key_fails_missing_challenge() {
     // Try to attest RSA signing key without providing attestation challenge.
     let sign_key_alias = format!("ksrsa_attested_test_key_missing_challenge{}", getuid());
     let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(sign_key_alias),
@@ -357,24 +390,18 @@ fn keystore2_attest_key_fails_missing_challenge() {
 fn keystore2_attest_rsa_key_with_non_attest_key_fails_incompat_purpose_error() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let att_challenge: &[u8] = b"foo";
 
     let alias = format!("non_attest_key_{}", getuid());
-    let non_attest_key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
-        Domain::APP,
-        -1,
-        Some(alias),
-        None,
-    )
-    .unwrap();
+    let non_attest_key_metadata =
+        key_generations::generate_ec_p256_signing_key(&sl, Domain::APP, -1, Some(alias), None)
+            .unwrap();
 
     // Try to generate RSA signing key with non-attestation key to sign it.
     let sign_key_alias = format!("ksrsa_attested_sign_test_key_non_attest_{}", getuid());
     let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(sign_key_alias),
@@ -399,13 +426,12 @@ fn keystore2_attest_rsa_key_with_non_attest_key_fails_incompat_purpose_error() {
 fn keystore2_attest_rsa_key_with_symmetric_key_fails_sys_error() {
     skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let att_challenge: &[u8] = b"foo";
 
     let alias = "aes_attest_key";
     let sym_key_metadata = key_generations::generate_sym_key(
-        &sec_level,
+        &sl,
         Algorithm::AES,
         128,
         alias,
@@ -418,7 +444,7 @@ fn keystore2_attest_rsa_key_with_symmetric_key_fails_sys_error() {
     // Try to generate RSA signing key with symmetric key as attestation key.
     let sign_key_alias = format!("ksrsa_attested_sign_test_key_sym_attest_{}", getuid());
     let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(sign_key_alias),
@@ -437,56 +463,6 @@ fn keystore2_attest_rsa_key_with_symmetric_key_fails_sys_error() {
     assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());
 }
 
-/// Generate RSA attestation key and try to use it as attestation key while generating symmetric
-/// key. Test should generate symmetric key successfully. Verify that generated symmetric key
-/// should not have attestation record or certificate.
-#[test]
-fn keystore2_attest_symmetric_key_fail_sys_error() {
-    skip_test_if_no_app_attest_key_feature!();
-
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
-    let att_challenge: &[u8] = b"foo";
-
-    // Create attestation key.
-    let attestation_key_metadata =
-        key_generations::generate_attestation_key(&sec_level, Algorithm::RSA, att_challenge)
-            .unwrap();
-
-    let mut cert_chain: Vec<u8> = Vec::new();
-    cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
-    cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
-    validate_certchain(&cert_chain).expect("Error while validating cert chain.");
-
-    // Generate symmetric key with above generated key as attestation key.
-    let gen_params = authorizations::AuthSetBuilder::new()
-        .no_auth_required()
-        .algorithm(Algorithm::AES)
-        .purpose(KeyPurpose::ENCRYPT)
-        .purpose(KeyPurpose::DECRYPT)
-        .key_size(128)
-        .padding_mode(PaddingMode::NONE)
-        .block_mode(BlockMode::ECB)
-        .attestation_challenge(att_challenge.to_vec());
-
-    let alias = format!("ks_test_sym_key_attest_{}", getuid());
-    let aes_key_metadata = sec_level
-        .generateKey(
-            &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
-            Some(&attestation_key_metadata.key),
-            &gen_params,
-            0,
-            b"entropy",
-        )
-        .unwrap();
-
-    // Should not have public certificate.
-    assert!(aes_key_metadata.certificate.is_none());
-
-    // Should not have an attestation record.
-    assert!(aes_key_metadata.certificateChain.is_none());
-}
-
 fn get_attestation_ids(keystore2: &binder::Strong<dyn IKeystoreService>) -> Vec<(Tag, Vec<u8>)> {
     let attest_ids = vec![
         (Tag::ATTESTATION_ID_BRAND, "brand"),
@@ -525,22 +501,24 @@ fn generate_attested_key_with_device_attest_ids(algorithm: Algorithm) {
     skip_test_if_no_device_id_attestation_feature!();
     skip_device_id_attestation_tests!();
     skip_test_if_no_app_attest_key_feature!();
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let att_challenge: &[u8] = b"foo";
+    let Some(attest_key_metadata) = key_generations::map_ks_error(
+        key_generations::generate_attestation_key(&sl, algorithm, att_challenge),
+    )
+    .unwrap() else {
+        return;
+    };
 
-    let attest_key_metadata =
-        key_generations::generate_attestation_key(&sec_level, algorithm, att_challenge).unwrap();
-
-    let attest_id_params = get_attestation_ids(&keystore2);
+    let attest_id_params = get_attestation_ids(&sl.keystore2);
 
     for (attest_id, value) in attest_id_params {
         // Create RSA/EC key and use attestation key to sign it.
         let key_alias = format!("ks_attested_test_key_{}", getuid());
         let key_metadata =
             key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
-                &sec_level,
+                &sl,
                 algorithm,
                 Some(key_alias),
                 att_challenge,
@@ -584,21 +562,21 @@ fn keystore2_attest_rsa_attestation_id() {
 #[test]
 fn keystore2_attest_key_fails_with_invalid_attestation_id() {
     skip_test_if_no_device_id_attestation_feature!();
+    skip_device_id_attestation_tests!();
+    skip_test_if_no_app_attest_key_feature!();
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let digest = Digest::SHA_2_256;
     let att_challenge: &[u8] = b"foo";
 
     // Create EC-Attestation key.
-    let attest_key_metadata = key_generations::generate_ec_attestation_key(
-        &sec_level,
-        att_challenge,
-        digest,
-        EcCurve::P_256,
+    let Some(attest_key_metadata) = key_generations::map_ks_error(
+        key_generations::generate_ec_attestation_key(&sl, att_challenge, digest, EcCurve::P_256),
     )
-    .unwrap();
+    .unwrap() else {
+        return;
+    };
 
     let attest_id_params = vec![
         (Tag::ATTESTATION_ID_BRAND, b"invalid-brand".to_vec()),
@@ -614,7 +592,7 @@ fn keystore2_attest_key_fails_with_invalid_attestation_id() {
         // Create EC key and use attestation key to sign it.
         let ec_key_alias = format!("ks_ec_attested_test_key_fail_{}{}", getuid(), digest.0);
         let result = key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
-            &sec_level,
+            &sl,
             Algorithm::EC,
             Some(ec_key_alias),
             att_challenge,
@@ -638,20 +616,22 @@ fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_
         return;
     }
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let att_challenge: &[u8] = b"foo";
-    let attest_key_metadata =
-        key_generations::generate_attestation_key(&sec_level, Algorithm::RSA, att_challenge)
-            .unwrap();
+    let Some(attest_key_metadata) = key_generations::map_ks_error(
+        key_generations::generate_attestation_key(&sl, Algorithm::RSA, att_challenge),
+    )
+    .unwrap() else {
+        return;
+    };
 
-    let attest_id_params = get_attestation_ids(&keystore2);
+    let attest_id_params = get_attestation_ids(&sl.keystore2);
     for (attest_id, value) in attest_id_params {
         // Create RSA/EC key and use attestation key to sign it.
         let key_alias = format!("ks_attested_test_key_{}", getuid());
         let result = key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
-            &sec_level,
+            &sl,
             Algorithm::RSA,
             Some(key_alias),
             att_challenge,
@@ -666,3 +646,54 @@ fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_
         assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
     }
 }
+
+/// Try to generate an attestation key from user context with UID other than AID_SYSTEM or AID_ROOT
+/// and also there is no package name associated with it. In such case key generation should fail
+/// while collecting Attestation Application ID (AAID) from AAID provider service and keystore
+/// should return error response code - `GET_ATTESTATION_APPLICATION_ID_FAILED`.
+#[test]
+fn keystore2_generate_attested_key_fail_to_get_aaid() {
+    static APP_USER_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+    const USER_ID: u32 = 99;
+    const APPLICATION_ID: u32 = 19901;
+    static APP_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
+    static APP_GID: u32 = APP_UID;
+
+    // SAFETY: The test is run in a separate process with no other threads.
+    unsafe {
+        run_as::run_as(APP_USER_CTX, Uid::from_raw(APP_UID), Gid::from_raw(APP_GID), || {
+            skip_test_if_no_app_attest_key_feature!();
+            let sl = SecLevel::tee();
+            if sl.keystore2.getInterfaceVersion().unwrap() < 4 {
+                // `GET_ATTESTATION_APPLICATION_ID_FAILED` is supported on devices with
+                // `IKeystoreService` version >= 4.
+                return;
+            }
+            let att_challenge: &[u8] = b"foo";
+            let alias = format!("ks_attest_rsa_encrypt_key_aaid_fail{}", getuid());
+
+            let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
+                &sl,
+                Domain::APP,
+                -1,
+                Some(alias),
+                &key_generations::KeyParams {
+                    key_size: 2048,
+                    purpose: vec![KeyPurpose::ATTEST_KEY],
+                    padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
+                    digest: Some(Digest::SHA_2_256),
+                    mgf_digest: None,
+                    block_mode: None,
+                    att_challenge: Some(att_challenge.to_vec()),
+                },
+                None,
+            ));
+
+            assert!(result.is_err());
+            assert_eq!(
+                result.unwrap_err(),
+                Error::Rc(ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED)
+            );
+        })
+    };
+}
diff --git a/keystore2/tests/keystore2_client_authorizations_tests.rs b/keystore2/tests/keystore2_client_authorizations_tests.rs
index 32be99e0..6732f5c1 100644
--- a/keystore2/tests/keystore2_client_authorizations_tests.rs
+++ b/keystore2/tests/keystore2_client_authorizations_tests.rs
@@ -12,49 +12,39 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use std::time::SystemTime;
-
-use openssl::bn::{BigNum, MsbOption};
-use openssl::x509::X509NameBuilder;
-
+use crate::keystore2_client_test_utils::{
+    app_attest_key_feature_exists, delete_app_key,
+    perform_sample_asym_sign_verify_op, perform_sample_hmac_sign_verify_op,
+    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op,
+    verify_certificate_serial_num, verify_certificate_subject_name, SAMPLE_PLAIN_TEXT,
+};
+use crate::{require_keymint, skip_test_if_no_app_attest_key_feature};
+use aconfig_android_hardware_biometrics_rust;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
     ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
     SecurityLevel::SecurityLevel, Tag::Tag,
 };
-
-use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
-    KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
-};
-
-use aconfig_android_hardware_biometrics_rust;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    HardwareAuthToken::HardwareAuthToken,
-    HardwareAuthenticatorType::HardwareAuthenticatorType
+    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
 };
-use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::Timestamp::Timestamp;
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_auth_service, get_keystore_service, key_generations,
-    key_generations::Error,
+use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
+    Timestamp::Timestamp
 };
-
-use crate::keystore2_client_test_utils::{
-    app_attest_key_feature_exists, delete_app_key, perform_sample_asym_sign_verify_op,
-    perform_sample_hmac_sign_verify_op, perform_sample_sym_key_decrypt_op,
-    perform_sample_sym_key_encrypt_op, verify_certificate_serial_num,
-    verify_certificate_subject_name, SAMPLE_PLAIN_TEXT,
+use android_system_keystore2::aidl::android::system::keystore2::{
+    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
+    ResponseCode::ResponseCode,
 };
-
-use crate::{skip_test_if_no_app_attest_key_feature, skip_tests_if_keymaster_impl_present};
-
 use keystore2_test_utils::ffi_test_utils::get_value_from_attest_record;
+use keystore2_test_utils::{
+    authorizations, get_keystore_auth_service, key_generations,
+    key_generations::Error, SecLevel,
+};
+use openssl::bn::{BigNum, MsbOption};
+use openssl::x509::X509NameBuilder;
+use std::time::SystemTime;
 
-fn gen_key_including_unique_id(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
-    alias: &str,
-) -> Vec<u8> {
+fn gen_key_including_unique_id(sl: &SecLevel, alias: &str) -> Option<Vec<u8>> {
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
@@ -65,7 +55,9 @@ fn gen_key_including_unique_id(
         .attestation_challenge(b"foo".to_vec())
         .include_unique_id();
 
-    let key_metadata = key_generations::generate_key(sec_level, &gen_params, alias).unwrap();
+    let key_metadata =
+        key_generations::map_ks_error(key_generations::generate_key(sl, &gen_params, alias))
+            .unwrap()?;
 
     let unique_id = get_value_from_attest_record(
         key_metadata.certificate.as_ref().unwrap(),
@@ -74,23 +66,30 @@ fn gen_key_including_unique_id(
     )
     .expect("Unique id not found.");
     assert!(!unique_id.is_empty());
-    unique_id
+    Some(unique_id)
 }
 
 fn generate_key_and_perform_sign_verify_op_max_times(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     gen_params: &authorizations::AuthSetBuilder,
     alias: &str,
     max_usage_count: i32,
-) -> binder::Result<KeyMetadata> {
-    let key_metadata = key_generations::generate_key(sec_level, gen_params, alias)?;
+) -> binder::Result<Option<KeyMetadata>> {
+    let Some(key_metadata) = key_generations::generate_key(sl, gen_params, alias)? else {
+        return Ok(None);
+    };
 
     // Use above generated key `max_usage_count` times.
     for _ in 0..max_usage_count {
-        perform_sample_asym_sign_verify_op(sec_level, &key_metadata, None, Some(Digest::SHA_2_256));
+        perform_sample_asym_sign_verify_op(
+            &sl.binder,
+            &key_metadata,
+            None,
+            Some(Digest::SHA_2_256),
+        );
     }
 
-    Ok(key_metadata)
+    Ok(Some(key_metadata))
 }
 
 /// Generate a key with `USAGE_COUNT_LIMIT` and verify the key characteristics. Test should be able
@@ -98,24 +97,23 @@ fn generate_key_and_perform_sign_verify_op_max_times(
 /// times subsequent attempts to use the key in test should fail with response code `KEY_NOT_FOUND`.
 /// Test should also verify that the attest record includes `USAGE_COUNT_LIMIT` for attested keys.
 fn generate_key_and_perform_op_with_max_usage_limit(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     gen_params: &authorizations::AuthSetBuilder,
     alias: &str,
     max_usage_count: i32,
     check_attestation: bool,
 ) {
     // Generate a key and use the key for `max_usage_count` times.
-    let key_metadata = generate_key_and_perform_sign_verify_op_max_times(
-        sec_level,
-        gen_params,
-        alias,
-        max_usage_count,
-    )
-    .unwrap();
+    let Some(key_metadata) =
+        generate_key_and_perform_sign_verify_op_max_times(sl, gen_params, alias, max_usage_count)
+            .unwrap()
+    else {
+        return;
+    };
 
     let auth = key_generations::get_key_auth(&key_metadata.authorizations, Tag::USAGE_COUNT_LIMIT)
         .unwrap();
-    if check_attestation && key_generations::has_default_keymint() {
+    if check_attestation && sl.is_keymint() {
         // Check usage-count-limit is included in attest-record.
         // `USAGE_COUNT_LIMIT` is supported from KeyMint1.0
         assert_ne!(
@@ -142,7 +140,7 @@ fn generate_key_and_perform_op_with_max_usage_limit(
     }
 
     // Try to use the key one more time.
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
@@ -156,8 +154,7 @@ fn generate_key_and_perform_op_with_max_usage_limit(
 /// the generated key successfully.
 #[test]
 fn keystore2_gen_key_auth_active_datetime_test_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let active_datetime = duration_since_epoch.as_millis();
@@ -168,18 +165,17 @@ fn keystore2_gen_key_auth_active_datetime_test_success() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .active_date_time(active_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         alias,
     );
     assert!(result.is_ok());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `ACTIVE_DATETIME` set to future date and time. Test should successfully
@@ -188,8 +184,7 @@ fn keystore2_gen_key_auth_active_datetime_test_success() {
 /// `KEY_NOT_YET_VALID`.
 #[test]
 fn keystore2_gen_key_auth_future_active_datetime_test_op_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let future_active_datetime = duration_since_epoch.as_millis() + (24 * 60 * 60 * 1000);
@@ -200,19 +195,18 @@ fn keystore2_gen_key_auth_future_active_datetime_test_op_fail() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .active_date_time(future_active_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         alias,
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::KEY_NOT_YET_VALID), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `ORIGINATION_EXPIRE_DATETIME` set to future date and time. Test should
@@ -220,8 +214,7 @@ fn keystore2_gen_key_auth_future_active_datetime_test_op_fail() {
 /// sign operation using the generated key successfully.
 #[test]
 fn keystore2_gen_key_auth_future_origination_expire_datetime_test_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let origination_expire_datetime = duration_since_epoch.as_millis() + (24 * 60 * 60 * 1000);
@@ -232,18 +225,17 @@ fn keystore2_gen_key_auth_future_origination_expire_datetime_test_success() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .origination_expire_date_time(origination_expire_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         alias,
     );
     assert!(result.is_ok());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `ORIGINATION_EXPIRE_DATETIME` set to current date and time. Test should
@@ -252,8 +244,7 @@ fn keystore2_gen_key_auth_future_origination_expire_datetime_test_success() {
 /// `KEY_EXPIRED`.
 #[test]
 fn keystore2_gen_key_auth_origination_expire_datetime_test_op_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let origination_expire_datetime = duration_since_epoch.as_millis();
@@ -264,19 +255,18 @@ fn keystore2_gen_key_auth_origination_expire_datetime_test_op_fail() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .origination_expire_date_time(origination_expire_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         alias,
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::KEY_EXPIRED), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a HMAC key with `USAGE_EXPIRE_DATETIME` set to future date and time. Test should
@@ -284,8 +274,7 @@ fn keystore2_gen_key_auth_origination_expire_datetime_test_op_fail() {
 /// sign and verify operations using the generated key successfully.
 #[test]
 fn keystore2_gen_key_auth_future_usage_expire_datetime_hmac_verify_op_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let usage_expire_datetime = duration_since_epoch.as_millis() + (24 * 60 * 60 * 1000);
@@ -300,10 +289,12 @@ fn keystore2_gen_key_auth_future_usage_expire_datetime_hmac_verify_op_success()
         .usage_expire_date_time(usage_expire_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_hmac_verify_success";
-    let key_metadata = key_generations::generate_key(&sec_level, &gen_params, alias).unwrap();
+    let Some(key_metadata) = key_generations::generate_key(&sl, &gen_params, alias).unwrap() else {
+        return;
+    };
 
-    perform_sample_hmac_sign_verify_op(&sec_level, &key_metadata.key);
-    delete_app_key(&keystore2, alias).unwrap();
+    perform_sample_hmac_sign_verify_op(&sl.binder, &key_metadata.key);
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `USAGE_EXPIRE_DATETIME` set to current date and time. Test should
@@ -312,8 +303,7 @@ fn keystore2_gen_key_auth_future_usage_expire_datetime_hmac_verify_op_success()
 /// `KEY_EXPIRED`.
 #[test]
 fn keystore2_gen_key_auth_usage_expire_datetime_hmac_verify_op_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let usage_expire_datetime = duration_since_epoch.as_millis();
@@ -328,10 +318,12 @@ fn keystore2_gen_key_auth_usage_expire_datetime_hmac_verify_op_fail() {
         .usage_expire_date_time(usage_expire_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_hamc_verify_fail";
-    let key_metadata = key_generations::generate_key(&sec_level, &gen_params, alias).unwrap();
+    let Some(key_metadata) = key_generations::generate_key(&sl, &gen_params, alias).unwrap() else {
+        return;
+    };
 
     let result = key_generations::map_ks_error(
-        sec_level.createOperation(
+        sl.binder.createOperation(
             &key_metadata.key,
             &authorizations::AuthSetBuilder::new()
                 .purpose(KeyPurpose::VERIFY)
@@ -341,7 +333,7 @@ fn keystore2_gen_key_auth_usage_expire_datetime_hmac_verify_op_fail() {
     );
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::KEY_EXPIRED), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate AES key with `USAGE_EXPIRE_DATETIME` set to future date and time. Test should
@@ -349,8 +341,7 @@ fn keystore2_gen_key_auth_usage_expire_datetime_hmac_verify_op_fail() {
 /// Encrypt and Decrypt operations successfully.
 #[test]
 fn keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let usage_expire_datetime = duration_since_epoch.as_millis() + (24 * 60 * 60 * 1000);
@@ -365,9 +356,11 @@ fn keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success() {
         .usage_expire_date_time(usage_expire_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
-    let key_metadata = key_generations::generate_key(&sec_level, &gen_params, alias).unwrap();
+    let Some(key_metadata) = key_generations::generate_key(&sl, &gen_params, alias).unwrap() else {
+        return;
+    };
     let cipher_text = perform_sample_sym_key_encrypt_op(
-        &sec_level,
+        &sl.binder,
         PaddingMode::PKCS7,
         BlockMode::ECB,
         &mut None,
@@ -379,7 +372,7 @@ fn keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success() {
     assert!(cipher_text.is_some());
 
     let plain_text = perform_sample_sym_key_decrypt_op(
-        &sec_level,
+        &sl.binder,
         &cipher_text.unwrap(),
         PaddingMode::PKCS7,
         BlockMode::ECB,
@@ -390,7 +383,7 @@ fn keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success() {
     .unwrap();
     assert!(plain_text.is_some());
     assert_eq!(plain_text.unwrap(), SAMPLE_PLAIN_TEXT.to_vec());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate AES key with `USAGE_EXPIRE_DATETIME` set to current date and time. Test should
@@ -399,8 +392,7 @@ fn keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success() {
 /// `KEY_EXPIRED`.
 #[test]
 fn keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let usage_expire_datetime = duration_since_epoch.as_millis();
@@ -415,9 +407,11 @@ fn keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail() {
         .usage_expire_date_time(usage_expire_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
-    let key_metadata = key_generations::generate_key(&sec_level, &gen_params, alias).unwrap();
+    let Some(key_metadata) = key_generations::generate_key(&sl, &gen_params, alias).unwrap() else {
+        return;
+    };
     let cipher_text = perform_sample_sym_key_encrypt_op(
-        &sec_level,
+        &sl.binder,
         PaddingMode::PKCS7,
         BlockMode::ECB,
         &mut None,
@@ -429,7 +423,7 @@ fn keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail() {
     assert!(cipher_text.is_some());
 
     let result = key_generations::map_ks_error(perform_sample_sym_key_decrypt_op(
-        &sec_level,
+        &sl.binder,
         &cipher_text.unwrap(),
         PaddingMode::PKCS7,
         BlockMode::ECB,
@@ -439,7 +433,7 @@ fn keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail() {
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::KEY_EXPIRED), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `EARLY_BOOT_ONLY`. Test should successfully generate
@@ -447,9 +441,8 @@ fn keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail() {
 /// during creation of an operation using this key.
 #[test]
 fn keystore2_gen_key_auth_early_boot_only_op_fail() {
-    skip_tests_if_keymaster_impl_present!();
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
+    require_keymint!(sl);
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
@@ -458,19 +451,18 @@ fn keystore2_gen_key_auth_early_boot_only_op_fail() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .early_boot_only();
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         alias,
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::EARLY_BOOT_ENDED), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `MAX_USES_PER_BOOT`. Test should successfully generate
@@ -479,8 +471,7 @@ fn keystore2_gen_key_auth_early_boot_only_op_fail() {
 /// subsequent attempts to use the key in test should fail with error code MAX_OPS_EXCEEDED.
 #[test]
 fn keystore2_gen_key_auth_max_uses_per_boot() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     const MAX_USES_COUNT: i32 = 3;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -490,28 +481,26 @@ fn keystore2_gen_key_auth_max_uses_per_boot() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .max_uses_per_boot(MAX_USES_COUNT);
 
     let alias = "ks_test_auth_tags_test";
     // Generate a key and use the key for `MAX_USES_COUNT` times.
-    let key_metadata = generate_key_and_perform_sign_verify_op_max_times(
-        &sec_level,
-        &gen_params,
-        alias,
-        MAX_USES_COUNT,
-    )
-    .unwrap();
+    let Some(key_metadata) =
+        generate_key_and_perform_sign_verify_op_max_times(&sl, &gen_params, alias, MAX_USES_COUNT)
+            .unwrap()
+    else {
+        return;
+    };
 
     // Try to use the key one more time.
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::KEY_MAX_OPS_EXCEEDED), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `USAGE_COUNT_LIMIT`. Test should successfully generate
@@ -521,8 +510,7 @@ fn keystore2_gen_key_auth_max_uses_per_boot() {
 /// Test should also verify that the attest record includes `USAGE_COUNT_LIMIT`.
 #[test]
 fn keystore2_gen_key_auth_usage_count_limit() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     const MAX_USES_COUNT: i32 = 3;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -536,13 +524,7 @@ fn keystore2_gen_key_auth_usage_count_limit() {
         .usage_count_limit(MAX_USES_COUNT);
 
     let alias = "ks_test_auth_tags_test";
-    generate_key_and_perform_op_with_max_usage_limit(
-        &sec_level,
-        &gen_params,
-        alias,
-        MAX_USES_COUNT,
-        true,
-    );
+    generate_key_and_perform_op_with_max_usage_limit(&sl, &gen_params, alias, MAX_USES_COUNT, true);
 }
 
 /// Generate a key with `USAGE_COUNT_LIMIT`. Test should successfully generate
@@ -552,8 +534,7 @@ fn keystore2_gen_key_auth_usage_count_limit() {
 /// Test should also verify that the attest record includes `USAGE_COUNT_LIMIT`.
 #[test]
 fn keystore2_gen_key_auth_usage_count_limit_one() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     const MAX_USES_COUNT: i32 = 1;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -567,13 +548,7 @@ fn keystore2_gen_key_auth_usage_count_limit_one() {
         .usage_count_limit(MAX_USES_COUNT);
 
     let alias = "ks_test_auth_tags_test";
-    generate_key_and_perform_op_with_max_usage_limit(
-        &sec_level,
-        &gen_params,
-        alias,
-        MAX_USES_COUNT,
-        true,
-    );
+    generate_key_and_perform_op_with_max_usage_limit(&sl, &gen_params, alias, MAX_USES_COUNT, true);
 }
 
 /// Generate a non-attested key with `USAGE_COUNT_LIMIT`. Test should successfully generate
@@ -582,8 +557,7 @@ fn keystore2_gen_key_auth_usage_count_limit_one() {
 /// subsequent attempts to use the key in test should fail with response code `KEY_NOT_FOUND`.
 #[test]
 fn keystore2_gen_non_attested_key_auth_usage_count_limit() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     const MAX_USES_COUNT: i32 = 2;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -597,7 +571,7 @@ fn keystore2_gen_non_attested_key_auth_usage_count_limit() {
 
     let alias = "ks_test_auth_tags_test";
     generate_key_and_perform_op_with_max_usage_limit(
-        &sec_level,
+        &sl,
         &gen_params,
         alias,
         MAX_USES_COUNT,
@@ -610,8 +584,7 @@ fn keystore2_gen_non_attested_key_auth_usage_count_limit() {
 /// specify `CREATION_DATETIME`.
 #[test]
 fn keystore2_gen_key_auth_creation_date_time_test_fail_with_invalid_arg_error() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
     let creation_datetime = duration_since_epoch.as_millis();
@@ -622,11 +595,10 @@ fn keystore2_gen_key_auth_creation_date_time_test_fail_with_invalid_arg_error()
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .creation_date_time(creation_datetime.try_into().unwrap());
 
     let alias = "ks_test_auth_tags_test";
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -647,27 +619,25 @@ fn keystore2_gen_key_auth_creation_date_time_test_fail_with_invalid_arg_error()
 /// included in attest record and it remains the same for new keys generated.
 #[test]
 fn keystore2_gen_key_auth_include_unique_id_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias_first = "ks_test_auth_tags_test_1";
-    let unique_id_first = gen_key_including_unique_id(&sec_level, alias_first);
+    if let Some(unique_id_first) = gen_key_including_unique_id(&sl, alias_first) {
+        let alias_second = "ks_test_auth_tags_test_2";
+        let unique_id_second = gen_key_including_unique_id(&sl, alias_second).unwrap();
 
-    let alias_second = "ks_test_auth_tags_test_2";
-    let unique_id_second = gen_key_including_unique_id(&sec_level, alias_second);
+        assert_eq!(unique_id_first, unique_id_second);
 
-    assert_eq!(unique_id_first, unique_id_second);
-
-    delete_app_key(&keystore2, alias_first).unwrap();
-    delete_app_key(&keystore2, alias_second).unwrap();
+        delete_app_key(&sl.keystore2, alias_first).unwrap();
+        delete_app_key(&sl.keystore2, alias_second).unwrap();
+    }
 }
 
 /// Generate a key with `APPLICATION_DATA`. Test should create an operation using the
 /// same `APPLICATION_DATA` successfully.
 #[test]
 fn keystore2_gen_key_auth_app_data_test_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
@@ -680,7 +650,7 @@ fn keystore2_gen_key_auth_app_data_test_success() {
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
@@ -689,7 +659,7 @@ fn keystore2_gen_key_auth_app_data_test_success() {
         alias,
     );
     assert!(result.is_ok());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `APPLICATION_DATA`. Try to create an operation using the
@@ -697,8 +667,7 @@ fn keystore2_gen_key_auth_app_data_test_success() {
 /// `INVALID_KEY_BLOB`.
 #[test]
 fn keystore2_gen_key_auth_app_data_test_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
@@ -711,7 +680,7 @@ fn keystore2_gen_key_auth_app_data_test_fail() {
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
@@ -721,15 +690,14 @@ fn keystore2_gen_key_auth_app_data_test_fail() {
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_KEY_BLOB), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `APPLICATION_ID`. Test should create an operation using the
 /// same `APPLICATION_ID` successfully.
 #[test]
 fn keystore2_gen_key_auth_app_id_test_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
@@ -742,7 +710,7 @@ fn keystore2_gen_key_auth_app_id_test_success() {
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
@@ -751,7 +719,7 @@ fn keystore2_gen_key_auth_app_id_test_success() {
         alias,
     );
     assert!(result.is_ok());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate a key with `APPLICATION_ID`. Try to create an operation using the
@@ -759,8 +727,7 @@ fn keystore2_gen_key_auth_app_id_test_success() {
 /// `INVALID_KEY_BLOB`.
 #[test]
 fn keystore2_gen_key_auth_app_id_test_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
@@ -773,7 +740,7 @@ fn keystore2_gen_key_auth_app_id_test_fail() {
 
     let alias = "ks_test_auth_tags_test";
     let result = key_generations::map_ks_error(key_generations::create_key_and_operation(
-        &sec_level,
+        &sl,
         &gen_params,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
@@ -783,7 +750,7 @@ fn keystore2_gen_key_auth_app_id_test_fail() {
     ));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_KEY_BLOB), result.unwrap_err());
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate an attestation-key without specifying `APPLICATION_ID` and `APPLICATION_DATA`.
@@ -792,8 +759,7 @@ fn keystore2_gen_key_auth_app_id_test_fail() {
 #[test]
 fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
     skip_test_if_no_app_attest_key_feature!();
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     // Generate attestation key.
     let attest_gen_params = authorizations::AuthSetBuilder::new()
@@ -804,8 +770,11 @@ fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
         .ec_curve(EcCurve::P_256)
         .attestation_challenge(b"foo".to_vec());
     let attest_alias = "ks_test_auth_tags_attest_key";
-    let attest_key_metadata =
-        key_generations::generate_key(&sec_level, &attest_gen_params, attest_alias).unwrap();
+    let Some(attest_key_metadata) =
+        key_generations::generate_key(&sl, &attest_gen_params, attest_alias).unwrap()
+    else {
+        return;
+    };
 
     // Generate attested key.
     let alias = "ks_test_auth_tags_attested_key";
@@ -820,7 +789,7 @@ fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
         .app_id(b"app-id".to_vec())
         .app_data(b"app-data".to_vec());
 
-    let result = sec_level.generateKey(
+    let result = sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -834,8 +803,8 @@ fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
     );
 
     assert!(result.is_ok());
-    delete_app_key(&keystore2, alias).unwrap();
-    delete_app_key(&keystore2, attest_alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, attest_alias).unwrap();
 }
 
 /// Generate an attestation-key with specifying `APPLICATION_ID` and `APPLICATION_DATA`.
@@ -847,8 +816,7 @@ fn keystore2_gen_attested_key_auth_app_id_app_data_test_success() {
 #[test]
 fn keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail() {
     skip_test_if_no_app_attest_key_feature!();
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     // Generate attestation key.
     let attest_gen_params = authorizations::AuthSetBuilder::new()
@@ -861,8 +829,11 @@ fn keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail() {
         .app_id(b"app-id".to_vec())
         .app_data(b"app-data".to_vec());
     let attest_alias = "ks_test_auth_tags_attest_key";
-    let attest_key_metadata =
-        key_generations::generate_key(&sec_level, &attest_gen_params, attest_alias).unwrap();
+    let Some(attest_key_metadata) =
+        key_generations::generate_key(&sl, &attest_gen_params, attest_alias).unwrap()
+    else {
+        return;
+    };
 
     // Generate new key using above generated attestation key without providing app-id and app-data.
     let alias = "ks_test_auth_tags_attested_key";
@@ -875,7 +846,7 @@ fn keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail() {
         .ec_curve(EcCurve::P_256)
         .attestation_challenge(b"foo".to_vec());
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -890,7 +861,7 @@ fn keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail() {
 
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_KEY_BLOB), result.unwrap_err());
-    delete_app_key(&keystore2, attest_alias).unwrap();
+    delete_app_key(&sl.keystore2, attest_alias).unwrap();
 }
 
 fn add_hardware_token(auth_type: HardwareAuthenticatorType) {
@@ -951,9 +922,8 @@ fn keystore2_flagged_on_get_last_auth_fingerprint_success() {
 /// generate a key successfully and verify the specified key parameters.
 #[test]
 fn keystore2_gen_key_auth_serial_number_subject_test_success() {
-    skip_tests_if_keymaster_impl_present!();
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
+    require_keymint!(sl);
 
     let cert_subject = "test cert subject";
     let mut x509_name = X509NameBuilder::new().unwrap();
@@ -970,16 +940,17 @@ fn keystore2_gen_key_auth_serial_number_subject_test_success() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256)
         .ec_curve(EcCurve::P_256)
-        .attestation_challenge(b"foo".to_vec())
         .cert_subject_name(x509_name)
         .cert_serial(serial.to_vec());
 
     let alias = "ks_test_auth_tags_test";
-    let key_metadata = key_generations::generate_key(&sec_level, &gen_params, alias).unwrap();
+    let Some(key_metadata) = key_generations::generate_key(&sl, &gen_params, alias).unwrap() else {
+        return;
+    };
     verify_certificate_subject_name(
         key_metadata.certificate.as_ref().unwrap(),
         cert_subject.as_bytes(),
     );
     verify_certificate_serial_num(key_metadata.certificate.as_ref().unwrap(), &serial);
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
diff --git a/keystore2/tests/keystore2_client_delete_key_tests.rs b/keystore2/tests/keystore2_client_delete_key_tests.rs
index 2a06edbc..a0fb9c2a 100644
--- a/keystore2/tests/keystore2_client_delete_key_tests.rs
+++ b/keystore2/tests/keystore2_client_delete_key_tests.rs
@@ -12,27 +12,24 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::getuid;
-
-use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    ErrorCode::ErrorCode, SecurityLevel::SecurityLevel,
-};
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::ErrorCode::ErrorCode;
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
 };
-
-use keystore2_test_utils::{get_keystore_service, key_generations, key_generations::Error};
+use keystore2_test_utils::{
+    get_keystore_service, key_generations, key_generations::Error, SecLevel,
+};
+use nix::unistd::getuid;
 
 /// Generate a key and delete it using keystore2 service `deleteKey` API. Test should successfully
 /// delete the generated key.
 #[test]
 fn keystore2_delete_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "delete_key_success_key";
 
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -40,10 +37,10 @@ fn keystore2_delete_key_success() {
     )
     .unwrap();
 
-    keystore2.deleteKey(&key_metadata.key).expect("Failed to delete a key.");
+    sl.keystore2.deleteKey(&key_metadata.key).expect("Failed to delete a key.");
 
     // Check wehther deleted key is removed from keystore.
-    let result = key_generations::map_ks_error(keystore2.getKeyEntry(&key_metadata.key));
+    let result = key_generations::map_ks_error(sl.keystore2.getKeyEntry(&key_metadata.key));
     assert!(result.is_err());
     assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
 }
@@ -70,12 +67,11 @@ fn keystore2_delete_key_fail() {
 /// `INVALID_ARGUMENT`.
 #[test]
 fn keystore2_delete_key_with_blob_domain_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "delete_key_blob_fail_key";
 
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::BLOB,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias.to_string()),
@@ -83,7 +79,7 @@ fn keystore2_delete_key_with_blob_domain_fail() {
     )
     .unwrap();
 
-    let result = key_generations::map_ks_error(keystore2.deleteKey(&key_metadata.key));
+    let result = key_generations::map_ks_error(sl.keystore2.deleteKey(&key_metadata.key));
     assert!(result.is_err());
     assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());
 }
@@ -92,12 +88,11 @@ fn keystore2_delete_key_with_blob_domain_fail() {
 /// security level `deleteKey` API. Test should delete the key successfully.
 #[test]
 fn keystore2_delete_key_blob_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "delete_key_blob_success_key";
 
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::BLOB,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias.to_string()),
@@ -105,7 +100,7 @@ fn keystore2_delete_key_blob_success() {
     )
     .unwrap();
 
-    let result = sec_level.deleteKey(&key_metadata.key);
+    let result = sl.binder.deleteKey(&key_metadata.key);
     assert!(result.is_ok());
 }
 
@@ -113,10 +108,9 @@ fn keystore2_delete_key_blob_success() {
 /// key with error code `INVALID_ARGUMENT`.
 #[test]
 fn keystore2_delete_key_fails_with_missing_key_blob() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
-    let result = key_generations::map_ks_error(sec_level.deleteKey(&KeyDescriptor {
+    let result = key_generations::map_ks_error(sl.binder.deleteKey(&KeyDescriptor {
         domain: Domain::BLOB,
         nspace: key_generations::SELINUX_SHELL_NAMESPACE,
         alias: None,
@@ -131,20 +125,14 @@ fn keystore2_delete_key_fails_with_missing_key_blob() {
 /// with error code `INVALID_ARGUMENT`.
 #[test]
 fn keystore2_delete_key_blob_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_delete_keyblob_test_key_{}", getuid());
 
-    let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
-        Domain::APP,
-        -1,
-        Some(alias),
-        None,
-    )
-    .unwrap();
+    let key_metadata =
+        key_generations::generate_ec_p256_signing_key(&sl, Domain::APP, -1, Some(alias), None)
+            .unwrap();
 
-    let result = key_generations::map_ks_error(sec_level.deleteKey(&key_metadata.key));
+    let result = key_generations::map_ks_error(sl.binder.deleteKey(&key_metadata.key));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_ARGUMENT), result.unwrap_err());
 }
diff --git a/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs b/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs
index b784adf4..91370c77 100644
--- a/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs
+++ b/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs
@@ -11,23 +11,18 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
-    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, SecurityLevel::SecurityLevel, Tag::Tag,
-};
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
-
-use keystore2_test_utils::ffi_test_utils::get_value_from_attest_record;
 
 use crate::keystore2_client_test_utils::{
     delete_app_key, get_attest_id_value, is_second_imei_id_attestation_required,
-    perform_sample_asym_sign_verify_op,
+    perform_sample_asym_sign_verify_op, skip_device_unique_attestation_tests,
 };
-
-use crate::skip_tests_if_keymaster_impl_present;
+use crate::require_keymint;
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
+    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, Tag::Tag,
+};
+use keystore2_test_utils::ffi_test_utils::get_value_from_attest_record;
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
 
 /// This macro is used for generating device unique attested EC key with device id attestation.
 macro_rules! test_ec_key_device_unique_attestation_id {
@@ -50,6 +45,9 @@ macro_rules! test_rsa_key_device_unique_attestation_id {
 }
 
 fn generate_ec_key_device_unique_attested_with_id_attest(attest_id_tag: Tag, prop_name: &str) {
+    if skip_device_unique_attestation_tests() {
+        return;
+    }
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
@@ -67,6 +65,9 @@ fn generate_ec_key_device_unique_attested_with_id_attest(attest_id_tag: Tag, pro
 }
 
 fn generate_rsa_key_device_unique_attested_with_id_attest(attest_id_tag: Tag, prop_name: &str) {
+    if skip_device_unique_attestation_tests() {
+        return;
+    }
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::RSA)
@@ -113,17 +114,10 @@ fn generate_device_unique_attested_key_with_device_attest_ids(
     attest_id: Tag,
     prop_name: &str,
 ) {
-    let keystore2 = get_keystore_service();
-    let result =
-        key_generations::map_ks_error(keystore2.getSecurityLevel(SecurityLevel::STRONGBOX));
-    if result.is_err() {
-        assert_eq!(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE), result.unwrap_err());
-        return;
-    }
-    let sec_level = result.unwrap();
+    let Some(sl) = SecLevel::strongbox() else { return };
 
     if attest_id == Tag::ATTESTATION_ID_SECOND_IMEI
-        && !is_second_imei_id_attestation_required(&keystore2)
+        && !is_second_imei_id_attestation_required(&sl.keystore2)
     {
         return;
     }
@@ -134,12 +128,9 @@ fn generate_device_unique_attested_key_with_device_attest_ids(
         }
         let gen_params = add_attest_id_auth(gen_params, attest_id, value.clone());
         let alias = "ks_test_device_unique_attest_id_test";
-        match key_generations::map_ks_error(key_generations::generate_key(
-            &sec_level,
-            &gen_params,
-            alias,
-        )) {
-            Ok(key_metadata) => {
+        match key_generations::map_ks_error(key_generations::generate_key(&sl, &gen_params, alias))
+        {
+            Ok(Some(key_metadata)) => {
                 let attest_id_value = get_value_from_attest_record(
                     key_metadata.certificate.as_ref().unwrap(),
                     attest_id,
@@ -147,8 +138,9 @@ fn generate_device_unique_attested_key_with_device_attest_ids(
                 )
                 .expect("Attest id verification failed.");
                 assert_eq!(attest_id_value, value);
-                delete_app_key(&keystore2, alias).unwrap();
+                delete_app_key(&sl.keystore2, alias).unwrap();
             }
+            Ok(None) => {}
             Err(e) => {
                 assert_eq!(e, Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
             }
@@ -160,9 +152,8 @@ fn generate_device_unique_attested_key_with_device_attest_ids(
 /// Test should fail to generate a key with error code `INVALID_ARGUMENT`
 #[test]
 fn keystore2_gen_key_device_unique_attest_with_default_sec_level_unimplemented() {
-    skip_tests_if_keymaster_impl_present!();
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
+    require_keymint!(sl);
 
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
@@ -175,11 +166,8 @@ fn keystore2_gen_key_device_unique_attest_with_default_sec_level_unimplemented()
         .device_unique_attestation();
 
     let alias = "ks_test_auth_tags_test";
-    let result = key_generations::map_ks_error(key_generations::generate_key(
-        &sec_level,
-        &gen_params,
-        alias,
-    ));
+    let result =
+        key_generations::map_ks_error(key_generations::generate_key(&sl, &gen_params, alias));
     assert!(result.is_err());
     assert!(matches!(
         result.unwrap_err(),
@@ -192,15 +180,11 @@ fn keystore2_gen_key_device_unique_attest_with_default_sec_level_unimplemented()
 /// use it for performing an operation.
 #[test]
 fn keystore2_gen_ec_key_device_unique_attest_with_strongbox_sec_level_test_success() {
-    let keystore2 = get_keystore_service();
-    let result =
-        key_generations::map_ks_error(keystore2.getSecurityLevel(SecurityLevel::STRONGBOX));
-    if result.is_err() {
-        assert_eq!(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE), result.unwrap_err());
+    let Some(sl) = SecLevel::strongbox() else { return };
+    if skip_device_unique_attestation_tests() {
         return;
     }
 
-    let sec_level = result.unwrap();
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::EC)
@@ -212,20 +196,17 @@ fn keystore2_gen_ec_key_device_unique_attest_with_strongbox_sec_level_test_succe
         .device_unique_attestation();
 
     let alias = "ks_device_unique_ec_key_attest_test";
-    match key_generations::map_ks_error(key_generations::generate_key(
-        &sec_level,
-        &gen_params,
-        alias,
-    )) {
-        Ok(key_metadata) => {
+    match key_generations::map_ks_error(key_generations::generate_key(&sl, &gen_params, alias)) {
+        Ok(Some(key_metadata)) => {
             perform_sample_asym_sign_verify_op(
-                &sec_level,
+                &sl.binder,
                 &key_metadata,
                 None,
                 Some(Digest::SHA_2_256),
             );
-            delete_app_key(&keystore2, alias).unwrap();
+            delete_app_key(&sl.keystore2, alias).unwrap();
         }
+        Ok(None) => {}
         Err(e) => {
             assert_eq!(e, Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
         }
@@ -237,15 +218,11 @@ fn keystore2_gen_ec_key_device_unique_attest_with_strongbox_sec_level_test_succe
 /// use it for performing an operation.
 #[test]
 fn keystore2_gen_rsa_key_device_unique_attest_with_strongbox_sec_level_test_success() {
-    let keystore2 = get_keystore_service();
-    let result =
-        key_generations::map_ks_error(keystore2.getSecurityLevel(SecurityLevel::STRONGBOX));
-    if result.is_err() {
-        assert_eq!(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE), result.unwrap_err());
+    let Some(sl) = SecLevel::strongbox() else { return };
+    if skip_device_unique_attestation_tests() {
         return;
     }
 
-    let sec_level = result.unwrap();
     let gen_params = authorizations::AuthSetBuilder::new()
         .no_auth_required()
         .algorithm(Algorithm::RSA)
@@ -259,20 +236,17 @@ fn keystore2_gen_rsa_key_device_unique_attest_with_strongbox_sec_level_test_succ
         .device_unique_attestation();
 
     let alias = "ks_device_unique_rsa_key_attest_test";
-    match key_generations::map_ks_error(key_generations::generate_key(
-        &sec_level,
-        &gen_params,
-        alias,
-    )) {
-        Ok(key_metadata) => {
+    match key_generations::map_ks_error(key_generations::generate_key(&sl, &gen_params, alias)) {
+        Ok(Some(key_metadata)) => {
             perform_sample_asym_sign_verify_op(
-                &sec_level,
+                &sl.binder,
                 &key_metadata,
                 Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
                 Some(Digest::SHA_2_256),
             );
-            delete_app_key(&keystore2, alias).unwrap();
+            delete_app_key(&sl.keystore2, alias).unwrap();
         }
+        Ok(None) => {}
         Err(e) => {
             assert_eq!(e, Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
         }
@@ -283,15 +257,11 @@ fn keystore2_gen_rsa_key_device_unique_attest_with_strongbox_sec_level_test_succ
 /// Test should fail with error response code `CANNOT_ATTEST_IDS`.
 #[test]
 fn keystore2_device_unique_attest_key_fails_with_invalid_attestation_id() {
-    let keystore2 = get_keystore_service();
-    let result =
-        key_generations::map_ks_error(keystore2.getSecurityLevel(SecurityLevel::STRONGBOX));
-    if result.is_err() {
-        assert_eq!(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE), result.unwrap_err());
+    let Some(sl) = SecLevel::strongbox() else { return };
+    if skip_device_unique_attestation_tests() {
         return;
     }
 
-    let sec_level = result.unwrap();
     let attest_id_params = vec![
         (Tag::ATTESTATION_ID_BRAND, b"invalid-brand".to_vec()),
         (Tag::ATTESTATION_ID_DEVICE, b"invalid-device-name".to_vec()),
@@ -315,13 +285,10 @@ fn keystore2_device_unique_attest_key_fails_with_invalid_attestation_id() {
         let alias = "ks_ec_device_unique_attested_test_key_fail";
         let gen_params = add_attest_id_auth(gen_params, attest_id, value.clone());
 
-        let result = key_generations::map_ks_error(key_generations::generate_key(
-            &sec_level,
-            &gen_params,
-            alias,
-        ));
+        let result =
+            key_generations::map_ks_error(key_generations::generate_key(&sl, &gen_params, alias));
         assert!(result.is_err());
-        assert!(matches!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS)));
+        assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
     }
 }
 
diff --git a/keystore2/tests/keystore2_client_ec_key_tests.rs b/keystore2/tests/keystore2_client_ec_key_tests.rs
index f2c6d0f9..8aa9bc49 100644
--- a/keystore2/tests/keystore2_client_ec_key_tests.rs
+++ b/keystore2/tests/keystore2_client_ec_key_tests.rs
@@ -12,27 +12,23 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{getuid, Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-
+use crate::keystore2_client_test_utils::{
+    delete_app_key, execute_op_run_as_child, get_vsr_api_level, perform_sample_sign_operation,
+    BarrierReached, ForcedOp, TestOutcome,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
-    KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
+    KeyPurpose::KeyPurpose,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
-    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
-    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
+    CreateOperationResponse::CreateOperationResponse, Domain::Domain, KeyDescriptor::KeyDescriptor,
     ResponseCode::ResponseCode,
 };
-
 use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as,
-};
-
-use crate::keystore2_client_test_utils::{
-    delete_app_key, execute_op_run_as_child, get_vsr_api_level, perform_sample_sign_operation,
-    BarrierReached, ForcedOp, TestOutcome,
+    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
 };
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
 
 macro_rules! test_ec_sign_key_op_success {
     ( $test_name:ident, $digest:expr, $ec_curve:expr ) => {
@@ -57,7 +53,7 @@ macro_rules! test_ec_sign_key_op_with_none_or_md5_digest {
 }
 
 fn create_ec_key_and_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
@@ -65,9 +61,9 @@ fn create_ec_key_and_operation(
     ec_curve: EcCurve,
 ) -> binder::Result<CreateOperationResponse> {
     let key_metadata =
-        key_generations::generate_ec_key(sec_level, domain, nspace, alias, ec_curve, digest)?;
+        key_generations::generate_ec_key(sl, domain, nspace, alias, ec_curve, digest)?;
 
-    sec_level.createOperation(
+    sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(digest),
         false,
@@ -75,11 +71,10 @@ fn create_ec_key_and_operation(
 }
 
 fn perform_ec_sign_key_op_success(alias: &str, digest: Digest, ec_curve: EcCurve) {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let op_response = create_ec_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -96,15 +91,14 @@ fn perform_ec_sign_key_op_success(alias: &str, digest: Digest, ec_curve: EcCurve
         ))
     );
 
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 fn perform_ec_sign_key_op_with_none_or_md5_digest(alias: &str, digest: Digest, ec_curve: EcCurve) {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     match key_generations::map_ks_error(create_ec_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -126,7 +120,7 @@ fn perform_ec_sign_key_op_with_none_or_md5_digest(alias: &str, digest: Digest, e
         }
     }
 
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 // Below macros generate tests for generating EC keys with curves EcCurve::P_224, EcCurve::P_256,
@@ -199,12 +193,11 @@ test_ec_sign_key_op_success!(sign_ec_key_op_sha512_ec_p521, Digest::SHA_2_512, E
 /// INVALID_ARGUMENT error is expected.
 #[test]
 fn keystore2_get_key_entry_blob_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     // Generate a key with domain as BLOB.
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::BLOB,
         key_generations::SELINUX_SHELL_NAMESPACE,
         None,
@@ -213,23 +206,22 @@ fn keystore2_get_key_entry_blob_fail() {
     .unwrap();
 
     // Try to load the key using above generated KeyDescriptor.
-    let result = key_generations::map_ks_error(keystore2.getKeyEntry(&key_metadata.key));
+    let result = key_generations::map_ks_error(sl.keystore2.getKeyEntry(&key_metadata.key));
     assert!(result.is_err());
     assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());
 
     // Delete the generated key blob.
-    sec_level.deleteKey(&key_metadata.key).unwrap();
+    sl.binder.deleteKey(&key_metadata.key).unwrap();
 }
 
 /// Try to generate a key with invalid Domain. `INVALID_ARGUMENT` error response is expected.
 #[test]
 fn keystore2_generate_key_invalid_domain() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_invalid_test_key_{}", getuid());
 
     let result = key_generations::map_ks_error(key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain(99), // Invalid domain.
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias),
@@ -244,8 +236,7 @@ fn keystore2_generate_key_invalid_domain() {
 /// `UNSUPPORTED_EC_CURVE or UNSUPPORTED_KEY_SIZE` error response is expected.
 #[test]
 fn keystore2_generate_ec_key_missing_curve() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_ec_no_curve_test_key_{}", getuid());
 
     // Don't provide EC curve.
@@ -256,7 +247,7 @@ fn keystore2_generate_ec_key_missing_curve() {
         .purpose(KeyPurpose::VERIFY)
         .digest(Digest::SHA_2_256);
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::SELINUX,
             nspace: key_generations::SELINUX_SHELL_NAMESPACE,
@@ -280,8 +271,7 @@ fn keystore2_generate_ec_key_missing_curve() {
 /// `INCOMPATIBLE_PURPOSE` error response is expected.
 #[test]
 fn keystore2_generate_ec_key_25519_multi_purpose() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_ec_no_curve_test_key_{}", getuid());
 
     // Specify `SIGN and AGREE_KEY` purposes.
@@ -293,7 +283,7 @@ fn keystore2_generate_ec_key_25519_multi_purpose() {
         .purpose(KeyPurpose::AGREE_KEY)
         .digest(Digest::SHA_2_256);
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::SELINUX,
             nspace: key_generations::SELINUX_SHELL_NAMESPACE,
@@ -314,12 +304,11 @@ fn keystore2_generate_ec_key_25519_multi_purpose() {
 /// able to create an operation successfully.
 #[test]
 fn keystore2_ec_25519_generate_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_ec_25519_none_test_key_gen_{}", getuid());
     let key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias),
@@ -328,7 +317,8 @@ fn keystore2_ec_25519_generate_key_success() {
     )
     .unwrap();
 
-    let op_response = sec_level
+    let op_response = sl
+        .binder
         .createOperation(
             &key_metadata.key,
             &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::NONE),
@@ -350,8 +340,7 @@ fn keystore2_ec_25519_generate_key_success() {
 /// `UNSUPPORTED_DIGEST`.
 #[test]
 fn keystore2_ec_25519_generate_key_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let digests = [
         Digest::MD5,
@@ -365,7 +354,7 @@ fn keystore2_ec_25519_generate_key_fail() {
     for digest in digests {
         let alias = format!("ks_ec_25519_test_key_gen_{}{}", getuid(), digest.0);
         let key_metadata = key_generations::generate_ec_key(
-            &sec_level,
+            &sl,
             Domain::APP,
             -1,
             Some(alias.to_string()),
@@ -378,7 +367,7 @@ fn keystore2_ec_25519_generate_key_fail() {
         // Digest::NONE".  However, this was not checked at the time so we can only be strict about
         // checking this for more recent implementations.
         if get_vsr_api_level() >= 35 {
-            let result = key_generations::map_ks_error(sec_level.createOperation(
+            let result = key_generations::map_ks_error(sl.binder.createOperation(
                 &key_metadata.key,
                 &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(digest),
                 false,
@@ -394,12 +383,11 @@ fn keystore2_ec_25519_generate_key_fail() {
 /// `INCOMPATIBLE_DIGEST` error as there is a mismatch of digest mode in key authorizations.
 #[test]
 fn keystore2_create_op_with_incompatible_key_digest() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_ec_test_incomp_key_digest";
     let key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -412,7 +400,7 @@ fn keystore2_create_op_with_incompatible_key_digest() {
         [Digest::NONE, Digest::SHA1, Digest::SHA_2_224, Digest::SHA_2_384, Digest::SHA_2_512];
 
     for digest in digests {
-        let result = key_generations::map_ks_error(sec_level.createOperation(
+        let result = key_generations::map_ks_error(sl.binder.createOperation(
             &key_metadata.key,
             &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(digest),
             false,
@@ -488,11 +476,10 @@ fn keystore2_key_owner_validation() {
 /// successfully.
 #[test]
 fn keystore2_generate_key_with_blob_domain() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::BLOB,
         key_generations::SELINUX_SHELL_NAMESPACE,
         None,
@@ -507,7 +494,7 @@ fn keystore2_generate_key_with_blob_domain() {
     // Must have the key blob.
     assert!(key_metadata.key.blob.is_some());
 
-    let op_response = key_generations::map_ks_error(sec_level.createOperation(
+    let op_response = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
@@ -522,5 +509,5 @@ fn keystore2_generate_key_with_blob_domain() {
     );
 
     // Delete the generated key blob.
-    sec_level.deleteKey(&key_metadata.key).unwrap();
+    sl.binder.deleteKey(&key_metadata.key).unwrap();
 }
diff --git a/keystore2/tests/keystore2_client_grant_key_tests.rs b/keystore2/tests/keystore2_client_grant_key_tests.rs
index 516869a1..50b87b9a 100644
--- a/keystore2/tests/keystore2_client_grant_key_tests.rs
+++ b/keystore2/tests/keystore2_client_grant_key_tests.rs
@@ -12,37 +12,32 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{getuid, Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-
+use crate::keystore2_client_test_utils::{
+    generate_ec_key_and_grant_to_users, perform_sample_sign_operation,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Digest::Digest, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
+    Digest::Digest, KeyPurpose::KeyPurpose,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
-    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
+    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
     ResponseCode::ResponseCode,
 };
-
 use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as,
-};
-
-use crate::keystore2_client_test_utils::{
-    generate_ec_key_and_grant_to_users, perform_sample_sign_operation,
+    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
 };
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
 
 /// Generate an EC signing key and grant it to the user with given access vector.
 fn generate_ec_key_and_grant_to_user(
     grantee_uid: i32,
     access_vector: i32,
 ) -> binder::Result<KeyDescriptor> {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("{}{}", "ks_grant_test_key_1", getuid());
 
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::SELINUX,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias),
@@ -50,15 +45,14 @@ fn generate_ec_key_and_grant_to_user(
     )
     .unwrap();
 
-    keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
+    sl.keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
 }
 
 fn load_grant_key_and_perform_sign_operation(
-    keystore2: &binder::Strong<dyn IKeystoreService>,
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     grant_key_nspace: i64,
 ) -> Result<(), binder::Status> {
-    let key_entry_response = keystore2.getKeyEntry(&KeyDescriptor {
+    let key_entry_response = sl.keystore2.getKeyEntry(&KeyDescriptor {
         domain: Domain::GRANT,
         nspace: grant_key_nspace,
         alias: None,
@@ -66,7 +60,7 @@ fn load_grant_key_and_perform_sign_operation(
     })?;
 
     // Perform sample crypto operation using granted key.
-    let op_response = sec_level.createOperation(
+    let op_response = sl.binder.createOperation(
         &key_entry_response.metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
@@ -195,12 +189,11 @@ fn keystore2_grant_get_info_use_key_perm() {
             Uid::from_raw(GRANTEE_UID),
             Gid::from_raw(GRANTEE_GID),
             move || {
-                let keystore2 = get_keystore_service();
-                let sec_level =
-                    keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+                let sl = SecLevel::tee();
 
                 // Load the granted key.
-                let key_entry_response = keystore2
+                let key_entry_response = sl
+                    .keystore2
                     .getKeyEntry(&KeyDescriptor {
                         domain: Domain::GRANT,
                         nspace: grant_key_nspace,
@@ -210,7 +203,8 @@ fn keystore2_grant_get_info_use_key_perm() {
                     .unwrap();
 
                 // Perform sample crypto operation using granted key.
-                let op_response = sec_level
+                let op_response = sl
+                    .binder
                     .createOperation(
                         &key_entry_response.metadata.key,
                         &authorizations::AuthSetBuilder::new()
@@ -228,12 +222,13 @@ fn keystore2_grant_get_info_use_key_perm() {
                 );
 
                 // Try to delete the key, it is expected to be fail with permission denied error.
-                let result = key_generations::map_ks_error(keystore2.deleteKey(&KeyDescriptor {
-                    domain: Domain::GRANT,
-                    nspace: grant_key_nspace,
-                    alias: None,
-                    blob: None,
-                }));
+                let result =
+                    key_generations::map_ks_error(sl.keystore2.deleteKey(&KeyDescriptor {
+                        domain: Domain::GRANT,
+                        nspace: grant_key_nspace,
+                        alias: None,
+                        blob: None,
+                    }));
                 assert!(result.is_err());
                 assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
             },
@@ -258,12 +253,10 @@ fn keystore2_grant_delete_key_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let access_vector = KeyPermission::DELETE.0;
             let mut grant_keys = generate_ec_key_and_grant_to_users(
-                &keystore2,
-                &sec_level,
+                &sl,
                 Some(ALIAS.to_string()),
                 vec![GRANTEE_UID.try_into().unwrap()],
                 access_vector,
@@ -335,13 +328,11 @@ fn keystore2_grant_key_fails_with_permission_denied() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let access_vector = KeyPermission::GET_INFO.0;
             let alias = format!("ks_grant_perm_denied_key_{}", getuid());
             let mut grant_keys = generate_ec_key_and_grant_to_users(
-                &keystore2,
-                &sec_level,
+                &sl,
                 Some(alias),
                 vec![GRANTEE_UID.try_into().unwrap()],
                 access_vector,
@@ -411,8 +402,7 @@ fn keystore2_grant_key_fails_with_permission_denied() {
 /// `GRANT` access. Test should fail to grant a key with `PERMISSION_DENIED` error response code.
 #[test]
 fn keystore2_grant_key_fails_with_grant_perm_expect_perm_denied() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let access_vector = KeyPermission::GRANT.0;
     let alias = format!("ks_grant_access_vec_key_{}", getuid());
     let user_id = 98;
@@ -420,8 +410,7 @@ fn keystore2_grant_key_fails_with_grant_perm_expect_perm_denied() {
     let grantee_uid = user_id * AID_USER_OFFSET + application_id;
 
     let result = key_generations::map_ks_error(generate_ec_key_and_grant_to_users(
-        &keystore2,
-        &sec_level,
+        &sl,
         Some(alias),
         vec![grantee_uid.try_into().unwrap()],
         access_vector,
@@ -470,13 +459,11 @@ fn keystore2_ungrant_key_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = format!("ks_ungrant_test_key_1{}", getuid());
             let access_vector = KeyPermission::GET_INFO.0;
             let mut grant_keys = generate_ec_key_and_grant_to_users(
-                &keystore2,
-                &sec_level,
+                &sl,
                 Some(alias.to_string()),
                 vec![GRANTEE_UID.try_into().unwrap()],
                 access_vector,
@@ -485,8 +472,8 @@ fn keystore2_ungrant_key_success() {
 
             let grant_key_nspace = grant_keys.remove(0);
 
-            //Ungrant above granted key.
-            keystore2
+            // Ungrant above granted key.
+            sl.keystore2
                 .ungrant(
                     &KeyDescriptor {
                         domain: Domain::APP,
@@ -542,12 +529,11 @@ fn keystore2_ungrant_fails_with_non_existing_key_expect_key_not_found_error() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = format!("{}{}", "ks_grant_delete_ungrant_test_key_1", getuid());
 
             let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sec_level,
+                &sl,
                 Domain::SELINUX,
                 key_generations::SELINUX_SHELL_NAMESPACE,
                 Some(alias.to_string()),
@@ -556,17 +542,18 @@ fn keystore2_ungrant_fails_with_non_existing_key_expect_key_not_found_error() {
             .unwrap();
 
             let access_vector = KeyPermission::GET_INFO.0;
-            let grant_key = keystore2
+            let grant_key = sl
+                .keystore2
                 .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
                 .unwrap();
             assert_eq!(grant_key.domain, Domain::GRANT);
 
             // Delete above granted key.
-            keystore2.deleteKey(&key_metadata.key).unwrap();
+            sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 
             // Try to ungrant above granted key.
             let result = key_generations::map_ks_error(
-                keystore2.ungrant(&key_metadata.key, GRANTEE_UID.try_into().unwrap()),
+                sl.keystore2.ungrant(&key_metadata.key, GRANTEE_UID.try_into().unwrap()),
             );
             assert!(result.is_err());
             assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
@@ -574,7 +561,7 @@ fn keystore2_ungrant_fails_with_non_existing_key_expect_key_not_found_error() {
             // Generate a new key with the same alias and try to access the earlier granted key
             // in grantee context.
             let result = key_generations::generate_ec_p256_signing_key(
-                &sec_level,
+                &sl,
                 Domain::SELINUX,
                 key_generations::SELINUX_SHELL_NAMESPACE,
                 Some(alias),
@@ -631,14 +618,12 @@ fn keystore2_grant_key_to_multi_users_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     let mut grant_keys = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = format!("ks_grant_test_key_2{}", getuid());
             let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
 
             generate_ec_key_and_grant_to_users(
-                &keystore2,
-                &sec_level,
+                &sl,
                 Some(alias),
                 vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
                 access_vector,
@@ -658,15 +643,12 @@ fn keystore2_grant_key_to_multi_users_success() {
                 Uid::from_raw(*grantee_uid),
                 Gid::from_raw(*grantee_gid),
                 move || {
-                    let keystore2 = get_keystore_service();
-                    let sec_level =
-                        keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+                    let sl = SecLevel::tee();
 
                     assert_eq!(
                         Ok(()),
                         key_generations::map_ks_error(load_grant_key_and_perform_sign_operation(
-                            &keystore2,
-                            &sec_level,
+                            &sl,
                             grant_key_nspace
                         ))
                     );
@@ -697,15 +679,13 @@ fn keystore2_grant_key_to_multi_users_delete_fails_with_key_not_found_error() {
     // SAFETY: The test is run in a separate process with no other threads.
     let mut grant_keys = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = format!("ks_grant_test_key_2{}", getuid());
             let access_vector =
                 KeyPermission::GET_INFO.0 | KeyPermission::USE.0 | KeyPermission::DELETE.0;
 
             generate_ec_key_and_grant_to_users(
-                &keystore2,
-                &sec_level,
+                &sl,
                 Some(alias),
                 vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
                 access_vector,
@@ -723,21 +703,18 @@ fn keystore2_grant_key_to_multi_users_delete_fails_with_key_not_found_error() {
             Uid::from_raw(GRANTEE_1_UID),
             Gid::from_raw(GRANTEE_1_GID),
             move || {
-                let keystore2 = get_keystore_service();
-                let sec_level =
-                    keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+                let sl = SecLevel::tee();
 
                 assert_eq!(
                     Ok(()),
                     key_generations::map_ks_error(load_grant_key_and_perform_sign_operation(
-                        &keystore2,
-                        &sec_level,
+                        &sl,
                         grant_key1_nspace
                     ))
                 );
 
                 // Delete the granted key.
-                keystore2
+                sl.keystore2
                     .deleteKey(&KeyDescriptor {
                         domain: Domain::GRANT,
                         nspace: grant_key1_nspace,
diff --git a/keystore2/tests/keystore2_client_hmac_key_tests.rs b/keystore2/tests/keystore2_client_hmac_key_tests.rs
index 6bb80017..76780a0b 100644
--- a/keystore2/tests/keystore2_client_hmac_key_tests.rs
+++ b/keystore2/tests/keystore2_client_hmac_key_tests.rs
@@ -12,23 +12,18 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::keystore2_client_test_utils::perform_sample_sign_operation;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
-    SecurityLevel::SecurityLevel,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
-};
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
+    Domain::Domain, KeyDescriptor::KeyDescriptor,
 };
-
-use crate::keystore2_client_test_utils::perform_sample_sign_operation;
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
 
 /// Generate HMAC key with given parameters and perform a sample operation using generated key.
 fn create_hmac_key_and_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: &str,
     key_size: i32,
     mac_len: i32,
@@ -36,9 +31,9 @@ fn create_hmac_key_and_operation(
     digest: Digest,
 ) -> Result<(), binder::Status> {
     let key_metadata =
-        key_generations::generate_hmac_key(sec_level, alias, key_size, min_mac_len, digest)?;
+        key_generations::generate_hmac_key(sl, alias, key_size, min_mac_len, digest)?;
 
-    let op_response = sec_level.createOperation(
+    let op_response = sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new()
             .purpose(KeyPurpose::SIGN)
@@ -69,22 +64,14 @@ fn keystore2_hmac_key_op_success() {
     let mac_len = 128;
     let key_size = 128;
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for digest in digests {
         let alias = format!("ks_hmac_test_key_{}", digest.0);
 
         assert_eq!(
             Ok(()),
-            create_hmac_key_and_operation(
-                &sec_level,
-                &alias,
-                key_size,
-                mac_len,
-                min_mac_len,
-                digest,
-            )
+            create_hmac_key_and_operation(&sl, &alias, key_size, mac_len, min_mac_len, digest,)
         );
     }
 }
@@ -96,13 +83,12 @@ fn keystore2_hmac_gen_keys_fails_expect_unsupported_key_size() {
     let min_mac_len = 256;
     let digest = Digest::SHA_2_256;
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for key_size in 0..513 {
         let alias = format!("ks_hmac_test_key_{}", key_size);
         let result = key_generations::map_ks_error(key_generations::generate_hmac_key(
-            &sec_level,
+            &sl,
             &alias,
             key_size,
             min_mac_len,
@@ -128,13 +114,12 @@ fn keystore2_hmac_gen_keys_fails_expect_unsupported_min_mac_length() {
     let digest = Digest::SHA_2_256;
     let key_size = 128;
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for min_mac_len in 0..257 {
         let alias = format!("ks_hmac_test_key_mml_{}", min_mac_len);
         match key_generations::map_ks_error(key_generations::generate_hmac_key(
-            &sec_level,
+            &sl,
             &alias,
             key_size,
             min_mac_len,
@@ -159,8 +144,7 @@ fn keystore2_hmac_gen_keys_fails_expect_unsupported_min_mac_length() {
 /// Test fails to generate a key with multiple digests with an error code `UNSUPPORTED_DIGEST`.
 #[test]
 fn keystore2_hmac_gen_key_multi_digests_fails_expect_unsupported_digest() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_hmac_test_key_multi_dig";
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -173,7 +157,7 @@ fn keystore2_hmac_gen_key_multi_digests_fails_expect_unsupported_digest() {
         .digest(Digest::SHA1)
         .digest(Digest::SHA_2_256);
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -193,8 +177,7 @@ fn keystore2_hmac_gen_key_multi_digests_fails_expect_unsupported_digest() {
 /// no digest should fail with an error code `UNSUPPORTED_DIGEST`.
 #[test]
 fn keystore2_hmac_gen_key_no_digests_fails_expect_unsupported_digest() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_hmac_test_key_no_dig";
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -205,7 +188,7 @@ fn keystore2_hmac_gen_key_no_digests_fails_expect_unsupported_digest() {
         .key_size(128)
         .min_mac_length(128);
 
-    let result = key_generations::map_ks_error(sec_level.generateKey(
+    let result = key_generations::map_ks_error(sl.binder.generateKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
@@ -227,12 +210,11 @@ fn keystore2_hmac_gen_key_no_digests_fails_expect_unsupported_digest() {
 fn keystore2_hmac_gen_key_with_none_digest_fails_expect_unsupported_digest() {
     let min_mac_len = 128;
     let key_size = 128;
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_hmac_test_key_fail";
     let result = key_generations::map_ks_error(key_generations::generate_hmac_key(
-        &sec_level,
+        &sl,
         alias,
         key_size,
         min_mac_len,
@@ -253,14 +235,13 @@ fn keystore2_hmac_key_op_with_mac_len_greater_than_digest_len_fail() {
     let mac_len = 256;
     let key_size = 128;
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for digest in digests {
         let alias = format!("ks_hmac_test_key_{}", digest.0);
 
         let result = key_generations::map_ks_error(create_hmac_key_and_operation(
-            &sec_level,
+            &sl,
             &alias,
             key_size,
             mac_len,
@@ -284,14 +265,13 @@ fn keystore2_hmac_key_op_with_mac_len_less_than_min_mac_len_fail() {
     let mac_len = 64;
     let key_size = 128;
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     for digest in digests {
         let alias = format!("ks_hmac_test_key_{}", digest.0);
 
         let result = key_generations::map_ks_error(create_hmac_key_and_operation(
-            &sec_level,
+            &sl,
             &alias,
             key_size,
             mac_len,
diff --git a/keystore2/tests/keystore2_client_import_keys_tests.rs b/keystore2/tests/keystore2_client_import_keys_tests.rs
index bf787d29..f3a267bb 100644
--- a/keystore2/tests/keystore2_client_import_keys_tests.rs
+++ b/keystore2/tests/keystore2_client_import_keys_tests.rs
@@ -12,49 +12,41 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::getuid;
-
-use openssl::rand::rand_bytes;
-use openssl::x509::X509;
-
+use crate::keystore2_client_test_utils::{
+    encrypt_secure_key, encrypt_transport_key, get_vsr_api_level,
+    perform_sample_asym_sign_verify_op, perform_sample_hmac_sign_verify_op,
+    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
     ErrorCode::ErrorCode, HardwareAuthenticatorType::HardwareAuthenticatorType,
-    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
+    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     AuthenticatorSpec::AuthenticatorSpec, Domain::Domain,
     IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
     KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
 };
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
-
 use keystore2_test_utils::ffi_test_utils::{
     create_wrapped_key, create_wrapped_key_additional_auth_data,
 };
-
-use crate::keystore2_client_test_utils::{
-    encrypt_secure_key, encrypt_transport_key, get_vsr_api_level,
-    perform_sample_asym_sign_verify_op, perform_sample_hmac_sign_verify_op,
-    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
-};
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
+use nix::unistd::getuid;
+use openssl::rand::rand_bytes;
+use openssl::x509::X509;
 
 pub fn import_rsa_sign_key_and_perform_sample_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
     import_params: authorizations::AuthSetBuilder,
 ) {
     let key_metadata =
-        key_generations::import_rsa_2048_key(sec_level, domain, nspace, alias, import_params)
-            .unwrap();
+        key_generations::import_rsa_2048_key(sl, domain, nspace, alias, import_params).unwrap();
 
     perform_sample_asym_sign_verify_op(
-        sec_level,
+        &sl.binder,
         &key_metadata,
         Some(PaddingMode::RSA_PSS),
         Some(Digest::SHA_2_256),
@@ -93,7 +85,7 @@ fn perform_sym_key_encrypt_decrypt_op(
 }
 
 fn build_secure_key_wrapper(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     secure_key: &[u8],
     transport_key: &[u8],
     nonce: &[u8],
@@ -103,10 +95,10 @@ fn build_secure_key_wrapper(
     // Encrypt secure key with transport key.
     let transport_key_alias = format!("ks_transport_key_aes_256_key_test_{}", getuid());
     let transport_key_metadata =
-        key_generations::import_transport_key(sec_level, Some(transport_key_alias), transport_key)
+        key_generations::import_transport_key(sl, Some(transport_key_alias), transport_key)
             .unwrap();
     let encrypted_secure_key = encrypt_secure_key(
-        sec_level,
+        &sl.binder,
         secure_key,
         aad,
         nonce.to_vec(),
@@ -135,8 +127,7 @@ fn build_secure_key_wrapper(
 /// imported key. Test should be able to create an operation successfully.
 #[test]
 fn keystore2_rsa_import_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_rsa_key_test_import_1_{}{}", getuid(), 2048);
 
@@ -153,7 +144,7 @@ fn keystore2_rsa_import_key_success() {
         .cert_not_after(253402300799000);
 
     import_rsa_sign_key_and_perform_sample_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias),
@@ -167,8 +158,7 @@ fn keystore2_rsa_import_key_success() {
 /// able to create an operation successfully.
 #[test]
 fn keystore2_rsa_import_key_determine_key_size_and_pub_exponent() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_rsa_key_test_import_2_{}{}", getuid(), 2048);
 
@@ -184,7 +174,7 @@ fn keystore2_rsa_import_key_determine_key_size_and_pub_exponent() {
         .cert_not_after(253402300799000);
 
     import_rsa_sign_key_and_perform_sample_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias),
@@ -196,8 +186,7 @@ fn keystore2_rsa_import_key_determine_key_size_and_pub_exponent() {
 /// a key with `IMPORT_PARAMETER_MISMATCH` error code.
 #[test]
 fn keystore2_rsa_import_key_fails_with_keysize_param_mismatch_error() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_rsa_key_test_import_3_{}{}", getuid(), 2048);
 
@@ -213,7 +202,7 @@ fn keystore2_rsa_import_key_fails_with_keysize_param_mismatch_error() {
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    let result = key_generations::map_ks_error(sec_level.importKey(
+    let result = key_generations::map_ks_error(sl.binder.importKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
         None,
         &import_params,
@@ -229,8 +218,7 @@ fn keystore2_rsa_import_key_fails_with_keysize_param_mismatch_error() {
 /// Test should fail to import a key with `IMPORT_PARAMETER_MISMATCH` error code.
 #[test]
 fn keystore2_rsa_import_key_fails_with_public_exponent_param_mismatch_error() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_rsa_key_test_import_4_{}{}", getuid(), 2048);
 
@@ -246,7 +234,7 @@ fn keystore2_rsa_import_key_fails_with_public_exponent_param_mismatch_error() {
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    let result = key_generations::map_ks_error(sec_level.importKey(
+    let result = key_generations::map_ks_error(sl.binder.importKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
         None,
         &import_params,
@@ -259,12 +247,11 @@ fn keystore2_rsa_import_key_fails_with_public_exponent_param_mismatch_error() {
 }
 
 /// Try to import a key with multiple purposes. Test should fail to import a key with
-/// `INCOMPATIBLE_PURPOSE` error code. If the backend is `keymaster` then `importKey` shall be
-/// successful.
+/// `INCOMPATIBLE_PURPOSE` error code. If the backend is `keymaster` or KeyMint-version-1 then
+/// `importKey` shall be successful.
 #[test]
 fn keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_rsa_key_test_import_5_{}{}", getuid(), 2048);
 
@@ -280,7 +267,7 @@ fn keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error() {
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    let result = key_generations::map_ks_error(sec_level.importKey(
+    let result = key_generations::map_ks_error(sl.binder.importKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
         None,
         &import_params,
@@ -288,9 +275,15 @@ fn keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error() {
         key_generations::RSA_2048_KEY,
     ));
 
-    if key_generations::has_default_keymint() {
-        assert!(result.is_err());
-        assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
+    if sl.is_keymint() {
+        if sl.get_keymint_version() >= 2 {
+            // The KeyMint v1 spec required that KeyPurpose::ATTEST_KEY not be combined
+            // with other key purposes.  However, this was not checked at the time
+            // so we can only be strict about checking this for implementations of KeyMint
+            // version 2 and above.
+            assert!(result.is_err());
+            assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
+        }
     } else {
         assert!(result.is_ok());
     }
@@ -301,8 +294,7 @@ fn keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error() {
 /// able to create an operation successfully.
 #[test]
 fn keystore2_import_ec_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_ec_key_test_import_1_{}{}", getuid(), 256);
 
@@ -323,24 +315,18 @@ fn keystore2_import_ec_key_success() {
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    let key_metadata = key_generations::import_ec_p_256_key(
-        &sec_level,
-        Domain::APP,
-        -1,
-        Some(alias),
-        import_params,
-    )
-    .expect("Failed to import EC key.");
+    let key_metadata =
+        key_generations::import_ec_p_256_key(&sl, Domain::APP, -1, Some(alias), import_params)
+            .expect("Failed to import EC key.");
 
-    perform_sample_asym_sign_verify_op(&sec_level, &key_metadata, None, Some(Digest::SHA_2_256));
+    perform_sample_asym_sign_verify_op(&sl.binder, &key_metadata, None, Some(Digest::SHA_2_256));
 }
 
 /// Try to import EC key with wrong ec-curve as import-key-parameter. Test should fail to import a
 /// key with `IMPORT_PARAMETER_MISMATCH` error code.
 #[test]
 fn keystore2_ec_import_key_fails_with_mismatch_curve_error() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_ec_key_test_import_1_{}{}", getuid(), 256);
 
@@ -354,7 +340,7 @@ fn keystore2_ec_import_key_fails_with_mismatch_curve_error() {
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    let result = key_generations::map_ks_error(sec_level.importKey(
+    let result = key_generations::map_ks_error(sl.binder.importKey(
         &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
         None,
         &import_params,
@@ -369,47 +355,41 @@ fn keystore2_ec_import_key_fails_with_mismatch_curve_error() {
 /// Test should be able to create an operation successfully.
 #[test]
 fn keystore2_import_aes_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_aes_key_test_import_1_{}{}", getuid(), 256);
-    let key_metadata = key_generations::import_aes_key(&sec_level, Domain::APP, -1, Some(alias))
+    let key_metadata = key_generations::import_aes_key(&sl, Domain::APP, -1, Some(alias))
         .expect("Failed to import AES key.");
 
-    perform_sym_key_encrypt_decrypt_op(&sec_level, &key_metadata);
+    perform_sym_key_encrypt_decrypt_op(&sl.binder, &key_metadata);
 }
 
 /// Import 3DES key and verify key parameters. Try to create an operation using the imported key.
 /// Test should be able to create an operation successfully.
 #[test]
 fn keystore2_import_3des_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = key_generations::map_ks_error(
-        keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT),
-    )
-    .unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_3des_key_test_import_1_{}{}", getuid(), 168);
 
-    let key_metadata = key_generations::import_3des_key(&sec_level, Domain::APP, -1, Some(alias))
+    let key_metadata = key_generations::import_3des_key(&sl, Domain::APP, -1, Some(alias))
         .expect("Failed to import 3DES key.");
 
-    perform_sym_key_encrypt_decrypt_op(&sec_level, &key_metadata);
+    perform_sym_key_encrypt_decrypt_op(&sl.binder, &key_metadata);
 }
 
 /// Import HMAC key and verify key parameters. Try to create an operation using the imported key.
 /// Test should be able to create an operation successfully.
 #[test]
 fn keystore2_import_hmac_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_hmac_key_test_import_1_{}", getuid());
 
-    let key_metadata = key_generations::import_hmac_key(&sec_level, Domain::APP, -1, Some(alias))
+    let key_metadata = key_generations::import_hmac_key(&sl, Domain::APP, -1, Some(alias))
         .expect("Failed to import HMAC key.");
 
-    perform_sample_hmac_sign_verify_op(&sec_level, &key_metadata.key);
+    perform_sample_hmac_sign_verify_op(&sl.binder, &key_metadata.key);
 }
 
 /// This test creates a wrapped key data and imports it. Validates the imported wrapped key.
@@ -419,8 +399,7 @@ fn keystore2_import_hmac_key_success() {
 /// Test should successfully import the wrapped key and perform crypto operations.
 #[test]
 fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let mut secure_key = [0; 32];
     rand_bytes(&mut secure_key).unwrap();
@@ -434,7 +413,7 @@ fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
     // Import wrapping key.
     let wrapping_key_alias = format!("ks_wrapping_key_test_import_2_{}_2048", getuid());
     let wrapping_key_metadata = key_generations::import_wrapping_key(
-        &sec_level,
+        &sl,
         key_generations::RSA_2048_KEY,
         Some(wrapping_key_alias),
     )
@@ -446,7 +425,7 @@ fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
 
     // Build ASN.1 DER-encoded wrapped key material as described in `SecureKeyWrapper` schema.
     let wrapped_key_data = build_secure_key_wrapper(
-        &sec_level,
+        &sl,
         &secure_key,
         &transport_key,
         &nonce,
@@ -458,14 +437,14 @@ fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
     // Unwrap the key. Import wrapped key.
     let secured_key_alias = format!("ks_wrapped_aes_key_{}", getuid());
     let secured_key_metadata = key_generations::import_wrapped_key(
-        &sec_level,
+        &sl,
         Some(secured_key_alias),
         &wrapping_key_metadata,
         Some(wrapped_key_data.to_vec()),
     )
     .unwrap();
 
-    perform_sym_key_encrypt_decrypt_op(&sec_level, &secured_key_metadata);
+    perform_sym_key_encrypt_decrypt_op(&sl.binder, &secured_key_metadata);
 }
 
 /// Create a wrapped key data with invalid Additional Authenticated Data (AAD) and
@@ -476,8 +455,7 @@ fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
 /// Test should fail to import the wrapped key with error code `VERIFICATION_FAILED`.
 #[test]
 fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let mut secure_key = [0; 32];
     rand_bytes(&mut secure_key).unwrap();
@@ -491,7 +469,7 @@ fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
     // Import wrapping key.
     let wrapping_key_alias = format!("ks_wrapping_key_test_import_2_{}_2048", getuid());
     let wrapping_key_metadata = key_generations::import_wrapping_key(
-        &sec_level,
+        &sl,
         key_generations::RSA_2048_KEY,
         Some(wrapping_key_alias),
     )
@@ -502,7 +480,7 @@ fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
 
     // Build ASN.1 DER-encoded wrapped key material as described in `SecureKeyWrapper` schema.
     let wrapped_key_data = build_secure_key_wrapper(
-        &sec_level,
+        &sl,
         &secure_key,
         &transport_key,
         &nonce,
@@ -514,7 +492,7 @@ fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
     // Unwrap the key. Import wrapped key.
     let secured_key_alias = format!("ks_wrapped_aes_key_{}", getuid());
     let result = key_generations::map_ks_error(key_generations::import_wrapped_key(
-        &sec_level,
+        &sl,
         Some(secured_key_alias),
         &wrapping_key_metadata,
         Some(wrapped_key_data.to_vec()),
@@ -528,8 +506,7 @@ fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
 /// perform crypto operations successfully.
 #[test]
 fn keystore2_import_wrapped_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_wrapped_key_test_import_1_{}_256", getuid());
     let wrapping_key_alias = format!("ks_wrapping_key_test_import_1_{}_2048", getuid());
@@ -548,7 +525,7 @@ fn keystore2_import_wrapped_key_success() {
         .cert_not_after(253402300799000);
 
     let key_metadata = key_generations::import_wrapping_key_and_wrapped_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias),
@@ -558,7 +535,7 @@ fn keystore2_import_wrapped_key_success() {
     .expect("Failed to import wrapped key.");
 
     // Try to perform operations using wrapped key.
-    perform_sym_key_encrypt_decrypt_op(&sec_level, &key_metadata);
+    perform_sym_key_encrypt_decrypt_op(&sl.binder, &key_metadata);
 }
 
 /// Import wrapping-key without specifying KeyPurpose::WRAP_KEY in import key parameters. Try to
@@ -567,8 +544,7 @@ fn keystore2_import_wrapped_key_success() {
 /// `WRAP_KEY` purpose.
 #[test]
 fn keystore2_import_wrapped_key_fails_with_wrong_purpose() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let wrapping_key_alias = format!("ks_wrapping_key_test_import_2_{}_2048", getuid());
     let alias = format!("ks_wrapped_key_test_import_2_{}_256", getuid());
@@ -588,7 +564,7 @@ fn keystore2_import_wrapped_key_fails_with_wrong_purpose() {
 
     let result =
         key_generations::map_ks_error(key_generations::import_wrapping_key_and_wrapped_key(
-            &sec_level,
+            &sl,
             Domain::APP,
             -1,
             Some(alias),
@@ -604,8 +580,7 @@ fn keystore2_import_wrapped_key_fails_with_wrong_purpose() {
 /// Test should fail to import wrapped key with `ResponseCode::KEY_NOT_FOUND`.
 #[test]
 fn keystore2_import_wrapped_key_fails_with_missing_wrapping_key() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let unwrap_params = authorizations::AuthSetBuilder::new()
         .digest(Digest::SHA_2_256)
@@ -621,7 +596,7 @@ fn keystore2_import_wrapped_key_fails_with_missing_wrapping_key() {
     // Wrapping key with this alias doesn't exist.
     let wrapping_key_alias = format!("ks_wrapping_key_not_exist_{}_2048", getuid());
 
-    let result = key_generations::map_ks_error(sec_level.importWrappedKey(
+    let result = key_generations::map_ks_error(sl.binder.importWrappedKey(
         &KeyDescriptor {
             domain: Domain::APP,
             nspace: -1,
diff --git a/keystore2/tests/keystore2_client_key_agreement_tests.rs b/keystore2/tests/keystore2_client_key_agreement_tests.rs
index 6b2e3c2d..6744b60d 100644
--- a/keystore2/tests/keystore2_client_key_agreement_tests.rs
+++ b/keystore2/tests/keystore2_client_key_agreement_tests.rs
@@ -12,27 +12,21 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::getuid;
-
-use openssl::ec::{EcGroup, EcKey};
-use openssl::error::ErrorStack;
-use openssl::nid::Nid;
-use openssl::pkey::{PKey, PKeyRef, Private, Public};
-use openssl::pkey_ctx::PkeyCtx;
-use openssl::x509::X509;
-
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
-    SecurityLevel::SecurityLevel,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
     KeyMetadata::KeyMetadata,
 };
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
+use nix::unistd::getuid;
+use openssl::ec::{EcGroup, EcKey};
+use openssl::error::ErrorStack;
+use openssl::nid::Nid;
+use openssl::pkey::{PKey, PKeyRef, Private, Public};
+use openssl::pkey_ctx::PkeyCtx;
+use openssl::x509::X509;
 
 /// This macro is used to verify that the key agreement works for the given curve.
 macro_rules! test_ec_key_agree {
@@ -89,13 +83,12 @@ fn ec_curve_to_openrssl_curve_name(ec_curve: &EcCurve) -> Nid {
 /// Generate two EC keys with given curve from KeyMint and OpeanSSL. Perform local ECDH between
 /// them and verify that the derived secrets are the same.
 fn perform_ec_key_agreement(ec_curve: EcCurve) {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let openssl_ec_curve = ec_curve_to_openrssl_curve_name(&ec_curve);
 
     let alias = format!("ks_ec_test_key_agree_{}", getuid());
     let keymint_key = key_generations::generate_ec_agree_key(
-        &sec_level,
+        &sl,
         ec_curve,
         Digest::SHA_2_256,
         Domain::APP,
@@ -111,7 +104,7 @@ fn perform_ec_key_agreement(ec_curve: EcCurve) {
     let local_key = PKey::from_ec_key(ec_key).unwrap();
     let local_pub_key = local_key.public_key_to_der().unwrap();
 
-    check_agreement(&sec_level, &keymint_key.key, &keymint_pub_key, &local_key, &local_pub_key);
+    check_agreement(&sl.binder, &keymint_key.key, &keymint_pub_key, &local_key, &local_pub_key);
 }
 
 test_ec_key_agree!(test_ec_p224_key_agreement, EcCurve::P_224);
@@ -119,16 +112,15 @@ test_ec_key_agree!(test_ec_p256_key_agreement, EcCurve::P_256);
 test_ec_key_agree!(test_ec_p384_key_agreement, EcCurve::P_384);
 test_ec_key_agree!(test_ec_p521_key_agreement, EcCurve::P_521);
 
-/// Generate two EC keys with curve `CURVE_25519` from KeyMint and OpeanSSL.
+/// Generate two EC keys with curve `CURVE_25519` from KeyMint and OpenSSL.
 /// Perform local ECDH between them and verify that the derived secrets are the same.
 #[test]
 fn keystore2_ec_25519_agree_key_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_ec_25519_test_key_agree_{}", getuid());
     let keymint_key = key_generations::generate_ec_agree_key(
-        &sec_level,
+        &sl,
         EcCurve::CURVE_25519,
         Digest::NONE,
         Domain::APP,
@@ -142,19 +134,18 @@ fn keystore2_ec_25519_agree_key_success() {
     let local_key = PKey::generate_x25519().unwrap();
     let local_pub_key = local_key.public_key_to_der().unwrap();
 
-    check_agreement(&sec_level, &keymint_key.key, &keymint_pub_key, &local_key, &local_pub_key);
+    check_agreement(&sl.binder, &keymint_key.key, &keymint_pub_key, &local_key, &local_pub_key);
 }
 
 /// Generate two EC keys with different curves and try to perform local ECDH. Since keys are using
 /// different curves operation should fail with `ErrorCode:INVALID_ARGUMENT`.
 #[test]
 fn keystore2_ec_agree_key_with_different_curves_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = format!("ks_test_key_agree_fail{}", getuid());
     let keymint_key = key_generations::generate_ec_agree_key(
-        &sec_level,
+        &sl,
         EcCurve::P_256,
         Digest::SHA_2_256,
         Domain::APP,
@@ -169,7 +160,7 @@ fn keystore2_ec_agree_key_with_different_curves_fail() {
     // If the keys are using different curves KeyMint should fail with
     // ErrorCode:INVALID_ARGUMENT.
     let authorizations = authorizations::AuthSetBuilder::new().purpose(KeyPurpose::AGREE_KEY);
-    let key_agree_op = sec_level.createOperation(&keymint_key.key, &authorizations, false).unwrap();
+    let key_agree_op = sl.binder.createOperation(&keymint_key.key, &authorizations, false).unwrap();
     assert!(key_agree_op.iOperation.is_some());
 
     let op = key_agree_op.iOperation.unwrap();
diff --git a/keystore2/tests/keystore2_client_key_id_domain_tests.rs b/keystore2/tests/keystore2_client_key_id_domain_tests.rs
index 09b13784..8f9191f3 100644
--- a/keystore2/tests/keystore2_client_key_id_domain_tests.rs
+++ b/keystore2/tests/keystore2_client_key_id_domain_tests.rs
@@ -12,20 +12,15 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::getuid;
-
+use crate::keystore2_client_test_utils::perform_sample_sign_operation;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Digest::Digest, EcCurve::EcCurve, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
+    Digest::Digest, EcCurve::EcCurve, KeyPurpose::KeyPurpose,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
 };
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
-};
-
-use crate::keystore2_client_test_utils::perform_sample_sign_operation;
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
+use nix::unistd::getuid;
 
 /// Try to generate a key with `Domain::KEY_ID`, test should fail with an error code
 /// `SYSTEM_ERROR`. `Domain::KEY_ID` is not allowed to use for generating a key. Key id is returned
@@ -33,11 +28,10 @@ use crate::keystore2_client_test_utils::perform_sample_sign_operation;
 #[test]
 fn keystore2_generate_key_with_key_id_domain_expect_sys_error() {
     let alias = "ks_gen_key_id_test_key";
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let result = key_generations::map_ks_error(key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::KEY_ID,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias.to_string()),
@@ -53,12 +47,11 @@ fn keystore2_generate_key_with_key_id_domain_expect_sys_error() {
 /// successfully.
 #[test]
 fn keystore2_find_key_with_key_id_as_domain() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = "ks_key_id_test_key";
 
     let key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -68,7 +61,8 @@ fn keystore2_find_key_with_key_id_as_domain() {
     .expect("Failed to generate a EC key.");
 
     // Try to load the above generated key with KEY_ID as domain.
-    let key_entry_response = keystore2
+    let key_entry_response = sl
+        .keystore2
         .getKeyEntry(&KeyDescriptor {
             domain: Domain::KEY_ID,
             nspace: key_metadata.key.nspace,
@@ -85,7 +79,8 @@ fn keystore2_find_key_with_key_id_as_domain() {
 
     // Try to create an operation using above loaded key, operation should be created
     // successfully.
-    let op_response = sec_level
+    let op_response = sl
+        .binder
         .createOperation(
             &key_entry_response.metadata.key,
             &authorizations::AuthSetBuilder::new()
@@ -110,12 +105,11 @@ fn keystore2_find_key_with_key_id_as_domain() {
 /// create an operation using the rebound key.
 #[test]
 fn keystore2_key_id_alias_rebind_verify_by_alias() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_key_id_test_alias_rebind_1_{}", getuid());
 
     let key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -127,7 +121,7 @@ fn keystore2_key_id_alias_rebind_verify_by_alias() {
     // Generate a key with same alias as above generated key, so that alias will be rebound
     // to this key.
     let new_key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias),
@@ -142,7 +136,7 @@ fn keystore2_key_id_alias_rebind_verify_by_alias() {
 
     // Try to create an operation using previously generated key_metadata.
     // It should fail as previously generated key material is no longer remains valid.
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
@@ -152,7 +146,8 @@ fn keystore2_key_id_alias_rebind_verify_by_alias() {
 
     // Try to create an operation using rebound key, operation should be created
     // successfully.
-    let op_response = sec_level
+    let op_response = sl
+        .binder
         .createOperation(
             &new_key_metadata.key,
             &authorizations::AuthSetBuilder::new()
@@ -177,12 +172,11 @@ fn keystore2_key_id_alias_rebind_verify_by_alias() {
 /// Test should successfully create an operation using the rebound key.
 #[test]
 fn keystore2_key_id_alias_rebind_verify_by_key_id() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_key_id_test_alias_rebind_2_{}", getuid());
 
     let key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -192,7 +186,8 @@ fn keystore2_key_id_alias_rebind_verify_by_key_id() {
     .expect("Failed to generate a EC key.");
 
     // Load the above generated key with KEY_ID as domain.
-    let key_entry_response = keystore2
+    let key_entry_response = sl
+        .keystore2
         .getKeyEntry(&KeyDescriptor {
             domain: Domain::KEY_ID,
             nspace: key_metadata.key.nspace,
@@ -210,7 +205,7 @@ fn keystore2_key_id_alias_rebind_verify_by_key_id() {
     // Generate another key with same alias as above generated key, so that alias will be rebound
     // to this key.
     let new_key_metadata = key_generations::generate_ec_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias),
@@ -227,7 +222,7 @@ fn keystore2_key_id_alias_rebind_verify_by_key_id() {
 
     // Try to create an operation using previously loaded key_entry_response.
     // It should fail as previously generated key material is no longer valid.
-    let result = key_generations::map_ks_error(sec_level.createOperation(
+    let result = key_generations::map_ks_error(sl.binder.createOperation(
         &key_entry_response.metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
         false,
@@ -237,7 +232,8 @@ fn keystore2_key_id_alias_rebind_verify_by_key_id() {
 
     // Try to create an operation using rebound key, operation should be created
     // successfully.
-    let op_response = sec_level
+    let op_response = sl
+        .binder
         .createOperation(
             &new_key_metadata.key,
             &authorizations::AuthSetBuilder::new()
diff --git a/keystore2/tests/keystore2_client_keystore_engine_tests.rs b/keystore2/tests/keystore2_client_keystore_engine_tests.rs
index 4651931b..01f8917e 100644
--- a/keystore2/tests/keystore2_client_keystore_engine_tests.rs
+++ b/keystore2/tests/keystore2_client_keystore_engine_tests.rs
@@ -12,27 +12,24 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyPurpose::KeyPurpose,
-    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
+    PaddingMode::PaddingMode,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
-    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
+    Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
+    KeyPermission::KeyPermission,
 };
-
-use keystore2_test_utils::{authorizations::AuthSetBuilder, get_keystore_service, run_as};
-
 use keystore2_test_utils::ffi_test_utils::perform_crypto_op_using_keystore_engine;
-
+use keystore2_test_utils::{
+    authorizations::AuthSetBuilder, get_keystore_service, run_as, SecLevel,
+};
+use nix::unistd::{Gid, Uid};
 use openssl::x509::X509;
+use rustutils::users::AID_USER_OFFSET;
 
 fn generate_rsa_key_and_grant_to_user(
-    keystore2: &binder::Strong<dyn IKeystoreService>,
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: &str,
     grantee_uid: i32,
     access_vector: i32,
@@ -47,7 +44,8 @@ fn generate_rsa_key_and_grant_to_user(
         .padding_mode(PaddingMode::NONE)
         .digest(Digest::NONE);
 
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .generateKey(
             &KeyDescriptor {
                 domain: Domain::APP,
@@ -64,12 +62,11 @@ fn generate_rsa_key_and_grant_to_user(
 
     assert!(key_metadata.certificate.is_some());
 
-    keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
+    sl.keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
 }
 
 fn generate_ec_key_and_grant_to_user(
-    keystore2: &binder::Strong<dyn IKeystoreService>,
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: &str,
     grantee_uid: i32,
     access_vector: i32,
@@ -82,7 +79,8 @@ fn generate_ec_key_and_grant_to_user(
         .digest(Digest::NONE)
         .ec_curve(EcCurve::P_256);
 
-    let key_metadata = sec_level
+    let key_metadata = sl
+        .binder
         .generateKey(
             &KeyDescriptor {
                 domain: Domain::APP,
@@ -99,12 +97,11 @@ fn generate_ec_key_and_grant_to_user(
 
     assert!(key_metadata.certificate.is_some());
 
-    keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
+    sl.keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
 }
 
 fn generate_key_and_grant_to_user(
-    keystore2: &binder::Strong<dyn IKeystoreService>,
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: &str,
     grantee_uid: u32,
     algo: Algorithm,
@@ -115,16 +112,14 @@ fn generate_key_and_grant_to_user(
 
     let grant_key = match algo {
         Algorithm::RSA => generate_rsa_key_and_grant_to_user(
-            keystore2,
-            sec_level,
+            sl,
             alias,
             grantee_uid.try_into().unwrap(),
             access_vector,
         )
         .unwrap(),
         Algorithm::EC => generate_ec_key_and_grant_to_user(
-            keystore2,
-            sec_level,
+            sl,
             alias,
             grantee_uid.try_into().unwrap(),
             access_vector,
@@ -170,17 +165,9 @@ fn keystore2_perofrm_crypto_op_using_keystore2_engine_rsa_key_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = "keystore2_engine_rsa_key";
-            generate_key_and_grant_to_user(
-                &keystore2,
-                &sec_level,
-                alias,
-                GRANTEE_UID,
-                Algorithm::RSA,
-            )
-            .unwrap()
+            generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::RSA).unwrap()
         })
     };
 
@@ -213,17 +200,9 @@ fn keystore2_perofrm_crypto_op_using_keystore2_engine_ec_key_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = "keystore2_engine_ec_test_key";
-            generate_key_and_grant_to_user(
-                &keystore2,
-                &sec_level,
-                alias,
-                GRANTEE_UID,
-                Algorithm::EC,
-            )
-            .unwrap()
+            generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::EC).unwrap()
         })
     };
 
@@ -257,20 +236,14 @@ fn keystore2_perofrm_crypto_op_using_keystore2_engine_pem_pub_key_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     let grant_key_nspace = unsafe {
         run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = "keystore2_engine_rsa_pem_pub_key";
-            let grant_key_nspace = generate_key_and_grant_to_user(
-                &keystore2,
-                &sec_level,
-                alias,
-                GRANTEE_UID,
-                Algorithm::RSA,
-            )
-            .unwrap();
+            let grant_key_nspace =
+                generate_key_and_grant_to_user(&sl, alias, GRANTEE_UID, Algorithm::RSA).unwrap();
 
             // Update certificate with encodeed PEM data.
-            let key_entry_response = keystore2
+            let key_entry_response = sl
+                .keystore2
                 .getKeyEntry(&KeyDescriptor {
                     domain: Domain::APP,
                     nspace: -1,
@@ -281,7 +254,7 @@ fn keystore2_perofrm_crypto_op_using_keystore2_engine_pem_pub_key_success() {
             let cert_bytes = key_entry_response.metadata.certificate.as_ref().unwrap();
             let cert = X509::from_der(cert_bytes.as_ref()).unwrap();
             let cert_pem = cert.to_pem().unwrap();
-            keystore2
+            sl.keystore2
                 .updateSubcomponent(&key_entry_response.metadata.key, Some(&cert_pem), None)
                 .expect("updateSubcomponent failed.");
 
diff --git a/keystore2/tests/keystore2_client_list_entries_tests.rs b/keystore2/tests/keystore2_client_list_entries_tests.rs
index 8b3f7001..539dac2d 100644
--- a/keystore2/tests/keystore2_client_list_entries_tests.rs
+++ b/keystore2/tests/keystore2_client_list_entries_tests.rs
@@ -12,19 +12,18 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{getuid, Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-use std::collections::HashSet;
-use std::fmt::Write;
-
-use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
+use crate::keystore2_client_test_utils::{delete_all_entries, delete_app_key, verify_aliases};
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
     KeyPermission::KeyPermission, ResponseCode::ResponseCode,
 };
-
-use crate::keystore2_client_test_utils::{delete_all_entries, delete_app_key, verify_aliases};
-use keystore2_test_utils::{get_keystore_service, key_generations, key_generations::Error, run_as};
+use keystore2_test_utils::{
+    get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
+};
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
+use std::collections::HashSet;
+use std::fmt::Write;
 
 /// Try to find a key with given key parameters using `listEntries` API.
 fn key_alias_exists(
@@ -63,20 +62,19 @@ fn keystore2_list_entries_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
 
             let alias = format!("list_entries_grant_key1_{}", getuid());
 
             // Make sure there is no key exist with this `alias` in `SELINUX` domain and
             // `SELINUX_SHELL_NAMESPACE` namespace.
             if key_alias_exists(
-                &keystore2,
+                &sl.keystore2,
                 Domain::SELINUX,
                 key_generations::SELINUX_SHELL_NAMESPACE,
                 alias.to_string(),
             ) {
-                keystore2
+                sl.keystore2
                     .deleteKey(&KeyDescriptor {
                         domain: Domain::SELINUX,
                         nspace: key_generations::SELINUX_SHELL_NAMESPACE,
@@ -88,7 +86,7 @@ fn keystore2_list_entries_success() {
 
             // Generate a key with above defined `alias`.
             let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sec_level,
+                &sl,
                 Domain::SELINUX,
                 key_generations::SELINUX_SHELL_NAMESPACE,
                 Some(alias.to_string()),
@@ -99,7 +97,7 @@ fn keystore2_list_entries_success() {
             // Verify that above generated key entry is listed with domain SELINUX and
             // namespace SELINUX_SHELL_NAMESPACE
             assert!(key_alias_exists(
-                &keystore2,
+                &sl.keystore2,
                 Domain::SELINUX,
                 key_generations::SELINUX_SHELL_NAMESPACE,
                 alias,
@@ -107,7 +105,7 @@ fn keystore2_list_entries_success() {
 
             // Grant a key with GET_INFO permission.
             let access_vector = KeyPermission::GET_INFO.0;
-            keystore2
+            sl.keystore2
                 .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
                 .unwrap();
         })
@@ -121,13 +119,11 @@ fn keystore2_list_entries_success() {
             Uid::from_raw(GRANTEE_UID),
             Gid::from_raw(GRANTEE_GID),
             move || {
-                let keystore2 = get_keystore_service();
-                let sec_level =
-                    keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+                let sl = SecLevel::tee();
                 let alias = format!("list_entries_success_key{}", getuid());
 
                 let key_metadata = key_generations::generate_ec_p256_signing_key(
-                    &sec_level,
+                    &sl,
                     Domain::APP,
                     -1,
                     Some(alias.to_string()),
@@ -137,7 +133,7 @@ fn keystore2_list_entries_success() {
 
                 // Make sure there is only one key entry exist and that should be the same key
                 // generated in this user context. Granted key shouldn't be included in this list.
-                let key_descriptors = keystore2.listEntries(Domain::APP, -1).unwrap();
+                let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
                 assert_eq!(1, key_descriptors.len());
 
                 let key = key_descriptors.first().unwrap();
@@ -145,9 +141,9 @@ fn keystore2_list_entries_success() {
                 assert_eq!(key.nspace, GRANTEE_UID.try_into().unwrap());
                 assert_eq!(key.domain, Domain::APP);
 
-                keystore2.deleteKey(&key_metadata.key).unwrap();
+                sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 
-                let key_descriptors = keystore2.listEntries(Domain::APP, -1).unwrap();
+                let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
                 assert_eq!(0, key_descriptors.len());
             },
         )
@@ -204,14 +200,13 @@ fn keystore2_list_entries_with_long_aliases_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     unsafe {
         run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
 
             // Make sure there are no keystore entries exist before adding new entries.
-            let key_descriptors = keystore2.listEntries(Domain::APP, -1).unwrap();
+            let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
             if !key_descriptors.is_empty() {
                 key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
-                    delete_app_key(&keystore2, &alias).unwrap();
+                    delete_app_key(&sl.keystore2, &alias).unwrap();
                 });
             }
 
@@ -223,8 +218,7 @@ fn keystore2_list_entries_with_long_aliases_success() {
                 write!(alias, "{}_{}", "X".repeat(6000), count).unwrap();
                 imported_key_aliases.insert(alias.clone());
 
-                let result =
-                    key_generations::import_aes_key(&sec_level, Domain::APP, -1, Some(alias));
+                let result = key_generations::import_aes_key(&sl, Domain::APP, -1, Some(alias));
                 assert!(result.is_ok());
             }
 
@@ -237,7 +231,7 @@ fn keystore2_list_entries_with_long_aliases_success() {
             //    list of key aliases
             //  - continue above steps till it cleanup all the imported keystore entries.
             while !imported_key_aliases.is_empty() {
-                let key_descriptors = keystore2.listEntries(Domain::APP, -1).unwrap();
+                let key_descriptors = sl.keystore2.listEntries(Domain::APP, -1).unwrap();
 
                 // Check retrieved key entries list is a subset of imported keys list.
                 assert!(key_descriptors
@@ -246,7 +240,7 @@ fn keystore2_list_entries_with_long_aliases_success() {
 
                 // Delete the listed key entries from Keystore as well as from imported keys list.
                 key_descriptors.into_iter().map(|key| key.alias.unwrap()).for_each(|alias| {
-                    delete_app_key(&keystore2, &alias).unwrap();
+                    delete_app_key(&sl.keystore2, &alias).unwrap();
                     assert!(imported_key_aliases.remove(&alias));
                 });
             }
@@ -271,17 +265,16 @@ fn keystore2_list_entries_batched_with_long_aliases_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     unsafe {
         run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
 
             // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&keystore2);
+            delete_all_entries(&sl.keystore2);
 
             // Import 100 keys with aliases of length 6000.
             let mut imported_key_aliases =
-                key_generations::import_aes_keys(&sec_level, "X".repeat(6000), 1..101).unwrap();
+                key_generations::import_aes_keys(&sl, "X".repeat(6000), 1..101).unwrap();
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 100,
                 "Error while importing keys"
             );
@@ -290,7 +283,7 @@ fn keystore2_list_entries_batched_with_long_aliases_success() {
             let mut alias;
             while !imported_key_aliases.is_empty() {
                 let key_descriptors =
-                    keystore2.listEntriesBatched(Domain::APP, -1, start_past_alias).unwrap();
+                    sl.keystore2.listEntriesBatched(Domain::APP, -1, start_past_alias).unwrap();
 
                 // Check retrieved key entries list is a subset of imported keys list.
                 assert!(key_descriptors
@@ -306,9 +299,9 @@ fn keystore2_list_entries_batched_with_long_aliases_success() {
             }
 
             assert!(imported_key_aliases.is_empty());
-            delete_all_entries(&keystore2);
+            delete_all_entries(&sl.keystore2);
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 0,
                 "Error while doing cleanup"
             );
@@ -339,25 +332,23 @@ fn keystore2_list_entries_batched_with_multi_procs_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     unsafe {
         run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
 
             // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&keystore2);
+            delete_all_entries(&sl.keystore2);
 
             // Import 3 keys with below aliases -
             // [key_test_batch_list_1, key_test_batch_list_2, key_test_batch_list_3]
             let imported_key_aliases =
-                key_generations::import_aes_keys(&sec_level, ALIAS_PREFIX.to_string(), 1..4)
-                    .unwrap();
+                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 1..4).unwrap();
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 3,
                 "Error while importing keys"
             );
 
             // List all entries in keystore for this user-id.
-            let key_descriptors = keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
+            let key_descriptors = sl.keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
             assert_eq!(key_descriptors.len(), 3);
 
             // Makes sure all listed aliases are matching with imported keys aliases.
@@ -370,20 +361,18 @@ fn keystore2_list_entries_batched_with_multi_procs_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     unsafe {
         run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
 
             // Import another 5 keys with below aliases -
             // [ key_test_batch_list_4, key_test_batch_list_5, key_test_batch_list_6,
             //   key_test_batch_list_7, key_test_batch_list_8 ]
             let mut imported_key_aliases =
-                key_generations::import_aes_keys(&sec_level, ALIAS_PREFIX.to_string(), 4..9)
-                    .unwrap();
+                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 4..9).unwrap();
 
             // Above context already 3 keys are imported, in this context 5 keys are imported,
             // total 8 keystore entries are expected to be present in Keystore for this user-id.
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 8,
                 "Error while importing keys"
             );
@@ -391,7 +380,8 @@ fn keystore2_list_entries_batched_with_multi_procs_success() {
             // List keystore entries with `start_past_alias` as "key_test_batch_list_3".
             // `listEntriesBatched` should list all the keystore entries with
             // alias > "key_test_batch_list_3".
-            let key_descriptors = keystore2
+            let key_descriptors = sl
+                .keystore2
                 .listEntriesBatched(Domain::APP, -1, Some("key_test_batch_list_3"))
                 .unwrap();
             assert_eq!(key_descriptors.len(), 5);
@@ -403,7 +393,7 @@ fn keystore2_list_entries_batched_with_multi_procs_success() {
 
             // List all keystore entries with `start_past_alias` as `None`.
             // `listEntriesBatched` should list all the keystore entries.
-            let key_descriptors = keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
+            let key_descriptors = sl.keystore2.listEntriesBatched(Domain::APP, -1, None).unwrap();
             assert_eq!(key_descriptors.len(), 8);
 
             // Include previously imported keys aliases as well
@@ -416,9 +406,9 @@ fn keystore2_list_entries_batched_with_multi_procs_success() {
                 .iter()
                 .all(|key| imported_key_aliases.contains(key.alias.as_ref().unwrap())));
 
-            delete_all_entries(&keystore2);
+            delete_all_entries(&sl.keystore2);
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 0,
                 "Error while doing cleanup"
             );
@@ -459,23 +449,23 @@ fn keystore2_list_entries_batched_with_empty_keystore_success() {
 /// Test should successfully list the imported key.
 #[test]
 fn keystore2_list_entries_batched_with_selinux_domain_success() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "test_selinux_key_list_alias_batched";
-    let _result = keystore2.deleteKey(&KeyDescriptor {
+    let _result = sl.keystore2.deleteKey(&KeyDescriptor {
         domain: Domain::SELINUX,
         nspace: key_generations::SELINUX_SHELL_NAMESPACE,
         alias: Some(alias.to_string()),
         blob: None,
     });
 
-    let initial_count = keystore2
+    let initial_count = sl
+        .keystore2
         .getNumberOfEntries(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE)
         .unwrap();
 
     key_generations::import_aes_key(
-        &sec_level,
+        &sl,
         Domain::SELINUX,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias.to_string()),
@@ -483,14 +473,15 @@ fn keystore2_list_entries_batched_with_selinux_domain_success() {
     .unwrap();
 
     assert_eq!(
-        keystore2
+        sl.keystore2
             .getNumberOfEntries(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE)
             .unwrap(),
         initial_count + 1,
         "Error while getting number of keystore entries accessible."
     );
 
-    let key_descriptors = keystore2
+    let key_descriptors = sl
+        .keystore2
         .listEntriesBatched(Domain::SELINUX, key_generations::SELINUX_SHELL_NAMESPACE, None)
         .unwrap();
     assert_eq!(key_descriptors.len(), (initial_count + 1) as usize);
@@ -499,7 +490,7 @@ fn keystore2_list_entries_batched_with_selinux_domain_success() {
         key_descriptors.into_iter().map(|key| key.alias.unwrap()).filter(|a| a == alias).count();
     assert_eq!(count, 1);
 
-    keystore2
+    sl.keystore2
         .deleteKey(&KeyDescriptor {
             domain: Domain::SELINUX,
             nspace: key_generations::SELINUX_SHELL_NAMESPACE,
@@ -522,11 +513,10 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
     // SAFETY: The test is run in a separate process with no other threads.
     unsafe {
         run_as::run_as(CLIENT_CTX, Uid::from_raw(CLIENT_UID), Gid::from_raw(CLIENT_GID), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
 
             // Make sure there are no keystore entries exist before adding new entries.
-            delete_all_entries(&keystore2);
+            delete_all_entries(&sl.keystore2);
 
             // Import keys with below mentioned aliases -
             // [
@@ -542,48 +532,49 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
             //   key_test_batch_list_22,
             // ]
             let _imported_key_aliases =
-                key_generations::import_aes_keys(&sec_level, ALIAS_PREFIX.to_string(), 1..6)
-                    .unwrap();
+                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 1..6).unwrap();
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 5,
                 "Error while importing keys"
             );
             let _imported_key_aliases =
-                key_generations::import_aes_keys(&sec_level, ALIAS_PREFIX.to_string(), 10..13)
-                    .unwrap();
+                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 10..13).unwrap();
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 8,
                 "Error while importing keys"
             );
             let _imported_key_aliases =
-                key_generations::import_aes_keys(&sec_level, ALIAS_PREFIX.to_string(), 21..23)
-                    .unwrap();
+                key_generations::import_aes_keys(&sl, ALIAS_PREFIX.to_string(), 21..23).unwrap();
             assert_eq!(
-                keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
+                sl.keystore2.getNumberOfEntries(Domain::APP, -1).unwrap(),
                 10,
                 "Error while importing keys"
             );
 
             // List the aliases using given `startingPastAlias` and verify the listed
             // aliases with the expected list of aliases.
-            verify_aliases(&keystore2, Some(format!("{}{}", ALIAS_PREFIX, "_5").as_str()), vec![]);
+            verify_aliases(
+                &sl.keystore2,
+                Some(format!("{}{}", ALIAS_PREFIX, "_5").as_str()),
+                vec![],
+            );
 
             verify_aliases(
-                &keystore2,
+                &sl.keystore2,
                 Some(format!("{}{}", ALIAS_PREFIX, "_4").as_str()),
                 vec![ALIAS_PREFIX.to_owned() + "_5"],
             );
 
             verify_aliases(
-                &keystore2,
+                &sl.keystore2,
                 Some(format!("{}{}", ALIAS_PREFIX, "_3").as_str()),
                 vec![ALIAS_PREFIX.to_owned() + "_4", ALIAS_PREFIX.to_owned() + "_5"],
             );
 
             verify_aliases(
-                &keystore2,
+                &sl.keystore2,
                 Some(format!("{}{}", ALIAS_PREFIX, "_2").as_str()),
                 vec![
                     ALIAS_PREFIX.to_owned() + "_21",
@@ -595,7 +586,7 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
             );
 
             verify_aliases(
-                &keystore2,
+                &sl.keystore2,
                 Some(format!("{}{}", ALIAS_PREFIX, "_1").as_str()),
                 vec![
                     ALIAS_PREFIX.to_owned() + "_10",
@@ -611,7 +602,7 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
             );
 
             verify_aliases(
-                &keystore2,
+                &sl.keystore2,
                 Some(ALIAS_PREFIX),
                 vec![
                     ALIAS_PREFIX.to_owned() + "_1",
@@ -628,7 +619,7 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
             );
 
             verify_aliases(
-                &keystore2,
+                &sl.keystore2,
                 None,
                 vec![
                     ALIAS_PREFIX.to_owned() + "_1",
diff --git a/keystore2/tests/keystore2_client_operation_tests.rs b/keystore2/tests/keystore2_client_operation_tests.rs
index 89b5a319..5f640efa 100644
--- a/keystore2/tests/keystore2_client_operation_tests.rs
+++ b/keystore2/tests/keystore2_client_operation_tests.rs
@@ -12,27 +12,28 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{getuid, Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-use std::thread;
-use std::thread::JoinHandle;
-
+use crate::keystore2_client_test_utils::{
+    create_signing_operation, execute_op_run_as_child, perform_sample_sign_operation,
+    BarrierReached, ForcedOp, TestOutcome,
+};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
-    Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
+    Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     CreateOperationResponse::CreateOperationResponse, Domain::Domain,
     IKeystoreOperation::IKeystoreOperation, ResponseCode::ResponseCode,
 };
-
 use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as,
+    authorizations, key_generations, key_generations::Error, run_as, SecLevel,
 };
-
-use crate::keystore2_client_test_utils::{
-    create_signing_operation, execute_op_run_as_child, perform_sample_sign_operation,
-    BarrierReached, ForcedOp, TestOutcome,
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
+use std::sync::{
+    atomic::{AtomicBool, Ordering},
+    Arc,
 };
+use std::thread;
+use std::thread::JoinHandle;
 
 /// Create `max_ops` number child processes with the given context and perform an operation under each
 /// child process.
@@ -312,11 +313,10 @@ fn keystore2_ops_prune_test() {
     child_handle.recv();
 
     // Generate a key to use in below operations.
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let alias = format!("ks_prune_op_test_key_{}", getuid());
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::SELINUX,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias),
@@ -327,7 +327,7 @@ fn keystore2_ops_prune_test() {
     // Create multiple operations in this process to trigger cannibalizing sibling operations.
     let mut ops: Vec<binder::Result<CreateOperationResponse>> = (0..MAX_OPS)
         .map(|_| {
-            sec_level.createOperation(
+            sl.binder.createOperation(
                 &key_metadata.key,
                 &authorizations::AuthSetBuilder::new()
                     .purpose(KeyPurpose::SIGN)
@@ -353,7 +353,7 @@ fn keystore2_ops_prune_test() {
         // Create a new operation, it should trigger to cannibalize one of their own sibling
         // operations.
         ops.push(
-            sec_level.createOperation(
+            sl.binder.createOperation(
                 &key_metadata.key,
                 &authorizations::AuthSetBuilder::new()
                     .purpose(KeyPurpose::SIGN)
@@ -380,6 +380,7 @@ fn keystore2_ops_prune_test() {
 ///   - untrusted_app
 ///   - system_server
 ///   - priv_app
+///
 /// `PERMISSION_DENIED` error response is expected.
 #[test]
 fn keystore2_forced_op_perm_denied_test() {
@@ -464,3 +465,120 @@ fn keystore2_op_fails_operation_busy() {
 
     assert!(result1 || result2);
 }
+
+/// Create an operation and use it for performing sign operation. After completing the operation
+/// try to abort the operation. Test should fail to abort already finalized operation with error
+/// code `INVALID_OPERATION_HANDLE`.
+#[test]
+fn keystore2_abort_finalized_op_fail_test() {
+    let op_response = create_signing_operation(
+        ForcedOp(false),
+        KeyPurpose::SIGN,
+        Digest::SHA_2_256,
+        Domain::APP,
+        -1,
+        Some("ks_op_abort_fail_test_key".to_string()),
+    )
+    .unwrap();
+
+    let op: binder::Strong<dyn IKeystoreOperation> = op_response.iOperation.unwrap();
+    perform_sample_sign_operation(&op).unwrap();
+    let result = key_generations::map_ks_error(op.abort());
+    assert!(result.is_err());
+    assert_eq!(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE), result.unwrap_err());
+}
+
+/// Create an operation and use it for performing sign operation. Before finishing the operation
+/// try to abort the operation. Test should successfully abort the operation. After aborting try to
+/// use the operation handle, test should fail to use already aborted operation handle with error
+/// code `INVALID_OPERATION_HANDLE`.
+#[test]
+fn keystore2_op_abort_success_test() {
+    let op_response = create_signing_operation(
+        ForcedOp(false),
+        KeyPurpose::SIGN,
+        Digest::SHA_2_256,
+        Domain::APP,
+        -1,
+        Some("ks_op_abort_success_key".to_string()),
+    )
+    .unwrap();
+
+    let op: binder::Strong<dyn IKeystoreOperation> = op_response.iOperation.unwrap();
+    op.update(b"my message").unwrap();
+    let result = key_generations::map_ks_error(op.abort());
+    assert!(result.is_ok());
+
+    // Try to use the op handle after abort.
+    let result = key_generations::map_ks_error(op.finish(None, None));
+    assert!(result.is_err());
+    assert_eq!(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE), result.unwrap_err());
+}
+
+/// Executes an operation in a thread. Performs an `update` operation repeatedly till the user
+/// interrupts it or encounters any error other than `OPERATION_BUSY`.
+/// Return `false` in case of any error other than `OPERATION_BUSY`, otherwise it returns true.
+fn perform_abort_op_busy_in_thread(
+    op: binder::Strong<dyn IKeystoreOperation>,
+    should_exit_clone: Arc<AtomicBool>,
+) -> JoinHandle<bool> {
+    thread::spawn(move || {
+        loop {
+            if should_exit_clone.load(Ordering::Relaxed) {
+                // Caller requested to exit the thread.
+                return true;
+            }
+
+            match key_generations::map_ks_error(op.update(b"my message")) {
+                Ok(_) => continue,
+                Err(Error::Rc(ResponseCode::OPERATION_BUSY)) => continue,
+                Err(_) => return false,
+            }
+        }
+    })
+}
+
+/// Create an operation and try to use same operation handle in multiple threads to perform
+/// operations. Test tries to abort the operation and expects `abort` call to fail with the error
+/// response `OPERATION_BUSY` as multiple threads try to access the same operation handle
+/// simultaneously. Test tries to simulate `OPERATION_BUSY` error response from `abort` api.
+#[test]
+fn keystore2_op_abort_fails_with_operation_busy_error_test() {
+    loop {
+        let op_response = create_signing_operation(
+            ForcedOp(false),
+            KeyPurpose::SIGN,
+            Digest::SHA_2_256,
+            Domain::APP,
+            -1,
+            Some("op_abort_busy_alias_test_key".to_string()),
+        )
+        .unwrap();
+        let op: binder::Strong<dyn IKeystoreOperation> = op_response.iOperation.unwrap();
+
+        let should_exit = Arc::new(AtomicBool::new(false));
+
+        let update_t_handle1 = perform_abort_op_busy_in_thread(op.clone(), should_exit.clone());
+        let update_t_handle2 = perform_abort_op_busy_in_thread(op.clone(), should_exit.clone());
+
+        // Attempt to abort the operation and anticipate an 'OPERATION_BUSY' error, as multiple
+        // threads are concurrently accessing the same operation handle.
+        let result = match op.abort() {
+            Ok(_) => 0, // Operation successfully aborted.
+            Err(e) => e.service_specific_error(),
+        };
+
+        // Notify threads to stop performing `update` operation.
+        should_exit.store(true, Ordering::Relaxed);
+
+        let _update_op_result = update_t_handle1.join().unwrap();
+        let _update_op_result2 = update_t_handle2.join().unwrap();
+
+        if result == ResponseCode::OPERATION_BUSY.0 {
+            // The abort call failed with an OPERATION_BUSY error, as anticipated, due to multiple
+            // threads competing for access to the same operation handle.
+            return;
+        }
+        assert_eq!(result, 0);
+    }
+}
diff --git a/keystore2/tests/keystore2_client_rsa_key_tests.rs b/keystore2/tests/keystore2_client_rsa_key_tests.rs
index ad176a48..cb8729f1 100644
--- a/keystore2/tests/keystore2_client_rsa_key_tests.rs
+++ b/keystore2/tests/keystore2_client_rsa_key_tests.rs
@@ -12,20 +12,14 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::keystore2_client_test_utils::{delete_app_key, perform_sample_sign_operation, ForcedOp};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
-    SecurityLevel::SecurityLevel,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     CreateOperationResponse::CreateOperationResponse, Domain::Domain,
-    IKeystoreSecurityLevel::IKeystoreSecurityLevel,
-};
-
-use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error,
 };
-
-use crate::keystore2_client_test_utils::{delete_app_key, perform_sample_sign_operation, ForcedOp};
+use keystore2_test_utils::{authorizations, key_generations, key_generations::Error, SecLevel};
 
 /// This macro is used for creating signing key operation tests using digests and paddings
 /// for various key sizes.
@@ -77,16 +71,19 @@ macro_rules! test_rsa_encrypt_key_op {
 
 /// Generate a RSA key and create an operation using the generated key.
 fn create_rsa_key_and_operation(
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     domain: Domain,
     nspace: i64,
     alias: Option<String>,
     key_params: &key_generations::KeyParams,
     op_purpose: KeyPurpose,
     forced_op: ForcedOp,
-) -> binder::Result<CreateOperationResponse> {
-    let key_metadata =
-        key_generations::generate_rsa_key(sec_level, domain, nspace, alias, key_params, None)?;
+) -> binder::Result<Option<CreateOperationResponse>> {
+    let Some(key_metadata) =
+        key_generations::generate_rsa_key(sl, domain, nspace, alias, key_params, None)?
+    else {
+        return Ok(None);
+    };
 
     let mut op_params = authorizations::AuthSetBuilder::new().purpose(op_purpose);
 
@@ -103,7 +100,7 @@ fn create_rsa_key_and_operation(
         op_params = op_params.block_mode(value)
     }
 
-    sec_level.createOperation(&key_metadata.key, &op_params, forced_op.0)
+    sl.binder.createOperation(&key_metadata.key, &op_params, forced_op.0).map(Some)
 }
 
 /// Generate RSA signing key with given parameters and perform signing operation.
@@ -113,11 +110,10 @@ fn perform_rsa_sign_key_op_success(
     alias: &str,
     padding: PaddingMode,
 ) {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
-    let op_response = create_rsa_key_and_operation(
-        &sec_level,
+    let Some(op_response) = create_rsa_key_and_operation(
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -133,7 +129,9 @@ fn perform_rsa_sign_key_op_success(
         KeyPurpose::SIGN,
         ForcedOp(false),
     )
-    .expect("Failed to create an operation.");
+    .expect("Failed to create an operation.") else {
+        return;
+    };
 
     assert!(op_response.iOperation.is_some());
     assert_eq!(
@@ -143,17 +141,16 @@ fn perform_rsa_sign_key_op_success(
         ))
     );
 
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate RSA signing key with given parameters and try to perform signing operation.
 /// Error `INCOMPATIBLE_DIGEST | UNKNOWN_ERROR` is expected while creating an opearation.
 fn perform_rsa_sign_key_op_failure(digest: Digest, alias: &str, padding: PaddingMode) {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -176,7 +173,7 @@ fn perform_rsa_sign_key_op_failure(digest: Digest, alias: &str, padding: Padding
         e == Error::Km(ErrorCode::UNKNOWN_ERROR) || e == Error::Km(ErrorCode::INCOMPATIBLE_DIGEST)
     );
 
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Generate RSA encrypt/decrypt key with given parameters and perform decrypt operation.
@@ -187,11 +184,10 @@ fn create_rsa_encrypt_decrypt_key_op_success(
     padding: PaddingMode,
     mgf_digest: Option<Digest>,
 ) {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let result = create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -210,7 +206,7 @@ fn create_rsa_encrypt_decrypt_key_op_success(
 
     assert!(result.is_ok());
 
-    delete_app_key(&keystore2, alias).unwrap();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 // Below macros generate tests for generating RSA signing keys with -
@@ -1533,12 +1529,11 @@ test_rsa_encrypt_key_op!(
 /// `INCOMPATIBLE_DIGEST` error code.
 #[test]
 fn keystore2_rsa_generate_signing_key_padding_pss_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_pss_none_key_op_test";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1565,12 +1560,11 @@ fn keystore2_rsa_generate_signing_key_padding_pss_fail() {
 /// with an error code `INCOMPATIBLE_DIGEST`.
 #[test]
 fn keystore2_rsa_generate_key_with_oaep_padding_fail() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_oaep_padding_fail_test";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1596,12 +1590,11 @@ fn keystore2_rsa_generate_key_with_oaep_padding_fail() {
 /// `UNSUPPORTED_PADDING_MODE`.
 #[test]
 fn keystore2_rsa_generate_keys() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_unsupport_padding_test";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1625,12 +1618,11 @@ fn keystore2_rsa_generate_keys() {
 /// `INCOMPATIBLE_PURPOSE` is expected as the generated key doesn't support sign operation.
 #[test]
 fn keystore2_rsa_encrypt_key_op_invalid_purpose() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_test_key_1";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1654,12 +1646,11 @@ fn keystore2_rsa_encrypt_key_op_invalid_purpose() {
 /// `INCOMPATIBLE_PURPOSE` is expected as the generated key doesn't support decrypt operation.
 #[test]
 fn keystore2_rsa_sign_key_op_invalid_purpose() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_test_key_2";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1683,12 +1674,11 @@ fn keystore2_rsa_sign_key_op_invalid_purpose() {
 /// generated key, an error `UNSUPPORTED_PURPOSE` is expected as RSA doesn't support AGREE_KEY.
 #[test]
 fn keystore2_rsa_key_unsupported_purpose() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_test_3";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1713,14 +1703,13 @@ fn keystore2_rsa_key_unsupported_purpose() {
 /// mode.
 #[test]
 fn keystore2_rsa_encrypt_key_unsupported_padding() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let paddings = [PaddingMode::RSA_PKCS1_1_5_SIGN, PaddingMode::RSA_PSS];
 
     for padding in paddings {
         let alias = format!("ks_rsa_encrypt_key_unsupported_pad_test{}", padding.0);
         let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-            &sec_level,
+            &sl,
             Domain::APP,
             -1,
             Some(alias.to_string()),
@@ -1746,14 +1735,13 @@ fn keystore2_rsa_encrypt_key_unsupported_padding() {
 /// unsupported padding mode.
 #[test]
 fn keystore2_rsa_signing_key_unsupported_padding() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
     let paddings = [PaddingMode::RSA_PKCS1_1_5_ENCRYPT, PaddingMode::RSA_OAEP];
 
     for padding in paddings {
         let alias = format!("ks_rsa_sign_key_unsupported_pad_test_4_{}", padding.0);
         let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-            &sec_level,
+            &sl,
             Domain::APP,
             -1,
             Some(alias.to_string()),
@@ -1779,12 +1767,11 @@ fn keystore2_rsa_signing_key_unsupported_padding() {
 /// with RSA key.
 #[test]
 fn keystore2_rsa_key_unsupported_op() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_test_5";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1810,12 +1797,11 @@ fn keystore2_rsa_key_unsupported_op() {
 /// generated with decrypt purpose.
 #[test]
 fn keystore2_rsa_key_missing_purpose() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_test_6";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1840,12 +1826,11 @@ fn keystore2_rsa_key_missing_purpose() {
 /// operation with generated key, unsupported digest error is expected.
 #[test]
 fn keystore2_rsa_gen_keys_with_oaep_paddings_without_digest() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_padding_fail";
     let result = key_generations::map_ks_error(create_rsa_key_and_operation(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
@@ -1869,12 +1854,11 @@ fn keystore2_rsa_gen_keys_with_oaep_paddings_without_digest() {
 /// Generate RSA keys with unsupported key size, an error `UNSUPPORTED_KEY_SIZE` is expected.
 #[test]
 fn keystore2_rsa_gen_keys_unsupported_size() {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let alias = "ks_rsa_key_padding_fail";
     let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
-        &sec_level,
+        &sl,
         Domain::APP,
         -1,
         Some(alias.to_string()),
diff --git a/keystore2/tests/keystore2_client_test_utils.rs b/keystore2/tests/keystore2_client_test_utils.rs
index 7534da3a..f028a65a 100644
--- a/keystore2/tests/keystore2_client_test_utils.rs
+++ b/keystore2/tests/keystore2_client_test_utils.rs
@@ -12,29 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{Gid, Uid};
-use serde::{Deserialize, Serialize};
-
-use std::path::PathBuf;
-use std::process::{Command, Output};
-
-use openssl::bn::BigNum;
-use openssl::encrypt::Encrypter;
-use openssl::error::ErrorStack;
-use openssl::hash::MessageDigest;
-use openssl::nid::Nid;
-use openssl::pkey::PKey;
-use openssl::pkey::Public;
-use openssl::rsa::Padding;
-use openssl::sign::Verifier;
-use openssl::x509::X509;
-
-use binder::wait_for_interface;
-
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     BlockMode::BlockMode, Digest::Digest, ErrorCode::ErrorCode,
     KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
-    SecurityLevel::SecurityLevel, Tag::Tag,
+    Tag::Tag,
 };
 use android_system_keystore2::aidl::android::system::keystore2::{
     CreateOperationResponse::CreateOperationResponse, Domain::Domain,
@@ -42,12 +23,24 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
     KeyParameters::KeyParameters, ResponseCode::ResponseCode,
 };
-
-use packagemanager_aidl::aidl::android::content::pm::IPackageManagerNative::IPackageManagerNative;
-
+use binder::wait_for_interface;
 use keystore2_test_utils::{
-    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as,
+    authorizations, key_generations, key_generations::Error, run_as, SecLevel,
 };
+use nix::unistd::{Gid, Uid};
+use openssl::bn::BigNum;
+use openssl::encrypt::Encrypter;
+use openssl::error::ErrorStack;
+use openssl::hash::MessageDigest;
+use openssl::nid::Nid;
+use openssl::pkey::PKey;
+use openssl::pkey::Public;
+use openssl::rsa::Padding;
+use openssl::sign::Verifier;
+use openssl::x509::X509;
+use packagemanager_aidl::aidl::android::content::pm::IPackageManagerNative::IPackageManagerNative;
+use serde::{Deserialize, Serialize};
+use std::process::{Command, Output};
 
 /// This enum is used to communicate between parent and child processes.
 #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
@@ -70,8 +63,9 @@ pub struct ForcedOp(pub bool);
 pub const SAMPLE_PLAIN_TEXT: &[u8] = b"my message 11111";
 
 pub const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";
-pub const APP_ATTEST_KEY_FEATURE: &str = "android.hardware.keystore.app_attest_key";
-pub const DEVICE_ID_ATTESTATION_FEATURE: &str = "android.software.device_id_attestation";
+const APP_ATTEST_KEY_FEATURE: &str = "android.hardware.keystore.app_attest_key";
+const DEVICE_ID_ATTESTATION_FEATURE: &str = "android.software.device_id_attestation";
+const STRONGBOX_KEYSTORE_FEATURE: &str = "android.hardware.strongbox_keystore";
 
 /// Determines whether app_attest_key_feature is supported or not.
 pub fn app_attest_key_feature_exists() -> bool {
@@ -89,6 +83,15 @@ pub fn device_id_attestation_feature_exists() -> bool {
     pm.hasSystemFeature(DEVICE_ID_ATTESTATION_FEATURE, 0).expect("hasSystemFeature failed.")
 }
 
+/// Determines whether device-unique attestation might be supported by StrongBox.
+pub fn skip_device_unique_attestation_tests() -> bool {
+    let pm = wait_for_interface::<dyn IPackageManagerNative>(PACKAGE_MANAGER_NATIVE_SERVICE)
+        .expect("Failed to get package manager native service.");
+
+    // Device unique attestation was first included in Keymaster 4.1.
+    !pm.hasSystemFeature(STRONGBOX_KEYSTORE_FEATURE, 41).expect("hasSystemFeature failed.")
+}
+
 /// Determines whether to skip device id attestation tests on GSI build with API level < 34.
 pub fn skip_device_id_attest_tests() -> bool {
     // b/298586194, there are some devices launched with Android T, and they will be receiving
@@ -96,10 +99,7 @@ pub fn skip_device_id_attest_tests() -> bool {
     // (ro.product.*_for_attestation) reading logic would not be available for such devices
     // hence skipping this test for such scenario.
 
-    // This file is only present on GSI builds.
-    let gsi_marker = PathBuf::from("/system/system_ext/etc/init/init.gsi.rc");
-
-    get_vsr_api_level() < 34 && gsi_marker.as_path().is_file()
+    get_vsr_api_level() < 34 && key_generations::is_gsi()
 }
 
 #[macro_export]
@@ -130,9 +130,9 @@ macro_rules! skip_device_id_attestation_tests {
 }
 
 #[macro_export]
-macro_rules! skip_tests_if_keymaster_impl_present {
-    () => {
-        if !key_generations::has_default_keymint() {
+macro_rules! require_keymint {
+    ($sl:ident) => {
+        if !$sl.is_keymint() {
             return;
         }
     };
@@ -141,19 +141,18 @@ macro_rules! skip_tests_if_keymaster_impl_present {
 /// Generate EC key and grant it to the list of users with given access vector.
 /// Returns the list of granted keys `nspace` values in the order of given grantee uids.
 pub fn generate_ec_key_and_grant_to_users(
-    keystore2: &binder::Strong<dyn IKeystoreService>,
-    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
+    sl: &SecLevel,
     alias: Option<String>,
     grantee_uids: Vec<i32>,
     access_vector: i32,
 ) -> Result<Vec<i64>, binder::Status> {
     let key_metadata =
-        key_generations::generate_ec_p256_signing_key(sec_level, Domain::APP, -1, alias, None)?;
+        key_generations::generate_ec_p256_signing_key(sl, Domain::APP, -1, alias, None)?;
 
     let mut granted_keys = Vec::new();
 
     for uid in grantee_uids {
-        let granted_key = keystore2.grant(&key_metadata.key, uid, access_vector)?;
+        let granted_key = sl.keystore2.grant(&key_metadata.key, uid, access_vector)?;
         assert_eq!(granted_key.domain, Domain::GRANT);
         granted_keys.push(granted_key.nspace);
     }
@@ -171,14 +170,12 @@ pub fn create_signing_operation(
     nspace: i64,
     alias: Option<String>,
 ) -> binder::Result<CreateOperationResponse> {
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let key_metadata =
-        key_generations::generate_ec_p256_signing_key(&sec_level, domain, nspace, alias, None)
-            .unwrap();
+        key_generations::generate_ec_p256_signing_key(&sl, domain, nspace, alias, None).unwrap();
 
-    sec_level.createOperation(
+    sl.binder.createOperation(
         &key_metadata.key,
         &authorizations::AuthSetBuilder::new().purpose(op_purpose).digest(op_digest),
         forced_op.0,
diff --git a/keystore2/tests/keystore2_client_tests.rs b/keystore2/tests/keystore2_client_tests.rs
index a0c140a0..34ba81f7 100644
--- a/keystore2/tests/keystore2_client_tests.rs
+++ b/keystore2/tests/keystore2_client_tests.rs
@@ -12,6 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+// TODO: rename modules to strip text repeated from crate name ("keystore2_client_" and "_tests").
 pub mod keystore2_client_3des_key_tests;
 pub mod keystore2_client_aes_key_tests;
 pub mod keystore2_client_attest_key_tests;
@@ -30,3 +31,5 @@ pub mod keystore2_client_operation_tests;
 pub mod keystore2_client_rsa_key_tests;
 pub mod keystore2_client_test_utils;
 pub mod keystore2_client_update_subcomponent_tests;
+
+pub mod user_auth;
diff --git a/keystore2/tests/keystore2_client_update_subcomponent_tests.rs b/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
index d9576a84..e25e52a2 100644
--- a/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
+++ b/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
@@ -12,9 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{getuid, Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     ErrorCode::ErrorCode, SecurityLevel::SecurityLevel,
 };
@@ -22,8 +19,11 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
     ResponseCode::ResponseCode,
 };
-
-use keystore2_test_utils::{get_keystore_service, key_generations, key_generations::Error, run_as};
+use keystore2_test_utils::{
+    get_keystore_service, key_generations, key_generations::Error, run_as, SecLevel,
+};
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
 
 /// Generate a key and update its public certificate and certificate chain. Test should be able to
 /// load the key and able to verify whether its certificate and cert-chain are updated successfully.
@@ -31,11 +31,10 @@ use keystore2_test_utils::{get_keystore_service, key_generations, key_generation
 fn keystore2_update_subcomponent_success() {
     let alias = "update_subcomponent_success_key";
 
-    let keystore2 = get_keystore_service();
-    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+    let sl = SecLevel::tee();
 
     let key_metadata = key_generations::generate_ec_p256_signing_key(
-        &sec_level,
+        &sl,
         Domain::SELINUX,
         key_generations::SELINUX_SHELL_NAMESPACE,
         Some(alias.to_string()),
@@ -46,11 +45,11 @@ fn keystore2_update_subcomponent_success() {
     let other_cert: [u8; 32] = [123; 32];
     let other_cert_chain: [u8; 32] = [12; 32];
 
-    keystore2
+    sl.keystore2
         .updateSubcomponent(&key_metadata.key, Some(&other_cert), Some(&other_cert_chain))
         .expect("updateSubcomponent should have succeeded.");
 
-    let key_entry_response = keystore2.getKeyEntry(&key_metadata.key).unwrap();
+    let key_entry_response = sl.keystore2.getKeyEntry(&key_metadata.key).unwrap();
     assert_eq!(Some(other_cert.to_vec()), key_entry_response.metadata.certificate);
     assert_eq!(Some(other_cert_chain.to_vec()), key_entry_response.metadata.certificateChain);
 }
@@ -170,13 +169,12 @@ fn keystore2_update_subcomponent_fails_permission_denied() {
     // SAFETY: The test is run in a separate process with no other threads.
     let mut granted_keys = unsafe {
         run_as::run_as(GRANTOR_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+            let sl = SecLevel::tee();
             let alias = format!("ks_update_subcompo_test_1_{}", getuid());
             let mut granted_keys = Vec::new();
 
             let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sec_level,
+                &sl,
                 Domain::APP,
                 -1,
                 Some(alias),
@@ -186,7 +184,8 @@ fn keystore2_update_subcomponent_fails_permission_denied() {
 
             // Grant a key without update permission.
             let access_vector = KeyPermission::GET_INFO.0;
-            let granted_key = keystore2
+            let granted_key = sl
+                .keystore2
                 .grant(&key_metadata.key, GRANTEE_1_UID.try_into().unwrap(), access_vector)
                 .unwrap();
             assert_eq!(granted_key.domain, Domain::GRANT);
@@ -194,7 +193,8 @@ fn keystore2_update_subcomponent_fails_permission_denied() {
 
             // Grant a key with update permission.
             let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::UPDATE.0;
-            let granted_key = keystore2
+            let granted_key = sl
+                .keystore2
                 .grant(&key_metadata.key, GRANTEE_2_UID.try_into().unwrap(), access_vector)
                 .unwrap();
             assert_eq!(granted_key.domain, Domain::GRANT);
diff --git a/keystore2/tests/legacy_blobs/Android.bp b/keystore2/tests/legacy_blobs/Android.bp
index 0f310f51..92d13072 100644
--- a/keystore2/tests/legacy_blobs/Android.bp
+++ b/keystore2/tests/legacy_blobs/Android.bp
@@ -38,7 +38,6 @@ rust_test {
         "libkeystore2_crypto_rust",
         "libkeystore2_test_utils",
         "libkeystore2_with_test_utils",
-        "liblazy_static",
         "liblibc",
         "libnix",
         "librustutils",
diff --git a/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs b/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs
index 3be99ee3..11a4c0b1 100644
--- a/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs
+++ b/keystore2/tests/legacy_blobs/keystore2_legacy_blob_tests.rs
@@ -12,35 +12,26 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use nix::unistd::{getuid, Gid, Uid};
-use rustutils::users::AID_USER_OFFSET;
-use serde::{Deserialize, Serialize};
-
-use std::ops::Deref;
-use std::path::PathBuf;
-
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel;
-
-use android_system_keystore2::aidl::android::system::keystore2::{
-    Domain::Domain, KeyDescriptor::KeyDescriptor,
-};
-
-use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::IKeystoreMaintenance;
-
 use android_security_authorization::aidl::android::security::authorization::{
     IKeystoreAuthorization::IKeystoreAuthorization,
 };
-
+use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::IKeystoreMaintenance;
+use android_system_keystore2::aidl::android::system::keystore2::{
+    Domain::Domain, KeyDescriptor::KeyDescriptor,
+};
 use keystore2::key_parameter::KeyParameter as KsKeyparameter;
 use keystore2::legacy_blob::test_utils::legacy_blob_test_vectors::*;
 use keystore2::legacy_blob::test_utils::*;
 use keystore2::legacy_blob::LegacyKeyCharacteristics;
 use keystore2::utils::AesGcm;
 use keystore2_crypto::{Password, ZVec};
-
-use keystore2_test_utils::get_keystore_service;
-use keystore2_test_utils::key_generations;
-use keystore2_test_utils::run_as;
+use keystore2_test_utils::{get_keystore_service, key_generations, run_as, SecLevel};
+use nix::unistd::{getuid, Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
+use serde::{Deserialize, Serialize};
+use std::ops::Deref;
+use std::path::PathBuf;
 
 static USER_MANAGER_SERVICE_NAME: &str = "android.security.maintenance";
 static AUTH_SERVICE_NAME: &str = "android.security.authorization";
@@ -160,15 +151,12 @@ fn keystore2_encrypted_characteristics() -> anyhow::Result<()> {
                     println!("onUserRemoved error: {:#?}", e);
                 }
             }
+            let sl = SecLevel::tee();
 
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2
-                .getSecurityLevel(SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT)
-                .unwrap();
             // Generate Key BLOB and prepare legacy keystore blob files.
             let att_challenge: Option<&[u8]> = if rkp_only() { None } else { Some(b"foo") };
             let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sec_level,
+                &sl,
                 Domain::BLOB,
                 SELINUX_SHELL_NAMESPACE,
                 None,
@@ -412,14 +400,11 @@ fn keystore2_encrypted_certificates() -> anyhow::Result<()> {
                 }
             }
 
-            let keystore2 = get_keystore_service();
-            let sec_level = keystore2
-                .getSecurityLevel(SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT)
-                .unwrap();
+            let sl = SecLevel::tee();
             // Generate Key BLOB and prepare legacy keystore blob files.
             let att_challenge: Option<&[u8]> = if rkp_only() { None } else { Some(b"foo") };
             let key_metadata = key_generations::generate_ec_p256_signing_key(
-                &sec_level,
+                &sl,
                 Domain::BLOB,
                 SELINUX_SHELL_NAMESPACE,
                 None,
diff --git a/keystore2/tests/user_auth.rs b/keystore2/tests/user_auth.rs
new file mode 100644
index 00000000..4e3c6925
--- /dev/null
+++ b/keystore2/tests/user_auth.rs
@@ -0,0 +1,261 @@
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
+//! Tests for user authentication interactions (via `IKeystoreAuthorization`).
+
+use crate::keystore2_client_test_utils::BarrierReached;
+use android_security_authorization::aidl::android::security::authorization::{
+    IKeystoreAuthorization::IKeystoreAuthorization
+};
+use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::{
+     IKeystoreMaintenance,
+};
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, HardwareAuthToken::HardwareAuthToken,
+    HardwareAuthenticatorType::HardwareAuthenticatorType, SecurityLevel::SecurityLevel,
+    KeyPurpose::KeyPurpose
+};
+use android_system_keystore2::aidl::android::system::keystore2::{
+    CreateOperationResponse::CreateOperationResponse, Domain::Domain, KeyDescriptor::KeyDescriptor,
+    KeyMetadata::KeyMetadata,
+};
+use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
+    Timestamp::Timestamp,
+};
+use keystore2_test_utils::{
+    get_keystore_service, run_as, authorizations::AuthSetBuilder,
+};
+use log::{warn, info};
+use nix::unistd::{Gid, Uid};
+use rustutils::users::AID_USER_OFFSET;
+
+/// Test user ID.
+const TEST_USER_ID: i32 = 100;
+/// Fake password blob.
+static PASSWORD: &[u8] = &[
+    0x42, 0x39, 0x30, 0x37, 0x44, 0x37, 0x32, 0x37, 0x39, 0x39, 0x43, 0x42, 0x39, 0x41, 0x42, 0x30,
+    0x34, 0x31, 0x30, 0x38, 0x46, 0x44, 0x33, 0x45, 0x39, 0x42, 0x32, 0x38, 0x36, 0x35, 0x41, 0x36,
+    0x33, 0x44, 0x42, 0x42, 0x43, 0x36, 0x33, 0x42, 0x34, 0x39, 0x37, 0x33, 0x35, 0x45, 0x41, 0x41,
+    0x32, 0x45, 0x31, 0x35, 0x43, 0x43, 0x46, 0x32, 0x39, 0x36, 0x33, 0x34, 0x31, 0x32, 0x41, 0x39,
+];
+/// Fake SID value corresponding to Gatekeeper.
+static GK_SID: i64 = 123456;
+/// Fake SID value corresponding to a biometric authenticator.
+static BIO_SID1: i64 = 345678;
+/// Fake SID value corresponding to a biometric authenticator.
+static BIO_SID2: i64 = 456789;
+
+const WEAK_UNLOCK_ENABLED: bool = true;
+const WEAK_UNLOCK_DISABLED: bool = false;
+const UNFORCED: bool = false;
+
+fn get_authorization() -> binder::Strong<dyn IKeystoreAuthorization> {
+    binder::get_interface("android.security.authorization").unwrap()
+}
+
+fn get_maintenance() -> binder::Strong<dyn IKeystoreMaintenance> {
+    binder::get_interface("android.security.maintenance").unwrap()
+}
+
+fn abort_op(result: binder::Result<CreateOperationResponse>) {
+    if let Ok(rsp) = result {
+        if let Some(op) = rsp.iOperation {
+            if let Err(e) = op.abort() {
+                warn!("abort op failed: {e:?}");
+            }
+        } else {
+            warn!("can't abort op with missing iOperation");
+        }
+    } else {
+        warn!("can't abort failed op: {result:?}");
+    }
+}
+
+/// RAII structure to ensure that test users are removed at the end of a test.
+struct TestUser {
+    id: i32,
+    maint: binder::Strong<dyn IKeystoreMaintenance>,
+}
+
+impl TestUser {
+    fn new() -> Self {
+        Self::new_user(TEST_USER_ID, PASSWORD)
+    }
+    fn new_user(user_id: i32, password: &[u8]) -> Self {
+        let maint = get_maintenance();
+        maint.onUserAdded(user_id).expect("failed to add test user");
+        maint
+            .initUserSuperKeys(user_id, password, /* allowExisting= */ false)
+            .expect("failed to init test user");
+        Self { id: user_id, maint }
+    }
+}
+
+impl Drop for TestUser {
+    fn drop(&mut self) {
+        let _ = self.maint.onUserRemoved(self.id);
+    }
+}
+
+#[test]
+fn keystore2_test_unlocked_device_required() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_client_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+    static CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
+    const UID: u32 = TEST_USER_ID as u32 * AID_USER_OFFSET + 1001;
+
+    // Safety: only one thread at this point, and nothing yet done with binder.
+    let mut child_handle = unsafe {
+        // Perform keystore actions while running as the test user.
+        run_as::run_as_child(
+            CTX,
+            Uid::from_raw(UID),
+            Gid::from_raw(UID),
+            move |reader, writer| -> Result<(), String> {
+                // Action A: create a new unlocked-device-required key (which thus requires
+                // super-encryption), while the device is unlocked.
+                let ks2 = get_keystore_service();
+                if ks2.getInterfaceVersion().unwrap() < 4 {
+                    // Assuming `IKeystoreAuthorization::onDeviceLocked` and
+                    // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
+                    // with `IKeystoreService` >= 4.
+                    return Ok(());
+                }
+
+                // Now we're in a new process, wait to be notified before starting.
+                reader.recv();
+
+                let sec_level = ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
+                let params = AuthSetBuilder::new()
+                    .no_auth_required()
+                    .unlocked_device_required()
+                    .algorithm(Algorithm::EC)
+                    .purpose(KeyPurpose::SIGN)
+                    .purpose(KeyPurpose::VERIFY)
+                    .digest(Digest::SHA_2_256)
+                    .ec_curve(EcCurve::P_256);
+
+                let KeyMetadata { key, .. } = sec_level
+                    .generateKey(
+                        &KeyDescriptor {
+                            domain: Domain::APP,
+                            nspace: -1,
+                            alias: Some("unlocked-device-required".to_string()),
+                            blob: None,
+                        },
+                        None,
+                        &params,
+                        0,
+                        b"entropy",
+                    )
+                    .expect("key generation failed");
+                info!("A: created unlocked-device-required key while unlocked {key:?}");
+                writer.send(&BarrierReached {}); // A done.
+
+                // Action B: fail to use the unlocked-device-required key while locked.
+                reader.recv();
+                let params =
+                    AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
+                let result = sec_level.createOperation(&key, &params, UNFORCED);
+                info!("B: use unlocked-device-required key while locked => {result:?}");
+                assert!(result.is_err());
+                writer.send(&BarrierReached {}); // B done.
+
+                // Action C: try to use the unlocked-device-required key while unlocked with a
+                // password.
+                reader.recv();
+                let result = sec_level.createOperation(&key, &params, UNFORCED);
+                info!("C: use unlocked-device-required key while lskf-unlocked => {result:?}");
+                assert!(result.is_ok(), "failed with {result:?}");
+                abort_op(result);
+                writer.send(&BarrierReached {}); // C done.
+
+                // Action D: try to use the unlocked-device-required key while unlocked with a weak
+                // biometric.
+                reader.recv();
+                let result = sec_level.createOperation(&key, &params, UNFORCED);
+                info!("D: use unlocked-device-required key while weak-locked => {result:?}");
+                assert!(result.is_ok(), "createOperation failed: {result:?}");
+                abort_op(result);
+                writer.send(&BarrierReached {}); // D done.
+
+                let _ = sec_level.deleteKey(&key);
+                Ok(())
+            },
+        )
+    }
+    .unwrap();
+
+    let ks2 = get_keystore_service();
+    if ks2.getInterfaceVersion().unwrap() < 4 {
+        // Assuming `IKeystoreAuthorization::onDeviceLocked` and
+        // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
+        // with `IKeystoreService` >= 4.
+        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+        return;
+    }
+    // Now that the separate process has been forked off, it's safe to use binder.
+    let user = TestUser::new();
+    let user_id = user.id;
+    let auth_service = get_authorization();
+
+    // Lock and unlock to ensure super keys are already created.
+    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_DISABLED).unwrap();
+    auth_service.onDeviceUnlocked(user_id, Some(PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_SID)).unwrap();
+
+    info!("trigger child process action A while unlocked and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv();
+
+    // Move to locked and don't allow weak unlock, so super keys are wiped.
+    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_DISABLED).unwrap();
+
+    info!("trigger child process action B while locked and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv();
+
+    // Unlock with password => loads super key from database.
+    auth_service.onDeviceUnlocked(user_id, Some(PASSWORD)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(GK_SID)).unwrap();
+
+    info!("trigger child process action C while lskf-unlocked and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv();
+
+    // Move to locked and allow weak unlock, then do a weak unlock.
+    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_ENABLED).unwrap();
+    auth_service.onDeviceUnlocked(user_id, None).unwrap();
+
+    info!("trigger child process action D while weak-unlocked and wait for completion");
+    child_handle.send(&BarrierReached {});
+    child_handle.recv();
+
+    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+}
+
+/// Generate a fake [`HardwareAuthToken`] for the given sid.
+fn fake_lskf_token(gk_sid: i64) -> HardwareAuthToken {
+    HardwareAuthToken {
+        challenge: 0,
+        userId: gk_sid,
+        authenticatorId: 0,
+        authenticatorType: HardwareAuthenticatorType::PASSWORD,
+        timestamp: Timestamp { milliSeconds: 123 },
+        mac: vec![1, 2, 3],
+    }
+}
diff --git a/keystore2/watchdog/src/lib.rs b/keystore2/watchdog/src/lib.rs
index fa4620a8..b4a1e0fd 100644
--- a/keystore2/watchdog/src/lib.rs
+++ b/keystore2/watchdog/src/lib.rs
@@ -29,6 +29,9 @@ use std::{
     time::{Duration, Instant},
 };
 
+#[cfg(test)]
+mod tests;
+
 /// Represents a Watchdog record. It can be created with `Watchdog::watch` or
 /// `Watchdog::watch_with`. It disarms the record when dropped.
 pub struct WatchPoint {
@@ -58,59 +61,73 @@ struct Index {
 struct Record {
     started: Instant,
     deadline: Instant,
-    callback: Option<Box<dyn Fn() -> String + Send + 'static>>,
+    context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
 }
 
 struct WatchdogState {
     state: State,
     thread: Option<thread::JoinHandle<()>>,
-    timeout: Duration,
+    /// How long to wait before dropping the watchdog thread when idle.
+    idle_timeout: Duration,
     records: HashMap<Index, Record>,
-    last_report: Instant,
-    has_overdue: bool,
+    last_report: Option<Instant>,
+    noisy_timeout: Duration,
 }
 
 impl WatchdogState {
-    fn update_overdue_and_find_next_timeout(&mut self) -> (bool, Option<Duration>) {
+    /// If we have overdue records, we want to log them but slowly backoff
+    /// so that we do not clog the logs. We start with logs every
+    /// `MIN_REPORT_TIMEOUT` sec then increment the timeout by 5 up
+    /// to a maximum of `MAX_REPORT_TIMEOUT`.
+    const MIN_REPORT_TIMEOUT: Duration = Duration::from_secs(1);
+    const MAX_REPORT_TIMEOUT: Duration = Duration::from_secs(30);
+
+    fn reset_noisy_timeout(&mut self) {
+        self.noisy_timeout = Self::MIN_REPORT_TIMEOUT;
+    }
+
+    fn update_noisy_timeout(&mut self) {
+        let noisy_update = self.noisy_timeout + Duration::from_secs(5);
+        self.noisy_timeout = min(Self::MAX_REPORT_TIMEOUT, noisy_update);
+    }
+
+    fn overdue_and_next_timeout(&self) -> (bool, Option<Duration>) {
         let now = Instant::now();
         let mut next_timeout: Option<Duration> = None;
         let mut has_overdue = false;
         for (_, r) in self.records.iter() {
             let timeout = r.deadline.saturating_duration_since(now);
             if timeout == Duration::new(0, 0) {
+                // This timeout has passed.
                 has_overdue = true;
-                continue;
+            } else {
+                // This timeout is still to come; see if it's the closest one to now.
+                next_timeout = match next_timeout {
+                    Some(nt) if timeout < nt => Some(timeout),
+                    Some(nt) => Some(nt),
+                    None => Some(timeout),
+                };
             }
-            next_timeout = match next_timeout {
-                Some(nt) => {
-                    if timeout < nt {
-                        Some(timeout)
-                    } else {
-                        Some(nt)
-                    }
-                }
-                None => Some(timeout),
-            };
         }
         (has_overdue, next_timeout)
     }
 
-    fn log_report(&mut self, has_overdue: bool) -> bool {
-        match (self.has_overdue, has_overdue) {
-            (true, true) => {
-                if self.last_report.elapsed() < Watchdog::NOISY_REPORT_TIMEOUT {
-                    self.has_overdue = false;
-                    return false;
-                }
-            }
-            (_, false) => {
-                self.has_overdue = false;
-                return false;
+    fn log_report(&mut self, has_overdue: bool) {
+        if !has_overdue {
+            // Nothing to report.
+            self.last_report = None;
+            return;
+        }
+        // Something to report...
+        if let Some(reported_at) = self.last_report {
+            if reported_at.elapsed() < self.noisy_timeout {
+                // .. but it's too soon since the last report.
+                self.last_report = None;
+                return;
             }
-            (false, true) => {}
         }
-        self.last_report = Instant::now();
-        self.has_overdue = has_overdue;
+        self.update_noisy_timeout();
+        self.last_report = Some(Instant::now());
         log::warn!("### Keystore Watchdog report - BEGIN ###");
 
         let now = Instant::now();
@@ -149,15 +166,15 @@ impl WatchdogState {
 
         for g in groups.iter() {
             for (i, r) in g.iter() {
-                match &r.callback {
-                    Some(cb) => {
+                match &r.context {
+                    Some(ctx) => {
                         log::warn!(
-                            "{:?} {} Pending: {:?} Overdue {:?}: {}",
+                            "{:?} {} Pending: {:?} Overdue {:?} for {:?}",
                             i.tid,
                             i.id,
                             r.started.elapsed(),
                             r.deadline.elapsed(),
-                            (cb)()
+                            ctx
                         );
                     }
                     None => {
@@ -173,11 +190,33 @@ impl WatchdogState {
             }
         }
         log::warn!("### Keystore Watchdog report - END ###");
-        true
     }
 
     fn disarm(&mut self, index: Index) {
-        self.records.remove(&index);
+        let result = self.records.remove(&index);
+        if let Some(record) = result {
+            let now = Instant::now();
+            let timeout_left = record.deadline.saturating_duration_since(now);
+            if timeout_left == Duration::new(0, 0) {
+                match &record.context {
+                    Some(ctx) => log::info!(
+                        "Watchdog complete for: {:?} {} Pending: {:?} Overdue {:?} for {:?}",
+                        index.tid,
+                        index.id,
+                        record.started.elapsed(),
+                        record.deadline.elapsed(),
+                        ctx
+                    ),
+                    None => log::info!(
+                        "Watchdog complete for: {:?} {} Pending: {:?} Overdue {:?}",
+                        index.tid,
+                        index.id,
+                        record.started.elapsed(),
+                        record.deadline.elapsed()
+                    ),
+                }
+            }
+        }
     }
 
     fn arm(&mut self, index: Index, record: Record) {
@@ -195,71 +234,66 @@ pub struct Watchdog {
 }
 
 impl Watchdog {
-    /// If we have overdue records, we want to be noisy about it and log a report
-    /// at least every `NOISY_REPORT_TIMEOUT` interval.
-    const NOISY_REPORT_TIMEOUT: Duration = Duration::from_secs(1);
-
-    /// Construct a [`Watchdog`]. When `timeout` has elapsed since the watchdog thread became
+    /// Construct a [`Watchdog`]. When `idle_timeout` has elapsed since the watchdog thread became
     /// idle, i.e., there are no more active or overdue watch points, the watchdog thread
     /// terminates.
-    pub fn new(timeout: Duration) -> Arc<Self> {
+    pub fn new(idle_timeout: Duration) -> Arc<Self> {
         Arc::new(Self {
             state: Arc::new((
                 Condvar::new(),
                 Mutex::new(WatchdogState {
                     state: State::NotRunning,
                     thread: None,
-                    timeout,
+                    idle_timeout,
                     records: HashMap::new(),
-                    last_report: Instant::now(),
-                    has_overdue: false,
+                    last_report: None,
+                    noisy_timeout: WatchdogState::MIN_REPORT_TIMEOUT,
                 }),
             )),
         })
     }
 
     fn watch_with_optional(
-        wd: &Arc<Self>,
-        callback: Option<Box<dyn Fn() -> String + Send + 'static>>,
+        wd: Arc<Self>,
+        context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
         id: &'static str,
         timeout: Duration,
     ) -> Option<WatchPoint> {
-        let deadline = Instant::now().checked_add(timeout);
-        if deadline.is_none() {
+        let Some(deadline) = Instant::now().checked_add(timeout) else {
             log::warn!("Deadline computation failed for WatchPoint \"{}\"", id);
             log::warn!("WatchPoint not armed.");
             return None;
-        }
-        wd.arm(callback, id, deadline.unwrap());
-        Some(WatchPoint { id, wd: wd.clone(), not_send: Default::default() })
+        };
+        wd.arm(context, id, deadline);
+        Some(WatchPoint { id, wd, not_send: Default::default() })
     }
 
     /// Create a new watch point. If the WatchPoint is not dropped before the timeout
     /// expires, a report is logged at least every second, which includes the id string
-    /// and whatever string the callback returns.
+    /// and any provided context.
     pub fn watch_with(
         wd: &Arc<Self>,
         id: &'static str,
         timeout: Duration,
-        callback: impl Fn() -> String + Send + 'static,
+        context: impl std::fmt::Debug + Send + 'static,
     ) -> Option<WatchPoint> {
-        Self::watch_with_optional(wd, Some(Box::new(callback)), id, timeout)
+        Self::watch_with_optional(wd.clone(), Some(Box::new(context)), id, timeout)
     }
 
-    /// Like `watch_with`, but without a callback.
+    /// Like `watch_with`, but without context.
     pub fn watch(wd: &Arc<Self>, id: &'static str, timeout: Duration) -> Option<WatchPoint> {
-        Self::watch_with_optional(wd, None, id, timeout)
+        Self::watch_with_optional(wd.clone(), None, id, timeout)
     }
 
     fn arm(
         &self,
-        callback: Option<Box<dyn Fn() -> String + Send + 'static>>,
+        context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
         id: &'static str,
         deadline: Instant,
     ) {
         let tid = thread::current().id();
         let index = Index { tid, id };
-        let record = Record { started: Instant::now(), deadline, callback };
+        let record = Record { started: Instant::now(), deadline, context };
 
         let (ref condvar, ref state) = *self.state;
 
@@ -297,21 +331,24 @@ impl Watchdog {
             let mut state = state.lock().unwrap();
 
             loop {
-                let (has_overdue, next_timeout) = state.update_overdue_and_find_next_timeout();
+                let (has_overdue, next_timeout) = state.overdue_and_next_timeout();
                 state.log_report(has_overdue);
+
                 let (next_timeout, idle) = match (has_overdue, next_timeout) {
-                    (true, Some(next_timeout)) => {
-                        (min(next_timeout, Self::NOISY_REPORT_TIMEOUT), false)
-                    }
+                    (true, Some(next_timeout)) => (min(next_timeout, state.noisy_timeout), false),
+                    (true, None) => (state.noisy_timeout, false),
                     (false, Some(next_timeout)) => (next_timeout, false),
-                    (true, None) => (Self::NOISY_REPORT_TIMEOUT, false),
-                    (false, None) => (state.timeout, true),
+                    (false, None) => (state.idle_timeout, true),
                 };
 
+                // Wait until the closest timeout pops, but use a condition variable so that if a
+                // new watchpoint is started in the meanwhile it will interrupt the wait so we can
+                // recalculate.
                 let (s, timeout) = condvar.wait_timeout(state, next_timeout).unwrap();
                 state = s;
 
                 if idle && timeout.timed_out() && state.records.is_empty() {
+                    state.reset_noisy_timeout();
                     state.state = State::NotRunning;
                     break;
                 }
@@ -321,40 +358,3 @@ impl Watchdog {
         state.state = State::Running;
     }
 }
-
-#[cfg(test)]
-mod tests {
-
-    use super::*;
-    use std::sync::atomic;
-    use std::thread;
-    use std::time::Duration;
-
-    #[test]
-    fn test_watchdog() {
-        android_logger::init_once(
-            android_logger::Config::default()
-                .with_tag("keystore2_watchdog_tests")
-                .with_max_level(log::LevelFilter::Debug),
-        );
-
-        let wd = Watchdog::new(Watchdog::NOISY_REPORT_TIMEOUT.checked_mul(3).unwrap());
-        let hit_count = Arc::new(atomic::AtomicU8::new(0));
-        let hit_count_clone = hit_count.clone();
-        let wp =
-            Watchdog::watch_with(&wd, "test_watchdog", Duration::from_millis(100), move || {
-                format!("hit_count: {}", hit_count_clone.fetch_add(1, atomic::Ordering::Relaxed))
-            });
-        assert_eq!(0, hit_count.load(atomic::Ordering::Relaxed));
-        thread::sleep(Duration::from_millis(500));
-        assert_eq!(1, hit_count.load(atomic::Ordering::Relaxed));
-        thread::sleep(Watchdog::NOISY_REPORT_TIMEOUT);
-        assert_eq!(2, hit_count.load(atomic::Ordering::Relaxed));
-        drop(wp);
-        thread::sleep(Watchdog::NOISY_REPORT_TIMEOUT.checked_mul(4).unwrap());
-        assert_eq!(2, hit_count.load(atomic::Ordering::Relaxed));
-        let (_, ref state) = *wd.state;
-        let state = state.lock().unwrap();
-        assert_eq!(state.state, State::NotRunning);
-    }
-}
diff --git a/keystore2/watchdog/src/tests.rs b/keystore2/watchdog/src/tests.rs
new file mode 100644
index 00000000..d35c0dde
--- /dev/null
+++ b/keystore2/watchdog/src/tests.rs
@@ -0,0 +1,86 @@
+// Copyright 2021, The Android Open Source Project
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
+//! Watchdog tests.
+
+use super::*;
+use std::sync::atomic;
+use std::thread;
+use std::time::Duration;
+
+/// Count the number of times `Debug::fmt` is invoked.
+#[derive(Default, Clone)]
+struct DebugCounter(Arc<atomic::AtomicU8>);
+impl DebugCounter {
+    fn value(&self) -> u8 {
+        self.0.load(atomic::Ordering::Relaxed)
+    }
+}
+impl std::fmt::Debug for DebugCounter {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
+        let count = self.0.fetch_add(1, atomic::Ordering::Relaxed);
+        write!(f, "hit_count: {count}")
+    }
+}
+
+#[test]
+fn test_watchdog() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_watchdog_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    let wd = Watchdog::new(Duration::from_secs(3));
+    let hit_counter = DebugCounter::default();
+    let wp =
+        Watchdog::watch_with(&wd, "test_watchdog", Duration::from_millis(100), hit_counter.clone());
+    assert_eq!(0, hit_counter.value());
+    thread::sleep(Duration::from_millis(500));
+    assert_eq!(1, hit_counter.value());
+    thread::sleep(Duration::from_secs(1));
+    assert_eq!(1, hit_counter.value());
+
+    drop(wp);
+    thread::sleep(Duration::from_secs(10));
+    assert_eq!(1, hit_counter.value());
+    let (_, ref state) = *wd.state;
+    let state = state.lock().unwrap();
+    assert_eq!(state.state, State::NotRunning);
+}
+
+#[test]
+fn test_watchdog_backoff() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_watchdog_tests")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    let wd = Watchdog::new(Duration::from_secs(3));
+    let hit_counter = DebugCounter::default();
+    let wp =
+        Watchdog::watch_with(&wd, "test_watchdog", Duration::from_millis(100), hit_counter.clone());
+    assert_eq!(0, hit_counter.value());
+    thread::sleep(Duration::from_millis(500));
+    assert_eq!(1, hit_counter.value());
+    thread::sleep(Duration::from_secs(6));
+    assert_eq!(2, hit_counter.value());
+    thread::sleep(Duration::from_secs(11));
+    assert_eq!(3, hit_counter.value());
+
+    drop(wp);
+    thread::sleep(Duration::from_secs(4));
+    assert_eq!(3, hit_counter.value());
+}
diff --git a/prng_seeder/Android.bp b/prng_seeder/Android.bp
index 4f9b7e14..b56a405c 100644
--- a/prng_seeder/Android.bp
+++ b/prng_seeder/Android.bp
@@ -19,19 +19,6 @@ package {
     default_applicable_licenses: ["system_security_license"],
 }
 
-rust_bindgen {
-    name: "libcutils_socket_bindgen",
-    crate_name: "cutils_socket_bindgen",
-    wrapper_src: "cutils_wrapper.h",
-    source_stem: "bindings",
-    bindgen_flags: [
-        "--allowlist-function=android_get_control_socket",
-    ],
-    shared_libs: [
-        "libcutils",
-    ],
-}
-
 rust_defaults {
     name: "prng_seeder_defaults",
     edition: "2021",
@@ -39,10 +26,10 @@ rust_defaults {
         "libanyhow",
         "libbssl_sys",
         "libclap",
-        "libcutils_socket_bindgen",
         "liblogger",
         "liblog_rust",
         "libnix",
+        "librustutils",
         "libtokio",
     ],
 
@@ -73,10 +60,10 @@ rust_test {
         "libanyhow",
         "libbssl_sys",
         "libclap",
-        "libcutils_socket_bindgen",
         "liblogger",
         "liblog_rust",
         "libnix",
+        "librustutils",
         "libtokio",
     ],
     test_suites: ["general-tests"],
diff --git a/prng_seeder/src/cutils_socket.rs b/prng_seeder/src/cutils_socket.rs
deleted file mode 100644
index b408be60..00000000
--- a/prng_seeder/src/cutils_socket.rs
+++ /dev/null
@@ -1,29 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-use std::ffi::CString;
-use std::os::unix::{net::UnixListener, prelude::FromRawFd};
-
-use anyhow::{ensure, Result};
-
-pub fn android_get_control_socket(name: &str) -> Result<UnixListener> {
-    let name = CString::new(name)?;
-    // SAFETY: name is a valid C string, and android_get_control_socket doesn't retain it after it
-    // returns.
-    let fd = unsafe { cutils_socket_bindgen::android_get_control_socket(name.as_ptr()) };
-    ensure!(fd >= 0, "android_get_control_socket failed");
-    // SAFETY: android_get_control_socket either returns a valid and open FD or -1, and we checked
-    // that it's not -1.
-    Ok(unsafe { UnixListener::from_raw_fd(fd) })
-}
diff --git a/prng_seeder/src/main.rs b/prng_seeder/src/main.rs
index cb7f38d7..d112d619 100644
--- a/prng_seeder/src/main.rs
+++ b/prng_seeder/src/main.rs
@@ -18,7 +18,6 @@
 //! by init.
 
 mod conditioner;
-mod cutils_socket;
 mod drbg;
 
 use std::{
@@ -70,6 +69,9 @@ fn get_socket(path: &Path) -> Result<UnixListener> {
 }
 
 fn setup() -> Result<(ConditionerBuilder, UnixListener)> {
+    // SAFETY: nobody has taken ownership of the inherited FDs yet.
+    unsafe { rustutils::inherited_fd::init_once() }
+        .context("In setup, failed to own inherited FDs")?;
     configure_logging()?;
     let cli = Cli::try_parse()?;
     // SAFETY: Nothing else sets the signal handler, so either it was set here or it is the default.
@@ -78,8 +80,9 @@ fn setup() -> Result<(ConditionerBuilder, UnixListener)> {
 
     let listener = match cli.socket {
         Some(path) => get_socket(path.as_path())?,
-        None => cutils_socket::android_get_control_socket("prng_seeder")
-            .context("In setup, calling android_get_control_socket")?,
+        None => rustutils::sockets::android_get_control_socket("prng_seeder")
+            .context("In setup, calling android_get_control_socket")?
+            .into(),
     };
     let hwrng = std::fs::File::open(&cli.source)
         .with_context(|| format!("Unable to open hwrng {}", cli.source.display()))?;
diff --git a/provisioner/Android.bp b/provisioner/Android.bp
index ede1ae6c..6a4dc243 100644
--- a/provisioner/Android.bp
+++ b/provisioner/Android.bp
@@ -36,6 +36,7 @@ cc_defaults {
     ],
     static_libs: [
         "android.hardware.common-V2-ndk",
+        "android.hardware.drm.common-V1-ndk",
         "android.hardware.drm-V1-ndk",
         "android.hardware.security.rkp-V3-ndk",
         "libbase",
diff --git a/provisioner/rkp_factory_extraction_lib.cpp b/provisioner/rkp_factory_extraction_lib.cpp
index ec70d086..2c2614d3 100644
--- a/provisioner/rkp_factory_extraction_lib.cpp
+++ b/provisioner/rkp_factory_extraction_lib.cpp
@@ -224,7 +224,8 @@ CborResult<Array> composeCertificateRequestV3(const std::vector<uint8_t>& csr) {
 }
 
 CborResult<cppbor::Array> getCsrV3(std::string_view componentName,
-                                   IRemotelyProvisionedComponent* irpc, bool selfTest) {
+                                   IRemotelyProvisionedComponent* irpc, bool selfTest,
+                                   bool allowDegenerate) {
     std::vector<uint8_t> csr;
     std::vector<MacedPublicKey> emptyKeys;
     const std::vector<uint8_t> challenge = generateChallenge();
@@ -237,7 +238,8 @@ CborResult<cppbor::Array> getCsrV3(std::string_view componentName,
     }
 
     if (selfTest) {
-        auto result = verifyFactoryCsr(/*keysToSign=*/cppbor::Array(), csr, irpc, challenge);
+        auto result =
+            verifyFactoryCsr(/*keysToSign=*/cppbor::Array(), csr, irpc, challenge, allowDegenerate);
         if (!result) {
             std::cerr << "Self test failed for IRemotelyProvisionedComponent '" << componentName
                       << "'. Error message: '" << result.message() << "'." << std::endl;
@@ -249,7 +251,7 @@ CborResult<cppbor::Array> getCsrV3(std::string_view componentName,
 }
 
 CborResult<Array> getCsr(std::string_view componentName, IRemotelyProvisionedComponent* irpc,
-                         bool selfTest) {
+                         bool selfTest, bool allowDegenerate) {
     RpcHardwareInfo hwInfo;
     auto status = irpc->getHardwareInfo(&hwInfo);
     if (!status.isOk()) {
@@ -264,7 +266,7 @@ CborResult<Array> getCsr(std::string_view componentName, IRemotelyProvisionedCom
         }
         return getCsrV1(componentName, irpc);
     } else {
-        return getCsrV3(componentName, irpc, selfTest);
+        return getCsrV3(componentName, irpc, selfTest, allowDegenerate);
     }
 }
 
diff --git a/provisioner/rkp_factory_extraction_lib.h b/provisioner/rkp_factory_extraction_lib.h
index 93c498ad..94bd7519 100644
--- a/provisioner/rkp_factory_extraction_lib.h
+++ b/provisioner/rkp_factory_extraction_lib.h
@@ -47,7 +47,7 @@ std::vector<uint8_t> generateChallenge();
 CborResult<cppbor::Array>
 getCsr(std::string_view componentName,
        aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent* irpc,
-       bool selfTest);
+       bool selfTest, bool allowDegenerate);
 
 // Generates a test certificate chain and validates it, exiting the process on error.
 void selfTestGetCsr(
diff --git a/provisioner/rkp_factory_extraction_lib_test.cpp b/provisioner/rkp_factory_extraction_lib_test.cpp
index 3fe88da8..247c508b 100644
--- a/provisioner/rkp_factory_extraction_lib_test.cpp
+++ b/provisioner/rkp_factory_extraction_lib_test.cpp
@@ -181,7 +181,7 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV2Hal) {
                         Return(ByMove(ScopedAStatus::ok()))));  //
 
     auto [csr, csrErrMsg] = getCsr("mock component name", mockRpc.get(),
-                                   /*selfTest=*/false);
+                                   /*selfTest=*/false, /*allowDegenerate=*/true);
     ASSERT_THAT(csr, NotNull()) << csrErrMsg;
     ASSERT_THAT(csr->asArray(), Pointee(Property(&Array::size, Eq(4))));
 
@@ -251,7 +251,7 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV3Hal) {
                         Return(ByMove(ScopedAStatus::ok()))));
 
     auto [csr, csrErrMsg] = getCsr("mock component name", mockRpc.get(),
-                                   /*selfTest=*/false);
+                                   /*selfTest=*/false, /*allowDegenerate=*/true);
     ASSERT_THAT(csr, NotNull()) << csrErrMsg;
     ASSERT_THAT(csr, Pointee(Property(&Array::size, Eq(5))));
 
diff --git a/provisioner/rkp_factory_extraction_tool.cpp b/provisioner/rkp_factory_extraction_tool.cpp
index 1cb11448..c0f6beb1 100644
--- a/provisioner/rkp_factory_extraction_tool.cpp
+++ b/provisioner/rkp_factory_extraction_tool.cpp
@@ -43,6 +43,8 @@ DEFINE_bool(self_test, true,
             "If true, this tool performs a self-test, validating the payload for correctness. "
             "This checks that the device on the factory line is producing valid output "
             "before attempting to upload the output to the device info service.");
+DEFINE_bool(allow_degenerate, true,
+            "If true, self_test validation will allow degenerate DICE chains in the CSR.");
 DEFINE_string(serialno_prop, "ro.serialno",
               "The property of getting serial number. Defaults to 'ro.serialno'.");
 
@@ -83,7 +85,7 @@ void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisione
     if (std::string(name) == "avf" && !isRemoteProvisioningSupported(irpc)) {
         return;
     }
-    auto [request, errMsg] = getCsr(name, irpc, FLAGS_self_test);
+    auto [request, errMsg] = getCsr(name, irpc, FLAGS_self_test, FLAGS_allow_degenerate);
     auto fullName = getFullServiceName(descriptor, name);
     if (!request) {
         std::cerr << "Unable to build CSR for '" << fullName << ": " << errMsg << std::endl;
```

