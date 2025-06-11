```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 9b96f369..7ba873b1 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,6 +5,3 @@ rustfmt = true
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 rustfmt = --config-path=rustfmt.toml
-
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/fsverity/OWNERS b/fsverity/OWNERS
index f9e7b25e..1f2485a0 100644
--- a/fsverity/OWNERS
+++ b/fsverity/OWNERS
@@ -1,4 +1,3 @@
-alanstokes@google.com
 ebiggers@google.com
 jeffv@google.com
 jiyong@google.com
diff --git a/fsverity/fsverity_manifest_generator.py b/fsverity/fsverity_manifest_generator.py
index ca7ac5cb..d2324505 100644
--- a/fsverity/fsverity_manifest_generator.py
+++ b/fsverity/fsverity_manifest_generator.py
@@ -31,7 +31,7 @@ def _digest(fsverity_path, input_file):
   cmd = [fsverity_path, 'digest', input_file]
   cmd.extend(['--compact'])
   cmd.extend(['--hash-alg', HASH_ALGORITHM])
-  out = subprocess.check_output(cmd, universal_newlines=True).strip()
+  out = subprocess.check_output(cmd, text=True).strip()
   return bytes(bytearray.fromhex(out))
 
 if __name__ == '__main__':
@@ -46,22 +46,50 @@ if __name__ == '__main__':
       required=True)
   p.add_argument(
       '--base-dir',
-      help='directory to use as a relative root for the inputs',
-      required=True)
+      help='directory to use as a relative root for the inputs. Also see the documentation of '
+      'inputs')
   p.add_argument(
       'inputs',
       nargs='*',
-      help='input file for the build manifest')
+      help='input file for the build manifest. It can be in either of two forms: <file> or '
+      '<file>,<path_on_device>. If the first form is used, --base-dir must be provided, and the '
+      'path on device will be the filepath relative to the base dir')
   args = p.parse_args()
 
+  links = {}
   digests = FSVerityDigests()
   for f in sorted(args.inputs):
-    # f is a full path for now; make it relative so it starts with {mount_point}/
-    digest = digests.digests[os.path.relpath(f, args.base_dir)]
-    digest.digest = _digest(args.fsverity_path, f)
-    digest.hash_alg = HASH_ALGORITHM
+    if args.base_dir:
+      # f is a full path for now; make it relative so it starts with {mount_point}/
+      rel = os.path.relpath(f, args.base_dir)
+    else:
+      parts = f.split(',')
+      if len(parts) != 2 or not parts[0] or not parts[1]:
+        sys.exit("Since --base-path wasn't provided, all inputs must be pairs separated by commas "
+          "but this input wasn't: " + f)
+      f, rel = parts
+
+    # Some fsv_meta files are links to other ones. Don't read through the link, because the
+    # layout of files in the build system may not match the layout of files on the device.
+    # Instead, read its target and use it to copy the digest from the real file after all files
+    # are processed.
+    if os.path.islink(f):
+      links[rel] = os.path.normpath(os.path.join(os.path.dirname(rel), os.readlink(f)))
+    else:
+      digest = digests.digests[rel]
+      digest.digest = _digest(args.fsverity_path, f)
+      digest.hash_alg = HASH_ALGORITHM
+
+  for link_rel, real_rel in links.items():
+    if real_rel not in digests.digests:
+      sys.exit(f'There was a fsv_meta symlink to {real_rel}, but that file was not a fsv_meta file')
+    link_digest = digests.digests[link_rel]
+    real_digest = digests.digests[real_rel]
+    link_digest.CopyFrom(real_digest)
 
-  manifest = digests.SerializeToString()
+  # Serialize with deterministic=True for reproducible builds and build caching.
+  # The serialized contents will still change across different versions of protobuf.
+  manifest = digests.SerializeToString(deterministic=True)
 
   with open(args.output, "wb") as f:
     f.write(manifest)
diff --git a/fsverity_init/Android.bp b/fsverity_init/Android.bp
deleted file mode 100644
index 212aac4a..00000000
--- a/fsverity_init/Android.bp
+++ /dev/null
@@ -1,41 +0,0 @@
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "system_security_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["system_security_license"],
-}
-
-cc_binary {
-    name: "fsverity_init",
-    srcs: [
-        "fsverity_init.cpp",
-    ],
-    static_libs: [
-        "aconfig_fsverity_init_c_lib",
-        "libmini_keyctl_static",
-    ],
-    shared_libs: [
-        "libbase",
-        "libkeyutils",
-        "liblog",
-    ],
-    cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
-    ],
-}
-
-aconfig_declarations {
-    name: "aconfig_fsverity_init",
-    package: "android.security.flag",
-    container: "system",
-    srcs: ["flags.aconfig"],
-}
-
-cc_aconfig_library {
-    name: "aconfig_fsverity_init_c_lib",
-    aconfig_declarations: "aconfig_fsverity_init",
-}
diff --git a/fsverity_init/OWNERS b/fsverity_init/OWNERS
deleted file mode 100644
index f9e7b25e..00000000
--- a/fsverity_init/OWNERS
+++ /dev/null
@@ -1,5 +0,0 @@
-alanstokes@google.com
-ebiggers@google.com
-jeffv@google.com
-jiyong@google.com
-victorhsieh@google.com
diff --git a/fsverity_init/flags.aconfig b/fsverity_init/flags.aconfig
deleted file mode 100644
index 495c71c4..00000000
--- a/fsverity_init/flags.aconfig
+++ /dev/null
@@ -1,10 +0,0 @@
-package: "android.security.flag"
-container: "system"
-
-flag {
-    name: "deprecate_fsverity_init"
-    namespace: "hardware_backed_security"
-    description: "Feature flag for deprecate fsverity_init"
-    bug: "290064770"
-    is_fixed_read_only: true
-}
diff --git a/fsverity_init/fsverity_init.cpp b/fsverity_init/fsverity_init.cpp
deleted file mode 100644
index 717beebc..00000000
--- a/fsverity_init/fsverity_init.cpp
+++ /dev/null
@@ -1,112 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-//
-// fsverity_init is a tool for loading X.509 certificates into the kernel keyring used by the
-// fsverity builtin signature verification kernel feature
-// (https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#built-in-signature-verification).
-// Starting in Android 14, Android has actually stopped using this feature, as it was too inflexible
-// and caused problems.  It has been replaced by userspace signature verification.  Also, some uses
-// of fsverity in Android are now for integrity-only use cases.
-//
-// Regardless, there may exist fsverity files on-disk that were created by Android 13 or earlier.
-// These files still have builtin signatures.  If the kernel is an older kernel that still has
-// CONFIG_FS_VERITY_BUILTIN_SIGNATURES enabled, these files cannot be opened unless the
-// corresponding key is in the ".fs-verity" keyring.  Therefore, this tool still has to exist and be
-// used to load keys into the kernel, even though this has no security purpose anymore.
-//
-// This tool can be removed as soon as all supported kernels are guaranteed to have
-// CONFIG_FS_VERITY_BUILTIN_SIGNATURES disabled, or alternatively as soon as support for upgrades
-// from Android 13 or earlier is no longer required.
-//
-
-#define LOG_TAG "fsverity_init"
-
-#include <sys/types.h>
-
-#include <filesystem>
-#include <string>
-
-#include <android-base/file.h>
-#include <android-base/logging.h>
-#include <android-base/strings.h>
-#include <android_security_flag.h>
-#include <log/log.h>
-#include <mini_keyctl_utils.h>
-
-void LoadKeyFromFile(key_serial_t keyring_id, const char* keyname, const std::string& path) {
-    LOG(INFO) << "LoadKeyFromFile path=" << path << " keyname=" << keyname;
-    std::string content;
-    if (!android::base::ReadFileToString(path, &content)) {
-        LOG(ERROR) << "Failed to read key from " << path;
-        return;
-    }
-    if (add_key("asymmetric", keyname, content.c_str(), content.size(), keyring_id) < 0) {
-        PLOG(ERROR) << "Failed to add key from " << path;
-    }
-}
-
-void LoadKeyFromDirectory(key_serial_t keyring_id, const char* keyname_prefix, const char* dir) {
-    if (!std::filesystem::exists(dir)) {
-        return;
-    }
-    int counter = 0;
-    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
-        if (!android::base::EndsWithIgnoreCase(entry.path().c_str(), ".der")) continue;
-        std::string keyname = keyname_prefix + std::to_string(counter);
-        counter++;
-        LoadKeyFromFile(keyring_id, keyname.c_str(), entry.path());
-    }
-}
-
-void LoadKeyFromVerifiedPartitions(key_serial_t keyring_id) {
-    // NB: Directories need to be synced with FileIntegrityService.java in
-    // frameworks/base.
-    LoadKeyFromDirectory(keyring_id, "fsv_system_", "/system/etc/security/fsverity");
-    LoadKeyFromDirectory(keyring_id, "fsv_product_", "/product/etc/security/fsverity");
-}
-
-int main(int argc, const char** argv) {
-    if (android::security::flag::deprecate_fsverity_init()) {
-        // Don't load keys to the built-in fs-verity keyring in kernel. This will make existing
-        // files not readable. We expect to only enable the flag when there are no such files or
-        // when failure is ok (e.g. with a fallback).
-        return 0;
-    }
-
-    if (argc < 2) {
-        LOG(ERROR) << "Not enough arguments";
-        return -1;
-    }
-
-    key_serial_t keyring_id = android::GetKeyringId(".fs-verity");
-    if (keyring_id < 0) {
-        // This is expected on newer kernels.  See comment at the beginning of this file.
-        LOG(DEBUG) << "no initialization required";
-        return 0;
-    }
-
-    const std::string_view command = argv[1];
-
-    if (command == "--load-verified-keys") {
-        LoadKeyFromVerifiedPartitions(keyring_id);
-    } else {
-        LOG(ERROR) << "Unknown argument(s).";
-        return -1;
-    }
-
-    return 0;
-}
diff --git a/keystore2/Android.bp b/keystore2/Android.bp
index ef5111fd..92a4bed8 100644
--- a/keystore2/Android.bp
+++ b/keystore2/Android.bp
@@ -46,12 +46,14 @@ rust_defaults {
         "android.security.maintenance-rust",
         "android.security.metrics-rust",
         "android.security.rkp_aidl-rust",
+        "apex_aidl_interface-rust",
         "libaconfig_android_hardware_biometrics_rust",
         "libandroid_security_flags_rust",
         "libanyhow",
         "libbinder_rs",
         "libbssl_crypto",
         "libder",
+        "libhex",
         "libkeystore2_aaid-rust",
         "libkeystore2_apc_compat-rust",
         "libkeystore2_crypto_rust",
@@ -111,7 +113,6 @@ rust_test {
     defaults: ["libkeystore2_defaults"],
     rustlibs: [
         "libandroid_logger",
-        "libhex",
         "libkeystore2_test_utils",
         "libkeystore2_with_test_utils",
         "liblibsqlite3_sys",
@@ -191,6 +192,11 @@ java_aconfig_library {
     defaults: ["framework-minus-apex-aconfig-java-defaults"],
 }
 
+cc_aconfig_library {
+    name: "libkeystore2_flags_cc",
+    aconfig_declarations: "keystore2_flags",
+}
+
 rust_aconfig_library {
     name: "libkeystore2_flags_rust",
     crate_name: "keystore2_flags",
diff --git a/keystore2/aconfig/flags.aconfig b/keystore2/aconfig/flags.aconfig
index b15230ec..9161de87 100644
--- a/keystore2/aconfig/flags.aconfig
+++ b/keystore2/aconfig/flags.aconfig
@@ -25,14 +25,6 @@ flag {
   is_fixed_read_only: true
 }
 
-flag {
-  name: "enable_dump"
-  namespace: "hardware_backed_security"
-  description: "Include support for dump() on the IKeystoreMaintenance service"
-  bug: "344987718"
-  is_fixed_read_only: true
-}
-
 flag {
   name: "import_previously_emulated_keys"
   namespace: "hardware_backed_security"
diff --git a/keystore2/aidl/android/security/metrics/HardwareAuthenticatorType.aidl b/keystore2/aidl/android/security/metrics/HardwareAuthenticatorType.aidl
index b13f6ea5..d5cacfd6 100644
--- a/keystore2/aidl/android/security/metrics/HardwareAuthenticatorType.aidl
+++ b/keystore2/aidl/android/security/metrics/HardwareAuthenticatorType.aidl
@@ -17,16 +17,41 @@
 package android.security.metrics;
 
 /**
- * HardwareAuthenticatorType enum as defined in Keystore2KeyCreationWithAuthInfo of
- * frameworks/proto_logging/stats/atoms.proto.
+ * AIDL enum representing the
+ * android.os.statsd.Keystore2KeyCreationWithAuthInfo.HardwareAuthenticatorType protocol buffer enum
+ * defined in frameworks/proto_logging/stats/atoms.proto.
+ *
+ * This enum is a mirror of
+ * hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/HardwareAuthenticatorType.aidl
+ * except that:
+ *   - The enum tag number for the ANY value is set to 5,
+ *   - The enum tag numbers of all other values are incremented by 1, and
+ *   - Two new values are added: AUTH_TYPE_UNSPECIFIED and NO_AUTH_TYPE.
+ * The KeyMint AIDL enum is a bitmask, but since the enum tag numbers in this metrics-specific
+ * mirror were shifted, this enum can't behave as a bitmask. As a result, we have to explicitly add
+ * values to represent the bitwise OR of pairs of values that we expect to see in the wild.
  * @hide
  */
 @Backing(type="int")
 enum HardwareAuthenticatorType {
-    /** Unspecified takes 0. Other values are incremented by 1 compared to keymint spec. */
+    // Sentinel value to represent undefined enum tag numbers (which would represent combinations of
+    // values from the KeyMint enum that aren't explicitly represented here). We don't expect to see
+    // this value in the metrics, but if we do it means that an unexpected (bitwise OR) combination
+    // of KeyMint HardwareAuthenticatorType values is being used as the HardwareAuthenticatorType
+    // key parameter.
     AUTH_TYPE_UNSPECIFIED = 0,
+    // Corresponds to KeyMint's HardwareAuthenticatorType::NONE value (enum tag number 0).
     NONE = 1,
+    // Corresponds to KeyMint's HardwareAuthenticatorType::PASSWORD value (enum tag number 1 << 0).
     PASSWORD = 2,
+    // Corresponds to KeyMint's HardwareAuthenticatorType::FINGERPRINT value (enum tag number
+    // 1 << 1).
     FINGERPRINT = 3,
+    // Corresponds to the (bitwise OR) combination of KeyMint's HardwareAuthenticatorType::PASSWORD
+    // and HardwareAuthenticatorType::FINGERPRINT values.
+    PASSWORD_OR_FINGERPRINT = 4,
+    // Corresponds to KeyMint's HardwareAuthenticatorType::ANY value (enum tag number 0xFFFFFFFF).
     ANY = 5,
+    // No HardwareAuthenticatorType was specified in the key parameters.
+    NO_AUTH_TYPE = 6,
 }
\ No newline at end of file
diff --git a/keystore2/keystore2.rc b/keystore2/keystore2.rc
index d7d6951c..e669b18b 100644
--- a/keystore2/keystore2.rc
+++ b/keystore2/keystore2.rc
@@ -13,3 +13,5 @@ service keystore2 /system/bin/keystore2 /data/misc/keystore
     task_profiles ProcessCapacityHigh
     # The default memlock limit of 65536 bytes is too low for keystore.
     rlimit memlock unlimited unlimited
+    # Reboot to bootloader if Keystore crashes more than 4 times before `sys.boot_completed`.
+    critical window=0
diff --git a/keystore2/postprocessor_client/src/lib.rs b/keystore2/postprocessor_client/src/lib.rs
index 8b347f9f..beeb5f5d 100644
--- a/keystore2/postprocessor_client/src/lib.rs
+++ b/keystore2/postprocessor_client/src/lib.rs
@@ -77,7 +77,7 @@ pub fn process_certificate_chain(
             ]
         }
         Err(err) => {
-            error!("Failed to replace certificates ({err:#?}), falling back to original chain.");
+            warn!("Failed to replace certificates ({err:#?}), falling back to original chain.");
             certificates.push(Certificate { encodedCertificate: attestation_certs });
             certificates
         }
diff --git a/keystore2/selinux/src/lib.rs b/keystore2/selinux/src/lib.rs
index d57a99af..1f1e6924 100644
--- a/keystore2/selinux/src/lib.rs
+++ b/keystore2/selinux/src/lib.rs
@@ -247,34 +247,6 @@ pub fn getcon() -> Result<Context> {
     }
 }
 
-/// Safe wrapper around libselinux `getpidcon`. It initializes the `Context::Raw` variant of the
-/// returned `Context`.
-///
-/// ## Return
-///  * Ok(Context::Raw()) if successful.
-///  * Err(Error::sys()) if getpidcon succeeded but returned a NULL pointer.
-///  * Err(io::Error::last_os_error()) if getpidcon failed.
-pub fn getpidcon(pid: selinux::pid_t) -> Result<Context> {
-    init_logger_once();
-    let _lock = LIB_SELINUX_LOCK.lock().unwrap();
-
-    let mut con: *mut c_char = ptr::null_mut();
-    match unsafe { selinux::getpidcon(pid, &mut con) } {
-        0 => {
-            if !con.is_null() {
-                Ok(Context::Raw(con))
-            } else {
-                Err(anyhow!(Error::sys(format!(
-                    "getpidcon returned a NULL context for pid {}",
-                    pid
-                ))))
-            }
-        }
-        _ => Err(anyhow!(io::Error::last_os_error()))
-            .context(format!("getpidcon failed for pid {}", pid)),
-    }
-}
-
 /// Safe wrapper around selinux_check_access.
 ///
 /// ## Return
@@ -796,12 +768,4 @@ mod tests {
         check_keystore_perm!(reset);
         check_keystore_perm!(unlock);
     }
-
-    #[test]
-    fn test_getpidcon() {
-        // Check that `getpidcon` of our pid is equal to what `getcon` returns.
-        // And by using `unwrap` we make sure that both also have to return successfully
-        // fully to pass the test.
-        assert_eq!(getpidcon(std::process::id() as i32).unwrap(), getcon().unwrap());
-    }
 }
diff --git a/keystore2/src/authorization.rs b/keystore2/src/authorization.rs
index c76f86b0..7812df65 100644
--- a/keystore2/src/authorization.rs
+++ b/keystore2/src/authorization.rs
@@ -20,7 +20,6 @@ use crate::globals::{DB, ENFORCEMENTS, LEGACY_IMPORTER, SUPER_KEY};
 use crate::ks_err;
 use crate::permission::KeystorePerm;
 use crate::utils::{check_keystore_permission, watchdog as wd};
-use aconfig_android_hardware_biometrics_rust;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
 };
@@ -36,7 +35,6 @@ use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::Re
 use anyhow::{Context, Result};
 use keystore2_crypto::Password;
 use keystore2_selinux as selinux;
-use std::ffi::CString;
 
 /// This is the Authorization error type, it wraps binder exceptions and the
 /// Authorization ResponseCode
@@ -288,13 +286,6 @@ impl IKeystoreAuthorization for AuthorizationManager {
         secure_user_id: i64,
         auth_types: &[HardwareAuthenticatorType],
     ) -> binder::Result<i64> {
-        if aconfig_android_hardware_biometrics_rust::last_authentication_time() {
-            self.get_last_auth_time(secure_user_id, auth_types).map_err(into_logged_binder)
-        } else {
-            Err(BinderStatus::new_service_specific_error(
-                ResponseCode::PERMISSION_DENIED.0,
-                Some(CString::new("Feature is not enabled.").unwrap().as_c_str()),
-            ))
-        }
+        self.get_last_auth_time(secure_user_id, auth_types).map_err(into_logged_binder)
     }
 }
diff --git a/keystore2/src/crypto/lib.rs b/keystore2/src/crypto/lib.rs
index 09b84ec8..b6f308b1 100644
--- a/keystore2/src/crypto/lib.rs
+++ b/keystore2/src/crypto/lib.rs
@@ -317,7 +317,7 @@ impl OwnedECPoint {
     }
 }
 
-impl<'a> BorrowedECPoint<'a> {
+impl BorrowedECPoint<'_> {
     /// Get the wrapped EC_POINT object.
     pub fn get_point(&self) -> &EC_POINT {
         // Safety: We only create BorrowedECPoint objects for valid EC_POINTs.
diff --git a/keystore2/src/database.rs b/keystore2/src/database.rs
index 9f27b5a3..8f5617f2 100644
--- a/keystore2/src/database.rs
+++ b/keystore2/src/database.rs
@@ -1163,14 +1163,6 @@ impl KeystoreDB {
         let mut persistent_path_str = "file:".to_owned();
         persistent_path_str.push_str(&persistent_path.to_string_lossy());
 
-        // Connect to database in specific mode
-        let persistent_path_mode = if keystore2_flags::wal_db_journalmode_v3() {
-            "?journal_mode=WAL".to_owned()
-        } else {
-            "?journal_mode=DELETE".to_owned()
-        };
-        persistent_path_str.push_str(&persistent_path_mode);
-
         Ok(persistent_path_str)
     }
 
@@ -2437,11 +2429,13 @@ impl KeystoreDB {
         tx.execute("DELETE FROM persistent.keyparameter WHERE keyentryid = ?;", params![key_id])
             .context("Trying to delete keyparameters.")?;
         tx.execute("DELETE FROM persistent.grant WHERE keyentryid = ?;", params![key_id])
-            .context("Trying to delete grants.")?;
+            .context("Trying to delete grants to other apps.")?;
         // The associated blobentry rows are not immediately deleted when the owning keyentry is
         // removed, because a KeyMint `deleteKey()` invocation is needed (specifically for the
-        // `KEY_BLOB`).  Mark the affected rows with `state=Orphaned` so a subsequent garbage
-        // collection can do this.
+        // `KEY_BLOB`).  That should not be done from within the database transaction.  Also, calls
+        // to `deleteKey()` need to be delayed until the boot has completed, to avoid making
+        // permanent changes during an OTA before the point of no return.  Mark the affected rows
+        // with `state=Orphaned` so a subsequent garbage collection can do the `deleteKey()`.
         tx.execute(
             "UPDATE persistent.blobentry SET state = ? WHERE keyentryid = ?",
             params![BlobState::Orphaned, key_id],
@@ -2450,6 +2444,19 @@ impl KeystoreDB {
         Ok(updated != 0)
     }
 
+    fn delete_received_grants(tx: &Transaction, user_id: u32) -> Result<bool> {
+        let updated = tx
+            .execute(
+                &format!("DELETE FROM persistent.grant WHERE cast ( (grantee/{AID_USER_OFFSET}) as int) = ?;"),
+                params![user_id],
+            )
+            .context(format!(
+                "Trying to delete grants received by user ID {:?} from other apps.",
+                user_id
+            ))?;
+        Ok(updated != 0)
+    }
+
     /// Marks the given key as unreferenced and removes all of the grants to this key.
     /// Returns Ok(true) if a key was marked unreferenced as a hint for the garbage collector.
     pub fn unbind_key(
@@ -2521,7 +2528,19 @@ impl KeystoreDB {
                 );",
                 params![domain.0, namespace, KeyType::Client],
             )
-            .context("Trying to delete grants.")?;
+            .context(format!(
+                "Trying to delete grants issued for keys in domain {:?} and namespace {:?}.",
+                domain.0, namespace
+            ))?;
+            if domain == Domain::APP {
+                // Keystore uses the UID instead of the namespace argument for Domain::APP, so we
+                // just need to delete rows where grantee == namespace.
+                tx.execute("DELETE FROM persistent.grant WHERE grantee = ?;", params![namespace])
+                    .context(format!(
+                    "Trying to delete received grants for domain {:?} and namespace {:?}.",
+                    domain.0, namespace
+                ))?;
+            }
             tx.execute(
                 "DELETE FROM persistent.keyentry
                  WHERE domain = ? AND namespace = ? AND key_type = ?;",
@@ -2579,6 +2598,11 @@ impl KeystoreDB {
         let _wp = wd::watch("KeystoreDB::unbind_keys_for_user");
 
         self.with_transaction(Immediate("TX_unbind_keys_for_user"), |tx| {
+            Self::delete_received_grants(tx, user_id).context(format!(
+                "In unbind_keys_for_user. Failed to delete received grants for user ID {:?}.",
+                user_id
+            ))?;
+
             let mut stmt = tx
                 .prepare(&format!(
                     "SELECT id from persistent.keyentry
@@ -2624,7 +2648,7 @@ impl KeystoreDB {
             let mut notify_gc = false;
             for key_id in key_ids {
                 notify_gc = Self::mark_unreferenced(tx, key_id)
-                    .context("In unbind_keys_for_user.")?
+                    .context("In unbind_keys_for_user. Failed to mark key id as unreferenced.")?
                     || notify_gc;
             }
             Ok(()).do_gc(notify_gc)
@@ -3049,4 +3073,11 @@ impl KeystoreDB {
         let app_uids_vec: Vec<i64> = app_uids_affected_by_sid.into_iter().collect();
         Ok(app_uids_vec)
     }
+
+    /// Retrieve a database PRAGMA config value.
+    pub fn pragma<T: FromSql>(&mut self, name: &str) -> Result<T> {
+        self.conn
+            .query_row(&format!("PRAGMA persistent.{name}"), (), |row| row.get(0))
+            .context(format!("failed to read pragma {name}"))
+    }
 }
diff --git a/keystore2/src/database/tests.rs b/keystore2/src/database/tests.rs
index 4ada6942..fdcf2544 100644
--- a/keystore2/src/database/tests.rs
+++ b/keystore2/src/database/tests.rs
@@ -2090,6 +2090,108 @@ fn test_unbind_keys_for_user_removes_superkeys() -> Result<()> {
     Ok(())
 }
 
+#[test]
+fn test_unbind_keys_for_user_removes_received_grants() -> Result<()> {
+    let mut db = new_test_db()?;
+    const USER_ID_1: u32 = 1;
+    const USER_ID_2: u32 = 2;
+    const APPLICATION_ID_1: u32 = 11;
+    const APPLICATION_ID_2: u32 = 22;
+    const UID_1_FOR_USER_ID_1: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID_1;
+    const UID_2_FOR_USER_ID_1: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID_2;
+    const UID_1_FOR_USER_ID_2: u32 = USER_ID_2 * AID_USER_OFFSET + APPLICATION_ID_1;
+
+    // Pretend two application IDs for user ID 1 were granted access to 1 key each and one
+    // application ID for user ID 2 was granted access to 1 key.
+    db.conn.execute(
+        &format!(
+            "INSERT INTO persistent.grant (id, grantee, keyentryid, access_vector)
+                    VALUES (1, {UID_1_FOR_USER_ID_1}, 111, 222),
+                           (2, {UID_1_FOR_USER_ID_2}, 333, 444),
+                           (3, {UID_2_FOR_USER_ID_1}, 555, 666);"
+        ),
+        [],
+    )?;
+    db.unbind_keys_for_user(USER_ID_1)?;
+
+    let mut stmt = db.conn.prepare("SELECT id, grantee FROM persistent.grant")?;
+    let mut rows = stmt.query_map::<(i64, u32), _, _>([], |row| Ok((row.get(0)?, row.get(1)?)))?;
+
+    // The rows for the user ID 1 grantees (UID_1_FOR_USER_ID_1 and UID_2_FOR_USER_ID_1) should be
+    // deleted and the row for the user ID 2 grantee (UID_1_FOR_USER_ID_2) should be untouched.
+    let r = rows.next().unwrap().unwrap();
+    assert_eq!(r, (2, UID_1_FOR_USER_ID_2));
+    assert!(rows.next().is_none());
+
+    Ok(())
+}
+
+#[test]
+fn test_unbind_keys_for_namespace_removes_received_grants() -> Result<()> {
+    const USER_ID_1: u32 = 1;
+    const APPLICATION_ID_1: u32 = 11;
+    const APPLICATION_ID_2: u32 = 22;
+    const UID_1_FOR_USER_ID_1: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID_1;
+    const UID_2_FOR_USER_ID_1: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID_2;
+
+    // Check that grants are removed for Domain::APP.
+    {
+        let mut db = new_test_db()?;
+
+        // Pretend two application IDs for user ID 1 were granted access to 1 key each.
+        db.conn.execute(
+            &format!(
+                "INSERT INTO persistent.grant (id, grantee, keyentryid, access_vector)
+                VALUES (1, {UID_1_FOR_USER_ID_1}, 111, 222), (2, {UID_2_FOR_USER_ID_1}, 333, 444);"
+            ),
+            [],
+        )?;
+        // Keystore uses the UID as the namespace for Domain::APP keys.
+        db.unbind_keys_for_namespace(Domain::APP, UID_1_FOR_USER_ID_1.into())?;
+
+        let mut stmt = db.conn.prepare("SELECT id, grantee FROM persistent.grant")?;
+        let mut rows =
+            stmt.query_map::<(i64, u32), _, _>([], |row| Ok((row.get(0)?, row.get(1)?)))?;
+
+        // The row for the grant to the namespace that was cleared (UID_1_FOR_USER_ID_1) should be
+        // deleted. The other row should be untouched.
+        let r = rows.next().unwrap().unwrap();
+        assert_eq!(r, (2, UID_2_FOR_USER_ID_1));
+        assert!(rows.next().is_none());
+    }
+
+    // Check that grants aren't removed for Domain::SELINUX.
+    {
+        let mut db = new_test_db()?;
+
+        // Pretend two application IDs for user ID 1 were granted access to 1 key each.
+        db.conn.execute(
+            &format!(
+                "INSERT INTO persistent.grant (id, grantee, keyentryid, access_vector)
+                VALUES (1, {UID_1_FOR_USER_ID_1}, 111, 222), (2, {UID_2_FOR_USER_ID_1}, 333, 444);"
+            ),
+            [],
+        )?;
+        // Keystore uses the UID as the namespace for Domain::APP keys. Here we're passing in
+        // Domain::SELINUX, but still pass the UID as the "namespace" argument to make sure the
+        // code's logic is correct.
+        db.unbind_keys_for_namespace(Domain::SELINUX, UID_1_FOR_USER_ID_1.into())?;
+
+        let mut stmt = db.conn.prepare("SELECT id, grantee FROM persistent.grant")?;
+        let mut rows =
+            stmt.query_map::<(i64, u32), _, _>([], |row| Ok((row.get(0)?, row.get(1)?)))?;
+
+        // Both rows should still be present.
+        let r = rows.next().unwrap().unwrap();
+        assert_eq!(r, (1, UID_1_FOR_USER_ID_1));
+        let r = rows.next().unwrap().unwrap();
+        assert_eq!(r, (2, UID_2_FOR_USER_ID_1));
+        assert!(rows.next().is_none());
+    }
+
+    Ok(())
+}
+
 fn app_key_exists(db: &mut KeystoreDB, nspace: i64, alias: &str) -> Result<bool> {
     db.key_exists(Domain::APP, nspace, alias, KeyType::Client)
 }
diff --git a/keystore2/src/fuzzers/keystore2_unsafe_fuzzer.rs b/keystore2/src/fuzzers/keystore2_unsafe_fuzzer.rs
index fb4c9ad7..62167fb8 100644
--- a/keystore2/src/fuzzers/keystore2_unsafe_fuzzer.rs
+++ b/keystore2/src/fuzzers/keystore2_unsafe_fuzzer.rs
@@ -26,7 +26,7 @@ use keystore2_crypto::{
     hmac_sha256, parse_subject_from_certificate, Password, ZVec,
 };
 use keystore2_hal_names::get_hidl_instances;
-use keystore2_selinux::{check_access, getpidcon, setcon, Backend, Context, KeystoreKeyBackend};
+use keystore2_selinux::{check_access, setcon, Backend, Context, KeystoreKeyBackend};
 use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
 use std::{ffi::CString, sync::Arc};
 
@@ -108,9 +108,6 @@ enum FuzzCommand<'a> {
     Backend {
         namespace: &'a str,
     },
-    GetPidCon {
-        pid: i32,
-    },
     CheckAccess {
         source: &'a [u8],
         target: &'a [u8],
@@ -216,9 +213,6 @@ fuzz_target!(|commands: Vec<FuzzCommand>| {
                     let _res = backend.lookup(namespace);
                 }
             }
-            FuzzCommand::GetPidCon { pid } => {
-                let _res = getpidcon(pid);
-            }
             FuzzCommand::CheckAccess { source, target, tclass, perm } => {
                 let source = get_valid_cstring_data(source);
                 let target = get_valid_cstring_data(target);
diff --git a/keystore2/src/gc.rs b/keystore2/src/gc.rs
index f2341e3c..97416718 100644
--- a/keystore2/src/gc.rs
+++ b/keystore2/src/gc.rs
@@ -22,6 +22,7 @@ use crate::ks_err;
 use crate::{
     async_task,
     database::{KeystoreDB, SupersededBlob, Uuid},
+    globals,
     super_key::SuperKeyManager,
 };
 use anyhow::{Context, Result};
@@ -135,6 +136,17 @@ impl GcInternal {
     /// Processes one key and then schedules another attempt until it runs out of blobs to delete.
     fn step(&mut self) {
         self.notified.store(0, Ordering::Relaxed);
+        if !globals::boot_completed() {
+            // Garbage collection involves a operation (`IKeyMintDevice::deleteKey()`) that cannot
+            // be rolled back in some cases (specifically, when the key is rollback-resistant), even
+            // if the Keystore database is restored to the version of an earlier userdata filesystem
+            // checkpoint.
+            //
+            // This means that we should not perform GC until boot has fully completed, and any
+            // in-progress OTA is definitely not going to be rolled back.
+            log::info!("skip GC as boot not completed");
+            return;
+        }
         if let Err(e) = self.process_one_key() {
             log::error!("Error trying to delete blob entry. {:?}", e);
         }
diff --git a/keystore2/src/globals.rs b/keystore2/src/globals.rs
index 3b9c631b..9ee2a1e6 100644
--- a/keystore2/src/globals.rs
+++ b/keystore2/src/globals.rs
@@ -46,7 +46,11 @@ use android_security_compat::aidl::android::security::compat::IKeystoreCompatSer
 use anyhow::{Context, Result};
 use binder::FromIBinder;
 use binder::{get_declared_instances, is_declared};
-use std::sync::{Arc, LazyLock, Mutex, RwLock};
+use rustutils::system_properties::PropertyWatcher;
+use std::sync::{
+    atomic::{AtomicBool, Ordering},
+    Arc, LazyLock, Mutex, RwLock,
+};
 use std::{cell::RefCell, sync::Once};
 use std::{collections::HashMap, path::Path, path::PathBuf};
 
@@ -449,3 +453,40 @@ pub fn get_remotely_provisioned_component_name(security_level: &SecurityLevel) -
     .ok_or(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
     .context(ks_err!("Failed to get rpc for sec level {:?}", *security_level))
 }
+
+/// Whether boot is complete.
+static BOOT_COMPLETED: AtomicBool = AtomicBool::new(false);
+
+/// Indicate whether boot is complete.
+///
+/// This in turn indicates whether it is safe to make permanent changes to state.
+pub fn boot_completed() -> bool {
+    BOOT_COMPLETED.load(Ordering::Acquire)
+}
+
+/// Monitor the system property for boot complete.  This blocks and so needs to be run in a separate
+/// thread.
+pub fn await_boot_completed() {
+    // Use a fairly long watchdog timeout of 5 minutes here. This blocks until the device
+    // boots, which on a very slow device (e.g., emulator for a non-native architecture) can
+    // take minutes. Blocking here would be unexpected only if it never finishes.
+    let _wp = wd::watch_millis("await_boot_completed", 300_000);
+    log::info!("monitoring for sys.boot_completed=1");
+    while let Err(e) = watch_for_boot_completed() {
+        log::error!("failed to watch for boot_completed: {e:?}");
+        std::thread::sleep(std::time::Duration::from_secs(5));
+    }
+
+    BOOT_COMPLETED.store(true, Ordering::Release);
+    log::info!("wait_for_boot_completed done, triggering GC");
+
+    // Garbage collection may have been skipped until now, so trigger a check.
+    GC.notify_gc();
+}
+
+fn watch_for_boot_completed() -> Result<()> {
+    let mut w = PropertyWatcher::new("sys.boot_completed")
+        .context(ks_err!("PropertyWatcher::new failed"))?;
+    w.wait_for_value("1", None).context(ks_err!("Failed to wait for sys.boot_completed"))?;
+    Ok(())
+}
diff --git a/keystore2/src/keystore2_main.rs b/keystore2/src/keystore2_main.rs
index 178b36c7..e08a5f28 100644
--- a/keystore2/src/keystore2_main.rs
+++ b/keystore2/src/keystore2_main.rs
@@ -76,6 +76,11 @@ fn main() {
     // Write/update keystore.crash_count system property.
     metrics_store::update_keystore_crash_sysprop();
 
+    // Send KeyMint module information for attestations.
+    // Note that the information should be sent before code from modules starts running.
+    // (This is guaranteed by waiting for `keystore.module_hash.sent` == true during device boot.)
+    Maintenance::check_send_module_info();
+
     // Keystore 2.0 cannot change to the database directory (typically /data/misc/keystore) on
     // startup as Keystore 1.0 did because Keystore 2.0 is intended to run much earlier than
     // Keystore 1.0. Instead we set a global variable to the database path.
@@ -93,6 +98,7 @@ fn main() {
 
     ENFORCEMENTS.install_confirmation_token_receiver(confirmation_token_receiver);
 
+    std::thread::spawn(keystore2::globals::await_boot_completed);
     entropy::register_feeder();
     shared_secret_negotiation::perform_shared_secret_negotiation();
 
diff --git a/keystore2/src/maintenance.rs b/keystore2/src/maintenance.rs
index 1a5045ec..a0f5ee8a 100644
--- a/keystore2/src/maintenance.rs
+++ b/keystore2/src/maintenance.rs
@@ -19,7 +19,7 @@ use crate::error::into_logged_binder;
 use crate::error::map_km_error;
 use crate::error::Error;
 use crate::globals::get_keymint_device;
-use crate::globals::{DB, LEGACY_IMPORTER, SUPER_KEY, ENCODED_MODULE_INFO};
+use crate::globals::{DB, ENCODED_MODULE_INFO, LEGACY_IMPORTER, SUPER_KEY};
 use crate::ks_err;
 use crate::permission::{KeyPerm, KeystorePerm};
 use crate::super_key::SuperKeyManager;
@@ -30,6 +30,9 @@ use crate::utils::{
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
 };
+use apex_aidl_interface::aidl::android::apex::{
+    IApexService::IApexService,
+};
 use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::{
     BnKeystoreMaintenance, IKeystoreMaintenance,
 };
@@ -42,22 +45,27 @@ use android_security_metrics::aidl::android::security::metrics::{
 use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
 use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
 use anyhow::{anyhow, Context, Result};
+use binder::wait_for_interface;
 use bssl_crypto::digest;
 use der::{DerOrd, Encode, asn1::OctetString, asn1::SetOfVec, Sequence};
 use keystore2_crypto::Password;
+use rustutils::system_properties::PropertyWatcher;
 use std::cmp::Ordering;
 
 /// Reexport Domain for the benefit of DeleteListener
 pub use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;
 
+#[cfg(test)]
+mod tests;
+
 /// Version number of KeyMint V4.
 pub const KEYMINT_V4: i32 = 400;
 
 /// Module information structure for DER-encoding.
-#[derive(Sequence, Debug)]
+#[derive(Sequence, Debug, PartialEq, Eq)]
 struct ModuleInfo {
     name: OctetString,
-    version: i32,
+    version: i64,
 }
 
 impl DerOrd for ModuleInfo {
@@ -213,7 +221,8 @@ impl Maintenance {
                         && e.downcast_ref::<Error>()
                             == Some(&Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                     {
-                        log::info!("Call to {} failed for StrongBox as it is not available", name,)
+                        log::info!("Call to {} failed for StrongBox as it is not available", name);
+                        return Ok(());
                     } else {
                         log::error!(
                             "Call to {} failed for security level {}: {}.",
@@ -238,10 +247,108 @@ impl Maintenance {
         {
             log::error!("SUPER_KEY.set_up_boot_level_cache failed:\n{:?}\n:(", e);
         }
-
         Maintenance::call_on_all_security_levels("earlyBootEnded", |dev| dev.earlyBootEnded(), None)
     }
 
+    /// Spawns a thread to send module info if it hasn't already been sent. The thread first waits
+    /// for the apex info to be available.
+    /// (Module info would have already been sent in the case of a Keystore restart.)
+    ///
+    /// # Panics
+    ///
+    /// This method, and methods it calls, panic on failure, because a failure to populate module
+    /// information will block the boot process from completing. In this method, this happens if:
+    /// - the `apexd.status` property is unable to be monitored
+    /// - the `keystore.module_hash.sent` property cannot be updated
+    pub fn check_send_module_info() {
+        if rustutils::system_properties::read_bool("keystore.module_hash.sent", false)
+            .unwrap_or(false)
+        {
+            log::info!("Module info has already been sent.");
+            return;
+        }
+        if keystore2_flags::attest_modules() {
+            std::thread::spawn(move || {
+                // Wait for apex info to be available before populating.
+                Self::watch_apex_info().unwrap_or_else(|e| {
+                    log::error!("failed to monitor apexd.status property: {e:?}");
+                    panic!("Terminating due to inaccessibility of apexd.status property, blocking boot: {e:?}");
+                });
+            });
+        } else {
+            rustutils::system_properties::write("keystore.module_hash.sent", "true")
+                .unwrap_or_else(|e| {
+                        log::error!("Failed to set keystore.module_hash.sent to true; this will therefore block boot: {e:?}");
+                        panic!("Crashing Keystore because it failed to set keystore.module_hash.sent to true (which blocks boot).");
+                    }
+                );
+        }
+    }
+
+    /// Watch the `apexd.status` system property, and read apex module information once
+    /// it is `activated`.
+    ///
+    /// Blocks waiting for system property changes, so must be run in its own thread.
+    fn watch_apex_info() -> Result<()> {
+        let apex_prop = "apexd.status";
+        log::info!("start monitoring '{apex_prop}' property");
+        let mut w =
+            PropertyWatcher::new(apex_prop).context(ks_err!("PropertyWatcher::new failed"))?;
+        loop {
+            let value = w.read(|_name, value| Ok(value.to_string()));
+            log::info!("property '{apex_prop}' is now '{value:?}'");
+            if matches!(value.as_deref(), Ok("activated")) {
+                Self::read_and_set_module_info();
+                return Ok(());
+            }
+            log::info!("await a change to '{apex_prop}'...");
+            w.wait(None).context(ks_err!("property wait failed"))?;
+            log::info!("await a change to '{apex_prop}'...notified");
+        }
+    }
+
+    /// Read apex information (which is assumed to be present) and propagate module
+    /// information to KeyMint instances.
+    ///
+    /// # Panics
+    ///
+    /// This method panics on failure, because a failure to populate module information
+    /// will block the boot process from completing.  This happens if:
+    /// - apex information is not available (precondition)
+    /// - KeyMint instances fail to accept module information
+    /// - the `keystore.module_hash.sent` property cannot be updated
+    fn read_and_set_module_info() {
+        let modules = Self::read_apex_info().unwrap_or_else(|e| {
+            log::error!("failed to read apex info: {e:?}");
+            panic!("Terminating due to unavailability of apex info, blocking boot: {e:?}");
+        });
+        Self::set_module_info(modules).unwrap_or_else(|e| {
+            log::error!("failed to set module info: {e:?}");
+            panic!("Terminating due to KeyMint not accepting module info, blocking boot: {e:?}");
+        });
+        rustutils::system_properties::write("keystore.module_hash.sent", "true").unwrap_or_else(|e| {
+            log::error!("failed to set keystore.module_hash.sent property: {e:?}");
+            panic!("Terminating due to failure to set keystore.module_hash.sent property, blocking boot: {e:?}");
+        });
+    }
+
+    fn read_apex_info() -> Result<Vec<ModuleInfo>> {
+        let _wp = wd::watch("read_apex_info via IApexService.getActivePackages()");
+        let apexd: Strong<dyn IApexService> =
+            wait_for_interface("apexservice").context("failed to AIDL connect to apexd")?;
+        let packages = apexd.getActivePackages().context("failed to retrieve active packages")?;
+        packages
+            .into_iter()
+            .map(|pkg| {
+                log::info!("apex modules += {} version {}", pkg.moduleName, pkg.versionCode);
+                let name = OctetString::new(pkg.moduleName.as_bytes()).map_err(|e| {
+                    anyhow!("failed to convert '{}' to OCTET_STRING: {e:?}", pkg.moduleName)
+                })?;
+                Ok(ModuleInfo { name, version: pkg.versionCode })
+            })
+            .collect()
+    }
+
     fn migrate_key_namespace(source: &KeyDescriptor, destination: &KeyDescriptor) -> Result<()> {
         let calling_uid = ThreadState::get_calling_uid();
 
@@ -314,7 +421,10 @@ impl Maintenance {
         writeln!(f, "keystore2 running")?;
         writeln!(f)?;
 
-        // Display underlying device information
+        // Display underlying device information.
+        //
+        // Note that this chunk of output is parsed in a GTS test, so do not change the format
+        // without checking that the test still works.
         for sec_level in &[SecurityLevel::TRUSTED_ENVIRONMENT, SecurityLevel::STRONGBOX] {
             let Ok((_dev, hw_info, uuid)) = get_keymint_device(sec_level) else { continue };
 
@@ -326,6 +436,19 @@ impl Maintenance {
         }
         writeln!(f)?;
 
+        // Display module attestation information
+        {
+            let info = ENCODED_MODULE_INFO.read().unwrap();
+            if let Some(info) = info.as_ref() {
+                writeln!(f, "Attested module information (DER-encoded):")?;
+                writeln!(f, "  {}", hex::encode(info))?;
+                writeln!(f)?;
+            } else {
+                writeln!(f, "Attested module information not set")?;
+                writeln!(f)?;
+            }
+        }
+
         // Display database size information.
         match crate::metrics_store::pull_storage_stats() {
             Ok(atoms) => {
@@ -351,6 +474,34 @@ impl Maintenance {
         }
         writeln!(f)?;
 
+        // Display database config information.
+        writeln!(f, "Database configuration:")?;
+        DB.with(|db| -> std::io::Result<()> {
+            let pragma_str = |f: &mut dyn std::io::Write, name| -> std::io::Result<()> {
+                let mut db = db.borrow_mut();
+                let value: String = db
+                    .pragma(name)
+                    .unwrap_or_else(|e| format!("unknown value for '{name}', failed: {e:?}"));
+                writeln!(f, "  {name} = {value}")
+            };
+            let pragma_i32 = |f: &mut dyn std::io::Write, name| -> std::io::Result<()> {
+                let mut db = db.borrow_mut();
+                let value: i32 = db.pragma(name).unwrap_or_else(|e| {
+                    log::error!("unknown value for '{name}', failed: {e:?}");
+                    -1
+                });
+                writeln!(f, "  {name} = {value}")
+            };
+            pragma_i32(f, "auto_vacuum")?;
+            pragma_str(f, "journal_mode")?;
+            pragma_i32(f, "journal_size_limit")?;
+            pragma_i32(f, "synchronous")?;
+            pragma_i32(f, "schema_version")?;
+            pragma_i32(f, "user_version")?;
+            Ok(())
+        })?;
+        writeln!(f)?;
+
         // Display accumulated metrics.
         writeln!(f, "Metrics information:")?;
         writeln!(f)?;
@@ -363,8 +514,8 @@ impl Maintenance {
         Ok(())
     }
 
-    #[allow(dead_code)]
     fn set_module_info(module_info: Vec<ModuleInfo>) -> Result<()> {
+        log::info!("set_module_info with {} modules", module_info.len());
         let encoding = Self::encode_module_info(module_info)
             .map_err(|e| anyhow!({ e }))
             .context(ks_err!("Failed to encode module_info"))?;
@@ -396,7 +547,6 @@ impl Maintenance {
         )
     }
 
-    #[allow(dead_code)]
     fn encode_module_info(module_info: Vec<ModuleInfo>) -> Result<Vec<u8>, der::Error> {
         SetOfVec::<ModuleInfo>::from_iter(module_info.into_iter())?.to_der()
     }
@@ -408,10 +558,6 @@ impl Interface for Maintenance {
         f: &mut dyn std::io::Write,
         _args: &[&std::ffi::CStr],
     ) -> Result<(), binder::StatusCode> {
-        if !keystore2_flags::enable_dump() {
-            log::info!("skipping dump() as flag not enabled");
-            return Ok(());
-        }
         log::info!("dump()");
         let _wp = wd::watch("IKeystoreMaintenance::dump");
         check_dump_permission().map_err(|_e| {
diff --git a/keystore2/src/maintenance/tests.rs b/keystore2/src/maintenance/tests.rs
new file mode 100644
index 00000000..fbafa734
--- /dev/null
+++ b/keystore2/src/maintenance/tests.rs
@@ -0,0 +1,182 @@
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
+//! Maintenance tests.
+use super::*;
+use der::ErrorKind;
+
+#[test]
+fn test_encode_module_info_empty() {
+    let expected = vec![0x31, 0x00];
+    assert_eq!(expected, Maintenance::encode_module_info(Vec::new()).unwrap());
+}
+
+#[test]
+fn test_encode_module_info_same_name() {
+    // Same versions
+    let module_info: Vec<ModuleInfo> = vec![
+        ModuleInfo {
+            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
+            version: 25,
+        },
+        ModuleInfo {
+            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
+            version: 25,
+        },
+    ];
+    let actual = Maintenance::encode_module_info(module_info);
+    assert!(actual.is_err());
+    assert_eq!(ErrorKind::SetDuplicate, actual.unwrap_err().kind());
+
+    // Different versions
+    let module_info: Vec<ModuleInfo> = vec![
+        ModuleInfo {
+            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
+            version: 3,
+        },
+        ModuleInfo {
+            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
+            version: 789,
+        },
+    ];
+    let actual = Maintenance::encode_module_info(module_info);
+    assert!(actual.is_err());
+    assert_eq!(ErrorKind::SetDuplicate, actual.unwrap_err().kind());
+}
+
+#[test]
+fn test_encode_module_info_same_name_length() {
+    let module_info: Vec<ModuleInfo> = vec![
+        ModuleInfo { name: OctetString::new("com.android.wifi".to_string()).unwrap(), version: 2 },
+        ModuleInfo { name: OctetString::new("com.android.virt".to_string()).unwrap(), version: 1 },
+    ];
+    let actual = Maintenance::encode_module_info(module_info).unwrap();
+    let expected = hex::decode(concat!(
+        "312e",                             // SET OF, len 46
+        "3015",                             // SEQUENCE, len 21
+        "0410",                             // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e76697274", // "com.android.virt"
+        "020101",                           // INTEGER len 1 value 1
+        "3015",                             // SEQUENCE, len 21
+        "0410",                             // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e77696669", // "com.android.wifi"
+        "020102",                           // INTEGER len 1 value 2
+    ))
+    .unwrap();
+    assert_eq!(expected, actual);
+}
+
+#[test]
+fn test_encode_module_info_version_irrelevant() {
+    // Versions of the modules are irrelevant for determining encoding order since differing names
+    // guarantee a unique ascending order. See Maintenance::ModuleInfo::der_cmp for more detail.
+    let module_info: Vec<ModuleInfo> = vec![
+        ModuleInfo {
+            name: OctetString::new("com.android.extservices".to_string()).unwrap(),
+            version: 1,
+        },
+        ModuleInfo { name: OctetString::new("com.android.adbd".to_string()).unwrap(), version: 14 },
+    ];
+    let actual = Maintenance::encode_module_info(module_info).unwrap();
+    let expected = hex::decode(concat!(
+        "3135",                                           // SET OF, len 53
+        "3015",                                           // SEQUENCE, len 21
+        "0410",                                           // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e61646264",               // "com.android.abdb"
+        "02010e",                                         // INTEGER len 2 value 14
+        "301c",                                           // SEQUENCE, len 28
+        "0417",                                           // OCTET STRING, len 23
+        "636f6d2e616e64726f69642e6578747365727669636573", // "com.android.extservices"
+        "020101",                                         // INTEGER len 1 value 1
+    ))
+    .unwrap();
+    assert_eq!(expected, actual);
+}
+
+#[test]
+fn test_encode_module_info_alphaordering_irrelevant() {
+    // Character ordering of the names of modules is irrelevant for determining encoding order since
+    // differing name lengths guarantee a unique ascending order. See
+    // Maintenance::ModuleInfo::der_cmp for more detail.
+    let module_info: Vec<ModuleInfo> = vec![
+        ModuleInfo {
+            name: OctetString::new("com.android.crashrecovery".to_string()).unwrap(),
+            version: 3,
+        },
+        ModuleInfo { name: OctetString::new("com.android.rkpd".to_string()).unwrap(), version: 8 },
+    ];
+    let actual = Maintenance::encode_module_info(module_info).unwrap();
+    let expected = hex::decode(concat!(
+        "3137",                                               // SET OF, len 55
+        "3015",                                               // SEQUENCE, len 21
+        "0410",                                               // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e726b7064",                   // "com.android.rkpd"
+        "020108",                                             // INTEGER len 1 value 8
+        "301e",                                               // SEQUENCE, len 30
+        "0419",                                               // OCTET STRING, len 25
+        "636f6d2e616e64726f69642e63726173687265636f76657279", // "com.android.crashrecovery"
+        "020103",                                             // INTEGER len 1 value 3
+    ))
+    .unwrap();
+    assert_eq!(expected, actual);
+}
+
+#[test]
+fn test_encode_module_info() {
+    // Collection of `ModuleInfo`s from a few of the other test_encode_module_info_* tests
+    let module_info: Vec<ModuleInfo> = vec![
+        ModuleInfo { name: OctetString::new("com.android.rkpd".to_string()).unwrap(), version: 8 },
+        ModuleInfo {
+            name: OctetString::new("com.android.extservices".to_string()).unwrap(),
+            version: 1,
+        },
+        ModuleInfo {
+            name: OctetString::new("com.android.crashrecovery".to_string()).unwrap(),
+            version: 3,
+        },
+        ModuleInfo { name: OctetString::new("com.android.wifi".to_string()).unwrap(), version: 2 },
+        ModuleInfo { name: OctetString::new("com.android.virt".to_string()).unwrap(), version: 1 },
+        ModuleInfo { name: OctetString::new("com.android.adbd".to_string()).unwrap(), version: 14 },
+    ];
+    let actual = Maintenance::encode_module_info(module_info).unwrap();
+    let expected = hex::decode(concat!(
+        "31819a",                                             // SET OF, len 154
+        "3015",                                               // SEQUENCE, len 21
+        "0410",                                               // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e61646264",                   // "com.android.abdb"
+        "02010e",                                             // INTEGER len 2 value 14
+        "3015",                                               // SEQUENCE, len 21
+        "0410",                                               // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e726b7064",                   // "com.android.rkpd"
+        "020108",                                             // INTEGER len 1 value 8
+        "3015",                                               // SEQUENCE, len 21
+        "0410",                                               // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e76697274",                   // "com.android.virt"
+        "020101",                                             // INTEGER len 1 value 1
+        "3015",                                               // SEQUENCE, len 21
+        "0410",                                               // OCTET STRING, len 16
+        "636f6d2e616e64726f69642e77696669",                   // "com.android.wifi"
+        "020102",                                             // INTEGER len 1 value 2
+        "301c",                                               // SEQUENCE, len 28
+        "0417",                                               // OCTET STRING, len 23
+        "636f6d2e616e64726f69642e6578747365727669636573",     // "com.android.extservices"
+        "020101",                                             // INTEGER len 1 value 1
+        "301e",                                               // SEQUENCE, len 30
+        "0419",                                               // OCTET STRING, len 25
+        "636f6d2e616e64726f69642e63726173687265636f76657279", // "com.android.crashrecovery"
+        "020103",                                             // INTEGER len 1 value 3
+    ))
+    .unwrap();
+    assert_eq!(expected, actual);
+}
diff --git a/keystore2/src/metrics_store.rs b/keystore2/src/metrics_store.rs
index fd1f9b54..30c5973e 100644
--- a/keystore2/src/metrics_store.rs
+++ b/keystore2/src/metrics_store.rs
@@ -48,6 +48,9 @@ use anyhow::{anyhow, Context, Result};
 use std::collections::HashMap;
 use std::sync::{LazyLock, Mutex};
 
+#[cfg(test)]
+mod tests;
+
 // Note: Crash events are recorded at keystore restarts, based on the assumption that keystore only
 // gets restarted after a crash, during a boot cycle.
 const KEYSTORE_CRASH_COUNT_PROPERTY: &str = "keystore.crash_count";
@@ -205,7 +208,7 @@ fn process_key_creation_event_stats<U>(
     };
 
     let mut key_creation_with_auth_info = KeyCreationWithAuthInfo {
-        user_auth_type: MetricsHardwareAuthenticatorType::AUTH_TYPE_UNSPECIFIED,
+        user_auth_type: MetricsHardwareAuthenticatorType::NO_AUTH_TYPE,
         log10_auth_key_timeout_seconds: -1,
         security_level: MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
     };
@@ -258,6 +261,12 @@ fn process_key_creation_event_stats<U>(
                     HardwareAuthenticatorType::FINGERPRINT => {
                         MetricsHardwareAuthenticatorType::FINGERPRINT
                     }
+                    a if a.0
+                        == HardwareAuthenticatorType::PASSWORD.0
+                            | HardwareAuthenticatorType::FINGERPRINT.0 =>
+                    {
+                        MetricsHardwareAuthenticatorType::PASSWORD_OR_FINGERPRINT
+                    }
                     HardwareAuthenticatorType::ANY => MetricsHardwareAuthenticatorType::ANY,
                     _ => MetricsHardwareAuthenticatorType::AUTH_TYPE_UNSPECIFIED,
                 }
@@ -792,14 +801,14 @@ impl_summary_enum!(MetricsSecurityLevel, 9,
     SECURITY_LEVEL_KEYSTORE => "KEYSTORE",
 );
 
-// Metrics values for HardwareAuthenticatorType are broken -- the AIDL type is a bitmask
-// not an enum, so offseting the enum values by 1 doesn't work.
-impl_summary_enum!(MetricsHardwareAuthenticatorType, 6,
+impl_summary_enum!(MetricsHardwareAuthenticatorType, 8,
     AUTH_TYPE_UNSPECIFIED => "UNSPEC",
     NONE => "NONE",
     PASSWORD => "PASSWD",
     FINGERPRINT => "FPRINT",
+    PASSWORD_OR_FINGERPRINT => "PW_OR_FP",
     ANY => "ANY",
+    NO_AUTH_TYPE => "NOAUTH",
 );
 
 impl_summary_enum!(MetricsPurpose, 7,
@@ -974,31 +983,3 @@ impl Summary for KeystoreAtomPayload {
         }
     }
 }
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test_enum_show() {
-        let algo = MetricsAlgorithm::RSA;
-        assert_eq!("RSA ", algo.show());
-        let algo = MetricsAlgorithm(42);
-        assert_eq!("Unknown(42)", algo.show());
-    }
-
-    #[test]
-    fn test_enum_bitmask_show() {
-        let mut modes = 0i32;
-        compute_block_mode_bitmap(&mut modes, BlockMode::ECB);
-        compute_block_mode_bitmap(&mut modes, BlockMode::CTR);
-
-        assert_eq!(show_blockmode(modes), "-T-E");
-
-        // Add some bits not covered by the enum of valid bit positions.
-        modes |= 0xa0;
-        assert_eq!(show_blockmode(modes), "-T-E(full:0x000000aa)");
-        modes |= 0x300;
-        assert_eq!(show_blockmode(modes), "-T-E(full:0x000003aa)");
-    }
-}
diff --git a/keystore2/src/metrics_store/tests.rs b/keystore2/src/metrics_store/tests.rs
new file mode 100644
index 00000000..95d4a01d
--- /dev/null
+++ b/keystore2/src/metrics_store/tests.rs
@@ -0,0 +1,160 @@
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
+use crate::metrics_store::*;
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    HardwareAuthenticatorType::HardwareAuthenticatorType as AuthType, KeyParameter::KeyParameter,
+    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
+};
+use android_security_metrics::aidl::android::security::metrics::{
+    HardwareAuthenticatorType::HardwareAuthenticatorType as MetricsAuthType,
+    SecurityLevel::SecurityLevel as MetricsSecurityLevel,
+};
+
+#[test]
+fn test_enum_show() {
+    let algo = MetricsAlgorithm::RSA;
+    assert_eq!("RSA ", algo.show());
+    let algo = MetricsAlgorithm(42);
+    assert_eq!("Unknown(42)", algo.show());
+}
+
+#[test]
+fn test_enum_bitmask_show() {
+    let mut modes = 0i32;
+    compute_block_mode_bitmap(&mut modes, BlockMode::ECB);
+    compute_block_mode_bitmap(&mut modes, BlockMode::CTR);
+
+    assert_eq!(show_blockmode(modes), "-T-E");
+
+    // Add some bits not covered by the enum of valid bit positions.
+    modes |= 0xa0;
+    assert_eq!(show_blockmode(modes), "-T-E(full:0x000000aa)");
+    modes |= 0x300;
+    assert_eq!(show_blockmode(modes), "-T-E(full:0x000003aa)");
+}
+
+fn create_key_param_with_auth_type(auth_type: AuthType) -> KeyParameter {
+    KeyParameter {
+        tag: Tag::USER_AUTH_TYPE,
+        value: KeyParameterValue::HardwareAuthenticatorType(auth_type),
+    }
+}
+
+#[test]
+fn test_user_auth_type() {
+    let test_cases = [
+        (vec![], MetricsAuthType::NO_AUTH_TYPE),
+        (vec![AuthType::NONE], MetricsAuthType::NONE),
+        (vec![AuthType::PASSWORD], MetricsAuthType::PASSWORD),
+        (vec![AuthType::FINGERPRINT], MetricsAuthType::FINGERPRINT),
+        (
+            vec![AuthType(AuthType::PASSWORD.0 | AuthType::FINGERPRINT.0)],
+            MetricsAuthType::PASSWORD_OR_FINGERPRINT,
+        ),
+        (vec![AuthType::ANY], MetricsAuthType::ANY),
+        // 7 is the "next" undefined HardwareAuthenticatorType enum tag number, so
+        // force this test to fail and be updated if someone adds a new enum value.
+        (vec![AuthType(7)], MetricsAuthType::AUTH_TYPE_UNSPECIFIED),
+        (vec![AuthType(123)], MetricsAuthType::AUTH_TYPE_UNSPECIFIED),
+        (
+            // In practice, Tag::USER_AUTH_TYPE isn't a repeatable tag. It's allowed
+            // to appear once for auth-bound keys and contains the binary OR of the
+            // applicable auth types. However, this test case repeats the tag more
+            // than once in order to unit test the logic that constructs the atom.
+            vec![AuthType::ANY, AuthType(123), AuthType::PASSWORD],
+            // The last auth type wins.
+            MetricsAuthType::PASSWORD,
+        ),
+    ];
+    for (auth_types, expected) in test_cases {
+        let key_params: Vec<_> =
+            auth_types.iter().map(|a| create_key_param_with_auth_type(*a)).collect();
+        let (_, atom_with_auth_info, _) = process_key_creation_event_stats(
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+            &key_params,
+            &Ok(()),
+        );
+        assert!(matches!(
+            atom_with_auth_info,
+            KeystoreAtomPayload::KeyCreationWithAuthInfo(a) if a.user_auth_type == expected
+        ));
+    }
+}
+
+fn create_key_param_with_auth_timeout(timeout: i32) -> KeyParameter {
+    KeyParameter { tag: Tag::AUTH_TIMEOUT, value: KeyParameterValue::Integer(timeout) }
+}
+
+#[test]
+fn test_log_auth_timeout_seconds() {
+    let test_cases = [
+        (vec![], -1),
+        (vec![-1], 0),
+        // The metrics code computes the value of this field for a timeout `t` with
+        // `f32::log10(t as f32) as i32`. The result of f32::log10(0 as f32) is `-inf`.
+        // Casting this to i32 means it gets "rounded" to i32::MIN, which is -2147483648.
+        (vec![0], -2147483648),
+        (vec![1], 0),
+        (vec![9], 0),
+        (vec![10], 1),
+        (vec![999], 2),
+        (
+            // In practice, Tag::AUTH_TIMEOUT isn't a repeatable tag. It's allowed to
+            // appear once for auth-bound keys. However, this test case repeats the
+            // tag more than once in order to unit test the logic that constructs the
+            // atom.
+            vec![1, 0, 10],
+            // The last timeout wins.
+            1,
+        ),
+    ];
+    for (timeouts, expected) in test_cases {
+        let key_params: Vec<_> =
+            timeouts.iter().map(|t| create_key_param_with_auth_timeout(*t)).collect();
+        let (_, atom_with_auth_info, _) = process_key_creation_event_stats(
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+            &key_params,
+            &Ok(()),
+        );
+        assert!(matches!(
+            atom_with_auth_info,
+            KeystoreAtomPayload::KeyCreationWithAuthInfo(a)
+                if a.log10_auth_key_timeout_seconds == expected
+        ));
+    }
+}
+
+#[test]
+fn test_security_level() {
+    let test_cases = [
+        (SecurityLevel::SOFTWARE, MetricsSecurityLevel::SECURITY_LEVEL_SOFTWARE),
+        (
+            SecurityLevel::TRUSTED_ENVIRONMENT,
+            MetricsSecurityLevel::SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
+        ),
+        (SecurityLevel::STRONGBOX, MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX),
+        (SecurityLevel::KEYSTORE, MetricsSecurityLevel::SECURITY_LEVEL_KEYSTORE),
+        (SecurityLevel(123), MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED),
+    ];
+    for (security_level, expected) in test_cases {
+        let (_, atom_with_auth_info, _) =
+            process_key_creation_event_stats(security_level, &[], &Ok(()));
+        assert!(matches!(
+            atom_with_auth_info,
+            KeystoreAtomPayload::KeyCreationWithAuthInfo(a)
+                if a.security_level == expected
+        ));
+    }
+}
diff --git a/keystore2/src/operation.rs b/keystore2/src/operation.rs
index c11c1f43..0d5e88f3 100644
--- a/keystore2/src/operation.rs
+++ b/keystore2/src/operation.rs
@@ -237,6 +237,11 @@ impl Operation {
         }
     }
 
+    fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
+        let sec_level = self.logging_info.sec_level;
+        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, sec_level)
+    }
+
     fn get_pruning_info(&self) -> Option<PruningInfo> {
         // An operation may be finalized.
         if let Ok(guard) = self.outcome.try_lock() {
@@ -287,7 +292,7 @@ impl Operation {
         }
         *locked_outcome = Outcome::Pruned;
 
-        let _wp = wd::watch("Operation::prune: calling IKeyMintOperation::abort()");
+        let _wp = self.watch("Operation::prune: calling IKeyMintOperation::abort()");
 
         // We abort the operation. If there was an error we log it but ignore it.
         if let Err(e) = map_km_error(self.km_op.abort()) {
@@ -359,13 +364,13 @@ impl Operation {
             .lock()
             .unwrap()
             .before_update()
-            .context(ks_err!("Trying to get auth tokens."))?;
+            .context(ks_err!("Trying to get auth tokens for uid {}", self.owner))?;
 
         self.update_outcome(&mut outcome, {
-            let _wp = wd::watch("Operation::update_aad: calling IKeyMintOperation::updateAad");
+            let _wp = self.watch("Operation::update_aad: calling IKeyMintOperation::updateAad");
             map_km_error(self.km_op.updateAad(aad_input, hat.as_ref(), tst.as_ref()))
         })
-        .context(ks_err!("Update failed."))?;
+        .context(ks_err!("Update failed for uid {}", self.owner))?;
 
         Ok(())
     }
@@ -382,14 +387,14 @@ impl Operation {
             .lock()
             .unwrap()
             .before_update()
-            .context(ks_err!("Trying to get auth tokens."))?;
+            .context(ks_err!("Trying to get auth tokens for uid {}", self.owner))?;
 
         let output = self
             .update_outcome(&mut outcome, {
-                let _wp = wd::watch("Operation::update: calling IKeyMintOperation::update");
+                let _wp = self.watch("Operation::update: calling IKeyMintOperation::update");
                 map_km_error(self.km_op.update(input, hat.as_ref(), tst.as_ref()))
             })
-            .context(ks_err!("Update failed."))?;
+            .context(ks_err!("Update failed for uid {}", self.owner))?;
 
         if output.is_empty() {
             Ok(None)
@@ -412,11 +417,11 @@ impl Operation {
             .lock()
             .unwrap()
             .before_finish()
-            .context(ks_err!("Trying to get auth tokens."))?;
+            .context(ks_err!("Trying to get auth tokens for uid {}", self.owner))?;
 
         let output = self
             .update_outcome(&mut outcome, {
-                let _wp = wd::watch("Operation::finish: calling IKeyMintOperation::finish");
+                let _wp = self.watch("Operation::finish: calling IKeyMintOperation::finish");
                 map_km_error(self.km_op.finish(
                     input,
                     signature,
@@ -425,7 +430,7 @@ impl Operation {
                     confirmation_token.as_deref(),
                 ))
             })
-            .context(ks_err!("Finish failed."))?;
+            .context(ks_err!("Finish failed for uid {}", self.owner))?;
 
         self.auth_info.lock().unwrap().after_finish().context("In finish.")?;
 
@@ -447,7 +452,7 @@ impl Operation {
         *locked_outcome = outcome;
 
         {
-            let _wp = wd::watch("Operation::abort: calling IKeyMintOperation::abort");
+            let _wp = self.watch("Operation::abort: calling IKeyMintOperation::abort");
             map_km_error(self.km_op.abort()).context(ks_err!("KeyMint::abort failed."))
         }
     }
diff --git a/keystore2/src/remote_provisioning.rs b/keystore2/src/remote_provisioning.rs
index 2bdafd47..a1ce5f6a 100644
--- a/keystore2/src/remote_provisioning.rs
+++ b/keystore2/src/remote_provisioning.rs
@@ -129,6 +129,6 @@ fn get_rkpd_attestation_key(
     // by the calling function and allow for natural fallback to the factory key.
     let rpc_name = get_remotely_provisioned_component_name(security_level)
         .context(ks_err!("Trying to get IRPC name."))?;
-    let _wd = wd::watch("Calling get_rkpd_attestation_key()");
+    let _wd = wd::watch_millis("Calling get_rkpd_attestation_key()", 1000);
     rkpd_client::get_rkpd_attestation_key(&rpc_name, caller_uid)
 }
diff --git a/keystore2/src/super_key.rs b/keystore2/src/super_key.rs
index 42fd7645..3e657530 100644
--- a/keystore2/src/super_key.rs
+++ b/keystore2/src/super_key.rs
@@ -1218,7 +1218,7 @@ pub enum KeyBlob<'a> {
     Ref(&'a [u8]),
 }
 
-impl<'a> KeyBlob<'a> {
+impl KeyBlob<'_> {
     pub fn force_reencrypt(&self) -> bool {
         if let KeyBlob::Sensitive { force_reencrypt, .. } = self {
             *force_reencrypt
@@ -1229,7 +1229,7 @@ impl<'a> KeyBlob<'a> {
 }
 
 /// Deref returns a reference to the key material in any variant.
-impl<'a> Deref for KeyBlob<'a> {
+impl Deref for KeyBlob<'_> {
     type Target = [u8];
 
     fn deref(&self) -> &Self::Target {
diff --git a/keystore2/test_utils/attestation/Android.bp b/keystore2/test_utils/attestation/Android.bp
new file mode 100644
index 00000000..fb4dc7e7
--- /dev/null
+++ b/keystore2/test_utils/attestation/Android.bp
@@ -0,0 +1,56 @@
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
+    name: "libkeystore_attestation_defaults",
+    crate_name: "keystore_attestation",
+    srcs: ["lib.rs"],
+    defaults: [
+        "keymint_use_latest_hal_aidl_rust",
+    ],
+    rustlibs: [
+        "libbinder_rs",
+        "libder",
+        "liblog_rust",
+        "libspki",
+        "libx509_cert",
+    ],
+}
+
+rust_library {
+    name: "libkeystore_attestation",
+    defaults: ["libkeystore_attestation_defaults"],
+    vendor_available: true,
+    min_sdk_version: "35",
+}
+
+rust_test {
+    name: "libkeystore_attestation_test",
+    defaults: ["libkeystore_attestation_defaults"],
+    rustlibs: [
+        "libhex",
+    ],
+    test_suites: ["general-tests"],
+    auto_gen_config: true,
+    compile_multilib: "first",
+}
diff --git a/keystore2/test_utils/attestation/lib.rs b/keystore2/test_utils/attestation/lib.rs
new file mode 100644
index 00000000..31d3314d
--- /dev/null
+++ b/keystore2/test_utils/attestation/lib.rs
@@ -0,0 +1,693 @@
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
+//! Attestation parsing.
+
+use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
+    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
+    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
+    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue as KPV,
+    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, Tag::Tag, TagType::TagType,
+};
+use der::asn1::{Null, ObjectIdentifier, OctetStringRef, SetOfVec};
+use der::{oid::AssociatedOid, DerOrd, Enumerated, Reader, Sequence, SliceReader};
+use der::{Decode, EncodeValue, Length};
+use std::borrow::Cow;
+
+/// Determine the tag type for a tag, based on the top 4 bits of the tag number.
+fn tag_type(tag: Tag) -> TagType {
+    let raw_type = (tag.0 as u32) & 0xf0000000;
+    TagType(raw_type as i32)
+}
+
+/// Determine the raw tag value with tag type information stripped out.
+fn raw_tag_value(tag: Tag) -> u32 {
+    (tag.0 as u32) & 0x0fffffffu32
+}
+
+/// OID value for the Android Attestation extension.
+pub const ATTESTATION_EXTENSION_OID: ObjectIdentifier =
+    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
+
+/// Attestation extension contents
+#[derive(Debug, Clone, Sequence, PartialEq)]
+pub struct AttestationExtension<'a> {
+    /// Attestation version.
+    pub attestation_version: i32,
+    /// Security level that created the attestation.
+    pub attestation_security_level: SecurityLevel,
+    /// Keymint version.
+    pub keymint_version: i32,
+    /// Security level of the KeyMint instance holding the key.
+    pub keymint_security_level: SecurityLevel,
+    /// Attestation challenge.
+    #[asn1(type = "OCTET STRING")]
+    pub attestation_challenge: &'a [u8],
+    /// Unique ID.
+    #[asn1(type = "OCTET STRING")]
+    pub unique_id: &'a [u8],
+    /// Software-enforced key characteristics.
+    pub sw_enforced: AuthorizationList<'a>,
+    /// Hardware-enforced key characteristics.
+    pub hw_enforced: AuthorizationList<'a>,
+}
+
+impl AssociatedOid for AttestationExtension<'_> {
+    const OID: ObjectIdentifier = ATTESTATION_EXTENSION_OID;
+}
+
+/// Security level enumeration
+#[repr(u32)]
+#[derive(Debug, Clone, Copy, Enumerated, PartialEq)]
+pub enum SecurityLevel {
+    /// Software.
+    Software = 0,
+    /// TEE.
+    TrustedEnvironment = 1,
+    /// StrongBox.
+    Strongbox = 2,
+}
+
+/// Root of Trust ASN.1 structure
+#[derive(Debug, Clone, Sequence)]
+pub struct RootOfTrust<'a> {
+    /// Verified boot key hash.
+    #[asn1(type = "OCTET STRING")]
+    pub verified_boot_key: &'a [u8],
+    /// Device bootloader lock state.
+    pub device_locked: bool,
+    /// Verified boot state.
+    pub verified_boot_state: VerifiedBootState,
+    /// Verified boot hash
+    #[asn1(type = "OCTET STRING")]
+    pub verified_boot_hash: &'a [u8],
+}
+
+/// Attestation Application ID ASN.1 structure
+#[derive(Debug, Clone, Sequence)]
+pub struct AttestationApplicationId<'a> {
+    /// Package info.
+    pub package_info_records: SetOfVec<PackageInfoRecord<'a>>,
+    /// Signatures.
+    pub signature_digests: SetOfVec<OctetStringRef<'a>>,
+}
+
+/// Package record
+#[derive(Debug, Clone, Sequence)]
+pub struct PackageInfoRecord<'a> {
+    /// Package name
+    pub package_name: OctetStringRef<'a>,
+    /// Package version
+    pub version: i64,
+}
+
+impl DerOrd for PackageInfoRecord<'_> {
+    fn der_cmp(&self, other: &Self) -> Result<std::cmp::Ordering, der::Error> {
+        self.package_name.der_cmp(&other.package_name)
+    }
+}
+
+/// Verified Boot State as ASN.1 ENUMERATED type.
+#[repr(u32)]
+#[derive(Debug, Clone, Copy, Enumerated)]
+pub enum VerifiedBootState {
+    /// Verified.
+    Verified = 0,
+    /// Self-signed.
+    SelfSigned = 1,
+    /// Unverified.
+    Unverified = 2,
+    /// Failed.
+    Failed = 3,
+}
+
+/// Struct corresponding to an ASN.1 DER-serialized `AuthorizationList`.
+#[derive(Debug, Clone, PartialEq, Eq, Default)]
+pub struct AuthorizationList<'a> {
+    /// Key authorizations.
+    pub auths: Cow<'a, [KeyParameter]>,
+}
+
+impl From<Vec<KeyParameter>> for AuthorizationList<'_> {
+    /// Build an `AuthorizationList` using a set of key parameters.
+    fn from(auths: Vec<KeyParameter>) -> Self {
+        AuthorizationList { auths: auths.into() }
+    }
+}
+
+impl<'a> Sequence<'a> for AuthorizationList<'a> {}
+
+/// Stub (non-)implementation of DER-encoding, needed to implement [`Sequence`].
+impl EncodeValue for AuthorizationList<'_> {
+    fn value_len(&self) -> der::Result<Length> {
+        unimplemented!("Only decoding is implemented");
+    }
+    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
+        unimplemented!("Only decoding is implemented");
+    }
+}
+
+/// Implementation of [`der::DecodeValue`] which constructs an [`AuthorizationList`] from bytes.
+impl<'a> der::DecodeValue<'a> for AuthorizationList<'a> {
+    fn decode_value<R: der::Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
+        // Decode tags in the expected order.
+        let contents = decoder.read_slice(header.length)?;
+        let mut reader = SliceReader::new(contents)?;
+        let decoder = &mut reader;
+        let mut auths = Vec::new();
+        let mut next: Option<u32> = None;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::PURPOSE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ALGORITHM)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::KEY_SIZE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::BLOCK_MODE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::DIGEST)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::PADDING)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::CALLER_NONCE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::MIN_MAC_LENGTH)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::EC_CURVE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::RSA_PUBLIC_EXPONENT)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::RSA_OAEP_MGF_DIGEST)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ROLLBACK_RESISTANCE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::EARLY_BOOT_ONLY)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ACTIVE_DATETIME)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ORIGINATION_EXPIRE_DATETIME)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::USAGE_EXPIRE_DATETIME)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::USAGE_COUNT_LIMIT)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::USER_SECURE_ID)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::NO_AUTH_REQUIRED)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::USER_AUTH_TYPE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::AUTH_TIMEOUT)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ALLOW_WHILE_ON_BODY)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::TRUSTED_USER_PRESENCE_REQUIRED)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::TRUSTED_CONFIRMATION_REQUIRED)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::UNLOCKED_DEVICE_REQUIRED)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::CREATION_DATETIME)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::CREATION_DATETIME)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ORIGIN)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ROOT_OF_TRUST)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::OS_VERSION)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::OS_PATCHLEVEL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_APPLICATION_ID)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_BRAND)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_DEVICE)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_PRODUCT)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SERIAL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SERIAL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SERIAL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_IMEI)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_MEID)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_MANUFACTURER)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_MODEL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::VENDOR_PATCHLEVEL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::BOOT_PATCHLEVEL)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::DEVICE_UNIQUE_ATTESTATION)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SECOND_IMEI)?;
+        next = decode_opt_field(decoder, next, &mut auths, Tag::MODULE_HASH)?;
+
+        if next.is_some() {
+            // Extra tag encountered.
+            return Err(decoder.error(der::ErrorKind::Incomplete {
+                expected_len: Length::ZERO,
+                actual_len: decoder.remaining_len(),
+            }));
+        }
+
+        Ok(auths.into())
+    }
+}
+
+/// Attempt to decode an optional field associated with `expected_tag` from the `decoder`.
+///
+/// If `already_read_asn1_tag` is provided, then that ASN.1 tag has already been read from the
+/// `decoder` and its associated data is next.
+///
+/// (Because the field is optional, we might not read the tag we expect, but instead a later tag
+/// from the list.  If this happens, the actual decoded ASN.1 tag value is returned to the caller to
+/// be passed in on the next call to this function.)
+///
+/// If the decoded or re-used ASN.1 tag is the expected one, continue on to read the associated
+/// value and populate it in `auths`.
+fn decode_opt_field<'a, R: der::Reader<'a>>(
+    decoder: &mut R,
+    already_read_asn1_tag: Option<u32>,
+    auths: &mut Vec<KeyParameter>,
+    expected_tag: Tag,
+) -> Result<Option<u32>, der::Error> {
+    // Decode the ASN.1 tag if no tag is provided
+    let asn1_tag = match already_read_asn1_tag {
+        Some(tag) => Some(tag),
+        None => decode_explicit_tag_from_bytes(decoder)?,
+    };
+    let expected_asn1_tag = raw_tag_value(expected_tag);
+    match asn1_tag {
+        Some(v) if v == expected_asn1_tag => {
+            // Decode the length of the inner encoding
+            let inner_len = Length::decode(decoder)?;
+            if decoder.remaining_len() < inner_len {
+                return Err(der::ErrorKind::Incomplete {
+                    expected_len: inner_len,
+                    actual_len: decoder.remaining_len(),
+                }
+                .into());
+            }
+            let next_tlv = decoder.tlv_bytes()?;
+            decode_value_from_bytes(expected_tag, next_tlv, auths)?;
+            Ok(None)
+        }
+        Some(tag) => Ok(Some(tag)), // Return the tag for which the value is unread.
+        None => Ok(None),
+    }
+}
+
+/// Decode one or more `KeyParameterValue`s of the type associated with `tag` from the `decoder`,
+/// and add them to `auths`.
+fn decode_value_from_bytes(
+    tag: Tag,
+    data: &[u8],
+    auths: &mut Vec<KeyParameter>,
+) -> Result<(), der::Error> {
+    match tag_type(tag) {
+        TagType::ENUM_REP => {
+            let values = SetOfVec::<i32>::from_der(data)?;
+            for value in values.as_slice() {
+                auths.push(KeyParameter {
+                    tag,
+                    value: match tag {
+                        Tag::BLOCK_MODE => KPV::BlockMode(BlockMode(*value)),
+                        Tag::PADDING => KPV::PaddingMode(PaddingMode(*value)),
+                        Tag::DIGEST => KPV::Digest(Digest(*value)),
+                        Tag::RSA_OAEP_MGF_DIGEST => KPV::Digest(Digest(*value)),
+                        Tag::PURPOSE => KPV::KeyPurpose(KeyPurpose(*value)),
+                        _ => return Err(der::ErrorKind::TagNumberInvalid.into()),
+                    },
+                });
+            }
+        }
+        TagType::UINT_REP => {
+            let values = SetOfVec::<i32>::from_der(data)?;
+            for value in values.as_slice() {
+                auths.push(KeyParameter { tag, value: KPV::Integer(*value) });
+            }
+        }
+        TagType::ENUM => {
+            let value = i32::from_der(data)?;
+            auths.push(KeyParameter {
+                tag,
+                value: match tag {
+                    Tag::ALGORITHM => KPV::Algorithm(Algorithm(value)),
+                    Tag::EC_CURVE => KPV::EcCurve(EcCurve(value)),
+                    Tag::ORIGIN => KPV::Origin(KeyOrigin(value)),
+                    Tag::USER_AUTH_TYPE => {
+                        KPV::HardwareAuthenticatorType(HardwareAuthenticatorType(value))
+                    }
+                    _ => return Err(der::ErrorKind::TagNumberInvalid.into()),
+                },
+            });
+        }
+        TagType::UINT => {
+            let value = i32::from_der(data)?;
+            auths.push(KeyParameter { tag, value: KPV::Integer(value) });
+        }
+        TagType::ULONG => {
+            let value = i64::from_der(data)?;
+            auths.push(KeyParameter { tag, value: KPV::LongInteger(value) });
+        }
+        TagType::DATE => {
+            let value = i64::from_der(data)?;
+            auths.push(KeyParameter { tag, value: KPV::DateTime(value) });
+        }
+        TagType::BOOL => {
+            let _value = Null::from_der(data)?;
+            auths.push(KeyParameter { tag, value: KPV::BoolValue(true) });
+        }
+        TagType::BYTES if tag == Tag::ROOT_OF_TRUST => {
+            // Special case: root of trust is an ASN.1 `SEQUENCE` not an `OCTET STRING` so don't
+            // decode the bytes.
+            auths.push(KeyParameter { tag: Tag::ROOT_OF_TRUST, value: KPV::Blob(data.to_vec()) });
+        }
+        TagType::BYTES | TagType::BIGNUM => {
+            let value = OctetStringRef::from_der(data)?.as_bytes().to_vec();
+            auths.push(KeyParameter { tag, value: KPV::Blob(value) });
+        }
+        _ => {
+            return Err(der::ErrorKind::TagNumberInvalid.into());
+        }
+    }
+    Ok(())
+}
+
+/// Decode an explicit ASN.1 tag value, coping with large (>=31) tag values
+/// (which the `der` crate doesn't deal with).  Returns `Ok(None)` if the
+/// decoder is empty.
+fn decode_explicit_tag_from_bytes<'a, R: der::Reader<'a>>(
+    decoder: &mut R,
+) -> Result<Option<u32>, der::Error> {
+    if decoder.remaining_len() == Length::ZERO {
+        return Ok(None);
+    }
+    let b1 = decoder.read_byte()?;
+    let tag = if b1 & 0b00011111 == 0b00011111u8 {
+        // The initial byte of 0xbf indicates a larger (>=31) value for the ASN.1 tag:
+        // - 0bXY...... = class
+        // - 0b..C..... = constructed/primitive bit
+        // - 0b...11111 = marker indicating high tag form, tag value to follow
+        //
+        // The top three bits should be 0b101 = constructed context-specific
+        if b1 & 0b11100000 != 0b10100000 {
+            return Err(der::ErrorKind::TagNumberInvalid.into());
+        }
+
+        // The subsequent encoded tag value is broken down into 7-bit chunks (in big-endian order),
+        // and each chunk gets a high bit of 1 except the last, which gets a high bit of zero.
+        let mut bit_count = 0;
+        let mut tag: u32 = 0;
+        loop {
+            let b = decoder.read_byte()?;
+            let low_b = b & 0b01111111;
+            if bit_count == 0 && low_b == 0 {
+                // The first part of the tag number is zero, implying it is not miminally encoded.
+                return Err(der::ErrorKind::TagNumberInvalid.into());
+            }
+
+            bit_count += 7;
+            if bit_count > 32 {
+                // Tag value has more bits than the output type can hold.
+                return Err(der::ErrorKind::TagNumberInvalid.into());
+            }
+            tag = (tag << 7) | (low_b as u32);
+            if b & 0x80u8 == 0x00u8 {
+                // Top bit clear => this is the final part of the value.
+                if tag < 31 {
+                    // Tag is small enough that it should have been in short form.
+                    return Err(der::ErrorKind::TagNumberInvalid.into());
+                }
+                break tag;
+            }
+        }
+    } else {
+        // Get the tag value from the low 5 bits.
+        (b1 & 0b00011111u8) as u32
+    };
+    Ok(Some(tag))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use der::Encode;
+
+    const SIG: &[u8; 32] = &[
+        0xa4, 0x0d, 0xa8, 0x0a, 0x59, 0xd1, 0x70, 0xca, 0xa9, 0x50, 0xcf, 0x15, 0xc1, 0x8c, 0x45,
+        0x4d, 0x47, 0xa3, 0x9b, 0x26, 0x98, 0x9d, 0x8b, 0x64, 0x0e, 0xcd, 0x74, 0x5b, 0xa7, 0x1b,
+        0xf5, 0xdc,
+    ];
+    const VB_KEY: &[u8; 32] = &[0; 32];
+    const VB_HASH: &[u8; 32] = &[
+        0x6f, 0x84, 0xe6, 0x02, 0x73, 0x9d, 0x86, 0x2c, 0x93, 0x2a, 0x28, 0xf0, 0xa5, 0x27, 0x65,
+        0xa4, 0xae, 0xc2, 0x27, 0x8c, 0xb6, 0x3b, 0xe9, 0xbb, 0x63, 0xc7, 0xa8, 0xc7, 0x03, 0xad,
+        0x8e, 0xc1,
+    ];
+
+    /// Build a sample `AuthorizationList` suitable for use as `sw_enforced`.
+    fn sw_enforced() -> AuthorizationList<'static> {
+        let sig = OctetStringRef::new(SIG).unwrap();
+        let package = PackageInfoRecord {
+            package_name: OctetStringRef::new(b"android.keystore.cts").unwrap(),
+            version: 34,
+        };
+        let mut package_info_records = SetOfVec::new();
+        package_info_records.insert(package).unwrap();
+        let mut signature_digests = SetOfVec::new();
+        signature_digests.insert(sig).unwrap();
+        let aaid = AttestationApplicationId { package_info_records, signature_digests };
+        AuthorizationList {
+            auths: vec![
+                KeyParameter { tag: Tag::CREATION_DATETIME, value: KPV::DateTime(0x01903116c71f) },
+                KeyParameter {
+                    tag: Tag::ATTESTATION_APPLICATION_ID,
+                    value: KPV::Blob(aaid.to_der().unwrap()),
+                },
+            ]
+            .into(),
+        }
+    }
+
+    /// Build a sample `AuthorizationList` suitable for use as `hw_enforced`.
+    fn hw_enforced() -> AuthorizationList<'static> {
+        let rot = RootOfTrust {
+            verified_boot_key: VB_KEY,
+            device_locked: false,
+            verified_boot_state: VerifiedBootState::Unverified,
+            verified_boot_hash: VB_HASH,
+        };
+        AuthorizationList {
+            auths: vec![
+                KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::AGREE_KEY) },
+                KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::EC) },
+                KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(256) },
+                KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::NONE) },
+                KeyParameter { tag: Tag::EC_CURVE, value: KPV::EcCurve(EcCurve::CURVE_25519) },
+                KeyParameter { tag: Tag::NO_AUTH_REQUIRED, value: KPV::BoolValue(true) },
+                KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
+                KeyParameter { tag: Tag::ROOT_OF_TRUST, value: KPV::Blob(rot.to_der().unwrap()) },
+                KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(140000) },
+                KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202404) },
+                KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20240405) },
+                KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(20240405) },
+            ]
+            .into(),
+        }
+    }
+
+    #[test]
+    fn test_decode_auth_list_1() {
+        let want = sw_enforced();
+        let data = hex::decode(concat!(
+            "3055",     //  SEQUENCE
+            "bf853d08", //  [701]
+            "0206",     //  INTEGER
+            "01903116c71f",
+            "bf854545",                                 //  [709]
+            "0443",                                     //  OCTET STRING
+            "3041",                                     //  SEQUENCE
+            "311b",                                     //  SET
+            "3019",                                     //  SEQUENCE
+            "0414",                                     //  OCTET STRING
+            "616e64726f69642e6b657973746f72652e637473", //  "android.keystore.cts"
+            "020122",                                   //  INTEGER
+            "3122",                                     //  SET
+            "0420",                                     //  OCTET STRING
+            "a40da80a59d170caa950cf15c18c454d",
+            "47a39b26989d8b640ecd745ba71bf5dc",
+        ))
+        .unwrap();
+        let got = AuthorizationList::from_der(&data).unwrap();
+        assert_eq!(got, want);
+    }
+
+    #[test]
+    fn test_decode_auth_list_2() {
+        let want = hw_enforced();
+        let data = hex::decode(concat!(
+            "3081a1",   //  SEQUENCE
+            "a105",     //  [1]
+            "3103",     //  SET
+            "020106",   //  INTEGER
+            "a203",     //  [2]
+            "020103",   //  INTEGER 3
+            "a304",     //  [4]
+            "02020100", //  INTEGER 256
+            "a505",     //  [5]
+            "3103",     //  SET
+            "020100",   //  INTEGER 0
+            "aa03",     //  [10]
+            "020104",   //  INTEGER 4
+            "bf837702", //  [503]
+            "0500",     //  NULL
+            "bf853e03", //  [702]
+            "020100",   //  INTEGER 0
+            "bf85404c", //  [704]
+            "304a",     //  SEQUENCE
+            "0420",     //  OCTET STRING
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "010100", //  BOOLEAN
+            "0a0102", //  ENUMERATED
+            "0420",   //  OCTET STRING
+            "6f84e602739d862c932a28f0a52765a4",
+            "aec2278cb63be9bb63c7a8c703ad8ec1",
+            "bf854105",     //  [705]
+            "02030222e0",   //  INTEGER
+            "bf854205",     //  [706]
+            "02030316a4",   //  INTEGER
+            "bf854e06",     //  [718]
+            "02040134d815", //  INTEGER
+            "bf854f06",     //  [709]
+            "02040134d815", //  INTEGER
+        ))
+        .unwrap();
+        let got = AuthorizationList::from_der(&data).unwrap();
+        assert_eq!(got, want);
+    }
+
+    #[test]
+    fn test_decode_extension() {
+        let zeroes = [0; 128];
+        let want = AttestationExtension {
+            attestation_version: 300,
+            attestation_security_level: SecurityLevel::TrustedEnvironment,
+            keymint_version: 300,
+            keymint_security_level: SecurityLevel::TrustedEnvironment,
+            attestation_challenge: &zeroes,
+            unique_id: &[],
+            sw_enforced: sw_enforced(),
+            hw_enforced: hw_enforced(),
+        };
+
+        let data = hex::decode(concat!(
+            // Full extension would include the following prefix:
+            // "308201a2",             //  SEQUENCE
+            // "060a",                 //  OBJECT IDENTIFIER
+            // "2b06010401d679020111", //  Android attestation extension (1.3.6.1.4.1.11129.2.1.17)
+            // "04820192",             //  OCTET STRING
+            "3082018e", //  SEQUENCE
+            "0202012c", //  INTEGER 300
+            "0a0101",   //  ENUMERATED 1
+            "0202012c", //  INTEGER 300
+            "0a0101",   //  ENUMERATED 1
+            "048180",   //  OCTET STRING
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "0400", //  OCTET STRING
+            // softwareEnforced
+            "3055",     //  SEQUENCE
+            "bf853d08", //  [701]
+            "0206",     //  INTEGER
+            "01903116c71f",
+            "bf854545",                                 //  [709]
+            "0443",                                     //  OCTET STRING
+            "3041",                                     //  SEQUENCE
+            "311b",                                     //  SET
+            "3019",                                     //  SEQUENCE
+            "0414",                                     //  OCTET STRING
+            "616e64726f69642e6b657973746f72652e637473", //  "android.keystore.cts"
+            "020122",                                   //  INTEGER
+            "3122",                                     //  SET
+            "0420",                                     //  OCTET STRING
+            "a40da80a59d170caa950cf15c18c454d",
+            "47a39b26989d8b640ecd745ba71bf5dc",
+            // softwareEnforced
+            "3081a1",   //  SEQUENCE
+            "a105",     //  [1]
+            "3103",     //  SET
+            "020106",   //  INTEGER
+            "a203",     //  [2]
+            "020103",   //  INTEGER 3
+            "a304",     //  [4]
+            "02020100", //  INTEGER 256
+            "a505",     //  [5]
+            "3103",     //  SET
+            "020100",   //  INTEGER 0
+            "aa03",     //  [10]
+            "020104",   //  INTEGER 4
+            "bf837702", //  [503]
+            "0500",     //  NULL
+            "bf853e03", //  [702]
+            "020100",   //  INTEGER 0
+            "bf85404c", //  [704]
+            "304a",     //  SEQUENCE
+            "0420",     //  OCTET STRING
+            "00000000000000000000000000000000",
+            "00000000000000000000000000000000",
+            "010100", //  BOOLEAN
+            "0a0102", //  ENUMERATED
+            "0420",   //  OCTET STRING
+            "6f84e602739d862c932a28f0a52765a4",
+            "aec2278cb63be9bb63c7a8c703ad8ec1",
+            "bf854105",     //  [705]
+            "02030222e0",   //  INTEGER
+            "bf854205",     //  [706]
+            "02030316a4",   //  INTEGER
+            "bf854e06",     //  [718]
+            "02040134d815", //  INTEGER
+            "bf854f06",     //  [719]
+            "02040134d815", //  INTEGER
+        ))
+        .unwrap();
+        let got = AttestationExtension::from_der(&data).unwrap();
+        assert_eq!(got, want);
+    }
+
+    #[test]
+    fn test_decode_empty_auth_list() {
+        let want = AuthorizationList::default();
+        let data = hex::decode(
+            "3000", //  SEQUENCE
+        )
+        .unwrap();
+        let got = AuthorizationList::from_der(&data).unwrap();
+        assert_eq!(got, want);
+    }
+
+    #[test]
+    fn test_decode_explicit_tag() {
+        let err = Err(der::ErrorKind::TagNumberInvalid.into());
+        let tests = [
+            (vec![], Ok(None)),
+            (vec![0b10100000], Ok(Some(0))),
+            (vec![0b10100001], Ok(Some(1))),
+            (vec![0b10100010], Ok(Some(2))),
+            (vec![0b10111110], Ok(Some(30))),
+            (vec![0b10111111, 0b00011111], Ok(Some(31))),
+            (vec![0b10111111, 0b00100000], Ok(Some(32))),
+            (vec![0b10111111, 0b01111111], Ok(Some(127))),
+            (vec![0b10111111, 0b10000001, 0b00000000], Ok(Some(128))),
+            (vec![0b10111111, 0b10000010, 0b00000000], Ok(Some(256))),
+            (vec![0b10111111, 0b10000001, 0b10000000, 0b00000001], Ok(Some(16385))),
+            (vec![0b10111111, 0b10010000, 0b10000000, 0b10000000, 0b00000000], Ok(Some(33554432))),
+            // Top bits ignored for low tag numbers
+            (vec![0b00000000], Ok(Some(0))),
+            (vec![0b00000001], Ok(Some(1))),
+            // High tag numbers should start with 0b101
+            (vec![0b10011111, 0b00100000], err),
+            (vec![0b11111111, 0b00100000], err),
+            (vec![0b00111111, 0b00100000], err),
+            // High tag numbers should be minimally encoded
+            (vec![0b10111111, 0b10000000, 0b10000001, 0b00000000], err),
+            (vec![0b10111111, 0b00011110], err),
+            // Bigger than u32
+            (
+                vec![
+                    0b10111111, 0b10000001, 0b10000000, 0b10000000, 0b10000000, 0b10000000,
+                    0b00000000,
+                ],
+                err,
+            ),
+            // Incomplete tag
+            (vec![0b10111111, 0b10000001], Err(der::Error::incomplete(der::Length::new(2)))),
+        ];
+
+        for (input, want) in tests {
+            let mut reader = SliceReader::new(&input).unwrap();
+            let got = decode_explicit_tag_from_bytes(&mut reader);
+            assert_eq!(got, want, "for input {}", hex::encode(input));
+        }
+    }
+}
diff --git a/keystore2/test_utils/key_generations.rs b/keystore2/test_utils/key_generations.rs
index 5e823c25..98b227b9 100644
--- a/keystore2/test_utils/key_generations.rs
+++ b/keystore2/test_utils/key_generations.rs
@@ -536,13 +536,27 @@ fn check_common_auths(
             value: KeyParameterValue::Integer(get_os_version().try_into().unwrap())
         }
     ));
-    assert!(check_key_param(
-        authorizations,
-        &KeyParameter {
-            tag: Tag::OS_PATCHLEVEL,
-            value: KeyParameterValue::Integer(get_os_patchlevel().try_into().unwrap())
-        }
-    ));
+    if is_gsi() && sl.is_keymaster() {
+        // The expected value of TAG::OS_PATCHLEVEL should match the system's reported
+        // OS patch level (obtained via get_os_patchlevel()). However, booting a Generic System
+        // Image (GSI) with a newer patch level is permitted. Therefore, the generated key's
+        // TAG::OS_PATCHLEVEL may be less than or equal to the current system's OS patch level.
+        assert!(authorizations.iter().map(|auth| &auth.keyParameter).any(|key_param| key_param
+            .tag
+            == Tag::OS_PATCHLEVEL
+            && key_param.value
+                <= KeyParameterValue::Integer(get_os_patchlevel().try_into().unwrap())));
+    } else {
+        // The KeyMint spec required that the patch-levels match that of the running system, even
+        // under GSI.
+        assert!(check_key_param(
+            authorizations,
+            &KeyParameter {
+                tag: Tag::OS_PATCHLEVEL,
+                value: KeyParameterValue::Integer(get_os_patchlevel().try_into().unwrap())
+            }
+        ));
+    }
 
     assert!(check_key_param(
         authorizations,
diff --git a/keystore2/test_utils/lib.rs b/keystore2/test_utils/lib.rs
index 825657fd..8e74f92b 100644
--- a/keystore2/test_utils/lib.rs
+++ b/keystore2/test_utils/lib.rs
@@ -21,7 +21,7 @@ use std::{env::temp_dir, ops::Deref};
 
 use android_system_keystore2::aidl::android::system::keystore2::{
     IKeystoreService::IKeystoreService,
-    IKeystoreSecurityLevel::IKeystoreSecurityLevel,
+    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
@@ -193,4 +193,18 @@ impl SecLevel {
             0
         }
     }
+
+    /// Delete a key.
+    pub fn delete_key(&self, key: &KeyDescriptor) -> binder::Result<()> {
+        match self.binder.deleteKey(key) {
+            Ok(()) => Ok(()),
+            Err(s)
+                if s.exception_code() == binder::ExceptionCode::SERVICE_SPECIFIC
+                    && s.service_specific_error() == ErrorCode::UNIMPLEMENTED.0 =>
+            {
+                Ok(())
+            }
+            Err(e) => Err(e),
+        }
+    }
 }
diff --git a/keystore2/tests/Android.bp b/keystore2/tests/Android.bp
index 1f3d0b8e..8ec52389 100644
--- a/keystore2/tests/Android.bp
+++ b/keystore2/tests/Android.bp
@@ -52,12 +52,17 @@ rust_test {
         "libandroid_security_flags_rust",
         "libanyhow",
         "libbinder_rs",
+        "libbssl_crypto",
+        "libkeystore_attestation",
         "libkeystore2_test_utils",
+        "libhex",
         "liblog_rust",
+        "libkeystore2_flags_rust",
         "libnix",
         "libopenssl",
         "librustutils",
         "libserde",
+        "libx509_cert",
         "packagemanager_aidl-rust",
     ],
     require_root: true,
diff --git a/keystore2/tests/keystore2_client_attest_key_tests.rs b/keystore2/tests/keystore2_client_attest_key_tests.rs
index 02dfd3fd..553add07 100644
--- a/keystore2/tests/keystore2_client_attest_key_tests.rs
+++ b/keystore2/tests/keystore2_client_attest_key_tests.rs
@@ -13,7 +13,8 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    app_attest_key_feature_exists, device_id_attestation_feature_exists, get_attest_id_value,
+    app_attest_key_feature_exists, device_id_attestation_check_acceptable_error,
+    device_id_attestation_feature_exists, get_attest_id_value,
     is_second_imei_id_attestation_required, skip_device_id_attest_tests,
 };
 use crate::{
@@ -558,7 +559,7 @@ fn keystore2_attest_rsa_attestation_id() {
 }
 
 /// Try to generate an attested key with attestation of invalid device's identifiers. Test should
-/// fail with error response code `CANNOT_ATTEST_IDS`.
+/// fail to generate a key with proper error code.
 #[test]
 fn keystore2_attest_key_fails_with_invalid_attestation_id() {
     skip_test_if_no_device_id_attestation_feature!();
@@ -602,7 +603,7 @@ fn keystore2_attest_key_fails_with_invalid_attestation_id() {
         ));
 
         assert!(result.is_err());
-        assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
+        device_id_attestation_check_acceptable_error(attest_id, result.unwrap_err());
     }
 }
 
diff --git a/keystore2/tests/keystore2_client_authorizations_tests.rs b/keystore2/tests/keystore2_client_authorizations_tests.rs
index 504e6ab2..6d105cce 100644
--- a/keystore2/tests/keystore2_client_authorizations_tests.rs
+++ b/keystore2/tests/keystore2_client_authorizations_tests.rs
@@ -19,7 +19,6 @@ use crate::keystore2_client_test_utils::{
     verify_certificate_serial_num, verify_certificate_subject_name, SAMPLE_PLAIN_TEXT,
 };
 use crate::{require_keymint, skip_test_if_no_app_attest_key_feature};
-use aconfig_android_hardware_biometrics_rust;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
     ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
@@ -27,6 +26,7 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
+    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
 };
 use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
     Timestamp::Timestamp
@@ -35,6 +35,8 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
     ResponseCode::ResponseCode,
 };
+use bssl_crypto::digest;
+use keystore_attestation::{AttestationExtension, ATTESTATION_EXTENSION_OID};
 use keystore2_test_utils::ffi_test_utils::get_value_from_attest_record;
 use keystore2_test_utils::{
     authorizations, get_keystore_auth_service, key_generations,
@@ -43,6 +45,7 @@ use keystore2_test_utils::{
 use openssl::bn::{BigNum, MsbOption};
 use openssl::x509::X509NameBuilder;
 use std::time::SystemTime;
+use x509_cert::{certificate::Certificate, der::Decode};
 
 fn gen_key_including_unique_id(sl: &SecLevel, alias: &str) -> Option<Vec<u8>> {
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -518,6 +521,10 @@ fn keystore2_gen_key_auth_max_uses_per_boot() {
 #[test]
 fn keystore2_gen_key_auth_usage_count_limit() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() {
+        // `USAGE_COUNT_LIMIT` is supported from KeyMint1.0
+        return;
+    }
     const MAX_USES_COUNT: i32 = 3;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -542,6 +549,10 @@ fn keystore2_gen_key_auth_usage_count_limit() {
 #[test]
 fn keystore2_gen_key_auth_usage_count_limit_one() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() {
+        // `USAGE_COUNT_LIMIT` is supported from KeyMint1.0
+        return;
+    }
     const MAX_USES_COUNT: i32 = 1;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -565,6 +576,10 @@ fn keystore2_gen_key_auth_usage_count_limit_one() {
 #[test]
 fn keystore2_gen_non_attested_key_auth_usage_count_limit() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() {
+        // `USAGE_COUNT_LIMIT` is supported from KeyMint1.0
+        return;
+    }
     const MAX_USES_COUNT: i32 = 2;
 
     let gen_params = authorizations::AuthSetBuilder::new()
@@ -627,6 +642,12 @@ fn keystore2_gen_key_auth_creation_date_time_test_fail_with_invalid_arg_error()
 #[test]
 fn keystore2_gen_key_auth_include_unique_id_success() {
     let sl = SecLevel::tee();
+    if sl.is_keymaster() {
+        // b/387208956 - Some older devices with Keymaster implementations fail to generate an
+        // attestation key with `INCLUDE_UNIQUE_ID`, but this was not previously tested. Skip this
+        // test on devices with Keymaster implementation.
+        return;
+    }
 
     let alias_first = "ks_test_auth_tags_test_1";
     if let Some(unique_id_first) = gen_key_including_unique_id(&sl, alias_first) {
@@ -921,25 +942,7 @@ fn add_hardware_token(auth_type: HardwareAuthenticatorType) {
 }
 
 #[test]
-fn keystore2_flagged_off_get_last_auth_password_permission_denied() {
-    if aconfig_android_hardware_biometrics_rust::last_authentication_time() {
-        return;
-    }
-
-    let keystore_auth = get_keystore_auth_service();
-
-    let result = keystore_auth.getLastAuthTime(0, &[HardwareAuthenticatorType::PASSWORD]);
-
-    assert!(result.is_err());
-    assert_eq!(result.unwrap_err().service_specific_error(), ResponseCode::PERMISSION_DENIED.0);
-}
-
-#[test]
-fn keystore2_flagged_on_get_last_auth_password_success() {
-    if !aconfig_android_hardware_biometrics_rust::last_authentication_time() {
-        return;
-    }
-
+fn keystore2_get_last_auth_password_success() {
     let keystore_auth = get_keystore_auth_service();
 
     add_hardware_token(HardwareAuthenticatorType::PASSWORD);
@@ -947,11 +950,7 @@ fn keystore2_flagged_on_get_last_auth_password_success() {
 }
 
 #[test]
-fn keystore2_flagged_on_get_last_auth_fingerprint_success() {
-    if !aconfig_android_hardware_biometrics_rust::last_authentication_time() {
-        return;
-    }
-
+fn keystore2_get_last_auth_fingerprint_success() {
     let keystore_auth = get_keystore_auth_service();
 
     add_hardware_token(HardwareAuthenticatorType::FINGERPRINT);
@@ -996,3 +995,71 @@ fn keystore2_gen_key_auth_serial_number_subject_test_success() {
     verify_certificate_serial_num(key_metadata.certificate.as_ref().unwrap(), &serial);
     delete_app_key(&sl.keystore2, alias).unwrap();
 }
+
+#[test]
+fn test_supplementary_attestation_info() {
+    if !keystore2_flags::attest_modules() {
+        // Module info is only populated if the flag is set.
+        return;
+    }
+
+    // Test should not run before MODULE_HASH supplementary info is populated.
+    assert!(rustutils::system_properties::read_bool("keystore.module_hash.sent", false)
+        .unwrap_or(false));
+
+    let sl = SecLevel::tee();
+
+    // Retrieve the input value that gets hashed into the attestation.
+    let module_info = sl
+        .keystore2
+        .getSupplementaryAttestationInfo(Tag::MODULE_HASH)
+        .expect("supplementary info for MODULE_HASH should be populated during startup");
+    let again = sl.keystore2.getSupplementaryAttestationInfo(Tag::MODULE_HASH).unwrap();
+    assert_eq!(again, module_info);
+    let want_hash = digest::Sha256::hash(&module_info).to_vec();
+
+    // Requesting other types of information should fail.
+    let result = key_generations::map_ks_error(
+        sl.keystore2.getSupplementaryAttestationInfo(Tag::BLOCK_MODE),
+    );
+    assert!(result.is_err());
+    assert_eq!(result.unwrap_err(), Error::Rc(ResponseCode::INVALID_ARGUMENT));
+
+    if sl.get_keymint_version() < 400 {
+        // Module hash will only be populated in KeyMint if the underlying device is KeyMint V4+.
+        return;
+    }
+
+    // Generate an attestation.
+    let alias = "ks_module_info_test";
+    let params = authorizations::AuthSetBuilder::new()
+        .no_auth_required()
+        .algorithm(Algorithm::EC)
+        .purpose(KeyPurpose::SIGN)
+        .purpose(KeyPurpose::VERIFY)
+        .digest(Digest::SHA_2_256)
+        .ec_curve(EcCurve::P_256)
+        .attestation_challenge(b"froop".to_vec());
+    let metadata = key_generations::generate_key(&sl, &params, alias)
+        .expect("failed key generation")
+        .expect("no metadata");
+    let cert_data = metadata.certificate.as_ref().unwrap();
+    let cert = Certificate::from_der(cert_data).expect("failed to parse X509 cert");
+    let exts = cert.tbs_certificate.extensions.expect("no X.509 extensions");
+    let ext = exts
+        .iter()
+        .find(|ext| ext.extn_id == ATTESTATION_EXTENSION_OID)
+        .expect("no attestation extension");
+    let ext = AttestationExtension::from_der(ext.extn_value.as_bytes())
+        .expect("failed to parse attestation extension");
+
+    // Find the attested module hash value.
+    let mut got_hash = None;
+    for auth in ext.sw_enforced.auths.into_owned().iter() {
+        if let KeyParameter { tag: Tag::MODULE_HASH, value: KeyParameterValue::Blob(hash) } = auth {
+            got_hash = Some(hash.clone());
+        }
+    }
+    let got_hash = got_hash.expect("no MODULE_HASH in sw_enforced");
+    assert_eq!(hex::encode(got_hash), hex::encode(want_hash));
+}
diff --git a/keystore2/tests/keystore2_client_delete_key_tests.rs b/keystore2/tests/keystore2_client_delete_key_tests.rs
index a0fb9c2a..13f8eef9 100644
--- a/keystore2/tests/keystore2_client_delete_key_tests.rs
+++ b/keystore2/tests/keystore2_client_delete_key_tests.rs
@@ -100,7 +100,7 @@ fn keystore2_delete_key_blob_success() {
     )
     .unwrap();
 
-    let result = sl.binder.deleteKey(&key_metadata.key);
+    let result = sl.delete_key(&key_metadata.key);
     assert!(result.is_ok());
 }
 
@@ -110,7 +110,7 @@ fn keystore2_delete_key_blob_success() {
 fn keystore2_delete_key_fails_with_missing_key_blob() {
     let sl = SecLevel::tee();
 
-    let result = key_generations::map_ks_error(sl.binder.deleteKey(&KeyDescriptor {
+    let result = key_generations::map_ks_error(sl.delete_key(&KeyDescriptor {
         domain: Domain::BLOB,
         nspace: key_generations::SELINUX_SHELL_NAMESPACE,
         alias: None,
@@ -132,7 +132,7 @@ fn keystore2_delete_key_blob_fail() {
         key_generations::generate_ec_p256_signing_key(&sl, Domain::APP, -1, Some(alias), None)
             .unwrap();
 
-    let result = key_generations::map_ks_error(sl.binder.deleteKey(&key_metadata.key));
+    let result = key_generations::map_ks_error(sl.delete_key(&key_metadata.key));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_ARGUMENT), result.unwrap_err());
 }
diff --git a/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs b/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs
index 91370c77..fb848081 100644
--- a/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs
+++ b/keystore2/tests/keystore2_client_device_unique_attestation_tests.rs
@@ -13,8 +13,9 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    delete_app_key, get_attest_id_value, is_second_imei_id_attestation_required,
-    perform_sample_asym_sign_verify_op, skip_device_unique_attestation_tests,
+    delete_app_key, device_id_attestation_check_acceptable_error, get_attest_id_value,
+    is_second_imei_id_attestation_required, perform_sample_asym_sign_verify_op,
+    skip_device_unique_attestation_tests,
 };
 use crate::require_keymint;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
@@ -254,7 +255,7 @@ fn keystore2_gen_rsa_key_device_unique_attest_with_strongbox_sec_level_test_succ
 }
 
 /// Try to generate a device unique attested key with attestation of invalid device's identifiers.
-/// Test should fail with error response code `CANNOT_ATTEST_IDS`.
+/// Test should fail to generate a key with proper error code.
 #[test]
 fn keystore2_device_unique_attest_key_fails_with_invalid_attestation_id() {
     let Some(sl) = SecLevel::strongbox() else { return };
@@ -288,7 +289,7 @@ fn keystore2_device_unique_attest_key_fails_with_invalid_attestation_id() {
         let result =
             key_generations::map_ks_error(key_generations::generate_key(&sl, &gen_params, alias));
         assert!(result.is_err());
-        assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
+        device_id_attestation_check_acceptable_error(attest_id, result.unwrap_err());
     }
 }
 
diff --git a/keystore2/tests/keystore2_client_ec_key_tests.rs b/keystore2/tests/keystore2_client_ec_key_tests.rs
index 526a3390..17a88e74 100644
--- a/keystore2/tests/keystore2_client_ec_key_tests.rs
+++ b/keystore2/tests/keystore2_client_ec_key_tests.rs
@@ -211,7 +211,7 @@ fn keystore2_get_key_entry_blob_fail() {
     assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());
 
     // Delete the generated key blob.
-    sl.binder.deleteKey(&key_metadata.key).unwrap();
+    sl.delete_key(&key_metadata.key).unwrap();
 }
 
 /// Try to generate a key with invalid Domain. `INVALID_ARGUMENT` error response is expected.
@@ -514,5 +514,5 @@ fn keystore2_generate_key_with_blob_domain() {
     );
 
     // Delete the generated key blob.
-    sl.binder.deleteKey(&key_metadata.key).unwrap();
+    sl.delete_key(&key_metadata.key).unwrap();
 }
diff --git a/keystore2/tests/keystore2_client_grant_key_tests.rs b/keystore2/tests/keystore2_client_grant_key_tests.rs
index c171ab15..87d5f4dd 100644
--- a/keystore2/tests/keystore2_client_grant_key_tests.rs
+++ b/keystore2/tests/keystore2_client_grant_key_tests.rs
@@ -18,6 +18,7 @@ use crate::keystore2_client_test_utils::{
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Digest::Digest, KeyPurpose::KeyPurpose,
 };
+use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::IKeystoreMaintenance;
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
     KeyEntryResponse::KeyEntryResponse, KeyPermission::KeyPermission, ResponseCode::ResponseCode,
@@ -30,6 +31,8 @@ use keystore2_test_utils::{
 use nix::unistd::getuid;
 use rustutils::users::AID_USER_OFFSET;
 
+static USER_MANAGER_SERVICE_NAME: &str = "android.security.maintenance";
+
 /// Produce a [`KeyDescriptor`] for a granted key.
 fn granted_key_descriptor(nspace: i64) -> KeyDescriptor {
     KeyDescriptor { domain: Domain::GRANT, nspace, alias: None, blob: None }
@@ -88,6 +91,10 @@ fn sign_with_granted_key(grant_key_nspace: i64) -> Result<(), Error> {
     Ok(())
 }
 
+fn get_maintenance() -> binder::Strong<dyn IKeystoreMaintenance> {
+    binder::get_interface(USER_MANAGER_SERVICE_NAME).unwrap()
+}
+
 /// Try to grant an SELINUX key with permission that does not map to any of the `KeyPermission`
 /// values.  An error is expected with values that does not map to set of permissions listed in
 /// `KeyPermission`.
@@ -600,6 +607,223 @@ fn grant_fails_with_non_existing_selinux_key() {
     assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
 }
 
+/// Grant a key to a UID (user ID A + app B) then uninstall user ID A. Initialize a new user with
+/// the same user ID as the now-removed user. Check that app B for the new user can't load the key.
+#[test]
+fn grant_removed_when_grantee_user_id_removed() {
+    const GRANTOR_USER_ID: u32 = 97;
+    const GRANTOR_APPLICATION_ID: u32 = 10003;
+    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
+    static GRANTOR_GID: u32 = GRANTOR_UID;
+
+    const GRANTEE_USER_ID: u32 = 99;
+    const GRANTEE_APPLICATION_ID: u32 = 10001;
+    static GRANTEE_UID: u32 = GRANTEE_USER_ID * AID_USER_OFFSET + GRANTEE_APPLICATION_ID;
+    static GRANTEE_GID: u32 = GRANTEE_UID;
+
+    // Add a new user.
+    let create_grantee_user_id_fn = || {
+        let maint = get_maintenance();
+        maint.onUserAdded(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to add user");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_root(create_grantee_user_id_fn) };
+
+    // Child function to generate a key and grant it to GRANTEE_UID with `GET_INFO` permission.
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let access_vector = KeyPermission::GET_INFO.0;
+        let alias = format!("ks_grant_single_{}", getuid());
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap();
+
+        grant_keys.remove(0)
+    };
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
+    // Remove the grantee user and create a new user with the same user ID.
+    let overwrite_grantee_user_id_fn = || {
+        let maint = get_maintenance();
+        maint.onUserRemoved(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to remove user");
+        maint.onUserAdded(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to add user");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_root(overwrite_grantee_user_id_fn) };
+
+    // Second context identified by <uid, grant_nspace> (where uid is the same because the
+    // now-deleted and newly-created grantee users have the same user ID) does not have access to
+    // the above granted key.
+    let new_grantee_fn = move || {
+        // Check that the key cannot be accessed via grant (i.e. KeyDescriptor with Domain::GRANT).
+        let keystore2 = get_keystore_service();
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
+
+        // Check that the key also cannot be accessed via key ID (i.e. KeyDescriptor with
+        // Domain::KEY_ID) if the second context somehow gets a hold of it.
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
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, new_grantee_fn) };
+
+    // Clean up: remove grantee user.
+    let remove_grantee_user_id_fn = || {
+        let maint = get_maintenance();
+        maint.onUserRemoved(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to remove user");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_root(remove_grantee_user_id_fn) };
+}
+
+/// Grant a key to a UID (user ID A + app B) then clear the namespace for user ID A + app B. Check
+/// that the key can't be loaded by that UID (which would be the UID used if another app were to be
+/// installed for user ID A with the same application ID B).
+#[test]
+fn grant_removed_when_grantee_app_uninstalled() {
+    const GRANTOR_USER_ID: u32 = 97;
+    const GRANTOR_APPLICATION_ID: u32 = 10003;
+    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
+    static GRANTOR_GID: u32 = GRANTOR_UID;
+
+    const GRANTEE_USER_ID: u32 = 99;
+    const GRANTEE_APPLICATION_ID: u32 = 10001;
+    static GRANTEE_UID: u32 = GRANTEE_USER_ID * AID_USER_OFFSET + GRANTEE_APPLICATION_ID;
+    static GRANTEE_GID: u32 = GRANTEE_UID;
+
+    // Add a new user.
+    let create_grantee_user_id_fn = || {
+        let maint = get_maintenance();
+        maint.onUserAdded(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to add user");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_root(create_grantee_user_id_fn) };
+
+    // Child function to generate a key and grant it to GRANTEE_UID with `GET_INFO` permission.
+    let grantor_fn = || {
+        let sl = SecLevel::tee();
+        let access_vector = KeyPermission::GET_INFO.0;
+        let alias = format!("ks_grant_single_{}", getuid());
+        let mut grant_keys = generate_ec_key_and_grant_to_users(
+            &sl,
+            Some(alias),
+            vec![GRANTEE_UID.try_into().unwrap()],
+            access_vector,
+        )
+        .unwrap();
+
+        grant_keys.remove(0)
+    };
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
+    // Clear the app's namespace, which is what happens when an app is uninstalled. Exercising the
+    // full app uninstallation "flow" isn't possible from a Keystore VTS test since we'd need to
+    // exercise the Java code that calls into the Keystore service. So, we can only test the
+    // entrypoint that we know gets triggered during app uninstallation based on the code's control
+    // flow.
+    let clear_grantee_uid_namespace_fn = || {
+        let maint = get_maintenance();
+        maint
+            .clearNamespace(Domain::APP, GRANTEE_UID.try_into().unwrap())
+            .expect("failed to clear namespace");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_root(clear_grantee_uid_namespace_fn) };
+
+    // The same context identified by <uid, grant_nspace> not longer has access to the above granted
+    // key. This would be the context if a new app were installed and assigned the same app ID.
+    let new_grantee_fn = move || {
+        // Check that the key cannot be accessed via grant (i.e. KeyDescriptor with Domain::GRANT).
+        let keystore2 = get_keystore_service();
+        let result = get_granted_key(&keystore2, grant_key_nspace);
+        assert!(result.is_err());
+        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
+
+        // Check that the key also cannot be accessed via key ID (i.e. KeyDescriptor with
+        // Domain::KEY_ID) if the second context somehow gets a hold of it.
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
+    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, new_grantee_fn) };
+
+    // Clean up: remove grantee user.
+    let remove_grantee_user_id_fn = || {
+        let maint = get_maintenance();
+        maint.onUserRemoved(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to remove user");
+    };
+
+    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
+    // `--test-threads=1`), and nothing yet done with binder on the main thread.
+    unsafe { run_as::run_as_root(remove_grantee_user_id_fn) };
+}
+
 /// Grant an APP key to the user and immediately ungrant the granted key. In grantee context try to load
 /// the key. Grantee should fail to load the ungranted key with `KEY_NOT_FOUND` error response.
 #[test]
diff --git a/keystore2/tests/keystore2_client_test_utils.rs b/keystore2/tests/keystore2_client_test_utils.rs
index 831fc855..8d708662 100644
--- a/keystore2/tests/keystore2_client_test_utils.rs
+++ b/keystore2/tests/keystore2_client_test_utils.rs
@@ -518,9 +518,7 @@ pub fn verify_aliases(
 // then returns an empty byte vector.
 pub fn get_system_prop(name: &str) -> Vec<u8> {
     match rustutils::system_properties::read(name) {
-        Ok(Some(value)) => {
-            return value.as_bytes().to_vec();
-        }
+        Ok(Some(value)) => value.as_bytes().to_vec(),
         _ => {
             vec![]
         }
@@ -620,3 +618,25 @@ pub fn verify_certificate_serial_num(cert_bytes: &[u8], expected_serial_num: &Bi
     let serial_num = cert.serial_number();
     assert_eq!(serial_num.to_bn().as_ref().unwrap(), expected_serial_num);
 }
+
+/// Check the error code from an attempt to perform device ID attestation with an invalid value.
+pub fn device_id_attestation_check_acceptable_error(attest_id_tag: Tag, e: Error) {
+    match e {
+        // Standard/default error code for ID mismatch.
+        Error::Km(ErrorCode::CANNOT_ATTEST_IDS) => {}
+        Error::Km(ErrorCode::INVALID_TAG) if get_vsr_api_level() < 34 => {
+            // Allow older implementations to (incorrectly) use INVALID_TAG.
+        }
+        Error::Km(ErrorCode::ATTESTATION_IDS_NOT_PROVISIONED)
+            if matches!(
+                attest_id_tag,
+                Tag::ATTESTATION_ID_IMEI
+                    | Tag::ATTESTATION_ID_MEID
+                    | Tag::ATTESTATION_ID_SECOND_IMEI
+            ) =>
+        {
+            // Non-phone devices will not have IMEI/MEID provisioned.
+        }
+        _ => panic!("Unexpected error {e:?} on ID mismatch for {attest_id_tag:?}"),
+    }
+}
diff --git a/keystore2/tests/user_auth.rs b/keystore2/tests/user_auth.rs
index 187256b7..789f54bd 100644
--- a/keystore2/tests/user_auth.rs
+++ b/keystore2/tests/user_auth.rs
@@ -14,7 +14,9 @@
 
 //! Tests for user authentication interactions (via `IKeystoreAuthorization`).
 
-use crate::keystore2_client_test_utils::{BarrierReached, BarrierReachedWithData};
+use crate::keystore2_client_test_utils::{
+    BarrierReached, BarrierReachedWithData, get_vsr_api_level
+};
 use android_security_authorization::aidl::android::security::authorization::{
     IKeystoreAuthorization::IKeystoreAuthorization
 };
@@ -59,12 +61,13 @@ static SYNTHETIC_PASSWORD: &[u8] = &[
 ];
 /// Gatekeeper password.
 static GK_PASSWORD: &[u8] = b"correcthorsebatterystaple";
-/// Fake SID value corresponding to Gatekeeper.
-static GK_FAKE_SID: i64 = 123456;
-/// Fake SID value corresponding to a biometric authenticator.
-static BIO_FAKE_SID1: i64 = 345678;
-/// Fake SID value corresponding to a biometric authenticator.
-static BIO_FAKE_SID2: i64 = 456789;
+/// Fake SID base value corresponding to Gatekeeper.  Individual tests use different SIDs to reduce
+/// the chances of cross-contamination, calculated statically (because each test is forked into a
+/// separate process).
+static GK_FAKE_SID_BASE: i64 = 123400;
+/// Fake SID base value corresponding to a biometric authenticator.  Individual tests use different
+/// SIDs to reduce the chances of cross-contamination.
+static BIO_FAKE_SID_BASE: i64 = 345600;
 
 const WEAK_UNLOCK_ENABLED: bool = true;
 const WEAK_UNLOCK_DISABLED: bool = false;
@@ -171,6 +174,8 @@ impl Drop for TestUser {
 
 #[test]
 fn test_auth_bound_timeout_with_gk() {
+    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 1;
+    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 2;
     type Barrier = BarrierReachedWithData<Option<i64>>;
     android_logger::init_once(
         android_logger::Config::default()
@@ -199,8 +204,8 @@ fn test_auth_bound_timeout_with_gk() {
             ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
         let params = AuthSetBuilder::new()
             .user_secure_id(gk_sid)
-            .user_secure_id(BIO_FAKE_SID1)
-            .user_secure_id(BIO_FAKE_SID2)
+            .user_secure_id(bio_fake_sid1)
+            .user_secure_id(bio_fake_sid2)
             .user_auth_type(HardwareAuthenticatorType::ANY)
             .auth_timeout(3)
             .algorithm(Algorithm::EC)
@@ -214,7 +219,7 @@ fn test_auth_bound_timeout_with_gk() {
                 &KeyDescriptor {
                     domain: Domain::APP,
                     nspace: -1,
-                    alias: Some("auth-bound-timeout".to_string()),
+                    alias: Some("auth-bound-timeout-1".to_string()),
                     blob: None,
                 },
                 None,
@@ -223,7 +228,7 @@ fn test_auth_bound_timeout_with_gk() {
                 b"entropy",
             )
             .context("key generation failed")?;
-        info!("A: created auth-timeout key {key:?}");
+        info!("A: created auth-timeout key {key:?} bound to sids {gk_sid}, {bio_fake_sid1}, {bio_fake_sid2}");
 
         // No HATs so cannot create an operation using the key.
         let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
@@ -279,7 +284,7 @@ fn test_auth_bound_timeout_with_gk() {
 
     // Lock and unlock to ensure super keys are already created.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
         .unwrap();
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
 
@@ -304,6 +309,9 @@ fn test_auth_bound_timeout_with_gk() {
 
 #[test]
 fn test_auth_bound_timeout_failure() {
+    let gk_fake_sid = GK_FAKE_SID_BASE + 1;
+    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 3;
+    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 4;
     android_logger::init_once(
         android_logger::Config::default()
             .with_tag("keystore2_client_tests")
@@ -323,8 +331,8 @@ fn test_auth_bound_timeout_failure() {
         let sec_level =
             ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
         let params = AuthSetBuilder::new()
-            .user_secure_id(BIO_FAKE_SID1)
-            .user_secure_id(BIO_FAKE_SID2)
+            .user_secure_id(bio_fake_sid1)
+            .user_secure_id(bio_fake_sid2)
             .user_auth_type(HardwareAuthenticatorType::ANY)
             .auth_timeout(3)
             .algorithm(Algorithm::EC)
@@ -338,7 +346,7 @@ fn test_auth_bound_timeout_failure() {
                 &KeyDescriptor {
                     domain: Domain::APP,
                     nspace: -1,
-                    alias: Some("auth-bound-timeout".to_string()),
+                    alias: Some("auth-bound-timeout-2".to_string()),
                     blob: None,
                 },
                 None,
@@ -347,7 +355,7 @@ fn test_auth_bound_timeout_failure() {
                 b"entropy",
             )
             .context("key generation failed")?;
-        info!("A: created auth-timeout key {key:?}");
+        info!("A: created auth-timeout key {key:?} bound to sids {bio_fake_sid1}, {bio_fake_sid2}");
 
         // No HATs so cannot create an operation using the key.
         let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
@@ -361,7 +369,12 @@ fn test_auth_bound_timeout_failure() {
         reader.recv();
 
         let result = sec_level.createOperation(&key, &params, UNFORCED);
-        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        expect!(result.is_err());
+        if get_vsr_api_level() >= 35 {
+            // Older devices may report an incorrect error code when presented with an invalid auth
+            // token.
+            expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
+        }
         info!("B: failed auth-bound operation (HAT is invalid) as expected {result:?}");
 
         writer.send(&BarrierReached {}); // B done.
@@ -395,10 +408,10 @@ fn test_auth_bound_timeout_failure() {
 
     // Lock and unlock to ensure super keys are already created.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
         .unwrap();
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(gk_fake_sid)).unwrap();
 
     info!("trigger child process action A and wait for completion");
     child_handle.send(&BarrierReached {});
@@ -406,7 +419,7 @@ fn test_auth_bound_timeout_failure() {
 
     // Unlock with password and a fake auth token that matches the key
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_bio_lskf_token(GK_FAKE_SID, BIO_FAKE_SID1)).unwrap();
+    auth_service.addAuthToken(&fake_bio_lskf_token(gk_fake_sid, bio_fake_sid1)).unwrap();
 
     info!("trigger child process action B and wait for completion");
     child_handle.send(&BarrierReached {});
@@ -421,6 +434,8 @@ fn test_auth_bound_timeout_failure() {
 
 #[test]
 fn test_auth_bound_per_op_with_gk() {
+    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 5;
+    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 6;
     type Barrier = BarrierReachedWithData<Option<i64>>;
     android_logger::init_once(
         android_logger::Config::default()
@@ -449,7 +464,7 @@ fn test_auth_bound_per_op_with_gk() {
             ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
         let params = AuthSetBuilder::new()
             .user_secure_id(gk_sid)
-            .user_secure_id(BIO_FAKE_SID1)
+            .user_secure_id(bio_fake_sid1)
             .user_auth_type(HardwareAuthenticatorType::ANY)
             .algorithm(Algorithm::EC)
             .purpose(KeyPurpose::SIGN)
@@ -462,7 +477,7 @@ fn test_auth_bound_per_op_with_gk() {
                 &KeyDescriptor {
                     domain: Domain::APP,
                     nspace: -1,
-                    alias: Some("auth-per-op".to_string()),
+                    alias: Some("auth-per-op-1".to_string()),
                     blob: None,
                 },
                 None,
@@ -471,7 +486,7 @@ fn test_auth_bound_per_op_with_gk() {
                 b"entropy",
             )
             .context("key generation failed")?;
-        info!("A: created auth-per-op key {key:?}");
+        info!("A: created auth-per-op key {key:?} bound to sids {gk_sid}, {bio_fake_sid1}");
 
         // We can create an operation using the key...
         let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
@@ -530,7 +545,7 @@ fn test_auth_bound_per_op_with_gk() {
 
     // Lock and unlock to ensure super keys are already created.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
         .unwrap();
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
 
@@ -554,8 +569,10 @@ fn test_auth_bound_per_op_with_gk() {
 }
 
 #[test]
-fn test_auth_bound_per_op_failure() {
-    type Barrier = BarrierReachedWithData<i64>;
+fn test_auth_bound_per_op_with_gk_failure() {
+    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 7;
+    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 8;
+    type Barrier = BarrierReachedWithData<Option<i64>>;
     android_logger::init_once(
         android_logger::Config::default()
             .with_tag("keystore2_client_tests")
@@ -566,17 +583,24 @@ fn test_auth_bound_per_op_failure() {
                          writer: &mut ChannelWriter<Barrier>|
           -> Result<(), run_as::Error> {
         // Now we're in a new process, wait to be notified before starting.
-        reader.recv();
+        let gk_sid: i64 = match reader.recv().0 {
+            Some(sid) => sid,
+            None => {
+                // There is no AIDL Gatekeeper available, so abandon the test.  It would be nice to
+                // know this before starting the child process, but finding it out requires Binder,
+                // which can't be used until after the child has forked.
+                return Ok(());
+            }
+        };
 
         // Action A: create a new auth-bound key which requires auth-per-operation (because
         // AUTH_TIMEOUT is not specified), and fail to finish an operation using it.
         let ks2 = get_keystore_service();
-
         let sec_level =
             ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
         let params = AuthSetBuilder::new()
-            .user_secure_id(GK_FAKE_SID)
-            .user_secure_id(BIO_FAKE_SID1)
+            .user_secure_id(gk_sid)
+            .user_secure_id(bio_fake_sid1)
             .user_auth_type(HardwareAuthenticatorType::ANY)
             .algorithm(Algorithm::EC)
             .purpose(KeyPurpose::SIGN)
@@ -589,7 +613,7 @@ fn test_auth_bound_per_op_failure() {
                 &KeyDescriptor {
                     domain: Domain::APP,
                     nspace: -1,
-                    alias: Some("auth-per-op".to_string()),
+                    alias: Some("auth-per-op-2".to_string()),
                     blob: None,
                 },
                 None,
@@ -598,7 +622,7 @@ fn test_auth_bound_per_op_failure() {
                 b"entropy",
             )
             .context("key generation failed")?;
-        info!("A: created auth-per-op key {key:?}");
+        info!("A: created auth-per-op key {key:?} bound to sids {gk_sid}, {bio_fake_sid1}");
 
         // We can create an operation using the key...
         let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
@@ -613,7 +637,7 @@ fn test_auth_bound_per_op_failure() {
         expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
         info!("A: failed auth-per-op op (no HAT) as expected {result:?}");
 
-        writer.send(&Barrier::new(0)); // A done.
+        writer.send(&Barrier::new(None)); // A done.
 
         // Action B: fail again when an irrelevant HAT is available.
         reader.recv();
@@ -629,7 +653,7 @@ fn test_auth_bound_per_op_failure() {
         expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
         info!("B: failed auth-per-op op (HAT is not per-op) as expected {result:?}");
 
-        writer.send(&Barrier::new(0)); // B done.
+        writer.send(&Barrier::new(None)); // B done.
 
         // Action C: start an operation and pass out the challenge
         reader.recv();
@@ -638,7 +662,7 @@ fn test_auth_bound_per_op_failure() {
             .expect("failed to create auth-per-op operation");
         let op = result.iOperation.context("no operation in result")?;
         info!("C: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
-        writer.send(&Barrier::new(result.operationChallenge.unwrap().challenge)); // C done.
+        writer.send(&Barrier::new(Some(result.operationChallenge.unwrap().challenge))); // C done.
 
         // Action D: finishing the operation still fails because the per-op HAT
         // is invalid (the HMAC signature is faked and so the secure world
@@ -647,7 +671,7 @@ fn test_auth_bound_per_op_failure() {
         let result = op.finish(Some(b"data"), None);
         expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
         info!("D: failed auth-per-op op (HAT is per-op but invalid) as expected {result:?}");
-        writer.send(&Barrier::new(0)); // D done.
+        writer.send(&Barrier::new(None)); // D done.
 
         Ok(())
     };
@@ -664,37 +688,43 @@ fn test_auth_bound_per_op_failure() {
     // user.
     let _ks2 = get_keystore_service();
     let user = TestUser::new();
+    if user.gk.is_none() {
+        // Can't run this test if there's no AIDL Gatekeeper.
+        child_handle.send(&Barrier::new(None));
+        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
+        return;
+    }
     let user_id = user.id;
     let auth_service = get_authorization();
 
     // Lock and unlock to ensure super keys are already created.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
         .unwrap();
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
 
     info!("trigger child process action A and wait for completion");
-    child_handle.send(&Barrier::new(0));
+    let gk_sid = user.gk_sid.unwrap();
+    child_handle.send(&Barrier::new(Some(gk_sid)));
     child_handle.recv_or_die();
 
     // Unlock with password and a fake auth token.
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(gk_sid)).unwrap();
 
     info!("trigger child process action B and wait for completion");
-    child_handle.send(&Barrier::new(0));
+    child_handle.send(&Barrier::new(None));
     child_handle.recv_or_die();
 
     info!("trigger child process action C and wait for completion");
-    child_handle.send(&Barrier::new(0));
-    let challenge = child_handle.recv_or_die().0;
+    child_handle.send(&Barrier::new(None));
+    let challenge = child_handle.recv_or_die().0.expect("no challenge");
 
     // Add a fake auth token with the challenge value.
-    auth_service.addAuthToken(&fake_lskf_token_with_challenge(GK_FAKE_SID, challenge)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token_with_challenge(gk_sid, challenge)).unwrap();
 
     info!("trigger child process action D and wait for completion");
-    child_handle.send(&Barrier::new(0));
+    child_handle.send(&Barrier::new(None));
     child_handle.recv_or_die();
 
     assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
@@ -702,6 +732,9 @@ fn test_auth_bound_per_op_failure() {
 
 #[test]
 fn test_unlocked_device_required() {
+    let gk_fake_sid = GK_FAKE_SID_BASE + 3;
+    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 9;
+    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 10;
     android_logger::init_once(
         android_logger::Config::default()
             .with_tag("keystore2_client_tests")
@@ -804,10 +837,10 @@ fn test_unlocked_device_required() {
 
     // Lock and unlock to ensure super keys are already created.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
         .unwrap();
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(gk_fake_sid)).unwrap();
 
     info!("trigger child process action A while unlocked and wait for completion");
     child_handle.send(&BarrierReached {});
@@ -815,7 +848,7 @@ fn test_unlocked_device_required() {
 
     // Move to locked and don't allow weak unlock, so super keys are wiped.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_DISABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
         .unwrap();
 
     info!("trigger child process action B while locked and wait for completion");
@@ -824,7 +857,7 @@ fn test_unlocked_device_required() {
 
     // Unlock with password => loads super key from database.
     auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
-    auth_service.addAuthToken(&fake_lskf_token(GK_FAKE_SID)).unwrap();
+    auth_service.addAuthToken(&fake_lskf_token(gk_fake_sid)).unwrap();
 
     info!("trigger child process action C while lskf-unlocked and wait for completion");
     child_handle.send(&BarrierReached {});
@@ -832,7 +865,7 @@ fn test_unlocked_device_required() {
 
     // Move to locked and allow weak unlock, then do a weak unlock.
     auth_service
-        .onDeviceLocked(user_id, &[BIO_FAKE_SID1, BIO_FAKE_SID2], WEAK_UNLOCK_ENABLED)
+        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_ENABLED)
         .unwrap();
     auth_service.onDeviceUnlocked(user_id, None).unwrap();
 
@@ -866,7 +899,7 @@ fn fake_bio_lskf_token(gk_sid: i64, bio_sid: i64) -> HardwareAuthToken {
         challenge: 0,
         userId: gk_sid,
         authenticatorId: bio_sid,
-        authenticatorType: HardwareAuthenticatorType::PASSWORD,
+        authenticatorType: HardwareAuthenticatorType::FINGERPRINT,
         timestamp: Timestamp { milliSeconds: 123 },
         mac: vec![1, 2, 3],
     }
diff --git a/keystore2/watchdog/Android.bp b/keystore2/watchdog/Android.bp
index 5074388c..9a99f10b 100644
--- a/keystore2/watchdog/Android.bp
+++ b/keystore2/watchdog/Android.bp
@@ -26,6 +26,7 @@ rust_defaults {
     crate_name: "watchdog_rs",
     srcs: ["src/lib.rs"],
     rustlibs: [
+        "libchrono",
         "liblog_rust",
     ],
 }
diff --git a/keystore2/watchdog/src/lib.rs b/keystore2/watchdog/src/lib.rs
index b4a1e0fd..f6a12918 100644
--- a/keystore2/watchdog/src/lib.rs
+++ b/keystore2/watchdog/src/lib.rs
@@ -64,6 +64,18 @@ struct Record {
     context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
 }
 
+impl Record {
+    // Return a string representation of the start time of the record.
+    //
+    // Times are hard. This may not be accurate (e.g. if the system clock has been modified since
+    // the watchdog started), but it's _really_ useful to get a starting wall time for overrunning
+    // watchdogs.
+    fn started_utc(&self) -> String {
+        let started_utc = chrono::Utc::now() - self.started.elapsed();
+        format!("{}", started_utc.format("%m-%d %H:%M:%S%.3f UTC"))
+    }
+}
+
 struct WatchdogState {
     state: State,
     thread: Option<thread::JoinHandle<()>>,
@@ -137,8 +149,13 @@ impl WatchdogState {
             .filter(|(_, r)| r.deadline.saturating_duration_since(now) == Duration::new(0, 0))
             .collect();
 
-        log::warn!("When extracting from a bug report, please include this header");
-        log::warn!("and all {} records below.", overdue_records.len());
+        log::warn!(
+            concat!(
+                "When extracting from a bug report, please include this header ",
+                "and all {} records below (to footer)"
+            ),
+            overdue_records.len()
+        );
 
         // Watch points can be nested, i.e., a single thread may have multiple armed
         // watch points. And the most recent on each thread (thread recent) is closest to the point
@@ -169,9 +186,10 @@ impl WatchdogState {
                 match &r.context {
                     Some(ctx) => {
                         log::warn!(
-                            "{:?} {} Pending: {:?} Overdue {:?} for {:?}",
+                            "{:?} {} Started: {} Pending: {:?} Overdue {:?} for {:?}",
                             i.tid,
                             i.id,
+                            r.started_utc(),
                             r.started.elapsed(),
                             r.deadline.elapsed(),
                             ctx
@@ -179,9 +197,10 @@ impl WatchdogState {
                     }
                     None => {
                         log::warn!(
-                            "{:?} {} Pending: {:?} Overdue {:?}",
+                            "{:?} {} Started: {} Pending: {:?} Overdue {:?}",
                             i.tid,
                             i.id,
+                            r.started_utc(),
                             r.started.elapsed(),
                             r.deadline.elapsed()
                         );
@@ -200,17 +219,19 @@ impl WatchdogState {
             if timeout_left == Duration::new(0, 0) {
                 match &record.context {
                     Some(ctx) => log::info!(
-                        "Watchdog complete for: {:?} {} Pending: {:?} Overdue {:?} for {:?}",
+                        "Watchdog complete for: {:?} {} Started: {} Pending: {:?} Overdue {:?} for {:?}",
                         index.tid,
                         index.id,
+                        record.started_utc(),
                         record.started.elapsed(),
                         record.deadline.elapsed(),
                         ctx
                     ),
                     None => log::info!(
-                        "Watchdog complete for: {:?} {} Pending: {:?} Overdue {:?}",
+                        "Watchdog complete for: {:?} {} Started: {} Pending: {:?} Overdue {:?}",
                         index.tid,
                         index.id,
+                        record.started_utc(),
                         record.started.elapsed(),
                         record.deadline.elapsed()
                     ),
diff --git a/prng_seeder/src/main.rs b/prng_seeder/src/main.rs
index d112d619..c6adfd4d 100644
--- a/prng_seeder/src/main.rs
+++ b/prng_seeder/src/main.rs
@@ -69,11 +69,11 @@ fn get_socket(path: &Path) -> Result<UnixListener> {
 }
 
 fn setup() -> Result<(ConditionerBuilder, UnixListener)> {
+    configure_logging()?;
+    let cli = Cli::try_parse()?;
     // SAFETY: nobody has taken ownership of the inherited FDs yet.
     unsafe { rustutils::inherited_fd::init_once() }
         .context("In setup, failed to own inherited FDs")?;
-    configure_logging()?;
-    let cli = Cli::try_parse()?;
     // SAFETY: Nothing else sets the signal handler, so either it was set here or it is the default.
     unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }
         .context("In setup, setting SIGPIPE to SIG_IGN")?;
diff --git a/provisioner/rkp_factory_extraction_lib.h b/provisioner/rkp_factory_extraction_lib.h
index 3515f489..f6f21f5a 100644
--- a/provisioner/rkp_factory_extraction_lib.h
+++ b/provisioner/rkp_factory_extraction_lib.h
@@ -33,6 +33,18 @@ std::unordered_set<std::string> parseCommaDelimited(const std::string& input);
 // Challenge size must be between 32 and 64 bytes inclusive.
 constexpr size_t kChallengeSize = 64;
 
+// How CSRs should be validated when the rkp_factory_extraction_tool's "self_test"
+// flag is set to "true".
+struct CsrValidationConfig {
+    // Names of IRemotelyProvisionedComponent instances for which degenerate DICE
+    // chains are allowed.
+    std::unordered_set<std::string>* allow_degenerate_irpc_names;
+
+    // Names of IRemotelyProvisionedComponent instances for which UDS certificate
+    // chains are required to be present in the CSR.
+    std::unordered_set<std::string>* require_uds_certs_irpc_names;
+};
+
 // Contains a the result of an operation that should return cborData on success.
 // Returns an an error message and null cborData on error.
 template <typename T> struct CborResult {
diff --git a/provisioner/rkp_factory_extraction_lib_test.cpp b/provisioner/rkp_factory_extraction_lib_test.cpp
index 9bfb25e8..e21ef938 100644
--- a/provisioner/rkp_factory_extraction_lib_test.cpp
+++ b/provisioner/rkp_factory_extraction_lib_test.cpp
@@ -61,6 +61,77 @@ std::ostream& operator<<(std::ostream& os, const Item* item) {
 
 }  // namespace cppbor
 
+inline const std::vector<uint8_t> kCsrWithoutUdsCerts{
+    0x85, 0x01, 0xa0, 0x82, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0xb8, 0x36,
+    0xbb, 0x1e, 0x07, 0x85, 0x02, 0xde, 0xdb, 0x91, 0x38, 0x5d, 0xc7, 0xf8, 0x59, 0xa9, 0x4f, 0x50,
+    0xee, 0x2a, 0x3f, 0xa5, 0x5f, 0xaa, 0xa1, 0x8e, 0x46, 0x84, 0xb8, 0x3b, 0x4b, 0x6d, 0x22, 0x58,
+    0x20, 0xa1, 0xc1, 0xd8, 0xa5, 0x9d, 0x1b, 0xce, 0x8c, 0x65, 0x10, 0x8d, 0xcf, 0xa1, 0xf4, 0x91,
+    0x10, 0x09, 0xfb, 0xb0, 0xc5, 0xb4, 0x01, 0x75, 0x72, 0xb4, 0x44, 0xaa, 0x23, 0x13, 0xe1, 0xe9,
+    0xe5, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0x04, 0xa9, 0x01, 0x66, 0x69, 0x73, 0x73,
+    0x75, 0x65, 0x72, 0x02, 0x67, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x00, 0x47, 0x44,
+    0x50, 0x58, 0x20, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
+    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
+    0x55, 0x55, 0x55, 0x3a, 0x00, 0x47, 0x44, 0x52, 0x58, 0x20, 0xb8, 0x96, 0x54, 0xe2, 0x2c, 0xa4,
+    0xd2, 0x4a, 0x9c, 0x0e, 0x45, 0x11, 0xc8, 0xf2, 0x63, 0xf0, 0x66, 0x0d, 0x2e, 0x20, 0x48, 0x96,
+    0x90, 0x14, 0xf4, 0x54, 0x63, 0xc4, 0xf4, 0x39, 0x30, 0x38, 0x3a, 0x00, 0x47, 0x44, 0x53, 0x55,
+    0xa1, 0x3a, 0x00, 0x01, 0x11, 0x71, 0x6e, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
+    0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x00, 0x47, 0x44, 0x54, 0x58, 0x20, 0x55, 0x55, 0x55, 0x55,
+    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
+    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x3a, 0x00, 0x47, 0x44,
+    0x56, 0x41, 0x01, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x4d, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20,
+    0x01, 0x21, 0x58, 0x20, 0x91, 0xdc, 0x49, 0x60, 0x0d, 0x22, 0xf6, 0x28, 0x14, 0xaf, 0xab, 0xa5,
+    0x9d, 0x4f, 0x26, 0xac, 0xf9, 0x99, 0xe7, 0xe1, 0xc9, 0xb7, 0x5d, 0x36, 0x21, 0x9d, 0x00, 0x47,
+    0x63, 0x28, 0x79, 0xa7, 0x22, 0x58, 0x20, 0x13, 0x77, 0x51, 0x7f, 0x6a, 0xca, 0xa0, 0x50, 0x79,
+    0x52, 0xb4, 0x6b, 0xd9, 0xb1, 0x3a, 0x1c, 0x9f, 0x91, 0x97, 0x60, 0xc1, 0x4b, 0x43, 0x5e, 0x45,
+    0xd3, 0x0b, 0xa4, 0xbb, 0xc7, 0x27, 0x39, 0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20, 0x58, 0x40,
+    0x88, 0xbd, 0xf9, 0x82, 0x04, 0xfe, 0xa6, 0xfe, 0x82, 0x94, 0xa3, 0xe9, 0x10, 0x91, 0xb5, 0x2e,
+    0xa1, 0x62, 0x68, 0xa5, 0x3d, 0xab, 0xdb, 0xa5, 0x87, 0x2a, 0x97, 0x26, 0xb8, 0xd4, 0x60, 0x1a,
+    0xf1, 0x3a, 0x45, 0x72, 0x77, 0xd4, 0xeb, 0x2b, 0xa4, 0x48, 0x93, 0xba, 0xae, 0x79, 0x35, 0x57,
+    0x66, 0x54, 0x9d, 0x8e, 0xbd, 0xb0, 0x87, 0x5f, 0x8c, 0xf9, 0x04, 0xa3, 0xa7, 0x00, 0xf1, 0x21,
+    0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x02, 0x0f, 0x82, 0x58, 0x20, 0x01, 0x02, 0x03, 0x04,
+    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
+    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x59, 0x01, 0xe9, 0x84,
+    0x03, 0x67, 0x6b, 0x65, 0x79, 0x6d, 0x69, 0x6e, 0x74, 0xae, 0x65, 0x62, 0x72, 0x61, 0x6e, 0x64,
+    0x66, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64, 0x01, 0x65, 0x6d,
+    0x6f, 0x64, 0x65, 0x6c, 0x65, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x66, 0x64, 0x65, 0x76, 0x69, 0x63,
+    0x65, 0x66, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x67, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
+    0x65, 0x70, 0x69, 0x78, 0x65, 0x6c, 0x68, 0x76, 0x62, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x65,
+    0x67, 0x72, 0x65, 0x65, 0x6e, 0x6a, 0x6f, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
+    0x62, 0x31, 0x32, 0x6c, 0x6d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x65, 0x72,
+    0x66, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x6d, 0x76, 0x62, 0x6d, 0x65, 0x74, 0x61, 0x5f, 0x64,
+    0x69, 0x67, 0x65, 0x73, 0x74, 0x4f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
+    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5f, 0x6c,
+    0x65, 0x76, 0x65, 0x6c, 0x63, 0x74, 0x65, 0x65, 0x70, 0x62, 0x6f, 0x6f, 0x74, 0x5f, 0x70, 0x61,
+    0x74, 0x63, 0x68, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x1a, 0x01, 0x34, 0x8c, 0x62, 0x70, 0x62,
+    0x6f, 0x6f, 0x74, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x66,
+    0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x72, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x61,
+    0x74, 0x63, 0x68, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x1a, 0x01, 0x34, 0x8c, 0x61, 0x72, 0x76,
+    0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x70, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x6c, 0x65, 0x76, 0x65,
+    0x6c, 0x1a, 0x01, 0x34, 0x8c, 0x63, 0x82, 0xa6, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58,
+    0x20, 0x85, 0xcd, 0xd8, 0x8c, 0x35, 0x50, 0x11, 0x9c, 0x44, 0x24, 0xa7, 0xf1, 0xbf, 0x75, 0x6e,
+    0x7c, 0xab, 0x8c, 0x86, 0xfa, 0x23, 0x95, 0x2c, 0x11, 0xaf, 0xf9, 0x52, 0x80, 0x8f, 0x45, 0x43,
+    0x40, 0x22, 0x58, 0x20, 0xec, 0x4e, 0x0d, 0x5a, 0x81, 0xe8, 0x06, 0x12, 0x18, 0xa8, 0x10, 0x74,
+    0x6e, 0x56, 0x33, 0x11, 0x7d, 0x74, 0xff, 0x49, 0xf7, 0x38, 0x32, 0xda, 0xf4, 0x60, 0xaa, 0x19,
+    0x64, 0x29, 0x58, 0xbe, 0x23, 0x58, 0x21, 0x00, 0xa6, 0xd1, 0x85, 0xdb, 0x8b, 0x15, 0x84, 0xde,
+    0x34, 0xf2, 0xe3, 0xee, 0x73, 0x8b, 0x85, 0x57, 0xc1, 0xa3, 0x5d, 0x3f, 0x95, 0x14, 0xd3, 0x74,
+    0xfc, 0x73, 0x51, 0x7f, 0xe7, 0x1b, 0x30, 0xbb, 0xa6, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21,
+    0x58, 0x20, 0x96, 0x6c, 0x16, 0x6c, 0x4c, 0xa7, 0x73, 0x64, 0x9a, 0x34, 0x88, 0x75, 0xf4, 0xdc,
+    0xf3, 0x93, 0xb2, 0xf1, 0xd7, 0xfd, 0xe3, 0x11, 0xcf, 0x6b, 0xee, 0x26, 0xa4, 0xc5, 0xeb, 0xa5,
+    0x33, 0x24, 0x22, 0x58, 0x20, 0xe0, 0x33, 0xe8, 0x53, 0xb2, 0x65, 0x1e, 0x33, 0x2a, 0x61, 0x9a,
+    0x7a, 0xf4, 0x5f, 0x40, 0x0f, 0x80, 0x4a, 0x38, 0xff, 0x5d, 0x3c, 0xa3, 0x82, 0x36, 0x1e, 0x9d,
+    0x93, 0xd9, 0x48, 0xaa, 0x0a, 0x23, 0x58, 0x20, 0x5e, 0xe5, 0x8f, 0x9a, 0x8c, 0xd3, 0xf4, 0xc0,
+    0xf7, 0x08, 0x27, 0x5f, 0x8f, 0x77, 0x12, 0x36, 0x7b, 0x6d, 0xf7, 0x65, 0xd4, 0xcc, 0x63, 0xdc,
+    0x28, 0x35, 0x33, 0x27, 0x5d, 0x28, 0xc9, 0x9d, 0x58, 0x40, 0x6c, 0xfa, 0xc9, 0xc0, 0xdf, 0x0e,
+    0xe4, 0x17, 0x58, 0x06, 0xea, 0xf9, 0x88, 0x9e, 0x27, 0xa0, 0x89, 0x17, 0xa8, 0x1a, 0xe6, 0x0c,
+    0x5e, 0x85, 0xa1, 0x13, 0x20, 0x86, 0x14, 0x2e, 0xd6, 0xae, 0xfb, 0xc1, 0xb6, 0x59, 0x66, 0x83,
+    0xd2, 0xf4, 0xc8, 0x7a, 0x30, 0x0c, 0x6b, 0x53, 0x8b, 0x76, 0x06, 0xcb, 0x1b, 0x0f, 0xc3, 0x51,
+    0x71, 0x52, 0xd1, 0xe3, 0x2a, 0xbc, 0x53, 0x16, 0x46, 0x49, 0xa1, 0x6b, 0x66, 0x69, 0x6e, 0x67,
+    0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x78, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x31, 0x2f,
+    0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x31, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x31,
+    0x3a, 0x31, 0x31, 0x2f, 0x69, 0x64, 0x2f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x38, 0x30, 0x35, 0x2e,
+    0x34, 0x32, 0x3a, 0x75, 0x73, 0x65, 0x72, 0x2f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d,
+    0x6b, 0x65, 0x79, 0x73};
+
 std::string toBase64(const std::vector<uint8_t>& buffer) {
     size_t base64Length;
     int rc = EVP_EncodedLength(&base64Length, buffer.size());
@@ -184,7 +255,7 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV2Hal) {
     std::vector<uint8_t> eekChain;
     std::vector<uint8_t> challenge;
 
-    // Set up mock, then call getSCsr
+    // Set up mock, then call getCsr
     auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
     EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
         hwInfo->versionNumber = 2;
@@ -295,12 +366,7 @@ TEST(LibRkpFactoryExtractionTests, GetCsrWithV3Hal) {
 }
 
 TEST(LibRkpFactoryExtractionTests, requireUdsCerts) {
-    const std::vector<uint8_t> kCsr = Array()
-                                          .add(1 /* version */)
-                                          .add(Map() /* UdsCerts */)
-                                          .add(Array() /* DiceCertChain */)
-                                          .add(Array() /* SignedData */)
-                                          .encode();
+    const std::vector<uint8_t> csrEncoded = kCsrWithoutUdsCerts;
     std::vector<uint8_t> challenge;
 
     // Set up mock, then call getCsr
@@ -313,23 +379,18 @@ TEST(LibRkpFactoryExtractionTests, requireUdsCerts) {
                 generateCertificateRequestV2(IsEmpty(),   // keysToSign
                                              _,           // challenge
                                              NotNull()))  // _aidl_return
-        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(kCsr),
+        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(csrEncoded),
                         Return(ByMove(ScopedAStatus::ok()))));
 
     auto [csr, csrErrMsg] =
-        getCsr("mock component name", mockRpc.get(),
+        getCsr("default", mockRpc.get(),
                /*selfTest=*/true, /*allowDegenerate=*/false, /*requireUdsCerts=*/true);
     ASSERT_EQ(csr, nullptr);
-    ASSERT_THAT(csrErrMsg, testing::HasSubstr("UdsCerts must not be empty"));
+    ASSERT_THAT(csrErrMsg, testing::HasSubstr("UdsCerts are required"));
 }
 
 TEST(LibRkpFactoryExtractionTests, dontRequireUdsCerts) {
-    const std::vector<uint8_t> kCsr = Array()
-                                          .add(1 /* version */)
-                                          .add(Map() /* UdsCerts */)
-                                          .add(Array() /* DiceCertChain */)
-                                          .add(Array() /* SignedData */)
-                                          .encode();
+    const std::vector<uint8_t> csrEncoded = kCsrWithoutUdsCerts;
     std::vector<uint8_t> challenge;
 
     // Set up mock, then call getCsr
@@ -342,14 +403,14 @@ TEST(LibRkpFactoryExtractionTests, dontRequireUdsCerts) {
                 generateCertificateRequestV2(IsEmpty(),   // keysToSign
                                              _,           // challenge
                                              NotNull()))  // _aidl_return
-        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(kCsr),
+        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(csrEncoded),
                         Return(ByMove(ScopedAStatus::ok()))));
 
     auto [csr, csrErrMsg] =
-        getCsr("mock component name", mockRpc.get(),
+        getCsr("default", mockRpc.get(),
                /*selfTest=*/true, /*allowDegenerate=*/false, /*requireUdsCerts=*/false);
     ASSERT_EQ(csr, nullptr);
-    ASSERT_THAT(csrErrMsg, testing::Not(testing::HasSubstr("UdsCerts must not be empty")));
+    ASSERT_THAT(csrErrMsg, testing::HasSubstr("challenges do not match"));
 }
 
 TEST(LibRkpFactoryExtractionTests, parseCommaDelimitedString) {
@@ -362,4 +423,4 @@ TEST(LibRkpFactoryExtractionTests, parseCommaDelimitedString) {
     ASSERT_TRUE(rpcSet.count("avf") == 1);
     ASSERT_TRUE(rpcSet.count("strongbox") == 1);
     ASSERT_TRUE(rpcSet.count("Strongbox") == 1);
-}
\ No newline at end of file
+}
diff --git a/provisioner/rkp_factory_extraction_tool.cpp b/provisioner/rkp_factory_extraction_tool.cpp
index 599b52a4..f65e0ae8 100644
--- a/provisioner/rkp_factory_extraction_tool.cpp
+++ b/provisioner/rkp_factory_extraction_tool.cpp
@@ -40,17 +40,20 @@ using aidl::android::hardware::security::keymint::remote_prov::RKPVM_INSTANCE_NA
 
 DEFINE_string(output_format, "build+csr", "How to format the output. Defaults to 'build+csr'.");
 DEFINE_bool(self_test, true,
-            "If true, this tool performs a self-test, validating the payload for correctness. "
-            "This checks that the device on the factory line is producing valid output "
-            "before attempting to upload the output to the device info service.");
-DEFINE_bool(allow_degenerate, true,
-            "If true, self_test validation will allow degenerate DICE chains in the CSR.");
+            "Whether to validate the output for correctness. If enabled, this checks that the "
+            "device on the factory line is producing valid output before attempting to upload the "
+            "output to the device info service. Defaults to true.");
+DEFINE_string(allow_degenerate, "",
+              "Comma-delimited list of names of IRemotelyProvisionedComponent instances for which "
+              "self_test validation allows degenerate DICE chains in the CSR. Example: "
+              "avf,default,strongbox. Defaults to the empty string.");
 DEFINE_string(serialno_prop, "ro.serialno",
-              "The property of getting serial number. Defaults to 'ro.serialno'.");
+              "System property from which the serial number should be retrieved. Defaults to "
+              "'ro.serialno'.");
 DEFINE_string(require_uds_certs, "",
-              "The comma-delimited names of remotely provisioned "
-              "components whose UDS certificate chains are required to be present in the CSR. "
-              "Example: avf,default,strongbox");
+              "Comma-delimited list of names of IRemotelyProvisionedComponent instances for which "
+              "UDS certificate chains are required to be present in the CSR. Example: "
+              "avf,default,strongbox. Defaults to the empty string.");
 
 namespace {
 
@@ -84,7 +87,7 @@ void writeOutput(const std::string instance_name, const cppbor::Array& csr) {
 }
 
 void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisionedComponent* irpc,
-                   bool requireUdsCerts) {
+                   bool allowDegenerate, bool requireUdsCerts) {
     auto fullName = getFullServiceName(descriptor, name);
     // AVF RKP HAL is not always supported, so we need to check if it is supported before
     // generating the CSR.
@@ -96,8 +99,7 @@ void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisione
         }
     }
 
-    auto [request, errMsg] =
-        getCsr(name, irpc, FLAGS_self_test, FLAGS_allow_degenerate, requireUdsCerts);
+    auto [request, errMsg] = getCsr(name, irpc, FLAGS_self_test, allowDegenerate, requireUdsCerts);
     if (!request) {
         std::cerr << "Unable to build CSR for '" << fullName << "': " << errMsg << ", exiting."
                   << std::endl;
@@ -131,11 +133,25 @@ void getCsrForInstance(const char* name, void* context) {
         exit(-1);
     }
 
-    auto requireUdsCertsRpcNames = static_cast<std::unordered_set<std::string>*>(context);
-    auto requireUdsCerts = requireUdsCertsRpcNames->count(name) != 0;
-    requireUdsCertsRpcNames->erase(name);
+    auto csrValidationConfig = static_cast<CsrValidationConfig*>(context);
+    bool allowDegenerateFieldNotNull = csrValidationConfig->allow_degenerate_irpc_names != nullptr;
+    bool allowDegenerate = allowDegenerateFieldNotNull &&
+                           csrValidationConfig->allow_degenerate_irpc_names->count(name) > 0;
+    bool requireUdsCertsFieldNotNull = csrValidationConfig->require_uds_certs_irpc_names != nullptr;
+    bool requireUdsCerts = requireUdsCertsFieldNotNull &&
+                           csrValidationConfig->require_uds_certs_irpc_names->count(name) > 0;
+
+    // Record the fact that this IRemotelyProvisionedComponent instance was found by removing it
+    // from the sets in the context.
+    if (allowDegenerateFieldNotNull) {
+        csrValidationConfig->allow_degenerate_irpc_names->erase(name);
+    }
+    if (requireUdsCertsFieldNotNull) {
+        csrValidationConfig->require_uds_certs_irpc_names->erase(name);
+    }
+
     getCsrForIRpc(IRemotelyProvisionedComponent::descriptor, name, rkpService.get(),
-                  requireUdsCerts);
+                  allowDegenerate, requireUdsCerts);
 }
 
 }  // namespace
@@ -143,21 +159,38 @@ void getCsrForInstance(const char* name, void* context) {
 int main(int argc, char** argv) {
     gflags::ParseCommandLineFlags(&argc, &argv, /*remove_flags=*/true);
 
-    auto requireUdsCertsRpcNames = parseCommaDelimited(FLAGS_require_uds_certs);
+    auto allowDegenerateIRpcNames = parseCommaDelimited(FLAGS_allow_degenerate);
+    auto requireUdsCertsIRpcNames = parseCommaDelimited(FLAGS_require_uds_certs);
+    CsrValidationConfig csrValidationConfig = {
+        .allow_degenerate_irpc_names = &allowDegenerateIRpcNames,
+        .require_uds_certs_irpc_names = &requireUdsCertsIRpcNames,
+    };
 
     AServiceManager_forEachDeclaredInstance(IRemotelyProvisionedComponent::descriptor,
-                                            &requireUdsCertsRpcNames, getCsrForInstance);
+                                            &csrValidationConfig, getCsrForInstance);
 
     // Append drm CSRs
     for (auto const& [name, irpc] : android::mediadrm::getDrmRemotelyProvisionedComponents()) {
-        auto requireUdsCerts = requireUdsCertsRpcNames.count(name) != 0;
-        requireUdsCertsRpcNames.erase(name);
-        getCsrForIRpc(IDrmFactory::descriptor, name.c_str(), irpc.get(), requireUdsCerts);
+        bool allowDegenerate = allowDegenerateIRpcNames.count(name) != 0;
+        allowDegenerateIRpcNames.erase(name);
+        auto requireUdsCerts = requireUdsCertsIRpcNames.count(name) != 0;
+        requireUdsCertsIRpcNames.erase(name);
+        getCsrForIRpc(IDrmFactory::descriptor, name.c_str(), irpc.get(), allowDegenerate,
+                      requireUdsCerts);
     }
 
-    for (auto const& rpcName : requireUdsCertsRpcNames) {
-        std::cerr << "WARNING: You requested to enforce the presence of UDS Certs for '" << rpcName
-                  << "', but no Remotely Provisioned Component had that name." << std::endl;
+    // Print a warning for IRemotelyProvisionedComponent instance names that were passed
+    // in as parameters to the "require_uds_certs" and "allow_degenerate" flags but were
+    // ignored because no instances with those names were found.
+    for (const auto& irpcName : allowDegenerateIRpcNames) {
+        std::cerr << "WARNING: You requested special handling of 'self_test' validation checks "
+                  << "for '" << irpcName << "' via the 'allow_degenerate' flag but no such "
+                  << "IRemotelyProvisionedComponent instance exists." << std::endl;
+    }
+    for (const auto& irpcName : requireUdsCertsIRpcNames) {
+        std::cerr << "WARNING: You requested special handling of 'self_test' validation checks "
+                  << "for '" << irpcName << "' via the 'require_uds_certs' flag but no such "
+                  << "IRemotelyProvisionedComponent instance exists." << std::endl;
     }
 
     return 0;
```

