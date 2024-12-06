```diff
diff --git a/aidl_service.cpp b/aidl_service.cpp
index 3d18669..f3d9c93 100644
--- a/aidl_service.cpp
+++ b/aidl_service.cpp
@@ -33,23 +33,20 @@
 #include <binder/Status.h>
 #include <utils/Errors.h>
 
+#include <android/hardware/security/see/storage/Availability.h>
 #include <android/hardware/security/see/storage/BnDir.h>
 #include <android/hardware/security/see/storage/BnFile.h>
 #include <android/hardware/security/see/storage/BnSecureStorage.h>
 #include <android/hardware/security/see/storage/BnStorageSession.h>
 #include <android/hardware/security/see/storage/CreationMode.h>
-#include <android/hardware/security/see/storage/DeleteOptions.h>
-#include <android/hardware/security/see/storage/FileAvailability.h>
-#include <android/hardware/security/see/storage/FileIntegrity.h>
 #include <android/hardware/security/see/storage/FileMode.h>
-#include <android/hardware/security/see/storage/FileProperties.h>
+#include <android/hardware/security/see/storage/Filesystem.h>
 #include <android/hardware/security/see/storage/IDir.h>
 #include <android/hardware/security/see/storage/IFile.h>
 #include <android/hardware/security/see/storage/ISecureStorage.h>
 #include <android/hardware/security/see/storage/IStorageSession.h>
+#include <android/hardware/security/see/storage/Integrity.h>
 #include <android/hardware/security/see/storage/OpenOptions.h>
-#include <android/hardware/security/see/storage/ReadIntegrity.h>
-#include <android/hardware/security/see/storage/RenameOptions.h>
 
 #include "client.h"
 #include "client_session.h"
@@ -61,23 +58,20 @@ using ::android::RpcSession;
 using ::android::sp;
 using ::android::wp;
 using ::android::binder::Status;
+using ::android::hardware::security::see::storage::Availability;
 using ::android::hardware::security::see::storage::BnDir;
 using ::android::hardware::security::see::storage::BnFile;
 using ::android::hardware::security::see::storage::BnSecureStorage;
 using ::android::hardware::security::see::storage::BnStorageSession;
 using ::android::hardware::security::see::storage::CreationMode;
-using ::android::hardware::security::see::storage::DeleteOptions;
-using ::android::hardware::security::see::storage::FileAvailability;
-using ::android::hardware::security::see::storage::FileIntegrity;
 using ::android::hardware::security::see::storage::FileMode;
-using ::android::hardware::security::see::storage::FileProperties;
+using ::android::hardware::security::see::storage::Filesystem;
 using ::android::hardware::security::see::storage::IDir;
 using ::android::hardware::security::see::storage::IFile;
+using ::android::hardware::security::see::storage::Integrity;
 using ::android::hardware::security::see::storage::ISecureStorage;
 using ::android::hardware::security::see::storage::IStorageSession;
 using ::android::hardware::security::see::storage::OpenOptions;
-using ::android::hardware::security::see::storage::ReadIntegrity;
-using ::android::hardware::security::see::storage::RenameOptions;
 
 #define SS_ERR(args...) fprintf(stderr, "ss-aidl: " args)
 
@@ -120,7 +114,7 @@ static Status status_from_storage_err(storage_err err) {
     case storage_err::STORAGE_ERR_FS_REPAIRED:
         // TODO: Distinguish rolled back vs reset; catch other tampering
         return Status::fromServiceSpecificError(
-                ISecureStorage::ERR_FS_ROLLED_BACK);
+                ISecureStorage::ERR_FS_TAMPERED);
     default:
         return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION,
                                          "Unknown error code.");
@@ -138,41 +132,40 @@ static file_create_mode create_mode(CreationMode mode) {
     }
 }
 
-static Status get_fs(const FileProperties& properties,
+static Status get_fs(const Filesystem& filesystem,
                      storage_aidl_filesystem* out) {
-    switch (properties.integrity) {
-    case FileIntegrity::TAMPER_PROOF_AT_REST: {
+    switch (filesystem.integrity) {
+    case Integrity::TAMPER_PROOF_AT_REST: {
         // TP is persistent and available before userdata
         *out = STORAGE_AIDL_TP;
         break;
     }
-    case FileIntegrity::TAMPER_DETECT:
-    case FileIntegrity::TAMPER_DETECT_IGNORE_RESET: {
-        switch (properties.availability) {
-        case FileAvailability::BEFORE_USERDATA: {
-            if (properties.persistent) {
+    case Integrity::TAMPER_DETECT: {
+        switch (filesystem.availability) {
+        case Availability::BEFORE_USERDATA: {
+            if (filesystem.persistent) {
                 return Status::fromExceptionCode(
                         Status::EX_UNSUPPORTED_OPERATION,
-                        "Unsupported FileProperties: TDEA does not guarantee persistence");
+                        "Unsupported Filesystem properties: TDEA does not guarantee persistence");
             }
             *out = STORAGE_AIDL_TDEA;
             break;
         }
-        case FileAvailability::AFTER_USERDATA: {
-            *out = properties.persistent ? STORAGE_AIDL_TDP : STORAGE_AIDL_TD;
+        case Availability::AFTER_USERDATA: {
+            *out = filesystem.persistent ? STORAGE_AIDL_TDP : STORAGE_AIDL_TD;
             break;
         }
         default:
             return Status::fromExceptionCode(
                     Status::EX_UNSUPPORTED_OPERATION,
-                    "Unsupported FileProperties: Unknown FileAvailability value");
+                    "Unsupported Filesystem properties: Unknown Availability value");
         }
         break;
     }
     default:
         return Status::fromExceptionCode(
                 Status::EX_UNSUPPORTED_OPERATION,
-                "Unsupported FileProperties: Unknown FileIntegrity value");
+                "Unsupported Filesystem properties: Unknown Integrity value");
     }
     return Status::ok();
 }
@@ -204,9 +197,8 @@ private:
 
 class Dir : public BnDir {
 public:
-    Dir(std::weak_ptr<StorageClientSession> session, ReadIntegrity integrity)
+    Dir(std::weak_ptr<StorageClientSession> session)
             : session_(std::move(session)),
-              integrity_(integrity),
               last_state_(storage_file_list_flag::STORAGE_FILE_LIST_START),
               last_name_() {}
 
@@ -280,15 +272,13 @@ private:
 
     storage_op_flags op_flags() {
         return storage_op_flags{
-                // TODO: support acking reset only
-                .allow_repaired = integrity_ == ReadIntegrity::IGNORE_ROLLBACK,
+                .allow_repaired = false,
                 .complete_transaction = false,
                 .update_checkpoint = false,
         };
     }
 
     std::weak_ptr<StorageClientSession> session_;
-    ReadIntegrity integrity_;
 
     enum storage_file_list_flag last_state_;
     std::string last_name_;
@@ -298,16 +288,10 @@ class File : public BnFile {
 public:
     File(std::weak_ptr<StorageClientSession> session,
          uint32_t file_handle,
-         FileMode access_mode,
-         ReadIntegrity integrity,
-         bool allow_writes_during_ab_update)
+         FileMode access_mode)
             : session_(std::move(session)),
               file_handle_(file_handle),
-              access_mode_(access_mode),
-              integrity_(integrity),
-              allow_writes_during_ab_update_(allow_writes_during_ab_update) {
-        assert(!allow_writes_during_ab_update_);
-    }
+              access_mode_(access_mode) {}
 
     ~File() {
         std::shared_ptr<StorageClientSession> session = session_.lock();
@@ -482,8 +466,7 @@ public:
 private:
     storage_op_flags op_flags() {
         return storage_op_flags{
-                // TODO: support acking reset only
-                .allow_repaired = integrity_ == ReadIntegrity::IGNORE_ROLLBACK,
+                .allow_repaired = false,
                 .complete_transaction = false,
                 .update_checkpoint = false,
         };
@@ -492,8 +475,6 @@ private:
     std::weak_ptr<StorageClientSession> session_;
     uint32_t file_handle_;
     FileMode access_mode_;
-    ReadIntegrity integrity_;
-    bool allow_writes_during_ab_update_;
 };
 
 class StorageSession : public BnStorageSession {
@@ -507,11 +488,6 @@ public:
     Status openFile(const std::string& file_name,
                     const OpenOptions& options,
                     sp<IFile>* out) final {
-        if (options.allowWritesDuringAbUpdate) {
-            return Status::fromExceptionCode(
-                    Status::EX_UNSUPPORTED_OPERATION,
-                    "Unsupported option: allowWritesDuringAbUpdate");
-        }
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
             return Status::fromExceptionCode(
@@ -524,9 +500,7 @@ public:
                 client_session, file_name.data(), file_name.size(),
                 create_mode(options.createMode), options.truncateOnOpen,
                 storage_op_flags{
-                        // TODO: support acking reset only
-                        .allow_repaired = options.readIntegrity ==
-                                          ReadIntegrity::IGNORE_ROLLBACK,
+                        .allow_repaired = false,
                         .complete_transaction = false,
                         .update_checkpoint = false,
                 },
@@ -535,19 +509,11 @@ public:
             return status_from_storage_err(err);
         }
 
-        *out = sp<File>::make(session_, file_handle, options.accessMode,
-                              options.readIntegrity,
-                              options.allowWritesDuringAbUpdate);
+        *out = sp<File>::make(session_, file_handle, options.accessMode);
         return Status::ok();
     }
 
-    Status deleteFile(const std::string& file_name,
-                      const DeleteOptions& options) final {
-        if (options.allowWritesDuringAbUpdate) {
-            return Status::fromExceptionCode(
-                    Status::EX_UNSUPPORTED_OPERATION,
-                    "Unsupported option: allowWritesDuringAbUpdate");
-        }
+    Status deleteFile(const std::string& file_name) final {
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
             return Status::fromExceptionCode(
@@ -558,9 +524,7 @@ public:
         storage_err err = storage_file_delete(
                 client_session, file_name.data(), file_name.size(),
                 storage_op_flags{
-                        // TODO: support acking reset only
-                        .allow_repaired = options.readIntegrity ==
-                                          ReadIntegrity::IGNORE_ROLLBACK,
+                        .allow_repaired = false,
                         .complete_transaction = false,
                         .update_checkpoint = false,
                 });
@@ -569,12 +533,7 @@ public:
 
     Status renameFile(const std::string& file_name,
                       const std::string& new_name,
-                      const RenameOptions& options) final {
-        if (options.allowWritesDuringAbUpdate) {
-            return Status::fromExceptionCode(
-                    Status::EX_UNSUPPORTED_OPERATION,
-                    "Unsupported option: allowWritesDuringAbUpdate");
-        }
+                      CreationMode dest_create_mode) final {
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
             return Status::fromExceptionCode(
@@ -584,21 +543,16 @@ public:
 
         storage_err err = storage_file_move(
                 client_session, 0, false, file_name.data(), file_name.size(),
-                new_name.data(), new_name.size(),
-                create_mode(options.destCreateMode),
+                new_name.data(), new_name.size(), create_mode(dest_create_mode),
                 storage_op_flags{
-                        // TODO: support acking reset only
-                        .allow_repaired = options.readIntegrity ==
-                                          ReadIntegrity::IGNORE_ROLLBACK,
+                        .allow_repaired = false,
                         .complete_transaction = false,
                         .update_checkpoint = false,
                 });
         return status_from_storage_err(err);
     }
 
-    Status openDir(const std::string& file_name,
-                   ReadIntegrity integrity,
-                   sp<IDir>* out) final {
+    Status openDir(const std::string& file_name, sp<IDir>* out) final {
         if (!file_name.empty()) {
             return Status::fromExceptionCode(
                     Status::EX_ILLEGAL_ARGUMENT,
@@ -611,7 +565,7 @@ public:
         }
 
         // TODO: Catch tampering?
-        *out = sp<Dir>::make(session_, integrity);
+        *out = sp<Dir>::make(session_);
         return Status::ok();
     }
 
@@ -639,11 +593,11 @@ private:
 
 class StorageService {
 public:
-    Status MakeSession(const FileProperties& file_properties,
+    Status MakeSession(const Filesystem& filesystem,
                        const uuid_t* peer,
                        std::shared_ptr<StorageClientSession>* out) {
         storage_aidl_filesystem fs_type;
-        Status result = get_fs(file_properties, &fs_type);
+        Status result = get_fs(filesystem, &fs_type);
         if (!result.isOk()) {
             return result;
         }
@@ -709,11 +663,10 @@ public:
     SecureStorage(StorageService* service, uuid_t peer)
             : service_(service), peer_(peer) {}
 
-    Status startSession(const FileProperties& file_properties,
+    Status startSession(const Filesystem& filesystem,
                         sp<IStorageSession>* out) final {
         std::shared_ptr<StorageClientSession> session;
-        Status result =
-                service_->MakeSession(file_properties, &peer_, &session);
+        Status result = service_->MakeSession(filesystem, &peer_, &session);
         if (!result.isOk()) {
             return result;
         }
diff --git a/rules.mk b/rules.mk
index 4ca892e..093acbd 100644
--- a/rules.mk
+++ b/rules.mk
@@ -123,7 +123,9 @@ MODULE_DEFINES += STORAGE_AIDL_ENABLED=1
 MODULE_SRCS += $(LOCAL_DIR)/aidl_service.cpp
 MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty \
-	trusty/user/base/interface/secure_storage/cpp
+	trusty/user/base/interface/secure_storage/cpp \
+	trusty/user/base/lib/libstdc++-trusty \
+
 endif
 
 MODULE_DEPS += \
diff --git a/test/storage-unittest-aidl/lib.rs b/test/storage-unittest-aidl/lib.rs
index 2b7cb52..2ea4526 100644
--- a/test/storage-unittest-aidl/lib.rs
+++ b/test/storage-unittest-aidl/lib.rs
@@ -9,9 +9,8 @@ mod unittests;
 mod tests {
     use crate::define_tests_for;
     use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
-        FileAvailability::FileAvailability, FileIntegrity::FileIntegrity,
-        FileProperties::FileProperties, ISecureStorage::ISecureStorage,
-        IStorageSession::IStorageSession,
+        Availability::Availability, Filesystem::Filesystem, ISecureStorage::ISecureStorage,
+        IStorageSession::IStorageSession, Integrity::Integrity,
     };
     use binder::{Status, StatusCode, Strong};
     use core::ffi::CStr;
@@ -27,7 +26,7 @@ mod tests {
         RpcSession::new().setup_trusty_client(STORAGE_AIDL_PORT_NAME)
     }
 
-    fn start_session(properties: &FileProperties) -> Result<Strong<dyn IStorageSession>, Status> {
+    fn start_session(properties: &Filesystem) -> Result<Strong<dyn IStorageSession>, Status> {
         connect()?.startSession(properties)
     }
 
@@ -39,26 +38,26 @@ mod tests {
         assert_ok!(secure_storage.as_binder().ping_binder());
     }
 
-    const TP: &'static FileProperties = &FileProperties {
-        integrity: FileIntegrity::TAMPER_PROOF_AT_REST,
-        availability: FileAvailability::AFTER_USERDATA,
+    const TP: &'static Filesystem = &Filesystem {
+        integrity: Integrity::TAMPER_PROOF_AT_REST,
+        availability: Availability::AFTER_USERDATA,
         persistent: false,
     };
-    const TDEA: &'static FileProperties = &FileProperties {
-        integrity: FileIntegrity::TAMPER_DETECT,
-        availability: FileAvailability::BEFORE_USERDATA,
+    const TDEA: &'static Filesystem = &Filesystem {
+        integrity: Integrity::TAMPER_DETECT,
+        availability: Availability::BEFORE_USERDATA,
         persistent: false,
     };
     #[cfg(feature = "has_ns")]
-    const TDP: &'static FileProperties = &FileProperties {
-        integrity: FileIntegrity::TAMPER_DETECT,
-        availability: FileAvailability::AFTER_USERDATA,
+    const TDP: &'static Filesystem = &Filesystem {
+        integrity: Integrity::TAMPER_DETECT,
+        availability: Availability::AFTER_USERDATA,
         persistent: true,
     };
     #[cfg(feature = "has_ns")]
-    const TD: &'static FileProperties = &FileProperties {
-        integrity: FileIntegrity::TAMPER_DETECT,
-        availability: FileAvailability::AFTER_USERDATA,
+    const TD: &'static Filesystem = &Filesystem {
+        integrity: Integrity::TAMPER_DETECT,
+        availability: Availability::AFTER_USERDATA,
         persistent: false,
     };
 
diff --git a/test/storage-unittest-aidl/unittests/helpers.rs b/test/storage-unittest-aidl/unittests/helpers.rs
index 3eb227b..1e3f874 100644
--- a/test/storage-unittest-aidl/unittests/helpers.rs
+++ b/test/storage-unittest-aidl/unittests/helpers.rs
@@ -1,6 +1,5 @@
 use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
-    DeleteOptions::DeleteOptions, IFile::IFile, ISecureStorage as SecureStorage,
-    IStorageSession::IStorageSession, ReadIntegrity::ReadIntegrity,
+    IFile::IFile, ISecureStorage as SecureStorage, IStorageSession::IStorageSession,
 };
 use binder::ExceptionCode;
 
@@ -15,13 +14,8 @@ pub(crate) fn ensure_deleted(
     fname: &str,
     expectation: Exists,
 ) -> Result<(), String> {
-    const DEFAULT_DELETE: &'static DeleteOptions = &DeleteOptions {
-        readIntegrity: ReadIntegrity::NO_TAMPER,
-        allowWritesDuringAbUpdate: false,
-    };
-
     // Try to delete file
-    let rc = ss.deleteFile(fname, DEFAULT_DELETE);
+    let rc = ss.deleteFile(fname);
     match rc {
         Ok(()) => {
             if let Exists::MustNot = expectation {
diff --git a/test/storage-unittest-aidl/unittests/mod.rs b/test/storage-unittest-aidl/unittests/mod.rs
index 23d4627..0dce95b 100644
--- a/test/storage-unittest-aidl/unittests/mod.rs
+++ b/test/storage-unittest-aidl/unittests/mod.rs
@@ -1,6 +1,6 @@
 use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
     CreationMode::CreationMode, FileMode::FileMode, ISecureStorage as SecureStorage,
-    IStorageSession::IStorageSession, OpenOptions::OpenOptions, ReadIntegrity::ReadIntegrity,
+    IStorageSession::IStorageSession, OpenOptions::OpenOptions,
 };
 use binder::ExceptionCode;
 use test::{assert_ok, expect, fail};
@@ -11,17 +11,13 @@ use helpers::{ensure_deleted, Exists};
 const CREATE_EXCLUSIVE: &'static OpenOptions = &OpenOptions {
     createMode: CreationMode::CREATE_EXCLUSIVE,
     accessMode: FileMode::READ_WRITE,
-    readIntegrity: ReadIntegrity::NO_TAMPER,
     truncateOnOpen: true,
-    allowWritesDuringAbUpdate: false,
 };
 
 const NO_CREATE: &'static OpenOptions = &OpenOptions {
     createMode: CreationMode::NO_CREATE,
     accessMode: FileMode::READ_WRITE,
-    readIntegrity: ReadIntegrity::NO_TAMPER,
     truncateOnOpen: false,
-    allowWritesDuringAbUpdate: false,
 };
 
 pub(crate) fn create_delete(ss: &(impl IStorageSession + ?Sized)) {
@@ -131,7 +127,7 @@ pub(crate) fn file_list(ss: &(impl IStorageSession + ?Sized)) {
     }
 
     {
-        let dir = assert_ok!(ss.openDir("", ReadIntegrity::NO_TAMPER));
+        let dir = assert_ok!(ss.openDir(""));
         let filenames = assert_ok!(dir.readNextFilenames(0));
         expect!(filenames.is_empty(), "Found unexpected files: {:?}", filenames);
     }
@@ -148,7 +144,7 @@ pub(crate) fn file_list(ss: &(impl IStorageSession + ?Sized)) {
 
     let mut read_file_names = HashSet::new();
     {
-        let dir = assert_ok!(ss.openDir("", ReadIntegrity::NO_TAMPER));
+        let dir = assert_ok!(ss.openDir(""));
         let mut filenames = assert_ok!(dir.readNextFilenames(0));
         while !filenames.is_empty() {
             for filename in filenames {
diff --git a/usertests-inc.mk b/usertests-inc.mk
index 2f25730..a91951e 100644
--- a/usertests-inc.mk
+++ b/usertests-inc.mk
@@ -15,7 +15,11 @@
 
 TRUSTY_USER_TESTS += \
 	trusty/user/app/storage/test/storage-unittest \
+
+ifneq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_USER_TESTS += \
 	trusty/user/app/storage/test/storage-benchmark
+endif
 
 ifeq (true,$(call TOBOOL,$(STORAGE_AIDL_ENABLED)))
 TRUSTY_RUST_USER_TESTS += \
```

