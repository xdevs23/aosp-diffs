```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..6799cf3
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_storage",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/aidl_service.cpp b/aidl_service.cpp
index f3d9c93..e5caf37 100644
--- a/aidl_service.cpp
+++ b/aidl_service.cpp
@@ -16,7 +16,7 @@
 
 #include "aidl_service.h"
 
-#include <algorithm>
+#include <cassert>
 #include <cstddef>
 #include <cstdint>
 #include <cstdlib>
@@ -48,6 +48,7 @@
 #include <android/hardware/security/see/storage/Integrity.h>
 #include <android/hardware/security/see/storage/OpenOptions.h>
 
+#include "block_device_tipc.h"
 #include "client.h"
 #include "client_session.h"
 #include "file.h"
@@ -133,11 +134,11 @@ static file_create_mode create_mode(CreationMode mode) {
 }
 
 static Status get_fs(const Filesystem& filesystem,
-                     storage_aidl_filesystem* out) {
+                     storage_filesystem_type* out) {
     switch (filesystem.integrity) {
     case Integrity::TAMPER_PROOF_AT_REST: {
         // TP is persistent and available before userdata
-        *out = STORAGE_AIDL_TP;
+        *out = STORAGE_TP;
         break;
     }
     case Integrity::TAMPER_DETECT: {
@@ -148,11 +149,11 @@ static Status get_fs(const Filesystem& filesystem,
                         Status::EX_UNSUPPORTED_OPERATION,
                         "Unsupported Filesystem properties: TDEA does not guarantee persistence");
             }
-            *out = STORAGE_AIDL_TDEA;
+            *out = STORAGE_TDEA;
             break;
         }
         case Availability::AFTER_USERDATA: {
-            *out = filesystem.persistent ? STORAGE_AIDL_TDP : STORAGE_AIDL_TD;
+            *out = filesystem.persistent ? STORAGE_TDP : STORAGE_TD;
             break;
         }
         default:
@@ -172,27 +173,17 @@ static Status get_fs(const Filesystem& filesystem,
 
 class StorageClientSession {
 public:
-    StorageClientSession(struct fs* fs,
-                         storage_aidl_filesystem fs_type,
-                         const uuid_t* peer)
-            : inner_(), fs_type_(fs_type), active_(false) {
+    StorageClientSession(struct fs* fs, bool* fs_active, const uuid_t* peer)
+            : inner_(), active_(fs_active) {
         storage_client_session_init(&inner_, fs, peer);
-        active_ = true;
     }
-    ~StorageClientSession() { Deactivate(); }
+    ~StorageClientSession() { storage_client_session_destroy(&inner_); }
 
-    storage_client_session* get() { return active_ ? &inner_ : nullptr; }
-    storage_aidl_filesystem fs_type() { return fs_type_; }
-
-    void Deactivate() {
-        active_ = false;
-        storage_client_session_destroy(&inner_);
-    }
+    storage_client_session* get() { return *active_ ? &inner_ : nullptr; }
 
 private:
     storage_client_session inner_;
-    storage_aidl_filesystem fs_type_;
-    bool active_;
+    bool* active_;
 };
 
 class Dir : public BnDir {
@@ -223,9 +214,7 @@ public:
         }
         storage_client_session* client_session = session->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         if (last_state_ == storage_file_list_flag::STORAGE_FILE_LIST_END) {
@@ -332,9 +321,7 @@ public:
         }
         storage_client_session* client_session = session->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         out->resize(
@@ -369,9 +356,7 @@ public:
         }
         storage_client_session* client_session = session->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         storage_err result =
@@ -394,9 +379,7 @@ public:
         }
         storage_client_session* client_session = session->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         uint64_t size;
@@ -428,9 +411,7 @@ public:
         }
         storage_client_session* client_session = session->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         storage_err result = storage_file_set_size(session->get(), file_handle_,
@@ -452,9 +433,7 @@ public:
         }
         storage_client_session* client_session = session->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         storage_err result = storage_file_move(
@@ -482,6 +461,10 @@ public:
     StorageSession(std::shared_ptr<StorageClientSession> session)
             : session_(std::move(session)) {}
 
+    Status stageChangesForCommitOnAbUpdateComplete() final {
+        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
+    }
+
     Status commitChanges() final { return endTransactions(true); }
     Status abandonChanges() final { return endTransactions(false); }
 
@@ -490,9 +473,7 @@ public:
                     sp<IFile>* out) final {
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         uint32_t file_handle;
@@ -516,9 +497,7 @@ public:
     Status deleteFile(const std::string& file_name) final {
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         storage_err err = storage_file_delete(
@@ -536,9 +515,7 @@ public:
                       CreationMode dest_create_mode) final {
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         storage_err err = storage_file_move(
@@ -559,9 +536,7 @@ public:
                     "Service currently only supports opening the root dir.");
         }
         if (session_->get() == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
         // TODO: Catch tampering?
@@ -580,9 +555,7 @@ private:
 
         storage_client_session* client_session = session_->get();
         if (client_session == nullptr) {
-            return Status::fromExceptionCode(
-                    Status::EX_ILLEGAL_STATE,
-                    "Connection to underlying filesystem lost. Start a new session.");
+            return Status::fromStatusT(android::WOULD_BLOCK);
         }
         storage_err result = storage_transaction_end(client_session, flags);
         return status_from_storage_err(result);
@@ -596,66 +569,53 @@ public:
     Status MakeSession(const Filesystem& filesystem,
                        const uuid_t* peer,
                        std::shared_ptr<StorageClientSession>* out) {
-        storage_aidl_filesystem fs_type;
+        storage_filesystem_type fs_type;
         Status result = get_fs(filesystem, &fs_type);
         if (!result.isOk()) {
             return result;
         }
 
-        struct fs* fs = filesystems_[fs_type];
-        if (fs == nullptr) {
+        if (!filesystems_active_[fs_type]) {
             return Status::fromStatusT(android::WOULD_BLOCK);
         }
 
-        std::erase_if(sessions_,
-                      [](const std::weak_ptr<StorageClientSession>& session) {
-                          return session.expired();
-                      });
-
-        *out = std::make_shared<StorageClientSession>(fs, fs_type, peer);
-        sessions_.emplace_back(*out);
+        *out = std::make_shared<StorageClientSession>(
+                filesystems_[fs_type], &filesystems_active_[fs_type], peer);
         return Status::ok();
     }
 
-    void DeactivateFilesystem(storage_aidl_filesystem fs_type) {
-        if (filesystems_[fs_type] == nullptr) {
-            SS_ERR("Deactivating fs that's already inactive: %d", fs_type);
+    void DeactivateFilesystem(storage_filesystem_type fs_type) {
+        if (!filesystems_active_[fs_type]) {
+            // The filesystem might be still be inactive because it wasn't
+            // connected when storage_aidl_enable was called, like NS-backed
+            // filesystems would be before NS is available.
             return;
         }
 
-        filesystems_[fs_type] = nullptr;
+        filesystems_active_[fs_type] = false;
+    }
 
-        for (auto it = sessions_.begin(); it != sessions_.end();) {
-            auto session = it->lock();
-            if (session == nullptr) {
-                it = sessions_.erase(it);
-                continue;
-            }
+    void TryActivateFilesystem(struct block_device_tipc* block_devices,
+                               storage_filesystem_type fs_type) {
+        assert(!filesystems_active_[fs_type]);
 
-            if (session->fs_type() == fs_type) {
-                session->Deactivate();
-            }
-            ++it;
+        if (!block_device_tipc_fs_connected(block_devices, fs_type)) {
+            return;
         }
-    }
 
-    void ActivateFilesystem(struct fs* fs, storage_aidl_filesystem fs_type) {
-        if (filesystems_[fs_type] != nullptr) {
-            SS_ERR("Reactivating fs that's already active: %d", fs_type);
-            DeactivateFilesystem(fs_type);
+        if (filesystems_[fs_type] == nullptr) {
+            filesystems_[fs_type] =
+                    block_device_tipc_get_fs(block_devices, fs_type);
+        } else {
+            assert(filesystems_[fs_type] ==
+                   block_device_tipc_get_fs(block_devices, fs_type));
         }
-
-        filesystems_[fs_type] = fs;
-
-        std::erase_if(sessions_,
-                      [](const std::weak_ptr<StorageClientSession>& session) {
-                          return session.expired();
-                      });
+        filesystems_active_[fs_type] = true;
     }
 
 private:
-    std::array<struct fs*, STORAGE_AIDL_FILESYSTEMS_COUNT> filesystems_;
-    std::vector<std::weak_ptr<StorageClientSession>> sessions_;
+    std::array<struct fs*, STORAGE_FILESYSTEMS_COUNT> filesystems_;
+    std::array<bool, STORAGE_FILESYSTEMS_COUNT> filesystems_active_;
 };
 
 class SecureStorage : public BnSecureStorage {
@@ -725,18 +685,25 @@ int storage_aidl_create_service(struct storage_service_aidl_context* ctx,
     return EXIT_SUCCESS;
 }
 
-void storage_aidl_delete_service(struct storage_service_aidl_context* ctx) {
+void storage_aidl_destroy_service(struct storage_service_aidl_context* ctx) {
     delete ctx->inner;
-    ctx->inner = nullptr;
 }
 
-void storage_aidl_enable_filesystem(struct storage_service_aidl_context* ctx,
-                                    struct fs* fs,
-                                    enum storage_aidl_filesystem fs_type) {
-    ctx->inner->service.ActivateFilesystem(fs, fs_type);
+void storage_aidl_enable(struct storage_service_aidl_context* self,
+                         struct block_device_tipc* block_devices) {
+    storage_service::StorageService& service = self->inner->service;
+    service.TryActivateFilesystem(block_devices, STORAGE_TP);
+    service.TryActivateFilesystem(block_devices, STORAGE_TDEA);
+    service.TryActivateFilesystem(block_devices, STORAGE_TD);
+    service.TryActivateFilesystem(block_devices, STORAGE_TDP);
+    service.TryActivateFilesystem(block_devices, STORAGE_NSP);
 }
 
-void storage_aidl_disable_filesystem(struct storage_service_aidl_context* ctx,
-                                     enum storage_aidl_filesystem fs_type) {
-    ctx->inner->service.DeactivateFilesystem(fs_type);
-}
+void storage_aidl_disable(struct storage_service_aidl_context* self) {
+    storage_service::StorageService& service = self->inner->service;
+    service.DeactivateFilesystem(STORAGE_NSP);
+    service.DeactivateFilesystem(STORAGE_TDP);
+    service.DeactivateFilesystem(STORAGE_TD);
+    service.DeactivateFilesystem(STORAGE_TDEA);
+    service.DeactivateFilesystem(STORAGE_TP);
+}
\ No newline at end of file
diff --git a/aidl_service.h b/aidl_service.h
index 23ee19f..0a56307 100644
--- a/aidl_service.h
+++ b/aidl_service.h
@@ -21,16 +21,7 @@
 #include <lib/tipc/tipc.h>
 #include <lk/compiler.h>
 
-struct fs;
-
-enum storage_aidl_filesystem {
-    STORAGE_AIDL_TP,
-    STORAGE_AIDL_TDEA,
-    STORAGE_AIDL_TDP,
-    STORAGE_AIDL_TD,
-    STORAGE_AIDL_NSP,
-    STORAGE_AIDL_FILESYSTEMS_COUNT,
-};
+#include "block_device_tipc.h"
 
 __BEGIN_CDECLS
 
@@ -42,79 +33,74 @@ struct storage_service_aidl_context {
     struct storage_service_aidl_context_inner* inner;
 };
 
-#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(ctx) \
-    (struct storage_service_aidl_context) {             \
-        .inner = NULL                                   \
+#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(self) \
+    (struct storage_service_aidl_context) {              \
+        .inner = NULL                                    \
     }
 
 /**
  * storage_aidl_create_service() - Initialize a storage aidl service
- * @ctx: Out-param. Will contain the created &struct
- * storage_aidl_create_service, which must be cleaned up by passing it to
- * storage_aidl_delete_service().
+ * @self: Out-param. Will contain the created &struct
+ * storage_service_aidl_context, which must be cleaned up by passing it to
+ * storage_aidl_destroy_service().
  * @hset: The handle set the service will run on.
  */
-int storage_aidl_create_service(struct storage_service_aidl_context* ctx,
+int storage_aidl_create_service(struct storage_service_aidl_context* self,
                                 struct tipc_hset* hset);
 
 /**
- * storage_aidl_delete_service() - Delete a storage aidl service
- * @ctx: The &struct storage_aidl_create_service to delete. When called, there
- * must not be any remaining AIDL objects created from @ctx that are still
+ * storage_aidl_destroy_service() - Delete a storage aidl service
+ * @self: The &struct storage_service_aidl_context to delete. When called, there
+ * must not be any remaining AIDL objects created from @self that are still
  * callable (including remotely).
  */
-void storage_aidl_delete_service(struct storage_service_aidl_context* ctx);
+void storage_aidl_destroy_service(struct storage_service_aidl_context* self);
 
 /**
- * storage_aidl_enable_filesystem() - Connect the storage aidl service to a
- * backing filesystem
- * @ctx: The &struct storage_aidl_create_service to modify.
- * @fs: Filesystem object to use for access when AIDL calls are made.
- * @fs_type: The type of filesystem to connect. Callers should not connect a
- * second time for the same @fs_type without calling
- * storage_aidl_disable_filesystem() first.
+ * storage_aidl_enable() - Connect the storage aidl service to backing
+ * filesystems.
+ * @self: The &struct storage_service_aidl_context to modify.
+ * @block_devices: Context holding the filesystems to connect to.
+ *
+ * Callers must not connect a second time without calling storage_aidl_disable()
+ * first.
  */
-void storage_aidl_enable_filesystem(struct storage_service_aidl_context* ctx,
-                                    struct fs* fs,
-                                    enum storage_aidl_filesystem fs_type);
+void storage_aidl_enable(struct storage_service_aidl_context* self,
+                         struct block_device_tipc* block_devices);
 
 /**
- * storage_aidl_disable_filesystem() - Disconnect the storage aidl service from
- a backing filesystem
- * @ctx: The &struct storage_aidl_create_service to modify.
- * @fs_type: The type of filesystem to disconnect. Callers should not disconnect
- from a @fs_type that has not been previously connected with
- storage_aidl_enable_filesystem().
-
+ * storage_aidl_disable() - Disconnect the storage aidl service from backing
+ * filesystems.
+ * @self: The &struct storage_service_aidl_context to modify.
+ *
+ * Callers must only disable a service that has been previously enabled (with
+ * storage_aidl_enable()), and must not disable an already-disabled service.
  */
-void storage_aidl_disable_filesystem(struct storage_service_aidl_context* ctx,
-                                     enum storage_aidl_filesystem fs_type);
+void storage_aidl_disable(struct storage_service_aidl_context* self);
 
 #else
 
 struct storage_service_aidl_context {};
 
-#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(ctx) \
+#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(self) \
     (struct storage_service_aidl_context) {}
 
 static inline int storage_aidl_create_service(
-        struct storage_service_aidl_context* ctx,
+        struct storage_service_aidl_context* self,
         struct tipc_hset* hset) {
-    *ctx = STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(*ctx);
+    *self = STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(*self);
     return EXIT_SUCCESS;
 }
 
-static inline void storage_aidl_delete_service(
-        struct storage_service_aidl_context* ctx) {}
+static inline void storage_aidl_destroy_service(
+        struct storage_service_aidl_context* self) {}
 
-static inline void storage_aidl_enable_filesystem(
-        struct storage_service_aidl_context* ctx,
-        struct fs* fs,
-        enum storage_aidl_filesystem fs_type) {}
+static inline void storage_aidl_enable(
+        struct storage_service_aidl_context* self,
+        struct block_device_tipc* block_devices) {}
 
-static inline void storage_aidl_disable_filesystem(
-        struct storage_service_aidl_context* ctx,
-        enum storage_aidl_filesystem fs_type) {}
+static inline void storage_aidl_disable(
+        struct storage_service_aidl_context* self) {}
 
 #endif
 
diff --git a/block_device_tipc.c b/block_device_tipc.c
index 933ec2e..7baab40 100644
--- a/block_device_tipc.c
+++ b/block_device_tipc.c
@@ -32,7 +32,6 @@
 #include <openssl/mem.h>
 #include <openssl/rand.h>
 
-#include "aidl_service.h"
 #include "block_cache.h"
 #include "client_tipc.h"
 #include "fs.h"
@@ -97,6 +96,11 @@ const char file_system_id_tdp[] = "tdp";
 const char file_system_id_tp[] = "tp";
 const char file_system_id_nsp[] = "nsp";
 
+const char ns_filename[] = "0";
+const char ns_alternate_filename[] = "alternate/0";
+const char tdp_filename[] = "persist/0";
+const char nsp_filename[] = "persist/nsp";
+
 struct rpmb_key_derivation_in {
     uint8_t prefix[sizeof(struct key)];
     uint8_t block_data[RPMB_BUF_SIZE];
@@ -107,23 +111,35 @@ struct rpmb_key_derivation_out {
     uint8_t unused[sizeof(struct key)];
 };
 
-static int rpmb_check(struct block_device_tipc* state, uint16_t block) {
+struct rpmb_span {
+    uint16_t start;
+    uint16_t block_count;
+};
+
+struct rpmb_spans {
+    struct rpmb_span key;
+    struct rpmb_span ns;
+    struct rpmb_span tdp;
+    /* Start of the rest of the RPMB, which is used for TP and TDEA */
+    uint16_t rpmb_start;
+};
+
+static int rpmb_check(struct rpmb_state* rpmb_state, uint16_t block) {
     int ret;
     uint8_t tmp[RPMB_BUF_SIZE];
-    ret = rpmb_read(state->rpmb_state, tmp, block, 1);
+    ret = rpmb_read(rpmb_state, tmp, block, 1);
     SS_DBG_IO("%s: check rpmb_block %d, ret %d\n", __func__, block, ret);
     return ret;
 }
 
-static uint32_t rpmb_search_size(struct block_device_tipc* state,
-                                 uint16_t hint) {
+static uint32_t rpmb_search_size(struct rpmb_state* rpmb_state, uint16_t hint) {
     int ret;
     uint32_t low = 0;
     uint16_t high = UINT16_MAX;
     uint16_t curr = hint ? hint - 1 : UINT16_MAX;
 
     while (low <= high) {
-        ret = rpmb_check(state, curr);
+        ret = rpmb_check(rpmb_state, curr);
         switch (ret) {
         case 0:
             low = curr + 1;
@@ -160,7 +176,7 @@ static void block_device_tipc_rpmb_start_read(struct block_device* dev,
     assert(block < dev->block_count);
     rpmb_block = block + dev_rpmb->base;
 
-    ret = rpmb_read(dev_rpmb->state->rpmb_state, tmp,
+    ret = rpmb_read(dev_rpmb->rpmb_state, tmp,
                     rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
                     BLOCK_SIZE_RPMB_BLOCKS);
 
@@ -201,7 +217,7 @@ static void block_device_tipc_rpmb_start_write(struct block_device* dev,
 
     rpmb_block = block + dev_rpmb->base;
 
-    ret = rpmb_write(dev_rpmb->state->rpmb_state, data,
+    ret = rpmb_write(dev_rpmb->rpmb_state, data,
                      rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
                      BLOCK_SIZE_RPMB_BLOCKS, true, dev_rpmb->is_userdata);
 
@@ -227,7 +243,7 @@ static void block_device_tipc_ns_start_read(struct block_device* dev,
     uint8_t tmp[BLOCK_SIZE_MAIN]; /* TODO: pass data in? */
     struct block_device_ns* dev_ns = to_block_device_ns(dev);
 
-    ret = ns_read_pos(dev_ns->state->ipc_handle, dev_ns->ns_handle,
+    ret = ns_read_pos(dev_ns->ipc_handle, dev_ns->ns_handle,
                       block * BLOCK_SIZE_MAIN, tmp, BLOCK_SIZE_MAIN);
     SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
     if (ret == 0) {
@@ -251,7 +267,7 @@ static void block_device_tipc_ns_start_write(struct block_device* dev,
 
     assert(data_size == BLOCK_SIZE_MAIN);
 
-    ret = ns_write_pos(dev_ns->state->ipc_handle, dev_ns->ns_handle,
+    ret = ns_write_pos(dev_ns->ipc_handle, dev_ns->ns_handle,
                        block * BLOCK_SIZE_MAIN, data, data_size,
                        dev_ns->is_userdata, sync);
     SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
@@ -268,7 +284,7 @@ static void block_device_tipc_ns_wait_for_io(struct block_device* dev) {
 }
 
 static void block_device_tipc_init_dev_rpmb(struct block_device_rpmb* dev_rpmb,
-                                            struct block_device_tipc* state,
+                                            struct rpmb_state* rpmb_state,
                                             uint16_t base,
                                             uint32_t block_count,
                                             bool is_userdata) {
@@ -281,13 +297,13 @@ static void block_device_tipc_init_dev_rpmb(struct block_device_rpmb* dev_rpmb,
     dev_rpmb->dev.mac_size = 2;
     dev_rpmb->dev.tamper_detecting = true;
     list_initialize(&dev_rpmb->dev.io_ops);
-    dev_rpmb->state = state;
+    dev_rpmb->rpmb_state = rpmb_state;
     dev_rpmb->base = base;
     dev_rpmb->is_userdata = is_userdata;
 }
 
 static void block_device_tipc_init_dev_ns(struct block_device_ns* dev_ns,
-                                          struct block_device_tipc* state,
+                                          handle_t ipc_handle,
                                           bool is_userdata) {
     dev_ns->dev.start_read = block_device_tipc_ns_start_read;
     dev_ns->dev.start_write = block_device_tipc_ns_start_write;
@@ -297,7 +313,7 @@ static void block_device_tipc_init_dev_ns(struct block_device_ns* dev_ns,
     dev_ns->dev.mac_size = sizeof(struct mac);
     dev_ns->dev.tamper_detecting = false;
     list_initialize(&dev_ns->dev.io_ops);
-    dev_ns->state = state;
+    dev_ns->ipc_handle = ipc_handle;
     dev_ns->ns_handle = 0; /* Filled in later */
     dev_ns->is_userdata = is_userdata;
 }
@@ -446,176 +462,267 @@ static int block_device_tipc_init_rpmb_key(struct rpmb_state* state,
     return ret;
 }
 
-static int check_storage_size(handle_t handle,
-                              struct block_device_ns* dev_ns,
-                              data_block_t* sz) {
-    int ret;
-
-    assert(sz != NULL);
+static int set_storage_size(handle_t handle, struct block_device_ns* dev_ns) {
+    data_block_t sz;
 
-    ret = ns_get_max_size(handle, dev_ns->ns_handle, sz);
+    int ret = ns_get_max_size(handle, dev_ns->ns_handle, &sz);
     if (ret < 0) {
         /* In case we have an old storageproxyd, use default */
         if (ret == ERR_NOT_IMPLEMENTED) {
-            *sz = BLOCK_COUNT_MAIN * dev_ns->dev.block_size;
+            sz = BLOCK_COUNT_MAIN * dev_ns->dev.block_size;
             ret = 0;
         } else {
             SS_ERR("%s: Could not get max size: %d\n", __func__, ret);
+            return ret;
         }
-    } else if (*sz < (dev_ns->dev.block_size * 8)) {
+    } else if (sz < (dev_ns->dev.block_size * 8)) {
         SS_ERR("%s: max storage file size %" PRIu64 " is too small\n", __func__,
-               *sz);
-        ret = -1;
+               sz);
+        return -1;
     }
+
+    dev_ns->dev.block_count = sz / dev_ns->dev.block_size;
     return ret;
 }
 
-int block_device_tipc_init(struct block_device_tipc* state,
-                           struct tipc_hset* hset,
-                           struct storage_service_aidl_context* aidl_ctx,
-                           handle_t ipc_handle,
-                           const struct key* fs_key,
-                           const struct rpmb_key* rpmb_key,
-                           hwkey_session_t hwkey_session) {
+static bool block_device_tipc_has_ns(struct block_device_tipc* self) {
+    return self->dev_ns.dev.block_count;
+}
+
+/**
+ * init_rpmb_fs() - Initialize @self's RPMB fs and its backing block devices.
+ * @self:            The struct block_device_tipc to modify
+ * @fs_key:          The key to use for the filesystem.
+ * @partition_start: The first RPMB block in the partition to use for this fs.
+ *
+ * Return: NO_ERROR on success, error code less than 0 on error.
+ */
+static int init_rpmb_fs(struct block_device_tipc* self,
+                        const struct key* fs_key,
+                        uint16_t partition_start) {
     int ret;
-    bool alternate_data_partition = false;
-    uint32_t ns_init_flags = FS_INIT_FLAGS_NONE;
-#if HAS_FS_TDP
-    uint32_t tdp_init_flags = FS_INIT_FLAGS_NONE;
-#endif
-    uint8_t probe;
-    uint16_t rpmb_key_part_base = 0;
     uint32_t rpmb_block_count;
-    uint32_t rpmb_part_sb_ns_block_count = 2;
-    /*
-     * First block is reserved for rpmb key derivation data, whose base is
-     * rpmb_key_part_base
-     */
-    uint16_t rpmb_part1_base = 1;
-    uint16_t rpmb_part2_base = rpmb_part1_base + rpmb_part_sb_ns_block_count;
-
-    data_block_t sz;
-#if HAS_FS_TDP
-    uint16_t rpmb_part_sb_tdp_base = rpmb_part2_base;
-    rpmb_part2_base += rpmb_part_sb_ns_block_count;
-#endif
-    state->ipc_handle = ipc_handle;
-    state->aidl_ctx = aidl_ctx;
-
-    /* init rpmb */
-    ret = rpmb_init(&state->rpmb_state, &state->ipc_handle);
-    if (ret < 0) {
-        SS_ERR("%s: rpmb_init failed (%d)\n", __func__, ret);
-        goto err_rpmb_init;
-    }
-
-    ret = block_device_tipc_init_rpmb_key(state->rpmb_state, rpmb_key,
-                                          rpmb_key_part_base, hwkey_session);
-    if (ret < 0) {
-        SS_ERR("%s: block_device_tipc_init_rpmb_key failed (%d)\n", __func__,
-               ret);
-        goto err_init_rpmb_key;
-    }
 
     if (BLOCK_COUNT_RPMB) {
         rpmb_block_count = BLOCK_COUNT_RPMB;
-        ret = rpmb_check(state, rpmb_block_count * BLOCK_SIZE_RPMB_BLOCKS - 1);
-        if (ret) {
+        ret = rpmb_check(self->rpmb_state,
+                         rpmb_block_count * BLOCK_SIZE_RPMB_BLOCKS - 1);
+        if (ret < 0) {
             SS_ERR("%s: bad static rpmb size, %d\n", __func__,
                    rpmb_block_count);
             goto err_bad_rpmb_size;
         }
     } else {
-        rpmb_block_count =
-                rpmb_search_size(state, 0); /* TODO: get hint from ns */
+        rpmb_block_count = rpmb_search_size(self->rpmb_state,
+                                            0); /* TODO: get hint from ns */
         rpmb_block_count /= BLOCK_SIZE_RPMB_BLOCKS;
     }
-    if (rpmb_block_count < rpmb_part2_base) {
+    if (rpmb_block_count < partition_start) {
         ret = -1;
         SS_ERR("%s: bad rpmb size, %d\n", __func__, rpmb_block_count);
         goto err_bad_rpmb_size;
     }
 
-    block_device_tipc_init_dev_rpmb(&state->dev_rpmb, state, rpmb_part2_base,
-                                    rpmb_block_count - rpmb_part2_base, false);
+    block_device_tipc_init_dev_rpmb(&self->dev_rpmb, self->rpmb_state,
+                                    partition_start,
+                                    rpmb_block_count - partition_start, false);
 
     /* TODO: allow non-rpmb based tamper proof storage */
-    ret = fs_init(&state->tr_state_rpmb, file_system_id_tp, fs_key,
-                  &state->dev_rpmb.dev, &state->dev_rpmb.dev,
-                  FS_INIT_FLAGS_NONE);
+    ret = fs_init(&self->tr_state_rpmb, file_system_id_tp, fs_key,
+                  &self->dev_rpmb.dev, &self->dev_rpmb.dev, FS_INIT_FLAGS_NONE);
     if (ret < 0) {
+        SS_ERR("%s: failed to initialize TP: %d\n", __func__, ret);
         goto err_init_tr_state_rpmb;
     }
+    return 0;
+
+err_init_tr_state_rpmb:
+    block_cache_dev_destroy(&self->dev_rpmb.dev);
+err_bad_rpmb_size:
+    return ret;
+}
 
-    state->fs_rpmb.tr_state = &state->tr_state_rpmb;
+/**
+ * destroy_rpmb_fs() - Destroy @self's RPMB fs and its backing block devices.
+ */
+static void destroy_rpmb_fs(struct block_device_tipc* self) {
+    fs_destroy(&self->tr_state_rpmb);
+    block_cache_dev_destroy(&self->dev_rpmb.dev);
+}
 
-    storage_aidl_enable_filesystem(aidl_ctx, state->fs_rpmb.tr_state,
-                                   STORAGE_AIDL_TP);
-    ret = client_create_port(hset, &state->fs_rpmb.client_ctx,
-                             STORAGE_CLIENT_TP_PORT);
-    if (ret < 0) {
-        goto err_fs_rpmb_create_port;
+/**
+ * block_device_ns_open_file() - Open an ns backing file
+ *
+ * @self: The ns block device to use to open the file.
+ * @name: The name of the file to open.
+ * @create: Whether the file should be created if it doesn't already exist.
+ *
+ * Return: NO_ERROR on success, error code less than 0 if an error was
+ * encountered during initialization.
+ */
+static int block_device_ns_open_file(struct block_device_ns* self,
+                                     const char* name,
+                                     bool create) {
+    return ns_open_file(self->ipc_handle, name, &self->ns_handle, create);
+}
+
+/**
+ * block_device_ns_open_file_with_alternate() - Open an ns backing file,
+ * possibly falling back to an alternate if the primary is not available.
+ *
+ * @self:           The ns block device to use to open the file.
+ * @name:           The name of the primary file to open.
+ * @alternate_name: The name of the alternate file. Ignored if
+ *                  STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED is false.
+ * @create:         Whether the file should be created if it doesn't already
+ *                  exist.
+ * @used_alternate: Out-param, set only on successful return. Will tell whether
+ *                  the opened file was the alternate.
+ *
+ * Return: NO_ERROR on success, error code less than 0 if an error was
+ * encountered during initialization.
+ */
+static int block_device_ns_open_file_with_alternate(
+        struct block_device_ns* self,
+        const char* name,
+        const char* alternate_name,
+        bool create,
+        bool* used_alternate) {
+    int ret = block_device_ns_open_file(self, name, create);
+    if (ret >= 0) {
+        *used_alternate = false;
+        return NO_ERROR;
     }
 
-    state->fs_rpmb_boot.tr_state = &state->tr_state_rpmb;
+#if STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED
+    ret = block_device_ns_open_file(self, alternate_name, create);
+    if (ret >= 0) {
+        *used_alternate = true;
+        return NO_ERROR;
+    }
+#endif
+    return ret;
+}
+
+enum ns_init_result {
+    /* Negative codes reserved for other error values. */
+    NS_INIT_SUCCESS = 0,
+    NS_INIT_NOT_READY = 1,
+};
+
+/**
+ * init_ns_fs() - Initialize @self's NS fs and its backing block devices.
+ * @self:      The struct block_device_tipc to modify
+ * @fs_key:    The key to use for the filesystem.
+ * @partition: The RPMB blocks to use for the filesystem's superblocks.
+ *
+ * If no ns filesystems are available, return NS_INIT_NOT_READY and leave the NS
+ * fs uninitialized. (In that case, block_device_tipc_has_ns() will return
+ * false.)
+ *
+ * Return: NS_INIT_SUCCESS on success, NS_INIT_NOT_READY if ns is unavailable,
+ * or an error code less than 0 if an error was encountered during
+ * initialization.
+ */
+static int init_ns_fs(struct block_device_tipc* self,
+                      const struct key* fs_key,
+                      struct rpmb_span partition) {
+    block_device_tipc_init_dev_ns(&self->dev_ns, self->ipc_handle, true);
+
+    bool alternate_data_partition;
+    int ret = block_device_ns_open_file_with_alternate(
+            &self->dev_ns, ns_filename, ns_alternate_filename, true,
+            &alternate_data_partition);
+    if (ret < 0) {
+        /* NS not available; init RPMB fs only */
+        self->dev_ns.dev.block_count = 0;
+        return NS_INIT_NOT_READY;
+    }
 
-    storage_aidl_enable_filesystem(aidl_ctx, state->fs_rpmb_boot.tr_state,
-                                   STORAGE_AIDL_TDEA);
-    ret = client_create_port(hset, &state->fs_rpmb_boot.client_ctx,
-                             STORAGE_CLIENT_TDEA_PORT);
+    ret = set_storage_size(self->ipc_handle, &self->dev_ns);
     if (ret < 0) {
-        goto err_fs_rpmb_boot_create_port;
+        goto err_get_td_max_size;
+    }
+
+    /* Request empty file system if file is empty */
+    uint8_t probe;
+    uint32_t ns_init_flags = FS_INIT_FLAGS_NONE;
+    ret = ns_read_pos(self->ipc_handle, self->dev_ns.ns_handle, 0, &probe,
+                      sizeof(probe));
+    if (ret < (int)sizeof(probe)) {
+        ns_init_flags |= FS_INIT_FLAGS_DO_CLEAR;
     }
 
-    block_device_tipc_init_dev_ns(&state->dev_ns, state, true);
+    block_device_tipc_init_dev_rpmb(&self->dev_ns_rpmb, self->rpmb_state,
+                                    partition.start, partition.block_count,
+                                    true);
 
-    ret = ns_open_file(state->ipc_handle, "0", &state->dev_ns.ns_handle, true);
-    if (ret < 0) {
-        /*
-         * Only attempt to open the alternate file if allowed, and if not
-         * supported or available fall back to TP only.
-         */
-#if STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED
-        ret = ns_open_file(state->ipc_handle, "alternate/0",
-                           &state->dev_ns.ns_handle, true);
+#if STORAGE_NS_RECOVERY_CLEAR_ALLOWED
+    ns_init_flags |= FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED;
 #endif
-        if (ret >= 0) {
-            alternate_data_partition = true;
-        } else {
-            /* RPMB fs only */
-            state->dev_ns.dev.block_count = 0;
-            return 0;
-        }
+
+    /*
+     * This must be false if STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED is
+     * false.
+     */
+    if (alternate_data_partition) {
+        ns_init_flags |= FS_INIT_FLAGS_ALTERNATE_DATA;
     }
 
-    ret = check_storage_size(state->ipc_handle, &state->dev_ns, &sz);
+    ret = fs_init(&self->tr_state_ns, file_system_id_td, fs_key,
+                  &self->dev_ns.dev, &self->dev_ns_rpmb.dev, ns_init_flags);
     if (ret < 0) {
-        goto err_get_td_max_size;
+        SS_ERR("%s: failed to initialize TD: %d\n", __func__, ret);
+        goto err_init_fs_ns_tr_state;
     }
-    state->dev_ns.dev.block_count = sz / state->dev_ns.dev.block_size;
+
+    return NS_INIT_SUCCESS;
+
+err_init_fs_ns_tr_state:
+    block_cache_dev_destroy(&self->dev_ns.dev);
+err_get_td_max_size:
+    ns_close_file(self->ipc_handle, self->dev_ns.ns_handle);
+    return ret;
+}
+
+/**
+ * destroy_ns_fs() - Destroy @self's NS fs and its backing block devices.
+ */
+static void destroy_ns_fs(struct block_device_tipc* self) {
+    fs_destroy(&self->tr_state_ns);
+    block_cache_dev_destroy(&self->dev_ns.dev);
+}
 
 #if HAS_FS_TDP
-    block_device_tipc_init_dev_ns(&state->dev_ns_tdp, state, false);
+/**
+ * init_tdp_fs() - Initialize @self's TDP fs and its backing block devices.
+ * @self:      The struct block_device_tipc to modify
+ * @fs_key:    The key to use for the filesystem.
+ * @partition: The RPMB blocks to use for the filesystem's superblocks.
+ *
+ * Return: NO_ERROR on success, error code less than 0 on error.
+ */
+static int init_tdp_fs(struct block_device_tipc* self,
+                       const struct key* fs_key,
+                       struct rpmb_span partition) {
+    block_device_tipc_init_dev_ns(&self->dev_ns_tdp, self->ipc_handle, false);
 
-    ret = ns_open_file(state->ipc_handle, "persist/0",
-                       &state->dev_ns_tdp.ns_handle, true);
+    int ret = block_device_ns_open_file(&self->dev_ns_tdp, tdp_filename, true);
     if (ret < 0) {
         SS_ERR("%s: failed to open tdp file (%d)\n", __func__, ret);
         goto err_open_tdp;
     }
 
-    ret = check_storage_size(state->ipc_handle, &state->dev_ns_tdp, &sz);
+    ret = set_storage_size(self->ipc_handle, &self->dev_ns_tdp);
     if (ret < 0) {
         goto err_get_tdp_max_size;
     }
-    state->dev_ns_tdp.dev.block_count = sz / state->dev_ns_tdp.dev.block_size;
-
-    state->fs_tdp.tr_state = &state->tr_state_ns_tdp;
 
-    block_device_tipc_init_dev_rpmb(&state->dev_ns_tdp_rpmb, state,
-                                    rpmb_part_sb_tdp_base,
-                                    rpmb_part_sb_ns_block_count, false);
+    block_device_tipc_init_dev_rpmb(&self->dev_ns_tdp_rpmb, self->rpmb_state,
+                                    partition.start, partition.block_count,
+                                    false);
 
+    uint32_t tdp_init_flags = FS_INIT_FLAGS_NONE;
 #if STORAGE_TDP_AUTO_CHECKPOINT_ENABLED
     if (!system_state_provisioning_allowed()) {
         /*
@@ -626,109 +733,77 @@ int block_device_tipc_init(struct block_device_tipc* state,
     }
 #endif
 
-    ret = fs_init(&state->tr_state_ns_tdp, file_system_id_tdp, fs_key,
-                  &state->dev_ns_tdp.dev, &state->dev_ns_tdp_rpmb.dev,
+    ret = fs_init(&self->tr_state_ns_tdp, file_system_id_tdp, fs_key,
+                  &self->dev_ns_tdp.dev, &self->dev_ns_tdp_rpmb.dev,
                   tdp_init_flags);
     if (ret < 0) {
         goto err_init_fs_ns_tdp_tr_state;
     }
 
 #if STORAGE_TDP_RECOVERY_CHECKPOINT_RESTORE_ALLOWED
-    if (fs_check(&state->tr_state_ns_tdp) == FS_CHECK_INVALID_BLOCK) {
+    if (fs_check(&self->tr_state_ns_tdp) == FS_CHECK_INVALID_BLOCK) {
         SS_ERR("%s: TDP filesystem check failed with invalid block, "
                "attempting to restore checkpoint\n",
                __func__);
-        fs_destroy(&state->tr_state_ns_tdp);
-        ret = fs_init(&state->tr_state_ns_tdp, file_system_id_tdp, fs_key,
-                      &state->dev_ns_tdp.dev, &state->dev_ns_tdp_rpmb.dev,
+        fs_destroy(&self->tr_state_ns_tdp);
+        ret = fs_init(&self->tr_state_ns_tdp, file_system_id_tdp, fs_key,
+                      &self->dev_ns_tdp.dev, &self->dev_ns_tdp_rpmb.dev,
                       tdp_init_flags | FS_INIT_FLAGS_RESTORE_CHECKPOINT);
         if (ret < 0) {
+            SS_ERR("%s: failed to initialize TDP: %d\n", __func__, ret);
             goto err_init_fs_ns_tdp_tr_state;
         }
     }
 #endif
 
-#else
-    /*
-     * Create STORAGE_CLIENT_TDP_PORT alias after we know the backing file for
-     * STORAGE_CLIENT_TD_PORT is available. On future devices, using HAS_FS_TDP,
-     * STORAGE_CLIENT_TDP_PORT will not be available when the bootloader is
-     * running, so we limit access to this alias as well to prevent apps
-     * developed on old devices from relying on STORAGE_CLIENT_TDP_PORT being
-     * available early.
-     */
-    state->fs_tdp.tr_state = &state->tr_state_rpmb;
-#endif
-
-    storage_aidl_enable_filesystem(aidl_ctx, state->fs_tdp.tr_state,
-                                   STORAGE_AIDL_TDP);
-    ret = client_create_port(hset, &state->fs_tdp.client_ctx,
-                             STORAGE_CLIENT_TDP_PORT);
-    if (ret < 0) {
-        goto err_fs_rpmb_tdp_create_port;
-    }
-
-    /* Request empty file system if file is empty */
-    ret = ns_read_pos(state->ipc_handle, state->dev_ns.ns_handle, 0, &probe,
-                      sizeof(probe));
-    if (ret < (int)sizeof(probe)) {
-        ns_init_flags |= FS_INIT_FLAGS_DO_CLEAR;
-    }
-
-    state->fs_ns.tr_state = &state->tr_state_ns;
+    return 0;
 
-    block_device_tipc_init_dev_rpmb(&state->dev_ns_rpmb, state, rpmb_part1_base,
-                                    rpmb_part_sb_ns_block_count, true);
+err_init_fs_ns_tdp_tr_state:
+    block_cache_dev_destroy(&self->dev_ns_tdp.dev);
+err_get_tdp_max_size:
+    ns_close_file(self->ipc_handle, self->dev_ns_tdp.ns_handle);
+err_open_tdp:
+    return ret;
+}
 
-#if STORAGE_NS_RECOVERY_CLEAR_ALLOWED
-    ns_init_flags |= FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED;
+/**
+ * destroy_tdp_fs() - Destroy @self's TDP fs and its backing block devices.
+ */
+static void destroy_tdp_fs(struct block_device_tipc* self) {
+    fs_destroy(&self->tr_state_ns_tdp);
+    block_cache_dev_destroy(&self->dev_ns_tdp.dev);
+}
 #endif
 
-    /*
-     * This must be false if STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED is
-     * false.
-     */
-    if (alternate_data_partition) {
-        ns_init_flags |= FS_INIT_FLAGS_ALTERNATE_DATA;
-    }
-
-    ret = fs_init(&state->tr_state_ns, file_system_id_td, fs_key,
-                  &state->dev_ns.dev, &state->dev_ns_rpmb.dev, ns_init_flags);
-    if (ret < 0) {
-        goto err_init_fs_ns_tr_state;
-    }
-
-    storage_aidl_enable_filesystem(aidl_ctx, state->fs_ns.tr_state,
-                                   STORAGE_AIDL_TD);
-    ret = client_create_port(hset, &state->fs_ns.client_ctx,
-                             STORAGE_CLIENT_TD_PORT);
-    if (ret < 0) {
-        goto err_fs_ns_create_port;
-    }
-
 #if HAS_FS_NSP
-    block_device_tipc_init_dev_ns(&state->dev_ns_nsp, state, false);
+/**
+ * init_nsp_fs() - Initialize @self's NSP fs and its backing block devices.
+ * @self:      The struct block_device_tipc to modify
+ * @fs_key:    The key to use for the filesystem.
+ *
+ * Return: NO_ERROR on success, error code less than 0 on error.
+ */
+static int init_nsp_fs(struct block_device_tipc* self,
+                       const struct key* fs_key) {
+    block_device_tipc_init_dev_ns(&self->dev_ns_nsp, self->ipc_handle, false);
 
-    ret = ns_open_file(state->ipc_handle, "persist/nsp",
-                       &state->dev_ns_nsp.ns_handle, true);
+    int ret = block_device_ns_open_file(&self->dev_ns_nsp, nsp_filename, true);
     if (ret < 0) {
         SS_ERR("%s: failed to open NSP file (%d)\n", __func__, ret);
         goto err_open_nsp;
     }
 
-    ret = check_storage_size(state->ipc_handle, &state->dev_ns_nsp, &sz);
+    ret = set_storage_size(self->ipc_handle, &self->dev_ns_nsp);
     if (ret < 0) {
         goto err_get_nsp_max_size;
     }
-    state->dev_ns_nsp.dev.block_count = sz / state->dev_ns_nsp.dev.block_size;
-
-    state->fs_nsp.tr_state = &state->tr_state_ns_nsp;
 
-    ret = fs_init(&state->tr_state_ns_nsp, file_system_id_nsp, fs_key,
-                  &state->dev_ns_nsp.dev, &state->dev_ns_nsp.dev,
+    ret = fs_init(&self->tr_state_ns_nsp, file_system_id_nsp, fs_key,
+                  &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev,
                   FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED |
                           FS_INIT_FLAGS_ALLOW_TAMPERING);
     if (ret < 0) {
+        SS_ERR("%s: failed to initialize NSP: %d\n", __func__, ret);
         goto err_init_fs_ns_nsp_tr_state;
     }
 
@@ -736,108 +811,323 @@ int block_device_tipc_init(struct block_device_tipc* state,
      * Check that all files are accessible and attempt to clear the FS if files
      * cannot be accessed.
      */
-    if (fs_check(&state->tr_state_ns_nsp) != FS_CHECK_NO_ERROR) {
+    if (fs_check(&self->tr_state_ns_nsp) != FS_CHECK_NO_ERROR) {
         SS_ERR("%s: NSP filesystem check failed, attempting to clear\n",
                __func__);
-        fs_destroy(&state->tr_state_ns_nsp);
-        block_cache_dev_destroy(&state->dev_ns_nsp.dev);
+        fs_destroy(&self->tr_state_ns_nsp);
+        block_cache_dev_destroy(&self->dev_ns_nsp.dev);
 
-        ret = fs_init(&state->tr_state_ns_nsp, file_system_id_nsp, fs_key,
-                      &state->dev_ns_nsp.dev, &state->dev_ns_nsp.dev,
+        ret = fs_init(&self->tr_state_ns_nsp, file_system_id_nsp, fs_key,
+                      &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev,
                       FS_INIT_FLAGS_DO_CLEAR | FS_INIT_FLAGS_ALLOW_TAMPERING);
         if (ret < 0) {
+            SS_ERR("%s: failed to initialize NSP: %d\n", __func__, ret);
             goto err_init_fs_ns_nsp_tr_state;
         }
     }
+    return 0;
 
-#else
-    /*
-     * Create STORAGE_CLIENT_NSP_PORT alias to TDP if we don't support NSP on
-     * this build. TDP has stronger security properties than NSP, and NSP may be
-     * reset at any point, so this should be acceptable for clients.
-     */
-    state->fs_nsp.tr_state = state->fs_tdp.tr_state;
+err_init_fs_ns_nsp_tr_state:
+    block_cache_dev_destroy(&self->dev_ns_nsp.dev);
+err_get_nsp_max_size:
+    ns_close_file(self->ipc_handle, self->dev_ns_nsp.ns_handle);
+err_open_nsp:
+    return ret;
+}
+
+/**
+ * destroy_nsp_fs() - Destroy @self's NSP fs and its backing block devices.
+ */
+static void destroy_nsp_fs(struct block_device_tipc* self) {
+    fs_destroy(&self->tr_state_ns_nsp);
+    block_cache_dev_destroy(&self->dev_ns_nsp.dev);
+}
+#endif
+
+static void block_device_ns_disconnect(struct block_device_ns* self) {
+    if (self->ipc_handle != INVALID_IPC_HANDLE) {
+        ns_close_file(self->ipc_handle, self->ns_handle);
+        self->ipc_handle = INVALID_IPC_HANDLE;
+    }
+}
+
+static int init_ns_backed_filesystems(struct block_device_tipc* self,
+                                      const struct key* fs_key,
+                                      struct rpmb_span ns_partition,
+                                      struct rpmb_span tdp_partition) {
+    int ret = init_ns_fs(self, fs_key, ns_partition);
+    if (ret == NS_INIT_NOT_READY) {
+        /* If we don't currently have ns access, we didn't actually initialize
+         * `tr_state_ns`. Trying to init any other ns-dependent fs would fail,
+         * so skip them. */
+        assert(!block_device_tipc_has_ns(self));
+        return 0;
+    } else if (ret < 0) {
+        goto err_init_ns_fs;
+    }
+
+#if HAS_FS_TDP
+    ret = init_tdp_fs(self, fs_key, tdp_partition);
+    if (ret < 0) {
+        goto err_init_tdp_fs;
+    }
 #endif
 
-    storage_aidl_enable_filesystem(aidl_ctx, state->fs_nsp.tr_state,
-                                   STORAGE_AIDL_NSP);
-    ret = client_create_port(hset, &state->fs_nsp.client_ctx,
-                             STORAGE_CLIENT_NSP_PORT);
+#if HAS_FS_NSP
+    ret = init_nsp_fs(self, fs_key);
     if (ret < 0) {
-        goto err_fs_nsp_create_port;
+        goto err_init_nsp_fs;
     }
+#endif
 
     return 0;
 
-err_fs_nsp_create_port:
 #if HAS_FS_NSP
-    fs_destroy(&state->tr_state_ns_nsp);
-err_init_fs_ns_nsp_tr_state:
-    block_cache_dev_destroy(&state->dev_ns_nsp.dev);
-err_get_nsp_max_size:
-    ns_close_file(state->ipc_handle, state->dev_ns_nsp.ns_handle);
-err_open_nsp:
+err_init_nsp_fs:
 #endif
-    ipc_port_destroy(&state->fs_ns.client_ctx);
-err_fs_ns_create_port:
-    fs_destroy(&state->tr_state_ns);
-err_init_fs_ns_tr_state:
-    block_cache_dev_destroy(&state->dev_ns.dev);
-    ipc_port_destroy(&state->fs_tdp.client_ctx);
-err_fs_rpmb_tdp_create_port:
 #if HAS_FS_TDP
-    fs_destroy(&state->tr_state_ns_tdp);
-err_init_fs_ns_tdp_tr_state:
-    block_cache_dev_destroy(&state->dev_ns_tdp.dev);
-err_get_tdp_max_size:
-    ns_close_file(state->ipc_handle, state->dev_ns_tdp.ns_handle);
-err_open_tdp:
+    block_device_ns_disconnect(&self->dev_ns_tdp);
+    destroy_tdp_fs(self);
+err_init_tdp_fs:
 #endif
-err_get_td_max_size:
-    ns_close_file(state->ipc_handle, state->dev_ns.ns_handle);
-    ipc_port_destroy(&state->fs_rpmb_boot.client_ctx);
-err_fs_rpmb_boot_create_port:
-    ipc_port_destroy(&state->fs_rpmb.client_ctx);
-err_fs_rpmb_create_port:
-    fs_destroy(&state->tr_state_rpmb);
-err_init_tr_state_rpmb:
-    block_cache_dev_destroy(&state->dev_rpmb.dev);
-err_bad_rpmb_size:
+    block_device_ns_disconnect(&self->dev_ns);
+    destroy_ns_fs(self);
+err_init_ns_fs:
+    return ret;
+}
+
+/**
+ * rpmb_span_end() - Calculates the first block past the end of @self.
+ */
+static uint16_t rpmb_span_end(struct rpmb_span self) {
+    return self.start + self.block_count;
+}
+
+/**
+ * calculate_rpmb_spans() - Determines the starts and sizes of RPMB partitions.
+ */
+static void calculate_rpmb_spans(struct rpmb_spans* out) {
+    out->key.block_count = 1;
+    /* Used to store superblocks */
+    out->ns.block_count = 2;
+#if HAS_FS_TDP
+    out->tdp.block_count = out->ns.block_count;
+#else
+    out->tdp.block_count = 0;
+#endif
+
+    out->key.start = 0;
+    out->ns.start = rpmb_span_end(out->key);
+    out->tdp.start = rpmb_span_end(out->ns);
+    out->rpmb_start = rpmb_span_end(out->tdp);
+}
+
+int block_device_tipc_init(struct block_device_tipc* state,
+                           handle_t ipc_handle,
+                           const struct key* fs_key,
+                           const struct rpmb_key* rpmb_key,
+                           hwkey_session_t hwkey_session) {
+    int ret;
+    struct rpmb_spans partitions;
+    calculate_rpmb_spans(&partitions);
+
+    state->ipc_handle = ipc_handle;
+
+    /* init rpmb */
+    ret = rpmb_init(&state->rpmb_state, &state->ipc_handle);
+    if (ret < 0) {
+        SS_ERR("%s: rpmb_init failed (%d)\n", __func__, ret);
+        goto err_rpmb_init;
+    }
+
+    ret = block_device_tipc_init_rpmb_key(state->rpmb_state, rpmb_key,
+                                          partitions.key.start, hwkey_session);
+    if (ret < 0) {
+        SS_ERR("%s: block_device_tipc_init_rpmb_key failed (%d)\n", __func__,
+               ret);
+        goto err_init_rpmb_key;
+    }
+
+    ret = init_rpmb_fs(state, fs_key, partitions.rpmb_start);
+    if (ret < 0) {
+        goto err_init_rpmb_fs;
+    }
+
+    ret = init_ns_backed_filesystems(state, fs_key, partitions.ns,
+                                     partitions.tdp);
+    if (ret < 0) {
+        goto err_init_ns_fs;
+    }
+
+    return 0;
+
+err_init_ns_fs:
+    destroy_rpmb_fs(state);
+err_init_rpmb_fs:
 err_init_rpmb_key:
     rpmb_uninit(state->rpmb_state);
 err_rpmb_init:
     return ret;
 }
 
-void block_device_tipc_uninit(struct block_device_tipc* state) {
-    if (state->dev_ns.dev.block_count) {
-        storage_aidl_disable_filesystem(state->aidl_ctx, STORAGE_AIDL_TD);
-        ipc_port_destroy(&state->fs_ns.client_ctx);
-        fs_destroy(&state->tr_state_ns);
-        block_cache_dev_destroy(&state->dev_ns.dev);
-        ns_close_file(state->ipc_handle, state->dev_ns.ns_handle);
+void block_device_tipc_destroy(struct block_device_tipc* state) {
+    if (block_device_tipc_has_ns(state)) {
+#if HAS_FS_NSP
+        destroy_nsp_fs(state);
+#endif
+#if HAS_FS_TDP
+        destroy_tdp_fs(state);
+#endif
+        destroy_ns_fs(state);
+    }
 
-        storage_aidl_disable_filesystem(state->aidl_ctx, STORAGE_AIDL_TDP);
-        ipc_port_destroy(&state->fs_tdp.client_ctx);
+    destroy_rpmb_fs(state);
+    rpmb_uninit(state->rpmb_state);
+}
+
+bool block_device_tipc_fs_connected(struct block_device_tipc* self,
+                                    enum storage_filesystem_type fs_type) {
+    switch (fs_type) {
+    case STORAGE_TP:
+        return self->ipc_handle != INVALID_IPC_HANDLE;
+    case STORAGE_TDEA:
+        return self->ipc_handle != INVALID_IPC_HANDLE;
+    case STORAGE_TD:
+        return block_device_tipc_has_ns(self) &&
+               self->dev_ns.ipc_handle != INVALID_IPC_HANDLE;
+    case STORAGE_TDP:
 #if HAS_FS_TDP
-        fs_destroy(&state->tr_state_ns_tdp);
-        block_cache_dev_destroy(&state->dev_ns_tdp.dev);
-        ns_close_file(state->ipc_handle, state->dev_ns_tdp.ns_handle);
+        return block_device_tipc_has_ns(self) &&
+               self->dev_ns_tdp.ipc_handle != INVALID_IPC_HANDLE;
+#else
+        return block_device_tipc_fs_connected(self, STORAGE_TP);
 #endif
+    case STORAGE_NSP:
+#if HAS_FS_NSP
+        return block_device_tipc_has_ns(self) &&
+               self->dev_ns_nsp.ipc_handle != INVALID_IPC_HANDLE;
+#else
+        return block_device_tipc_fs_connected(self, STORAGE_TDP);
+#endif
+    case STORAGE_FILESYSTEMS_COUNT:
+    default:
+        SS_ERR("%s: Tried to check fs of unrecognized storage_filesystem type: (%d)\n",
+               __func__, fs_type);
+        return false;
+    }
+}
 
-        storage_aidl_disable_filesystem(state->aidl_ctx, STORAGE_AIDL_NSP);
-        ipc_port_destroy(&state->fs_nsp.client_ctx);
+struct fs* block_device_tipc_get_fs(struct block_device_tipc* self,
+                                    enum storage_filesystem_type fs_type) {
+    assert(block_device_tipc_fs_connected(self, fs_type));
+
+    switch (fs_type) {
+    case STORAGE_TP:
+        return &self->tr_state_rpmb;
+    case STORAGE_TDEA:
+        return &self->tr_state_rpmb;
+    case STORAGE_TD:
+        return &self->tr_state_ns;
+    case STORAGE_TDP:
+#if HAS_FS_TDP
+        return &self->tr_state_ns_tdp;
+#else
+        return block_device_tipc_get_fs(self, STORAGE_TP);
+#endif
+    case STORAGE_NSP:
 #if HAS_FS_NSP
-        fs_destroy(&state->tr_state_ns_nsp);
-        block_cache_dev_destroy(&state->dev_ns_nsp.dev);
-        ns_close_file(state->ipc_handle, state->dev_ns_nsp.ns_handle);
+        return &self->tr_state_ns_nsp;
+#else
+        return block_device_tipc_get_fs(self, STORAGE_TDP);
+#endif
+    case STORAGE_FILESYSTEMS_COUNT:
+    default:
+        SS_ERR("%s: Tried to init fs of unrecognized storage_filesystem type: (%d)\n",
+               __func__, fs_type);
+        return NULL;
+    }
+}
+
+int block_device_tipc_reconnect(struct block_device_tipc* self,
+                                handle_t ipc_handle,
+                                const struct key* fs_key) {
+    int ret;
+
+    assert(self->ipc_handle == INVALID_IPC_HANDLE);
+    /* rpmb_state keeps a pointer to this handle, so updating here will cause
+     * all the rpmb connections to use the new handle. */
+    self->ipc_handle = ipc_handle;
+
+    bool has_ns = block_device_tipc_has_ns(self);
+    if (!has_ns) {
+        struct rpmb_spans partitions;
+        calculate_rpmb_spans(&partitions);
+        ret = init_ns_backed_filesystems(self, fs_key, partitions.ns,
+                                         partitions.tdp);
+        if (ret < 0) {
+            SS_ERR("%s: failed to init NS backed filesystems (%d)\n", __func__,
+                   ret);
+            return ret;
+        }
+        return 0;
+    }
+
+    bool alternate_data_partition;
+    self->dev_ns.ipc_handle = ipc_handle;
+    ret = block_device_ns_open_file_with_alternate(&self->dev_ns, ns_filename,
+                                                   ns_alternate_filename, false,
+                                                   &alternate_data_partition);
+    if (ret < 0) {
+        /* NS not available right now; leave NS filesystems disconnected. */
+        self->dev_ns.ipc_handle = INVALID_IPC_HANDLE;
+        SS_ERR("%s: failed to reconnect ns filesystem (%d)\n", __func__, ret);
+        return 0;
+    }
+    assert(alternate_data_partition == self->tr_state_ns.alternate_data);
+#if HAS_FS_TDP
+    self->dev_ns_tdp.ipc_handle = ipc_handle;
+    ret = block_device_ns_open_file(&self->dev_ns_tdp, tdp_filename, false);
+    if (ret < 0) {
+        SS_ERR("%s: failed to reconnect tdp filesystem (%d)\n", __func__, ret);
+        self->dev_ns_tdp.ipc_handle = INVALID_IPC_HANDLE;
+        goto err_reconnect_tdp;
+    }
+#endif
+#if HAS_FS_NSP
+    self->dev_ns_nsp.ipc_handle = ipc_handle;
+    ret = block_device_ns_open_file(&self->dev_ns_nsp, nsp_filename, false);
+    if (ret < 0) {
+        SS_ERR("%s: failed to reconnect nsp filesystem (%d)\n", __func__, ret);
+        self->dev_ns_nsp.ipc_handle = INVALID_IPC_HANDLE;
+        goto err_reconnect_nsp;
+    }
+#endif
+
+    return 0;
+#if HAS_FS_NSP
+err_reconnect_nsp:
+#endif
+#if HAS_FS_TDP
+    block_device_ns_disconnect(&self->dev_ns_tdp);
+err_reconnect_tdp:
+#endif
+    block_device_ns_disconnect(&self->dev_ns);
+    return ret;
+}
+
+void block_device_tipc_disconnect(struct block_device_tipc* self) {
+    /* Must currently be connected to disconnect */
+    assert(self->ipc_handle != INVALID_IPC_HANDLE);
+    /* Disconnects rpmb */
+    self->ipc_handle = INVALID_IPC_HANDLE;
+
+    if (block_device_tipc_has_ns(self)) {
+        block_device_ns_disconnect(&self->dev_ns);
+#if HAS_FS_TDP
+        block_device_ns_disconnect(&self->dev_ns_tdp);
+#endif
+#if HAS_FS_NSP
+        block_device_ns_disconnect(&self->dev_ns_nsp);
 #endif
     }
-    storage_aidl_disable_filesystem(state->aidl_ctx, STORAGE_AIDL_TDEA);
-    ipc_port_destroy(&state->fs_rpmb_boot.client_ctx);
-    storage_aidl_disable_filesystem(state->aidl_ctx, STORAGE_AIDL_TP);
-    ipc_port_destroy(&state->fs_rpmb.client_ctx);
-    fs_destroy(&state->tr_state_rpmb);
-    block_cache_dev_destroy(&state->dev_rpmb.dev);
-    rpmb_uninit(state->rpmb_state);
 }
diff --git a/block_device_tipc.h b/block_device_tipc.h
index b42d7c8..787172b 100644
--- a/block_device_tipc.h
+++ b/block_device_tipc.h
@@ -16,18 +16,16 @@
 
 #pragma once
 
+#include <stdint.h>
+
 #include <lib/hwkey/hwkey.h>
-#include <lib/tipc/tipc.h>
 #include <trusty_ipc.h>
 
-#include "aidl_service.h"
 #include "block_device.h"
-#include "ipc.h"
+#include "crypt.h"
+#include "fs.h"
+#include "rpmb.h"
 #include "tipc_ns.h"
-#include "transaction.h"
-
-struct rpmb_key;
-struct block_device_tipc;
 
 /**
  * DOC: File System Identifiers
@@ -56,17 +54,26 @@ extern const char file_system_id_tdp[];
 extern const char file_system_id_tp[];
 extern const char file_system_id_nsp[];
 
+enum storage_filesystem_type {
+    STORAGE_TP,
+    STORAGE_TDEA,
+    STORAGE_TD,
+    STORAGE_TDP,
+    STORAGE_NSP,
+    STORAGE_FILESYSTEMS_COUNT,
+};
+
 /**
  * struct block_device_rpmb
- * @state:       Pointer to shared state containing ipc_handle and rpmb_state
  * @dev:         Block device state
+ * @rpmb_state:  State of the backing rpmb
  * @base:        First block to use in rpmb partition
  * @is_userdata: Is this RPMB device tied to the state of the userdata
  * partition?
  */
 struct block_device_rpmb {
     struct block_device dev;
-    struct block_device_tipc* state;
+    struct rpmb_state* rpmb_state;
     uint16_t base;
     bool is_userdata;
 };
@@ -74,63 +81,139 @@ struct block_device_rpmb {
 /**
  * struct block_device_ns
  * @dev:        Block device state
- * @state:      Pointer to shared state containing ipc_handle
- * @ns_handle:  Handle
+ * @ipc_handle: IPC handle to use to talk to ns
+ * @ns_handle:  Handle of the backing ns file
  * @is_userdata: Is the backing file for this device in the (non-persistent)
  *               userdata partition?
  */
 struct block_device_ns {
     struct block_device dev;
-    struct block_device_tipc* state;
+    handle_t ipc_handle;
     ns_handle_t ns_handle;
     bool is_userdata;
 };
 
-struct client_port_context {
-    struct fs* tr_state;
-    struct ipc_port_context client_ctx;
-};
-
 /**
  * struct block_device_tipc
- * @ipc_handle
+ * @ipc_handle:            IPC handle to use to talk to storageproxy.
+ * @rpmb_state:            State of the backing rpmb. Holds a pointer to
+ *                         @ipc_handle.
+ * @dev_rpmb:              The rpmb block device backing @tr_state_rpmb.
+ * @tr_state_rpmb:         Filesystem for rpmb (TP, TDEA).
+ * @dev_ns:                The rpmb block device containing the superblock for
+ *                         @tr_state_ns.
+ * @dev_ns_rpmb:           The rpmb block device backing @tr_state_ns.
+ * @tr_state_ns:           Filesystem for TD.
+ * @dev_ns_tdp:            The ns block device backing @tr_state_ns_tdp. Only
+ *                         present when $HAS_FS_TDP defined.
+ * @dev_ns_tdp_rpmb:       The rpmb block device containing the superblock for
+ *                         @tr_state_ns_tdp. Only present when $HAS_FS_TDP
+ *                         defined.
+ * @tr_state_ns_tdp:       Filesystem for TDP. Only present when $HAS_FS_TDP
+ *                         defined.
+ * @dev_ns_nsp:            The ns block device backing @tr_state_ns_nsp. Only
+ *                         present when $HAS_FS_NSP defined.
+ * @dev_ns_nsp_superblock: The ns block device containing the superblock for
+ *                         @tr_state_ns_nsp. Only present when $HAS_FS_NSP
+ *                         defined.
+ * @tr_state_ns_nsp:       Filesystem for NSP. Only present when $HAS_FS_NSP
+ *                         defined.
  */
-
 struct block_device_tipc {
     handle_t ipc_handle;
     struct rpmb_state* rpmb_state;
-    struct storage_service_aidl_context* aidl_ctx;
 
     struct block_device_rpmb dev_rpmb;
     struct fs tr_state_rpmb;
-    struct client_port_context fs_rpmb;
-    struct client_port_context fs_rpmb_boot;
+
+    struct block_device_ns dev_ns;
+    struct block_device_rpmb dev_ns_rpmb;
+    struct fs tr_state_ns;
 
 #if HAS_FS_TDP
     struct block_device_ns dev_ns_tdp;
     struct block_device_rpmb dev_ns_tdp_rpmb;
     struct fs tr_state_ns_tdp;
 #endif
-    struct client_port_context fs_tdp;
 
 #if HAS_FS_NSP
     struct block_device_ns dev_ns_nsp;
     struct block_device_ns dev_ns_nsp_superblock;
     struct fs tr_state_ns_nsp;
 #endif
-    struct client_port_context fs_nsp;
-
-    struct block_device_ns dev_ns;
-    struct block_device_rpmb dev_ns_rpmb;
-    struct fs tr_state_ns;
-    struct client_port_context fs_ns;
 };
 
-int block_device_tipc_init(struct block_device_tipc* state,
-                           struct tipc_hset* hset,
-                           struct storage_service_aidl_context* aidl_ctx,
+__BEGIN_CDECLS
+
+/**
+ * block_device_tipc_init() - Initialize a block device context
+ * @self: Out param. Will contain the created &struct block_device_tipc,
+ * which must later be cleaned up by passing to block_device_tipc_destroy()
+ * @ipc_handle: IPC handle to use to talk to ns.
+ * @fs_key: Key used to decrypt filesystems.
+ * @rpmb_key: Key used to access rpmb. If null, a derived key will be used
+ * instead.
+ * @hwkey_session: HWCrpyto session handle to use for rpmb access.
+ */
+int block_device_tipc_init(struct block_device_tipc* self,
                            handle_t ipc_handle,
                            const struct key* fs_key,
                            const struct rpmb_key* rpmb_key,
                            hwkey_session_t hwkey_session);
-void block_device_tipc_uninit(struct block_device_tipc* state);
+
+/**
+ * block_device_tipc_destroy() - Destroy a block device context
+ * @self: The &struct block_device_tipc to destroy. Does not free the
+ * context's memory. Any &struct fs &self returned from calls to
+ * block_device_tipc_get_fs() must no longer be in use. @self must have
+ * already been disconnected with &block_device_tipc_disconnect().
+ */
+void block_device_tipc_destroy(struct block_device_tipc* self);
+
+/**
+ * block_device_tipc_fs_connected() - Check whether a given filesystem is
+ * connected
+ *
+ * @self: The &struct block_device_tipc from which to check for a filesystem.
+ * @fs_type: The type of filesystem to check.
+ */
+bool block_device_tipc_fs_connected(struct block_device_tipc* self,
+                                    enum storage_filesystem_type fs_type);
+
+/**
+ * block_device_tipc_get_fs() - Get a reference to one of the managed
+ * filesystems
+ *
+ * @self: The &struct block_device_tipc to get a filesystem from.
+ * @fs_type: The type of filesystem to get.
+ */
+struct fs* block_device_tipc_get_fs(struct block_device_tipc* self,
+                                    enum storage_filesystem_type fs_type);
+
+/**
+ * block_device_tipc_disconnect() - Disconnect from the block devices
+ *
+ * Severs ipc connections to the block devices/filesystems backing the &struct
+ * fs objects returned by &block_device_tipc_get_fs(). These fs objects state
+ * will be maintained, but they must not be used until
+ * &block_device_tipc_reconnect() is called.
+ *
+ * @self: The &struct block_device_tipc to disconnect.
+ */
+void block_device_tipc_disconnect(struct block_device_tipc* self);
+
+/**
+ * block_device_tipc_reconnect() - Reconnect to the block devices
+ *
+ * Reestablishes ipc connections to the block devices/filesystems backing the
+ * &struct fs objects returned by &block_device_tipc_get_fs().
+ *
+ * @self: The &struct block_device_tipc to reconnect.
+ * @ipc_handle: IPC handle to use to talk to backing block devices/filesystems.
+ * @fs_key: Key used to decrypt filesystems.
+ */
+int block_device_tipc_reconnect(struct block_device_tipc* self,
+                                handle_t ipc_handle,
+                                const struct key* fs_key);
+
+__END_CDECLS
diff --git a/client.c b/client.c
index 2b8d057..aca0180 100644
--- a/client.c
+++ b/client.c
@@ -26,7 +26,6 @@
 
 #include "client_session.h"
 #include "file.h"
-#include "session.h"
 #include "storage_limits.h"
 
 // macros to help manage debug output
diff --git a/client_tipc.c b/client_tipc.c
index 3284085..90eb06f 100644
--- a/client_tipc.c
+++ b/client_tipc.c
@@ -30,13 +30,12 @@
 #include <openssl/mem.h>
 #include <uapi/err.h>
 
-#include "block_device_tipc.h"
 #include "client.h"
 #include "client_session.h"
 #include "client_session_tipc.h"
 #include "ipc.h"
-#include "session.h"
 #include "storage_limits.h"
+#include "tipc_service.h"
 
 /* macros to help manage debug output */
 #define SS_ERR(args...) fprintf(stderr, "ss: " args)
diff --git a/error_reporting.c b/error_reporting.c
index 8de4e00..da19c4e 100644
--- a/error_reporting.c
+++ b/error_reporting.c
@@ -24,9 +24,9 @@
 #include <trusty/uuid.h>
 #include <trusty_log.h>
 
-#include <storage_consts.h>
 #include <interface/metrics/metrics.h>
-#include "block_device_tipc.h"
+#include <storage_consts.h>
+#include "tipc_service.h"
 
 #define TLOG_TAG "ss-err_rep"
 
diff --git a/main.c b/main.c
index 7722be5..036e26d 100644
--- a/main.c
+++ b/main.c
@@ -35,7 +35,7 @@
 
 int main(void) {
     struct proxy_connect_context ctx = {
-            .aidl_ctx = STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(.aidl_ctx),
+            .service = STORAGE_SERVICE_INITIAL_VALUE(.service),
             .tipc_ctx = {.ops = {.on_connect = proxy_connect}},
     };
     uint32_t acl_flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT;
@@ -49,14 +49,8 @@ int main(void) {
         return EXIT_FAILURE;
     }
 
-    int rc = storage_aidl_create_service(&ctx.aidl_ctx, hset);
-    if (rc < 0) {
-        SS_ERR("fatal: unable to initialize aidl endpoint (%d)\n", rc);
-        return rc;
-    }
-
-    rc = ipc_port_create(hset, &ctx.tipc_ctx, STORAGE_DISK_PROXY_PORT, 1,
-                         STORAGE_MAX_BUFFER_SIZE, acl_flags);
+    int rc = ipc_port_create(hset, &ctx.tipc_ctx, STORAGE_DISK_PROXY_PORT, 1,
+                             STORAGE_MAX_BUFFER_SIZE, acl_flags);
     if (rc < 0) {
         SS_ERR("fatal: unable to initialize proxy endpoint (%d)\n", rc);
         return rc;
@@ -69,7 +63,6 @@ int main(void) {
         return rc;
     }
     rc = tipc_run_event_loop(hset);
-    storage_aidl_delete_service(&ctx.aidl_ctx);
-    ipc_port_destroy(&ctx.tipc_ctx);
+    proxy_destroy(&ctx);
     return rc;
 }
diff --git a/proxy.c b/proxy.c
index c4c1cfd..16df2a1 100644
--- a/proxy.c
+++ b/proxy.c
@@ -26,9 +26,11 @@
 #include <lib/hwkey/hwkey.h>
 
 #include "aidl_service.h"
+#include "block_device.h"
+#include "block_device_tipc.h"
 #include "ipc.h"
 #include "rpmb.h"
-#include "session.h"
+#include "tipc_service.h"
 
 #define SS_ERR(args...) fprintf(stderr, "ss: " args)
 
@@ -86,20 +88,11 @@ static int get_rpmb_auth_key(hwkey_session_t session,
 }
 #endif
 
-struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
-                                          const uuid_t* peer_uuid,
-                                          handle_t chan_handle) {
-    struct rpmb_key* rpmb_key_ptr = NULL;
+static int storage_service_init(struct storage_service* self,
+                                struct tipc_hset* hset,
+                                handle_t chan_handle) {
     int rc;
 
-    struct storage_session* session = calloc(1, sizeof(*session));
-    if (session == NULL) {
-        SS_ERR("%s: out of memory\n", __func__);
-        goto err_alloc_session;
-    }
-
-    session->magic = STORAGE_SESSION_MAGIC;
-
     rc = hwkey_open();
     if (rc < 0) {
         SS_ERR("%s: hwkey init failed: %d\n", __func__, rc);
@@ -109,13 +102,14 @@ struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
     hwkey_session_t hwkey_session = (hwkey_session_t)rc;
 
     /* Generate encryption key */
-    rc = get_storage_encryption_key(hwkey_session, session->key.byte,
-                                    sizeof(session->key));
+    rc = get_storage_encryption_key(hwkey_session, self->key.byte,
+                                    sizeof(self->key));
     if (rc < 0) {
         SS_ERR("%s: can't get storage key: (%d) \n", __func__, rc);
         goto err_get_storage_key;
     }
 
+    struct rpmb_key* rpmb_key_ptr = NULL;
     /* Init RPMB key */
 #if !WITH_HKDF_RPMB_KEY
     struct rpmb_key rpmb_key;
@@ -128,23 +122,26 @@ struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
     rpmb_key_ptr = &rpmb_key;
 #endif
 
-    struct proxy_connect_context* proxy_ctx =
-            containerof(parent_ctx, struct proxy_connect_context, tipc_ctx);
-
-    rc = block_device_tipc_init(&session->block_device, parent_ctx->common.hset,
-                                &proxy_ctx->aidl_ctx, chan_handle,
-                                &session->key, rpmb_key_ptr, hwkey_session);
+    rc = block_device_tipc_init(&self->block_device, chan_handle, &self->key,
+                                rpmb_key_ptr, hwkey_session);
     if (rc < 0) {
         SS_ERR("%s: block_device_tipc_init failed (%d)\n", __func__, rc);
         goto err_init_block_device;
     }
 
-    session->proxy_ctx.ops.on_disconnect = proxy_disconnect;
+    rc = storage_aidl_create_service(&self->aidl, hset);
+    if (rc < 0) {
+        SS_ERR("%s: storage_aidl_create_service failed (%d)\n", __func__, rc);
+        goto err_aidl_create_service;
+    }
 
-    hwkey_close(hwkey_session);
+    storage_aidl_enable(&self->aidl, &self->block_device);
 
-    return &session->proxy_ctx;
+    hwkey_close(hwkey_session);
+    self->initialized = true;
+    return NO_ERROR;
 
+err_aidl_create_service:
 err_init_block_device:
 #if !WITH_HKDF_RPMB_KEY
 err_get_rpmb_key:
@@ -152,15 +149,93 @@ err_get_rpmb_key:
 err_get_storage_key:
     hwkey_close(hwkey_session);
 err_hwkey_open:
+    free(self);
+err_alloc_service:
+    return rc;
+}
+
+static void storage_service_disconnect(struct storage_service* self) {
+    storage_aidl_disable(&self->aidl);
+    block_device_tipc_disconnect(&self->block_device);
+}
+
+static int storage_service_reconnect(struct storage_service* self,
+                                     handle_t chan_handle) {
+    int rc = block_device_tipc_reconnect(&self->block_device, chan_handle,
+                                         &self->key);
+    if (rc < 0) {
+        return rc;
+    }
+
+    storage_aidl_enable(&self->aidl, &self->block_device);
+    return NO_ERROR;
+}
+
+static void storage_service_destroy(struct storage_service* self) {
+    storage_aidl_destroy_service(&self->aidl);
+    block_device_tipc_destroy(&self->block_device);
+}
+
+struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
+                                          const uuid_t* peer_uuid,
+                                          handle_t chan_handle) {
+    struct proxy_connect_context* self =
+            containerof(parent_ctx, struct proxy_connect_context, tipc_ctx);
+    struct tipc_hset* hset = parent_ctx->common.hset;
+    int rc;
+
+    if (!self->service.initialized) {
+        rc = storage_service_init(&self->service, hset, chan_handle);
+        if (rc < 0) {
+            goto err_service_init;
+        }
+    } else {
+        rc = storage_service_reconnect(&self->service, chan_handle);
+        if (rc < 0) {
+            goto err_service_reconnect;
+        }
+    }
+
+    struct storage_session* session = calloc(1, sizeof(*session));
+    if (session == NULL) {
+        SS_ERR("%s: out of memory\n", __func__);
+        goto err_alloc_session;
+    }
+
+    session->magic = STORAGE_SESSION_MAGIC;
+    session->service = &self->service;
+
+    rc = storage_tipc_service_init(&session->tipc,
+                                   &session->service->block_device, hset);
+    if (rc < 0) {
+        SS_ERR("%s: block_device_tipc_init failed (%d)\n", __func__, rc);
+        goto err_init_block_device_tipc;
+    }
+
+    session->proxy_ctx.ops.on_disconnect = proxy_disconnect;
+    return &session->proxy_ctx;
+
+err_init_block_device_tipc:
     free(session);
 err_alloc_session:
+    storage_service_disconnect(&self->service);
+err_service_reconnect:
+    storage_service_destroy(&self->service);
+err_service_init:
     return NULL;
 }
 
 void proxy_disconnect(struct ipc_channel_context* ctx) {
     struct storage_session* session = proxy_context_to_session(ctx);
+    struct storage_service* service = session->service;
 
-    block_device_tipc_uninit(&session->block_device);
-
+    storage_tipc_service_destroy(&session->tipc, &service->block_device);
     free(session);
+
+    storage_service_disconnect(service);
 }
+
+void proxy_destroy(struct proxy_connect_context* self) {
+    storage_service_destroy(&self->service);
+    ipc_port_destroy(&self->tipc_ctx);
+}
\ No newline at end of file
diff --git a/proxy.h b/proxy.h
index 315236a..6bda9d8 100644
--- a/proxy.h
+++ b/proxy.h
@@ -18,10 +18,55 @@
 #include <uapi/trusty_uuid.h>
 
 #include "aidl_service.h"
+#include "block_device_tipc.h"
+#include "crypt.h"
 #include "ipc.h"
+#include "tipc_service.h"
 
+#include "crypt.h"
+#include "ipc.h"
+#include "tipc_service.h"
+
+struct storage_service {
+    bool initialized;
+    struct key key;
+    struct block_device_tipc block_device;
+    struct storage_service_aidl_context aidl;
+};
+
+#define STORAGE_SERVICE_INITIAL_VALUE(self)                        \
+    (struct storage_service) {                                     \
+        .initialized = false,                                      \
+        .aidl = STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(.aidl), \
+    }
+
+/* SSSC (Secure Storage Session Context) */
+#define STORAGE_SESSION_MAGIC 0x53535343
+
+/**
+ * storage_session - Session that exists for the duration of a proxy connection
+ * @magic:        a sentinel value used for checking for data corruption.
+ *                Initialized to STORAGE_SESSION_MAGIC.
+ * @service:      storage app state that persists across connections
+ * @tipc:         tipc service accepting client connections and requests
+ * @proxy_ctx:    the context object on the proxy channel
+ */
+struct storage_session {
+    uint32_t magic;
+    struct storage_service* service;
+    struct storage_tipc_service tipc;
+
+    struct ipc_channel_context proxy_ctx;
+};
+
+/**
+ * proxy_connect_context - Context for opening a connection to storageproxy
+ *
+ * @service: storage app state
+ * @tipc_ctx: context object for the proxy port
+ */
 struct proxy_connect_context {
-    struct storage_service_aidl_context aidl_ctx;
+    struct storage_service service;
     struct ipc_port_context tipc_ctx;
 };
 
@@ -32,3 +77,13 @@ struct proxy_connect_context {
 struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
                                           const uuid_t* peer_uuid,
                                           handle_t chan_handle);
+
+/** proxy_destroy() - Clean up a &struct proxy_connect_context
+ *
+ * Does not free @self.
+ *
+ * @self: The proxy context to delete. Must have been previously connected to
+ * the proxy (see &proxy_connect()), but no longer have an active connection
+ * (see &proxy_disconnect()).
+ */
+void proxy_destroy(struct proxy_connect_context* self);
\ No newline at end of file
diff --git a/rules.mk b/rules.mk
index 093acbd..4412d4d 100644
--- a/rules.mk
+++ b/rules.mk
@@ -97,6 +97,7 @@ MODULE_SRCS := \
 	$(LOCAL_DIR)/rpmb.c \
 	$(LOCAL_DIR)/super.c \
 	$(LOCAL_DIR)/tipc_ns.c \
+	$(LOCAL_DIR)/tipc_service.c \
 	$(LOCAL_DIR)/transaction.c \
 
 MODULE_LIBRARY_DEPS := \
diff --git a/session.h b/session.h
deleted file mode 100644
index 13f9491..0000000
--- a/session.h
+++ /dev/null
@@ -1,40 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
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
-#pragma once
-
-#include "block_device_tipc.h"
-#include "crypt.h"
-#include "ipc.h"
-
-/* SSSC (Secure Storage Session Context) */
-#define STORAGE_SESSION_MAGIC 0x53535343
-
-/**
- * storage_proxy_session
- * @magic:        a sentinel value used for checking for data corruption.
- *                Initialized to STORAGE_SESSION_MAGIC.
- * @block_device: the file system state
- * @key:          storage encryption key
- * @proxy_ctx:    the context object on the proxy channel
- */
-struct storage_session {
-    uint32_t magic;
-    struct block_device_tipc block_device;
-    struct key key;
-
-    struct ipc_channel_context proxy_ctx;
-};
diff --git a/storage_mock/test_mock_storage_rules.mk b/storage_mock/test_mock_storage_rules.mk
index a45e9d2..6a57a41 100644
--- a/storage_mock/test_mock_storage_rules.mk
+++ b/storage_mock/test_mock_storage_rules.mk
@@ -28,5 +28,8 @@ HOST_FLAGS := \
 	-Wno-deprecated-declarations \
 	-DSTORAGE_FAKE \
 
+HOST_DEPS := \
+	trusty/user/base/host/unittest \
+
 include trusty/user/app/storage/storage_mock/add_mock_storage.mk
 include trusty/kernel/make/host_test.mk
diff --git a/test/storage-reconnect-test/main.cpp b/test/storage-reconnect-test/main.cpp
new file mode 100644
index 0000000..734fb8b
--- /dev/null
+++ b/test/storage-reconnect-test/main.cpp
@@ -0,0 +1,452 @@
+#include <cinttypes>
+#include <cstddef>
+#include <cstdint>
+#include <cstdlib>
+#include <vector>
+
+#include <lib/storage/storage.h>
+#include <lib/tipc/tipc.h>
+#include <lib/unittest/unittest.h>
+#include <trusty/time.h>
+#include <trusty_unittest.h>
+
+#include <binder/IBinder.h>
+#include <binder/RpcServerTrusty.h>
+#include <binder/RpcTransportTipcTrusty.h>
+
+#include <android/hardware/security/see/storage/Availability.h>
+#include <android/hardware/security/see/storage/CreationMode.h>
+#include <android/hardware/security/see/storage/FileMode.h>
+#include <android/hardware/security/see/storage/Filesystem.h>
+#include <android/hardware/security/see/storage/IFile.h>
+#include <android/hardware/security/see/storage/ISecureStorage.h>
+#include <android/hardware/security/see/storage/IStorageSession.h>
+#include <android/hardware/security/see/storage/Integrity.h>
+#include <android/hardware/security/see/storage/OpenOptions.h>
+
+// Needs to be included after AIDL files; definition of ERR_NOT_FOUND macro
+// breaks the AIDL definitions.
+#include <uapi/err.h>
+static const int err_not_found = ERR_NOT_FOUND;
+#undef ERR_NOT_FOUND
+
+using ::android::IBinder;
+using ::android::RpcSession;
+using ::android::RpcTransportCtxFactoryTipcTrusty;
+using ::android::sp;
+using ::android::status_t;
+using ::android::binder::Status;
+using ::android::binder::unique_fd;
+using ::android::hardware::security::see::storage::Availability;
+using ::android::hardware::security::see::storage::CreationMode;
+using ::android::hardware::security::see::storage::FileMode;
+using ::android::hardware::security::see::storage::Filesystem;
+using ::android::hardware::security::see::storage::IFile;
+using ::android::hardware::security::see::storage::Integrity;
+using ::android::hardware::security::see::storage::ISecureStorage;
+using ::android::hardware::security::see::storage::IStorageSession;
+using ::android::hardware::security::see::storage::OpenOptions;
+
+enum class FsType {
+    TP,
+    TDEA,
+    TD,
+    TDP,
+    NSP,
+};
+
+struct FsConnection {
+    storage_session_t tipc_session = STORAGE_INVALID_SESSION;
+    sp<IStorageSession> aidl_session = nullptr;
+};
+
+static const char aidl_port[] = "com.android.hardware.security.see.storage";
+static sp<ISecureStorage> aidl_storage = nullptr;
+static std::array<FsConnection, 5> connections;
+
+static FsType storage_test_client_fs;
+
+static const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7};
+
+static const char tipc_commit_file[] = "test_reconnect_committed_tipc";
+static const char tipc_nocommit_file[] = "test_reconnect_uncommitted_tipc";
+static const char aidl_commit_file[] = "test_reconnect_committed_aidl";
+static const char aidl_nocommit_file[] = "test_reconnect_uncommitted_aidl";
+
+#define TLOG_TAG "ss-reconnecttest"
+
+static const char* client_port(FsType fs_type) {
+    switch (fs_type) {
+    case FsType::TP:
+        return STORAGE_CLIENT_TP_PORT;
+    case FsType::TDEA:
+        return STORAGE_CLIENT_TDEA_PORT;
+    case FsType::TD:
+        return STORAGE_CLIENT_TD_PORT;
+    case FsType::TDP:
+        return STORAGE_CLIENT_TDP_PORT;
+    case FsType::NSP:
+        return STORAGE_CLIENT_NSP_PORT;
+    }
+}
+
+static bool client_fs(FsType fs_type, Filesystem* out) {
+    switch (fs_type) {
+    case FsType::TP:
+        *out = Filesystem();
+        out->integrity = Integrity::TAMPER_PROOF_AT_REST;
+        out->availability = Availability::AFTER_USERDATA;
+        out->persistent = false;
+        return true;
+    case FsType::TDEA:
+        *out = Filesystem();
+        out->integrity = Integrity::TAMPER_DETECT;
+        out->availability = Availability::BEFORE_USERDATA;
+        out->persistent = false;
+        return true;
+    case FsType::TD:
+        *out = Filesystem();
+        out->integrity = Integrity::TAMPER_DETECT;
+        out->availability = Availability::AFTER_USERDATA;
+        out->persistent = false;
+        return true;
+    case FsType::TDP:
+        *out = Filesystem();
+        out->integrity = Integrity::TAMPER_DETECT;
+        out->availability = Availability::AFTER_USERDATA;
+        out->persistent = true;
+        return true;
+    case FsType::NSP:
+        // AIDL service never accesses NSP currently
+        return false;
+    }
+}
+
+TEST(StorageReconnectBeforeTest, TipcWrite) {
+    int rc;
+    file_handle_t handle;
+    storage_session_t& session =
+            connections[static_cast<size_t>(storage_test_client_fs)]
+                    .tipc_session;
+
+    if (session != STORAGE_INVALID_SESSION) {
+        storage_close_session(session);
+        session = STORAGE_INVALID_SESSION;
+    }
+
+    rc = storage_open_session(&session, client_port(storage_test_client_fs));
+    ASSERT_EQ(0, rc);
+
+    // Ensure files doesn't exist.
+    rc = storage_delete_file(session, tipc_commit_file, STORAGE_OP_COMPLETE);
+    rc = (rc == err_not_found) ? 0 : rc;
+    ASSERT_EQ(0, rc);
+    rc = storage_delete_file(session, tipc_nocommit_file, STORAGE_OP_COMPLETE);
+    rc = (rc == err_not_found) ? 0 : rc;
+    ASSERT_EQ(0, rc);
+
+    // Write to file.
+    rc = storage_open_file(
+            session, &handle, tipc_commit_file,
+            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE, 0);
+    ASSERT_EQ(0, rc);
+
+    rc = storage_write(handle, 0, &data, sizeof(data), STORAGE_OP_COMPLETE);
+    EXPECT_EQ(sizeof(data), rc);
+    storage_close_file(handle);
+
+    // Write to file, but don't commit.
+    rc = storage_open_file(
+            session, &handle, tipc_nocommit_file,
+            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE, 0);
+    ASSERT_EQ(0, rc);
+
+    rc = storage_write(handle, 0, &data, sizeof(data), 0);
+    EXPECT_EQ(sizeof(data), rc);
+    storage_close_file(handle);
+
+test_abort:;
+}
+
+TEST(StorageReconnectDuringTest, TipcCheckSessionInvalid) {
+    int rc;
+    storage_session_t& session =
+            connections[static_cast<size_t>(storage_test_client_fs)]
+                    .tipc_session;
+
+    // StorageReconnectBeforeTest should have already run
+    ASSERT_NE(STORAGE_INVALID_SESSION, session);
+
+    // Can't commit; storageproxyd disconnected
+    rc = storage_end_transaction(session, true);
+    EXPECT_EQ(ERR_CHANNEL_CLOSED, rc);
+
+test_abort:;
+}
+
+TEST(StorageReconnectAfterTest, TipcCheckWritten) {
+    int rc;
+    file_handle_t handle;
+    storage_session_t& session =
+            connections[static_cast<size_t>(storage_test_client_fs)]
+                    .tipc_session;
+
+    // StorageReconnectBeforeTest should have already run
+    ASSERT_NE(STORAGE_INVALID_SESSION, session);
+
+    // Wait so that storage has time to reconnect to storageproxyd
+    storage_session_t temp_session;
+    rc = storage_open_session(&temp_session,
+                              client_port(storage_test_client_fs));
+
+    // Attempt to commit write from StorageReconnectBeforeTest
+    rc = storage_end_transaction(session, true);
+    // Fails because storageproxy rebooted and this session was abandoned
+    EXPECT_EQ(ERR_CHANNEL_CLOSED, rc);
+
+    session = temp_session;
+
+    // Read written file and check contents match data
+    static uint8_t buf[sizeof(data)];
+    rc = storage_open_file(session, &handle, tipc_commit_file, 0, 0);
+    ASSERT_EQ(0, rc);
+    rc = storage_read(handle, 0, &buf, sizeof(buf));
+    ASSERT_EQ(sizeof(data), rc);
+    for (size_t i = 0; i < sizeof(data); ++i) {
+        EXPECT_EQ(data[i], buf[i]);
+    }
+
+    // File doesn't exist because creation never committed
+    rc = storage_delete_file(session, tipc_nocommit_file, STORAGE_OP_COMPLETE);
+    EXPECT_EQ(err_not_found, rc);
+
+    storage_close_session(session);
+    session = STORAGE_INVALID_SESSION;
+test_abort:;
+}
+
+static OpenOptions create_exclusive() {
+    OpenOptions result;
+    result.createMode = CreationMode::CREATE_EXCLUSIVE;
+    result.accessMode = FileMode::READ_WRITE;
+    result.truncateOnOpen = true;
+    return result;
+}
+static OpenOptions no_create() {
+    OpenOptions result;
+    result.createMode = CreationMode::NO_CREATE;
+    result.accessMode = FileMode::READ_WRITE;
+    result.truncateOnOpen = false;
+    return result;
+}
+
+TEST(StorageReconnectBeforeTest, AidlWrite) {
+    auto vec_data = std::vector<uint8_t>(data, data + sizeof(data));
+    sp<IFile> file;
+    int64_t written;
+    Status ret;
+
+    Filesystem client;
+    bool enable_test = client_fs(storage_test_client_fs, &client);
+    if (!enable_test) {
+        goto test_abort;
+    }
+    ASSERT_NE(nullptr, aidl_storage.get());
+
+    {
+        sp<IStorageSession>& aidl_session =
+                connections[static_cast<size_t>(storage_test_client_fs)]
+                        .aidl_session;
+
+        if (aidl_session != nullptr) {
+            aidl_session = nullptr;
+        }
+
+        ret = aidl_storage->startSession(client, &aidl_session);
+        ASSERT_EQ(true, ret.isOk());
+
+        // Ensure both files deleted
+        ret = aidl_session->deleteFile(aidl_commit_file);
+        ASSERT_EQ(true,
+                  ret.isOk() ||
+                          ret.exceptionCode() == Status::EX_SERVICE_SPECIFIC &&
+                                  ret.serviceSpecificErrorCode() ==
+                                          ISecureStorage::ERR_NOT_FOUND);
+        ret = aidl_session->deleteFile(aidl_nocommit_file);
+        ASSERT_EQ(true,
+                  ret.isOk() ||
+                          ret.exceptionCode() == Status::EX_SERVICE_SPECIFIC &&
+                                  ret.serviceSpecificErrorCode() ==
+                                          ISecureStorage::ERR_NOT_FOUND);
+
+        // Write and commit
+        ret = aidl_session->openFile(aidl_commit_file, create_exclusive(),
+                                     &file);
+        ASSERT_EQ(true, ret.isOk());
+        ret = file->write(0, vec_data, &written);
+        ASSERT_EQ(true, ret.isOk());
+        ASSERT_EQ(vec_data.size(), written);
+        ret = aidl_session->commitChanges();
+        ASSERT_EQ(true, ret.isOk());
+
+        // Write but leave uncommitted
+        ret = aidl_session->openFile(aidl_nocommit_file, create_exclusive(),
+                                     &file);
+        ASSERT_EQ(true, ret.isOk());
+        ret = file->write(0, vec_data, &written);
+        ASSERT_EQ(true, ret.isOk());
+        ASSERT_EQ(vec_data.size(), written);
+    }
+test_abort:;
+}
+
+TEST(StorageReconnectDuringTest, AidlCheckSessionInvalid) {
+    Status ret;
+    Filesystem client;
+    bool enable_test = client_fs(storage_test_client_fs, &client);
+    if (!enable_test) {
+        goto test_abort;
+    }
+    ASSERT_NE(nullptr, aidl_storage.get());
+
+    {
+        sp<IStorageSession>& aidl_session =
+                connections[static_cast<size_t>(storage_test_client_fs)]
+                        .aidl_session;
+        ASSERT_NE(nullptr, aidl_session.get());
+
+        // Session invalid now
+        ret = aidl_session->commitChanges();
+        ASSERT_EQ(Status::EX_TRANSACTION_FAILED, ret.exceptionCode());
+        ASSERT_EQ(android::WOULD_BLOCK, ret.transactionError());
+
+        // Creating a new session on the same filesystem would block
+        sp<IStorageSession> temp_storage;
+        ret = aidl_storage->startSession(client, &temp_storage);
+        ASSERT_EQ(Status::EX_TRANSACTION_FAILED, ret.exceptionCode());
+        ASSERT_EQ(android::WOULD_BLOCK, ret.transactionError());
+    }
+test_abort:;
+}
+
+TEST(StorageReconnectAfterTest, AidlCheckWritten) {
+    sp<IFile> file;
+    Status ret;
+    Filesystem client;
+    std::vector<uint8_t> read_buf;
+    bool enable_test = client_fs(storage_test_client_fs, &client);
+    if (!enable_test) {
+        goto test_abort;
+    }
+    ASSERT_NE(nullptr, aidl_storage.get());
+
+    read_buf.reserve(sizeof(data));
+
+    {
+        // Session is reconnected; commit the uncommitted changes
+        sp<IStorageSession>& aidl_session =
+                connections[static_cast<size_t>(storage_test_client_fs)]
+                        .aidl_session;
+        ASSERT_NE(nullptr, aidl_session.get());
+        ret = aidl_session->commitChanges();
+        ASSERT_EQ(true, ret.isOk());
+
+        // Read what was committed in AidlWrite
+        ret = aidl_session->openFile(aidl_commit_file, no_create(), &file);
+        ASSERT_EQ(true, ret.isOk());
+        ret = file->read(sizeof(data), 0, &read_buf);
+        ASSERT_EQ(true, ret.isOk());
+        ASSERT_EQ(sizeof(data), read_buf.size());
+        for (size_t i = 0; i < sizeof(data); ++i) {
+            EXPECT_EQ(data[i], read_buf[i]);
+        }
+
+        // Read what was just committed
+        read_buf.clear();
+        ret = aidl_session->openFile(aidl_nocommit_file, no_create(), &file);
+        ASSERT_EQ(true, ret.isOk());
+        ret = file->read(sizeof(data), 0, &read_buf);
+        ASSERT_EQ(true, ret.isOk());
+        ASSERT_EQ(sizeof(data), read_buf.size());
+        for (size_t i = 0; i < sizeof(data); ++i) {
+            EXPECT_EQ(data[i], read_buf[i]);
+        }
+    }
+test_abort:;
+}
+
+struct storage_unittest {
+    struct unittest unittest;
+    FsType client;
+    const char* run_mode;
+};
+
+static bool run_test(struct unittest* test) {
+    struct storage_unittest* storage_test =
+            containerof(test, struct storage_unittest, unittest);
+    storage_test_client_fs = storage_test->client;
+    return RUN_ALL_SUITE_TESTS(storage_test->run_mode);
+}
+
+#define PORT_BASE "com.android.storage-reconnect-test."
+
+#define DEFINE_STORAGE_UNIT_TEST(fs, fs_name, run_mode_val, run_mode_name) \
+    {                                                                      \
+        .unittest =                                                        \
+                {                                                          \
+                        .port_name = PORT_BASE fs_name run_mode_name,      \
+                        .run_test = run_test,                              \
+                },                                                         \
+        .client = (fs), .run_mode = (run_mode_val),                        \
+    }
+
+#define DEFINE_STORAGE_UNIT_TESTS_FS(fs, fs_name)                              \
+    DEFINE_STORAGE_UNIT_TEST((fs), fs_name, "StorageReconnectBeforeTest",      \
+                             ".before"),                                       \
+            DEFINE_STORAGE_UNIT_TEST((fs), fs_name,                            \
+                                     "StorageReconnectDuringTest", ".during"), \
+            DEFINE_STORAGE_UNIT_TEST((fs), fs_name,                            \
+                                     "StorageReconnectAfterTest", ".after")
+
+int main(void) {
+    static struct storage_unittest storage_unittests[] = {
+            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::NSP, "nsp"),
+            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TD, "td"),
+            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TDP, "tdp"),
+            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TDEA, "tdea"),
+            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TP, "tp"),
+    };
+    static struct unittest* unittests[countof(storage_unittests)];
+
+    for (size_t i = 0; i < countof(storage_unittests); i++) {
+        unittests[i] = &storage_unittests[i].unittest;
+    }
+
+    int rc = connect(aidl_port, IPC_CONNECT_WAIT_FOR_PORT);
+    if (rc < 0) {
+        TLOGE("Couldn't connect to IStorageService port (%s)\n", aidl_port);
+        return rc;
+    }
+    sp<android::RpcSession> sess =
+            RpcSession::make(RpcTransportCtxFactoryTipcTrusty::make());
+    if (sess == nullptr) {
+        TLOGE("Failed to make RPC session.\n");
+        return ERR_GENERIC;
+    }
+    unique_fd chan_fd;
+    chan_fd.reset(rc);
+    status_t status = sess->setupPreconnectedClient(
+            std::move(chan_fd), []() { return unique_fd(); });
+    if (status != android::OK) {
+        TLOGE("Error (%d) during setupPreconnectedClient\n", status);
+        return ERR_GENERIC;
+    }
+    sp<IBinder> root = sess->getRootObject();
+    if (root == nullptr) {
+        TLOGE("Couldn't get root object.\n");
+        return ERR_GENERIC;
+    }
+
+    aidl_storage = ISecureStorage::asInterface(root);
+    return unittest_main(unittests, countof(unittests));
+}
\ No newline at end of file
diff --git a/test/storage-reconnect-test/manifest.json b/test/storage-reconnect-test/manifest.json
new file mode 100644
index 0000000..53c6918
--- /dev/null
+++ b/test/storage-reconnect-test/manifest.json
@@ -0,0 +1,5 @@
+{
+    "uuid": "e6618af4-8646-409f-856b-2cac1750b299",
+    "min_heap": 65536,
+    "min_stack": 8192
+}
diff --git a/test/storage-reconnect-test/rules.mk b/test/storage-reconnect-test/rules.mk
new file mode 100644
index 0000000..4f1278f
--- /dev/null
+++ b/test/storage-reconnect-test/rules.mk
@@ -0,0 +1,35 @@
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
+	$(LOCAL_DIR)/main.cpp \
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty \
+	trusty/user/base/interface/secure_storage/cpp \
+	trusty/user/base/lib/libc-trusty \
+	trusty/user/base/lib/libstdc++-trusty \
+	trusty/user/base/lib/tipc \
+	trusty/user/base/lib/storage \
+	trusty/user/base/lib/system_state \
+	trusty/user/base/lib/unittest \
+
+include make/trusted_app.mk
diff --git a/test/storage-unittest/main.c b/test/storage-unittest/main.c
index 432aa14..c5cac73 100644
--- a/test/storage-unittest/main.c
+++ b/test/storage-unittest/main.c
@@ -3088,7 +3088,7 @@ test_abort:;
 #define RUN_MODE_ALL NULL
 #define RUN_MODE_INIT_NO_COMMIT_SMALL "StorageInitNoCommitSmallTest"
 #define RUN_MODE_INIT_NO_COMMIT_LARGE "StorageInitNoCommitLargeTest"
-#define RUN_MODE_INIT_NO_COMMIT_CLEANUP "StorageInitNoCommitClenupTest"
+#define RUN_MODE_INIT_NO_COMMIT_CLEANUP "StorageInitNoCommitCleanupTest"
 #define RUN_MODE_INIT "StorageInitTest"
 #define RUN_MODE_CHECK "StorageCheckTest"
 #define RUN_MODE_CLEAN "StorageCleanTest"
diff --git a/test/storage_host_test/rules.mk b/test/storage_host_test/rules.mk
index 7c6111a..6c09281 100644
--- a/test/storage_host_test/rules.mk
+++ b/test/storage_host_test/rules.mk
@@ -23,6 +23,7 @@ HOST_SRCS := \
 	$(STORAGE_DIR)/block_allocator.c \
 	$(STORAGE_DIR)/block_cache.c \
 	$(STORAGE_DIR)/block_device_tipc.c \
+	$(STORAGE_DIR)/tipc_service.c \
 	$(STORAGE_DIR)/block_mac.c \
 	$(STORAGE_DIR)/block_map.c \
 	$(STORAGE_DIR)/block_set.c \
@@ -70,6 +71,7 @@ HOST_LIBS := \
 	m
 
 HOST_DEPS := \
-	trusty/user/base/host/boringssl
+	trusty/user/base/host/boringssl \
+	trusty/user/base/host/unittest \
 
 include make/host_test.mk
diff --git a/test/storage_host_test/storage_host_test.c b/test/storage_host_test/storage_host_test.c
index 87b6cb4..47a7eed 100644
--- a/test/storage_host_test/storage_host_test.c
+++ b/test/storage_host_test/storage_host_test.c
@@ -26,7 +26,6 @@
 #include <lk/err_ptr.h>
 #include <trusty_unittest.h>
 
-#include "aidl_service.h"
 #include "block_cache.h"
 #include "block_device_tipc.h"
 #include "crypt.h"
@@ -34,6 +33,7 @@
 #include "file.h"
 #include "rpmb.h"
 #include "storageproxy_shim.h"
+#include "tipc_service.h"
 #include "transaction.h"
 
 /* For BLOCK_CACHE_SIZE */
@@ -41,9 +41,8 @@
 
 static struct key storage_test_key;
 static struct block_device_tipc test_block_device;
+static struct storage_tipc_service test_tipc_service;
 static struct tipc_hset* hset;
-static struct storage_service_aidl_context aidl =
-        STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(aidl);
 
 static bool print_test_verbose = false;
 
@@ -506,10 +505,14 @@ TEST_P(StorageTest, FailRpmbVerify) {
      * verify_failed flag from the rpmb state.
      */
     transaction_free(&_state->tr);
-    block_device_tipc_uninit(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, hset, &aidl, null_handle,
+    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
+    block_device_tipc_destroy(&test_block_device);
+    rc = block_device_tipc_init(&test_block_device, null_handle,
                                 &storage_test_key, NULL, null_handle);
     ASSERT_EQ(rc, 0);
+    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
+                                   hset);
+    ASSERT_EQ(rc, 0);
     transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
 
     /* Everything should work now */
@@ -647,10 +650,14 @@ TEST_P(StorageTest, DesyncBackingFile) {
     ignore_next_ns_writes(0);
     transaction_free(&_state->tr);
 
-    block_device_tipc_uninit(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, hset, &aidl, null_handle,
+    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
+    block_device_tipc_destroy(&test_block_device);
+    rc = block_device_tipc_init(&test_block_device, null_handle,
                                 &storage_test_key, NULL, null_handle);
     ASSERT_EQ(rc, 0);
+    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
+                                   hset);
+    ASSERT_EQ(rc, 0);
     transaction_init(&_state->tr, fs, true);
     _state->initial_super_block_version = _state->tr.fs->super_block_version;
 
@@ -740,10 +747,14 @@ TEST_P(StorageTest, CorruptFileInfo) {
     transaction_free(&_state->tr);
 
     /* remount the filesystem to clear the block cache */
-    block_device_tipc_uninit(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, hset, &aidl, null_handle,
+    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
+    block_device_tipc_destroy(&test_block_device);
+    rc = block_device_tipc_init(&test_block_device, null_handle,
                                 &storage_test_key, NULL, null_handle);
     ASSERT_EQ(rc, 0);
+    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
+                                   hset);
+    ASSERT_EQ(rc, 0);
     transaction_init(&_state->tr, fs, true);
     _state->initial_super_block_version = _state->tr.fs->super_block_version;
 
@@ -753,10 +764,14 @@ TEST_P(StorageTest, CorruptFileInfo) {
     ASSERT_EQ(true, fs->needs_full_scan);
     transaction_free(&_state->tr);
 
-    block_device_tipc_uninit(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, hset, &aidl, null_handle,
+    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
+    block_device_tipc_destroy(&test_block_device);
+    rc = block_device_tipc_init(&test_block_device, null_handle,
                                 &storage_test_key, NULL, null_handle);
     ASSERT_EQ(rc, 0);
+    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
+                                   hset);
+    ASSERT_EQ(rc, 0);
     transaction_init(&_state->tr, fs, true);
     _state->initial_super_block_version = _state->tr.fs->super_block_version;
 
@@ -823,14 +838,15 @@ int main(int argc, const char* argv[]) {
     if (IS_ERR(hset)) {
         fprintf(stderr, "%s: tipc_hset_create failed (%d)\n", __func__, rc);
     }
-    rc = storage_aidl_create_service(&aidl, hset);
+    rc = block_device_tipc_init(&test_block_device, null_handle,
+                                &storage_test_key, NULL, null_handle);
     if (rc < 0) {
-        fprintf(stderr, "%s: storage_aidl_create_service failed (%d)\n",
-                __func__, rc);
+        fprintf(stderr, "%s: block_device_tipc_init failed (%d)\n", __func__,
+                rc);
         goto err;
     }
-    rc = block_device_tipc_init(&test_block_device, hset, &aidl, null_handle,
-                                &storage_test_key, NULL, null_handle);
+    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
+                                   hset);
     if (rc < 0) {
         fprintf(stderr, "%s: block_device_tipc_init failed (%d)\n", __func__,
                 rc);
@@ -839,9 +855,10 @@ int main(int argc, const char* argv[]) {
 
     rc = RUN_ALL_TESTS() ? 0 : 1;
 
-    block_device_tipc_uninit(&test_block_device);
+    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
+
 init_err:
-    storage_aidl_delete_service(&aidl);
+    block_device_tipc_destroy(&test_block_device);
 err:
     crypt_shutdown();
     destroy_rpmb_state();
diff --git a/test/storage_host_test/storageproxy_shim.c b/test/storage_host_test/storageproxy_shim.c
index 15c9208..75fc3c0 100644
--- a/test/storage_host_test/storageproxy_shim.c
+++ b/test/storage_host_test/storageproxy_shim.c
@@ -30,9 +30,9 @@
 #include <uapi/err.h>
 #include <unistd.h>
 
-#include "block_device_tipc.h"
 #include "rpmb.h"
 #include "rpmb_dev/rpmb_dev.h"
+#include "tipc_service.h"
 
 #define TLOG_TAG "ss-test"
 
diff --git a/tipc_service.c b/tipc_service.c
new file mode 100644
index 0000000..bb046bd
--- /dev/null
+++ b/tipc_service.c
@@ -0,0 +1,117 @@
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
+#include "tipc_service.h"
+
+#include <interface/storage/storage.h>
+#include <lib/tipc/tipc.h>
+
+#include "block_device_tipc.h"
+#include "client_tipc.h"
+
+#define SS_ERR(args...) fprintf(stderr, "ss: " args)
+
+// TODO: Put this somewhere central?
+static const char* port_name(enum storage_filesystem_type fs_type) {
+    switch (fs_type) {
+    case STORAGE_TP:
+        return STORAGE_CLIENT_TP_PORT;
+    case STORAGE_TDEA:
+        return STORAGE_CLIENT_TDEA_PORT;
+    case STORAGE_TDP:
+        return STORAGE_CLIENT_TDP_PORT;
+    case STORAGE_TD:
+        return STORAGE_CLIENT_TD_PORT;
+    case STORAGE_NSP:
+        return STORAGE_CLIENT_NSP_PORT;
+    case STORAGE_FILESYSTEMS_COUNT:
+    default:
+        SS_ERR("%s: Tried to get port for unrecognized storage_filesystem_type type: (%d)\n",
+               __func__, fs_type);
+        return NULL;
+    }
+}
+
+static int client_port_context_init(struct client_port_context* self,
+                                    enum storage_filesystem_type fs_type,
+                                    struct block_device_tipc* ctx,
+                                    struct tipc_hset* hset) {
+    if (!block_device_tipc_fs_connected(ctx, fs_type)) {
+        return 0;
+    }
+    self->tr_state = block_device_tipc_get_fs(ctx, fs_type);
+    return client_create_port(hset, &self->client_ctx, port_name(fs_type));
+}
+
+static void client_port_context_destroy(struct client_port_context* self,
+                                        enum storage_filesystem_type fs_type,
+                                        struct block_device_tipc* ctx) {
+    if (!block_device_tipc_fs_connected(ctx, fs_type)) {
+        return;
+    }
+    ipc_port_destroy(&self->client_ctx);
+}
+
+int storage_tipc_service_init(struct storage_tipc_service* self,
+                              struct block_device_tipc* ctx,
+                              struct tipc_hset* hset) {
+    int ret = client_port_context_init(&self->fs_rpmb, STORAGE_TP, ctx, hset);
+    if (ret < 0) {
+        goto err_fs_rpmb_create_port;
+    }
+
+    ret = client_port_context_init(&self->fs_rpmb_boot, STORAGE_TDEA, ctx,
+                                   hset);
+    if (ret < 0) {
+        goto err_fs_rpmb_boot_create_port;
+    }
+
+    ret = client_port_context_init(&self->fs_tdp, STORAGE_TDP, ctx, hset);
+    if (ret < 0) {
+        goto err_fs_tdp_create_port;
+    }
+
+    ret = client_port_context_init(&self->fs_ns, STORAGE_TD, ctx, hset);
+    if (ret < 0) {
+        goto err_fs_ns_create_port;
+    }
+
+    ret = client_port_context_init(&self->fs_nsp, STORAGE_NSP, ctx, hset);
+    if (ret < 0) {
+        goto err_fs_nsp_create_port;
+    }
+    return 0;
+
+err_fs_nsp_create_port:
+    client_port_context_destroy(&self->fs_ns, STORAGE_TD, ctx);
+err_fs_ns_create_port:
+    client_port_context_destroy(&self->fs_tdp, STORAGE_TDP, ctx);
+err_fs_tdp_create_port:
+    client_port_context_destroy(&self->fs_rpmb_boot, STORAGE_TDEA, ctx);
+err_fs_rpmb_boot_create_port:
+    client_port_context_destroy(&self->fs_rpmb, STORAGE_TP, ctx);
+err_fs_rpmb_create_port:
+    return ret;
+}
+
+void storage_tipc_service_destroy(struct storage_tipc_service* self,
+                                  struct block_device_tipc* ctx) {
+    client_port_context_destroy(&self->fs_nsp, STORAGE_NSP, ctx);
+    client_port_context_destroy(&self->fs_ns, STORAGE_TD, ctx);
+    client_port_context_destroy(&self->fs_tdp, STORAGE_TDP, ctx);
+    client_port_context_destroy(&self->fs_rpmb_boot, STORAGE_TDEA, ctx);
+    client_port_context_destroy(&self->fs_rpmb, STORAGE_TP, ctx);
+}
diff --git a/tipc_service.h b/tipc_service.h
new file mode 100644
index 0000000..30795b1
--- /dev/null
+++ b/tipc_service.h
@@ -0,0 +1,80 @@
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
+#pragma once
+
+#include <lib/tipc/tipc.h>
+#include <trusty_ipc.h>
+
+#include "block_device_tipc.h"
+#include "ipc.h"
+#include "tipc_ns.h"
+
+/**
+ * struct client_port_context
+ * @tr_state:   Pointer to the backing filesystem.
+ * @client_ctx: Context for the port opened to clients.
+ */
+struct client_port_context {
+    struct fs* tr_state;
+    struct ipc_port_context client_ctx;
+};
+
+/**
+ * struct storage_tipc_service
+ * @fs_rpmb:      Client port for TP.
+ * @fs_rpmb_boot: Client port for TDEA.
+ * @fs_tdp:       Client port for TDP. If $HAS_FS_TDP is undefined, aliases TP.
+ *                Only initialized and available if ns is available.
+ * @fs_nsp:       Client port for NSP. If $HAS_FS_NSP is undefined, aliases TDP.
+ *                Only initialized and available if ns is available.
+ * @fs_ns:        Client port for TD. Only initialized and available if ns is
+ *                available.
+ */
+struct storage_tipc_service {
+    struct client_port_context fs_rpmb;
+    struct client_port_context fs_rpmb_boot;
+
+    struct client_port_context fs_tdp;
+    struct client_port_context fs_nsp;
+    struct client_port_context fs_ns;
+};
+
+/**
+ * storage_tipc_service_init() - Initialize a &struct storage_tipc_service
+ *
+ * Opens tipc ports through which clients can make changes to storage.
+ *
+ * @self: Out param. Will contain the newly initialized &struct
+ * storage_tipc_service.
+ * @ctx: &struct block_device_tipc containing the filesystems backing the
+ * client ports.
+ * @hset: Handle set to handle incoming messages on the client ports.
+ */
+int storage_tipc_service_init(struct storage_tipc_service* self,
+                              struct block_device_tipc* ctx,
+                              struct tipc_hset* hset);
+
+/**
+ * storage_tipc_service_destroy() - Deinitialize a &struct storage_tipc_service
+ *
+ * Closes all tipc client ports that were opened by storage_tipc_service_init().
+ *
+ * @self: The &struct storage_tipc_service to destroy. The backing memory is not
+ * freed.
+ * @ctx: The &struct block_device_tipc used to init @self.
+ */
+void storage_tipc_service_destroy(struct storage_tipc_service* self,
+                                  struct block_device_tipc* ctx);
\ No newline at end of file
diff --git a/usertests-inc.mk b/usertests-inc.mk
index a91951e..5198895 100644
--- a/usertests-inc.mk
+++ b/usertests-inc.mk
@@ -15,6 +15,7 @@
 
 TRUSTY_USER_TESTS += \
 	trusty/user/app/storage/test/storage-unittest \
+	trusty/user/app/storage/test/storage-reconnect-test \
 
 ifneq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
 TRUSTY_USER_TESTS += \
```

