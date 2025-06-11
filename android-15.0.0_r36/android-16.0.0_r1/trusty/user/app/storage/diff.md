```diff
diff --git a/aidl_service.cpp b/aidl_service.cpp
index e5caf37..f0c76b5 100644
--- a/aidl_service.cpp
+++ b/aidl_service.cpp
@@ -403,6 +403,10 @@ public:
             return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                              "File not opened for writing.");
         }
+        if (new_size < 0) {
+            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
+                                             "File size must not be negative.");
+        }
         std::shared_ptr<StorageClientSession> session = session_.lock();
         if (session == nullptr) {
             return Status::fromExceptionCode(
diff --git a/block_cache.c b/block_cache.c
index ef4f989..ed4b781 100644
--- a/block_cache.c
+++ b/block_cache.c
@@ -1164,6 +1164,25 @@ const void* block_get_super(struct fs* fs,
                                 NULL);
 }
 
+/**
+ * block_get_super_with_mac - Get super block data and check the mac
+ * @fs:         File system state object.
+ * @block_mac:  Block number and mac.
+ * @ref:        Pointer to store reference in.
+ *
+ * Return: Const block data pointer.
+ */
+const void* block_get_super_with_mac(struct fs* fs,
+                                     const struct block_mac* block_mac,
+                                     struct obj_ref* ref) {
+    assert(fs);
+    assert(fs->super_dev);
+
+    return block_cache_get_data(
+            fs, fs->super_dev, block_mac_to_block_fs(fs, block_mac), true,
+            block_mac_to_mac_fs(fs, block_mac), fs->mac_size, ref, NULL);
+}
+
 /**
  * block_get_no_tr_fail - Get block data
  * @tr:         Transaction to get device from
diff --git a/block_cache.h b/block_cache.h
index 8235686..6f6c8de 100644
--- a/block_cache.h
+++ b/block_cache.h
@@ -65,6 +65,10 @@ const void* block_get_super(struct fs* fs,
                             data_block_t block,
                             struct obj_ref* ref);
 
+const void* block_get_super_with_mac(struct fs* fs,
+                                     const struct block_mac* block_mac,
+                                     struct obj_ref* ref);
+
 const void* block_get_no_tr_fail(struct transaction* tr,
                                  const struct block_mac* block_mac,
                                  const struct iv* iv,
diff --git a/block_device_tipc.c b/block_device_tipc.c
index 7baab40..5098726 100644
--- a/block_device_tipc.c
+++ b/block_device_tipc.c
@@ -268,8 +268,8 @@ static void block_device_tipc_ns_start_write(struct block_device* dev,
     assert(data_size == BLOCK_SIZE_MAIN);
 
     ret = ns_write_pos(dev_ns->ipc_handle, dev_ns->ns_handle,
-                       block * BLOCK_SIZE_MAIN, data, data_size,
-                       dev_ns->is_userdata, sync);
+                       block * BLOCK_SIZE_MAIN, data, data_size, sync,
+                       dev_ns->is_userdata);
     SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
     if (ret == BLOCK_SIZE_MAIN) {
         res = BLOCK_WRITE_SUCCESS;
diff --git a/block_mac.c b/block_mac.c
index 8b4e054..8541fc1 100644
--- a/block_mac.c
+++ b/block_mac.c
@@ -54,22 +54,39 @@ data_block_t block_mac_to_block(const struct transaction* tr,
     return block_mac_to_block_fs(tr->fs, block_mac);
 }
 
+const void* block_mac_to_mac_fs(const struct fs* fs,
+                                const struct block_mac* block_mac) {
+    return block_mac->data + block_mac_block_size(fs);
+}
+
 const void* block_mac_to_mac(const struct transaction* tr,
                              const struct block_mac* block_mac) {
-    return block_mac->data + block_mac_block_size(tr->fs);
+    return block_mac_to_mac_fs(tr->fs, block_mac);
+}
+
+void block_mac_set_block_fs(const struct fs* fs,
+                            struct block_mac* block_mac,
+                            data_block_t block) {
+    memcpy(block_mac->data, &block, block_mac_block_size(fs));
 }
 
 void block_mac_set_block(const struct transaction* tr,
                          struct block_mac* block_mac,
                          data_block_t block) {
-    memcpy(block_mac->data, &block, block_mac_block_size(tr->fs));
+    block_mac_set_block_fs(tr->fs, block_mac, block);
+}
+
+void block_mac_set_mac_fs(const struct fs* fs,
+                          struct block_mac* block_mac,
+                          const struct mac* mac) {
+    memcpy(block_mac->data + block_mac_block_size(fs), mac,
+           block_mac_mac_size(fs));
 }
 
 void block_mac_set_mac(const struct transaction* tr,
                        struct block_mac* block_mac,
                        const struct mac* mac) {
-    memcpy(block_mac->data + block_mac_block_size(tr->fs), mac,
-           block_mac_mac_size(tr->fs));
+    block_mac_set_mac_fs(tr->fs, block_mac, mac);
 }
 
 bool block_mac_eq(const struct transaction* tr,
diff --git a/block_mac.h b/block_mac.h
index bec4583..323a4a4 100644
--- a/block_mac.h
+++ b/block_mac.h
@@ -47,11 +47,19 @@ data_block_t block_mac_to_block_fs(const struct fs* fs,
                                    const struct block_mac* block_mac);
 data_block_t block_mac_to_block(const struct transaction* tr,
                                 const struct block_mac* block_mac);
+const void* block_mac_to_mac_fs(const struct fs* fs,
+                                const struct block_mac* block_mac);
 const void* block_mac_to_mac(const struct transaction* tr,
                              const struct block_mac* block_mac);
+void block_mac_set_block_fs(const struct fs* fs,
+                            struct block_mac* block_mac,
+                            data_block_t block);
 void block_mac_set_block(const struct transaction* tr,
                          struct block_mac* block_mac,
                          data_block_t block);
+void block_mac_set_mac_fs(const struct fs* fs,
+                          struct block_mac* block_mac,
+                          const struct mac* mac);
 void block_mac_set_mac(const struct transaction* tr,
                        struct block_mac* block_mac,
                        const struct mac* mac);
diff --git a/common.mk b/common.mk
new file mode 100644
index 0000000..7f321a9
--- /dev/null
+++ b/common.mk
@@ -0,0 +1,40 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# This file exports the following common variables to be used in storage
+# makefiles:
+#	- STORAGE_COMMON_SRCS:      Core storage source files list
+#	- STORAGE_COMMON_TIPC_SRCS: TIPC related storage source files list
+
+STORAGE_SRC_DIR := $(GET_LOCAL_DIR)
+
+STORAGE_COMMON_SRCS := \
+	$(STORAGE_SRC_DIR)/block_allocator.c \
+	$(STORAGE_SRC_DIR)/block_cache.c \
+	$(STORAGE_SRC_DIR)/block_mac.c \
+	$(STORAGE_SRC_DIR)/block_map.c \
+	$(STORAGE_SRC_DIR)/block_set.c \
+	$(STORAGE_SRC_DIR)/block_tree.c \
+	$(STORAGE_SRC_DIR)/checkpoint.c \
+	$(STORAGE_SRC_DIR)/crypt.c \
+	$(STORAGE_SRC_DIR)/file.c \
+	$(STORAGE_SRC_DIR)/super.c \
+	$(STORAGE_SRC_DIR)/transaction.c \
+
+STORAGE_COMMON_TIPC_SRCS := \
+	$(STORAGE_SRC_DIR)/block_device_tipc.c \
+	$(STORAGE_SRC_DIR)/tipc_service.c \
+
+undefine STORAGE_SRC_DIR
diff --git a/rpmb_dev/rules.mk b/rpmb_dev/rules.mk
index f8ec78b..608ff5f 100644
--- a/rpmb_dev/rules.mk
+++ b/rpmb_dev/rules.mk
@@ -26,6 +26,7 @@ HOST_FLAGS := -DBUILD_STORAGE_TEST=1
 
 HOST_LIBS := \
 	m \
+	c++ \
 
 # We need to statically link openssl into the host tool in case the version
 # we're building with is unavailable on the host it will be running on.
diff --git a/rules.mk b/rules.mk
index 4412d4d..695c991 100644
--- a/rules.mk
+++ b/rules.mk
@@ -77,28 +77,20 @@ ifeq (true,$(call TOBOOL,$(STORAGE_TDP_AUTO_CHECKPOINT_ENABLED)))
     MODULE_DEFINES += STORAGE_TDP_AUTO_CHECKPOINT_ENABLED=1
 endif
 
+include $(LOCAL_DIR)/common.mk
+
 MODULE_SRCS := \
-	$(LOCAL_DIR)/block_allocator.c \
-	$(LOCAL_DIR)/block_cache.c \
-	$(LOCAL_DIR)/block_device_tipc.c \
-	$(LOCAL_DIR)/block_mac.c \
-	$(LOCAL_DIR)/block_map.c \
-	$(LOCAL_DIR)/block_set.c \
-	$(LOCAL_DIR)/block_tree.c \
-	$(LOCAL_DIR)/checkpoint.c \
+	$(STORAGE_COMMON_SRCS) \
+	$(STORAGE_COMMON_TIPC_SRCS) \
 	$(LOCAL_DIR)/client.c \
 	$(LOCAL_DIR)/client_tipc.c \
-	$(LOCAL_DIR)/crypt.c \
 	$(LOCAL_DIR)/error_reporting.c \
-	$(LOCAL_DIR)/file.c \
 	$(LOCAL_DIR)/ipc.c \
 	$(LOCAL_DIR)/main.c \
 	$(LOCAL_DIR)/proxy.c \
 	$(LOCAL_DIR)/rpmb.c \
-	$(LOCAL_DIR)/super.c \
 	$(LOCAL_DIR)/tipc_ns.c \
 	$(LOCAL_DIR)/tipc_service.c \
-	$(LOCAL_DIR)/transaction.c \
 
 MODULE_LIBRARY_DEPS := \
 	trusty/user/base/interface/metrics \
@@ -133,6 +125,9 @@ MODULE_DEPS += \
 	trusty/user/app/storage/test/block_host_test \
 	trusty/user/app/storage/test/storage_host_test \
 
+undefine STORAGE_COMMON_SRCS
+undefine STORAGE_COMMON_TIPC_SRCS
+
 include make/trusted_app.mk
 
 # Build host side unit tests for mock storage implementation.
diff --git a/super.c b/super.c
index 6e625e4..0dba82e 100644
--- a/super.c
+++ b/super.c
@@ -690,14 +690,6 @@ static int fs_init_from_super(struct fs* fs,
     const struct block_mac* new_free_root;
     const struct block_mac* new_checkpoint = NULL;
 
-    /*
-     * We check that the super-block matches these block device params in
-     * super_block_valid(). If these params change, the filesystem (and
-     * alternate backup) will be wiped and reset with the new params.
-     */
-    fs->block_num_size = fs->dev->block_num_size;
-    fs->mac_size = fs->dev->mac_size;
-
     block_set_init(fs, &fs->free);
     fs->free.block_tree.copy_on_write = true;
     fs_file_tree_init(fs, &fs->files);
@@ -1184,6 +1176,14 @@ int fs_init(struct fs* fs,
     fs->initial_super_block_tr = NULL;
     list_add_tail(&fs_list, &fs->node);
 
+    /*
+     * We check that the super-block matches these block device params in
+     * super_block_valid(). If these params change, the filesystem (and
+     * alternate backup) will be wiped and reset with the new params.
+     */
+    fs->block_num_size = fs->dev->block_num_size;
+    fs->mac_size = fs->dev->mac_size;
+
     if (dev == super_dev) {
         fs->min_block_num = 2;
     } else {
diff --git a/test/block_host_test/rules.mk b/test/block_host_test/rules.mk
index e269258..cda01d1 100644
--- a/test/block_host_test/rules.mk
+++ b/test/block_host_test/rules.mk
@@ -19,18 +19,10 @@ STORAGE_DIR := $(LOCAL_DIR)/../..
 
 HOST_TEST := storage_block_test
 
+include $(STORAGE_DIR)/common.mk
+
 HOST_SRCS := \
-	$(STORAGE_DIR)/block_allocator.c \
-	$(STORAGE_DIR)/block_cache.c \
-	$(STORAGE_DIR)/block_mac.c \
-	$(STORAGE_DIR)/block_map.c \
-	$(STORAGE_DIR)/block_set.c \
-	$(STORAGE_DIR)/block_tree.c \
-	$(STORAGE_DIR)/checkpoint.c \
-	$(STORAGE_DIR)/crypt.c \
-	$(STORAGE_DIR)/file.c \
-	$(STORAGE_DIR)/super.c \
-	$(STORAGE_DIR)/transaction.c \
+	$(STORAGE_COMMON_SRCS) \
 	$(LOCAL_DIR)/block_test.c \
 	$(COMMON_DIR)/error_reporting_mock.c \
 
@@ -43,8 +35,11 @@ HOST_INCLUDE_DIRS += \
 
 HOST_LIBS := \
 	m \
+	c++ \
 
 HOST_DEPS := \
 	trusty/user/base/host/boringssl
 
+undefine STORAGE_COMMON_SRCS
+
 include make/host_test.mk
diff --git a/test/storage_host_test/rules.mk b/test/storage_host_test/rules.mk
index 6c09281..43cb749 100644
--- a/test/storage_host_test/rules.mk
+++ b/test/storage_host_test/rules.mk
@@ -19,22 +19,13 @@ STORAGE_DIR := $(LOCAL_DIR)/../..
 
 HOST_TEST := storage_host_test
 
+include $(STORAGE_DIR)/common.mk
+
 HOST_SRCS := \
-	$(STORAGE_DIR)/block_allocator.c \
-	$(STORAGE_DIR)/block_cache.c \
-	$(STORAGE_DIR)/block_device_tipc.c \
-	$(STORAGE_DIR)/tipc_service.c \
-	$(STORAGE_DIR)/block_mac.c \
-	$(STORAGE_DIR)/block_map.c \
-	$(STORAGE_DIR)/block_set.c \
-	$(STORAGE_DIR)/block_tree.c \
-	$(STORAGE_DIR)/checkpoint.c \
-	$(STORAGE_DIR)/crypt.c \
-	$(STORAGE_DIR)/file.c \
+	$(STORAGE_COMMON_SRCS) \
+	$(STORAGE_COMMON_TIPC_SRCS) \
 	$(STORAGE_DIR)/rpmb_dev/rpmb_dev.c \
 	$(STORAGE_DIR)/rpmb.c \
-	$(STORAGE_DIR)/super.c \
-	$(STORAGE_DIR)/transaction.c \
 	$(LOCAL_DIR)/library_shims.c \
 	$(LOCAL_DIR)/storage_host_test.c \
 	$(LOCAL_DIR)/storageproxy_shim.c \
@@ -68,10 +59,14 @@ HOST_FLAGS += -DSTORAGE_TDP_RECOVERY_CHECKPOINT_RESTORE_ALLOWED=1
 HOST_FLAGS += -DHAS_FS_TDP=1
 
 HOST_LIBS := \
-	m
+	m \
+	c++ \
 
 HOST_DEPS := \
 	trusty/user/base/host/boringssl \
 	trusty/user/base/host/unittest \
 
+undefine STORAGE_COMMON_SRCS
+undefine STORAGE_COMMON_TIPC_SRCS
+
 include make/host_test.mk
diff --git a/test/storage_host_test/storageproxy_shim.c b/test/storage_host_test/storageproxy_shim.c
index 75fc3c0..53e677a 100644
--- a/test/storage_host_test/storageproxy_shim.c
+++ b/test/storage_host_test/storageproxy_shim.c
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#define _GNU_SOURCE /* for asprintf */
+
 #include "storageproxy_shim.h"
 
 #include <errno.h>
@@ -68,6 +70,19 @@ bool init_rpmb_state(const char* base_directory) {
         }
     }
 
+    /* Remove the non-secure data file */
+    char* ns_path;
+    rc = asprintf(&ns_path, "%s/0", data_directory);
+    if (rc < 0) {
+        goto err_rm_ns_file;
+    }
+    rc = remove(ns_path);
+    if (rc < 0) {
+        if (errno != ENOENT) {
+            goto err_rm_ns_file;
+        }
+    }
+
 #if HAS_FS_TDP
     char* tdp_directory =
             malloc(strlen(data_directory) + sizeof(PERSIST_DIRECTORY) + 2);
@@ -84,6 +99,19 @@ bool init_rpmb_state(const char* base_directory) {
             goto err_tdp_mkdir;
         }
     }
+
+    /* Remove the TDP data file */
+    char* tdp_path;
+    rc = asprintf(&tdp_path, "%s/0", tdp_directory);
+    if (rc < 0) {
+        goto err_rm_tdp_file;
+    }
+    rc = remove(tdp_path);
+    if (rc < 0) {
+        if (errno != ENOENT) {
+            goto err_rm_tdp_file;
+        }
+    }
 #endif
 
     char* rpmb_filename =
@@ -123,11 +151,15 @@ err_rpmb_filename:
     free(rpmb_filename);
 err_alloc_rpmb:
 #if HAS_FS_TDP
+err_rm_tdp_file:
+    free(tdp_path);
 err_tdp_mkdir:
 err_tdp_dirname:
     free(tdp_directory);
 err_alloc_tdp:
 #endif
+err_rm_ns_file:
+    free(ns_path);
 err_mkdir:
     return res;
 }
@@ -305,8 +337,8 @@ int ns_write_pos(handle_t ipc_handle,
                  ns_off_t pos,
                  const void* data,
                  int data_size,
-                 bool is_userdata,
-                 bool sync) {
+                 bool sync,
+                 bool sync_checkpoint) {
     if (ignore_next_ns_write_count > 0) {
         if (ignore_next_ns_write_count != INT_MAX) {
             ignore_next_ns_write_count--;
diff --git a/tipc_ns.c b/tipc_ns.c
index c5a3fb3..6207e4c 100644
--- a/tipc_ns.c
+++ b/tipc_ns.c
@@ -325,13 +325,13 @@ int ns_write_pos(handle_t ipc_handle,
                  ns_off_t pos,
                  const void* data,
                  int data_size,
-                 bool is_userdata,
-                 bool sync) {
+                 bool sync,
+                 bool sync_checkpoint) {
     uint32_t flags = 0;
     SS_DBG_IO("%s: handle %llu, pos %llu, size %d\n", __func__, handle, pos,
               data_size);
 
-    if (is_userdata) {
+    if (sync_checkpoint) {
         flags |= STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT;
     }
 
diff --git a/tipc_ns.h b/tipc_ns.h
index 0bf2019..2c9de49 100644
--- a/tipc_ns.h
+++ b/tipc_ns.h
@@ -41,5 +41,5 @@ int ns_write_pos(handle_t ipc_handle,
                  ns_off_t pos,
                  const void* data,
                  int data_size,
-                 bool is_userdata,
-                 bool sync);
+                 bool sync,
+                 bool sync_checkpoint);
```

