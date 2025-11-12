```diff
diff --git a/block_allocator.c b/block_allocator.c
index be721ee..103df67 100644
--- a/block_allocator.c
+++ b/block_allocator.c
@@ -256,40 +256,28 @@ static data_block_t find_free_block(struct transaction* tr,
 
     block = min_block;
     do {
-        block = block_set_find_next_block(tr, &tr->fs->free, block, true);
-        if (tr->failed) {
-            return 0;
-        }
-
-        /*
-         * if block_set_find_next_block() returns 0, there was no available free
-         * block after min_block
-         */
-        if (!block) {
-            break;
-        }
-        assert(block >= min_block);
-
-        /*
-         * set min_block to a candidate for an available free block. If no
-         * checkpoint or pending allocation contains this block, block will
-         * still equal min_block and we will exit the loop
-         */
-        min_block = block;
+        bool min_block_updated = false;
 
-        pr_read("check free block %" PRIu64 "\n", block);
+        /* Skip blocks in any free set */
+        assert(!list_is_empty(&tr->fs->free_sets));
+        list_for_every_entry(&tr->fs->free_sets, set, struct block_set, node) {
+            block = block_set_find_next_block(tr, set, block, true);
+            if (tr->failed) {
+                return 0;
+            }
+            if (!block) {
+                goto no_free_blocks;
+            }
+            assert(block >= min_block);
 
-        /* check if the block is also free in the checkpoint */
-        block = block_set_find_next_block(tr, &tr->fs->checkpoint_free, block,
-                                          true);
-        if (tr->failed) {
-            return 0;
-        }
-        if (!block) {
-            break;
+            if (!min_block_updated) {
+                min_block = block;
+                min_block_updated = true;
+            }
         }
-        assert(block >= min_block);
+        assert(min_block_updated);
 
+        /* Skip blocks in any transaction's allocated set. */
         assert(!list_is_empty(&tr->fs->allocated));
         list_for_every_entry(&tr->fs->allocated, set, struct block_set, node) {
             block = block_set_find_next_block(tr, set, block, false);
@@ -298,43 +286,49 @@ static data_block_t find_free_block(struct transaction* tr,
             }
             assert(block >= min_block);
         };
+
+        /* Skip blocks that aren't free in the allocator queue. */
         block = block_allocator_queue_find_free_block(&block_allocator_queue,
                                                       block);
         assert(block >= min_block);
+
+        /*
+         * If block == min_block, all our checks found that block was free, so
+         * return it. Otherwise, only the last N checks succeeded, so try the
+         * checks again with the new value of block as the candidate.
+         */
     } while (block != min_block);
 
-    if (!block) {
-        if (LOCAL_TRACE >= TRACE_LEVEL_READ) {
-            if (min_block_in) {
-                block = find_free_block(tr, 0);
-            }
-            printf("%s: no space, min_block %" PRIu64
-                   ", free block ignoring_min_block %" PRIu64 "\n",
-                   __func__, min_block_in, block);
-
-            printf("%s: free\n", __func__);
-            block_set_print(tr, &tr->fs->free);
-            printf("%s: checkpoint free\n", __func__);
-            block_set_print(tr, &tr->fs->checkpoint_free);
-            list_for_every_entry(&tr->fs->allocated, set, struct block_set,
-                                 node) {
+    pr_read("found free block %" PRIu64 "\n", block);
+    return block;
+
+no_free_blocks:
+    if (LOCAL_TRACE >= TRACE_LEVEL_READ) {
+        if (min_block_in) {
+            block = find_free_block(tr, 0);
+        }
+        printf("%s: no space, min_block %" PRIu64
+               ", free block ignoring_min_block %" PRIu64 "\n",
+               __func__, min_block_in, block);
+
+        printf("%s: free\n", __func__);
+        block_set_print(tr, &tr->fs->free);
+        printf("%s: checkpoint free\n", __func__);
+        block_set_print(tr, &tr->fs->checkpoint_free);
+
+        list_for_every_entry(&tr->fs->allocated, set, struct block_set, node) {
 #if TLOG_LVL >= TLOG_LVL_DEBUG
-                printf("%s: allocated %p\n", __func__, set);
+            printf("%s: allocated %p\n", __func__, set);
 #endif
-                block_set_print(tr, set);
-            }
-            if (tr->new_free_set) {
-                printf("%s: new free\n", __func__);
-                block_set_print(tr, tr->new_free_set);
-            }
+            block_set_print(tr, set);
+        }
+        if (tr->new_free_set) {
+            printf("%s: new free\n", __func__);
+            block_set_print(tr, tr->new_free_set);
         }
-
-        return 0;
     }
 
-    pr_read("found free block %" PRIu64 "\n", block);
-
-    return block;
+    return 0;
 }
 
 /**
diff --git a/block_cache.c b/block_cache.c
index ed4b781..fd1e38e 100644
--- a/block_cache.c
+++ b/block_cache.c
@@ -142,7 +142,8 @@ static void block_cache_queue_write(struct block_cache_entry* entry,
     block_cache_queue_io_op(entry, BLOCK_CACHE_IO_OP_WRITE);
     stats_timer_start(STATS_CACHE_START_WRITE);
     entry->dev->start_write(entry->dev, entry->block, encrypted_data,
-                            entry->block_size, entry->is_superblock);
+                            entry->block_size, entry->is_superblock,
+                            entry->is_superblock);
     stats_timer_stop(STATS_CACHE_START_WRITE);
 }
 
diff --git a/block_device.h b/block_device.h
index d628657..e633828 100644
--- a/block_device.h
+++ b/block_device.h
@@ -46,12 +46,34 @@ typedef uint64_t data_block_t;
  *                      the block device.
  */
 struct block_device {
+    /**
+     * start_read() - Start an operation to read a block.
+     * @dev:   The block device containing start_read().
+     * @block: The block to read.
+     */
     void (*start_read)(struct block_device* dev, data_block_t block);
+    /**
+     * start_write() - Start an operation to write to a block.
+     * @dev:              The block device containing start_write().
+     * @block:            The block to write data to.
+     * @data:             The data to be written.
+     * @data_size:        The size of *data, in bytes. Must be equal to this
+     *                    device's @block_size.
+     * @sync:             Whether pending changes on the device should be
+     *                    flushed before and after this block is written.
+     * @ensure_no_checkpoint: Whether the write should fail if there's a pending
+     *                    user data checkpoint.
+     */
     void (*start_write)(struct block_device* dev,
                         data_block_t block,
                         const void* data,
                         size_t data_size,
-                        bool sync);
+                        bool sync,
+                        bool ensure_no_checkpoint);
+    /**
+     * wait_for_io() - Wait for pending read/write operations to complete.
+     * @dev: The block device containing wait_for_io().
+     */
     void (*wait_for_io)(struct block_device* dev);
 
     data_block_t block_count;
diff --git a/block_device_tipc.c b/block_device_tipc.c
index 5098726..5bdae32 100644
--- a/block_device_tipc.c
+++ b/block_device_tipc.c
@@ -124,6 +124,12 @@ struct rpmb_spans {
     uint16_t rpmb_start;
 };
 
+#if STORAGE_EXTERNAL_SUPER_BLOCK_MAC
+extern struct super_block_mac_device super_block_mac_dev_tdp;
+extern struct super_block_mac_device super_block_mac_dev_td;
+#endif /* STORAGE_EXTERNAL_SUPER_BLOCK_MAC */
+
+#if HAS_RPMB
 static int rpmb_check(struct rpmb_state* rpmb_state, uint16_t block) {
     int ret;
     uint8_t tmp[RPMB_BUF_SIZE];
@@ -186,6 +192,7 @@ static void block_device_tipc_rpmb_start_read(struct block_device* dev,
     block_cache_complete_read(dev, block, tmp, BLOCK_SIZE_RPMB,
                               ret ? BLOCK_READ_IO_ERROR : BLOCK_READ_SUCCESS);
 }
+#endif /* HAS_RPMB */
 
 static inline enum block_write_error translate_write_error(int rc) {
     switch (rc) {
@@ -200,17 +207,22 @@ static inline enum block_write_error translate_write_error(int rc) {
     }
 }
 
+#if HAS_RPMB
 static void block_device_tipc_rpmb_start_write(struct block_device* dev,
                                                data_block_t block,
                                                const void* data,
                                                size_t data_size,
-                                               bool sync) {
+                                               bool sync,
+                                               bool ensure_no_checkpoint) {
     int ret;
     uint16_t rpmb_block;
     struct block_device_rpmb* dev_rpmb = dev_rpmb_to_state(dev);
 
     /* We currently sync every rpmb write. TODO: can we avoid this? */
-    (void)sync;
+    sync = true;
+
+    /* Currently allow writes to non-TD fs during checkpoint. TODO: remove */
+    ensure_no_checkpoint = ensure_no_checkpoint && dev_rpmb->is_userdata;
 
     assert(data_size == BLOCK_SIZE_RPMB);
     assert(block < dev->block_count);
@@ -219,7 +231,7 @@ static void block_device_tipc_rpmb_start_write(struct block_device* dev,
 
     ret = rpmb_write(dev_rpmb->rpmb_state, data,
                      rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
-                     BLOCK_SIZE_RPMB_BLOCKS, true, dev_rpmb->is_userdata);
+                     BLOCK_SIZE_RPMB_BLOCKS, sync, ensure_no_checkpoint);
 
     SS_DBG_IO("%s: block %" PRIu64 ", base %d, rpmb_block %d, ret %d\n",
               __func__, block, dev_rpmb->base, rpmb_block, ret);
@@ -230,6 +242,7 @@ static void block_device_tipc_rpmb_start_write(struct block_device* dev,
 static void block_device_tipc_rpmb_wait_for_io(struct block_device* dev) {
     assert(0); /* TODO: use async read/write */
 }
+#endif /* HAS_RPMB */
 
 static struct block_device_ns* to_block_device_ns(struct block_device* dev) {
     assert(dev);
@@ -260,16 +273,20 @@ static void block_device_tipc_ns_start_write(struct block_device* dev,
                                              data_block_t block,
                                              const void* data,
                                              size_t data_size,
-                                             bool sync) {
+                                             bool sync,
+                                             bool ensure_no_checkpoint) {
     int ret;
     enum block_write_error res = BLOCK_WRITE_FAILED;
     struct block_device_ns* dev_ns = to_block_device_ns(dev);
 
+    /* Currently allow writes to non-TD fs during checkpoint. TODO: remove */
+    ensure_no_checkpoint = ensure_no_checkpoint && dev_ns->is_userdata;
+
     assert(data_size == BLOCK_SIZE_MAIN);
 
     ret = ns_write_pos(dev_ns->ipc_handle, dev_ns->ns_handle,
                        block * BLOCK_SIZE_MAIN, data, data_size, sync,
-                       dev_ns->is_userdata);
+                       ensure_no_checkpoint);
     SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
     if (ret == BLOCK_SIZE_MAIN) {
         res = BLOCK_WRITE_SUCCESS;
@@ -283,6 +300,7 @@ static void block_device_tipc_ns_wait_for_io(struct block_device* dev) {
     assert(0); /* TODO: use async read/write */
 }
 
+#if HAS_RPMB
 static void block_device_tipc_init_dev_rpmb(struct block_device_rpmb* dev_rpmb,
                                             struct rpmb_state* rpmb_state,
                                             uint16_t base,
@@ -301,6 +319,7 @@ static void block_device_tipc_init_dev_rpmb(struct block_device_rpmb* dev_rpmb,
     dev_rpmb->base = base;
     dev_rpmb->is_userdata = is_userdata;
 }
+#endif /* HAS_RPMB */
 
 static void block_device_tipc_init_dev_ns(struct block_device_ns* dev_ns,
                                           handle_t ipc_handle,
@@ -318,6 +337,7 @@ static void block_device_tipc_init_dev_ns(struct block_device_ns* dev_ns,
     dev_ns->is_userdata = is_userdata;
 }
 
+#if HAS_RPMB
 /**
  * hwkey_derive_rpmb_key() - Derive rpmb key through hwkey server.
  * @session:  The hwkey session handle.
@@ -461,6 +481,7 @@ static int block_device_tipc_init_rpmb_key(struct rpmb_state* state,
 
     return ret;
 }
+#endif /* HAS_RPMB */
 
 static int set_storage_size(handle_t handle, struct block_device_ns* dev_ns) {
     data_block_t sz;
@@ -489,6 +510,7 @@ static bool block_device_tipc_has_ns(struct block_device_tipc* self) {
     return self->dev_ns.dev.block_count;
 }
 
+#if HAS_RPMB
 /**
  * init_rpmb_fs() - Initialize @self's RPMB fs and its backing block devices.
  * @self:            The struct block_device_tipc to modify
@@ -529,7 +551,8 @@ static int init_rpmb_fs(struct block_device_tipc* self,
 
     /* TODO: allow non-rpmb based tamper proof storage */
     ret = fs_init(&self->tr_state_rpmb, file_system_id_tp, fs_key,
-                  &self->dev_rpmb.dev, &self->dev_rpmb.dev, FS_INIT_FLAGS_NONE);
+                  &self->dev_rpmb.dev, &self->dev_rpmb.dev, NULL,
+                  FS_INIT_FLAGS_NONE);
     if (ret < 0) {
         SS_ERR("%s: failed to initialize TP: %d\n", __func__, ret);
         goto err_init_tr_state_rpmb;
@@ -549,6 +572,7 @@ static void destroy_rpmb_fs(struct block_device_tipc* self) {
     fs_destroy(&self->tr_state_rpmb);
     block_cache_dev_destroy(&self->dev_rpmb.dev);
 }
+#endif /* HAS_RPMB */
 
 /**
  * block_device_ns_open_file() - Open an ns backing file
@@ -627,6 +651,8 @@ enum ns_init_result {
 static int init_ns_fs(struct block_device_tipc* self,
                       const struct key* fs_key,
                       struct rpmb_span partition) {
+    struct block_device* super_dev;
+    struct super_block_mac_device* super_block_mac_dev = NULL;
     block_device_tipc_init_dev_ns(&self->dev_ns, self->ipc_handle, true);
 
     bool alternate_data_partition;
@@ -653,9 +679,11 @@ static int init_ns_fs(struct block_device_tipc* self,
         ns_init_flags |= FS_INIT_FLAGS_DO_CLEAR;
     }
 
+#if HAS_RPMB
     block_device_tipc_init_dev_rpmb(&self->dev_ns_rpmb, self->rpmb_state,
                                     partition.start, partition.block_count,
                                     true);
+#endif /* HAS_RPMB */
 
 #if STORAGE_NS_RECOVERY_CLEAR_ALLOWED
     ns_init_flags |= FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED;
@@ -669,8 +697,19 @@ static int init_ns_fs(struct block_device_tipc* self,
         ns_init_flags |= FS_INIT_FLAGS_ALTERNATE_DATA;
     }
 
+#if HAS_RPMB
+    super_dev = &self->dev_ns_rpmb.dev;
+#else
+    super_dev = &self->dev_ns.dev;
+#endif /* HAS_RPMB */
+
+#if STORAGE_EXTERNAL_SUPER_BLOCK_MAC
+    super_block_mac_dev = &super_block_mac_dev_td;
+#endif /* STORAGE_EXTERNAL_SUPER_BLOCK_MAC */
+
     ret = fs_init(&self->tr_state_ns, file_system_id_td, fs_key,
-                  &self->dev_ns.dev, &self->dev_ns_rpmb.dev, ns_init_flags);
+                  &self->dev_ns.dev, super_dev, super_block_mac_dev,
+                  ns_init_flags);
     if (ret < 0) {
         SS_ERR("%s: failed to initialize TD: %d\n", __func__, ret);
         goto err_init_fs_ns_tr_state;
@@ -705,6 +744,8 @@ static void destroy_ns_fs(struct block_device_tipc* self) {
 static int init_tdp_fs(struct block_device_tipc* self,
                        const struct key* fs_key,
                        struct rpmb_span partition) {
+    struct block_device* super_dev;
+    struct super_block_mac_device* super_block_mac_dev = NULL;
     block_device_tipc_init_dev_ns(&self->dev_ns_tdp, self->ipc_handle, false);
 
     int ret = block_device_ns_open_file(&self->dev_ns_tdp, tdp_filename, true);
@@ -718,9 +759,11 @@ static int init_tdp_fs(struct block_device_tipc* self,
         goto err_get_tdp_max_size;
     }
 
+#if HAS_RPMB
     block_device_tipc_init_dev_rpmb(&self->dev_ns_tdp_rpmb, self->rpmb_state,
                                     partition.start, partition.block_count,
                                     false);
+#endif /* HAS_RPMB */
 
     uint32_t tdp_init_flags = FS_INIT_FLAGS_NONE;
 #if STORAGE_TDP_AUTO_CHECKPOINT_ENABLED
@@ -733,8 +776,18 @@ static int init_tdp_fs(struct block_device_tipc* self,
     }
 #endif
 
+#if HAS_RPMB
+    super_dev = &self->dev_ns_tdp_rpmb.dev;
+#else
+    super_dev = &self->dev_ns_tdp.dev;
+#endif /* HAS_RPMB */
+
+#if STORAGE_EXTERNAL_SUPER_BLOCK_MAC
+    super_block_mac_dev = &super_block_mac_dev_tdp;
+#endif /* STORAGE_EXTERNAL_SUPER_BLOCK_MAC */
+
     ret = fs_init(&self->tr_state_ns_tdp, file_system_id_tdp, fs_key,
-                  &self->dev_ns_tdp.dev, &self->dev_ns_tdp_rpmb.dev,
+                  &self->dev_ns_tdp.dev, super_dev, super_block_mac_dev,
                   tdp_init_flags);
     if (ret < 0) {
         goto err_init_fs_ns_tdp_tr_state;
@@ -747,7 +800,7 @@ static int init_tdp_fs(struct block_device_tipc* self,
                __func__);
         fs_destroy(&self->tr_state_ns_tdp);
         ret = fs_init(&self->tr_state_ns_tdp, file_system_id_tdp, fs_key,
-                      &self->dev_ns_tdp.dev, &self->dev_ns_tdp_rpmb.dev,
+                      &self->dev_ns_tdp.dev, super_dev, super_block_mac_dev,
                       tdp_init_flags | FS_INIT_FLAGS_RESTORE_CHECKPOINT);
         if (ret < 0) {
             SS_ERR("%s: failed to initialize TDP: %d\n", __func__, ret);
@@ -799,7 +852,7 @@ static int init_nsp_fs(struct block_device_tipc* self,
     }
 
     ret = fs_init(&self->tr_state_ns_nsp, file_system_id_nsp, fs_key,
-                  &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev,
+                  &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev, NULL,
                   FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED |
                           FS_INIT_FLAGS_ALLOW_TAMPERING);
     if (ret < 0) {
@@ -818,7 +871,7 @@ static int init_nsp_fs(struct block_device_tipc* self,
         block_cache_dev_destroy(&self->dev_ns_nsp.dev);
 
         ret = fs_init(&self->tr_state_ns_nsp, file_system_id_nsp, fs_key,
-                      &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev,
+                      &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev, NULL,
                       FS_INIT_FLAGS_DO_CLEAR | FS_INIT_FLAGS_ALLOW_TAMPERING);
         if (ret < 0) {
             SS_ERR("%s: failed to initialize NSP: %d\n", __func__, ret);
@@ -896,6 +949,7 @@ err_init_ns_fs:
     return ret;
 }
 
+#if HAS_RPMB
 /**
  * rpmb_span_end() - Calculates the first block past the end of @self.
  */
@@ -921,6 +975,7 @@ static void calculate_rpmb_spans(struct rpmb_spans* out) {
     out->tdp.start = rpmb_span_end(out->ns);
     out->rpmb_start = rpmb_span_end(out->tdp);
 }
+#endif /* HAS_RPMB */
 
 int block_device_tipc_init(struct block_device_tipc* state,
                            handle_t ipc_handle,
@@ -929,10 +984,14 @@ int block_device_tipc_init(struct block_device_tipc* state,
                            hwkey_session_t hwkey_session) {
     int ret;
     struct rpmb_spans partitions;
+
+#if HAS_RPMB
     calculate_rpmb_spans(&partitions);
+#endif /* HAS_RPMB */
 
     state->ipc_handle = ipc_handle;
 
+#if HAS_RPMB
     /* init rpmb */
     ret = rpmb_init(&state->rpmb_state, &state->ipc_handle);
     if (ret < 0) {
@@ -952,6 +1011,7 @@ int block_device_tipc_init(struct block_device_tipc* state,
     if (ret < 0) {
         goto err_init_rpmb_fs;
     }
+#endif /* HAS_RPMB */
 
     ret = init_ns_backed_filesystems(state, fs_key, partitions.ns,
                                      partitions.tdp);
@@ -962,11 +1022,13 @@ int block_device_tipc_init(struct block_device_tipc* state,
     return 0;
 
 err_init_ns_fs:
+#if HAS_RPMB
     destroy_rpmb_fs(state);
 err_init_rpmb_fs:
 err_init_rpmb_key:
     rpmb_uninit(state->rpmb_state);
 err_rpmb_init:
+#endif /* HAS_RPMB */
     return ret;
 }
 
@@ -981,17 +1043,27 @@ void block_device_tipc_destroy(struct block_device_tipc* state) {
         destroy_ns_fs(state);
     }
 
+#if HAS_RPMB
     destroy_rpmb_fs(state);
     rpmb_uninit(state->rpmb_state);
+#endif /* HAS_RPMB */
 }
 
 bool block_device_tipc_fs_connected(struct block_device_tipc* self,
                                     enum storage_filesystem_type fs_type) {
     switch (fs_type) {
     case STORAGE_TP:
+#if HAS_RPMB
         return self->ipc_handle != INVALID_IPC_HANDLE;
+#else
+        return false;
+#endif /* HAS_RPMB */
     case STORAGE_TDEA:
+#if HAS_RPMB
         return self->ipc_handle != INVALID_IPC_HANDLE;
+#else
+        return block_device_tipc_fs_connected(self, STORAGE_TDP);
+#endif /* HAS_RPMB */
     case STORAGE_TD:
         return block_device_tipc_has_ns(self) &&
                self->dev_ns.ipc_handle != INVALID_IPC_HANDLE;
@@ -1023,9 +1095,22 @@ struct fs* block_device_tipc_get_fs(struct block_device_tipc* self,
 
     switch (fs_type) {
     case STORAGE_TP:
+#if HAS_RPMB
         return &self->tr_state_rpmb;
+#else
+        return NULL;
+#endif /* HAS_RPMB */
     case STORAGE_TDEA:
+#if HAS_RPMB
         return &self->tr_state_rpmb;
+#else
+        /*
+         * STORAGE_TDP must be backed by a partition in the non-rpmb case so we
+         * can make it available early since there are clients that need early
+         * access.
+         */
+        return block_device_tipc_get_fs(self, STORAGE_TDP);
+#endif /* HAS_RPMB */
     case STORAGE_TD:
         return &self->tr_state_ns;
     case STORAGE_TDP:
@@ -1061,7 +1146,9 @@ int block_device_tipc_reconnect(struct block_device_tipc* self,
     bool has_ns = block_device_tipc_has_ns(self);
     if (!has_ns) {
         struct rpmb_spans partitions;
+#if HAS_RPMB
         calculate_rpmb_spans(&partitions);
+#endif /* HAS_RPMB */
         ret = init_ns_backed_filesystems(self, fs_key, partitions.ns,
                                          partitions.tdp);
         if (ret < 0) {
diff --git a/block_device_tipc.h b/block_device_tipc.h
index 787172b..584c8f8 100644
--- a/block_device_tipc.h
+++ b/block_device_tipc.h
@@ -63,6 +63,7 @@ enum storage_filesystem_type {
     STORAGE_FILESYSTEMS_COUNT,
 };
 
+#if HAS_RPMB
 /**
  * struct block_device_rpmb
  * @dev:         Block device state
@@ -77,6 +78,7 @@ struct block_device_rpmb {
     uint16_t base;
     bool is_userdata;
 };
+#endif /* HAS_RPMB */
 
 /**
  * struct block_device_ns
@@ -121,18 +123,24 @@ struct block_device_ns {
  */
 struct block_device_tipc {
     handle_t ipc_handle;
-    struct rpmb_state* rpmb_state;
 
+#if HAS_RPMB
+    struct rpmb_state* rpmb_state;
     struct block_device_rpmb dev_rpmb;
     struct fs tr_state_rpmb;
+#endif /* HAS_RPMB */
 
     struct block_device_ns dev_ns;
+#if HAS_RPMB
     struct block_device_rpmb dev_ns_rpmb;
+#endif /* HAS_RPMB */
     struct fs tr_state_ns;
 
 #if HAS_FS_TDP
     struct block_device_ns dev_ns_tdp;
+#if HAS_RPMB
     struct block_device_rpmb dev_ns_tdp_rpmb;
+#endif /* HAS_RPMB */
     struct fs tr_state_ns_tdp;
 #endif
 
diff --git a/block_set.c b/block_set.c
index 63b0926..604f1e4 100644
--- a/block_set.c
+++ b/block_set.c
@@ -137,7 +137,7 @@ static void block_set_print_ranges(struct transaction* tr,
     struct block_range range;
     int split_line = 0;
 
-    printf("set:\n");
+    printf("set%s:\n", list_in_list(&set->node) ? "" : " (not in list)");
 
     block_tree_walk(tr, &set->block_tree, 0, true, &path);
     block_range_init_from_path(&range, &path);
diff --git a/checkpoint.c b/checkpoint.c
index 29c36b1..87abcd2 100644
--- a/checkpoint.c
+++ b/checkpoint.c
@@ -105,7 +105,8 @@ void checkpoint_update_roots(struct transaction* tr,
  * @fs:             File-system to initialize checkpoint state in.
  * @checkpoint:     Checkpoint root page block and mac. Must be a valid block.
  * @files:          New checkpoint file tree. May be %NULL.
- * @free:           New checkpoint free set. May be %NULL.
+ * @free:           New checkpoint free set. May be %NULL. If not %NULL, must be
+ *                  an empty, initialized block set which is not a list.
  *
  * Returns %true if the @files and @free nodes were properly populated from the
  * fields in @checkpoint. Either @files or @free may be %NULL; %NULL out params
@@ -139,8 +140,11 @@ bool checkpoint_read(struct transaction* tr,
         files->root = checkpoint_ro->files;
     }
     if (free) {
+        assert(!list_in_list(&free->node));
+        assert(block_range_empty(free->initial_range));
+
         free->block_tree.root = checkpoint_ro->free;
-        block_range_clear(&free->initial_range);
+        list_add_tail(&tr->fs->free_sets, &free->node);
     }
 
 err_magic_mismatch:
diff --git a/crypt.h b/crypt.h
index 234ea56..c094afd 100644
--- a/crypt.h
+++ b/crypt.h
@@ -18,16 +18,16 @@
 
 #include <stdint.h>
 
+#include <storage_internal/mac.h>
+
+#ifndef DEBUG_MAC_VALUES
 #define DEBUG_MAC_VALUES 0
+#endif
 
 struct key {
     uint8_t byte[32];
 };
 
-struct mac {
-    uint8_t byte[16];
-};
-
 struct iv {
     uint8_t byte[16];
 };
diff --git a/fs.h b/fs.h
index 80771ff..83cbf60 100644
--- a/fs.h
+++ b/fs.h
@@ -18,6 +18,8 @@
 
 #include <stdbool.h>
 
+#include <storage_internal/super_block_mac_device.h>
+
 #if BUILD_STORAGE_TEST
 #define FULL_ASSERT 1
 #else
@@ -65,6 +67,9 @@ STATIC_ASSERT(sizeof(struct super_block_backup) == 76);
  * @transactions:                   Transaction list.
  * @allocated:                      List of block sets containing blocks
  *                                  allocated by active transactions.
+ * @free_sets:                      List of all active free sets for this fs. A
+ *                                  block is only free if it's in all of the
+ *                                  contained sets.
  * @free:                           Block set of free blocks.
  * @files:                          B+ tree of all files.
  * @checkpoint:                     Block and mac of the latest committed
@@ -72,10 +77,13 @@ STATIC_ASSERT(sizeof(struct super_block_backup) == 76);
  *                                  holds the files root and free set at the
  *                                  time of the most recent checkpoint.
  * @checkpoint_free:                Block set of free blocks at the time of the
- *                                  last committed checkpoint. A block is only
- *                                  free if it is in both @free and
- *                                  @checkpoint_free.
+ *                                  last committed checkpoint. If there is no
+ *                                  last committed checkpoint, this will be an
+ *                                  empty block set and will not be linked in
+ *                                  the @free_sets list.
  * @super_dev:                      Block device used to store super blocks.
+ * @super_block_mac_dev:            Device used to load and store the super
+ *                                  block mac found in external storage.
  * @readable:                       %true if the file system is initialized and
  *                                  readable. If false, no reads are valid and
  *                                  @writable must be %false.
@@ -94,6 +102,7 @@ STATIC_ASSERT(sizeof(struct super_block_backup) == 76);
  *                                  super-block in.
  * @super_block_version:            Last read or written super block version.
  * @written_super_block_version:    Last written super block version.
+ * @written_super_block_mac:        Last written super block mac.
  * @main_repaired:                  %true if main file system has been repaired
  *                                  since being wiped. In alternate state only
  *                                  used to persist this flag in the super
@@ -137,11 +146,13 @@ struct fs {
     struct block_device* dev;
     struct list_node transactions;
     struct list_node allocated;
+    struct list_node free_sets;
     struct block_set free;
     struct block_tree files;
     struct block_mac checkpoint;
     struct block_set checkpoint_free;
     struct block_device* super_dev;
+    struct super_block_mac_device* super_block_mac_dev;
     bool readable;
     bool writable;
     bool allow_tampering;
@@ -149,6 +160,7 @@ struct fs {
     data_block_t super_block[2];
     unsigned int super_block_version;
     unsigned int written_super_block_version;
+    struct block_mac written_super_block_mac;
     bool main_repaired;
     bool alternate_data;
     bool needs_full_scan;
@@ -219,6 +231,7 @@ int fs_init(struct fs* fs,
             const struct key* key,
             struct block_device* dev,
             struct block_device* super_dev,
+            struct super_block_mac_device* super_block_mac_dev,
             fs_init_flags32_t flags);
 
 static inline bool fs_is_repaired(struct fs* fs) {
diff --git a/lib_internal/include/storage_internal/mac.h b/lib_internal/include/storage_internal/mac.h
new file mode 100644
index 0000000..29dc9aa
--- /dev/null
+++ b/lib_internal/include/storage_internal/mac.h
@@ -0,0 +1,23 @@
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
+#pragma once
+
+#include <stdint.h>
+
+struct mac {
+    uint8_t byte[16];
+};
diff --git a/lib_internal/include/storage_internal/super_block_mac_device.h b/lib_internal/include/storage_internal/super_block_mac_device.h
new file mode 100644
index 0000000..1e5b08a
--- /dev/null
+++ b/lib_internal/include/storage_internal/super_block_mac_device.h
@@ -0,0 +1,85 @@
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
+#pragma once
+
+#include <stdint.h>
+
+#include "mac.h"
+
+/**
+ * enum super_block_mac_device_error - Possible error codes
+ * @SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED: Not initialized error
+ * @SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION:   Communication error
+ */
+enum super_block_mac_device_error {
+    SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED = -1,
+    SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION = -2,
+};
+
+/**
+ * struct super_block_mac_device - Device used to load and store a super block
+ *                                 mac found in external storage.
+ * @get:            Pointer to function to get a super block mac in external
+ *                  storage.
+ * @set:            Pointer to function to set a super block mac in external
+ *                  storage.
+ * @delete_mac:     Pointer to function to delete a super block mac in external
+ *                  storage.
+ */
+struct super_block_mac_device {
+    /**
+     * get - Get super block mac in external storage.
+     * @super_block_mac_dev: The super block mac device containing get().
+     * @flags:               Flags to populate.
+     * @mac:                 Pointer to the mac to populate.
+     *
+     * If this function is called before the mac has been initialized, then
+     * SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED will be returned with a
+     * valid set of flags, and @mac will be left untouched.
+     *
+     * Return: 0 on success, &enum super_block_mac_device_error otherwise.
+     */
+    int (*get)(struct super_block_mac_device* super_block_mac_dev,
+               uint8_t* flags,
+               struct mac* mac);
+
+    /**
+     * set - Set super block mac in external storage.
+     * @super_block_mac_dev: The super block mac device containing set().
+     * @flags:               Flags to populate. The 7 lower bit are available
+     *                       for use since the MSB is reserved and will trigger
+     *                       an assert if set.
+     * @mac:                 Pointer to the mac to store.
+     *
+     * Return: 0 on success, &enum super_block_mac_device_error otherwise.
+     */
+    int (*set)(struct super_block_mac_device* super_block_mac_dev,
+               const uint8_t flags,
+               const struct mac* mac);
+
+    /**
+     * delete_mac - Uninitialize super block mac in external storage.
+     * @super_block_mac_dev: The super block mac device containing delete_mac().
+     *
+     * This function should ensure that the mac value cannot be used in the
+     * future, but preserve the flags field to retain super block version
+     * information. It is not required to reset the mac value.
+     *
+     * Return: 0 on success, &enum super_block_mac_device_error otherwise.
+     */
+    int (*delete_mac)(struct super_block_mac_device* super_block_mac_dev);
+};
diff --git a/lib_internal/rules.mk b/lib_internal/rules.mk
new file mode 100644
index 0000000..aed4a58
--- /dev/null
+++ b/lib_internal/rules.mk
@@ -0,0 +1,27 @@
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
+# This module defines shared storage interfaces for feature libraries that are
+# directly linked into the Trusty storage application. By having this module
+# separate from the storage application, we avoid circular dependencies when
+# implementing storage internal specific feature libraries.
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_EXPORT_INCLUDES += $(LOCAL_DIR)/include
+
+include make/library.mk
diff --git a/rpmb.c b/rpmb.c
index b1376bc..d1b107e 100644
--- a/rpmb.c
+++ b/rpmb.c
@@ -433,7 +433,7 @@ static int rpmb_write_data(struct rpmb_state* state,
                            uint16_t addr,
                            uint16_t count,
                            bool sync,
-                           bool sync_checkpoint) {
+                           bool ensure_no_checkpoint) {
     int i;
     int ret;
     struct rpmb_key mac;
@@ -462,7 +462,8 @@ static int rpmb_write_data(struct rpmb_state* state,
     }
 
     ret = rpmb_send(state->mmc_handle, cmd, sizeof(cmd[0]) * count, &rescmd,
-                    sizeof(rescmd), &res, sizeof(res), sync, sync_checkpoint);
+                    sizeof(rescmd), &res, sizeof(res), sync,
+                    ensure_no_checkpoint);
     if (ret < 0) {
         fprintf(stderr, "rpmb send failed: %d, result: %hu\n", ret,
                 rpmb_get_u16(res.result));
@@ -595,7 +596,7 @@ int rpmb_write(struct rpmb_state* state,
                uint16_t addr,
                uint16_t count,
                bool sync,
-               bool sync_checkpoint) {
+               bool ensure_no_checkpoint) {
     int ret;
 
     if (!state)
@@ -603,7 +604,7 @@ int rpmb_write(struct rpmb_state* state,
     if (state->verify_failed)
         return -EIO;
 
-    ret = rpmb_write_data(state, buf, addr, count, sync, sync_checkpoint);
+    ret = rpmb_write_data(state, buf, addr, count, sync, ensure_no_checkpoint);
     if (ret < 0)
         return ret;
 
diff --git a/rpmb.h b/rpmb.h
index 647fe0f..0a95b75 100644
--- a/rpmb.h
+++ b/rpmb.h
@@ -52,7 +52,7 @@ int rpmb_write(struct rpmb_state* state,
                uint16_t addr,
                uint16_t count,
                bool sync,
-               bool sync_checkpoint);
+               bool ensure_no_checkpoint);
 
 /* needs */
 int rpmb_send(void* mmc_handle,
@@ -63,6 +63,6 @@ int rpmb_send(void* mmc_handle,
               void* read_buf,
               size_t read_buf_size,
               bool sync,
-              bool sync_checkpoint);
+              bool ensure_no_checkpoint);
 
 #endif
diff --git a/rpmb_dev/rules.mk b/rpmb_dev/rules.mk
index 608ff5f..43619f5 100644
--- a/rpmb_dev/rules.mk
+++ b/rpmb_dev/rules.mk
@@ -22,6 +22,9 @@ HOST_SRCS := \
 	$(LOCAL_DIR)/main.c \
 	$(LOCAL_DIR)/rpmb_dev.c \
 
+HOST_INCLUDE_DIRS += \
+	$(LOCAL_DIR)/../lib_internal/include \
+
 HOST_FLAGS := -DBUILD_STORAGE_TEST=1
 
 HOST_LIBS := \
diff --git a/rules.mk b/rules.mk
index 695c991..89c7b9a 100644
--- a/rules.mk
+++ b/rules.mk
@@ -37,6 +37,11 @@ ifeq (true,$(call TOBOOL,$(WITH_HKDF_RPMB_KEY)))
     MODULE_DEFINES += WITH_HKDF_RPMB_KEY=1
 endif
 
+STORAGE_HAS_RPMB ?= true
+ifeq (true,$(call TOBOOL,$(STORAGE_HAS_RPMB)))
+    MODULE_DEFINES += HAS_RPMB=1
+endif
+
 STORAGE_HAS_FS_TDP ?= false
 ifeq (true,$(call TOBOOL,$(STORAGE_HAS_FS_TDP)))
     MODULE_DEFINES += HAS_FS_TDP=1
@@ -77,6 +82,10 @@ ifeq (true,$(call TOBOOL,$(STORAGE_TDP_AUTO_CHECKPOINT_ENABLED)))
     MODULE_DEFINES += STORAGE_TDP_AUTO_CHECKPOINT_ENABLED=1
 endif
 
+ifneq ($(STORAGE_EXTERNAL_SUPER_BLOCK_MAC),)
+    MODULE_DEFINES += STORAGE_EXTERNAL_SUPER_BLOCK_MAC=1
+endif
+
 include $(LOCAL_DIR)/common.mk
 
 MODULE_SRCS := \
@@ -93,6 +102,7 @@ MODULE_SRCS := \
 	$(LOCAL_DIR)/tipc_service.c \
 
 MODULE_LIBRARY_DEPS := \
+	trusty/user/app/storage/lib_internal \
 	trusty/user/base/interface/metrics \
 	trusty/user/base/interface/storage \
 	trusty/user/base/lib/hwkey \
@@ -101,6 +111,10 @@ MODULE_LIBRARY_DEPS := \
 	trusty/user/base/lib/tipc \
 	external/boringssl \
 
+ifneq ($(STORAGE_EXTERNAL_SUPER_BLOCK_MAC),)
+MODULE_LIBRARY_DEPS += $(STORAGE_EXTERNAL_SUPER_BLOCK_MAC)
+endif
+
 ifeq (true,$(call TOBOOL,$(STORAGE_ENABLE_ERROR_REPORTING)))
 MODULE_LIBRARY_DEPS += \
 	trusty/user/base/interface/stats/nw \
diff --git a/super.c b/super.c
index 0dba82e..63e0a7e 100644
--- a/super.c
+++ b/super.c
@@ -289,7 +289,14 @@ static bool update_super_block_internal(struct transaction* tr,
     super_rw->flags3 = flags;
     tr->fs->written_super_block_version = ver;
 
-    block_put_dirty_no_mac(super_rw, &super_ref, tr->fs->allow_tampering);
+    if (tr->fs->super_block_mac_dev) {
+        block_mac_set_block(tr, &tr->fs->written_super_block_mac,
+                            tr->fs->super_block[index]);
+        block_put_dirty(tr, super_rw, &super_ref,
+                        &tr->fs->written_super_block_mac, NULL);
+    } else {
+        block_put_dirty_no_mac(super_rw, &super_ref, tr->fs->allow_tampering);
+    }
 
     return true;
 }
@@ -324,6 +331,33 @@ bool update_super_block(struct transaction* tr,
  */
 static bool write_initial_super_block(struct fs* fs) {
     struct transaction* tr;
+    int ret;
+
+    if (fs->super_block_mac_dev) {
+        /*
+         * If we're here, we've been asked to clear the file system and external
+         * super block mac support is enabled. So we delete the mac here, while
+         * preserving the flags that contain the current version.
+         *
+         * At this point, we have already read the current version number.
+         * When we call update_super_block_internal, the written super block
+         * version number will be incremented by one so sequential versions are
+         * preserved.
+         *
+         * If we reboot after delete_mac, but before we call
+         * update_super_block_internal, we will attempt to read the mac during
+         * fs_init and find it uninitialized. Since, the version stored in the
+         * flags field is not reset, we use that as the current super block
+         * version. When we call update_super_block_internal, the next super
+         * block written will be the super block version found in the flags
+         * incremented by one.
+         */
+        ret = fs->super_block_mac_dev->delete_mac(fs->super_block_mac_dev);
+        if (ret) {
+            return false;
+        }
+    }
+
     tr = calloc(1, sizeof(*tr));
     if (!tr) {
         return false;
@@ -370,17 +404,7 @@ void write_current_super_block(struct fs* fs, bool reinitialize) {
          * only allow transaction_initial_super_block_complete() to reinitialize
          * a failed special transaction after it attempts and fails to write the
          * block to disk.
-         *
-         * Since we pin special superblock entries in the block cache and
-         * therefore cannot evict them with normal transactions,
-         * transaction_initial_super_block_complete() is the only place we can
-         * attempt a special transaction write, and if it fails the transaction
-         * is immediately reinitialized. Therefore we should only ever be in a
-         * failed state if reinitialize is true (i.e. we are being called from
-         * transaction_initial_super_block_complete()).
          */
-
-        assert(reinitialize || !fs->initial_super_block_tr->failed);
         if (!fs->initial_super_block_tr->failed || !reinitialize) {
             return;
         }
@@ -566,8 +590,6 @@ static bool use_new_super(const struct block_device* dev,
     return false;
 }
 
-static void fs_init_free_set(struct fs* fs, struct block_set* set);
-
 /**
  * fs_set_roots - Initialize fs state from super block roots
  * @fs:                File system state object
@@ -608,10 +630,10 @@ static bool fs_set_roots(struct fs* fs,
         transaction_init(&tr, fs, true);
 
         /*
-         * fs->checkpoint_free is initialized to contain all blocks, so we
-         * don't have to initialize it if there is no checkpoint on disk
+         * fs->checkpoint_free is initialized to be empty and not included in
+         * fs->free_sets. Make sure we haven't somehow initialized it already.
          */
-        assert(!block_range_empty(fs->checkpoint_free.initial_range));
+        assert(!list_in_list(&fs->checkpoint_free.node));
 
         if (block_mac_valid(&tr, &fs->checkpoint)) {
             success = checkpoint_read(&tr, &fs->checkpoint, &checkpoint_files,
@@ -628,7 +650,15 @@ static bool fs_set_roots(struct fs* fs,
              */
             fs->main_repaired = true;
             fs->files.root = checkpoint_files.root;
+
+            /*
+             * Remove fs->free from free_sets while we overwrite it so the list
+             * doesn't break.
+             */
+            list_delete(&fs->free.node);
             block_set_copy_ro(&tr, &fs->free, &fs->checkpoint_free);
+            list_add_head(&fs->free_sets, &fs->free.node);
+
             /*
              * block_set_copy_ro() clears the copy_on_write flag for the free
              * set, so we have to reset it to allow modification.
@@ -692,18 +722,20 @@ static int fs_init_from_super(struct fs* fs,
 
     block_set_init(fs, &fs->free);
     fs->free.block_tree.copy_on_write = true;
+    list_add_tail(&fs->free_sets, &fs->free.node);
+
     fs_file_tree_init(fs, &fs->files);
     fs->files.copy_on_write = true;
     fs->files.allow_copy_on_write = true;
     fs->main_repaired = false;
 
-    memset(&fs->checkpoint, 0, sizeof(fs->checkpoint));
-    block_set_init(fs, &fs->checkpoint_free);
     /*
-     * checkpoint_init() will clear the checkpoint initial range if a valid
+     * Iff no checkpoint exists, fs->checkpoint_free shouldn't be part of
+     * fs->free_sets. Leave it out of the list for now until we know whether a
      * checkpoint exists.
      */
-    fs_init_free_set(fs, &fs->checkpoint_free);
+    memset(&fs->checkpoint, 0, sizeof(fs->checkpoint));
+    block_set_init(fs, &fs->checkpoint_free);
 
     /* Reserve 1/4 for tmp blocks plus half of the remaining space */
     fs->reserved_count = fs->dev->block_count / 8 * 5;
@@ -861,7 +893,7 @@ static int fs_init_from_super(struct fs* fs,
         } else {
             pr_init("fs %s: loaded super block version %d, checkpoint exists: %d\n",
                     fs->name, fs->super_block_version,
-                    block_range_empty(fs->checkpoint_free.initial_range));
+                    list_in_list(&fs->checkpoint_free.node));
         }
     } else {
         if (is_clear) {
@@ -875,6 +907,12 @@ static int fs_init_from_super(struct fs* fs,
                 fs->needs_full_scan = false;
             }
         } else {
+            /*
+             * Note: is_clear might not be set as expected if the external super
+             * block mac feature is enabled. If we delete the mac value and
+             * reset before calling write_initial_super_block when attempting a
+             * factory reset, we will end up in this case.
+             */
             pr_init("fs %s: no valid super-block found, create empty\n",
                     fs->name);
         }
@@ -918,6 +956,74 @@ static int fs_init_from_super(struct fs* fs,
     return 0;
 }
 
+/**
+ * diagnose_external_super_block_mac_load_failure - Read super blocks and print
+ *                                                  version debug info.
+ * @fs:         File system state object.
+ * @flags:      Flags loaded from the external mac device
+ */
+static void diagnose_external_super_block_mac_load_failure(
+        struct fs* fs,
+        uint8_t external_flags) {
+    const struct super_block* super = NULL;
+    struct obj_ref super_ref = OBJ_REF_INITIAL_VALUE(super_ref);
+    const struct super_block* other_super;
+    struct obj_ref other_super_ref = OBJ_REF_INITIAL_VALUE(other_super_ref);
+    bool is_super_valid;
+    bool is_other_super_valid;
+    uint32_t super_version;
+    uint32_t other_super_version;
+    uint32_t external_version = external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK;
+
+    /*
+     * Failed to read the super block with mac so attempt a read
+     * without a mac for both super blocks and diagnose the problem.
+     */
+    super = block_get_super(
+            fs, (external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK) % 2,
+            &super_ref);
+    other_super = block_get_super(
+            fs, ((external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK) + 1) % 2,
+            &other_super_ref);
+
+    is_super_valid = super ? super_block_valid(fs->dev, super) : false;
+    is_other_super_valid =
+            other_super ? super_block_valid(fs->dev, other_super) : false;
+    super_version =
+            is_super_valid ? super->flags & SUPER_BLOCK_FLAGS_VERSION_MASK : -1;
+    other_super_version =
+            is_other_super_valid
+                    ? other_super->flags & SUPER_BLOCK_FLAGS_VERSION_MASK
+                    : -1;
+
+    pr_err("fs %s expected super-block version (0x%x) from external flags\n",
+           fs->name, external_version);
+    if (super && is_super_valid) {
+        pr_err("fs %s data super-block valid with version (0x%x)\n", fs->name,
+               super_version);
+    } else if (super && !is_super_valid) {
+        pr_err("fs %s data super-block was read, but is invalid\n", fs->name);
+    } else if (!super) {
+        pr_err("fs %s data super-block could not be read\n", fs->name);
+    }
+
+    if (other_super && is_other_super_valid) {
+        pr_err("fs %s other super-block valid with version (0x%x)\n", fs->name,
+               other_super_version);
+    } else if (other_super && !is_other_super_valid) {
+        pr_err("fs %s other super-block was read, but is invalid\n", fs->name);
+    } else if (!other_super) {
+        pr_err("fs %s other super-block could not be read\n", fs->name);
+    }
+
+    if (super) {
+        block_put(super, &super_ref);
+    }
+    if (other_super) {
+        block_put(other_super, &other_super_ref);
+    }
+}
+
 /**
  * load_super_block - Find and load superblock and initialize file system state
  * @fs:         File system state object.
@@ -933,9 +1039,63 @@ static int load_super_block(struct fs* fs, fs_init_flags32_t flags) {
     struct obj_ref new_super_ref = OBJ_REF_INITIAL_VALUE(new_super_ref);
     const struct super_block* old_super = NULL;
     struct obj_ref old_super_ref = OBJ_REF_INITIAL_VALUE(old_super_ref);
+    struct block_mac super_block_mac;
+    struct mac super_mac;
+    uint8_t external_flags;
 
     assert(fs->super_dev->block_size >= sizeof(struct super_block));
 
+    if (fs->super_block_mac_dev) {
+        ret = fs->super_block_mac_dev->get(fs->super_block_mac_dev,
+                                           &external_flags, &super_mac);
+        if (ret == SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED) {
+            /*
+             * Super block does not exist and a reset is allowed, preserve the
+             * external super block version and reinit.
+             */
+            pr_warn("super-block mac is uninitialized, write new super block\n");
+            fs->super_block_version =
+                    external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK;
+            goto fs_init_from_super;
+        } else if (ret) {
+            pr_err("failed to read super-block mac (%d)\n", ret);
+            ret = -1;
+            goto err;
+        }
+
+        block_mac_set_mac_fs(fs, &super_block_mac, &super_mac);
+        block_mac_set_block_fs(
+                fs, &super_block_mac,
+                (external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK) % 2);
+        old_super =
+                block_get_super_with_mac(fs, &super_block_mac, &old_super_ref);
+        if (!old_super) {
+            diagnose_external_super_block_mac_load_failure(fs, external_flags);
+            ret = -1;
+            goto err;
+        }
+
+        if (!super_block_valid(fs->dev, old_super)) {
+            pr_err("read super-block with mac, but super-block is invalid\n");
+            diagnose_external_super_block_mac_load_failure(fs, external_flags);
+            ret = -1;
+            goto err;
+        }
+
+        if ((external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK) ==
+            (old_super->flags & SUPER_BLOCK_FLAGS_VERSION_MASK)) {
+            pr_init("read super-block with mac, version (0x%x)\n",
+                    external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK);
+        } else {
+            pr_warn("warning read super-block with mac version (0x%x), "
+                    "does not match found super-block version (0x%x)\n",
+                    external_flags & SUPER_BLOCK_FLAGS_VERSION_MASK,
+                    old_super->flags & SUPER_BLOCK_FLAGS_VERSION_MASK);
+        }
+
+        goto fs_init_from_super;
+    }
+
     for (i = 0; i < countof(fs->super_block); i++) {
         new_super = block_get_super(fs, fs->super_block[i], &new_super_ref);
         if (!new_super) {
@@ -961,6 +1121,7 @@ static int load_super_block(struct fs* fs, fs_init_flags32_t flags) {
         }
     }
 
+fs_init_from_super:
     ret = fs_init_from_super(fs, old_super, flags);
 err:
     if (old_super) {
@@ -1130,11 +1291,13 @@ void fs_file_tree_init(const struct fs* fs, struct block_tree* tree) {
 
 /**
  * fs_init - Initialize file system state
- * @fs:         File system state object.
- * @name:       File system name for error reporting. Must be a static string.
- * @key:        Key pointer. Must not be freed while @fs is in use.
- * @dev:        Main block device.
- * @super_dev:  Block device for super block.
+ * @fs:                   File system state object.
+ * @name:                 File system name for error reporting. Must be a static
+ *                        string.
+ * @key:                  Key pointer. Must not be freed while @fs is in use.
+ * @dev:                  Main block device.
+ * @super_dev:            Block device for super block.
+ * @super_block_mac_dev:  Block device for external super block mac storage.
  * @flags:      Any of &typedef fs_init_flags32_t, ORed together.
  */
 int fs_init(struct fs* fs,
@@ -1142,6 +1305,7 @@ int fs_init(struct fs* fs,
             const struct key* key,
             struct block_device* dev,
             struct block_device* super_dev,
+            struct super_block_mac_device* super_block_mac_dev,
             fs_init_flags32_t flags) {
     int ret;
 
@@ -1167,12 +1331,14 @@ int fs_init(struct fs* fs,
     fs->key = key;
     fs->dev = dev;
     fs->super_dev = super_dev;
+    fs->super_block_mac_dev = super_block_mac_dev;
     fs->readable = false;
     fs->writable = false;
     fs->allow_tampering = flags & FS_INIT_FLAGS_ALLOW_TAMPERING;
     fs->checkpoint_required = false;
     list_initialize(&fs->transactions);
     list_initialize(&fs->allocated);
+    list_initialize(&fs->free_sets);
     fs->initial_super_block_tr = NULL;
     list_add_tail(&fs_list, &fs->node);
 
diff --git a/test/block_host_test/block_test.c b/test/block_host_test/block_test.c
index 999088d..df8cb0d 100644
--- a/test/block_host_test/block_test.c
+++ b/test/block_host_test/block_test.c
@@ -35,6 +35,7 @@
 #include "debug_stats.h"
 #include "error_reporting_mock.h"
 #include "file.h"
+#include "super_block_mac_storage_fake.h"
 #include "transaction.h"
 
 #include <time.h>
@@ -155,7 +156,7 @@ static void block_test_clear_reinit_etc(struct transaction* tr,
         memset(&blocks[start], 0, (BLOCK_COUNT - start) * sizeof(struct block));
     }
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, flags);
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL, flags);
     assert(ret == 0);
     fs->reserved_count = 18; /* HACK: override default reserved space */
     transaction_init(tr, fs, true);
@@ -191,7 +192,8 @@ static void block_test_start_write(struct block_device* dev,
                                    data_block_t block,
                                    const void* data,
                                    size_t data_size,
-                                   bool sync) {
+                                   bool sync,
+                                   bool ensure_no_checkpoint) {
     assert(block < countof(blocks));
     assert(data_size <= sizeof(blocks[block].data));
     memcpy(blocks[block].data, data, data_size);
@@ -2184,7 +2186,7 @@ static void future_fs_version_test(struct transaction* tr) {
     fs_destroy(fs);
     block_cache_dev_destroy(dev);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_NONE);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2199,7 +2201,7 @@ static void future_fs_version_test(struct transaction* tr) {
     fs_destroy(fs);
     block_cache_dev_destroy(dev);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_DO_CLEAR);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2233,7 +2235,7 @@ static void future_fs_version_test(struct transaction* tr) {
     block_cache_clean_transaction(tr);
     transaction_free(tr);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_NONE);
     assert(ret == 0);
 
@@ -2310,7 +2312,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
 
     fs_destroy(fs);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_NONE);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2325,7 +2327,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
     fs_destroy(fs);
     block_cache_dev_destroy(dev);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_DO_CLEAR);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2352,7 +2354,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
     /* set all flag bits, this should fail unless we support 16 flags */
     set_required_flags(fs, UINT16_MAX);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_NONE);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2367,7 +2369,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
     fs_destroy(fs);
     block_cache_dev_destroy(dev);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_DO_CLEAR);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2390,7 +2392,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
     /* set highest flag bit, this should fail unless we support 16 flags */
     set_required_flags(fs, 0x1U << 15);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_NONE);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2405,7 +2407,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
     fs_destroy(fs);
     block_cache_dev_destroy(dev);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_DO_CLEAR);
     assert(ret == 0);
     assert(!fs_is_readable(fs));
@@ -2427,7 +2429,7 @@ static void unknown_required_flags_test(struct transaction* tr) {
 
     set_required_flags(fs, initial_required_flags);
 
-    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev, NULL,
                   FS_INIT_FLAGS_NONE);
     assert(ret == 0);
 
@@ -3457,6 +3459,263 @@ static void fs_alternate_init_test(struct transaction* tr) {
     file_close(&file);
 }
 
+/*
+ * Helper function to read the super block version from the cache.
+ */
+static uint8_t get_super_block_version_from_cache(struct transaction* tr,
+                                                  uint8_t slot) {
+    struct fs* fs = tr->fs;
+    struct obj_ref super_ref = OBJ_REF_INITIAL_VALUE(super_ref);
+    const uint32_t* super_ro;
+    size_t flags_offset_u32 = 24 / 4;
+    data_block_t block;
+    uint8_t super_block_version;
+
+    assert(slot == 0 || slot == 1);
+
+    block = fs->super_block[slot];
+    super_ro = block_get_super(fs, block, &super_ref);
+    assert(super_ro);
+    super_block_version = super_ro[flags_offset_u32] & 0x3;
+    block_put(super_ro, &super_ref);
+
+    return super_block_version;
+}
+
+/*
+ * Helper function to read the super block version from the fake external mac
+ * device.
+ */
+static int get_super_block_version_from_fake_dev(void) {
+    uint8_t flags;
+    struct mac mac;
+
+    fake_super_block_mac_get(NULL, &flags, &mac);
+    return flags & 0x3;
+}
+
+static void fs_external_super_block_mac_test(struct transaction* tr) {
+    struct fs* fs = tr->fs;
+    const struct key* key = fs->key;
+    struct block_device* dev = fs->dev;
+    struct block_device* super_dev = fs->super_dev;
+    struct storage_file_handle file;
+    int ret;
+
+    struct super_block_mac_device fake_super_block_mac_dev = {
+            .get = fake_super_block_mac_get,
+            .set = fake_super_block_mac_set,
+            .delete_mac = fake_super_block_mac_delete,
+    };
+
+    /* Reinit the file system with external mac support */
+    transaction_fail(tr);
+    transaction_free(tr);
+    fs_destroy(fs);
+    block_cache_dev_destroy(dev);
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+                  &fake_super_block_mac_dev, FS_INIT_FLAGS_NONE);
+    assert(!ret);
+    assert(fs->super_block_version == 0);
+    transaction_init(tr, fs, true);
+
+    /* Create a file an make sure the super block version increments */
+    file_test(tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, file_test_block_count,
+              0, 0, false, 1);
+    transaction_complete(tr);
+    assert(!tr->failed);
+    assert(fs->super_block_version == 1);
+    assert(fs->written_super_block_version == 1);
+    assert(get_super_block_version_from_fake_dev() == 1);
+
+    /* Read the super block and verify the version directly */
+    assert(get_super_block_version_from_cache(tr, 1) == 1);
+
+    /* Make sure we can reopen the file */
+    transaction_activate(tr);
+    open_test_file_etc(tr, &file, __func__, FILE_OPEN_NO_CREATE,
+                       FILE_OP_SUCCESS);
+    file_close(&file);
+    transaction_complete(tr);
+    transaction_free(tr);
+    assert(!tr->failed);
+    assert(fs->super_block_version == 1);
+    assert(fs->written_super_block_version == 1);
+    assert(get_super_block_version_from_fake_dev() == 1);
+
+    /* Restart the file system and make sure we can read the file */
+    fs_destroy(fs);
+    block_cache_dev_destroy(dev);
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+                  &fake_super_block_mac_dev, FS_INIT_FLAGS_NONE);
+    assert(!ret);
+    assert(fs->super_block_version == 1);
+
+    transaction_init(tr, fs, true);
+    open_test_file_etc(tr, &file, __func__, FILE_OPEN_NO_CREATE,
+                       FILE_OP_SUCCESS);
+    file_close(&file);
+    transaction_complete(tr);
+    assert(!tr->failed);
+    assert(fs->super_block_version == 1);
+    assert(fs->written_super_block_version == 1);
+    assert(get_super_block_version_from_fake_dev() == 1);
+    transaction_free(tr);
+
+    /* Trigger a "factory reset" via the FS clear flag */
+    fs_destroy(fs);
+    block_cache_dev_destroy(dev);
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+                  &fake_super_block_mac_dev, FS_INIT_FLAGS_DO_CLEAR);
+    assert(!ret);
+    assert(fs->super_block_version == 1);
+    assert(fs->written_super_block_version == 2);
+    assert(get_super_block_version_from_fake_dev() == 1);
+
+    /*
+     * Read the super blocks and verify that the version has incremented
+     * sequentially.
+     */
+    assert(get_super_block_version_from_cache(tr, 0) == 2);
+    assert(get_super_block_version_from_cache(tr, 1) == 1);
+
+    /*
+     * Drive the file system to write the special initial super block
+     * transaction. The super block version increments here.
+     *
+     * TODO: Update this test once the storage application is fixed to
+     * not write this unneeded initial super block transaction.
+     */
+    fs_mark_scan_required(fs);
+    assert(fs->super_block_version == 2);
+    assert(fs->written_super_block_version == 2);
+    assert(get_super_block_version_from_fake_dev() == 2);
+    assert(get_super_block_version_from_cache(tr, 0) == 2);
+    assert(get_super_block_version_from_cache(tr, 1) == 1);
+
+    /*
+     * Do a NOP transaction. Since this triggers a change to the free block set
+     * to configure the file system for use, a new super block is written and
+     * the version will increment.
+     */
+    transaction_init(tr, fs, true);
+    transaction_complete(tr);
+    transaction_free(tr);
+    assert(!tr->failed);
+    assert(fs->super_block_version == 3);
+    assert(fs->written_super_block_version == 3);
+    assert(get_super_block_version_from_fake_dev() == 3);
+    assert(get_super_block_version_from_cache(tr, 0) == 2);
+    assert(get_super_block_version_from_cache(tr, 1) == 3);
+
+    /*
+     * Make sure we can't read the file we created. This is a true NOP
+     * transaction and the super block version will not increment.
+     */
+    transaction_init(tr, fs, true);
+    open_test_file_etc(tr, &file, __func__, FILE_OPEN_NO_CREATE,
+                       FILE_OP_ERR_NOT_FOUND);
+    transaction_complete(tr);
+    transaction_free(tr);
+    assert(!tr->failed);
+    assert(fs->super_block_version == 3);
+    assert(fs->written_super_block_version == 3);
+    assert(get_super_block_version_from_fake_dev() == 3);
+
+    /*
+     * Read the super blocks and verify that the version has incremented
+     * sequentially.
+     */
+    assert(get_super_block_version_from_cache(tr, 0) == 2);
+    assert(get_super_block_version_from_cache(tr, 1) == 3);
+
+    /* Clean up for next test */
+    fake_super_block_mac_test_reset();
+    transaction_init(tr, fs, true);
+}
+
+static void fs_external_super_block_mac_partial_clear_test(
+        struct transaction* tr) {
+    struct fs* fs = tr->fs;
+    const struct key* key = fs->key;
+    struct block_device* dev = fs->dev;
+    struct block_device* super_dev = fs->super_dev;
+    struct storage_file_handle file;
+    int ret;
+
+    struct super_block_mac_device fake_super_block_mac_dev = {
+            .get = fake_super_block_mac_get,
+            .set = fake_super_block_mac_set,
+            .delete_mac = fake_super_block_mac_delete,
+    };
+
+    /* Reinit the file system with external mac support */
+    transaction_fail(tr);
+    transaction_free(tr);
+    fs_destroy(fs);
+    block_cache_dev_destroy(dev);
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+                  &fake_super_block_mac_dev, FS_INIT_FLAGS_NONE);
+    assert(!ret);
+    assert(fs->super_block_version == 0);
+
+    /* Create a file an make sure the super block version increments */
+    transaction_init(tr, fs, true);
+    file_test(tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, file_test_block_count,
+              0, 0, false, 1);
+    transaction_complete(tr);
+    transaction_free(tr);
+    assert(!tr->failed);
+    assert(fs->super_block_version == 1);
+    assert(fs->written_super_block_version == 1);
+    assert(get_super_block_version_from_fake_dev() == 1);
+    assert(get_super_block_version_from_cache(tr, 1) == 1);
+
+    /*
+     * Delete the mac to simulate a failed "factory reset". In other words, we
+     * have invalidated the mac and reset before writing a new super block.
+     */
+    ret = fake_super_block_mac_delete(&fake_super_block_mac_dev);
+    assert(!ret);
+
+    /* Restart the file system */
+    fs_destroy(fs);
+    block_cache_dev_destroy(dev);
+    ret = fs_init(fs, FILE_SYSTEM_TEST, key, dev, super_dev,
+                  &fake_super_block_mac_dev, FS_INIT_FLAGS_NONE);
+    assert(!ret);
+
+    /*
+     * Verify that the super block version is unchanged after a mac delete since
+     * the flags are preserved and we write the new super block on the next
+     * transaction.
+     */
+    assert(fs->super_block_version == 1);
+    assert(fs->written_super_block_version == 1);
+    assert(get_super_block_version_from_fake_dev() == 1);
+    assert(get_super_block_version_from_cache(tr, 1) == 1);
+
+    /* Make sure we can't read the file we created */
+    transaction_init(tr, fs, true);
+    open_test_file_etc(tr, &file, __func__, FILE_OPEN_NO_CREATE,
+                       FILE_OP_ERR_NOT_FOUND);
+    transaction_complete(tr);
+    transaction_free(tr);
+    assert(!tr->failed);
+    /* Verify we wrote the next super block version */
+    assert(fs->super_block_version == 2);
+    assert(fs->written_super_block_version == 2);
+    assert(get_super_block_version_from_fake_dev() == 2);
+
+    /* Verify the new super block versions directly */
+    assert(get_super_block_version_from_cache(tr, 0) == 2);
+    assert(get_super_block_version_from_cache(tr, 1) == 1);
+
+    /* Clean up for next test */
+    fake_super_block_mac_test_reset();
+    transaction_init(tr, fs, true);
+}
+
 #if 0
 static void file_allocate_leave_10_test2(struct transaction *tr)
 {
@@ -3600,6 +3859,8 @@ struct {
         TEST(fs_alternate_empty_test),
         TEST(fs_alternate_recovery_test),
         TEST(fs_alternate_init_test),
+        TEST(fs_external_super_block_mac_test),
+        TEST(fs_external_super_block_mac_partial_clear_test),
 };
 
 int main(int argc, const char* argv[]) {
@@ -3653,7 +3914,8 @@ int main(int argc, const char* argv[]) {
     crypt_init();
     block_cache_init();
 
-    fs_init(&fs, FILE_SYSTEM_TEST, &key, &dev, &dev, FS_INIT_FLAGS_DO_CLEAR);
+    fs_init(&fs, FILE_SYSTEM_TEST, &key, &dev, &dev, NULL,
+            FS_INIT_FLAGS_DO_CLEAR);
     fs.reserved_count = 18; /* HACK: override default reserved space */
     transaction_init(&tr, &fs, false);
 
@@ -3677,7 +3939,7 @@ int main(int argc, const char* argv[]) {
             transaction_free(&tr);
             fs_destroy(&fs);
             block_cache_dev_destroy(&dev);
-            fs_init(&fs, FILE_SYSTEM_TEST, &key, &dev, &dev,
+            fs_init(&fs, FILE_SYSTEM_TEST, &key, &dev, &dev, NULL,
                     FS_INIT_FLAGS_NONE);
             fs.reserved_count = 18; /* HACK: override default reserved space */
             transaction_init(&tr, &fs, false);
diff --git a/test/block_host_test/rules.mk b/test/block_host_test/rules.mk
index cda01d1..65b92e0 100644
--- a/test/block_host_test/rules.mk
+++ b/test/block_host_test/rules.mk
@@ -24,13 +24,15 @@ include $(STORAGE_DIR)/common.mk
 HOST_SRCS := \
 	$(STORAGE_COMMON_SRCS) \
 	$(LOCAL_DIR)/block_test.c \
+	$(LOCAL_DIR)/super_block_mac_storage_fake.c \
 	$(COMMON_DIR)/error_reporting_mock.c \
 
 HOST_FLAGS := -DBUILD_STORAGE_TEST=1
 
 HOST_INCLUDE_DIRS += \
-	$(STORAGE_DIR) \
 	$(COMMON_DIR) \
+	$(STORAGE_DIR) \
+	$(STORAGE_DIR)/lib_internal/include \
 	trusty/kernel/lib/libc-ext/include \
 
 HOST_LIBS := \
diff --git a/test/block_host_test/super_block_mac_storage_fake.c b/test/block_host_test/super_block_mac_storage_fake.c
new file mode 100644
index 0000000..07a20a6
--- /dev/null
+++ b/test/block_host_test/super_block_mac_storage_fake.c
@@ -0,0 +1,82 @@
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
+#include <assert.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <string.h>
+
+#include <storage_internal/super_block_mac_device.h>
+
+#include "block_mac.h"
+#include "crypt.h"
+
+#define SUPER_BLOCK_MAC_IS_SET_FLAG 0x80
+
+/* Local super block mac mock storage */
+static uint8_t super_block_flags = 0;
+static uint8_t super_block_mac[16] = {0};
+
+int fake_super_block_mac_get(struct super_block_mac_device* dev,
+                             uint8_t* flags,
+                             struct mac* mac) {
+    assert(mac);
+    assert(flags);
+
+    *flags = super_block_flags;
+    if (!(super_block_flags & SUPER_BLOCK_MAC_IS_SET_FLAG)) {
+        return SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED;
+    }
+
+    uint8_t* local_mac = (uint8_t*)&super_block_mac;
+    memcpy(&mac->byte, local_mac, sizeof(struct mac));
+    printf("%s: flags(0x%x), " MAC_PRINTF_STR "\n", __func__, *flags,
+           UINT8_16_PRINTF_ARGS(local_mac));
+
+    return 0;
+}
+
+int fake_super_block_mac_set(struct super_block_mac_device* dev,
+                             const uint8_t flags,
+                             const struct mac* mac) {
+    assert(mac);
+
+    /* Assert that we always set super block version n + 1 for debugging */
+    assert((flags & 0x03) == (((super_block_flags & 0x03) + 1) & 0x03));
+
+    super_block_flags = flags | SUPER_BLOCK_MAC_IS_SET_FLAG;
+    uint8_t* local_mac = (uint8_t*)&super_block_mac;
+    memcpy(local_mac, &mac->byte, sizeof(struct mac));
+    printf("%s: flags (0x%x), " MAC_PRINTF_STR "\n", __func__, flags,
+           UINT8_16_PRINTF_ARGS(local_mac));
+
+    return 0;
+}
+
+int fake_super_block_mac_delete(struct super_block_mac_device* dev) {
+    uint8_t old_super_block_flags = super_block_flags;
+    super_block_flags = super_block_flags & ~SUPER_BLOCK_MAC_IS_SET_FLAG;
+    memset(super_block_mac, 0, 16);
+    printf("%s: flags (0x%02x) -> (0x%02x)\n", __func__, old_super_block_flags,
+           super_block_flags);
+
+    return 0;
+}
+
+void fake_super_block_mac_test_reset(void) {
+    super_block_flags = 0;
+    memset(super_block_mac, 0, 16);
+}
diff --git a/test/block_host_test/super_block_mac_storage_fake.h b/test/block_host_test/super_block_mac_storage_fake.h
new file mode 100644
index 0000000..54fa801
--- /dev/null
+++ b/test/block_host_test/super_block_mac_storage_fake.h
@@ -0,0 +1,29 @@
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
+#include <stdint.h>
+
+#include <storage_internal/super_block_mac_device.h>
+
+int fake_super_block_mac_get(struct super_block_mac_device* dev,
+                             uint8_t* flags,
+                             struct mac* mac);
+int fake_super_block_mac_set(struct super_block_mac_device* dev,
+                             const uint8_t flags,
+                             const struct mac* mac);
+int fake_super_block_mac_delete(struct super_block_mac_device* dev);
+
+void fake_super_block_mac_test_reset(void);
\ No newline at end of file
diff --git a/test/storage_host_test/rules.mk b/test/storage_host_test/rules.mk
index 43cb749..948191a 100644
--- a/test/storage_host_test/rules.mk
+++ b/test/storage_host_test/rules.mk
@@ -32,9 +32,10 @@ HOST_SRCS := \
 	$(COMMON_DIR)/error_reporting_mock.c \
 
 HOST_INCLUDE_DIRS += \
+	$(COMMON_DIR) \
 	$(LOCAL_DIR) \
 	$(STORAGE_DIR) \
-	$(COMMON_DIR) \
+	$(STORAGE_DIR)/lib_internal/include \
 	trusty/kernel/lib/libc-ext/include \
 	trusty/user/base/interface/storage/include \
 
@@ -57,6 +58,7 @@ HOST_FLAGS += \
 HOST_FLAGS += -DSTORAGE_NS_RECOVERY_CLEAR_ALLOWED=1
 HOST_FLAGS += -DSTORAGE_TDP_RECOVERY_CHECKPOINT_RESTORE_ALLOWED=1
 HOST_FLAGS += -DHAS_FS_TDP=1
+HOST_FLAGS += -DHAS_RPMB=1
 
 HOST_LIBS := \
 	m \
diff --git a/test/storage_host_test/storage_host_test.c b/test/storage_host_test/storage_host_test.c
index 47a7eed..e64b811 100644
--- a/test/storage_host_test/storage_host_test.c
+++ b/test/storage_host_test/storage_host_test.c
@@ -195,13 +195,15 @@ static void file_test_etc(struct transaction* tr,
                           int id) {
     enum file_op_result delete_res;
     struct storage_file_handle file;
+    bool file_opened = false;
 
     open_test_file_etc(tr, &file, path, create, FILE_OP_SUCCESS,
                        allow_repaired);
-    ASSERT_EQ(false, HasFailure());
+    ASSERT_EQ(false, HasFatalFailure());
     if (tr->failed) {
         goto test_abort;
     }
+    file_opened = true;
 
     file_test_commit(tr, commit);
 
@@ -224,7 +226,9 @@ static void file_test_etc(struct transaction* tr,
     }
 
 test_abort:;
-    file_close(&file);
+    if (file_opened) {
+        file_close(&file);
+    }
 }
 
 static void file_test(struct transaction* tr,
@@ -272,12 +276,51 @@ static void reset_repaired_flag(struct transaction* tr) {
     transaction_initial_super_block_complete(tr->fs->initial_super_block_tr);
 }
 
+static void remount_filesystems_etc(bool ns_rollback, bool checkpoint_ns) {
+    handle_t null_handle = 0;
+    int rc;
+
+    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
+    block_device_tipc_destroy(&test_block_device);
+
+    if (ns_rollback) {
+        roll_back_ns_state();
+    }
+    if (checkpoint_ns) {
+        save_current_ns_state();
+    }
+
+    rc = block_device_tipc_init(&test_block_device, null_handle,
+                                &storage_test_key, NULL, null_handle);
+    ASSERT_EQ(rc, NO_ERROR);
+
+    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
+                                   hset);
+    ASSERT_EQ(rc, NO_ERROR);
+
+test_abort:;
+}
+
+static void remount_filesystems() {
+    return remount_filesystems_etc(/*ns_rollback=*/false,
+                                   /*checkpoint_ns=*/false);
+}
+static void remount_filesystems_with_ns_rollback() {
+    return remount_filesystems_etc(/*ns_rollback=*/true,
+                                   /*checkpoint_ns=*/false);
+}
+static void remount_filesystems_with_checkpoint_ns() {
+    return remount_filesystems_etc(/*ns_rollback=*/false,
+                                   /*checkpoint_ns=*/true);
+}
+
 typedef struct transaction_test {
     struct transaction tr;
     int initial_super_block_version;
 } StorageTest_t;
 
 #define IS_TP() (_state->tr.fs == &test_block_device.tr_state_rpmb)
+#define IS_TD() (_state->tr.fs == &test_block_device.tr_state_ns)
 
 #if HAS_FS_TDP
 #define IS_TDP() (_state->tr.fs == &test_block_device.tr_state_ns_tdp)
@@ -314,6 +357,115 @@ TEST_P(StorageTest, FileCreate) {
 test_abort:;
 }
 
+TEST_P(StorageTest, FileCreateUdcUserdata) {
+    const char* filename = "FileCreateUdcUserdata";
+    struct storage_file_handle file;
+
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+
+    /* Remount to set up a user data checkpoint. Save the state of ns because
+     * we're pretending it's backed by /data and will be rolled back. */
+    transaction_free(&_state->tr);
+    set_is_data_checkpoint_active(true);
+    remount_filesystems_with_checkpoint_ns();
+    ASSERT_EQ(false, HasFatalFailure());
+    transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
+
+    /* Try to create a file during the checkpoint. */
+    open_test_file(&_state->tr, &file, filename, FILE_OPEN_CREATE_EXCLUSIVE);
+    ASSERT_EQ(false, HasFatalFailure());
+    file_close(&file);
+    transaction_complete(&_state->tr);
+    if (IS_TD()) {
+        ASSERT_EQ(true, _state->tr.failed);
+    } else {
+        /* For non-TD filesystems, the write storage doesn't wait for
+         * checkpointing to complete in order to write. */
+        ASSERT_EQ(false, _state->tr.failed);
+    }
+
+    /* Simulate device reboot that rolls back the checkpoint. The ns device is
+     * rolled back because it's backed by /data. */
+    transaction_free(&_state->tr);
+    set_is_data_checkpoint_active(false);
+    remount_filesystems_with_ns_rollback();
+    ASSERT_EQ(false, HasFatalFailure());
+    transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
+
+    /* Superblock was never written and ns writes were rolled back, so the file
+     * doesn't exist to be found. */
+    if (IS_TD()) {
+        open_test_file_etc(&_state->tr, &file, filename, FILE_OPEN_NO_CREATE,
+                           FILE_OP_ERR_NOT_FOUND, false);
+        ASSERT_EQ(false, HasFatalFailure());
+    } else {
+        open_test_file(&_state->tr, &file, filename, FILE_OPEN_NO_CREATE);
+        ASSERT_EQ(false, HasFatalFailure());
+        file_close(&file);
+    }
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+
+test_abort:;
+    set_is_data_checkpoint_active(false);
+}
+
+TEST_P(StorageTest, FileCreateUdcDedicatedPartition) {
+    const char* filename = "FileCreateUdcDedicatedPartition";
+    struct storage_file_handle file;
+
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+
+    /* Remount to set up a user data checkpoint. Don't save the state of ns,
+     * because we're pretending it's backed by a dedicated partition and won't
+     * be rolled back. */
+    transaction_free(&_state->tr);
+    set_is_data_checkpoint_active(true);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
+    transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
+
+    /* Try to create a file during the checkpoint. */
+    open_test_file(&_state->tr, &file, filename, FILE_OPEN_CREATE_EXCLUSIVE);
+    ASSERT_EQ(false, HasFatalFailure());
+    file_close(&file);
+    transaction_complete(&_state->tr);
+    if (IS_TD()) {
+        ASSERT_EQ(true, _state->tr.failed);
+    } else {
+        /* For non-TD fs, the write storage doesn't wait for checkpointing to
+         * complete in order to write. */
+        ASSERT_EQ(false, _state->tr.failed);
+    }
+
+    /* Simulate device reboot that rolls back the checkpoint. The ns device is
+     * not rolled back because it's backed by /data. */
+    transaction_free(&_state->tr);
+    set_is_data_checkpoint_active(false);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
+    transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
+
+    /* Superblock was never written, so the file is not found even though its
+     * data is on the ns device. */
+    if (IS_TD()) {
+        open_test_file_etc(&_state->tr, &file, filename, FILE_OPEN_NO_CREATE,
+                           FILE_OP_ERR_NOT_FOUND, false);
+        ASSERT_EQ(false, HasFatalFailure());
+    } else {
+        open_test_file(&_state->tr, &file, filename, FILE_OPEN_NO_CREATE);
+        ASSERT_EQ(false, HasFatalFailure());
+        file_close(&file);
+    }
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+
+test_abort:;
+    set_is_data_checkpoint_active(false);
+}
+
 TEST_P(StorageTest, FailDataWrite) {
     fail_next_rpmb_writes(1, false);
     file_test(&_state->tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, 1, 0, 0, false,
@@ -380,6 +532,44 @@ TEST_P(StorageTest, FailDataWriteFullCache) {
 test_abort:;
 }
 
+TEST_P(StorageTest, FailDataWriteFullCacheUdc) {
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+
+    /* Remount to set up a user data checkpoint. */
+    transaction_free(&_state->tr);
+    set_is_data_checkpoint_active(true);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
+    transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
+
+    /* Overflow the cache. */
+    file_test(&_state->tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE,
+              BLOCK_CACHE_SIZE + 1, 0, 0, false, 0);
+    /* Dirty blocks flushed successfully. */
+    ASSERT_EQ(false, _state->tr.failed);
+    /* Can't write superblock for TD during UDC. */
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(IS_TD(), _state->tr.failed);
+
+    /* Clear the checkpoint and simulate device reboot. */
+    transaction_free(&_state->tr);
+    set_is_data_checkpoint_active(false);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
+    transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
+
+    /* File doesn't exist on TD. */
+    enum file_create_mode mode =
+            IS_TD() ? FILE_OPEN_CREATE_EXCLUSIVE : FILE_OPEN_NO_CREATE;
+    file_test(&_state->tr, __func__, mode, BLOCK_CACHE_SIZE + 1, 0, 0, true, 0);
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+
+test_abort:;
+    set_is_data_checkpoint_active(false);
+}
+
 TEST_P(StorageTest, FailDataWriteWithCounterIncrement) {
     fail_next_rpmb_writes(1, true);
     file_test(&_state->tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, 1, 0, 0, false,
@@ -454,9 +644,6 @@ test_abort:;
  * device just because this happens.
  */
 TEST_P(StorageTest, FailRpmbVerify) {
-    handle_t null_handle = 0;
-    int rc;
-
     file_test(&_state->tr, "FailRpmbVerifyValidFile",
               FILE_OPEN_CREATE_EXCLUSIVE, 1, 0, 0, false, 0);
     transaction_complete(&_state->tr);
@@ -505,14 +692,8 @@ TEST_P(StorageTest, FailRpmbVerify) {
      * verify_failed flag from the rpmb state.
      */
     transaction_free(&_state->tr);
-    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
-    block_device_tipc_destroy(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, null_handle,
-                                &storage_test_key, NULL, null_handle);
-    ASSERT_EQ(rc, 0);
-    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
-                                   hset);
-    ASSERT_EQ(rc, 0);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
     transaction_init(&_state->tr, *((struct fs**)GetParam()), true);
 
     /* Everything should work now */
@@ -524,6 +705,61 @@ TEST_P(StorageTest, FailRpmbVerify) {
 test_abort:;
 }
 
+TEST_P(StorageTest, FailedSpecialTransactionWithCommitWrites) {
+    /* Create a transaction with some changes. Make RPMB writes fail. */
+    fail_next_rpmb_writes(1, true);
+    file_test(&_state->tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, 1, 0, 0, false,
+              0);
+
+    /* Try to commit the transaction while RPMB writes are failing.
+     * The failed RPMB write leaves the RPMB in unknown state (b/c the rpmb
+     * device has commit_failed_writes set), so an initial_super_block_tr is
+     * created for this filesystem. */
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(true, _state->tr.failed);
+    ASSERT_NE(NULL, _state->tr.fs->initial_super_block_tr);
+    ASSERT_EQ(false, _state->tr.fs->initial_super_block_tr->failed);
+    ASSERT_NE(_state->tr.fs->super_block_version,
+              _state->tr.fs->written_super_block_version);
+    expect_errors(TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH_RECOVERED, 1);
+
+    /* Reactivate transaction. RPMB writes are still broken. */
+    transaction_activate(&_state->tr);
+    fail_next_rpmb_writes(1, true);
+    file_test(&_state->tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, 1, 0, 0, false,
+              0);
+
+    /* initial_super_block_tr exists, so it has to be committed before the
+     * current transaction. That commit fails because its RPMB write fails,
+     * leaving the filesystem in unknown state (again b/c the rpmb device has
+     * commit_failed_writes set). */
+    block_cache_clean_transaction(&_state->tr);
+    ASSERT_EQ(true, _state->tr.failed);
+    ASSERT_NE(NULL, _state->tr.fs->initial_super_block_tr);
+    /* initial_super_block_tr failed, but
+     * transaction_initial_super_block_complete reinitializes it. */
+    EXPECT_EQ(false, _state->tr.fs->initial_super_block_tr->failed);
+
+    /* Reactivate transaction again. RPMB writes work now. */
+    transaction_activate(&_state->tr);
+    file_test(&_state->tr, __func__, FILE_OPEN_CREATE_EXCLUSIVE, 1, 0, 0, false,
+              0);
+
+    /* initial_super_block_tr exists, so it has to be committed before the
+     * current transaction. Both transactions succeed. */
+    block_cache_clean_transaction(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+    EXPECT_EQ(NULL, _state->tr.fs->initial_super_block_tr);
+    transaction_complete(&_state->tr);
+    ASSERT_EQ(false, _state->tr.failed);
+    ASSERT_EQ(NULL, _state->tr.fs->initial_super_block_tr);
+
+test_abort:;
+    if (!_state->tr.failed) {
+        transaction_fail(&_state->tr);
+    }
+}
+
 TEST(StorageTest, FlushFailingSpecialTransaction) {
     struct transaction td_tr;
     struct transaction tp_tr;
@@ -607,8 +843,6 @@ test_abort:;
 /* Storage tests for filesystems with non-RPMB backing file */
 
 TEST_P(StorageTest, DesyncBackingFile) {
-    int rc;
-    handle_t null_handle = 0;
     struct storage_file_handle file;
     bool allow_repaired = false;
     struct fs* fs = _state->tr.fs;
@@ -650,14 +884,8 @@ TEST_P(StorageTest, DesyncBackingFile) {
     ignore_next_ns_writes(0);
     transaction_free(&_state->tr);
 
-    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
-    block_device_tipc_destroy(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, null_handle,
-                                &storage_test_key, NULL, null_handle);
-    ASSERT_EQ(rc, 0);
-    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
-                                   hset);
-    ASSERT_EQ(rc, 0);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
     transaction_init(&_state->tr, fs, true);
     _state->initial_super_block_version = _state->tr.fs->super_block_version;
 
@@ -693,8 +921,6 @@ test_abort:;
 }
 
 TEST_P(StorageTest, CorruptFileInfo) {
-    int rc;
-    handle_t null_handle = 0;
     struct storage_file_handle file;
     bool allow_repaired = false;
     struct fs* fs = _state->tr.fs;
@@ -747,14 +973,8 @@ TEST_P(StorageTest, CorruptFileInfo) {
     transaction_free(&_state->tr);
 
     /* remount the filesystem to clear the block cache */
-    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
-    block_device_tipc_destroy(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, null_handle,
-                                &storage_test_key, NULL, null_handle);
-    ASSERT_EQ(rc, 0);
-    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
-                                   hset);
-    ASSERT_EQ(rc, 0);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
     transaction_init(&_state->tr, fs, true);
     _state->initial_super_block_version = _state->tr.fs->super_block_version;
 
@@ -764,14 +984,8 @@ TEST_P(StorageTest, CorruptFileInfo) {
     ASSERT_EQ(true, fs->needs_full_scan);
     transaction_free(&_state->tr);
 
-    storage_tipc_service_destroy(&test_tipc_service, &test_block_device);
-    block_device_tipc_destroy(&test_block_device);
-    rc = block_device_tipc_init(&test_block_device, null_handle,
-                                &storage_test_key, NULL, null_handle);
-    ASSERT_EQ(rc, 0);
-    rc = storage_tipc_service_init(&test_tipc_service, &test_block_device,
-                                   hset);
-    ASSERT_EQ(rc, 0);
+    remount_filesystems();
+    ASSERT_EQ(false, HasFatalFailure());
     transaction_init(&_state->tr, fs, true);
     _state->initial_super_block_version = _state->tr.fs->super_block_version;
 
@@ -793,11 +1007,13 @@ TEST_P(StorageTest, CorruptFileInfo) {
         file_test_etc(&_state->tr, false, allow_repaired, "checkpoint_only",
                       FILE_OPEN_NO_CREATE, NULL, FILE_OPEN_NO_CREATE, 0, 1, 0,
                       true, 1);
+        ASSERT_EQ(false, HasFatalFailure());
     }
 
     file_test_etc(&_state->tr, false, allow_repaired, __func__,
                   FILE_OPEN_CREATE_EXCLUSIVE, NULL, FILE_OPEN_NO_CREATE, 1, 0,
                   0, false, 0);
+    ASSERT_EQ(false, HasFatalFailure());
     transaction_complete(&_state->tr);
     ASSERT_EQ(false, _state->tr.failed);
 
diff --git a/test/storage_host_test/storageproxy_shim.c b/test/storage_host_test/storageproxy_shim.c
index 53e677a..9d11955 100644
--- a/test/storage_host_test/storageproxy_shim.c
+++ b/test/storage_host_test/storageproxy_shim.c
@@ -47,6 +47,7 @@ static char data_directory[PATH_MAX];
 static struct rpmb_dev_state rpmb_state = {
         .data_fd = -1,
 };
+static bool data_checkpoint_active = false;
 
 /* If >0 silently ignore writes to NS backing data files. */
 static int ignore_next_ns_write_count = 0;
@@ -54,6 +55,26 @@ void ignore_next_ns_writes(int count) {
     ignore_next_ns_write_count = count;
 }
 
+static int construct_ns_paths(char** ns_path, char** ns_backup_path) {
+    int rc;
+
+    rc = asprintf(ns_path, "%s/0", data_directory);
+    if (rc < 0) {
+        goto err_ns_path;
+    }
+
+    rc = asprintf(ns_backup_path, "%s/backup-0", data_directory);
+    if (rc < 0) {
+        goto err_ns_backup_path;
+    }
+    return NO_ERROR;
+
+err_ns_backup_path:
+    free(*ns_path);
+err_ns_path:
+    return rc;
+}
+
 bool init_rpmb_state(const char* base_directory) {
     int rc;
     bool res = false;
@@ -70,12 +91,14 @@ bool init_rpmb_state(const char* base_directory) {
         }
     }
 
-    /* Remove the non-secure data file */
     char* ns_path;
-    rc = asprintf(&ns_path, "%s/0", data_directory);
+    char* ns_backup_path;
+    rc = construct_ns_paths(&ns_path, &ns_backup_path);
     if (rc < 0) {
-        goto err_rm_ns_file;
+        goto err_construct_ns_paths;
     }
+
+    /* Remove the non-secure data file */
     rc = remove(ns_path);
     if (rc < 0) {
         if (errno != ENOENT) {
@@ -83,6 +106,14 @@ bool init_rpmb_state(const char* base_directory) {
         }
     }
 
+    /* Remove the backup non-secure data file */
+    rc = remove(ns_backup_path);
+    if (rc < 0) {
+        if (errno != ENOENT) {
+            goto err_rm_ns_backup_file;
+        }
+    }
+
 #if HAS_FS_TDP
     char* tdp_directory =
             malloc(strlen(data_directory) + sizeof(PERSIST_DIRECTORY) + 2);
@@ -158,8 +189,11 @@ err_tdp_dirname:
     free(tdp_directory);
 err_alloc_tdp:
 #endif
+err_rm_ns_backup_file:
 err_rm_ns_file:
+    free(ns_backup_path);
     free(ns_path);
+err_construct_ns_paths:
 err_mkdir:
     return res;
 }
@@ -192,7 +226,11 @@ int rpmb_send(void* mmc_handle,
               void* read_buf,
               size_t read_buf_size,
               bool sync,
-              bool sync_checkpoint) {
+              bool ensure_no_checkpoint) {
+    if (ensure_no_checkpoint && data_checkpoint_active) {
+        return ERR_GENERIC;
+    }
+
     rpmb_state.res_count = read_buf_size / sizeof(struct rpmb_packet);
     assert(rpmb_state.res_count <= MAX_PACKET_COUNT);
     rpmb_state.cmd_count =
@@ -338,13 +376,18 @@ int ns_write_pos(handle_t ipc_handle,
                  const void* data,
                  int data_size,
                  bool sync,
-                 bool sync_checkpoint) {
+                 bool ensure_no_checkpoint) {
     if (ignore_next_ns_write_count > 0) {
         if (ignore_next_ns_write_count != INT_MAX) {
             ignore_next_ns_write_count--;
         }
         return data_size;
     }
+
+    if (ensure_no_checkpoint && data_checkpoint_active) {
+        return ERR_GENERIC;
+    }
+
     if (write_with_retry(handle, data, data_size, pos)) {
         fprintf(stderr, "shim %s: write failed: %s\n", __func__,
                 strerror(errno));
@@ -352,3 +395,118 @@ int ns_write_pos(handle_t ipc_handle,
     }
     return data_size;
 }
+
+static int copy(int src, int dst) {
+    uint8_t buf[256];
+    ssize_t buf_read;
+    ssize_t buf_written;
+    ssize_t rc;
+
+    do {
+        rc = read(src, &buf, sizeof(buf));
+        if (rc < 0) {
+            fprintf(stderr, "shim %s: read from fd %d failed: %s\n", __func__,
+                    src, strerror(errno));
+            return ERR_GENERIC;
+        }
+        buf_read = rc;
+        buf_written = 0;
+
+        do {
+            rc = write(dst, &buf + buf_written, buf_read - buf_written);
+            if (rc < 0) {
+                fprintf(stderr, "shim %s: write to fd %d failed: %s\n",
+                        __func__, dst, strerror(errno));
+                return ERR_GENERIC;
+            }
+            buf_written += rc;
+        } while (buf_read > buf_written);
+    } while (buf_read > 0);
+
+    return NO_ERROR;
+}
+
+static int copy_path(char* src, char* dst) {
+    int fd_src;
+    int fd_dst;
+    int rc;
+
+    rc = open(src, O_RDONLY);
+    if (rc < 0) {
+        fprintf(stderr, "shim %s: open of file %s failed: %s\n", __func__, src,
+                strerror(errno));
+        goto err_open_src;
+    }
+    fd_src = rc;
+
+    rc = open(dst, O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, S_IWUSR | S_IRUSR);
+    if (rc < 0) {
+        fprintf(stderr, "shim %s: open of file %s failed: %s\n", __func__, dst,
+                strerror(errno));
+        goto err_open_dst;
+    }
+    fd_dst = rc;
+
+    rc = copy(fd_src, fd_dst);
+    if (rc < 0) {
+        goto err_copy;
+    }
+
+err_copy:
+    close(fd_dst);
+err_open_dst:
+    close(fd_src);
+err_open_src:
+    return rc;
+}
+
+int move(const char* src, const char* dst) {
+    int rc;
+
+    rc = rename(src, dst);
+    if (rc < 0) {
+        fprintf(stderr,
+                "shim %s: rename file failed: %s\n\tsrc: %s\n\tdst: %s\n",
+                __func__, strerror(errno), src, dst);
+        goto err_rename;
+    }
+
+    return NO_ERROR;
+
+err_rename:
+    return rc;
+}
+
+void save_current_ns_state() {
+    int rc;
+    char* ns_path;
+    char* ns_backup_path;
+
+    rc = construct_ns_paths(&ns_path, &ns_backup_path);
+    assert(rc == NO_ERROR);
+
+    rc = copy_path(ns_path, ns_backup_path);
+    assert(rc == NO_ERROR);
+
+    free(ns_path);
+    free(ns_backup_path);
+}
+
+void roll_back_ns_state() {
+    int rc;
+    char* ns_path;
+    char* ns_backup_path;
+
+    rc = construct_ns_paths(&ns_path, &ns_backup_path);
+    assert(rc == NO_ERROR);
+
+    rc = move(ns_backup_path, ns_path);
+    assert(rc == NO_ERROR);
+
+    free(ns_path);
+    free(ns_backup_path);
+}
+
+void set_is_data_checkpoint_active(bool is_data_checkpoint_active) {
+    data_checkpoint_active = is_data_checkpoint_active;
+}
diff --git a/test/storage_host_test/storageproxy_shim.h b/test/storage_host_test/storageproxy_shim.h
index 5e9cdfd..ad21f48 100644
--- a/test/storage_host_test/storageproxy_shim.h
+++ b/test/storage_host_test/storageproxy_shim.h
@@ -58,3 +58,36 @@ void fail_next_rpmb_get_counters(int count);
  * Used for testing failure conditions
  */
 void ignore_next_ns_writes(int count);
+
+/**
+ * save_current_ns_state - Save the current the NS backing files so that they
+ *                         can be rolled back later.
+ *
+ * Only one state can be saved at a time. Attempting to save a state while one
+ * already exists will trigger an assert failure. Rolling back (with
+ * roll_back_ns_state()) will destroy the saved state.
+ *
+ * Must not be called while the struct block_device_tipc is initialized.
+ */
+void save_current_ns_state();
+
+/**
+ * roll_back_ns_state - Roll back to a state of the NS backing files previously
+ *                      saved with save_current_ns_state().
+ *
+ * This will consume the saved state. Rolling back with no existing saved state
+ * will trigger an assert failure.
+ *
+ * Must not be called while the struct block_device_tipc is initialized.
+ */
+void roll_back_ns_state();
+
+/**
+ * set_is_data_checkpoint_active - Set whether the fake storage proxy will
+ * consider data checkpointing to be active, and therefore whether it will
+ * disallow writes made with STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT.
+ *
+ * @is_data_checkpoint_active: The value to set. `true` means to disallow writes
+ *                             made with STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT.
+ */
+void set_is_data_checkpoint_active(bool is_data_checkpoint_active);
diff --git a/tipc_ns.c b/tipc_ns.c
index 6207e4c..5266f5c 100644
--- a/tipc_ns.c
+++ b/tipc_ns.c
@@ -72,7 +72,7 @@ int rpmb_send(void* handle_,
               void* read_buf,
               size_t read_size,
               bool sync,
-              bool sync_checkpoint) {
+              bool ensure_no_checkpoint) {
     SS_DBG_IO(
             "%s: handle %p, rel_write size %zu, write size %zu, read size %zu\n",
             __func__, handle_, reliable_write_size, write_size, read_size);
@@ -96,7 +96,7 @@ int rpmb_send(void* handle_,
                     write_size,
     };
 
-    if (sync_checkpoint) {
+    if (ensure_no_checkpoint) {
         msg.flags |= STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT;
     }
 
@@ -326,12 +326,12 @@ int ns_write_pos(handle_t ipc_handle,
                  const void* data,
                  int data_size,
                  bool sync,
-                 bool sync_checkpoint) {
+                 bool ensure_no_checkpoint) {
     uint32_t flags = 0;
     SS_DBG_IO("%s: handle %llu, pos %llu, size %d\n", __func__, handle, pos,
               data_size);
 
-    if (sync_checkpoint) {
+    if (ensure_no_checkpoint) {
         flags |= STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT;
     }
 
diff --git a/tipc_ns.h b/tipc_ns.h
index 2c9de49..07a0458 100644
--- a/tipc_ns.h
+++ b/tipc_ns.h
@@ -42,4 +42,4 @@ int ns_write_pos(handle_t ipc_handle,
                  const void* data,
                  int data_size,
                  bool sync,
-                 bool sync_checkpoint);
+                 bool ensure_no_checkpoint);
diff --git a/transaction.c b/transaction.c
index 913a163..2c2a871 100644
--- a/transaction.c
+++ b/transaction.c
@@ -321,6 +321,26 @@ static void check_free_tree(struct transaction* tr, struct block_set* free) {
     }
 }
 
+/**
+ * write_super_block_mac - Write the current super block mac to external
+ *                         storage.
+ * @tr:         Transaction object.
+ */
+static void write_super_block_mac(struct transaction* tr) {
+    if (tr->fs->super_block_mac_dev->set(
+                tr->fs->super_block_mac_dev,
+                tr->fs->written_super_block_version,
+                block_mac_to_mac(tr, &tr->fs->written_super_block_mac))) {
+        /*
+         * We failed to send the mac to external storage so we need to mark
+         * the superblock transaction as failed.
+         */
+        if (!tr->failed) {
+            transaction_fail(tr);
+        }
+    }
+}
+
 /**
  * transaction_complete - Complete transaction, optionally updating checkpoint
  * @tr:                Transaction object.
@@ -482,6 +502,10 @@ void transaction_complete_etc(struct transaction* tr, bool update_checkpoint) {
     }
     block_cache_clean_transaction(tr);
 
+    if (tr->fs->super_block_mac_dev && !tr->failed) {
+        write_super_block_mac(tr);
+    }
+
     /*
      * If an error was detected writing the super block, it is not safe to
      * continue as we do not know if the write completed. We need to rewrite a
@@ -518,8 +542,12 @@ void transaction_complete_etc(struct transaction* tr, bool update_checkpoint) {
         tr->fs->main_repaired = true;
     }
     if (update_checkpoint) {
+        assert(block_range_empty(tr->fs->checkpoint_free.initial_range));
         tr->fs->checkpoint_free.block_tree.root = new_free_set.block_tree.root;
-        block_range_clear(&tr->fs->checkpoint_free.initial_range);
+
+        if (!list_in_list(&tr->fs->checkpoint_free.node)) {
+            list_add_tail(&tr->fs->free_sets, &tr->fs->checkpoint_free.node);
+        }
     }
 
 complete_nop_transaction:
@@ -595,6 +623,10 @@ err_transaction_failed:
 void transaction_initial_super_block_complete(struct transaction* tr) {
     assert(tr == tr->fs->initial_super_block_tr);
     block_cache_clean_transaction(tr);
+    if (tr->fs->super_block_mac_dev && !tr->failed) {
+        write_super_block_mac(tr);
+    }
+
     if (tr->failed) {
         /*
          * If we failed to write the superblock we re-initialize a new attempt
```

