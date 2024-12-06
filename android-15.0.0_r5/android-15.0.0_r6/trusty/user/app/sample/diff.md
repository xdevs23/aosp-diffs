```diff
diff --git a/build-config-boottests b/build-config-boottests
index 5787770..13406ae 100644
--- a/build-config-boottests
+++ b/build-config-boottests
@@ -16,5 +16,6 @@
 
 [
     porttest("com.android.trusty.rust.hwcryptohalserver.test"),
+    porttest("com.android.trusty.rust.hwcryptohal_common.test"),
     porttest("com.android.trusty.rust.hwcryptokey_test.test"),
 ]
diff --git a/hwcrypto/hwkey_srv.c b/hwcrypto/hwkey_srv.c
index 12b6b32..8d1130e 100644
--- a/hwcrypto/hwkey_srv.c
+++ b/hwcrypto/hwkey_srv.c
@@ -65,13 +65,6 @@ struct opaque_handle_node {
  */
 static struct list_node opaque_handles = LIST_INITIAL_VALUE(opaque_handles);
 
-static void hwkey_port_handler(const uevent_t* ev, void* priv);
-static void hwkey_chan_handler(const uevent_t* ev, void* priv);
-
-static struct tipc_event_handler hwkey_port_evt_handler = {
-        .proc = hwkey_port_handler,
-};
-
 static uint8_t req_data[HWKEY_MAX_MSG_SIZE + 1];
 static __attribute__((aligned(4))) uint8_t key_data[HWKEY_MAX_MSG_SIZE];
 
@@ -507,11 +500,15 @@ send_response:
 /*
  *  Read and queue HWKEY request message
  */
-static int hwkey_chan_handle_msg(struct hwkey_chan_ctx* ctx) {
+int hwkey_chan_handle_msg(const struct tipc_port* port,
+                          handle_t chan,
+                          void* received_ctx) {
     int rc;
     size_t req_data_len;
     struct hwkey_msg_header* hdr;
 
+    struct hwkey_chan_ctx* ctx = (struct hwkey_chan_ctx*)received_ctx;
+
     rc = tipc_recv1(ctx->chan, sizeof(*hdr), req_data, sizeof(req_data) - 1);
     if (rc < 0) {
         TLOGE("failed (%d) to recv msg from chan %d\n", rc, ctx->chan);
@@ -578,79 +575,6 @@ static int hwkey_chan_handle_msg(struct hwkey_chan_ctx* ctx) {
     return rc;
 }
 
-/*
- *  HWKEY service channel event handler
- */
-static void hwkey_chan_handler(const uevent_t* ev, void* priv) {
-    struct hwkey_chan_ctx* ctx = priv;
-
-    assert(ctx);
-    assert(ev->handle == ctx->chan);
-
-    tipc_handle_chan_errors(ev);
-
-    if (ev->event & IPC_HANDLE_POLL_HUP) {
-        /* closed by peer. */
-        hwkey_ctx_close(ctx);
-        return;
-    }
-
-    if (ev->event & IPC_HANDLE_POLL_MSG) {
-        int rc = hwkey_chan_handle_msg(ctx);
-        if (rc < 0) {
-            /* report an error and close channel */
-            TLOGE("failed (%d) to handle event on channel %d\n", rc,
-                  ev->handle);
-            hwkey_ctx_close(ctx);
-        }
-    }
-}
-
-/*
- * HWKEY service port event handler
- */
-static void hwkey_port_handler(const uevent_t* ev, void* priv) {
-    uuid_t peer_uuid;
-
-    tipc_handle_port_errors(ev);
-
-    if (ev->event & IPC_HANDLE_POLL_READY) {
-        /* incoming connection: accept it */
-        int rc = accept(ev->handle, &peer_uuid);
-        if (rc < 0) {
-            TLOGE("failed (%d) to accept on port %d\n", rc, ev->handle);
-            return;
-        }
-
-        handle_t chan = (handle_t)rc;
-        if (!hwkey_client_allowed(&peer_uuid)) {
-            TLOGE("access to hwkey service denied\n");
-            close(chan);
-            return;
-        }
-
-        struct hwkey_chan_ctx* ctx = calloc(1, sizeof(*ctx));
-        if (!ctx) {
-            TLOGE("failed (%d) to allocate context on chan %d\n", rc, chan);
-            close(chan);
-            return;
-        }
-
-        /* init channel state */
-        ctx->evt_handler.priv = ctx;
-        ctx->evt_handler.proc = hwkey_chan_handler;
-        ctx->chan = chan;
-        ctx->uuid = peer_uuid;
-
-        rc = set_cookie(chan, &ctx->evt_handler);
-        if (rc < 0) {
-            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan);
-            hwkey_ctx_close(ctx);
-            return;
-        }
-    }
-}
-
 /*
  *  Install Key slot provider
  */
@@ -703,7 +627,7 @@ uint32_t get_key_handle(const struct hwkey_keyslot* slot,
      */
     uint8_t random_buf[HWKEY_OPAQUE_HANDLE_SIZE + 2];
     while (1) {
-        int rc = hwrng_dev_get_rng_data(random_buf, sizeof(random_buf));
+        int rc = trusty_rng_hw_rand(random_buf, sizeof(random_buf));
         if (rc != NO_ERROR) {
             /* Don't leave an empty entry if we couldn't generate a token */
             delete_opaque_handle(entry);
@@ -766,29 +690,36 @@ uint32_t get_opaque_key(const uuid_t* uuid,
 }
 
 /*
- *  Initialize HWKEY service
+ * Create hwkey channel context
  */
-int hwkey_start_service(void) {
-    int rc;
-    handle_t port;
+int hwkey_chan_ctx_create(const struct tipc_port* port,
+                          handle_t chan,
+                          const struct uuid* peer,
+                          void** ctx) {
+    struct hwkey_chan_ctx* chan_ctx = calloc(1, sizeof(*chan_ctx));
 
-    TLOGD("Start HWKEY service\n");
-
-    /* Initialize service */
-    rc = port_create(HWKEY_PORT, 1, HWKEY_MAX_MSG_SIZE,
-                     IPC_PORT_ALLOW_TA_CONNECT);
-    if (rc < 0) {
-        TLOGE("Failed (%d) to create port %s\n", rc, HWKEY_PORT);
-        return rc;
+    if (!chan_ctx) {
+        return ERR_NO_MEMORY;
     }
 
-    port = (handle_t)rc;
-    rc = set_cookie(port, &hwkey_port_evt_handler);
-    if (rc) {
-        TLOGE("failed (%d) to set_cookie on port %d\n", rc, port);
-        close(port);
-        return rc;
-    }
+    chan_ctx->uuid = *peer;
+    chan_ctx->chan = chan;
+    *ctx = chan_ctx;
 
     return NO_ERROR;
 }
+
+/*
+ * Close specified hwkey channel context
+ */
+void hwkey_chan_ctx_close(void* ctx) {
+    struct opaque_handle_node* entry;
+    struct opaque_handle_node* temp;
+    list_for_every_entry_safe(&opaque_handles, entry, temp,
+                              struct opaque_handle_node, node) {
+        if (entry->owner == ctx) {
+            delete_opaque_handle(entry);
+        }
+    }
+    free(ctx);
+}
diff --git a/hwcrypto/hwkey_srv_fake_provider.c b/hwcrypto/hwkey_srv_fake_provider.c
index af34468..532d344 100644
--- a/hwcrypto/hwkey_srv_fake_provider.c
+++ b/hwcrypto/hwkey_srv_fake_provider.c
@@ -35,6 +35,7 @@
 #include <interface/hwkey/hwkey.h>
 #include <lib/system_state/system_state.h>
 #include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
 #include <trusty_log.h>
 
 #include <hwcrypto_consts.h>
@@ -42,6 +43,9 @@
 
 #pragma message "Compiling FAKE HWKEY provider"
 
+/* 0 means unlimited number of connections */
+#define HWKEY_MAX_NUM_CHANNELS 0
+
 /*
  *  This module is a sample only. For real device, this code
  *  needs to be rewritten to operate on real per device key that
@@ -853,16 +857,6 @@ static const uuid_t* allowed_clients[] = {
         &hwbcc_unittest_uuid,
 };
 
-bool hwkey_client_allowed(const uuid_t* uuid) {
-    assert(uuid);
-    for (unsigned int i = 0; i < countof(allowed_clients); i++) {
-        if (memcmp(allowed_clients[i], uuid, sizeof(uuid_t)) == 0) {
-            return true;
-        }
-    }
-    return false;
-}
-
 /*
  *  List of keys slots that hwkey service supports
  */
@@ -1023,10 +1017,38 @@ static bool hwkey_self_test(void) {
     return true;
 }
 
+/*
+ *  Initialize HWKEY service
+ */
+static int hwkey_start_service(struct tipc_hset* hset) {
+    TLOGD("Start HWKEY service\n");
+
+    static struct tipc_port_acl acl = {
+            .flags = IPC_PORT_ALLOW_TA_CONNECT,
+            .uuid_num = countof(allowed_clients),
+            .uuids = allowed_clients,
+    };
+
+    static struct tipc_port port = {
+            .name = HWKEY_PORT,
+            .msg_max_size = HWKEY_MAX_MSG_SIZE,
+            .msg_queue_len = 1,
+            .acl = &acl,
+    };
+
+    static struct tipc_srv_ops ops = {
+            .on_message = hwkey_chan_handle_msg,
+            .on_connect = hwkey_chan_ctx_create,
+            .on_channel_cleanup = hwkey_chan_ctx_close,
+    };
+
+    return tipc_add_service(hset, &port, 1, HWKEY_MAX_NUM_CHANNELS, &ops);
+}
+
 /*
  *  Initialize Fake HWKEY service provider
  */
-void hwkey_init_srv_provider(void) {
+int hwkey_init_srv_provider(struct tipc_hset* hset) {
     int rc;
 
     TLOGE("Init FAKE!!!! HWKEY service provider\n");
@@ -1042,8 +1064,10 @@ void hwkey_init_srv_provider(void) {
     hwkey_install_keys(_keys, countof(_keys));
 
     /* start service */
-    rc = hwkey_start_service();
+    rc = hwkey_start_service(hset);
     if (rc != NO_ERROR) {
         TLOGE("failed (%d) to start HWKEY service\n", rc);
     }
+
+    return rc;
 }
diff --git a/hwcrypto/hwkey_srv_priv.h b/hwcrypto/hwkey_srv_priv.h
index 8ffe97c..84209f1 100644
--- a/hwcrypto/hwkey_srv_priv.h
+++ b/hwcrypto/hwkey_srv_priv.h
@@ -16,6 +16,8 @@
 #pragma once
 
 #include <interface/hwkey/hwkey.h>
+#include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
 #include <lk/compiler.h>
 #include <stdbool.h>
 #include <sys/types.h>
@@ -136,13 +138,20 @@ uint32_t get_opaque_key(const uuid_t* uuid,
                         size_t kbuf_len,
                         size_t* klen);
 
-void hwkey_init_srv_provider(void);
+int hwkey_init_srv_provider(struct tipc_hset* hset);
 
 void hwkey_install_keys(const struct hwkey_keyslot* keys, unsigned int kcnt);
 
-int hwkey_start_service(void);
+int hwkey_chan_handle_msg(const struct tipc_port* _port,
+                          handle_t _chan,
+                          void* _received_ctx);
 
-bool hwkey_client_allowed(const uuid_t* uuid);
+int hwkey_chan_ctx_create(const struct tipc_port* port,
+                          handle_t chan,
+                          const struct uuid* peer,
+                          void** ctx);
+
+void hwkey_chan_ctx_close(void* ctx);
 
 uint32_t derive_key_v1(const uuid_t* uuid,
                        const uint8_t* ikm_data,
diff --git a/hwcrypto/hwrng_srv.c b/hwcrypto/hwrng_srv.c
index ae76945..1757839 100644
--- a/hwcrypto/hwrng_srv.c
+++ b/hwcrypto/hwrng_srv.c
@@ -27,28 +27,24 @@
 #include <hwcrypto/hwrng_dev.h>
 #include <interface/hwrng/hwrng.h>
 #include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
 #include <trusty_log.h>
 
 #define HWRNG_SRV_NAME HWRNG_PORT
 #define MAX_HWRNG_MSG_SIZE 4096
 
+/* 0 means unlimited number of connections */
+#define HWRNG_MAX_NUM_CHANNELS 0
+
 struct hwrng_chan_ctx {
     struct tipc_event_handler evt_handler;
     struct list_node node;
     handle_t chan;
     size_t req_size;
+    int error;
     bool send_blocked;
 };
 
-static void hwrng_port_handler(const uevent_t* ev, void* priv);
-static void hwrng_chan_handler(const uevent_t* ev, void* priv);
-
-static handle_t hwrng_port = INVALID_IPC_HANDLE;
-
-static struct tipc_event_handler hwrng_port_evt_handler = {
-        .proc = hwrng_port_handler,
-};
-
 static uint8_t rng_data[MAX_HWRNG_MSG_SIZE];
 
 static struct list_node hwrng_req_list = LIST_INITIAL_VALUE(hwrng_req_list);
@@ -73,95 +69,85 @@ static void _hexdump8(const void* ptr, size_t len) {
     }
 }
 
-/*
- * Close specified HWRNG service channel
- */
-static void hwrng_close_chan(struct hwrng_chan_ctx* ctx) {
-    close(ctx->chan);
-
-    if (list_in_list(&ctx->node))
-        list_delete(&ctx->node);
-
-    free(ctx);
-}
-
 /*
  * Handle HWRNG request queue
  */
-static bool hwrng_handle_req_queue(void) {
+static void hwrng_handle_req_queue(void) {
     int rc;
     struct hwrng_chan_ctx* ctx;
     struct hwrng_chan_ctx* temp;
 
-    /* service channels */
-    bool need_more = false;
-
     /* for all pending requests */
-    list_for_every_entry_safe(&hwrng_req_list, ctx, temp, struct hwrng_chan_ctx,
-                              node) {
-        if (ctx->send_blocked)
-            continue; /* cant service it rignt now */
-
-        size_t len = ctx->req_size;
-
-        if (len > MAX_HWRNG_MSG_SIZE)
-            len = MAX_HWRNG_MSG_SIZE;
-
-        /* get hwrng data */
-        rc = hwrng_dev_get_rng_data(rng_data, len);
-        if (rc != NO_ERROR) {
-            TLOGE("failed (%d) to get hwrng data\n", rc);
-            hwrng_close_chan(ctx);
-            continue;
-        }
-
-        /* send reply */
-        rc = tipc_send1(ctx->chan, rng_data, len);
-        if (rc < 0) {
-            if (rc == ERR_NOT_ENOUGH_BUFFER) {
-                /* mark it as send_blocked */
-                ctx->send_blocked = true;
-            } else {
-                /* just close HWRNG request channel */
-                TLOGE("failed (%d) to send_reply\n", rc);
-                hwrng_close_chan(ctx);
+    bool more_requests;
+    do {
+        more_requests = false;
+        list_for_every_entry_safe(&hwrng_req_list, ctx, temp,
+                                  struct hwrng_chan_ctx, node) {
+            if (ctx->error || ctx->send_blocked) {
+                continue; /* can't service it right now */
             }
-            continue;
-        }
 
-        ctx->req_size -= len;
+            size_t len = ctx->req_size;
 
-        if (ctx->req_size == 0) {
-            /* remove it from pending list */
-            list_delete(&ctx->node);
-        } else {
-            need_more = true;
-        }
-    }
+            if (len > MAX_HWRNG_MSG_SIZE)
+                len = MAX_HWRNG_MSG_SIZE;
 
-    return need_more;
-}
+            /* get hwrng data */
+            rc = trusty_rng_hw_rand(rng_data, len);
+            if (rc != NO_ERROR) {
+                TLOGE("failed (%d) to get hwrng data\n", rc);
+                ctx->error = rc;
+                continue;
+            }
 
-/*
- * Check if we can handle request queue
- */
-static void hwrng_kick_req_queue(void) {
-    hwrng_handle_req_queue();
+            /* send reply */
+            rc = tipc_send1(ctx->chan, rng_data, len);
+            if (rc < 0) {
+                if (rc == ERR_NOT_ENOUGH_BUFFER) {
+                    /* mark it as send_blocked */
+                    ctx->send_blocked = true;
+                } else {
+                    /* just close HWRNG request channel */
+                    TLOGE("failed (%d) to send_reply\n", rc);
+                    ctx->error = rc;
+                }
+                continue;
+            }
+
+            ctx->req_size -= len;
+
+            if (ctx->req_size == 0) {
+                /* remove it from pending list */
+                list_delete(&ctx->node);
+            } else {
+                more_requests = true;
+            }
+        }
+    } while (more_requests);
 }
 
 /*
  *  Read and queue HWRNG request message
  */
-static int hwrng_chan_handle_msg(struct hwrng_chan_ctx* ctx) {
+static int hwrng_chan_handle_msg(const struct tipc_port* port,
+                                 handle_t chan,
+                                 void* received_ctx) {
     int rc;
     struct hwrng_req req;
 
+    struct hwrng_chan_ctx* ctx = (struct hwrng_chan_ctx*)received_ctx;
+
     assert(ctx);
 
+    /* check for an error from a previous send attempt */
+    if (ctx->error) {
+        return ctx->error;
+    }
+
     /* read request */
-    rc = tipc_recv1(ctx->chan, sizeof(req), &req, sizeof(req));
+    rc = tipc_recv1(chan, sizeof(req), &req, sizeof(req));
     if (rc < 0) {
-        TLOGE("failed (%d) to receive msg for chan %d\n", rc, ctx->chan);
+        TLOGE("failed (%d) to receive msg for chan %d\n", rc, chan);
         return rc;
     }
 
@@ -175,111 +161,93 @@ static int hwrng_chan_handle_msg(struct hwrng_chan_ctx* ctx) {
         list_add_tail(&hwrng_req_list, &ctx->node);
     }
 
-    return 0;
+    hwrng_handle_req_queue();
+
+    return ctx->error;
 }
 
 /*
- *  Channel handler where HWRNG requests are coming from
+ * Create hwrng channel context
  */
-static void hwrng_chan_handler(const uevent_t* ev, void* priv) {
-    struct hwrng_chan_ctx* ctx = priv;
-
-    assert(ctx);
-    assert(ev->handle == ctx->chan);
-
-    tipc_handle_chan_errors(ev);
-
-    if (ev->event & IPC_HANDLE_POLL_HUP) {
-        hwrng_close_chan(ctx);
-    } else {
-        if (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED) {
-            ctx->send_blocked = false;
-        }
-
-        if (ev->event & IPC_HANDLE_POLL_MSG) {
-            int rc = hwrng_chan_handle_msg(ctx);
-            if (rc) {
-                hwrng_close_chan(ctx);
-            }
-        }
+static int hwrng_chan_ctx_create(const struct tipc_port* port,
+                                 handle_t chan,
+                                 const struct uuid* peer,
+                                 void** ctx) {
+    struct hwrng_chan_ctx* chan_ctx = calloc(1, sizeof(*chan_ctx));
+
+    if (!chan_ctx) {
+        return ERR_NO_MEMORY;
     }
 
-    /* kick state machine */
-    hwrng_kick_req_queue();
+    /* init channel state */
+    chan_ctx->chan = chan;
+    *ctx = chan_ctx;
+
+    return NO_ERROR;
 }
 
 /*
- * Port were HWRNG requests are coming from
+ * Close specified hwrng channel context
  */
-static void hwrng_port_handler(const uevent_t* ev, void* priv) {
-    uuid_t peer_uuid;
+static void hwrng_chan_ctx_close(void* ctx_rcv) {
+    struct hwrng_chan_ctx* ctx = (struct hwrng_chan_ctx*)ctx_rcv;
 
-    tipc_handle_port_errors(ev);
+    if (list_in_list(&ctx->node))
+        list_delete(&ctx->node);
 
-    if (ev->event & IPC_HANDLE_POLL_READY) {
-        handle_t chan;
+    close(ctx->chan);
+    free(ctx);
+}
 
-        /* incoming connection: accept it */
-        int rc = accept(ev->handle, &peer_uuid);
-        if (rc < 0) {
-            TLOGE("failed (%d) to accept on port %d\n", rc, ev->handle);
-            return;
-        }
-        chan = (handle_t)rc;
-
-        /* allocate state */
-        struct hwrng_chan_ctx* ctx = calloc(1, sizeof(*ctx));
-        if (!ctx) {
-            TLOGE("failed to alloc state for chan %d\n", chan);
-            close(chan);
-            return;
-        }
+static int hwrng_handle_send_unblocked(const struct tipc_port* port,
+                                       handle_t chan,
+                                       void* ctx_v) {
+    struct hwrng_chan_ctx* ctx = ctx_v;
 
-        /* init channel state */
-        ctx->evt_handler.priv = ctx;
-        ctx->evt_handler.proc = hwrng_chan_handler;
-        ctx->chan = chan;
-
-        /* attach channel handler */
-        rc = set_cookie(chan, &ctx->evt_handler);
-        if (rc) {
-            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan);
-            free(ctx);
-            close(chan);
-            return;
-        }
+    if (ctx->error) {
+        return ctx->error;
     }
+
+    ctx->send_blocked = false;
+
+    hwrng_handle_req_queue();
+
+    return ctx->error;
 }
 
 /*
  *  Initialize HWRNG services
  */
-int hwrng_start_service(void) {
+int hwrng_start_service(struct tipc_hset* hset) {
     int rc;
 
     TLOGD("Start HWRNG service\n");
 
-    /* create HWRNG port */
-    rc = port_create(HWRNG_SRV_NAME, 1, MAX_HWRNG_MSG_SIZE,
-                     IPC_PORT_ALLOW_TA_CONNECT);
-    if (rc < 0) {
-        TLOGE("Failed (%d) to create port '%s'\n", rc, HWRNG_SRV_NAME);
-        goto err_port_create;
-    }
-
-    hwrng_port = (handle_t)rc;
-    set_cookie(hwrng_port, &hwrng_port_evt_handler);
+    static struct tipc_port_acl acl = {
+            .flags = IPC_PORT_ALLOW_TA_CONNECT,
+            .uuid_num = 0,
+            .uuids = NULL,
+    };
+
+    static struct tipc_port port = {
+            .name = HWRNG_SRV_NAME,
+            .msg_max_size = MAX_HWRNG_MSG_SIZE,
+            .msg_queue_len = 1,
+            .acl = &acl,
+    };
+
+    static struct tipc_srv_ops ops = {
+            .on_message = hwrng_chan_handle_msg,
+            .on_connect = hwrng_chan_ctx_create,
+            .on_channel_cleanup = hwrng_chan_ctx_close,
+            .on_send_unblocked = hwrng_handle_send_unblocked,
+    };
 
     rc = hwrng_dev_init();
     if (rc != NO_ERROR) {
         TLOGE("Failed (%d) to initialize HWRNG device\n", rc);
-        goto err_hwrng_dev_init;
+        return rc;
     }
 
-    return NO_ERROR;
-
-err_hwrng_dev_init:
-    close(hwrng_port);
-err_port_create:
-    return rc;
+    return tipc_add_service(hset, &port, 1, HWRNG_MAX_NUM_CHANNELS, &ops);
 }
diff --git a/hwcrypto/hwrng_srv_fake_provider.c b/hwcrypto/hwrng_srv_fake_provider.c
index cf360a9..729b569 100644
--- a/hwcrypto/hwrng_srv_fake_provider.c
+++ b/hwcrypto/hwrng_srv_fake_provider.c
@@ -16,12 +16,14 @@
 
 #define TLOG_TAG "hwrng_fake_srv"
 
+#include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <uapi/err.h>
 
 #include <hwcrypto/hwrng_dev.h>
+#include <trusty/time.h>
 #include <trusty_log.h>
 
 #pragma message "Compiling FAKE HWRNG provider"
@@ -35,9 +37,16 @@ int hwrng_dev_init(void) {
 static size_t counter = 1;
 
 __attribute__((no_sanitize("unsigned-integer-overflow"))) int
-hwrng_dev_get_rng_data(uint8_t* buf, size_t buf_len) {
+trusty_rng_hw_rand(uint8_t* buf, size_t buf_len) {
+    int64_t time;
+    trusty_gettime(0, &time);
+
+    time = time ^ (time >> 32);
+    time = time ^ (time >> 16);
+    const uint8_t mask = (time ^ (time >> 8)) & 0xff;
+
     for (uint8_t* end = buf + buf_len; buf < end; ++buf) {
-        *buf = counter++ & 0xff;
+        *buf = (counter++ ^ mask) & 0xff;
     }
     return NO_ERROR;
 }
diff --git a/hwcrypto/hwrng_srv_priv.h b/hwcrypto/hwrng_srv_priv.h
index 1b7c1d8..0f7ddf1 100644
--- a/hwcrypto/hwrng_srv_priv.h
+++ b/hwcrypto/hwrng_srv_priv.h
@@ -15,10 +15,11 @@
  */
 #pragma once
 
+#include <lib/tipc/tipc_srv.h>
 #include <lk/compiler.h>
 
 __BEGIN_CDECLS
 
-int hwrng_start_service(void);
+int hwrng_start_service(struct tipc_hset* hset);
 
 __END_CDECLS
diff --git a/hwcrypto/include/hwcrypto/hwrng_dev.h b/hwcrypto/include/hwcrypto/hwrng_dev.h
index ef9823a..a5a2e61 100644
--- a/hwcrypto/include/hwcrypto/hwrng_dev.h
+++ b/hwcrypto/include/hwcrypto/hwrng_dev.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include <lib/rng/trusty_rng.h>
 #include <lk/compiler.h>
 #include <stddef.h>
 #include <stdint.h>
@@ -35,12 +36,14 @@ __BEGIN_CDECLS
 int hwrng_dev_init(void);
 
 /*
- * hwrng_dev_get_rng_data() - get hardware-generated random data
+ * trusty_rng_hw_rand() - get hardware-generated random data. Function
+ * definition located in trusty_rng.h.
  * @buf: buffer to be filled up
  * @buf_len: requested amount of random data
  *
  * Return: NO_ERROR on success, a negative error code otherwise.
+ *
+ * int trusty_rng_hw_rand(uint8_t* data, size_t len);
  */
-int hwrng_dev_get_rng_data(uint8_t* buf, size_t buf_len);
 
 __END_CDECLS
diff --git a/hwcrypto/keybox/srv.c b/hwcrypto/keybox/srv.c
index a43efc8..d7a5ad3 100644
--- a/hwcrypto/keybox/srv.c
+++ b/hwcrypto/keybox/srv.c
@@ -32,25 +32,14 @@
 #include "keybox.h"
 #include "srv.h"
 
+/* 0 means unlimited number of connections */
+#define KEYBOX_MAX_NUM_CHANNELS 0
+
 struct keybox_chan_ctx {
     struct tipc_event_handler evt_handler;
     handle_t chan;
 };
 
-static void keybox_port_handler(const uevent_t* ev, void* priv);
-static void keybox_chan_handler(const uevent_t* ev, void* priv);
-
-static handle_t keybox_port = INVALID_IPC_HANDLE;
-
-static struct tipc_event_handler keybox_port_evt_handler = {
-        .proc = keybox_port_handler,
-};
-
-static void keybox_shutdown(struct keybox_chan_ctx* ctx) {
-    close(ctx->chan);
-    free(ctx);
-}
-
 struct full_keybox_unwrap_req {
     struct keybox_unwrap_req unwrap_header;
     uint8_t wrapped_keybox[KEYBOX_MAX_SIZE];
@@ -106,11 +95,13 @@ struct full_keybox_req {
     } cmd_header;
 };
 
-static int keybox_handle_msg(struct keybox_chan_ctx* ctx) {
+static int keybox_chan_handle_msg(const struct tipc_port* port,
+                                  handle_t chan,
+                                  void* ctx) {
     int rc;
     struct full_keybox_req req;
     enum keybox_status status = KEYBOX_STATUS_SUCCESS;
-    rc = tipc_recv1(ctx->chan, sizeof(req.header), &req, sizeof(req));
+    rc = tipc_recv1(chan, sizeof(req.header), &req, sizeof(req));
     if (rc < 0) {
         TLOGE("Failed (%d) to receive Keybox message\n", rc);
         return KEYBOX_STATUS_INTERNAL_ERROR;
@@ -119,7 +110,7 @@ static int keybox_handle_msg(struct keybox_chan_ctx* ctx) {
     size_t cmd_specific_size = (size_t)rc - sizeof(req.header);
     switch (req.header.cmd) {
     case KEYBOX_CMD_UNWRAP:
-        rc = keybox_handle_unwrap(ctx->chan, &req.cmd_header.unwrap,
+        rc = keybox_handle_unwrap(chan, &req.cmd_header.unwrap,
                                   cmd_specific_size);
         break;
     default:
@@ -127,7 +118,7 @@ static int keybox_handle_msg(struct keybox_chan_ctx* ctx) {
         struct keybox_resp rsp;
         rsp.cmd = req.header.cmd | KEYBOX_CMD_RSP_BIT;
         rsp.status = KEYBOX_STATUS_INVALID_REQUEST;
-        rc = tipc_send1(ctx->chan, &rsp, sizeof(rsp));
+        rc = tipc_send1(chan, &rsp, sizeof(rsp));
     }
 
     if (rc < 0) {
@@ -137,86 +128,27 @@ static int keybox_handle_msg(struct keybox_chan_ctx* ctx) {
     return status;
 }
 
-static void keybox_chan_handler(const uevent_t* ev, void* priv) {
-    struct keybox_chan_ctx* ctx = (struct keybox_chan_ctx*)priv;
-    assert(ctx);
-    assert(ev->handle == ctx->chan);
-
-    tipc_handle_chan_errors(ev);
-    int rc = 0;
-    if (ev->event & IPC_HANDLE_POLL_MSG) {
-        rc = keybox_handle_msg(ctx);
-    }
-    if (ev->event & IPC_HANDLE_POLL_HUP) {
-        keybox_shutdown(ctx);
-    }
-    if (rc) {
-        keybox_shutdown(ctx);
-    }
-}
-
-static void keybox_port_handler(const uevent_t* ev, void* priv) {
-    uuid_t peer_uuid;
-
-    tipc_handle_port_errors(ev);
-
-    if (ev->event & IPC_HANDLE_POLL_READY) {
-        handle_t chan;
-
-        /* incoming connection: accept it */
-        int rc = accept(ev->handle, &peer_uuid);
-        if (rc < 0) {
-            TLOGE("failed (%d) to accept on port %d\n", rc, ev->handle);
-            return;
-        }
-        chan = (handle_t)rc;
-
-        struct keybox_chan_ctx* ctx = calloc(1, sizeof(struct keybox_chan_ctx));
-
-        if (!ctx) {
-            TLOGE("failed to alloc state for chan %d\n", chan);
-            close(chan);
-            return;
-        }
-
-        /* init channel state */
-        ctx->evt_handler.priv = ctx;
-        ctx->evt_handler.proc = keybox_chan_handler;
-        ctx->chan = chan;
-
-        /* attach channel handler */
-        rc = set_cookie(chan, &ctx->evt_handler);
-        if (rc) {
-            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan);
-            free(ctx);
-            close(chan);
-            return;
-        }
-    }
-}
-
 /*
  *  Initialize Keybox service
  */
-int keybox_start_service(void) {
-    int rc;
-
+int keybox_start_service(struct tipc_hset* hset) {
     TLOGD("Start Keybox service\n");
 
-    /* create Keybox port */
-    rc = port_create(KEYBOX_PORT, 1, sizeof(struct full_keybox_req),
-                     IPC_PORT_ALLOW_TA_CONNECT);
-    if (rc < 0) {
-        TLOGE("Failed (%d) to create port '%s'\n", rc, KEYBOX_PORT);
-        goto cleanup;
-    }
-
-    keybox_port = (handle_t)rc;
-    set_cookie(keybox_port, &keybox_port_evt_handler);
-
-    return NO_ERROR;
+    // TODO: check why we are not restricting connections by uuid
+    static struct tipc_port_acl acl = {
+            .flags = IPC_PORT_ALLOW_TA_CONNECT,
+            .uuid_num = 0,
+            .uuids = NULL,
+    };
 
-cleanup:
-    close(keybox_port);
-    return rc;
+    static struct tipc_port port = {
+            .name = KEYBOX_PORT,
+            .msg_max_size = sizeof(struct full_keybox_req),
+            .msg_queue_len = 1,
+            .acl = &acl,
+    };
+    static struct tipc_srv_ops ops = {
+            .on_message = keybox_chan_handle_msg,
+    };
+    return tipc_add_service(hset, &port, 1, KEYBOX_MAX_NUM_CHANNELS, &ops);
 }
diff --git a/hwcrypto/keybox/srv.h b/hwcrypto/keybox/srv.h
index 74e2a2d..2c65108 100644
--- a/hwcrypto/keybox/srv.h
+++ b/hwcrypto/keybox/srv.h
@@ -16,10 +16,12 @@
 
 #pragma once
 
+#include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
 #include <lk/compiler.h>
 
 __BEGIN_CDECLS
 
-int keybox_start_service(void);
+int keybox_start_service(struct tipc_hset*);
 
 __END_CDECLS
diff --git a/hwcrypto/main.c b/hwcrypto/main.c
index 0e0f76c..3bd3713 100644
--- a/hwcrypto/main.c
+++ b/hwcrypto/main.c
@@ -24,6 +24,7 @@
 
 #include <hwcrypto/hwrng_dev.h>
 #include <lib/tipc/tipc.h>
+#include <lk/err_ptr.h>
 #include <trusty_log.h>
 
 #include "hwkey_srv_priv.h"
@@ -31,54 +32,39 @@
 
 #include "keybox/srv.h"
 
-/*
- *  Dispatch event
- */
-static void dispatch_event(const uevent_t* ev) {
-    assert(ev);
-
-    if (ev->event == IPC_HANDLE_POLL_NONE) {
-        /* not really an event, do nothing */
-        TLOGI("got an empty event\n");
-        return;
-    }
-
-    /* check if we have handler */
-    struct tipc_event_handler* handler = ev->cookie;
-    if (handler && handler->proc) {
-        /* invoke it */
-        handler->proc(ev, handler->priv);
-        return;
-    }
-
-    /* no handler? close it */
-    TLOGE("no handler for event (0x%x) with handle %d\n", ev->event,
-          ev->handle);
-
-    close(ev->handle);
-
-    return;
-}
-
 /*
  *  Main application event loop
  */
 int main(void) {
     int rc;
-    uevent_t event;
+    struct tipc_hset* hset;
 
     TLOGD("Initializing\n");
 
+    hset = tipc_hset_create();
+    if (IS_ERR(hset)) {
+        rc = PTR_ERR(hset);
+        TLOGE("tipc_hset_create failed (%d)\n", rc);
+        goto out;
+    }
+
     /* initialize service providers */
-    rc = hwrng_start_service();
+#if WITH_HWCRYPTO_HWRNG
+    rc = hwrng_start_service(hset);
     if (rc != NO_ERROR) {
         TLOGE("Failed (%d) to initialize HWRNG service\n", rc);
         goto out;
     }
-    hwkey_init_srv_provider();
+#endif
+
+    rc = hwkey_init_srv_provider(hset);
+    if (rc != NO_ERROR) {
+        TLOGE("Failed (%d) to initialize HwKey service\n", rc);
+        goto out;
+    }
 
 #if defined(WITH_FAKE_KEYBOX)
-    rc = keybox_start_service();
+    rc = keybox_start_service(hset);
     if (rc != NO_ERROR) {
         TLOGE("Failed (%d) to initialize Keybox service\n", rc);
         goto out;
@@ -88,21 +74,7 @@ int main(void) {
     TLOGD("enter main event loop\n");
 
     /* enter main event loop */
-    while (1) {
-        event.handle = INVALID_IPC_HANDLE;
-        event.event = 0;
-        event.cookie = NULL;
-
-        rc = wait_any(&event, INFINITE_TIME);
-        if (rc < 0) {
-            TLOGE("wait_any failed (%d)\n", rc);
-            break;
-        }
-
-        if (rc == NO_ERROR) { /* got an event */
-            dispatch_event(&event);
-        }
-    }
+    rc = tipc_run_event_loop(hset);
 
 out:
     return rc;
diff --git a/hwcrypto/rules.mk b/hwcrypto/rules.mk
index df15e65..0ae2908 100644
--- a/hwcrypto/rules.mk
+++ b/hwcrypto/rules.mk
@@ -26,7 +26,6 @@ MODULE_INCLUDES := $(LOCAL_DIR)/include
 
 MODULE_SRCS := \
 	$(LOCAL_DIR)/main.c \
-	$(LOCAL_DIR)/hwrng_srv.c \
 	$(LOCAL_DIR)/hwkey_srv.c \
 
 ifeq (true,$(call TOBOOL,$(WITH_FAKE_HWRNG)))
@@ -35,6 +34,8 @@ endif
 
 ifeq (true,$(call TOBOOL,$(WITH_FAKE_HWKEY)))
 MODULE_SRCS += $(LOCAL_DIR)/hwkey_srv_fake_provider.c
+MODULE_SRCS += $(LOCAL_DIR)/hwrng_srv.c
+MODULE_DEFINES += WITH_HWCRYPTO_HWRNG=1
 endif
 
 MODULE_LIBRARY_DEPS := \
diff --git a/hwcryptohal/aidl/rust/rules.mk b/hwcryptohal/aidl/rust/rules.mk
index 8feadf7..e164bd1 100644
--- a/hwcryptohal/aidl/rust/rules.mk
+++ b/hwcryptohal/aidl/rust/rules.mk
@@ -43,7 +43,9 @@ MODULE_AIDLS := \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/PatternParameters.aidl                      \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/AesCipherMode.aidl                    \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/AesGcmMode.aidl                       \
+    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/AesKey.aidl                           \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/CipherModeParameters.aidl             \
+    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/ExplicitKeyMaterial.aidl              \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HalErrorCode.aidl                     \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyLifetime.aidl                      \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyPermissions.aidl                   \
diff --git a/hwcryptohal/common/cose.rs b/hwcryptohal/common/cose.rs
new file mode 100644
index 0000000..3dc51d9
--- /dev/null
+++ b/hwcryptohal/common/cose.rs
@@ -0,0 +1,114 @@
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
+//! COSE/CBOR helper functions and macros
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
+        #[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
+        pub struct $wrapper_name(pub $aidl_name);
+
+        impl From<$wrapper_name> for $aidl_name {
+            fn from(value: $wrapper_name) -> Self {
+                value.0
+            }
+        }
+
+        impl From<$aidl_name> for $wrapper_name {
+            fn from(value: $aidl_name) -> Self {
+                $wrapper_name(value)
+            }
+        }
+
+        impl TryFrom<u64> for $wrapper_name {
+            type Error = $crate::err::HwCryptoError;
+
+            fn try_from(value: u64) -> Result<Self, Self::Error> {
+                let val = match value {
+                    $(x if x == $aidl_name::$field.0 as u64 =>Ok($aidl_name::$field)),+,
+                    _ => Err($crate::hwcrypto_err!(SERIALIZATION_ERROR, "unsupported enum val {}", value)),
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
+                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
+            }
+        }
+
+        impl From<$wrapper_name> for ciborium::value::Integer {
+            fn from(value: $wrapper_name) -> Self {
+                (value.0.0 as u64).into()
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
+            type Error = $crate::err::HwCryptoError;
+
+            fn try_from(value: i64) -> Result<Self, Self::Error> {
+                match value {
+                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
+                    _ => Err($crate::hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE enum label val {}", value)),
+                }
+            }
+        }
+
+        impl TryFrom<ciborium::value::Integer> for $name {
+            type Error = coset::CoseError;
+
+            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
+                let value: i64 = value.try_into()?;
+                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
+            }
+        }
+    }
+}
diff --git a/hwcryptohal/common/err.rs b/hwcryptohal/common/err.rs
index eb49044..5e022f2 100644
--- a/hwcryptohal/common/err.rs
+++ b/hwcryptohal/common/err.rs
@@ -22,6 +22,7 @@ use android_hardware_security_see::binder;
 use core::array::TryFromSliceError;
 use coset::CoseError;
 use tipc::TipcError;
+use vm_memory::VolatileMemoryError;
 
 /// Macro used to create a `HwCryptoError::HalError` by providing the AIDL `HalErrorCode` and a
 /// message: `hwcrypto_err!(UNSUPPORTED, "unsupported operation")`
@@ -48,6 +49,12 @@ pub enum HwCryptoError {
     CborError(kmr_wire::CborError),
 }
 
+impl HwCryptoError {
+    pub fn matches_hal_error_code(&self, error_code: i32) -> bool {
+        core::matches!(self, HwCryptoError::HalError { code, .. } if *code == error_code)
+    }
+}
+
 impl From<kmr_wire::CborError> for HwCryptoError {
     fn from(e: kmr_wire::CborError) -> Self {
         HwCryptoError::CborError(e)
@@ -78,6 +85,12 @@ impl From<TryReserveError> for HwCryptoError {
     }
 }
 
+impl From<VolatileMemoryError> for HwCryptoError {
+    fn from(e: VolatileMemoryError) -> Self {
+        hwcrypto_err!(BAD_PARAMETER, "memory buffer slice error: {}", e)
+    }
+}
+
 impl From<TryFromSliceError> for HwCryptoError {
     fn from(e: TryFromSliceError) -> Self {
         hwcrypto_err!(ALLOCATION_ERROR, "error allocating from slice: {}", e)
diff --git a/hwcryptohal/common/lib.rs b/hwcryptohal/common/lib.rs
index 6dfa221..a8aa017 100644
--- a/hwcryptohal/common/lib.rs
+++ b/hwcryptohal/common/lib.rs
@@ -16,4 +16,14 @@
 
 //! Library implementing common client and server HWCrypto functionality.
 
+pub mod cose;
 pub mod err;
+pub mod policy;
+
+// Trusty Rust unittests use a sligthly different setup and environment than
+// normal Rust unittests. The next call adds the necessary variables and code to be
+// able to compile this library as a Trusty unittest TA.
+#[cfg(test)]
+mod tests {
+    test::init!();
+}
diff --git a/hwcryptohal/common/manifest.json b/hwcryptohal/common/manifest.json
new file mode 100644
index 0000000..08edaf1
--- /dev/null
+++ b/hwcryptohal/common/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "hwcryptohalcommon_lib",
+    "uuid": "1527bfac-f6d3-410f-a01d-d07f228e384c",
+    "min_heap": 118784,
+    "min_stack": 32768
+}
diff --git a/hwcryptohal/common/policy.rs b/hwcryptohal/common/policy.rs
new file mode 100644
index 0000000..b49e538
--- /dev/null
+++ b/hwcryptohal/common/policy.rs
@@ -0,0 +1,384 @@
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
+//! KeyPolicy serialization facilities
+
+use alloc::collections::btree_set::BTreeSet;
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
+};
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
+use ciborium::Value;
+use coset::{AsCborValue, CborSerializable, CoseError};
+
+use crate::{aidl_enum_wrapper, cose_enum_gen};
+use crate::{err::HwCryptoError, hwcrypto_err};
+
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
+    fn new(key_policy: &KeyPolicy) -> Result<Self, crate::err::HwCryptoError> {
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
+    type Error = crate::err::HwCryptoError;
+
+    fn try_from(value: &KeyPolicy) -> Result<Self, Self::Error> {
+        Self::new(value)
+    }
+}
+
+impl TryFrom<KeyPolicy> for SerializableKeyPolicy {
+    type Error = crate::err::HwCryptoError;
+
+    fn try_from(value: KeyPolicy) -> Result<Self, Self::Error> {
+        (&value).try_into()
+    }
+}
+
+impl TryFrom<&SerializableKeyPolicy> for KeyPolicy {
+    type Error = crate::err::HwCryptoError;
+
+    fn try_from(value: &SerializableKeyPolicy) -> Result<Self, Self::Error> {
+        let mut key_permissions = Vec::new();
+        key_permissions.try_reserve(value.key_permissions.len())?;
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
+    type Error = crate::err::HwCryptoError;
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
+        let value = Value::Bool(self.management_key.into());
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
+pub static AES_SYMMETRIC_KEY_USES_MASK: i32 = KeyUse::ENCRYPT_DECRYPT.0 | KeyUse::WRAP.0;
+pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0;
+
+pub fn check_key_policy(key_policy: &KeyPolicy) -> Result<(), HwCryptoError> {
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
+                Err(hwcrypto_err!(
+                    BAD_PARAMETER,
+                    "usage not supported for AES symmetric key: {}",
+                    key_policy.usage.0
+                ))
+            } else {
+                Ok(())
+            }
+        }
+        KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
+            if (key_policy.usage.0 & !HMAC_KEY_USES_MASK) != 0 {
+                Err(hwcrypto_err!(
+                    BAD_PARAMETER,
+                    "usage not supported for HMAC key: {}",
+                    key_policy.usage.0
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
+        | KeyType::ECC_ED25519_SIGN => {
+            Err(hwcrypto_err!(UNSUPPORTED, "key type not supported yet"))
+        }
+        _ => Err(hwcrypto_err!(BAD_PARAMETER, "unknown keytype provided {:?}", key_policy.keyType)),
+    }
+}
+
+pub fn cbor_serialize_key_policy(key_policy: &KeyPolicy) -> Result<Vec<u8>, HwCryptoError> {
+    let serializable_key_policy: SerializableKeyPolicy = key_policy.try_into()?;
+    serializable_key_policy
+        .to_cbor_value()?
+        .to_vec()
+        .map_err(|_| hwcrypto_err!(SERIALIZATION_ERROR, "couldn't serialize policy"))
+}
+
+pub fn cbor_policy_to_aidl(cbor_key_policy: &[u8]) -> Result<KeyPolicy, HwCryptoError> {
+    let policy =
+        SerializableKeyPolicy::from_cbor_value(Value::from_slice(cbor_key_policy)?)?.try_into()?;
+    check_key_policy(&policy)?;
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
+        let serialize_result = cbor_serialize_key_policy(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
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
+        let serialize_result = cbor_serialize_key_policy(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.usage = KeyUse::DERIVE;
+        let serialize_result = cbor_serialize_key_policy(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.keyType = KeyType::HMAC_SHA256;
+        policy.usage = KeyUse::ENCRYPT;
+        let serialize_result = cbor_serialize_key_policy(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.usage = KeyUse::DECRYPT;
+        let serialize_result = cbor_serialize_key_policy(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+
+        policy.keyType = KeyType::HMAC_SHA512;
+        policy.usage = KeyUse::ENCRYPT_DECRYPT;
+        let serialize_result = cbor_serialize_key_policy(&policy);
+        expect!(serialize_result.is_ok(), "couldn't serialize policy");
+        let serialized_policy = serialize_result.unwrap();
+        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
+        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
+    }
+}
diff --git a/hwcryptohal/common/rules.mk b/hwcryptohal/common/rules.mk
index 78a062c..695cbc5 100644
--- a/hwcryptohal/common/rules.mk
+++ b/hwcryptohal/common/rules.mk
@@ -22,11 +22,16 @@ MODULE_SRCS += \
 
 MODULE_CRATE_NAME := hwcryptohal_common
 
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
 MODULE_LIBRARY_DEPS += \
 	trusty/user/app/sample/hwcryptohal/aidl/rust  \
 	trusty/user/base/lib/keymint-rust/common \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-sys \
 	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,vm-memory) \
+
+MODULE_RUST_TESTS := true
 
 include make/library.mk
diff --git a/hwcryptohal/server/cmd_processing.rs b/hwcryptohal/server/cmd_processing.rs
new file mode 100644
index 0000000..584c579
--- /dev/null
+++ b/hwcryptohal/server/cmd_processing.rs
@@ -0,0 +1,1343 @@
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
+//! Module providing an implementation of a cryptographic command processor.
+
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+    MemoryBufferReference::MemoryBufferReference, OperationData::OperationData,
+};
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    CryptoOperation::CryptoOperation,
+    MemoryBufferParameter::{
+        MemoryBuffer::MemoryBuffer as MemoryBufferAidl, MemoryBufferParameter,
+    },
+    OperationParameters::OperationParameters,
+};
+use core::ffi::c_void;
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use std::{os::fd::AsRawFd, ptr::NonNull};
+use vm_memory::{volatile_memory::VolatileSlice, Bytes, VolatileMemory};
+
+use crate::crypto_operation::{CopyOperation, CryptographicOperation, ICryptographicOperation};
+
+const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
+    trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;
+const INPUT_MEMORY_BUFFER_FLAGS: u32 = trusty_sys::MMAP_FLAG_PROT_READ;
+
+/// `CmdProcessorState` is a state machine with 3 states:
+///
+/// * `InitialState`: State machine operation starts here. No cryptographic operations can be
+///                   performed on this state (but copy operations are permitted). It is used to
+///                   set up memory buffers and Cryptographic operation parameters. We can go back
+///                   to this state from `RunningOperation` state after a `Finish` call.
+/// * `RunningOperation`: Once a call to `SetOperationParameters` is performed, we move to this
+///                       state. Any call to `DataInput` on this state will immediately perform the
+//                        requested cryptographic operation.
+/// * `Destroyed`: Any call to `DestroyContext` will make the state machine move to this state. Once
+///                in this state, the state machine cannot be used anymore.
+///
+/// The following diagram shows how we move between states. It is written in the form
+/// [Current State] -> [Next State]: [Operation performed on current state]:
+///
+/// `InitialState` -> `InitialState`: `CopyData`
+///         Call requires that an output buffer has been set and will immediately try to copy the
+///         data provided
+/// `InitialState` -> `InitialState`: `DataOutput`
+///         Sets output buffer. Any previously set up DataOutput is not used after this.
+/// `InitialState` -> `InitialState`: `SetMemoryBuffer`
+///         Sets an fd to be used by memory references. It can only be set once
+///         because currently output buffers will directly use the active memory buffer, instead of
+///         remembering which memory buffer was active at the moment the output was added. This
+///         should cover the current use cases, but could be refactored if needed.
+/// `InitialState` -> `RunningOperation`: `SetOperationParameters`
+///         Starts executing cryptographic operation.
+/// `RunningOperation` -> `RunningOperation`: `DataOutput`
+///         Sets output buffer. Any previously set up DataOutput is not used after this.
+/// `RunningOperation` -> `RunningOperation`: `CopyData`
+///         Call requires that an output buffer has been set and will immediately try to copy the
+///         data provided. It can be used to implement some cryptographic protocols which decrypt
+///         only some areas and directly copy other areas
+/// `RunningOperation` -> `RunningOperation`: `AadInput`
+///         Processes the provided data as Authenticated Additional Data
+/// `RunningOperation` -> `RunningOperation`: `DataInput`
+///         Immediately processes the provided data. For operations like encryption or decryption on
+///         which we need to immediately generate data, this call requires that an output buffer has
+///         been already set up
+/// `RunningOperation` -> `RunningOperation`: `SetPattern`
+///         Sets up a pattern of encrypted/unencrypted data to process on the subsequent calls to
+///         `DataInput`. Currently it is only used for AES CBC decryption (cbcs mode from IEC
+///         23001-7:2016)
+/// `RunningOperation` -> `InitialState`: `Finish`
+///         Finish an ongoing cryptographic operation. Notice that this call can generate data as in
+///         the case of signing operations or padded encryption. This call will invalidate any
+///         settings done by `SetOperationParameters` or `SetPattern`
+/// `RunningOperation` -> `RunningOperation`: `SetOperationParameters`
+///         Resets all cryptographic parameters set up on the previous `SetOperationParameters`
+///         operation and implicitly calls finish. Main use case is to reset IV for cbcs mode
+///         decryption without needing to call finish.
+/// `RunningOperation` -> `Destroyed`: `DestroyContext`
+///         This context cannot be used anymore
+/// `InitialState` -> `Destroyed`: `DestroyContext`
+///         This context cannot be used anymore
+#[derive(Debug, PartialEq)]
+enum CmdProcessorState {
+    InitialState,
+    RunningOperation,
+    Destroyed,
+}
+
+// `DataToProcess`is used to abstract away if the cryptographic operations are working on memory
+// buffers or vectors.
+pub(crate) enum DataToProcess<'a> {
+    VolatileSlice(VolatileSlice<'a>),
+    Slice(&'a mut [u8]),
+}
+
+impl<'a> DataToProcess<'a> {
+    pub(crate) fn len(&self) -> usize {
+        match self {
+            Self::VolatileSlice(vs) => vs.len(),
+            Self::Slice(s) => s.len(),
+        }
+    }
+
+    pub(crate) fn copy_slice(&mut self, from: &[u8]) -> Result<(), HwCryptoError> {
+        if self.len() < from.len() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "slice size: {} is less than the slice provided {}",
+                self.len(),
+                from.len()
+            ));
+        }
+        match self {
+            Self::VolatileSlice(to) => to.write_slice(from, 0)?,
+            Self::Slice(to) => to[..from.len()].copy_from_slice(from),
+        }
+        Ok(())
+    }
+
+    pub(crate) fn copy_from_slice(
+        &mut self,
+        slice: &DataToProcess<'a>,
+    ) -> Result<(), HwCryptoError> {
+        if self.len() < slice.len() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "slice size: {} is less than the slice provided {}",
+                self.len(),
+                slice.len()
+            ));
+        }
+
+        match (slice, self) {
+            (Self::Slice(from), Self::VolatileSlice(to)) => to.write_slice(from, 0)?,
+            (Self::VolatileSlice(from), Self::VolatileSlice(to)) => {
+                from.copy_to_volatile_slice(to.get_slice(0, to.len())?)
+            }
+            (Self::Slice(from), Self::Slice(to)) => to[..from.len()].copy_from_slice(from),
+            (Self::VolatileSlice(from), Self::Slice(to)) => from.read_slice(to, 0)?,
+        }
+        Ok(())
+    }
+
+    /// Grows the vector to the required size and return a `DataToProcess` to the newly allocated
+    /// portion
+    pub(crate) fn allocate_buffer_end_vector(
+        vector: &'a mut Vec<u8>,
+        buffer_size: usize,
+    ) -> Result<DataToProcess<'a>, HwCryptoError> {
+        let original_len = vector.len();
+        vector.try_reserve(buffer_size)?;
+        // Addition should be safe because try_reserve didn't fail
+        let new_len = original_len + buffer_size;
+        vector.resize_with(new_len, Default::default);
+        Ok(Self::Slice(&mut vector[original_len..new_len]))
+    }
+}
+
+// Structure that keeps track of current output buffer
+enum OutputData<'a> {
+    DataBuffer(&'a mut Vec<u8>),
+    MemoryReference(MemoryBufferReference, usize),
+}
+
+fn get_mmap_prot_flags(memory_buffer: &MemoryBufferAidl) -> u32 {
+    match memory_buffer {
+        MemoryBufferAidl::Input(_) => INPUT_MEMORY_BUFFER_FLAGS,
+        MemoryBufferAidl::Output(_) => OUTPUT_MEMORY_BUFFER_FLAGS,
+    }
+}
+
+// `MemoryBufferReference` types do not contain the necessary information to
+// know if it should operate on an Input or Output buffer. That information is provided by the
+// Operation which contains the `MemoryBufferReference`. This wrapper preserves that information to
+// be used along function call sequences.
+#[derive(Copy, Clone)]
+enum MemoryBufferReferenceWithType {
+    Input(MemoryBufferReference),
+    Output(MemoryBufferReference),
+}
+
+impl MemoryBufferReferenceWithType {
+    fn len(&self) -> Result<usize, HwCryptoError> {
+        match self {
+            MemoryBufferReferenceWithType::Input(buff_ref) => buff_ref.sizeBytes,
+            MemoryBufferReferenceWithType::Output(buff_ref) => buff_ref.sizeBytes,
+        }
+        .try_into()
+        .map_err(|e| {
+            hwcrypto_err!(BAD_PARAMETER, "buffer reference sizes cannot be negative: {:?}", e)
+        })
+    }
+
+    fn start_offset(&self) -> Result<usize, HwCryptoError> {
+        match self {
+            MemoryBufferReferenceWithType::Input(buff_ref) => buff_ref.startOffset,
+            MemoryBufferReferenceWithType::Output(buff_ref) => buff_ref.startOffset,
+        }
+        .try_into()
+        .map_err(|e| {
+            hwcrypto_err!(BAD_PARAMETER, "buffer reference offsets cannot be negative: {:?}", e)
+        })
+    }
+}
+
+/// Given a `MemoryBufferReference` it checks that its elements are valid (buffer_start should be
+/// positive and buffer_size should be greater than 0) and then returns the memory reference
+/// start/stop/size as an `usize` tuple
+fn get_limits(
+    buffer_reference: &MemoryBufferReferenceWithType,
+) -> Result<(usize, usize, usize), HwCryptoError> {
+    let buffer_size = buffer_reference.len()?;
+    let buffer_start = buffer_reference.start_offset()?;
+    if buffer_size == 0 {
+        return Err(hwcrypto_err!(BAD_PARAMETER, "buffer reference size shouldn't be 0"));
+    }
+    // Because both values are positive and originally signed, then the unsigned addition should not
+    // overflow. Using a checked add in case we can change these values to unsigned
+    // in the future
+    if let Some(buffer_end) = buffer_size.checked_add(buffer_start) {
+        Ok((buffer_start, buffer_end, buffer_size))
+    } else {
+        Err(hwcrypto_err!(BAD_PARAMETER, "buffer end overflowed"))
+    }
+}
+
+// Wrapper over pointer used to map memory buffer.
+struct MappedBuffer(NonNull<u8>);
+
+// SAFETY: `MappedBuffer` is only used to free object on drop or to create a `VolatileSlice` when
+//         we need to access the underlying memory buffer; never directly. It is safe to access and
+//         drop on a different thread. All accesses to the mmaped memory are done through the
+//         `VolatileSlice` which already has the assumption that the underlying memory is shared
+//         between different entities, so it only uses `std::ptr::{copy, read_volatile,
+//         write_volatile}` to access memory.
+unsafe impl Send for MappedBuffer {}
+
+struct MemoryBuffer {
+    buffer_ptr: MappedBuffer,
+    total_size: usize,
+}
+
+impl MemoryBuffer {
+    fn new(memory_buffer_parameters: &MemoryBufferParameter) -> Result<Self, HwCryptoError> {
+        if memory_buffer_parameters.sizeBytes <= 0 {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "Buffer size was not greater than 0"));
+        }
+        // memory_buffer_parameters.size is positive and because it is an i32, conversion is correct
+        let buffer_size = memory_buffer_parameters.sizeBytes as u32;
+        let protection_flags = get_mmap_prot_flags(&memory_buffer_parameters.bufferHandle);
+        let buffer_handle = match &memory_buffer_parameters.bufferHandle {
+            MemoryBufferAidl::Input(handle) | MemoryBufferAidl::Output(handle) => handle,
+        };
+        let buffer_handle = buffer_handle
+            .as_ref()
+            .ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "received a null buffer handle"))?;
+        // SAFETY: mmap is left to choose the address for the allocation. It will check that the
+        //         protection flags, size and fd are correct and return a negative value if
+        //         not.
+        let buffer_ptr = unsafe {
+            trusty_sys::mmap(
+                std::ptr::null_mut(),
+                buffer_size,
+                protection_flags,
+                buffer_handle.as_ref().as_raw_fd(),
+            )
+        };
+        if trusty_sys::Error::is_ptr_err(buffer_ptr as *const c_void) {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "mapping buffer handle failed: {}",
+                buffer_ptr
+            ));
+        }
+        // cast is correct because buffer_ptr is positive and a pointer
+        let buffer_ptr = NonNull::new(buffer_ptr as *mut u8)
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "buffer_ptr was NULL"))?;
+        // cast is correct because buffer_size is an u32
+        let total_size = buffer_size as usize;
+
+        Ok(Self { buffer_ptr: MappedBuffer(buffer_ptr), total_size })
+    }
+
+    fn get_memory_slice<'a>(&'a mut self) -> Result<VolatileSlice<'a>, HwCryptoError> {
+        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
+        //         operation would have failed. All accesses to this memory on this service are
+        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory is
+        //         only unmapped on drop, so it will available for the lifetime of the
+        //         `VolatileSlice`.
+        let mem_buffer = unsafe { VolatileSlice::new(self.buffer_ptr.0.as_ptr(), self.total_size) };
+        Ok(mem_buffer)
+    }
+
+    fn get_subslice_as_data_to_process<'a>(
+        &'a mut self,
+        start: usize,
+        size: usize,
+    ) -> Result<DataToProcess<'a>, HwCryptoError> {
+        let mem_buffer = self.get_memory_slice()?;
+        Ok(DataToProcess::VolatileSlice(mem_buffer.subslice(start, size)?))
+    }
+}
+
+impl Drop for MemoryBuffer {
+    fn drop(&mut self) {
+        // SAFETY: `buffer_ptr` and `total_size` were set up and remain unchanged for the lifetime
+        //         of the object. `buffer_ptr` is still mapped at this point
+        unsafe {
+            trusty_sys::munmap(self.buffer_ptr.0.as_ptr().cast::<c_void>(), self.total_size as u32)
+        };
+    }
+}
+
+// `CmdProcessorContext` is the type in charge of executing a set of commands.
+pub(crate) struct CmdProcessorContext {
+    current_input_memory_buffer: Option<MemoryBuffer>,
+    current_output_memory_buffer: Option<MemoryBuffer>,
+    current_state: CmdProcessorState,
+    current_crypto_operation: Option<Box<dyn ICryptographicOperation>>,
+}
+
+impl std::fmt::Debug for CmdProcessorContext {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(
+            f,
+            "CmdProcessorContext {{ input buffer set: {}, output buffer set: {}, state: {:?} }}",
+            self.current_input_memory_buffer.is_some(),
+            self.current_output_memory_buffer.is_some(),
+            self.current_state
+        )
+    }
+}
+
+impl CmdProcessorContext {
+    pub(crate) fn new() -> Self {
+        Self {
+            current_input_memory_buffer: None,
+            current_output_memory_buffer: None,
+            current_state: CmdProcessorState::InitialState,
+            current_crypto_operation: None,
+        }
+    }
+
+    // Helper function used to check if a given `MemoryBufferReference` is valid for the active
+    // `MemoryBuffer`s of the state machine
+    fn check_memory_reference_in_range(
+        &self,
+        buffer_reference: &MemoryBufferReferenceWithType,
+    ) -> Result<(), HwCryptoError> {
+        let current_memory_buffer = match buffer_reference {
+            MemoryBufferReferenceWithType::Input(_) => &self.current_input_memory_buffer,
+            MemoryBufferReferenceWithType::Output(_) => &self.current_output_memory_buffer,
+        };
+        let buffer_start = buffer_reference.start_offset()?;
+        let buffer_size = buffer_reference.len()?;
+        if buffer_size == 0 {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "cannot create buffer references of size 0"));
+        }
+        if let Some(current_memory_buffer) = current_memory_buffer {
+            if buffer_start >= current_memory_buffer.total_size {
+                return Err(hwcrypto_err!(BAD_PARAMETER, "buffer start falls outside of buffer"));
+            }
+            // Because both values are positive and signed, then the addition should not
+            // overflow. Using a checked add in case we can change these values to unsigned
+            // in the future
+            if let Some(buffer_end) = buffer_size.checked_add(buffer_start) {
+                if buffer_end > current_memory_buffer.total_size {
+                    Err(hwcrypto_err!(BAD_PARAMETER, "buffer reference falls outside of buffer"))
+                } else {
+                    Ok(())
+                }
+            } else {
+                Err(hwcrypto_err!(BAD_PARAMETER, "requested size goes past buffer end"))
+            }
+        } else {
+            Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "memory buffer has not been set yet, so we cannot process references to it"
+            ))
+        }
+    }
+
+    fn get_data_buffer_size(
+        &self,
+        buffer_reference: &MemoryBufferReferenceWithType,
+    ) -> Result<usize, HwCryptoError> {
+        self.check_memory_reference_in_range(buffer_reference)?;
+        buffer_reference.len()
+    }
+
+    fn set_memory_buffer_step(
+        &mut self,
+        parameters: &MemoryBufferParameter,
+        current_output_ref: &mut Option<OutputData>,
+    ) -> Result<(), HwCryptoError> {
+        let (current_memory_buffer, buffer_is_output) = match &parameters.bufferHandle {
+            MemoryBufferAidl::Input(_) => (&mut self.current_input_memory_buffer, false),
+            MemoryBufferAidl::Output(_) => (&mut self.current_output_memory_buffer, true),
+        };
+        if current_memory_buffer.is_some() {
+            Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer already set"))
+        } else {
+            if parameters.sizeBytes < 0 {
+                Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer size is negative"))
+            } else {
+                // With the current behaviour, next check should not be needed, because we can only
+                // set up the current_memory_buffer once and we can only set the current_output_ref
+                // after setting a current output memory buffer. Leaving the check here in case the
+                // behavior changes in the future
+                if buffer_is_output {
+                    if let Some(OutputData::MemoryReference(_, _)) = current_output_ref {
+                        // If the current output is a buffer reference, we need to invalidate it
+                        return Err(hwcrypto_err!(BAD_PARAMETER, "This should not be possible with current flow, we need to invalidate the current output reference now."));
+                    }
+                }
+                *current_memory_buffer = Some(MemoryBuffer::new(parameters)?);
+                Ok(())
+            }
+        }
+    }
+
+    fn add_output_step<'a>(
+        &mut self,
+        output_parameters: &'a mut OperationData,
+    ) -> Result<OutputData<'a>, HwCryptoError> {
+        match output_parameters {
+            OperationData::DataBuffer(buf) => Ok(OutputData::DataBuffer(buf)),
+            OperationData::MemoryBufferReference(buffer_reference) => {
+                Ok(OutputData::MemoryReference(
+                    *buffer_reference,
+                    self.get_data_buffer_size(&MemoryBufferReferenceWithType::Output(
+                        (*buffer_reference).into(),
+                    ))?,
+                ))
+            }
+        }
+    }
+
+    fn finish_step(
+        &mut self,
+        current_output_ref: &mut Option<OutputData>,
+    ) -> Result<(), HwCryptoError> {
+        self.operation_step(None, current_output_ref, true, None)?;
+        self.current_crypto_operation = None;
+        Ok(())
+    }
+
+    fn input_step(
+        &mut self,
+        input_parameters: &mut OperationData,
+        current_output_ref: &mut Option<OutputData>,
+    ) -> Result<(), HwCryptoError> {
+        self.operation_step(Some(input_parameters), current_output_ref, false, None)
+    }
+
+    fn operation_step(
+        &mut self,
+        input_parameters: Option<&mut OperationData>,
+        current_output_ref: &mut Option<OutputData>,
+        is_finish: bool,
+        operation_impl: Option<&mut dyn ICryptographicOperation>,
+    ) -> Result<(), HwCryptoError> {
+        // Doing this check here to keep the borrow checker happy because the next step borrows self
+        // mutably. This is because even though it is an input, if it is a buffer reference, the
+        // available method could potentially be use to modify the underlying memory buffer.
+        if let Some(OutputData::MemoryReference(buff_ref, _)) = current_output_ref.as_ref() {
+            self.check_memory_reference_in_range(&MemoryBufferReferenceWithType::Output(
+                (*buff_ref).into(),
+            ))?;
+        }
+        // Creating a `DataToProcess` variable to abstract away where the input is located
+        let input = match input_parameters {
+            Some(OperationData::MemoryBufferReference(buffer_reference)) => Some({
+                let buffer_reference =
+                    MemoryBufferReferenceWithType::Input((*buffer_reference).into());
+                self.check_memory_reference_in_range(&buffer_reference)?;
+                let (input_start, _input_stop, input_size) = get_limits(&buffer_reference)?;
+                self.current_input_memory_buffer
+                    .as_mut()
+                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "input buffer not set yet"))?
+                    .get_subslice_as_data_to_process(input_start, input_size)?
+            }),
+            Some(OperationData::DataBuffer(input)) => Some(DataToProcess::Slice(&mut input[..])),
+            None => None,
+        };
+        if let Some(ref input) = input {
+            if input.len() == 0 {
+                return Err(hwcrypto_err!(BAD_PARAMETER, "received an input of size 0"));
+            }
+        }
+        let crypto_operation: &mut dyn ICryptographicOperation =
+            operation_impl.ok_or(()).or_else(|_| {
+                let crypto_operation = self
+                    .current_crypto_operation
+                    .as_mut()
+                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "crypto operation has not been set yet"))?;
+                if !crypto_operation.is_active() {
+                    return Err(hwcrypto_err!(BAD_PARAMETER, "operation is not active"));
+                }
+                Ok(&mut **crypto_operation)
+            })?;
+        let req_output_size = crypto_operation.get_operation_req_size(input.as_ref(), is_finish)?;
+
+        // Getting a reference to the output for the copy operation
+        match current_output_ref
+            .as_mut()
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "no output buffer available"))?
+        {
+            OutputData::DataBuffer(output_vec) => {
+                // We are saving data into a vector, as long as we can resize the vector we can fit
+                // the result
+                let original_size = output_vec.len();
+                let output_buff =
+                    DataToProcess::allocate_buffer_end_vector(*output_vec, req_output_size)?;
+                let added_bytes = crypto_operation.operation(input, output_buff, is_finish)?;
+                output_vec.truncate(original_size + added_bytes);
+            }
+            OutputData::MemoryReference(output_buff_ref, remaining_size) => {
+                if req_output_size > *remaining_size {
+                    return Err(hwcrypto_err!(ALLOCATION_ERROR, "run out of space output buffer"));
+                }
+                let (_output_start, output_stop, _output_size) =
+                    get_limits(&MemoryBufferReferenceWithType::Output((*output_buff_ref).into()))?;
+                // We are automatically filling up the output buffer with the received input, so
+                // the first available position will be equal to the end of the buffer minus the
+                // remaining space:
+                //
+                //         |---------------------_output_size------------------------------|
+                //         |--------used space--------|----------remaining_size------------|
+                //         |xxxxxxxxxxxxxxxxxxxxxxxxxx|====================================|
+                // _output_start                output_start_offset                    output_stop
+                //
+                let output_start_offset = output_stop - *remaining_size;
+                let output_slice = self
+                    .current_output_memory_buffer
+                    .as_mut()
+                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "output buffer not set yet"))?
+                    .get_subslice_as_data_to_process(output_start_offset, req_output_size)?;
+                let req_output_size = crypto_operation.operation(input, output_slice, is_finish)?;
+                *remaining_size = *remaining_size - req_output_size;
+            }
+        }
+        Ok(())
+    }
+
+    fn copy_step(
+        &mut self,
+        copy_parameters: &mut OperationData,
+        current_output_ref: &mut Option<OutputData>,
+    ) -> Result<(), HwCryptoError> {
+        self.operation_step(
+            Some(copy_parameters),
+            current_output_ref,
+            false,
+            Some(&mut CopyOperation),
+        )
+    }
+
+    fn destroy_step(
+        &mut self,
+        current_output_ref: &mut Option<OutputData>,
+    ) -> Result<(), HwCryptoError> {
+        self.current_input_memory_buffer = None;
+        self.current_output_memory_buffer = None;
+        self.current_crypto_operation = None;
+        *current_output_ref = None;
+        self.current_state = CmdProcessorState::Destroyed;
+        Ok(())
+    }
+
+    pub(crate) fn is_destroyed(&self) -> bool {
+        self.current_state == CmdProcessorState::Destroyed
+    }
+
+    fn set_operation_parameters_step(
+        &mut self,
+        crypto_operation_parameters: &OperationParameters,
+        _current_output_ref: &mut Option<OutputData>,
+    ) -> Result<(), HwCryptoError> {
+        let crypto_operation = CryptographicOperation::new_binder(crypto_operation_parameters)?;
+        self.current_crypto_operation = Some(crypto_operation);
+        Ok(())
+    }
+
+    pub(crate) fn process_all_steps(
+        &mut self,
+        operations: &mut [CryptoOperation],
+    ) -> Result<(), HwCryptoError> {
+        if operations.is_empty() {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "Cannot process list of length 0",));
+        }
+        let mut curr_output: Option<OutputData> = None;
+        for current_step in operations {
+            match self.current_state {
+                CmdProcessorState::InitialState => match current_step {
+                    CryptoOperation::DataOutput(step_data) => {
+                        curr_output = Some(self.add_output_step(step_data)?);
+                    }
+                    CryptoOperation::CopyData(step_data) => {
+                        self.copy_step(step_data, &mut curr_output)?;
+                    }
+                    CryptoOperation::DestroyContext(_) => self.destroy_step(&mut curr_output)?,
+                    CryptoOperation::SetMemoryBuffer(step_data) => {
+                        self.set_memory_buffer_step(&step_data, &mut curr_output)?
+                    }
+                    CryptoOperation::SetOperationParameters(step_data) => {
+                        self.current_state = CmdProcessorState::RunningOperation;
+                        self.set_operation_parameters_step(&step_data, &mut curr_output)?;
+                    }
+                    CryptoOperation::SetPattern(_) => {
+                        return Err(hwcrypto_err!(
+                            BAD_PARAMETER,
+                            "SetPattern not permitted before calling SetOperationParameters"
+                        ))
+                    }
+                    CryptoOperation::DataInput(_) => {
+                        return Err(hwcrypto_err!(
+                            BAD_PARAMETER,
+                            "DataInput not permitted before calling SetOperationParameters"
+                        ))
+                    }
+                    CryptoOperation::AadInput(_) => {
+                        return Err(hwcrypto_err!(
+                            BAD_PARAMETER,
+                            "AadInput not permitted before calling SetOperationParameters"
+                        ))
+                    }
+                    CryptoOperation::Finish(_) => {
+                        return Err(hwcrypto_err!(
+                            BAD_PARAMETER,
+                            "Finish not permitted before calling SetOperationParameters"
+                        ))
+                    }
+                },
+                CmdProcessorState::RunningOperation => match current_step {
+                    CryptoOperation::DataOutput(step_data) => {
+                        curr_output = Some(self.add_output_step(step_data)?);
+                    }
+                    CryptoOperation::CopyData(step_data) => {
+                        self.copy_step(step_data, &mut curr_output)?;
+                    }
+                    CryptoOperation::DestroyContext(_) => self.destroy_step(&mut curr_output)?,
+                    CryptoOperation::Finish(_step_data) => {
+                        self.current_state = CmdProcessorState::InitialState;
+                        self.finish_step(&mut curr_output)?;
+                    }
+                    CryptoOperation::SetPattern(_) => {
+                        unimplemented!("SetPattern not implemented yet")
+                    }
+                    CryptoOperation::DataInput(step_data) => {
+                        self.input_step(step_data, &mut curr_output)?;
+                    }
+                    CryptoOperation::AadInput(_) => unimplemented!("AadInput not implemented yet"),
+                    CryptoOperation::SetOperationParameters(_step) => unimplemented!(
+                        "SetOperationParameters from RunningOperation not implemented yet"
+                    ),
+                    CryptoOperation::SetMemoryBuffer(_) => {
+                        return Err(hwcrypto_err!(
+                        BAD_PARAMETER,
+                        "SetMemoryBuffer not permitted once SetOperationParameters has been called"
+                    ))
+                    }
+                },
+                CmdProcessorState::Destroyed => {
+                    return Err(hwcrypto_err!(
+                        BAD_PARAMETER,
+                        "Cannot send any command after DestroyContext"
+                    ));
+                }
+            }
+        }
+        Ok(())
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::opaque_key::OpaqueKey;
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+        types::{
+            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters, HalErrorCode,
+            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
+            SymmetricCryptoParameters::SymmetricCryptoParameters,
+            SymmetricOperation::SymmetricOperation,
+            SymmetricOperationParameters::SymmetricOperationParameters,
+        },
+        KeyPolicy::KeyPolicy,
+        OperationParameters::OperationParameters,
+        PatternParameters::PatternParameters,
+    };
+    use binder::ParcelFileDescriptor;
+    use core::ffi::c_void;
+    use std::alloc::{alloc_zeroed, dealloc, Layout};
+    use std::os::fd::{FromRawFd, OwnedFd};
+    use test::{expect, expect_eq};
+
+    /// Structure only intended to use on unit tests. It will allocate a single memory page and
+    /// create a memref to it.
+    struct TestPageAllocator {
+        allocated_buffer: *mut u8,
+        layout: Layout,
+        raw_trusty_fd: i64,
+        parcel_file_descriptor_created: bool,
+    }
+
+    impl TestPageAllocator {
+        fn new() -> Result<Self, HwCryptoError> {
+            let page_size = Self::get_allocation_size();
+            if page_size == 0 {
+                return Err(hwcrypto_err!(ALLOCATION_ERROR, "received zero as the page size"));
+            }
+            let layout = Layout::from_size_align(page_size, page_size).map_err(|e| {
+                hwcrypto_err!(
+                    GENERIC_ERROR,
+                    "layout creation error, should not have happened: {:?}",
+                    e
+                )
+            })?;
+            // SAFETY: Layout is non-zero
+            let allocated_buffer = unsafe {
+                let ptr = alloc_zeroed(layout);
+                ptr
+            };
+            // Always mapping things as output to change the buffer values for tests
+            let prot_flags = OUTPUT_MEMORY_BUFFER_FLAGS;
+            // SAFETY: address and size are correct because they came from the allocation.
+            let raw_trusty_fd = unsafe {
+                trusty_sys::memref_create(
+                    allocated_buffer as *mut c_void,
+                    page_size as u32,
+                    prot_flags,
+                )
+            };
+            if raw_trusty_fd < 0 {
+                return Err(hwcrypto_err!(ALLOCATION_ERROR, "memref creation failed"));
+            }
+            let parcel_file_descriptor_created = false;
+            Ok(Self {
+                allocated_buffer,
+                layout,
+                raw_trusty_fd: raw_trusty_fd.into(),
+                parcel_file_descriptor_created,
+            })
+        }
+
+        fn get_parcel_file_descriptor(&mut self) -> Result<ParcelFileDescriptor, HwCryptoError> {
+            if self.parcel_file_descriptor_created {
+                return Err(hwcrypto_err!(
+                    GENERIC_ERROR,
+                    "only a single parcel file descriptor can be created"
+                ));
+            }
+            // fd is valid if the object has been created and we can take ownership of it.
+            self.parcel_file_descriptor_created = true;
+            let fd = unsafe { OwnedFd::from_raw_fd(self.raw_trusty_fd as i32) };
+            Ok(ParcelFileDescriptor::new(fd))
+        }
+
+        fn get_allocation_size() -> usize {
+            // SAFETY: FFI call with all safe arguments.
+            let page_size = unsafe { libc::getauxval(libc::AT_PAGESZ) };
+            page_size as usize
+        }
+
+        fn copy_values(&mut self, start: usize, values: &[u8]) -> Result<(), HwCryptoError> {
+            if self.parcel_file_descriptor_created {
+                // There is already another reference to this memory area, don't allow to change it
+                // anymore through this method
+                return Err(hwcrypto_err!(GENERIC_ERROR, "copy_values is meant for initialization before creating any other references to this memory area"));
+            }
+            if start + values.len() > Self::get_allocation_size() {
+                return Err(hwcrypto_err!(BAD_PARAMETER, "input won't fit in buffer"));
+            }
+            // SAFETY: - value is valid for all the range that is read
+            //         - allocated_buffer[start, start + values.len()] is a valid area to write
+            //         - allocated_buffer and values are properly aligned because they are `u8`
+            //         - both areas do not overlap because allocated_buffer is a newly allocated
+            //           buffer and we do not have methods to get references to this area until
+            //           after this method is no longer valid.
+            unsafe {
+                self.allocated_buffer
+                    .wrapping_add(start)
+                    .copy_from_nonoverlapping(values.as_ptr(), values.len());
+            }
+            Ok(())
+        }
+    }
+
+    impl Drop for TestPageAllocator {
+        fn drop(&mut self) {
+            // SAFETY: `allocated_buffer` is valid and have been allocated by the same allocator.
+            //         layout was stored at allocation time, so it matches.
+            unsafe { dealloc(self.allocated_buffer, self.layout) };
+        }
+    }
+
+    fn read_slice(
+        memory_buffer: &MemoryBuffer,
+        buf: &mut [u8],
+        start: usize,
+    ) -> Result<(), HwCryptoError> {
+        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
+        //         operation would have failed. All accesses to this memory on this service are
+        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory
+        //         is only unmapped on drop, so it will available for the lifetime of the
+        //         `VolatileSlice`.
+        let mem_buffer = unsafe {
+            VolatileSlice::new(memory_buffer.buffer_ptr.0.as_ptr(), memory_buffer.total_size)
+        };
+        mem_buffer.read_slice(buf, start).map_err(HwCryptoError::from)
+    }
+
+    fn write_slice(
+        memory_buffer: &mut MemoryBuffer,
+        buf: &[u8],
+        start: usize,
+    ) -> Result<(), HwCryptoError> {
+        let mem_buffer = memory_buffer.get_memory_slice()?;
+        Ok(mem_buffer.write_slice(buf, start)?)
+    }
+
+    #[test]
+    fn create_memory_buffer() {
+        let mut output_page = TestPageAllocator::new().expect("couldn't allocate test page");
+        output_page.copy_values(0, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
+
+        let total_buffer_size = TestPageAllocator::get_allocation_size();
+        let mem_buffer_parameters = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: total_buffer_size as i32,
+        };
+        let mut memory_buffer =
+            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't createa memory buffer");
+
+        let mut slice = vec![0; 5];
+
+        read_slice(&memory_buffer, &mut slice[0..2], 1).expect("couldn't get slice");
+        expect_eq!(&slice[0..2], &[2, 3], "wrong value retrieved through slice");
+
+        read_slice(&memory_buffer, &mut slice[0..1], 8).expect("couldn't get slice");
+        expect_eq!(&slice[0..1], &[9], "wrong value retrieved through slice");
+
+        let result = read_slice(&memory_buffer, &mut slice[0..2], total_buffer_size - 1);
+        expect!(result.is_err(), "Shouldn't be able to get slice with end out of range");
+
+        let result = read_slice(&memory_buffer, &mut slice[0..1], total_buffer_size);
+        expect!(result.is_err(), "Shouldn't be able to get slice with start out of range");
+
+        read_slice(&memory_buffer, &mut slice[0..1], 0).expect("couldn't get slice");
+        expect_eq!(&slice[0..1], &[1], "wrong value retrieved through slice");
+
+        read_slice(&memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
+        expect_eq!(&slice[0..3], &[5, 6, 7], "wrong value retrieved through slice");
+
+        write_slice(&mut memory_buffer, &[55], 5).expect("couldn't write slice");
+        read_slice(&memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
+        expect_eq!(&slice[0..3], &[5, 55, 7], "wrong value retrieved through slice");
+
+        read_slice(&memory_buffer, &mut slice[0..5], 3).expect("couldn't get slice");
+        expect_eq!(&slice[0..5], &[4, 5, 55, 7, 8], "wrong value retrieved through slice");
+    }
+
+    #[test]
+    fn create_output_data_references() {
+        let mut output_page = TestPageAllocator::new().expect("couldn't allocate test page");
+        let total_buffer_size = TestPageAllocator::get_allocation_size();
+        let mem_buffer_parameters = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: total_buffer_size as i32,
+        };
+
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(mem_buffer_parameters));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process SetMemoryBuffer command");
+        let mem_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
+        cmd_list
+            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));
+
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process valid memory reference");
+
+        let mem_ref = MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 1 };
+        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_err(),
+            "Shouldn't be able to process reference outside of buffer"
+        );
+
+        let mem_ref = MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 0 };
+        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_err(),
+            "Shouldn't be able to process reference outside of buffer"
+        );
+
+        let mem_ref = MemoryBufferReference { startOffset: 3, sizeBytes: 0 };
+        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to process 0 size references");
+
+        let mem_ref =
+            MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 1 };
+        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_ok(),
+            "Couldn't process a valid memory reference, len {}",
+            cmd_list.len()
+        );
+
+        let mem_ref =
+            MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 2 };
+        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_err(),
+            "Shouldn't be able to process reference that falls out of range"
+        );
+    }
+
+    #[test]
+    fn parse_empty_cmd_list() {
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        match &process_result {
+            Err(e) => expect!(
+                e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
+                "should have received a BAD_PARAMETER error"
+            ),
+            Ok(_) => expect!(process_result.is_err(), "Should have received an error"),
+        };
+
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        match &process_result {
+            Err(e) => expect!(
+                e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
+                "should have received a BAD_PARAMETER error"
+            ),
+            Ok(_) => expect!(process_result.is_err(), "Should have received an error"),
+        };
+    }
+
+    #[test]
+    fn parse_cmd_list_single_item() {
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+    }
+
+    #[test]
+    fn invalid_operations_initial_state() {
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new())));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on initial state");
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new())));
+
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on initial state");
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
+        cmd_list.push(CryptoOperation::SetPattern(pattern_params));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on initial state");
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call Finish on initial state");
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Should be able to call DataOutput");
+    }
+
+    #[test]
+    fn invalid_operations_destroyed_state() {
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::DestroyContext(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Should be able to call DestroyContext");
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call DataOutput on destroyed state");
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[1] = CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new()));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on destroyed state");
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[1] = CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new()));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on destroyed state");
+        let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
+        cmd_list[1] = CryptoOperation::SetPattern(pattern_params);
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on destroyed state");
+        cmd_list[1] = CryptoOperation::Finish(None);
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to call Finish on destroyed state");
+        let policy = KeyPolicy {
+            usage: KeyUse::SIGN,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_128_CBC_NO_PADDING,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy);
+        expect!(key.is_ok(), "couldn't generate key");
+        let key = key.unwrap();
+        let mode = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: [0; 16],
+        }));
+        let op_parameters = SymmetricOperationParameters {
+            key: Some(key),
+            direction: SymmetricOperation::ENCRYPT,
+            parameters: mode,
+        };
+        cmd_list[1] = CryptoOperation::SetOperationParameters(
+            OperationParameters::SymmetricCrypto(op_parameters),
+        );
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_err(),
+            "Shouldn't be able to call SetOperationParameters on destroyed state"
+        );
+    }
+
+    #[test]
+    fn check_output_step_length() {
+        let alloc_size = TestPageAllocator::get_allocation_size();
+        let mut output_page = TestPageAllocator::new().expect("couldn't create test page");
+        let output_memory_buffer = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't get fd"),
+            )),
+            sizeBytes: alloc_size as i32,
+        };
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(output_memory_buffer));
+        let output_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
+        cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
+            output_reference,
+        )));
+        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let mut read_slice_val = vec![55; 9];
+        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        expect_eq!(
+            &read_slice_val[..],
+            &[1, 2, 3, 0, 0, 0, 0, 0, 0],
+            "unexpected values after copy"
+        );
+
+        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(
+            process_result.is_err(),
+            "Command should have failed because we run out of output buffer"
+        );
+        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        expect_eq!(
+            &read_slice_val[..],
+            &[1, 2, 3, 0, 0, 0, 0, 0, 0],
+            "unexpected values after failed copy"
+        );
+    }
+
+    #[test]
+    fn output_step_out_range() {
+        let alloc_size = TestPageAllocator::get_allocation_size();
+        let mut output_page = TestPageAllocator::new().expect("couldn't get test page");
+        let output_memory_buffer = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't get fd"),
+            )),
+            sizeBytes: alloc_size as i32,
+        };
+        let mut input_page = TestPageAllocator::new().expect("couldn't get test page");
+        let input_memory_buffer = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Input(Some(
+                input_page.get_parcel_file_descriptor().expect("couldn't get fd"),
+            )),
+            sizeBytes: alloc_size as i32,
+        };
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(output_memory_buffer));
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(input_memory_buffer));
+        let output_reference =
+            MemoryBufferReference { startOffset: 0, sizeBytes: (alloc_size + 4) as i32 };
+        cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
+            output_reference,
+        )));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "shouldn't be able to add an output outside of range");
+        let output_reference =
+            MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
+        cmd_list[2] =
+            CryptoOperation::DataOutput(OperationData::MemoryBufferReference(output_reference));
+        let input_reference =
+            MemoryBufferReference { startOffset: 0, sizeBytes: (alloc_size + 4) as i32 };
+        cmd_list
+            .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "shouldn't be able to add an input ref outside of range");
+        let input_reference =
+            MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
+        cmd_list[3] =
+            CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "operation should have succeeded");
+    }
+
+    #[test]
+    fn memory_reference_copy_operation_on_initial_state() {
+        let alloc_size = TestPageAllocator::get_allocation_size();
+        let mut output_page = TestPageAllocator::new().expect("couldn't get test page");
+        let output_memory_buffer = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't get fd"),
+            )),
+            sizeBytes: alloc_size as i32,
+        };
+        let mut input_page = TestPageAllocator::new().expect("couldn't get test page");
+        input_page.copy_values(0, &[7, 8, 9]).unwrap();
+        let input_memory_buffer = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Input(Some(
+                input_page.get_parcel_file_descriptor().expect("couldn't get fd"),
+            )),
+            sizeBytes: alloc_size as i32,
+        };
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(output_memory_buffer));
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(input_memory_buffer));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let mut read_slice_val = vec![55; 9];
+        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        expect_eq!(&read_slice_val[..], &[0, 0, 0, 0, 0, 0, 0, 0, 0], "initial values where not 0");
+        let mut cmd_processor = CmdProcessorContext::new();
+        let output_reference =
+            MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
+        cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
+            output_reference,
+        )));
+        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        expect_eq!(&read_slice_val[..], &[1, 2, 3, 0, 0, 0, 0, 0, 0], "initial values where not 0");
+        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        expect_eq!(&read_slice_val[..], &[1, 2, 3, 4, 5, 6, 0, 0, 0], "initial values where not 0");
+        let input_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
+        cmd_list
+            .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
+        let mut cmd_processor = CmdProcessorContext::new();
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        cmd_list.clear();
+        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        expect_eq!(&read_slice_val[..], &[1, 2, 3, 4, 5, 6, 7, 8, 9], "initial values where not 0");
+    }
+
+    #[test]
+    fn simple_copy_operation_on_initial_state() {
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Shouldn't be able to copy before adding an output");
+        cmd_list.insert(0, CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process commands");
+        expect!(process_result.is_ok(), "Couldn't process second copy command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
+            unreachable!("should not happen beucase we created the cmd list on the test");
+        };
+        expect_eq!(output, &[1, 2, 3, 4, 5, 6], "values were not copied correctly");
+    }
+
+    #[test]
+    fn simple_copy_opeartion_on_initial_state_buffer_reference_input() {
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        let mut input_page = TestPageAllocator::new().expect("couldn't create test page");
+        input_page.copy_values(0, &[2, 4, 8, 3, 6, 9]).unwrap();
+        let input_memory_buffer = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Input(Some(
+                input_page.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: TestPageAllocator::get_allocation_size() as i32,
+        };
+        cmd_list.push(CryptoOperation::SetMemoryBuffer(input_memory_buffer));
+        let input_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 as i32 };
+        cmd_list
+            .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
+        let input_reference = MemoryBufferReference { startOffset: 3, sizeBytes: 3 as i32 };
+        //cmd_list
+        //    .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
+            unreachable!("should not happen beucase we created the cmd list on the test");
+        };
+        expect_eq!(output, &[2, 4, 8], "values were not copied correctly");
+        let mut cmd_processor = CmdProcessorContext::new();
+        cmd_list[2] =
+            CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process second copy command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
+            unreachable!("should not happen beucase we created the cmd list on the test");
+        };
+        expect_eq!(output, &[2, 4, 8, 3, 6, 9], "values were not copied correctly");
+    }
+
+    #[test]
+    fn aes_simple_test() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
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
+        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
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
+        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
+    }
+}
diff --git a/hwcryptohal/server/crypto_operation.rs b/hwcryptohal/server/crypto_operation.rs
new file mode 100644
index 0000000..2346af9
--- /dev/null
+++ b/hwcryptohal/server/crypto_operation.rs
@@ -0,0 +1,655 @@
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
+//! Module providing a shim for the different crypto operations.
+
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    OperationParameters::OperationParameters,
+};
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+    SymmetricCryptoParameters::SymmetricCryptoParameters,
+    SymmetricOperation::SymmetricOperation,
+};
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use kmr_common::crypto::{self, Aes, KeyMaterial, SymmetricOperation as CryptoSymmetricOperation};
+use vm_memory::Bytes;
+
+use crate::cmd_processing::DataToProcess;
+use crate::crypto_provider;
+use crate::helpers;
+use crate::opaque_key::OpaqueKey;
+
+pub(crate) trait ICryptographicOperation: Send {
+    // Returns the required minimum size in bytes the output buffer needs to have for the given
+    // `input`
+    fn get_operation_req_size(
+        &self,
+        input: Option<&DataToProcess>,
+        is_finish: bool,
+    ) -> Result<usize, HwCryptoError>;
+
+    fn operation<'a>(
+        &mut self,
+        input: Option<DataToProcess<'a>>,
+        output: DataToProcess<'a>,
+        is_finish: bool,
+    ) -> Result<usize, HwCryptoError>;
+
+    fn is_active(&self) -> bool;
+
+    #[allow(dead_code)]
+    fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
+        Err(hwcrypto_err!(
+            BAD_PARAMETER,
+            "update aad only valid for authenticated symmetric operations"
+        ))
+    }
+}
+
+trait IBaseCryptoOperation: Send {
+    fn update(
+        &mut self,
+        input: &DataToProcess,
+        output: &mut DataToProcess,
+    ) -> Result<usize, HwCryptoError>;
+
+    fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError>;
+
+    fn get_req_size_finish(&self) -> Result<usize, HwCryptoError>;
+
+    fn get_req_size_update(&self, input: &DataToProcess) -> Result<usize, HwCryptoError>;
+
+    fn is_active(&self) -> bool;
+
+    fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
+        Err(hwcrypto_err!(
+            BAD_PARAMETER,
+            "update aad only valid for authenticated symmetric operations"
+        ))
+    }
+}
+
+impl<T: IBaseCryptoOperation> ICryptographicOperation for T {
+    fn get_operation_req_size(
+        &self,
+        input: Option<&DataToProcess>,
+        is_finish: bool,
+    ) -> Result<usize, HwCryptoError> {
+        if is_finish {
+            self.get_req_size_finish()
+        } else {
+            let input =
+                input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+            self.get_req_size_update(input)
+        }
+    }
+
+    fn operation(
+        &mut self,
+        input: Option<DataToProcess>,
+        mut output: DataToProcess,
+        is_finish: bool,
+    ) -> Result<usize, HwCryptoError> {
+        if is_finish {
+            self.finish(&mut output)
+        } else {
+            let input =
+                input.as_ref().ok_or(hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+            self.update(&input, &mut output)
+        }
+    }
+
+    fn is_active(&self) -> bool {
+        self.is_active()
+    }
+
+    fn update_aad(&mut self, input: &DataToProcess) -> Result<(), HwCryptoError> {
+        self.update_aad(input)
+    }
+}
+
+// Newtype used because the traits we currently use for cryptographic operations cannot directly
+// either process `VolatileSlice`s or use pointers to memory, so we need to make a copy of the data.
+// TODO: refactor traits to not require copying the input for VolatileSlices
+struct TempBuffer(Vec<u8>);
+
+impl TempBuffer {
+    fn new() -> Self {
+        TempBuffer(Vec::new())
+    }
+
+    fn get_buffer_reference<'a>(
+        &'a mut self,
+        input: &'a DataToProcess,
+    ) -> Result<&'a [u8], HwCryptoError> {
+        match input {
+            DataToProcess::Slice(slice) => Ok(slice),
+            DataToProcess::VolatileSlice(slice) => {
+                self.0.clear();
+                let slice_len = slice.len();
+                self.0.try_reserve(slice_len)?;
+                // Addition should be safe because try_reserve didn't fail
+                self.0.resize_with(slice_len, Default::default);
+                slice.read_slice(&mut self.0, 0)?;
+                Ok(&self.0[..])
+            }
+        }
+    }
+}
+
+#[allow(dead_code)]
+pub(crate) struct AesOperation {
+    opaque_key: OpaqueKey,
+    emitting_op: Option<Box<dyn crypto::EmittingOperation>>,
+    dir: CryptoSymmetricOperation,
+    remaining_unaligned_data_size: usize,
+    block_based_encryption: bool,
+}
+
+impl AesOperation {
+    fn new(
+        opaque_key: OpaqueKey,
+        dir: SymmetricOperation,
+        parameters: &SymmetricCryptoParameters,
+    ) -> Result<Self, HwCryptoError> {
+        AesOperation::check_cipher_parameters(&opaque_key, dir, parameters)?;
+        let key_material = &opaque_key.key_material;
+        let dir = helpers::aidl_to_rust_symmetric_direction(dir)?;
+        let emitting_op = match key_material {
+            KeyMaterial::Aes(key) => {
+                let aes = crypto_provider::AesImpl;
+                let mode = helpers::aidl_to_rust_aes_cipher_params(parameters, &opaque_key)?;
+                aes.begin(key.clone(), mode, dir).map_err(|e| {
+                    hwcrypto_err!(GENERIC_ERROR, "couldn't begin aes operation: {:?}", e)
+                })
+            }
+            _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for AES symmetric operation")),
+        }?;
+        let block_based_encryption = helpers::symmetric_encryption_block_based(parameters)?;
+        let aes_operation = Self {
+            opaque_key,
+            emitting_op: Some(emitting_op),
+            dir,
+            remaining_unaligned_data_size: 0,
+            block_based_encryption,
+        };
+        Ok(aes_operation)
+    }
+
+    fn check_cipher_parameters(
+        opaque_key: &OpaqueKey,
+        dir: SymmetricOperation,
+        parameters: &SymmetricCryptoParameters,
+    ) -> Result<(), HwCryptoError> {
+        opaque_key.symmetric_operation_is_compatible(dir)?;
+        opaque_key.parameters_are_compatible_symmetric_cipher(parameters)
+    }
+
+    // Returns the size required to process the current block and how much extra data was cached for
+    // a future call
+    fn get_update_req_size_with_remainder(
+        &self,
+        input: &DataToProcess,
+    ) -> Result<(usize, usize), HwCryptoError> {
+        let input_size = input.len();
+        self.get_req_size_from_len(input_size)
+    }
+
+    fn get_req_size_from_len(&self, input_len: usize) -> Result<(usize, usize), HwCryptoError> {
+        if self.block_based_encryption {
+            match self.dir {
+                CryptoSymmetricOperation::Encrypt => {
+                    let input_size = input_len + self.remaining_unaligned_data_size;
+                    let extra_data_len = input_size % crypto::aes::BLOCK_SIZE;
+                    Ok((input_size - extra_data_len, extra_data_len))
+                }
+                CryptoSymmetricOperation::Decrypt => {
+                    Ok((AesOperation::round_to_block_size(input_len), 0))
+                }
+            }
+        } else {
+            Ok((input_len, 0))
+        }
+    }
+
+    fn round_to_block_size(size: usize) -> usize {
+        ((size + crypto::aes::BLOCK_SIZE - 1) / crypto::aes::BLOCK_SIZE) * crypto::aes::BLOCK_SIZE
+    }
+}
+
+impl IBaseCryptoOperation for AesOperation {
+    fn update(
+        &mut self,
+        input: &DataToProcess,
+        output: &mut DataToProcess,
+    ) -> Result<usize, HwCryptoError> {
+        let (req_size, unaligned_size) = self.get_update_req_size_with_remainder(input)?;
+        if output.len() != req_size {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
+        }
+        let op = self
+            .emitting_op
+            .as_mut()
+            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
+        // TODO: refactor traits to not require copying the input for VolatileSlices
+        let mut input_buffer = TempBuffer::new();
+        let input_data = input_buffer.get_buffer_reference(input)?;
+        let output_data = op.update(input_data)?;
+        let output_len = output_data.len();
+        output.copy_slice(output_data.as_slice())?;
+        self.remaining_unaligned_data_size = unaligned_size;
+        Ok(output_len)
+    }
+
+    fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError> {
+        let op = self
+            .emitting_op
+            .take()
+            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
+        let req_size = self.get_req_size_finish()?;
+        if output.len() != req_size {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
+        }
+        let output_data = op.finish()?;
+        let output_len = output_data.len();
+        output.copy_slice(output_data.as_slice())?;
+        self.remaining_unaligned_data_size = 0;
+        Ok(output_len)
+    }
+
+    fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
+        unimplemented!("GCM AES note supported yet");
+    }
+
+    fn get_req_size_finish(&self) -> Result<usize, HwCryptoError> {
+        let (req_size_to_process, _) = self.get_req_size_from_len(0)?;
+        match self.dir {
+            CryptoSymmetricOperation::Encrypt => Ok(req_size_to_process + crypto::aes::BLOCK_SIZE),
+            CryptoSymmetricOperation::Decrypt => Ok(crypto::aes::BLOCK_SIZE),
+        }
+    }
+
+    fn get_req_size_update(&self, input: &DataToProcess) -> Result<usize, HwCryptoError> {
+        let (req_size, _) = self.get_update_req_size_with_remainder(input)?;
+        Ok(req_size)
+    }
+
+    fn is_active(&self) -> bool {
+        self.emitting_op.is_some()
+    }
+}
+
+pub(crate) struct CopyOperation;
+
+impl ICryptographicOperation for CopyOperation {
+    fn get_operation_req_size(
+        &self,
+        input: Option<&DataToProcess>,
+        _is_finish: bool,
+    ) -> Result<usize, HwCryptoError> {
+        let input = input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+        Ok(input.len())
+    }
+
+    fn operation<'a>(
+        &mut self,
+        input: Option<DataToProcess<'a>>,
+        mut output: DataToProcess<'a>,
+        _is_finish: bool,
+    ) -> Result<usize, HwCryptoError> {
+        let num_bytes_copy = self.get_operation_req_size(input.as_ref(), false)?;
+        let input = input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+        output.copy_from_slice(&input)?;
+        Ok(num_bytes_copy)
+    }
+
+    fn is_active(&self) -> bool {
+        true
+    }
+}
+
+pub(crate) struct CryptographicOperation;
+
+impl CryptographicOperation {
+    pub(crate) fn new_binder(
+        crypto_operation_parameters: &OperationParameters,
+    ) -> Result<Box<dyn ICryptographicOperation>, HwCryptoError> {
+        match crypto_operation_parameters {
+            OperationParameters::SymmetricCrypto(symmetric_params) => {
+                if let Some(key) = &symmetric_params.key {
+                    let opaque_key: OpaqueKey = key.try_into()?;
+                    let dir = symmetric_params.direction;
+                    let parameters = &symmetric_params.parameters;
+                    AesOperation::check_cipher_parameters(&opaque_key, dir, parameters)?;
+                    let aes_operation = AesOperation::new(opaque_key, dir, parameters)?;
+                    Ok(Box::new(aes_operation))
+                } else {
+                    Err(hwcrypto_err!(BAD_PARAMETER, "key was null"))
+                }
+            }
+            _ => unimplemented!("operation not implemented yet"),
+        }
+    }
+}
+
+// Implementing ICryptographicOperation for () to use it as a type for when we need to pass a `None`
+// on an `Option<&impl ICryptographicOperation>`
+impl ICryptographicOperation for () {
+    fn get_operation_req_size(
+        &self,
+        _input: Option<&DataToProcess>,
+        _is_finish: bool,
+    ) -> Result<usize, HwCryptoError> {
+        Err(hwcrypto_err!(UNSUPPORTED, "cannot get size for null operation"))
+    }
+
+    fn operation(
+        &mut self,
+        _input: Option<DataToProcess>,
+        mut _output: DataToProcess,
+        _is_finish: bool,
+    ) -> Result<usize, HwCryptoError> {
+        Err(hwcrypto_err!(UNSUPPORTED, "nothing to execute on null operation"))
+    }
+
+    fn is_active(&self) -> bool {
+        false
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+        AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
+        KeyLifetime::KeyLifetime,
+        KeyType::KeyType, KeyUse::KeyUse,
+        SymmetricCryptoParameters::SymmetricCryptoParameters,
+        SymmetricOperation::SymmetricOperation,
+        SymmetricOperationParameters::SymmetricOperationParameters,
+    };
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+        KeyPolicy::KeyPolicy,
+    };
+    use test::{expect, expect_eq};
+
+    #[test]
+    fn use_aes_key() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let handle = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(handle.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let input_to_encrypt = "hello world1234";
+        let mut input_data = input_to_encrypt.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut op =
+            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
+        let mut output_data = vec![];
+        let output_slice = DataToProcess::Slice(&mut output_data[..]);
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        expect_eq!(written_bytes, 0, "Written bytes for encryptiong less than a block should be 0");
+        let req_size_finish =
+            op.get_operation_req_size(None, true).expect("couldn't get required_size");
+        expect_eq!(
+            req_size_finish,
+            16,
+            "Required size for encryptiong less than a block should be a block"
+        );
+        output_data.append(&mut vec![0u8; 16]);
+        let output_slice = DataToProcess::Slice(&mut output_data[..]);
+        op.operation(None, output_slice, true).expect("couldn't finish");
+        let output_slice = DataToProcess::Slice(&mut output_data[0..0]);
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let update_op = op.operation(Some(input_slice), output_slice, false);
+        expect!(update_op.is_err(), "shouldn't be able to run operations anymore");
+        let output_slice = DataToProcess::Slice(&mut output_data[0..0]);
+        let finish_op = op.operation(None, output_slice, true);
+        expect!(finish_op.is_err(), "shouldn't be able to run operations anymore");
+        let direction = SymmetricOperation::DECRYPT;
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(handle), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut op =
+            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
+        let output_slice = DataToProcess::Slice(&mut output_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&output_slice), false)
+            .expect("couldn't get required_size");
+        let mut decrypted_data = vec![0; req_size];
+        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[..]);
+        let mut decrypted_data_size =
+            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        let decrypted_data_start = decrypted_data_size;
+        let req_size_finish =
+            op.get_operation_req_size(None, true).expect("couldn't get required_size");
+        let decrypted_data_end = decrypted_data_size + req_size_finish;
+        let decrypted_slice =
+            DataToProcess::Slice(&mut decrypted_data[decrypted_data_start..decrypted_data_end]);
+        let total_finish_size = op.operation(None, decrypted_slice, true).expect("couldn't finish");
+        decrypted_data_size += total_finish_size;
+        decrypted_data.truncate(decrypted_data_size);
+        expect_eq!(input_to_encrypt.len(), decrypted_data_size, "bad length for decrypted data");
+        let decrypted_str = String::from_utf8(decrypted_data).unwrap();
+        expect_eq!(input_to_encrypt, decrypted_str, "bad data decrypted");
+    }
+
+    #[test]
+    fn process_aes_encrypt_decrypt_operations() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let handle = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(handle.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut op =
+            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
+        let input_to_encrypt = "test encryption string";
+        let mut input_data = input_to_encrypt.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
+        let mut output_data = vec![0; 200];
+        let output_slice = DataToProcess::Slice(&mut output_data[..req_size]);
+        let mut total_encryption_size = 0;
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        total_encryption_size += written_bytes;
+        expect_eq!(written_bytes, 16, "A block should have been encrypted");
+        let input_to_encrypt_2 = " for this ";
+        let mut input_data = input_to_encrypt_2.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        let output_start = written_bytes;
+        let output_stop = written_bytes + req_size;
+        expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
+        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_stop]);
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        expect_eq!(written_bytes, 16, "A block should have been encrypted");
+        total_encryption_size += written_bytes;
+        let output_start = output_start + written_bytes;
+        let input_to_encrypt_3 = "test";
+        let mut input_data = input_to_encrypt_3.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
+        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_start]);
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        total_encryption_size += written_bytes;
+        expect_eq!(written_bytes, 0, "No bytes should have been written");
+        let input_to_encrypt_4 = " is";
+        let mut input_data = input_to_encrypt_4.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
+        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_start]);
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        expect_eq!(written_bytes, 0, "No bytes should have been written");
+        total_encryption_size += written_bytes;
+        let input_to_encrypt_5 = " a ";
+        let mut input_data = input_to_encrypt_5.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
+        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_start]);
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        expect_eq!(written_bytes, 0, "No bytes should have been written");
+        total_encryption_size += written_bytes;
+        let input_to_encrypt_6 = "random one.";
+        let mut input_data = input_to_encrypt_6.as_bytes().to_vec();
+        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let req_size = op
+            .get_operation_req_size(Some(&input_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
+        let output_stop = output_start + req_size;
+        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_stop]);
+        let written_bytes =
+            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        total_encryption_size += written_bytes;
+        expect_eq!(written_bytes, 16, "A block should have been encrypted");
+        let output_start = output_start + written_bytes;
+        let req_size_finish =
+            op.get_operation_req_size(None, true).expect("couldn't get required_size");
+        expect_eq!(
+            req_size_finish,
+            16,
+            "Required size for encryptiong less than a block should be a block"
+        );
+        let output_stop = output_start + req_size_finish;
+        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_stop]);
+        let finish_written_bytes = op.operation(None, output_slice, true).expect("couldn't finish");
+        expect_eq!(finish_written_bytes, 16, "With padding we should have written a block");
+        total_encryption_size += finish_written_bytes;
+        output_data.truncate(total_encryption_size);
+        // Decrypting
+        let mut decrypted_data_size = 0;
+        let direction = SymmetricOperation::DECRYPT;
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(handle), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut op =
+            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
+        let mut decrypted_data = vec![0; total_encryption_size];
+        let output_slice = DataToProcess::Slice(&mut output_data[..4]);
+        let req_size = op
+            .get_operation_req_size(Some(&output_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 16, "worse case space for this size of input is a block");
+        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[..16]);
+        let written_bytes =
+            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        decrypted_data_size += written_bytes;
+        expect_eq!(written_bytes, 0, "No bytes should have been written");
+        let output_slice = DataToProcess::Slice(&mut output_data[4..32]);
+        let req_size = op
+            .get_operation_req_size(Some(&output_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 32, "worse case space for this size of input is 2 blocks");
+        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[..32]);
+        let written_bytes =
+            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        decrypted_data_size += written_bytes;
+        expect_eq!(written_bytes, 16, "One block should have been written");
+        let output_slice = DataToProcess::Slice(&mut output_data[32..50]);
+        let req_size = op
+            .get_operation_req_size(Some(&output_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 32, "worse case space for this size of input is 2 blocks");
+        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[16..48]);
+        let written_bytes =
+            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        decrypted_data_size += written_bytes;
+        expect_eq!(written_bytes, 32, "Two block should have been written");
+        let output_slice = DataToProcess::Slice(&mut output_data[50..64]);
+        let req_size = op
+            .get_operation_req_size(Some(&output_slice), false)
+            .expect("couldn't get required_size");
+        expect_eq!(req_size, 16, "worse case space for this size of input is 1 block");
+        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[48..64]);
+        let written_bytes =
+            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        decrypted_data_size += written_bytes;
+        expect_eq!(written_bytes, 0, "No blocks should have been written");
+        let req_size_finish =
+            op.get_operation_req_size(None, true).expect("couldn't get required_size");
+        expect_eq!(req_size_finish, 16, "Max size required to finish should be 1 block");
+        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[48..64]);
+        let total_finish_size = op.operation(None, decrypted_slice, true).expect("couldn't finish");
+        decrypted_data_size += total_finish_size;
+        decrypted_data.truncate(decrypted_data_size);
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode receivedd message");
+        let original_msg = input_to_encrypt.to_owned()
+            + input_to_encrypt_2
+            + input_to_encrypt_3
+            + input_to_encrypt_4
+            + input_to_encrypt_5
+            + input_to_encrypt_6;
+        expect_eq!(original_msg.len(), decrypted_msg.len(), "bad length for decrypted data");
+        expect_eq!(original_msg, decrypted_msg, "bad data decrypted");
+    }
+}
diff --git a/hwcryptohal/server/crypto_operation_context.rs b/hwcryptohal/server/crypto_operation_context.rs
new file mode 100644
index 0000000..02765c2
--- /dev/null
+++ b/hwcryptohal/server/crypto_operation_context.rs
@@ -0,0 +1,89 @@
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
+//! Implementation of the `ICryptoOperationContext` AIDL interface. It can be used to execute more
+//! commands over the same context.
+
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    CryptoOperation::CryptoOperation, ICryptoOperationContext::BnCryptoOperationContext,
+    ICryptoOperationContext::ICryptoOperationContext,
+};
+use binder::binder_impl::Binder;
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use std::sync::Mutex;
+
+use crate::cmd_processing::CmdProcessorContext;
+
+/// The `ICryptoOperationContext` implementation.
+pub struct CryptoOperationContext {
+    cmd_processor: Mutex<CmdProcessorContext>,
+}
+
+impl binder::Interface for CryptoOperationContext {}
+
+impl CryptoOperationContext {
+    pub(crate) fn new_binder(
+        cmd_processor: CmdProcessorContext,
+    ) -> binder::Strong<dyn ICryptoOperationContext> {
+        let hwcrypto_key = CryptoOperationContext { cmd_processor: Mutex::new(cmd_processor) };
+        BnCryptoOperationContext::new_binder(hwcrypto_key, binder::BinderFeatures::default())
+    }
+}
+
+impl ICryptoOperationContext for CryptoOperationContext {}
+
+pub(crate) struct BinderCryptoOperationContext(binder::Strong<dyn ICryptoOperationContext>);
+
+impl From<binder::Strong<dyn ICryptoOperationContext>> for BinderCryptoOperationContext {
+    fn from(value: binder::Strong<dyn ICryptoOperationContext>) -> Self {
+        Self(value)
+    }
+}
+
+impl From<BinderCryptoOperationContext> for binder::Strong<dyn ICryptoOperationContext> {
+    fn from(value: BinderCryptoOperationContext) -> Self {
+        value.0
+    }
+}
+
+impl BinderCryptoOperationContext {
+    pub(crate) fn process_all_steps(
+        &self,
+        operations: &mut [CryptoOperation],
+    ) -> Result<(), HwCryptoError> {
+        let binder = self.0.as_binder();
+        if binder.is_remote() {
+            return Err(hwcrypto_err!(GENERIC_ERROR, "binder is not local"));
+        }
+        let native_context: Binder<BnCryptoOperationContext> = binder.try_into().map_err(|e| {
+            hwcrypto_err!(GENERIC_ERROR, "shouldn't fail because binder is local {:?}", e)
+        })?;
+        let mut cmd_processor = native_context
+            .downcast_binder::<CryptoOperationContext>()
+            .ok_or(hwcrypto_err!(GENERIC_ERROR, "couldn't cast back operation context"))?
+            .cmd_processor
+            .lock()
+            .map_err(|e| {
+                hwcrypto_err!(
+                    GENERIC_ERROR,
+                    "poisoned mutex, shold not happen on a single thread application: {:?}",
+                    e
+                )
+            })?;
+        cmd_processor.process_all_steps(operations)?;
+        Ok(())
+    }
+}
diff --git a/hwcryptohal/server/helpers.rs b/hwcryptohal/server/helpers.rs
index 500d4cf..b1972a6 100644
--- a/hwcryptohal/server/helpers.rs
+++ b/hwcryptohal/server/helpers.rs
@@ -16,40 +16,103 @@
 
 //! Helper functions that includes data transformation for AIDL types.
 
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
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+    AesCipherMode::AesCipherMode, AesKey::AesKey, CipherModeParameters::CipherModeParameters,
+    ExplicitKeyMaterial::ExplicitKeyMaterial, KeyType::KeyType, KeyUse::KeyUse,
+    SymmetricCryptoParameters::SymmetricCryptoParameters, SymmetricOperation::SymmetricOperation,
+};
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use kmr_common::crypto::{
+    self, aes, KeyMaterial, OpaqueOr, SymmetricOperation as KmSymmetricOperation,
+};
+
+use crate::opaque_key::OpaqueKey;
+
+pub(crate) fn aidl_explicit_key_to_rust_key_material(
+    key_material: &ExplicitKeyMaterial,
+) -> Result<KeyMaterial, HwCryptoError> {
+    match key_material {
+        ExplicitKeyMaterial::Aes(AesKey::Aes128(km)) => {
+            Ok(KeyMaterial::Aes(OpaqueOr::Explicit(aes::Key::Aes128(*km))))
         }
+        ExplicitKeyMaterial::Aes(AesKey::Aes256(km)) => {
+            Ok(KeyMaterial::Aes(OpaqueOr::Explicit(aes::Key::Aes256(*km))))
+        }
+    }
+}
 
-        impl TryFrom<i64> for $name {
-            type Error = hwcryptohal_common::err::HwCryptoError;
+pub(crate) fn symmetric_encryption_block_based(
+    parameters: &SymmetricCryptoParameters,
+) -> Result<bool, HwCryptoError> {
+    match parameters {
+        SymmetricCryptoParameters::Aes(aes_params) => match aes_params {
+            AesCipherMode::Ctr(_) => Ok(false),
+            _ => Ok(true),
+        },
+    }
+}
 
-            fn try_from(value: i64) -> Result<Self, Self::Error> {
-                match value {
-                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
-                    _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE enum label val {}", value)),
+pub(crate) fn aidl_to_rust_aes_cipher_params(
+    params: &SymmetricCryptoParameters,
+    opaque_key: &OpaqueKey,
+) -> Result<crypto::aes::CipherMode, HwCryptoError> {
+    let SymmetricCryptoParameters::Aes(aes_params) = params;
+    match aes_params {
+        AesCipherMode::Cbc(CipherModeParameters { nonce }) => {
+            // TODO: change clone() into something like a try_clone()
+            let nonce = nonce.clone();
+            let nonce_len = nonce.len();
+            match opaque_key.get_key_type() {
+                KeyType::AES_128_CBC_NO_PADDING | KeyType::AES_256_CBC_NO_PADDING => {
+                    Ok(crypto::aes::CipherMode::CbcNoPadding {
+                        nonce: nonce.try_into().map_err(|_| {
+                            hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len)
+                        })?,
+                    })
+                }
+                KeyType::AES_128_CBC_PKCS7_PADDING | KeyType::AES_256_CBC_PKCS7_PADDING => {
+                    Ok(crypto::aes::CipherMode::CbcPkcs7Padding {
+                        nonce: nonce.try_into().map_err(|_| {
+                            hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len)
+                        })?,
+                    })
                 }
+                _ => Err(hwcrypto_err!(
+                    BAD_PARAMETER,
+                    "unsupporte key type for CBC: {:?}",
+                    opaque_key.get_key_type()
+                )),
             }
         }
+        AesCipherMode::Ctr(CipherModeParameters { nonce }) => {
+            let nonce_len = nonce.len();
+            // TODO: change clone() into something like a try_clone()
+            Ok(crypto::aes::CipherMode::Ctr {
+                nonce: nonce
+                    .clone()
+                    .try_into()
+                    .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len))?,
+            })
+        }
+    }
+}
 
-        impl TryFrom<ciborium::value::Integer> for $name {
-            type Error = coset::CoseError;
+pub(crate) fn aidl_to_rust_symmetric_direction(
+    dir: SymmetricOperation,
+) -> Result<KmSymmetricOperation, HwCryptoError> {
+    match dir {
+        SymmetricOperation::ENCRYPT => Ok(KmSymmetricOperation::Encrypt),
+        SymmetricOperation::DECRYPT => Ok(KmSymmetricOperation::Decrypt),
+        _ => Err(hwcrypto_err!(UNSUPPORTED, "unsupported symmetric operation: {:?}", dir)),
+    }
+}
 
-            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
-                let value: i64 = value.try_into()?;
-                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
-            }
-        }
+pub(crate) fn direction_to_key_usage(
+    operation: &SymmetricOperation,
+) -> Result<KeyUse, HwCryptoError> {
+    match *operation {
+        SymmetricOperation::ENCRYPT => Ok(KeyUse::ENCRYPT),
+        SymmetricOperation::DECRYPT => Ok(KeyUse::DECRYPT),
+        _ => Err(hwcrypto_err!(BAD_PARAMETER, "invalid operation type: {:?}", operation)),
     }
 }
diff --git a/hwcryptohal/server/hwcrypto_device_key.rs b/hwcryptohal/server/hwcrypto_device_key.rs
index 6f72e62..aa08a65 100644
--- a/hwcryptohal/server/hwcrypto_device_key.rs
+++ b/hwcryptohal/server/hwcrypto_device_key.rs
@@ -18,43 +18,34 @@
 //! retrieve device specific keys.
 
 use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
-    types::{KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse},
+    types::{
+        ExplicitKeyMaterial::ExplicitKeyMaterial, KeyLifetime::KeyLifetime, KeyType::KeyType,
+        KeyUse::KeyUse,
+    },
     IHwCryptoKey::{
         BnHwCryptoKey, DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
         DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
         DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
         DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
     },
+    IHwCryptoOperations::IHwCryptoOperations,
+    IOpaqueKey::IOpaqueKey,
     KeyPolicy::KeyPolicy,
 };
 use android_hardware_security_see::binder;
-use binder::StatusCode;
 use ciborium::{cbor, Value};
 use coset::{AsCborValue, CborSerializable, CoseError};
-use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
 use hwkey::{Hwkey, KdfVersion};
 use tipc::Uuid;
 
-use crate::cose_enum_gen;
-use crate::opaque_key::{self, OpaqueKey};
+use crate::hwcrypto_operations::HwCryptoOperations;
+
+use crate::helpers;
+use crate::opaque_key::{self, DerivationContext, HkdfOperationType, OpaqueKey};
 use crate::service_encryption_key::{self, EncryptionHeader};
 
 const DEVICE_KEY_CTX: &[u8] = b"device_key_derivation_contextKEK";
-const DICE_BOUND_POLICY_CTX: &[u8] = b"dice_bound";
-
-const OPAQUE_KEY_CTX: &[u8] = b"opaque";
-const CLEAR_KEY_CTX: &[u8] = b"cleark";
-const OPAQUE_CLEAR_CTX_SIZE: usize = 6;
-
-// Checking that both context have the same size and it is equal to `OPAQUE_CLEAR_CTX_SIZE`
-const _: () = assert!(
-    (OPAQUE_KEY_CTX.len() == OPAQUE_CLEAR_CTX_SIZE),
-    "opaque context size must match OPAQUE_CLEAR_CTX_SIZE"
-);
-const _: () = assert!(
-    (CLEAR_KEY_CTX.len() == OPAQUE_CLEAR_CTX_SIZE),
-    "clear context size must match OPAQUE_CLEAR_CTX_SIZE"
-);
 
 // enum used for serializing the `VersionContext`
 cose_enum_gen! {
@@ -218,11 +209,9 @@ impl HwCryptoKey {
         // Getting back a stable DICE policy for context, so keys derived with the same version will
         // match
         let dice_context = VersionContext::get_stable_context(dice_policy_for_key_version)?;
-        let mut concat_context = Vec::<u8>::new();
-        concat_context.try_reserve(DICE_BOUND_POLICY_CTX.len())?;
-        concat_context.extend_from_slice(DICE_BOUND_POLICY_CTX);
-        concat_context.try_reserve(dice_context.len())?;
-        concat_context.extend_from_slice(dice_context.as_slice());
+        let mut op_context = DerivationContext::new(HkdfOperationType::DiceBoundDerivation)?;
+        op_context.add_owned_binary_string(dice_context)?;
+        let concat_context = op_context.create_key_derivation_context()?;
 
         // The returned key will only be used for derivation, so fixing tis type to HMAC_SHA256
         let key_type = KeyType::HMAC_SHA256;
@@ -247,12 +236,12 @@ impl HwCryptoKey {
 
                 session_req
                     .kdf(KdfVersion::Best)
-                    .derive(&concat_context, &mut derived_key[..])
+                    .derive(concat_context.as_slice(), &mut derived_key[..])
                     .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to derive key {:?}", e))?;
 
                 let policy = KeyPolicy {
                     usage: KeyUse::DERIVE,
-                    keyLifetime: KeyLifetime::EPHEMERAL,
+                    keyLifetime: KeyLifetime::HARDWARE,
                     keyPermissions: Vec::new(),
                     keyType: key_type,
                     keyManagementKey: false,
@@ -321,14 +310,8 @@ impl IHwCryptoKey for HwCryptoKey {
             ))?
             .try_into()?;
 
-        let mut concat_context = Vec::<u8>::new();
-        concat_context.try_reserve(parameters.context.len()).map_err(|_| StatusCode::NO_MEMORY)?;
-        concat_context.extend_from_slice(&parameters.context);
-        concat_context.try_reserve(OPAQUE_CLEAR_CTX_SIZE).map_err(|_| StatusCode::NO_MEMORY)?;
-
         match &parameters.keyPolicy {
             DerivedKeyPolicy::ClearKey(clear_policy) => {
-                concat_context.extend_from_slice(CLEAR_KEY_CTX);
                 // Adding key size to the context as well for a similar reason as to add the key
                 // policy to the context.
                 let key_size = clear_policy.keySizeBytes.try_into().map_err(|_| {
@@ -337,43 +320,132 @@ impl IHwCryptoKey for HwCryptoKey {
                         Some("shouldn't happen, we checked that keySize was positive"),
                     )
                 })?;
-                // A u32 fits on a usize on the architectures we use, so conversion is correct
-                if key_size > (u32::MAX as usize) {
-                    return Err(binder::Status::new_exception_str(
-                        binder::ExceptionCode::UNSUPPORTED_OPERATION,
-                        Some("requested key size was too big"),
-                    ));
-                }
-                let key_size_as_bytes = (key_size as u32).to_le_bytes();
-                concat_context
-                    .try_reserve(key_size_as_bytes.len())
-                    .map_err(|_| StatusCode::NO_MEMORY)?;
-                concat_context.extend_from_slice(&key_size_as_bytes[..]);
 
-                let derived_key =
-                    derivation_key.derive_raw_key_material(concat_context.as_slice(), key_size)?;
+                let derived_key = derivation_key
+                    .derive_clear_key_material(parameters.context.as_slice(), key_size)?;
                 Ok(DerivedKey::ExplicitKey(derived_key))
             }
             DerivedKeyPolicy::OpaqueKey(key_policy) => {
-                concat_context.extend_from_slice(OPAQUE_KEY_CTX);
-                // TODO: Add keyPolicy to the context to mitigate attacks trying to use the same
-                //       generated key material under different algorithms.
-                let _derived_key =
-                    derivation_key.derive_key(key_policy, concat_context.as_slice())?;
-                Err(binder::Status::new_exception_str(
-                    binder::ExceptionCode::UNSUPPORTED_OPERATION,
-                    Some("cannot return opaque keys until we add its policy to context"),
-                ))
+                let derived_key =
+                    derivation_key.derive_opaque_key(key_policy, parameters.context.as_slice())?;
+                Ok(DerivedKey::Opaque(Some(derived_key)))
             }
         }
     }
+
+    fn getHwCryptoOperations(&self) -> binder::Result<binder::Strong<dyn IHwCryptoOperations>> {
+        Ok(HwCryptoOperations::new_binder())
+    }
+
+    fn importClearKey(
+        &self,
+        key_to_be_imported: &ExplicitKeyMaterial,
+        new_key_policy: &KeyPolicy,
+    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
+        let key_material = helpers::aidl_explicit_key_to_rust_key_material(key_to_be_imported)?;
+        Ok(OpaqueKey::import_key_material(new_key_policy, key_material)?)
+    }
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::ClearKeyPolicy::ClearKeyPolicy;
-    use test::{assert_ok, expect};
+    use crate::hwcrypto_ipc_server::RUST_SERVICE_PORT;
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+        types::{
+            AesCipherMode::AesCipherMode, AesKey::AesKey,
+            CipherModeParameters::CipherModeParameters, OperationData::OperationData,
+            SymmetricCryptoParameters::SymmetricCryptoParameters,
+            SymmetricOperation::SymmetricOperation,
+            SymmetricOperationParameters::SymmetricOperationParameters,
+        },
+        CryptoOperation::CryptoOperation,
+        CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
+        CryptoOperationSet::CryptoOperationSet,
+        IHwCryptoKey::ClearKeyPolicy::ClearKeyPolicy,
+        OperationParameters::OperationParameters,
+    };
+    use binder::Strong;
+    use rpcbinder::RpcSession;
+    use test::{assert_ok, expect, expect_eq};
+
+    #[test]
+    fn import_clear_aes_key() {
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let aes_key_material: ExplicitKeyMaterial = ExplicitKeyMaterial::Aes(AesKey::Aes128([
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+        ]));
+        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        //// Decrypting
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::DECRYPT;
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode received message");
+        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
+    }
 
     #[test]
     fn derived_dice_bound_keys() {
diff --git a/hwcryptohal/server/hwcrypto_ipc_server.rs b/hwcryptohal/server/hwcrypto_ipc_server.rs
index 4248abe..a69b2c3 100644
--- a/hwcryptohal/server/hwcrypto_ipc_server.rs
+++ b/hwcryptohal/server/hwcrypto_ipc_server.rs
@@ -16,20 +16,58 @@
 
 //! AIDL IPC Server code.
 use crate::hwcrypto_device_key;
+use crate::hwcrypto_operations;
+use alloc::rc::Rc;
 use binder::SpIBinder;
 use core::ffi::CStr;
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
 use rpcbinder::RpcServer;
-use tipc::{Manager, PortCfg, Uuid};
+use tipc::{self, service_dispatcher, wrap_service, Manager, PortCfg, Uuid};
 
-const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
+wrap_service!(HwCryptoDeviceKey(RpcServer: UnbufferedService));
+wrap_service!(HwCryptoOperations(RpcServer: UnbufferedService));
+
+service_dispatcher! {
+    enum HWCryptoHal {
+        HwCryptoOperations,
+        HwCryptoDeviceKey,
+    }
+}
+
+pub(crate) const RUST_HWCRYPTO_OPS_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.ops.V1";
+pub(crate) const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
 
 fn create_device_key_service(uuid: Uuid) -> Option<SpIBinder> {
     Some(hwcrypto_device_key::HwCryptoKey::new_binder(uuid).as_binder())
 }
 
 pub fn main_loop() -> Result<(), HwCryptoError> {
+    let mut dispatcher = HWCryptoHal::<2>::new().map_err(|e| {
+        hwcrypto_err!(GENERIC_ERROR, "could not create multi-service dispatcher: {:?}", e)
+    })?;
+
+    let hw_key = hwcrypto_operations::HwCryptoOperations::new_binder();
+    let hwk_rpc_server = RpcServer::new(hw_key.as_binder());
+    let hwk_service = HwCryptoOperations(hwk_rpc_server);
     let hwdk_rpc_server = RpcServer::new_per_session(create_device_key_service);
+    let hwdk_service = HwCryptoDeviceKey(hwdk_rpc_server);
+
+    let cfg =
+        PortCfg::new(RUST_HWCRYPTO_OPS_PORT.to_str().expect("should not happen, valid utf-8"))
+            .map_err(|e| {
+                hwcrypto_err!(
+                    GENERIC_ERROR,
+                    "could not create port config for {:?}: {:?}",
+                    RUST_HWCRYPTO_OPS_PORT,
+                    e
+                )
+            })?
+            .allow_ta_connect()
+            .allow_ns_connect();
+
+    dispatcher
+        .add_service(Rc::new(hwk_service), cfg)
+        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could add HWCrypto service: {:?}", e))?;
 
     let cfg = PortCfg::new(RUST_SERVICE_PORT.to_str().expect("should not happen, valid utf-8"))
         .map_err(|e| {
@@ -43,7 +81,11 @@ pub fn main_loop() -> Result<(), HwCryptoError> {
         .allow_ta_connect()
         .allow_ns_connect();
 
-    let manager = Manager::<_, _, 1, 4>::new_unbuffered(hwdk_rpc_server, cfg)
+    dispatcher.add_service(Rc::new(hwdk_service), cfg).map_err(|e| {
+        hwcrypto_err!(GENERIC_ERROR, "could add HWCrypto device key service: {:?}", e)
+    })?;
+
+    let manager = Manager::<_, _, 2, 4>::new_with_dispatcher(dispatcher, [])
         .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not create service manager: {:?}", e))?;
 
     manager
@@ -54,6 +96,7 @@ pub fn main_loop() -> Result<(), HwCryptoError> {
 #[cfg(test)]
 mod tests {
     use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoOperations::IHwCryptoOperations;
     use rpcbinder::RpcSession;
     use binder::{IBinder, Strong};
     use test::expect_eq;
@@ -61,8 +104,13 @@ mod tests {
 
     #[test]
     fn connect_server() {
-        let session: Strong<dyn IHwCryptoKey> =
-            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        let session: Strong<dyn IHwCryptoOperations> = RpcSession::new()
+            .setup_trusty_client(RUST_HWCRYPTO_OPS_PORT)
+            .expect("Failed to connect");
         expect_eq!(session.as_binder().ping_binder(), Ok(()));
+
+        let session_device_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        expect_eq!(session_device_key.as_binder().ping_binder(), Ok(()));
     }
 }
diff --git a/hwcryptohal/server/hwcrypto_operations.rs b/hwcryptohal/server/hwcrypto_operations.rs
new file mode 100644
index 0000000..e0a0e53
--- /dev/null
+++ b/hwcryptohal/server/hwcrypto_operations.rs
@@ -0,0 +1,215 @@
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
+//! Implementation of the `IHwCryptoOperations` AIDL interface. It can be use to retrieve the
+//! key generation interface and to process cryptographic operations.
+
+use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
+    CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
+    IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
+};
+use android_hardware_security_see::binder;
+use hwcryptohal_common::hwcrypto_err;
+
+use crate::cmd_processing::CmdProcessorContext;
+use crate::crypto_operation_context::{BinderCryptoOperationContext, CryptoOperationContext};
+
+/// The `IHwCryptoOperations` implementation.
+pub struct HwCryptoOperations;
+
+impl binder::Interface for HwCryptoOperations {}
+
+impl HwCryptoOperations {
+    pub(crate) fn new_binder() -> binder::Strong<dyn IHwCryptoOperations> {
+        let hwcrypto_operations = HwCryptoOperations;
+        BnHwCryptoOperations::new_binder(hwcrypto_operations, binder::BinderFeatures::default())
+    }
+}
+
+impl IHwCryptoOperations for HwCryptoOperations {
+    fn processCommandList(
+        &self,
+        command_lists: &mut std::vec::Vec<CryptoOperationSet>,
+        _additional_error_info: &mut CryptoOperationErrorAdditionalInfo,
+    ) -> binder::Result<Vec<CryptoOperationResult>> {
+        let mut results = Vec::<CryptoOperationResult>::new();
+        for command_list in command_lists {
+            results.try_reserve(1).map_err(|e| {
+                hwcrypto_err!(ALLOCATION_ERROR, "couldn't grow result vector: {:?}", e)
+            })?;
+            results.push(CryptoOperationResult { context: None });
+            match &command_list.context {
+                None => {
+                    let mut cmd_processor = CmdProcessorContext::new();
+                    cmd_processor.process_all_steps(&mut command_list.operations)?;
+                    if !cmd_processor.is_destroyed() {
+                        let operation_context = CryptoOperationContext::new_binder(cmd_processor);
+                        (*results
+                            .last_mut()
+                            .expect("shouldn't happen, we pushed an element before match"))
+                        .context = Some(operation_context);
+                    }
+                }
+                Some(operation_context) => {
+                    BinderCryptoOperationContext::from(operation_context.clone())
+                        .process_all_steps(&mut command_list.operations)?;
+                }
+            }
+        }
+        Ok(results)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::hwcrypto_ipc_server::RUST_SERVICE_PORT;
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+        types::{
+            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
+            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
+            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
+            SymmetricOperation::SymmetricOperation,
+            SymmetricOperationParameters::SymmetricOperationParameters,
+        },
+        CryptoOperation::CryptoOperation,
+        IHwCryptoKey::{
+            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
+            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
+            DiceBoundDerivationKey::DiceBoundDerivationKey,
+            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
+        },
+        KeyPolicy::KeyPolicy,
+        OperationParameters::OperationParameters,
+    };
+    use binder::Strong;
+    use rpcbinder::RpcSession;
+    use test::{assert_ok, expect, expect_eq};
+
+    #[test]
+    fn aes_simple_test_from_binder() {
+        let hw_device_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
+        let key_and_policy =
+            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
+        let DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: policy } =
+            key_and_policy;
+        expect!(key.is_some(), "should have received a key");
+        expect!(policy.len() > 0, "should have received a DICE policy");
+
+        let hw_crypto = hw_device_key.getHwCryptoOperations().expect("Failed to get crypto ops.");
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::HARDWARE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+
+        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
+            .expect("couldn't serialize policy");
+        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);
+        let params = DerivedKeyParameters {
+            derivationKey: key,
+            keyPolicy: key_policy,
+            context: "context".as_bytes().to_vec(),
+        };
+        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
+        let key = match derived_key {
+            DerivedKey::Opaque(key) => key.expect("key shouldn't be NULL"),
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        let mut op_result = hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let context = op_result.remove(0).context;
+        // Separating the finish call on a different command set to test the returned context
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(encrypted_data);
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        //// Decrypting
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::DECRYPT;
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode received message");
+        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
+    }
+}
diff --git a/hwcryptohal/server/lib.rs b/hwcryptohal/server/lib.rs
index b5f509c..f824779 100644
--- a/hwcryptohal/server/lib.rs
+++ b/hwcryptohal/server/lib.rs
@@ -22,10 +22,14 @@
 
 pub mod hwcrypto_ipc_server;
 
+mod cmd_processing;
+mod crypto_operation;
+mod crypto_operation_context;
 mod crypto_provider;
 mod ffi_bindings;
 mod helpers;
 mod hwcrypto_device_key;
+mod hwcrypto_operations;
 mod opaque_key;
 mod platform_functions;
 mod service_encryption_key;
diff --git a/hwcryptohal/server/opaque_key.rs b/hwcryptohal/server/opaque_key.rs
index 21ebd31..43ff75f 100644
--- a/hwcryptohal/server/opaque_key.rs
+++ b/hwcryptohal/server/opaque_key.rs
@@ -17,7 +17,9 @@
 //! Implementation of the `IOpaqueKey` AIDL interface. It is used as a handle to key material
 
 use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
-    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
+    AesCipherMode::AesCipherMode, KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions,
+    KeyType::KeyType, KeyUse::KeyUse, SymmetricCryptoParameters::SymmetricCryptoParameters,
+    SymmetricOperation::SymmetricOperation,
 };
 use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
     IOpaqueKey::{BnOpaqueKey, IOpaqueKey},
@@ -25,8 +27,14 @@ use android_hardware_security_see::aidl::android::hardware::security::see::hwcry
 };
 use android_hardware_security_see::binder;
 use binder::binder_impl::Binder;
+use ciborium::Value;
 use core::fmt;
-use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use coset::CborSerializable;
+use hwcryptohal_common::{
+    err::HwCryptoError,
+    hwcrypto_err,
+    policy::{self, KeyLifetimeSerializable, KeyTypeSerializable, KeyUseSerializable},
+};
 use kmr_common::{
     crypto::{self, Aes, CurveType, Hkdf, Hmac, KeyMaterial, OpaqueOr, Rng},
     explicit, FallibleAllocExt,
@@ -35,6 +43,7 @@ use kmr_wire::keymint::EcCurve;
 use std::sync::OnceLock;
 
 use crate::crypto_provider;
+use crate::helpers;
 
 /// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
 const UNIQUE_VALUE_SIZEOF: usize = 32;
@@ -81,31 +90,87 @@ fn get_boot_unique_value() -> Result<BootUniqueValue, HwCryptoError> {
     Ok(boot_unique_value.clone())
 }
 
+#[derive(Copy, Clone)]
+pub(crate) enum HkdfOperationType {
+    DiceBoundDerivation = 1,
+    ClearKeyDerivation = 3,
+    OpaqueKeyDerivation = 4,
+}
+
+pub(crate) struct DerivationContext {
+    context_components: Vec<Value>,
+}
+
+impl DerivationContext {
+    pub(crate) fn new(op_type: HkdfOperationType) -> Result<Self, HwCryptoError> {
+        let mut context_components = Vec::new();
+        context_components.try_reserve(1)?;
+        context_components.push(Value::Integer((op_type as u8).into()));
+        Ok(Self { context_components })
+    }
+
+    pub(crate) fn add_binary_string(&mut self, binary_string: &[u8]) -> Result<(), HwCryptoError> {
+        self.context_components.try_reserve(1)?;
+        let mut context = Vec::new();
+        context.try_reserve(binary_string.len())?;
+        context.extend_from_slice(binary_string);
+        self.context_components.push(Value::Bytes(context));
+        Ok(())
+    }
+
+    pub(crate) fn add_owned_binary_string(
+        &mut self,
+        binary_string: Vec<u8>,
+    ) -> Result<(), HwCryptoError> {
+        self.context_components.try_reserve(1)?;
+        self.context_components.push(Value::Bytes(binary_string));
+        Ok(())
+    }
+
+    pub(crate) fn add_unsigned_integer(&mut self, value: u64) -> Result<(), HwCryptoError> {
+        self.context_components.try_reserve(1)?;
+        self.context_components.push(Value::Integer(value.into()));
+        Ok(())
+    }
+
+    pub(crate) fn create_key_derivation_context(self) -> Result<Vec<u8>, HwCryptoError> {
+        let context = Value::Array(self.context_components);
+        Ok(context.to_vec()?)
+    }
+}
+
 /// Header for a `ClearKey` which contains the key policy along with some data needed to manipulate
 /// the key.
 #[derive(Debug)]
-#[allow(dead_code)]
 pub(crate) struct KeyHeader {
     boot_unique_value: BootUniqueValue,
     expiration_time: Option<u64>,
-    key_lifetime: KeyLifetime,
+    key_lifetime: KeyLifetimeSerializable,
     key_permissions: Vec<KeyPermissions>,
-    key_usage: KeyUse,
-    key_type: KeyType,
+    key_usage: KeyUseSerializable,
+    key_type: KeyTypeSerializable,
     management_key: bool,
 }
 
 impl KeyHeader {
     fn new(policy: &KeyPolicy) -> Result<Self, HwCryptoError> {
+        let boot_unique_value = BootUniqueValue::new()?;
+        Self::new_with_boot_value(policy, boot_unique_value)
+    }
+
+    fn new_with_boot_value(
+        policy: &KeyPolicy,
+        boot_unique_value: BootUniqueValue,
+    ) -> Result<Self, HwCryptoError> {
         let mut key_permissions = Vec::new();
         key_permissions.try_extend_from_slice(&policy.keyPermissions[..])?;
         Ok(Self {
-            boot_unique_value: BootUniqueValue::new()?,
+            boot_unique_value,
             expiration_time: None,
-            key_lifetime: policy.keyLifetime,
+            key_lifetime: KeyLifetimeSerializable(policy.keyLifetime),
             key_permissions,
-            key_usage: policy.usage,
-            key_type: policy.keyType,
+            key_usage: KeyUseSerializable(policy.usage),
+            key_type: KeyTypeSerializable(policy.keyType),
             management_key: policy.keyManagementKey,
         })
     }
@@ -114,10 +179,10 @@ impl KeyHeader {
         let mut key_permissions = Vec::new();
         key_permissions.try_extend_from_slice(&self.key_permissions[..])?;
         Ok(KeyPolicy {
-            usage: self.key_usage,
-            keyLifetime: self.key_lifetime,
+            usage: self.key_usage.0,
+            keyLifetime: self.key_lifetime.0,
             keyPermissions: key_permissions,
-            keyType: self.key_type,
+            keyType: self.key_type.0,
             keyManagementKey: self.management_key,
         })
     }
@@ -138,7 +203,6 @@ impl KeyHeader {
 }
 
 /// `IOpaqueKey` implementation.
-#[allow(dead_code)]
 pub struct OpaqueKey {
     pub(crate) key_header: KeyHeader,
     pub(crate) key_material: KeyMaterial,
@@ -176,6 +240,32 @@ impl OpaqueKey {
         Ok(opaque_keybinder)
     }
 
+    fn check_clear_import_policy(policy: &KeyPolicy) -> Result<(), HwCryptoError> {
+        if policy.keyLifetime != KeyLifetime::PORTABLE {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "imported clear keys should have a PORTABLE lifetime"
+            ));
+        }
+        Ok(())
+    }
+
+    pub(crate) fn import_key_material(
+        policy: &KeyPolicy,
+        key_material: KeyMaterial,
+    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
+        check_key_material_with_policy(&key_material, policy)?;
+        Self::check_clear_import_policy(policy)?;
+        Self::new_binder(policy, key_material)
+    }
+
+    #[allow(unused)]
+    pub(crate) fn generate_opaque_key(
+        policy: &KeyPolicy,
+    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
+        let key_material = generate_key_material(&policy.keyType, None)?;
+        OpaqueKey::new_binder(policy, key_material)
+    }
     fn try_clone(&self) -> Result<Self, HwCryptoError> {
         let key_header = self.key_header.try_clone()?;
         let key_material = self.key_material.clone();
@@ -208,11 +298,16 @@ impl OpaqueKey {
         self.key_can_be_used_for_derivation()
     }
 
-    pub(crate) fn derive_raw_key_material(
+    // All key derivation functions that uses an `OpaqueKey` as key material should use this
+    // function. If the key derivation do not fit one of the current use cases defined in
+    // `HkdfOperationType`, a new enum value should be added to `HkdfOperationType` for the use
+    // case.
+    fn derive_raw_key_material(
         &self,
-        context: &[u8],
+        context: DerivationContext,
         derived_key_size: usize,
     ) -> Result<Vec<u8>, HwCryptoError> {
+        let context_with_op_type = context.create_key_derivation_context()?;
         match &self.key_material {
             KeyMaterial::Hmac(key) => {
                 let hkdf = crypto_provider::HmacImpl;
@@ -220,7 +315,7 @@ impl OpaqueKey {
                     hwcrypto_err!(BAD_PARAMETER, "only explicit HMAC keys supported")
                 })?;
                 let raw_key = hkdf
-                    .hkdf(&[], &explicit_key.0, context, derived_key_size)
+                    .hkdf(&[], &explicit_key.0, context_with_op_type.as_slice(), derived_key_size)
                     .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "couldn't derive key {:?}", e))?;
                 Ok(raw_key)
             }
@@ -228,24 +323,39 @@ impl OpaqueKey {
         }
     }
 
-    pub(crate) fn derive_key(
+    pub(crate) fn derive_clear_key_material(
         &self,
-        policy: &KeyPolicy,
+        context: &[u8],
+        derived_key_size: usize,
+    ) -> Result<Vec<u8>, HwCryptoError> {
+        let mut op_context = DerivationContext::new(HkdfOperationType::ClearKeyDerivation)?;
+        op_context.add_unsigned_integer(derived_key_size as u64)?;
+        op_context.add_binary_string(context)?;
+        self.derive_raw_key_material(op_context, derived_key_size)
+    }
+
+    pub(crate) fn derive_opaque_key(
+        &self,
+        policy: &[u8],
         context: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
-        self.check_key_derivation_parameters(policy)?;
-        let derived_key_size = get_key_size_in_bytes(&policy.keyType)?;
-        let raw_key_material = self.derive_raw_key_material(context, derived_key_size)?;
-        Self::new_opaque_key_from_raw_bytes(policy, raw_key_material)
+        let aidl_policy = policy::cbor_policy_to_aidl(policy)?;
+        self.check_key_derivation_parameters(&aidl_policy)?;
+        let derived_key_size = get_key_size_in_bytes(&aidl_policy.keyType)?;
+        let mut op_context = DerivationContext::new(HkdfOperationType::OpaqueKeyDerivation)?;
+        op_context.add_binary_string(policy)?;
+        op_context.add_binary_string(context)?;
+        let raw_key_material = self.derive_raw_key_material(op_context, derived_key_size)?;
+        Self::new_opaque_key_from_raw_bytes(&aidl_policy, raw_key_material)
     }
 
     fn derivation_allowed_lifetime(
         &self,
         derived_key_lifetime: KeyLifetime,
     ) -> Result<bool, HwCryptoError> {
-        validate_lifetime(self.key_header.key_lifetime)?;
+        validate_lifetime(self.key_header.key_lifetime.0)?;
         validate_lifetime(derived_key_lifetime)?;
-        match self.key_header.key_lifetime {
+        match self.key_header.key_lifetime.0 {
             //ephemeral keys can be used to derive/wrap any other key
             KeyLifetime::EPHEMERAL => Ok(true),
             KeyLifetime::HARDWARE => {
@@ -277,11 +387,54 @@ impl OpaqueKey {
             KeyMaterial::Hmac(_) => Ok(()),
             _ => Err(hwcrypto_err!(UNSUPPORTED, "Only HMAC keys can be used for key derivation")),
         }?;
-        if self.key_header.key_usage != KeyUse::DERIVE {
+        if self.key_header.key_usage.0 != KeyUse::DERIVE {
             return Err(hwcrypto_err!(BAD_PARAMETER, "key was not exclusively a derive key"));
         }
         Ok(())
     }
+
+    pub(crate) fn key_usage_supported(&self, usage: KeyUse) -> bool {
+        (usage.0 & self.key_header.key_usage.0 .0) == usage.0
+    }
+
+    pub fn get_key_type(&self) -> KeyType {
+        self.key_header.key_type.0
+    }
+
+    /// Checks if the requested operation (encrypt/decrypt) can be done with this key
+    pub(crate) fn symmetric_operation_is_compatible(
+        &self,
+        direction: SymmetricOperation,
+    ) -> Result<(), HwCryptoError> {
+        let dir = helpers::direction_to_key_usage(&direction)?;
+        if !self.key_usage_supported(dir) {
+            Err(hwcrypto_err!(BAD_PARAMETER, "provided key do not support {:?}", dir))
+        } else {
+            Ok(())
+        }
+    }
+
+    /// Checks if the requested algorithm parameters are compatible with this key
+    pub(crate) fn parameters_are_compatible_symmetric_cipher(
+        &self,
+        parameters: &SymmetricCryptoParameters,
+    ) -> Result<(), HwCryptoError> {
+        match parameters {
+            SymmetricCryptoParameters::Aes(aes_parameters) => match aes_parameters {
+                AesCipherMode::Cbc(_) => match self.get_key_type() {
+                    KeyType::AES_128_CBC_NO_PADDING
+                    | KeyType::AES_128_CBC_PKCS7_PADDING
+                    | KeyType::AES_256_CBC_NO_PADDING
+                    | KeyType::AES_256_CBC_PKCS7_PADDING => Ok(()),
+                    _ => Err(hwcrypto_err!(BAD_PARAMETER, "provided incompatible AES key for CBC")),
+                },
+                AesCipherMode::Ctr(_) => match self.get_key_type() {
+                    KeyType::AES_128_CTR | KeyType::AES_256_CTR => Ok(()),
+                    _ => Err(hwcrypto_err!(BAD_PARAMETER, "provided incompatible AES key for CTR")),
+                },
+            },
+        }
+    }
 }
 
 impl binder::Interface for OpaqueKey {}
@@ -406,8 +559,8 @@ pub(crate) fn check_key_material_with_policy(
     }
 }
 
-// Get key size in bytesgiven the backend AES key type. Used to check if we received enough bytes
-// from the caller for an AES key.
+// Get key size given the backend AES key type. Used to check if we received enough bytes from the
+// caller for an AES key.
 fn get_aes_variant_key_size(variant: &crypto::aes::Variant) -> usize {
     match variant {
         crypto::aes::Variant::Aes128 => 16,
diff --git a/hwcryptohal/server/rules.mk b/hwcryptohal/server/rules.mk
index 608d3c6..36b9096 100644
--- a/hwcryptohal/server/rules.mk
+++ b/hwcryptohal/server/rules.mk
@@ -39,6 +39,7 @@ MODULE_LIBRARY_DEPS += \
 	$(call FIND_CRATE,log) \
 	trusty/user/base/lib/trusty-log \
 	trusty/user/base/lib/trusty-std \
+	$(call FIND_CRATE,vm-memory) \
 
 MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	trusty_rng_.* \
diff --git a/hwcryptohal/server/service_encryption_key.rs b/hwcryptohal/server/service_encryption_key.rs
index 61b3d3d..8bb1e66 100644
--- a/hwcryptohal/server/service_encryption_key.rs
+++ b/hwcryptohal/server/service_encryption_key.rs
@@ -241,7 +241,7 @@ fn get_new_key_derivation_context() -> [u8; KEY_DERIVATION_CTX_LENGTH] {
     key_ctx
 }
 
-fn parse_cborium_bytes_to_fixed_array(
+pub(crate) fn parse_cborium_bytes_to_fixed_array(
     value: &ciborium::value::Value,
     name: &str,
 ) -> Result<[u8; KEY_DERIVATION_CTX_LENGTH], HwCryptoError> {
diff --git a/hwcryptokey-test/aes_vectors.rs b/hwcryptokey-test/aes_vectors.rs
new file mode 100644
index 0000000..4bca737
--- /dev/null
+++ b/hwcryptokey-test/aes_vectors.rs
@@ -0,0 +1,344 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#[cfg(test)]
+mod tests {
+    pub(crate) const RUST_HWCRYPTO_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
+
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+        types::{
+            AesCipherMode::AesCipherMode, AesKey::AesKey,
+            CipherModeParameters::CipherModeParameters, ExplicitKeyMaterial::ExplicitKeyMaterial,
+            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
+            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
+            SymmetricOperation::SymmetricOperation,
+            SymmetricOperationParameters::SymmetricOperationParameters,
+        },
+        CryptoOperation::CryptoOperation,
+        CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
+        CryptoOperationSet::CryptoOperationSet,
+        ICryptoOperationContext::ICryptoOperationContext,
+        IHwCryptoKey::IHwCryptoKey,
+        KeyPolicy::KeyPolicy,
+        OperationParameters::OperationParameters,
+    };
+    use binder::Strong;
+    use rpcbinder::RpcSession;
+    use std::collections::HashMap;
+    use test::expect;
+    use trusty_std::ffi::{CString, FallibleCString};
+
+    #[derive(Debug, Clone, PartialEq)]
+    enum OPERATION {
+        ENCRYPT,
+        DECRYPT,
+    }
+
+    #[derive(Debug, Clone, PartialEq)]
+    enum MODE {
+        CBC,
+        CTR,
+    }
+
+    #[derive(Debug)]
+    struct Vector {
+        op: Option<OPERATION>,
+        mode: Option<MODE>,
+        key_length: Option<u16>,
+        iv_size: Option<u16>,
+        payload_size: Option<u16>,
+        params: HashMap<String, String>,
+    }
+
+    #[test]
+    fn aes_vector_test() {
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCGFSbox128.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCGFSbox256.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCKeySbox128.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCKeySbox256.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarKey128.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarKey256.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarTxt128.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarTxt256.rsp")));
+
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/aesmmt/CBCMMT128.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/aesmmt/CBCMMT256.rsp")));
+
+        run_aes_vectors(parse_vectors(include_str!("vectors/NIST/CTR/ctr_128.rsp")));
+        run_aes_vectors(parse_vectors(include_str!("vectors/NIST/CTR/ctr_256.rsp")));
+    }
+
+    fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
+        if s.len() % 2 == 0 {
+            (0..s.len())
+                .step_by(2)
+                .map(|i| s.get(i..i + 2).and_then(|sub| u8::from_str_radix(sub, 16).ok()))
+                .collect()
+        } else {
+            None
+        }
+    }
+
+    fn parse_vectors(raw: &str) -> Vec<Vector> {
+        let mut vectors: Vec<Vector> = Vec::new();
+
+        let mut params: HashMap<String, String> = HashMap::new();
+        let mut mode: Option<MODE> = None;
+        let mut op: Option<OPERATION> = None;
+        let mut key_length: Option<u16> = None;
+        let mut iv_size: Option<u16> = None;
+        let mut payload_size: Option<u16>;
+
+        for line in raw.lines() {
+            // Check for header settings
+            if line.contains("test data for") {
+                let parts: Vec<&str> = line.split("test data for").collect();
+                let mode_str = parts[1].trim();
+
+                match mode_str {
+                    "CBC" => {
+                        mode = Some(MODE::CBC);
+                        iv_size = Some(128);
+                    }
+                    "CTR" => {
+                        mode = Some(MODE::CTR);
+                        iv_size = Some(128);
+                    }
+                    _ => {
+                        mode = None;
+                        iv_size = None;
+                    }
+                };
+            }
+
+            // Check for key length
+            if line.contains("Key Length") {
+                let parts: Vec<&str> = line.split(":").collect();
+                key_length = Some(parts[1].trim().parse::<u16>().unwrap());
+            }
+
+            // Check for encrypt or decrypt
+            if line.contains("[ENCRYPT]") {
+                op = Some(OPERATION::ENCRYPT);
+            }
+
+            if line.contains("[DECRYPT]") {
+                op = Some(OPERATION::DECRYPT);
+            }
+
+            // Check for vector components
+            if line.contains("=") {
+                let words: Vec<_> = line.split_whitespace().filter(|s| s != &"=").collect();
+                params.insert(words[0].to_string(), words[1].to_string());
+            }
+
+            // Check for vector completion
+            if line.trim().len() == 0 && params.len() > 0 {
+                // Vector complete, add to array
+                payload_size = Some((params["PLAINTEXT"].len() * 4).try_into().unwrap());
+
+                let current_vector = Vector {
+                    op: op.clone(),
+                    mode: mode.clone(),
+                    key_length: key_length.clone(),
+                    iv_size: iv_size.clone(),
+                    payload_size: payload_size.clone(),
+                    params: params.clone(),
+                };
+                params.clear();
+                vectors.push(current_vector);
+            }
+        }
+
+        // Add last vector to array if not yet added
+        if params.len() > 0 {
+            payload_size = Some((params["PLAINTEXT"].len() * 4).try_into().unwrap());
+
+            let current_vector = Vector {
+                op: op.clone(),
+                mode: mode.clone(),
+                key_length: key_length.clone(),
+                iv_size: iv_size.clone(),
+                payload_size: payload_size.clone(),
+                params: params.clone(),
+            };
+            params.clear();
+            vectors.push(current_vector);
+        }
+
+        vectors
+    }
+
+    fn get_key_type(key_length: &u16, mode: &MODE) -> Option<KeyType> {
+        match key_length {
+            128 => match mode {
+                MODE::CBC => Some(KeyType::AES_128_CBC_NO_PADDING),
+                MODE::CTR => Some(KeyType::AES_128_CTR),
+            },
+            256 => match mode {
+                MODE::CBC => Some(KeyType::AES_256_CBC_NO_PADDING),
+                MODE::CTR => Some(KeyType::AES_256_CTR),
+            },
+            _ => None,
+        }
+    }
+
+    fn run_aes_vectors(vectors: Vec<Vector>) {
+        let port =
+            CString::try_new(RUST_HWCRYPTO_SERVICE_PORT).expect("Failed to allocate port name");
+        let hw_crypto: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(port.as_c_str()).expect("Failed to connect");
+        let hw_crypto_ops =
+            hw_crypto.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+
+        let mut current_key: Vec<u8> = Vec::new();
+        let mut current_iv: Vec<u8> = Vec::new();
+        let mut new_iv: bool;
+
+        let mut context: Option<Strong<dyn ICryptoOperationContext>> = None;
+
+        for v in vectors {
+            if v.params.contains_key("IV") {
+                current_key = hex_to_bytes(v.params["KEY"].as_str()).expect("Bad hex value");
+                expect!(
+                    current_key.len() * 8 == v.key_length.unwrap() as usize,
+                    "Invalid key length"
+                );
+
+                current_iv = hex_to_bytes(v.params["IV"].as_str()).expect("Bad hex value");
+                expect!(current_iv.len() * 8 == v.iv_size.unwrap() as usize, "Invalid IV length");
+
+                new_iv = true;
+                context = None;
+            } else {
+                new_iv = false;
+            }
+
+            let plaintext: Vec<u8> =
+                hex_to_bytes(v.params["PLAINTEXT"].as_str()).expect("Bad hex value");
+            let ciphertext: Vec<u8> =
+                hex_to_bytes(v.params["CIPHERTEXT"].as_str()).expect("Bad hex value");
+
+            expect!(plaintext.len() * 8 == v.payload_size.unwrap() as usize, "Invalid data length");
+            expect!(
+                ciphertext.len() * 8 == v.payload_size.unwrap() as usize,
+                "Invalid data length"
+            );
+
+            let policy = KeyPolicy {
+                usage: KeyUse::ENCRYPT_DECRYPT,
+                keyLifetime: KeyLifetime::PORTABLE,
+                keyPermissions: Vec::new(),
+                keyType: get_key_type(&((current_key.len() * 8) as u16), &v.mode.as_ref().unwrap())
+                    .expect("Invalid key size or mode"),
+                keyManagementKey: false,
+            };
+
+            let aes_key_material: ExplicitKeyMaterial = match current_key.len() * 8 {
+                128 => ExplicitKeyMaterial::Aes(AesKey::Aes128(
+                    current_key.clone().try_into().expect("Bad key"),
+                )),
+                256 => ExplicitKeyMaterial::Aes(AesKey::Aes256(
+                    current_key.clone().try_into().expect("Bad key"),
+                )),
+                _ => panic!("Unsupported key length"),
+            };
+
+            let key = hw_crypto
+                .importClearKey(&aes_key_material, &policy)
+                .expect("Couldn't import clear key");
+
+            let parameters = match v.mode.clone().unwrap() {
+                MODE::CBC => {
+                    SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+                        nonce: current_iv.clone().try_into().expect("Failed to set IV"),
+                    }))
+                }
+                MODE::CTR => {
+                    SymmetricCryptoParameters::Aes(AesCipherMode::Ctr(CipherModeParameters {
+                        nonce: current_iv.clone().try_into().expect("Failed to set IV"),
+                    }))
+                }
+            };
+
+            let direction = match v.op.as_ref().unwrap() {
+                OPERATION::ENCRYPT => SymmetricOperation::ENCRYPT,
+                OPERATION::DECRYPT => SymmetricOperation::DECRYPT,
+            };
+
+            let sym_op_params =
+                SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+            let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+
+            let mut cmd_list = Vec::<CryptoOperation>::new();
+            let data_output = OperationData::DataBuffer(Vec::new());
+
+            // Build command list
+            cmd_list.push(CryptoOperation::DataOutput(data_output));
+
+            if v.mode.clone().unwrap() != MODE::CTR || new_iv {
+                cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+                // For CTR, only do this when IV changes
+            }
+
+            let input_data = match v.op.as_ref().unwrap() {
+                OPERATION::ENCRYPT => OperationData::DataBuffer(plaintext.clone()),
+                OPERATION::DECRYPT => OperationData::DataBuffer(ciphertext.clone()),
+            };
+            cmd_list.push(CryptoOperation::DataInput(input_data));
+
+            if v.mode.clone().unwrap() != MODE::CTR {
+                cmd_list.push(CryptoOperation::Finish(None)); // For CTR, don't do this
+            }
+
+            if v.mode.clone().unwrap() != MODE::CTR {
+                // Clear context unless processing CTR vectors
+                context = None;
+            }
+
+            let crypto_op_set =
+                CryptoOperationSet { context: context.clone(), operations: cmd_list };
+            let mut crypto_sets = Vec::new();
+            crypto_sets.push(crypto_op_set);
+            let mut additional_error_info =
+                CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+
+            let mut op_result = hw_crypto_ops
+                .processCommandList(&mut crypto_sets, &mut additional_error_info)
+                .expect("couldn't process commands");
+
+            // Capture context to be used with CTR vectors whenever we have a new IV
+            if new_iv {
+                context = op_result.remove(0).context;
+            }
+
+            // Verify results
+            let CryptoOperation::DataOutput(OperationData::DataBuffer(processed_data)) =
+                crypto_sets.remove(0).operations.remove(0)
+            else {
+                panic!("not reachable, we created this object above on the test");
+            };
+
+            match v.op.as_ref().unwrap() {
+                OPERATION::ENCRYPT => {
+                    expect!(processed_data.to_vec() == ciphertext, "Known answer mismatch")
+                }
+                OPERATION::DECRYPT => {
+                    expect!(processed_data.to_vec() == plaintext, "Known answer mismatch")
+                }
+            };
+        }
+    }
+}
diff --git a/hwcryptokey-test/main.rs b/hwcryptokey-test/main.rs
index 18666f5..1729407 100644
--- a/hwcryptokey-test/main.rs
+++ b/hwcryptokey-test/main.rs
@@ -14,7 +14,9 @@
  * limitations under the License.
  */
 
+mod aes_vectors;
 mod versioned_keys_explicit;
+mod versioned_keys_opaque;
 
 #[cfg(test)]
 mod tests {
diff --git a/hwcryptokey-test/manifest.json b/hwcryptokey-test/manifest.json
index 5a11488..c2423fe 100644
--- a/hwcryptokey-test/manifest.json
+++ b/hwcryptokey-test/manifest.json
@@ -1,6 +1,6 @@
 {
     "app_name": "hwcryptokey_test",
     "uuid": "1f365041-823e-4387-90ae-dad2f55f1d3e",
-    "min_heap": 118784,
+    "min_heap": 487424,
     "min_stack": 32768
 }
diff --git a/hwcryptokey-test/rules.mk b/hwcryptokey-test/rules.mk
index 7433d49..af080dd 100644
--- a/hwcryptokey-test/rules.mk
+++ b/hwcryptokey-test/rules.mk
@@ -28,7 +28,9 @@ MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust \
 	frameworks/native/libs/binder/trusty/rust/rpcbinder \
 	trusty/user/app/sample/hwcryptohal/aidl/rust  \
+	trusty/user/app/sample/hwcryptohal/common \
 	trusty/user/base/lib/trusty-std \
+	external/rust/crates/log \
 
 MODULE_RUST_TESTS := true
 
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCGFSbox128.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCGFSbox128.rsp
new file mode 100644
index 0000000..cd95971
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCGFSbox128.rsp
@@ -0,0 +1,95 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS GFSbox test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 128
+# Generated on Fri Apr 22 15:11:33 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
+CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
+
+COUNT = 1
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 9798c4640bad75c7c3227db910174e72
+CIPHERTEXT = a9a1631bf4996954ebc093957b234589
+
+COUNT = 2
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 96ab5c2ff612d9dfaae8c31f30c42168
+CIPHERTEXT = ff4f8391a6a40ca5b25d23bedd44a597
+
+COUNT = 3
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 6a118a874519e64e9963798a503f1d35
+CIPHERTEXT = dc43be40be0e53712f7e2bf5ca707209
+
+COUNT = 4
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = cb9fceec81286ca3e989bd979b0cb284
+CIPHERTEXT = 92beedab1895a94faa69b632e5cc47ce
+
+COUNT = 5
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = b26aeb1874e47ca8358ff22378f09144
+CIPHERTEXT = 459264f4798f6a78bacb89c15ed3d601
+
+COUNT = 6
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 58c8e00b2631686d54eab84b91f0aca1
+CIPHERTEXT = 08a4e2efec8a8e3312ca7460b9040bbf
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
+PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
+
+COUNT = 1
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a9a1631bf4996954ebc093957b234589
+PLAINTEXT = 9798c4640bad75c7c3227db910174e72
+
+COUNT = 2
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ff4f8391a6a40ca5b25d23bedd44a597
+PLAINTEXT = 96ab5c2ff612d9dfaae8c31f30c42168
+
+COUNT = 3
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dc43be40be0e53712f7e2bf5ca707209
+PLAINTEXT = 6a118a874519e64e9963798a503f1d35
+
+COUNT = 4
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 92beedab1895a94faa69b632e5cc47ce
+PLAINTEXT = cb9fceec81286ca3e989bd979b0cb284
+
+COUNT = 5
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 459264f4798f6a78bacb89c15ed3d601
+PLAINTEXT = b26aeb1874e47ca8358ff22378f09144
+
+COUNT = 6
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 08a4e2efec8a8e3312ca7460b9040bbf
+PLAINTEXT = 58c8e00b2631686d54eab84b91f0aca1
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCGFSbox256.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCGFSbox256.rsp
new file mode 100644
index 0000000..db99b2c
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCGFSbox256.rsp
@@ -0,0 +1,71 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS GFSbox test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 256
+# Generated on Fri Apr 22 15:11:38 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 014730f80ac625fe84f026c60bfd547d
+CIPHERTEXT = 5c9d844ed46f9885085e5d6a4f94c7d7
+
+COUNT = 1
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 0b24af36193ce4665f2825d7b4749c98
+CIPHERTEXT = a9ff75bd7cf6613d3731c77c3b6d0c04
+
+COUNT = 2
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 761c1fe41a18acf20d241650611d90f1
+CIPHERTEXT = 623a52fcea5d443e48d9181ab32c7421
+
+COUNT = 3
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 8a560769d605868ad80d819bdba03771
+CIPHERTEXT = 38f2c7ae10612415d27ca190d27da8b4
+
+COUNT = 4
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 91fbef2d15a97816060bee1feaa49afe
+CIPHERTEXT = 1bc704f1bce135ceb810341b216d7abe
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5c9d844ed46f9885085e5d6a4f94c7d7
+PLAINTEXT = 014730f80ac625fe84f026c60bfd547d
+
+COUNT = 1
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a9ff75bd7cf6613d3731c77c3b6d0c04
+PLAINTEXT = 0b24af36193ce4665f2825d7b4749c98
+
+COUNT = 2
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 623a52fcea5d443e48d9181ab32c7421
+PLAINTEXT = 761c1fe41a18acf20d241650611d90f1
+
+COUNT = 3
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 38f2c7ae10612415d27ca190d27da8b4
+PLAINTEXT = 8a560769d605868ad80d819bdba03771
+
+COUNT = 4
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1bc704f1bce135ceb810341b216d7abe
+PLAINTEXT = 91fbef2d15a97816060bee1feaa49afe
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCKeySbox128.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCKeySbox128.rsp
new file mode 100644
index 0000000..0c4a2e3
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCKeySbox128.rsp
@@ -0,0 +1,263 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS KeySbox test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 128
+# Generated on Fri Apr 22 15:11:33 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 10a58869d74be5a374cf867cfb473859
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6d251e6944b051e04eaa6fb4dbf78465
+
+COUNT = 1
+KEY = caea65cdbb75e9169ecd22ebe6e54675
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6e29201190152df4ee058139def610bb
+
+COUNT = 2
+KEY = a2e2fa9baf7d20822ca9f0542f764a41
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c3b44b95d9d2f25670eee9a0de099fa3
+
+COUNT = 3
+KEY = b6364ac4e1de1e285eaf144a2415f7a0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5d9b05578fc944b3cf1ccf0e746cd581
+
+COUNT = 4
+KEY = 64cf9c7abc50b888af65f49d521944b2
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f7efc89d5dba578104016ce5ad659c05
+
+COUNT = 5
+KEY = 47d6742eefcc0465dc96355e851b64d9
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0306194f666d183624aa230a8b264ae7
+
+COUNT = 6
+KEY = 3eb39790678c56bee34bbcdeccf6cdb5
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 858075d536d79ccee571f7d7204b1f67
+
+COUNT = 7
+KEY = 64110a924f0743d500ccadae72c13427
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 35870c6a57e9e92314bcb8087cde72ce
+
+COUNT = 8
+KEY = 18d8126516f8a12ab1a36d9f04d68e51
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6c68e9be5ec41e22c825b7c7affb4363
+
+COUNT = 9
+KEY = f530357968578480b398a3c251cd1093
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f5df39990fc688f1b07224cc03e86cea
+
+COUNT = 10
+KEY = da84367f325d42d601b4326964802e8e
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = bba071bcb470f8f6586e5d3add18bc66
+
+COUNT = 11
+KEY = e37b1c6aa2846f6fdb413f238b089f23
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 43c9f7e62f5d288bb27aa40ef8fe1ea8
+
+COUNT = 12
+KEY = 6c002b682483e0cabcc731c253be5674
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3580d19cff44f1014a7c966a69059de5
+
+COUNT = 13
+KEY = 143ae8ed6555aba96110ab58893a8ae1
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 806da864dd29d48deafbe764f8202aef
+
+COUNT = 14
+KEY = b69418a85332240dc82492353956ae0c
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a303d940ded8f0baff6f75414cac5243
+
+COUNT = 15
+KEY = 71b5c08a1993e1362e4d0ce9b22b78d5
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c2dabd117f8a3ecabfbb11d12194d9d0
+
+COUNT = 16
+KEY = e234cdca2606b81f29408d5f6da21206
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fff60a4740086b3b9c56195b98d91a7b
+
+COUNT = 17
+KEY = 13237c49074a3da078dc1d828bb78c6f
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8146a08e2357f0caa30ca8c94d1a0544
+
+COUNT = 18
+KEY = 3071a2a48fe6cbd04f1a129098e308f8
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4b98e06d356deb07ebb824e5713f7be3
+
+COUNT = 19
+KEY = 90f42ec0f68385f2ffc5dfc03a654dce
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7a20a53d460fc9ce0423a7a0764c6cf2
+
+COUNT = 20
+KEY = febd9a24d8b65c1c787d50a4ed3619a9
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f4a70d8af877f9b02b4c40df57d45b17
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 10a58869d74be5a374cf867cfb473859
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6d251e6944b051e04eaa6fb4dbf78465
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 1
+KEY = caea65cdbb75e9169ecd22ebe6e54675
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6e29201190152df4ee058139def610bb
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 2
+KEY = a2e2fa9baf7d20822ca9f0542f764a41
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c3b44b95d9d2f25670eee9a0de099fa3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 3
+KEY = b6364ac4e1de1e285eaf144a2415f7a0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5d9b05578fc944b3cf1ccf0e746cd581
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 4
+KEY = 64cf9c7abc50b888af65f49d521944b2
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f7efc89d5dba578104016ce5ad659c05
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 5
+KEY = 47d6742eefcc0465dc96355e851b64d9
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0306194f666d183624aa230a8b264ae7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 6
+KEY = 3eb39790678c56bee34bbcdeccf6cdb5
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 858075d536d79ccee571f7d7204b1f67
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 7
+KEY = 64110a924f0743d500ccadae72c13427
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 35870c6a57e9e92314bcb8087cde72ce
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 8
+KEY = 18d8126516f8a12ab1a36d9f04d68e51
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6c68e9be5ec41e22c825b7c7affb4363
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 9
+KEY = f530357968578480b398a3c251cd1093
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f5df39990fc688f1b07224cc03e86cea
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 10
+KEY = da84367f325d42d601b4326964802e8e
+IV = 00000000000000000000000000000000
+CIPHERTEXT = bba071bcb470f8f6586e5d3add18bc66
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 11
+KEY = e37b1c6aa2846f6fdb413f238b089f23
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 43c9f7e62f5d288bb27aa40ef8fe1ea8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 12
+KEY = 6c002b682483e0cabcc731c253be5674
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3580d19cff44f1014a7c966a69059de5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 13
+KEY = 143ae8ed6555aba96110ab58893a8ae1
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 806da864dd29d48deafbe764f8202aef
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 14
+KEY = b69418a85332240dc82492353956ae0c
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a303d940ded8f0baff6f75414cac5243
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 15
+KEY = 71b5c08a1993e1362e4d0ce9b22b78d5
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c2dabd117f8a3ecabfbb11d12194d9d0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 16
+KEY = e234cdca2606b81f29408d5f6da21206
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fff60a4740086b3b9c56195b98d91a7b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 17
+KEY = 13237c49074a3da078dc1d828bb78c6f
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8146a08e2357f0caa30ca8c94d1a0544
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 18
+KEY = 3071a2a48fe6cbd04f1a129098e308f8
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4b98e06d356deb07ebb824e5713f7be3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 19
+KEY = 90f42ec0f68385f2ffc5dfc03a654dce
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7a20a53d460fc9ce0423a7a0764c6cf2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 20
+KEY = febd9a24d8b65c1c787d50a4ed3619a9
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f4a70d8af877f9b02b4c40df57d45b17
+PLAINTEXT = 00000000000000000000000000000000
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCKeySbox256.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCKeySbox256.rsp
new file mode 100644
index 0000000..0ebe408
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCKeySbox256.rsp
@@ -0,0 +1,203 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS KeySbox test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 256
+# Generated on Fri Apr 22 15:11:38 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 46f2fb342d6f0ab477476fc501242c5f
+
+COUNT = 1
+KEY = 28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4bf3b0a69aeb6657794f2901b1440ad4
+
+COUNT = 2
+KEY = c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 352065272169abf9856843927d0674fd
+
+COUNT = 3
+KEY = 984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4307456a9e67813b452e15fa8fffe398
+
+COUNT = 4
+KEY = b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4663446607354989477a5c6f0f007ef4
+
+COUNT = 5
+KEY = 1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 531c2c38344578b84d50b3c917bbb6e1
+
+COUNT = 6
+KEY = dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fc6aec906323480005c58e7e1ab004ad
+
+COUNT = 7
+KEY = f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a3944b95ca0b52043584ef02151926a8
+
+COUNT = 8
+KEY = 797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a74289fe73a4c123ca189ea1e1b49ad5
+
+COUNT = 9
+KEY = 6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b91d4ea4488644b56cf0812fa7fcf5fc
+
+COUNT = 10
+KEY = ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 304f81ab61a80c2e743b94d5002a126b
+
+COUNT = 11
+KEY = 13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 649a71545378c783e368c9ade7114f6c
+
+COUNT = 12
+KEY = 07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 47cb030da2ab051dfc6c4bf6910d12bb
+
+COUNT = 13
+KEY = 90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 798c7c005dee432b2c8ea5dfa381ecc3
+
+COUNT = 14
+KEY = b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 637c31dc2591a07636f646b72daabbe7
+
+COUNT = 15
+KEY = fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 179a49c712154bbffbe6e7a84a18e220
+
+[DECRYPT]
+
+COUNT = 0
+KEY = c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 46f2fb342d6f0ab477476fc501242c5f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 1
+KEY = 28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4bf3b0a69aeb6657794f2901b1440ad4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 2
+KEY = c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 352065272169abf9856843927d0674fd
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 3
+KEY = 984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4307456a9e67813b452e15fa8fffe398
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 4
+KEY = b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4663446607354989477a5c6f0f007ef4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 5
+KEY = 1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 531c2c38344578b84d50b3c917bbb6e1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 6
+KEY = dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fc6aec906323480005c58e7e1ab004ad
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 7
+KEY = f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a3944b95ca0b52043584ef02151926a8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 8
+KEY = 797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a74289fe73a4c123ca189ea1e1b49ad5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 9
+KEY = 6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b91d4ea4488644b56cf0812fa7fcf5fc
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 10
+KEY = ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 304f81ab61a80c2e743b94d5002a126b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 11
+KEY = 13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 649a71545378c783e368c9ade7114f6c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 12
+KEY = 07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 47cb030da2ab051dfc6c4bf6910d12bb
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 13
+KEY = 90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 798c7c005dee432b2c8ea5dfa381ecc3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 14
+KEY = b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 637c31dc2591a07636f646b72daabbe7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 15
+KEY = fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 179a49c712154bbffbe6e7a84a18e220
+PLAINTEXT = 00000000000000000000000000000000
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarKey128.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarKey128.rsp
new file mode 100644
index 0000000..e250c59
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarKey128.rsp
@@ -0,0 +1,1547 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS VarKey test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 128
+# Generated on Fri Apr 22 15:11:33 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 80000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0edd33d3c621e546455bd8ba1418bec8
+
+COUNT = 1
+KEY = c0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4bc3f883450c113c64ca42e1112a9e87
+
+COUNT = 2
+KEY = e0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 72a1da770f5d7ac4c9ef94d822affd97
+
+COUNT = 3
+KEY = f0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 970014d634e2b7650777e8e84d03ccd8
+
+COUNT = 4
+KEY = f8000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f17e79aed0db7e279e955b5f493875a7
+
+COUNT = 5
+KEY = fc000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9ed5a75136a940d0963da379db4af26a
+
+COUNT = 6
+KEY = fe000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c4295f83465c7755e8fa364bac6a7ea5
+
+COUNT = 7
+KEY = ff000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b1d758256b28fd850ad4944208cf1155
+
+COUNT = 8
+KEY = ff800000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 42ffb34c743de4d88ca38011c990890b
+
+COUNT = 9
+KEY = ffc00000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9958f0ecea8b2172c0c1995f9182c0f3
+
+COUNT = 10
+KEY = ffe00000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 956d7798fac20f82a8823f984d06f7f5
+
+COUNT = 11
+KEY = fff00000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a01bf44f2d16be928ca44aaf7b9b106b
+
+COUNT = 12
+KEY = fff80000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b5f1a33e50d40d103764c76bd4c6b6f8
+
+COUNT = 13
+KEY = fffc0000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2637050c9fc0d4817e2d69de878aee8d
+
+COUNT = 14
+KEY = fffe0000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 113ecbe4a453269a0dd26069467fb5b5
+
+COUNT = 15
+KEY = ffff0000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 97d0754fe68f11b9e375d070a608c884
+
+COUNT = 16
+KEY = ffff8000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c6a0b3e998d05068a5399778405200b4
+
+COUNT = 17
+KEY = ffffc000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = df556a33438db87bc41b1752c55e5e49
+
+COUNT = 18
+KEY = ffffe000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 90fb128d3a1af6e548521bb962bf1f05
+
+COUNT = 19
+KEY = fffff000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 26298e9c1db517c215fadfb7d2a8d691
+
+COUNT = 20
+KEY = fffff800000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a6cb761d61f8292d0df393a279ad0380
+
+COUNT = 21
+KEY = fffffc00000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 12acd89b13cd5f8726e34d44fd486108
+
+COUNT = 22
+KEY = fffffe00000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 95b1703fc57ba09fe0c3580febdd7ed4
+
+COUNT = 23
+KEY = ffffff00000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = de11722d893e9f9121c381becc1da59a
+
+COUNT = 24
+KEY = ffffff80000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6d114ccb27bf391012e8974c546d9bf2
+
+COUNT = 25
+KEY = ffffffc0000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5ce37e17eb4646ecfac29b9cc38d9340
+
+COUNT = 26
+KEY = ffffffe0000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 18c1b6e2157122056d0243d8a165cddb
+
+COUNT = 27
+KEY = fffffff0000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 99693e6a59d1366c74d823562d7e1431
+
+COUNT = 28
+KEY = fffffff8000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6c7c64dc84a8bba758ed17eb025a57e3
+
+COUNT = 29
+KEY = fffffffc000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e17bc79f30eaab2fac2cbbe3458d687a
+
+COUNT = 30
+KEY = fffffffe000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1114bc2028009b923f0b01915ce5e7c4
+
+COUNT = 31
+KEY = ffffffff000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9c28524a16a1e1c1452971caa8d13476
+
+COUNT = 32
+KEY = ffffffff800000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ed62e16363638360fdd6ad62112794f0
+
+COUNT = 33
+KEY = ffffffffc00000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5a8688f0b2a2c16224c161658ffd4044
+
+COUNT = 34
+KEY = ffffffffe00000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 23f710842b9bb9c32f26648c786807ca
+
+COUNT = 35
+KEY = fffffffff00000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 44a98bf11e163f632c47ec6a49683a89
+
+COUNT = 36
+KEY = fffffffff80000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0f18aff94274696d9b61848bd50ac5e5
+
+COUNT = 37
+KEY = fffffffffc0000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 82408571c3e2424540207f833b6dda69
+
+COUNT = 38
+KEY = fffffffffe0000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 303ff996947f0c7d1f43c8f3027b9b75
+
+COUNT = 39
+KEY = ffffffffff0000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7df4daf4ad29a3615a9b6ece5c99518a
+
+COUNT = 40
+KEY = ffffffffff8000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c72954a48d0774db0b4971c526260415
+
+COUNT = 41
+KEY = ffffffffffc000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1df9b76112dc6531e07d2cfda04411f0
+
+COUNT = 42
+KEY = ffffffffffe000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8e4d8e699119e1fc87545a647fb1d34f
+
+COUNT = 43
+KEY = fffffffffff000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e6c4807ae11f36f091c57d9fb68548d1
+
+COUNT = 44
+KEY = fffffffffff800000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8ebf73aad49c82007f77a5c1ccec6ab4
+
+COUNT = 45
+KEY = fffffffffffc00000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4fb288cc2040049001d2c7585ad123fc
+
+COUNT = 46
+KEY = fffffffffffe00000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 04497110efb9dceb13e2b13fb4465564
+
+COUNT = 47
+KEY = ffffffffffff00000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 75550e6cb5a88e49634c9ab69eda0430
+
+COUNT = 48
+KEY = ffffffffffff80000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b6768473ce9843ea66a81405dd50b345
+
+COUNT = 49
+KEY = ffffffffffffc0000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cb2f430383f9084e03a653571e065de6
+
+COUNT = 50
+KEY = ffffffffffffe0000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ff4e66c07bae3e79fb7d210847a3b0ba
+
+COUNT = 51
+KEY = fffffffffffff0000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7b90785125505fad59b13c186dd66ce3
+
+COUNT = 52
+KEY = fffffffffffff8000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8b527a6aebdaec9eaef8eda2cb7783e5
+
+COUNT = 53
+KEY = fffffffffffffc000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 43fdaf53ebbc9880c228617d6a9b548b
+
+COUNT = 54
+KEY = fffffffffffffe000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 53786104b9744b98f052c46f1c850d0b
+
+COUNT = 55
+KEY = ffffffffffffff000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b5ab3013dd1e61df06cbaf34ca2aee78
+
+COUNT = 56
+KEY = ffffffffffffff800000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7470469be9723030fdcc73a8cd4fbb10
+
+COUNT = 57
+KEY = ffffffffffffffc00000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a35a63f5343ebe9ef8167bcb48ad122e
+
+COUNT = 58
+KEY = ffffffffffffffe00000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fd8687f0757a210e9fdf181204c30863
+
+COUNT = 59
+KEY = fffffffffffffff00000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7a181e84bd5457d26a88fbae96018fb0
+
+COUNT = 60
+KEY = fffffffffffffff80000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 653317b9362b6f9b9e1a580e68d494b5
+
+COUNT = 61
+KEY = fffffffffffffffc0000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 995c9dc0b689f03c45867b5faa5c18d1
+
+COUNT = 62
+KEY = fffffffffffffffe0000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 77a4d96d56dda398b9aabecfc75729fd
+
+COUNT = 63
+KEY = ffffffffffffffff0000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 84be19e053635f09f2665e7bae85b42d
+
+COUNT = 64
+KEY = ffffffffffffffff8000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 32cd652842926aea4aa6137bb2be2b5e
+
+COUNT = 65
+KEY = ffffffffffffffffc000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 493d4a4f38ebb337d10aa84e9171a554
+
+COUNT = 66
+KEY = ffffffffffffffffe000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d9bff7ff454b0ec5a4a2a69566e2cb84
+
+COUNT = 67
+KEY = fffffffffffffffff000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3535d565ace3f31eb249ba2cc6765d7a
+
+COUNT = 68
+KEY = fffffffffffffffff800000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f60e91fc3269eecf3231c6e9945697c6
+
+COUNT = 69
+KEY = fffffffffffffffffc00000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ab69cfadf51f8e604d9cc37182f6635a
+
+COUNT = 70
+KEY = fffffffffffffffffe00000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7866373f24a0b6ed56e0d96fcdafb877
+
+COUNT = 71
+KEY = ffffffffffffffffff00000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1ea448c2aac954f5d812e9d78494446a
+
+COUNT = 72
+KEY = ffffffffffffffffff80000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = acc5599dd8ac02239a0fef4a36dd1668
+
+COUNT = 73
+KEY = ffffffffffffffffffc0000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d8764468bb103828cf7e1473ce895073
+
+COUNT = 74
+KEY = ffffffffffffffffffe0000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1b0d02893683b9f180458e4aa6b73982
+
+COUNT = 75
+KEY = fffffffffffffffffff0000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 96d9b017d302df410a937dcdb8bb6e43
+
+COUNT = 76
+KEY = fffffffffffffffffff8000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ef1623cc44313cff440b1594a7e21cc6
+
+COUNT = 77
+KEY = fffffffffffffffffffc000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 284ca2fa35807b8b0ae4d19e11d7dbd7
+
+COUNT = 78
+KEY = fffffffffffffffffffe000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f2e976875755f9401d54f36e2a23a594
+
+COUNT = 79
+KEY = ffffffffffffffffffff000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ec198a18e10e532403b7e20887c8dd80
+
+COUNT = 80
+KEY = ffffffffffffffffffff800000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 545d50ebd919e4a6949d96ad47e46a80
+
+COUNT = 81
+KEY = ffffffffffffffffffffc00000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = dbdfb527060e0a71009c7bb0c68f1d44
+
+COUNT = 82
+KEY = ffffffffffffffffffffe00000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9cfa1322ea33da2173a024f2ff0d896d
+
+COUNT = 83
+KEY = fffffffffffffffffffff00000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8785b1a75b0f3bd958dcd0e29318c521
+
+COUNT = 84
+KEY = fffffffffffffffffffff80000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 38f67b9e98e4a97b6df030a9fcdd0104
+
+COUNT = 85
+KEY = fffffffffffffffffffffc0000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 192afffb2c880e82b05926d0fc6c448b
+
+COUNT = 86
+KEY = fffffffffffffffffffffe0000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6a7980ce7b105cf530952d74daaf798c
+
+COUNT = 87
+KEY = ffffffffffffffffffffff0000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ea3695e1351b9d6858bd958cf513ef6c
+
+COUNT = 88
+KEY = ffffffffffffffffffffff8000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6da0490ba0ba0343b935681d2cce5ba1
+
+COUNT = 89
+KEY = ffffffffffffffffffffffc000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f0ea23af08534011c60009ab29ada2f1
+
+COUNT = 90
+KEY = ffffffffffffffffffffffe000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ff13806cf19cc38721554d7c0fcdcd4b
+
+COUNT = 91
+KEY = fffffffffffffffffffffff000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6838af1f4f69bae9d85dd188dcdf0688
+
+COUNT = 92
+KEY = fffffffffffffffffffffff800000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 36cf44c92d550bfb1ed28ef583ddf5d7
+
+COUNT = 93
+KEY = fffffffffffffffffffffffc00000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d06e3195b5376f109d5c4ec6c5d62ced
+
+COUNT = 94
+KEY = fffffffffffffffffffffffe00000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c440de014d3d610707279b13242a5c36
+
+COUNT = 95
+KEY = ffffffffffffffffffffffff00000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f0c5c6ffa5e0bd3a94c88f6b6f7c16b9
+
+COUNT = 96
+KEY = ffffffffffffffffffffffff80000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3e40c3901cd7effc22bffc35dee0b4d9
+
+COUNT = 97
+KEY = ffffffffffffffffffffffffc0000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b63305c72bedfab97382c406d0c49bc6
+
+COUNT = 98
+KEY = ffffffffffffffffffffffffe0000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 36bbaab22a6bd4925a99a2b408d2dbae
+
+COUNT = 99
+KEY = fffffffffffffffffffffffff0000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 307c5b8fcd0533ab98bc51e27a6ce461
+
+COUNT = 100
+KEY = fffffffffffffffffffffffff8000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 829c04ff4c07513c0b3ef05c03e337b5
+
+COUNT = 101
+KEY = fffffffffffffffffffffffffc000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f17af0e895dda5eb98efc68066e84c54
+
+COUNT = 102
+KEY = fffffffffffffffffffffffffe000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 277167f3812afff1ffacb4a934379fc3
+
+COUNT = 103
+KEY = ffffffffffffffffffffffffff000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2cb1dc3a9c72972e425ae2ef3eb597cd
+
+COUNT = 104
+KEY = ffffffffffffffffffffffffff800000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 36aeaa3a213e968d4b5b679d3a2c97fe
+
+COUNT = 105
+KEY = ffffffffffffffffffffffffffc00000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9241daca4fdd034a82372db50e1a0f3f
+
+COUNT = 106
+KEY = ffffffffffffffffffffffffffe00000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c14574d9cd00cf2b5a7f77e53cd57885
+
+COUNT = 107
+KEY = fffffffffffffffffffffffffff00000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 793de39236570aba83ab9b737cb521c9
+
+COUNT = 108
+KEY = fffffffffffffffffffffffffff80000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 16591c0f27d60e29b85a96c33861a7ef
+
+COUNT = 109
+KEY = fffffffffffffffffffffffffffc0000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 44fb5c4d4f5cb79be5c174a3b1c97348
+
+COUNT = 110
+KEY = fffffffffffffffffffffffffffe0000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 674d2b61633d162be59dde04222f4740
+
+COUNT = 111
+KEY = ffffffffffffffffffffffffffff0000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b4750ff263a65e1f9e924ccfd98f3e37
+
+COUNT = 112
+KEY = ffffffffffffffffffffffffffff8000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 62d0662d6eaeddedebae7f7ea3a4f6b6
+
+COUNT = 113
+KEY = ffffffffffffffffffffffffffffc000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 70c46bb30692be657f7eaa93ebad9897
+
+COUNT = 114
+KEY = ffffffffffffffffffffffffffffe000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 323994cfb9da285a5d9642e1759b224a
+
+COUNT = 115
+KEY = fffffffffffffffffffffffffffff000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1dbf57877b7b17385c85d0b54851e371
+
+COUNT = 116
+KEY = fffffffffffffffffffffffffffff800
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = dfa5c097cdc1532ac071d57b1d28d1bd
+
+COUNT = 117
+KEY = fffffffffffffffffffffffffffffc00
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3a0c53fa37311fc10bd2a9981f513174
+
+COUNT = 118
+KEY = fffffffffffffffffffffffffffffe00
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ba4f970c0a25c41814bdae2e506be3b4
+
+COUNT = 119
+KEY = ffffffffffffffffffffffffffffff00
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2dce3acb727cd13ccd76d425ea56e4f6
+
+COUNT = 120
+KEY = ffffffffffffffffffffffffffffff80
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5160474d504b9b3eefb68d35f245f4b3
+
+COUNT = 121
+KEY = ffffffffffffffffffffffffffffffc0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 41a8a947766635dec37553d9a6c0cbb7
+
+COUNT = 122
+KEY = ffffffffffffffffffffffffffffffe0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 25d6cfe6881f2bf497dd14cd4ddf445b
+
+COUNT = 123
+KEY = fffffffffffffffffffffffffffffff0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 41c78c135ed9e98c096640647265da1e
+
+COUNT = 124
+KEY = fffffffffffffffffffffffffffffff8
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5a4d404d8917e353e92a21072c3b2305
+
+COUNT = 125
+KEY = fffffffffffffffffffffffffffffffc
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 02bc96846b3fdc71643f384cd3cc3eaf
+
+COUNT = 126
+KEY = fffffffffffffffffffffffffffffffe
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9ba4a9143f4e5d4048521c4f8877d88e
+
+COUNT = 127
+KEY = ffffffffffffffffffffffffffffffff
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a1f6258c877d5fcd8964484538bfc92c
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 80000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0edd33d3c621e546455bd8ba1418bec8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 1
+KEY = c0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4bc3f883450c113c64ca42e1112a9e87
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 2
+KEY = e0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 72a1da770f5d7ac4c9ef94d822affd97
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 3
+KEY = f0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 970014d634e2b7650777e8e84d03ccd8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 4
+KEY = f8000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f17e79aed0db7e279e955b5f493875a7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 5
+KEY = fc000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9ed5a75136a940d0963da379db4af26a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 6
+KEY = fe000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c4295f83465c7755e8fa364bac6a7ea5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 7
+KEY = ff000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b1d758256b28fd850ad4944208cf1155
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 8
+KEY = ff800000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 42ffb34c743de4d88ca38011c990890b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 9
+KEY = ffc00000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9958f0ecea8b2172c0c1995f9182c0f3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 10
+KEY = ffe00000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 956d7798fac20f82a8823f984d06f7f5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 11
+KEY = fff00000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a01bf44f2d16be928ca44aaf7b9b106b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 12
+KEY = fff80000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b5f1a33e50d40d103764c76bd4c6b6f8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 13
+KEY = fffc0000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2637050c9fc0d4817e2d69de878aee8d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 14
+KEY = fffe0000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 113ecbe4a453269a0dd26069467fb5b5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 15
+KEY = ffff0000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 97d0754fe68f11b9e375d070a608c884
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 16
+KEY = ffff8000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c6a0b3e998d05068a5399778405200b4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 17
+KEY = ffffc000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = df556a33438db87bc41b1752c55e5e49
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 18
+KEY = ffffe000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 90fb128d3a1af6e548521bb962bf1f05
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 19
+KEY = fffff000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 26298e9c1db517c215fadfb7d2a8d691
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 20
+KEY = fffff800000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a6cb761d61f8292d0df393a279ad0380
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 21
+KEY = fffffc00000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 12acd89b13cd5f8726e34d44fd486108
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 22
+KEY = fffffe00000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 95b1703fc57ba09fe0c3580febdd7ed4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 23
+KEY = ffffff00000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = de11722d893e9f9121c381becc1da59a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 24
+KEY = ffffff80000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6d114ccb27bf391012e8974c546d9bf2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 25
+KEY = ffffffc0000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5ce37e17eb4646ecfac29b9cc38d9340
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 26
+KEY = ffffffe0000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 18c1b6e2157122056d0243d8a165cddb
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 27
+KEY = fffffff0000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 99693e6a59d1366c74d823562d7e1431
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 28
+KEY = fffffff8000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6c7c64dc84a8bba758ed17eb025a57e3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 29
+KEY = fffffffc000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e17bc79f30eaab2fac2cbbe3458d687a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 30
+KEY = fffffffe000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1114bc2028009b923f0b01915ce5e7c4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 31
+KEY = ffffffff000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9c28524a16a1e1c1452971caa8d13476
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 32
+KEY = ffffffff800000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ed62e16363638360fdd6ad62112794f0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 33
+KEY = ffffffffc00000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5a8688f0b2a2c16224c161658ffd4044
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 34
+KEY = ffffffffe00000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 23f710842b9bb9c32f26648c786807ca
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 35
+KEY = fffffffff00000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 44a98bf11e163f632c47ec6a49683a89
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 36
+KEY = fffffffff80000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0f18aff94274696d9b61848bd50ac5e5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 37
+KEY = fffffffffc0000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 82408571c3e2424540207f833b6dda69
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 38
+KEY = fffffffffe0000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 303ff996947f0c7d1f43c8f3027b9b75
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 39
+KEY = ffffffffff0000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7df4daf4ad29a3615a9b6ece5c99518a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 40
+KEY = ffffffffff8000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c72954a48d0774db0b4971c526260415
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 41
+KEY = ffffffffffc000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1df9b76112dc6531e07d2cfda04411f0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 42
+KEY = ffffffffffe000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8e4d8e699119e1fc87545a647fb1d34f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 43
+KEY = fffffffffff000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e6c4807ae11f36f091c57d9fb68548d1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 44
+KEY = fffffffffff800000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8ebf73aad49c82007f77a5c1ccec6ab4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 45
+KEY = fffffffffffc00000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4fb288cc2040049001d2c7585ad123fc
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 46
+KEY = fffffffffffe00000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 04497110efb9dceb13e2b13fb4465564
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 47
+KEY = ffffffffffff00000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 75550e6cb5a88e49634c9ab69eda0430
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 48
+KEY = ffffffffffff80000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b6768473ce9843ea66a81405dd50b345
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 49
+KEY = ffffffffffffc0000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cb2f430383f9084e03a653571e065de6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 50
+KEY = ffffffffffffe0000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ff4e66c07bae3e79fb7d210847a3b0ba
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 51
+KEY = fffffffffffff0000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7b90785125505fad59b13c186dd66ce3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 52
+KEY = fffffffffffff8000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8b527a6aebdaec9eaef8eda2cb7783e5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 53
+KEY = fffffffffffffc000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 43fdaf53ebbc9880c228617d6a9b548b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 54
+KEY = fffffffffffffe000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 53786104b9744b98f052c46f1c850d0b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 55
+KEY = ffffffffffffff000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b5ab3013dd1e61df06cbaf34ca2aee78
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 56
+KEY = ffffffffffffff800000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7470469be9723030fdcc73a8cd4fbb10
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 57
+KEY = ffffffffffffffc00000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a35a63f5343ebe9ef8167bcb48ad122e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 58
+KEY = ffffffffffffffe00000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fd8687f0757a210e9fdf181204c30863
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 59
+KEY = fffffffffffffff00000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7a181e84bd5457d26a88fbae96018fb0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 60
+KEY = fffffffffffffff80000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 653317b9362b6f9b9e1a580e68d494b5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 61
+KEY = fffffffffffffffc0000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 995c9dc0b689f03c45867b5faa5c18d1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 62
+KEY = fffffffffffffffe0000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 77a4d96d56dda398b9aabecfc75729fd
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 63
+KEY = ffffffffffffffff0000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 84be19e053635f09f2665e7bae85b42d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 64
+KEY = ffffffffffffffff8000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 32cd652842926aea4aa6137bb2be2b5e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 65
+KEY = ffffffffffffffffc000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 493d4a4f38ebb337d10aa84e9171a554
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 66
+KEY = ffffffffffffffffe000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d9bff7ff454b0ec5a4a2a69566e2cb84
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 67
+KEY = fffffffffffffffff000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3535d565ace3f31eb249ba2cc6765d7a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 68
+KEY = fffffffffffffffff800000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f60e91fc3269eecf3231c6e9945697c6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 69
+KEY = fffffffffffffffffc00000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ab69cfadf51f8e604d9cc37182f6635a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 70
+KEY = fffffffffffffffffe00000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7866373f24a0b6ed56e0d96fcdafb877
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 71
+KEY = ffffffffffffffffff00000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1ea448c2aac954f5d812e9d78494446a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 72
+KEY = ffffffffffffffffff80000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = acc5599dd8ac02239a0fef4a36dd1668
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 73
+KEY = ffffffffffffffffffc0000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d8764468bb103828cf7e1473ce895073
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 74
+KEY = ffffffffffffffffffe0000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1b0d02893683b9f180458e4aa6b73982
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 75
+KEY = fffffffffffffffffff0000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 96d9b017d302df410a937dcdb8bb6e43
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 76
+KEY = fffffffffffffffffff8000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ef1623cc44313cff440b1594a7e21cc6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 77
+KEY = fffffffffffffffffffc000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 284ca2fa35807b8b0ae4d19e11d7dbd7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 78
+KEY = fffffffffffffffffffe000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f2e976875755f9401d54f36e2a23a594
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 79
+KEY = ffffffffffffffffffff000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ec198a18e10e532403b7e20887c8dd80
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 80
+KEY = ffffffffffffffffffff800000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 545d50ebd919e4a6949d96ad47e46a80
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 81
+KEY = ffffffffffffffffffffc00000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dbdfb527060e0a71009c7bb0c68f1d44
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 82
+KEY = ffffffffffffffffffffe00000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9cfa1322ea33da2173a024f2ff0d896d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 83
+KEY = fffffffffffffffffffff00000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8785b1a75b0f3bd958dcd0e29318c521
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 84
+KEY = fffffffffffffffffffff80000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 38f67b9e98e4a97b6df030a9fcdd0104
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 85
+KEY = fffffffffffffffffffffc0000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 192afffb2c880e82b05926d0fc6c448b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 86
+KEY = fffffffffffffffffffffe0000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6a7980ce7b105cf530952d74daaf798c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 87
+KEY = ffffffffffffffffffffff0000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ea3695e1351b9d6858bd958cf513ef6c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 88
+KEY = ffffffffffffffffffffff8000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6da0490ba0ba0343b935681d2cce5ba1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 89
+KEY = ffffffffffffffffffffffc000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f0ea23af08534011c60009ab29ada2f1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 90
+KEY = ffffffffffffffffffffffe000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ff13806cf19cc38721554d7c0fcdcd4b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 91
+KEY = fffffffffffffffffffffff000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6838af1f4f69bae9d85dd188dcdf0688
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 92
+KEY = fffffffffffffffffffffff800000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 36cf44c92d550bfb1ed28ef583ddf5d7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 93
+KEY = fffffffffffffffffffffffc00000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d06e3195b5376f109d5c4ec6c5d62ced
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 94
+KEY = fffffffffffffffffffffffe00000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c440de014d3d610707279b13242a5c36
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 95
+KEY = ffffffffffffffffffffffff00000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f0c5c6ffa5e0bd3a94c88f6b6f7c16b9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 96
+KEY = ffffffffffffffffffffffff80000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3e40c3901cd7effc22bffc35dee0b4d9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 97
+KEY = ffffffffffffffffffffffffc0000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b63305c72bedfab97382c406d0c49bc6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 98
+KEY = ffffffffffffffffffffffffe0000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 36bbaab22a6bd4925a99a2b408d2dbae
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 99
+KEY = fffffffffffffffffffffffff0000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 307c5b8fcd0533ab98bc51e27a6ce461
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 100
+KEY = fffffffffffffffffffffffff8000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 829c04ff4c07513c0b3ef05c03e337b5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 101
+KEY = fffffffffffffffffffffffffc000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f17af0e895dda5eb98efc68066e84c54
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 102
+KEY = fffffffffffffffffffffffffe000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 277167f3812afff1ffacb4a934379fc3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 103
+KEY = ffffffffffffffffffffffffff000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2cb1dc3a9c72972e425ae2ef3eb597cd
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 104
+KEY = ffffffffffffffffffffffffff800000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 36aeaa3a213e968d4b5b679d3a2c97fe
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 105
+KEY = ffffffffffffffffffffffffffc00000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9241daca4fdd034a82372db50e1a0f3f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 106
+KEY = ffffffffffffffffffffffffffe00000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c14574d9cd00cf2b5a7f77e53cd57885
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 107
+KEY = fffffffffffffffffffffffffff00000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 793de39236570aba83ab9b737cb521c9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 108
+KEY = fffffffffffffffffffffffffff80000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 16591c0f27d60e29b85a96c33861a7ef
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 109
+KEY = fffffffffffffffffffffffffffc0000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 44fb5c4d4f5cb79be5c174a3b1c97348
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 110
+KEY = fffffffffffffffffffffffffffe0000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 674d2b61633d162be59dde04222f4740
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 111
+KEY = ffffffffffffffffffffffffffff0000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b4750ff263a65e1f9e924ccfd98f3e37
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 112
+KEY = ffffffffffffffffffffffffffff8000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 62d0662d6eaeddedebae7f7ea3a4f6b6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 113
+KEY = ffffffffffffffffffffffffffffc000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 70c46bb30692be657f7eaa93ebad9897
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 114
+KEY = ffffffffffffffffffffffffffffe000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 323994cfb9da285a5d9642e1759b224a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 115
+KEY = fffffffffffffffffffffffffffff000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1dbf57877b7b17385c85d0b54851e371
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 116
+KEY = fffffffffffffffffffffffffffff800
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dfa5c097cdc1532ac071d57b1d28d1bd
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 117
+KEY = fffffffffffffffffffffffffffffc00
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3a0c53fa37311fc10bd2a9981f513174
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 118
+KEY = fffffffffffffffffffffffffffffe00
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ba4f970c0a25c41814bdae2e506be3b4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 119
+KEY = ffffffffffffffffffffffffffffff00
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2dce3acb727cd13ccd76d425ea56e4f6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 120
+KEY = ffffffffffffffffffffffffffffff80
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5160474d504b9b3eefb68d35f245f4b3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 121
+KEY = ffffffffffffffffffffffffffffffc0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 41a8a947766635dec37553d9a6c0cbb7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 122
+KEY = ffffffffffffffffffffffffffffffe0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 25d6cfe6881f2bf497dd14cd4ddf445b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 123
+KEY = fffffffffffffffffffffffffffffff0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 41c78c135ed9e98c096640647265da1e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 124
+KEY = fffffffffffffffffffffffffffffff8
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5a4d404d8917e353e92a21072c3b2305
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 125
+KEY = fffffffffffffffffffffffffffffffc
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 02bc96846b3fdc71643f384cd3cc3eaf
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 126
+KEY = fffffffffffffffffffffffffffffffe
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9ba4a9143f4e5d4048521c4f8877d88e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 127
+KEY = ffffffffffffffffffffffffffffffff
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a1f6258c877d5fcd8964484538bfc92c
+PLAINTEXT = 00000000000000000000000000000000
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarKey256.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarKey256.rsp
new file mode 100644
index 0000000..4012fde
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarKey256.rsp
@@ -0,0 +1,3083 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS VarKey test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 256
+# Generated on Fri Apr 22 15:11:38 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 8000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e35a6dcb19b201a01ebcfa8aa22b5759
+
+COUNT = 1
+KEY = c000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b29169cdcf2d83e838125a12ee6aa400
+
+COUNT = 2
+KEY = e000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d8f3a72fc3cdf74dfaf6c3e6b97b2fa6
+
+COUNT = 3
+KEY = f000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1c777679d50037c79491a94da76a9a35
+
+COUNT = 4
+KEY = f800000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9cf4893ecafa0a0247a898e040691559
+
+COUNT = 5
+KEY = fc00000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8fbb413703735326310a269bd3aa94b2
+
+COUNT = 6
+KEY = fe00000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 60e32246bed2b0e859e55c1cc6b26502
+
+COUNT = 7
+KEY = ff00000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ec52a212f80a09df6317021bc2a9819e
+
+COUNT = 8
+KEY = ff80000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f23e5b600eb70dbccf6c0b1d9a68182c
+
+COUNT = 9
+KEY = ffc0000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a3f599d63a82a968c33fe26590745970
+
+COUNT = 10
+KEY = ffe0000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d1ccb9b1337002cbac42c520b5d67722
+
+COUNT = 11
+KEY = fff0000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cc111f6c37cf40a1159d00fb59fb0488
+
+COUNT = 12
+KEY = fff8000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = dc43b51ab609052372989a26e9cdd714
+
+COUNT = 13
+KEY = fffc000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4dcede8da9e2578f39703d4433dc6459
+
+COUNT = 14
+KEY = fffe000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1a4c1c263bbccfafc11782894685e3a8
+
+COUNT = 15
+KEY = ffff000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 937ad84880db50613423d6d527a2823d
+
+COUNT = 16
+KEY = ffff800000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 610b71dfc688e150d8152c5b35ebc14d
+
+COUNT = 17
+KEY = ffffc00000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 27ef2495dabf323885aab39c80f18d8b
+
+COUNT = 18
+KEY = ffffe00000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 633cafea395bc03adae3a1e2068e4b4e
+
+COUNT = 19
+KEY = fffff00000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6e1b482b53761cf631819b749a6f3724
+
+COUNT = 20
+KEY = fffff80000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 976e6f851ab52c771998dbb2d71c75a9
+
+COUNT = 21
+KEY = fffffc0000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 85f2ba84f8c307cf525e124c3e22e6cc
+
+COUNT = 22
+KEY = fffffe0000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6bcca98bf6a835fa64955f72de4115fe
+
+COUNT = 23
+KEY = ffffff0000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2c75e2d36eebd65411f14fd0eb1d2a06
+
+COUNT = 24
+KEY = ffffff8000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = bd49295006250ffca5100b6007a0eade
+
+COUNT = 25
+KEY = ffffffc000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a190527d0ef7c70f459cd3940df316ec
+
+COUNT = 26
+KEY = ffffffe000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = bbd1097a62433f79449fa97d4ee80dbf
+
+COUNT = 27
+KEY = fffffff000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 07058e408f5b99b0e0f061a1761b5b3b
+
+COUNT = 28
+KEY = fffffff800000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5fd1f13fa0f31e37fabde328f894eac2
+
+COUNT = 29
+KEY = fffffffc00000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fc4af7c948df26e2ef3e01c1ee5b8f6f
+
+COUNT = 30
+KEY = fffffffe00000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 829fd7208fb92d44a074a677ee9861ac
+
+COUNT = 31
+KEY = ffffffff00000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ad9fc613a703251b54c64a0e76431711
+
+COUNT = 32
+KEY = ffffffff80000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 33ac9eccc4cc75e2711618f80b1548e8
+
+COUNT = 33
+KEY = ffffffffc0000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2025c74b8ad8f4cda17ee2049c4c902d
+
+COUNT = 34
+KEY = ffffffffe0000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f85ca05fe528f1ce9b790166e8d551e7
+
+COUNT = 35
+KEY = fffffffff0000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6f6238d8966048d4967154e0dad5a6c9
+
+COUNT = 36
+KEY = fffffffff8000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f2b21b4e7640a9b3346de8b82fb41e49
+
+COUNT = 37
+KEY = fffffffffc000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f836f251ad1d11d49dc344628b1884e1
+
+COUNT = 38
+KEY = fffffffffe000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 077e9470ae7abea5a9769d49182628c3
+
+COUNT = 39
+KEY = ffffffffff000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e0dcc2d27fc9865633f85223cf0d611f
+
+COUNT = 40
+KEY = ffffffffff800000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = be66cfea2fecd6bf0ec7b4352c99bcaa
+
+COUNT = 41
+KEY = ffffffffffc00000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = df31144f87a2ef523facdcf21a427804
+
+COUNT = 42
+KEY = ffffffffffe00000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b5bb0f5629fb6aae5e1839a3c3625d63
+
+COUNT = 43
+KEY = fffffffffff00000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3c9db3335306fe1ec612bdbfae6b6028
+
+COUNT = 44
+KEY = fffffffffff80000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3dd5c34634a79d3cfcc8339760e6f5f4
+
+COUNT = 45
+KEY = fffffffffffc0000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 82bda118a3ed7af314fa2ccc5c07b761
+
+COUNT = 46
+KEY = fffffffffffe0000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2937a64f7d4f46fe6fea3b349ec78e38
+
+COUNT = 47
+KEY = ffffffffffff0000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 225f068c28476605735ad671bb8f39f3
+
+COUNT = 48
+KEY = ffffffffffff8000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ae682c5ecd71898e08942ac9aa89875c
+
+COUNT = 49
+KEY = ffffffffffffc000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5e031cb9d676c3022d7f26227e85c38f
+
+COUNT = 50
+KEY = ffffffffffffe000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a78463fb064db5d52bb64bfef64f2dda
+
+COUNT = 51
+KEY = fffffffffffff000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8aa9b75e784593876c53a00eae5af52b
+
+COUNT = 52
+KEY = fffffffffffff800000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3f84566df23da48af692722fe980573a
+
+COUNT = 53
+KEY = fffffffffffffc00000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 31690b5ed41c7eb42a1e83270a7ff0e6
+
+COUNT = 54
+KEY = fffffffffffffe00000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 77dd7702646d55f08365e477d3590eda
+
+COUNT = 55
+KEY = ffffffffffffff00000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4c022ac62b3cb78d739cc67b3e20bb7e
+
+COUNT = 56
+KEY = ffffffffffffff80000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 092fa137ce18b5dfe7906f550bb13370
+
+COUNT = 57
+KEY = ffffffffffffffc0000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3e0cdadf2e68353c0027672c97144dd3
+
+COUNT = 58
+KEY = ffffffffffffffe0000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d8c4b200b383fc1f2b2ea677618a1d27
+
+COUNT = 59
+KEY = fffffffffffffff0000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 11825f99b0e9bb3477c1c0713b015aac
+
+COUNT = 60
+KEY = fffffffffffffff8000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f8b9fffb5c187f7ddc7ab10f4fb77576
+
+COUNT = 61
+KEY = fffffffffffffffc000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ffb4e87a32b37d6f2c8328d3b5377802
+
+COUNT = 62
+KEY = fffffffffffffffe000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d276c13a5d220f4da9224e74896391ce
+
+COUNT = 63
+KEY = ffffffffffffffff000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 94efe7a0e2e031e2536da01df799c927
+
+COUNT = 64
+KEY = ffffffffffffffff800000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8f8fd822680a85974e53a5a8eb9d38de
+
+COUNT = 65
+KEY = ffffffffffffffffc00000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e0f0a91b2e45f8cc37b7805a3042588d
+
+COUNT = 66
+KEY = ffffffffffffffffe00000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 597a6252255e46d6364dbeeda31e279c
+
+COUNT = 67
+KEY = fffffffffffffffff00000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f51a0f694442b8f05571797fec7ee8bf
+
+COUNT = 68
+KEY = fffffffffffffffff80000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9ff071b165b5198a93dddeebc54d09b5
+
+COUNT = 69
+KEY = fffffffffffffffffc0000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c20a19fd5758b0c4bc1a5df89cf73877
+
+COUNT = 70
+KEY = fffffffffffffffffe0000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 97120166307119ca2280e9315668e96f
+
+COUNT = 71
+KEY = ffffffffffffffffff0000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4b3b9f1e099c2a09dc091e90e4f18f0a
+
+COUNT = 72
+KEY = ffffffffffffffffff8000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = eb040b891d4b37f6851f7ec219cd3f6d
+
+COUNT = 73
+KEY = ffffffffffffffffffc000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9f0fdec08b7fd79aa39535bea42db92a
+
+COUNT = 74
+KEY = ffffffffffffffffffe000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2e70f168fc74bf911df240bcd2cef236
+
+COUNT = 75
+KEY = fffffffffffffffffff000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 462ccd7f5fd1108dbc152f3cacad328b
+
+COUNT = 76
+KEY = fffffffffffffffffff800000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a4af534a7d0b643a01868785d86dfb95
+
+COUNT = 77
+KEY = fffffffffffffffffffc00000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ab980296197e1a5022326c31da4bf6f3
+
+COUNT = 78
+KEY = fffffffffffffffffffe00000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f97d57b3333b6281b07d486db2d4e20c
+
+COUNT = 79
+KEY = ffffffffffffffffffff00000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f33fa36720231afe4c759ade6bd62eb6
+
+COUNT = 80
+KEY = ffffffffffffffffffff80000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fdcfac0c02ca538343c68117e0a15938
+
+COUNT = 81
+KEY = ffffffffffffffffffffc0000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ad4916f5ee5772be764fc027b8a6e539
+
+COUNT = 82
+KEY = ffffffffffffffffffffe0000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2e16873e1678610d7e14c02d002ea845
+
+COUNT = 83
+KEY = fffffffffffffffffffff0000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4e6e627c1acc51340053a8236d579576
+
+COUNT = 84
+KEY = fffffffffffffffffffff8000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ab0c8410aeeead92feec1eb430d652cb
+
+COUNT = 85
+KEY = fffffffffffffffffffffc000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e86f7e23e835e114977f60e1a592202e
+
+COUNT = 86
+KEY = fffffffffffffffffffffe000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e68ad5055a367041fade09d9a70a794b
+
+COUNT = 87
+KEY = ffffffffffffffffffffff000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0791823a3c666bb6162825e78606a7fe
+
+COUNT = 88
+KEY = ffffffffffffffffffffff800000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = dcca366a9bf47b7b868b77e25c18a364
+
+COUNT = 89
+KEY = ffffffffffffffffffffffc00000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 684c9efc237e4a442965f84bce20247a
+
+COUNT = 90
+KEY = ffffffffffffffffffffffe00000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a858411ffbe63fdb9c8aa1bfaed67b52
+
+COUNT = 91
+KEY = fffffffffffffffffffffff00000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 04bc3da2179c3015498b0e03910db5b8
+
+COUNT = 92
+KEY = fffffffffffffffffffffff80000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 40071eeab3f935dbc25d00841460260f
+
+COUNT = 93
+KEY = fffffffffffffffffffffffc0000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0ebd7c30ed2016e08ba806ddb008bcc8
+
+COUNT = 94
+KEY = fffffffffffffffffffffffe0000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 15c6becf0f4cec7129cbd22d1a79b1b8
+
+COUNT = 95
+KEY = ffffffffffffffffffffffff0000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0aeede5b91f721700e9e62edbf60b781
+
+COUNT = 96
+KEY = ffffffffffffffffffffffff8000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 266581af0dcfbed1585e0a242c64b8df
+
+COUNT = 97
+KEY = ffffffffffffffffffffffffc000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6693dc911662ae473216ba22189a511a
+
+COUNT = 98
+KEY = ffffffffffffffffffffffffe000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7606fa36d86473e6fb3a1bb0e2c0adf5
+
+COUNT = 99
+KEY = fffffffffffffffffffffffff000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 112078e9e11fbb78e26ffb8899e96b9a
+
+COUNT = 100
+KEY = fffffffffffffffffffffffff800000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 40b264e921e9e4a82694589ef3798262
+
+COUNT = 101
+KEY = fffffffffffffffffffffffffc00000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8d4595cb4fa7026715f55bd68e2882f9
+
+COUNT = 102
+KEY = fffffffffffffffffffffffffe00000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b588a302bdbc09197df1edae68926ed9
+
+COUNT = 103
+KEY = ffffffffffffffffffffffffff00000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 33f7502390b8a4a221cfecd0666624ba
+
+COUNT = 104
+KEY = ffffffffffffffffffffffffff80000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3d20253adbce3be2373767c4d822c566
+
+COUNT = 105
+KEY = ffffffffffffffffffffffffffc0000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a42734a3929bf84cf0116c9856a3c18c
+
+COUNT = 106
+KEY = ffffffffffffffffffffffffffe0000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e3abc4939457422bb957da3c56938c6d
+
+COUNT = 107
+KEY = fffffffffffffffffffffffffff0000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 972bdd2e7c525130fadc8f76fc6f4b3f
+
+COUNT = 108
+KEY = fffffffffffffffffffffffffff8000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 84a83d7b94c699cbcb8a7d9b61f64093
+
+COUNT = 109
+KEY = fffffffffffffffffffffffffffc000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ce61d63514aded03d43e6ebfc3a9001f
+
+COUNT = 110
+KEY = fffffffffffffffffffffffffffe000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6c839dd58eeae6b8a36af48ed63d2dc9
+
+COUNT = 111
+KEY = ffffffffffffffffffffffffffff000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cd5ece55b8da3bf622c4100df5de46f9
+
+COUNT = 112
+KEY = ffffffffffffffffffffffffffff800000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3b6f46f40e0ac5fc0a9c1105f800f48d
+
+COUNT = 113
+KEY = ffffffffffffffffffffffffffffc00000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ba26d47da3aeb028de4fb5b3a854a24b
+
+COUNT = 114
+KEY = ffffffffffffffffffffffffffffe00000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 87f53bf620d3677268445212904389d5
+
+COUNT = 115
+KEY = fffffffffffffffffffffffffffff00000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 10617d28b5e0f4605492b182a5d7f9f6
+
+COUNT = 116
+KEY = fffffffffffffffffffffffffffff80000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9aaec4fabbf6fae2a71feff02e372b39
+
+COUNT = 117
+KEY = fffffffffffffffffffffffffffffc0000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3a90c62d88b5c42809abf782488ed130
+
+COUNT = 118
+KEY = fffffffffffffffffffffffffffffe0000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = f1f1c5a40899e15772857ccb65c7a09a
+
+COUNT = 119
+KEY = ffffffffffffffffffffffffffffff0000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 190843d29b25a3897c692ce1dd81ee52
+
+COUNT = 120
+KEY = ffffffffffffffffffffffffffffff8000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a866bc65b6941d86e8420a7ffb0964db
+
+COUNT = 121
+KEY = ffffffffffffffffffffffffffffffc000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8193c6ff85225ced4255e92f6e078a14
+
+COUNT = 122
+KEY = ffffffffffffffffffffffffffffffe000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9661cb2424d7d4a380d547f9e7ec1cb9
+
+COUNT = 123
+KEY = fffffffffffffffffffffffffffffff000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 86f93d9ec08453a071e2e2877877a9c8
+
+COUNT = 124
+KEY = fffffffffffffffffffffffffffffff800000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 27eefa80ce6a4a9d598e3fec365434d2
+
+COUNT = 125
+KEY = fffffffffffffffffffffffffffffffc00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d62068444578e3ab39ce7ec95dd045dc
+
+COUNT = 126
+KEY = fffffffffffffffffffffffffffffffe00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b5f71d4dd9a71fe5d8bc8ba7e6ea3048
+
+COUNT = 127
+KEY = ffffffffffffffffffffffffffffffff00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6825a347ac479d4f9d95c5cb8d3fd7e9
+
+COUNT = 128
+KEY = ffffffffffffffffffffffffffffffff80000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e3714e94a5778955cc0346358e94783a
+
+COUNT = 129
+KEY = ffffffffffffffffffffffffffffffffc0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d836b44bb29e0c7d89fa4b2d4b677d2a
+
+COUNT = 130
+KEY = ffffffffffffffffffffffffffffffffe0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5d454b75021d76d4b84f873a8f877b92
+
+COUNT = 131
+KEY = fffffffffffffffffffffffffffffffff0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c3498f7eced2095314fc28115885b33f
+
+COUNT = 132
+KEY = fffffffffffffffffffffffffffffffff8000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6e668856539ad8e405bd123fe6c88530
+
+COUNT = 133
+KEY = fffffffffffffffffffffffffffffffffc000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8680db7f3a87b8605543cfdbe6754076
+
+COUNT = 134
+KEY = fffffffffffffffffffffffffffffffffe000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6c5d03b13069c3658b3179be91b0800c
+
+COUNT = 135
+KEY = ffffffffffffffffffffffffffffffffff000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ef1b384ac4d93eda00c92add0995ea5f
+
+COUNT = 136
+KEY = ffffffffffffffffffffffffffffffffff800000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = bf8115805471741bd5ad20a03944790f
+
+COUNT = 137
+KEY = ffffffffffffffffffffffffffffffffffc00000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c64c24b6894b038b3c0d09b1df068b0b
+
+COUNT = 138
+KEY = ffffffffffffffffffffffffffffffffffe00000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3967a10cffe27d0178545fbf6a40544b
+
+COUNT = 139
+KEY = fffffffffffffffffffffffffffffffffff00000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7c85e9c95de1a9ec5a5363a8a053472d
+
+COUNT = 140
+KEY = fffffffffffffffffffffffffffffffffff80000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a9eec03c8abec7ba68315c2c8c2316e0
+
+COUNT = 141
+KEY = fffffffffffffffffffffffffffffffffffc0000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cac8e414c2f388227ae14986fc983524
+
+COUNT = 142
+KEY = fffffffffffffffffffffffffffffffffffe0000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5d942b7f4622ce056c3ce3ce5f1dd9d6
+
+COUNT = 143
+KEY = ffffffffffffffffffffffffffffffffffff0000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d240d648ce21a3020282c3f1b528a0b6
+
+COUNT = 144
+KEY = ffffffffffffffffffffffffffffffffffff8000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 45d089c36d5c5a4efc689e3b0de10dd5
+
+COUNT = 145
+KEY = ffffffffffffffffffffffffffffffffffffc000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b4da5df4becb5462e03a0ed00d295629
+
+COUNT = 146
+KEY = ffffffffffffffffffffffffffffffffffffe000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = dcf4e129136c1a4b7a0f38935cc34b2b
+
+COUNT = 147
+KEY = fffffffffffffffffffffffffffffffffffff000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d9a4c7618b0ce48a3d5aee1a1c0114c4
+
+COUNT = 148
+KEY = fffffffffffffffffffffffffffffffffffff800000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ca352df025c65c7b0bf306fbee0f36ba
+
+COUNT = 149
+KEY = fffffffffffffffffffffffffffffffffffffc00000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 238aca23fd3409f38af63378ed2f5473
+
+COUNT = 150
+KEY = fffffffffffffffffffffffffffffffffffffe00000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 59836a0e06a79691b36667d5380d8188
+
+COUNT = 151
+KEY = ffffffffffffffffffffffffffffffffffffff00000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 33905080f7acf1cdae0a91fc3e85aee4
+
+COUNT = 152
+KEY = ffffffffffffffffffffffffffffffffffffff80000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 72c9e4646dbc3d6320fc6689d93e8833
+
+COUNT = 153
+KEY = ffffffffffffffffffffffffffffffffffffffc0000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ba77413dea5925b7f5417ea47ff19f59
+
+COUNT = 154
+KEY = ffffffffffffffffffffffffffffffffffffffe0000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6cae8129f843d86dc786a0fb1a184970
+
+COUNT = 155
+KEY = fffffffffffffffffffffffffffffffffffffff0000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fcfefb534100796eebbd990206754e19
+
+COUNT = 156
+KEY = fffffffffffffffffffffffffffffffffffffff8000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8c791d5fdddf470da04f3e6dc4a5b5b5
+
+COUNT = 157
+KEY = fffffffffffffffffffffffffffffffffffffffc000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c93bbdc07a4611ae4bb266ea5034a387
+
+COUNT = 158
+KEY = fffffffffffffffffffffffffffffffffffffffe000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c102e38e489aa74762f3efc5bb23205a
+
+COUNT = 159
+KEY = ffffffffffffffffffffffffffffffffffffffff000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 93201481665cbafc1fcc220bc545fb3d
+
+COUNT = 160
+KEY = ffffffffffffffffffffffffffffffffffffffff800000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4960757ec6ce68cf195e454cfd0f32ca
+
+COUNT = 161
+KEY = ffffffffffffffffffffffffffffffffffffffffc00000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = feec7ce6a6cbd07c043416737f1bbb33
+
+COUNT = 162
+KEY = ffffffffffffffffffffffffffffffffffffffffe00000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 11c5413904487a805d70a8edd9c35527
+
+COUNT = 163
+KEY = fffffffffffffffffffffffffffffffffffffffff00000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 347846b2b2e36f1f0324c86f7f1b98e2
+
+COUNT = 164
+KEY = fffffffffffffffffffffffffffffffffffffffff80000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 332eee1a0cbd19ca2d69b426894044f0
+
+COUNT = 165
+KEY = fffffffffffffffffffffffffffffffffffffffffc0000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 866b5b3977ba6efa5128efbda9ff03cd
+
+COUNT = 166
+KEY = fffffffffffffffffffffffffffffffffffffffffe0000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cc1445ee94c0f08cdee5c344ecd1e233
+
+COUNT = 167
+KEY = ffffffffffffffffffffffffffffffffffffffffff0000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = be288319029363c2622feba4b05dfdfe
+
+COUNT = 168
+KEY = ffffffffffffffffffffffffffffffffffffffffff8000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cfd1875523f3cd21c395651e6ee15e56
+
+COUNT = 169
+KEY = ffffffffffffffffffffffffffffffffffffffffffc000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cb5a408657837c53bf16f9d8465dce19
+
+COUNT = 170
+KEY = ffffffffffffffffffffffffffffffffffffffffffe000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ca0bf42cb107f55ccff2fc09ee08ca15
+
+COUNT = 171
+KEY = fffffffffffffffffffffffffffffffffffffffffff000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = fdd9bbb4a7dc2e4a23536a5880a2db67
+
+COUNT = 172
+KEY = fffffffffffffffffffffffffffffffffffffffffff800000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ede447b362c484993dec9442a3b46aef
+
+COUNT = 173
+KEY = fffffffffffffffffffffffffffffffffffffffffffc00000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 10dffb05904bff7c4781df780ad26837
+
+COUNT = 174
+KEY = fffffffffffffffffffffffffffffffffffffffffffe00000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c33bc13e8de88ac25232aa7496398783
+
+COUNT = 175
+KEY = ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ca359c70803a3b2a3d542e8781dea975
+
+COUNT = 176
+KEY = ffffffffffffffffffffffffffffffffffffffffffff80000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = bcc65b526f88d05b89ce8a52021fdb06
+
+COUNT = 177
+KEY = ffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = db91a38855c8c4643851fbfb358b0109
+
+COUNT = 178
+KEY = ffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ca6e8893a114ae8e27d5ab03a5499610
+
+COUNT = 179
+KEY = fffffffffffffffffffffffffffffffffffffffffffff0000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6629d2b8df97da728cdd8b1e7f945077
+
+COUNT = 180
+KEY = fffffffffffffffffffffffffffffffffffffffffffff8000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4570a5a18cfc0dd582f1d88d5c9a1720
+
+COUNT = 181
+KEY = fffffffffffffffffffffffffffffffffffffffffffffc000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 72bc65aa8e89562e3f274d45af1cd10b
+
+COUNT = 182
+KEY = fffffffffffffffffffffffffffffffffffffffffffffe000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 98551da1a6503276ae1c77625f9ea615
+
+COUNT = 183
+KEY = ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 0ddfe51ced7e3f4ae927daa3fe452cee
+
+COUNT = 184
+KEY = ffffffffffffffffffffffffffffffffffffffffffffff800000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = db826251e4ce384b80218b0e1da1dd4c
+
+COUNT = 185
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2cacf728b88abbad7011ed0e64a1680c
+
+COUNT = 186
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffe00000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 330d8ee7c5677e099ac74c9994ee4cfb
+
+COUNT = 187
+KEY = fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = edf61ae362e882ddc0167474a7a77f3a
+
+COUNT = 188
+KEY = fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6168b00ba7859e0970ecfd757efecf7c
+
+COUNT = 189
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d1415447866230d28bb1ea18a4cdfd02
+
+COUNT = 190
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 516183392f7a8763afec68a060264141
+
+COUNT = 191
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 77565c8d73cfd4130b4aa14d8911710f
+
+COUNT = 192
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 37232a4ed21ccc27c19c9610078cabac
+
+COUNT = 193
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 804f32ea71828c7d329077e712231666
+
+COUNT = 194
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d64424f23cb97215e9c2c6f28d29eab7
+
+COUNT = 195
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 023e82b533f68c75c238cebdb2ee89a2
+
+COUNT = 196
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffff800000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 193a3d24157a51f1ee0893f6777417e7
+
+COUNT = 197
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 84ecacfcd400084d078612b1945f2ef5
+
+COUNT = 198
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffe00000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1dcd8bb173259eb33a5242b0de31a455
+
+COUNT = 199
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 35e9eddbc375e792c19992c19165012b
+
+COUNT = 200
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8a772231c01dfdd7c98e4cfddcc0807a
+
+COUNT = 201
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6eda7ff6b8319180ff0d6e65629d01c3
+
+COUNT = 202
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = c267ef0e2d01a993944dd397101413cb
+
+COUNT = 203
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e9f80e9d845bcc0f62926af72eabca39
+
+COUNT = 204
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 6702990727aa0878637b45dcd3a3b074
+
+COUNT = 205
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2e2e647d5360e09230a5d738ca33471e
+
+COUNT = 206
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1f56413c7add6f43d1d56e4f02190330
+
+COUNT = 207
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 69cd0606e15af729d6bca143016d9842
+
+COUNT = 208
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a085d7c1a500873a20099c4caa3c3f5b
+
+COUNT = 209
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4fc0d230f8891415b87b83f95f2e09d1
+
+COUNT = 210
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4327d08c523d8eba697a4336507d1f42
+
+COUNT = 211
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7a15aab82701efa5ae36ab1d6b76290f
+
+COUNT = 212
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5bf0051893a18bb30e139a58fed0fa54
+
+COUNT = 213
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 97e8adf65638fd9cdf3bc22c17fe4dbd
+
+COUNT = 214
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1ee6ee326583a0586491c96418d1a35d
+
+COUNT = 215
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 26b549c2ec756f82ecc48008e529956b
+
+COUNT = 216
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 70377b6da669b072129e057cc28e9ca5
+
+COUNT = 217
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9c94b8b0cb8bcc919072262b3fa05ad9
+
+COUNT = 218
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2fbb83dfd0d7abcb05cd28cad2dfb523
+
+COUNT = 219
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 96877803de77744bb970d0a91f4debae
+
+COUNT = 220
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7379f3370cf6e5ce12ae5969c8eea312
+
+COUNT = 221
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 02dc99fa3d4f98ce80985e7233889313
+
+COUNT = 222
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1e38e759075ba5cab6457da51844295a
+
+COUNT = 223
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 70bed8dbf615868a1f9d9b05d3e7a267
+
+COUNT = 224
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 234b148b8cb1d8c32b287e896903d150
+
+COUNT = 225
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 294b033df4da853f4be3e243f7e513f4
+
+COUNT = 226
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3f58c950f0367160adec45f2441e7411
+
+COUNT = 227
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 37f655536a704e5ace182d742a820cf4
+
+COUNT = 228
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ea7bd6bb63418731aeac790fe42d61e8
+
+COUNT = 229
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = e74a4c999b4c064e48bb1e413f51e5ea
+
+COUNT = 230
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = ba9ebefdb4ccf30f296cecb3bc1943e8
+
+COUNT = 231
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3194367a4898c502c13bb7478640a72d
+
+COUNT = 232
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = da797713263d6f33a5478a65ef60d412
+
+COUNT = 233
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d1ac39bb1ef86b9c1344f214679aa376
+
+COUNT = 234
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2fdea9e650532be5bc0e7325337fd363
+
+COUNT = 235
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d3a204dbd9c2af158b6ca67a5156ce4a
+
+COUNT = 236
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 3a0a0e75a8da36735aee6684d965a778
+
+COUNT = 237
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 52fc3e620492ea99641ea168da5b6d52
+
+COUNT = 238
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d2e0c7f15b4772467d2cfc873000b2ca
+
+COUNT = 239
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 563531135e0c4d70a38f8bdb190ba04e
+
+COUNT = 240
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = a8a39a0f5663f4c0fe5f2d3cafff421a
+
+COUNT = 241
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = d94b5e90db354c1e42f61fabe167b2c0
+
+COUNT = 242
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 50e6d3c9b6698a7cd276f96b1473f35a
+
+COUNT = 243
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 9338f08e0ebee96905d8f2e825208f43
+
+COUNT = 244
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 8b378c86672aa54a3a266ba19d2580ca
+
+COUNT = 245
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cca7c3086f5f9511b31233da7cab9160
+
+COUNT = 246
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 5b40ff4ec9be536ba23035fa4f06064c
+
+COUNT = 247
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 60eb5af8416b257149372194e8b88749
+
+COUNT = 248
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 2f005a8aed8a361c92e440c15520cbd1
+
+COUNT = 249
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 7b03627611678a997717578807a800e2
+
+COUNT = 250
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = cf78618f74f6f3696e0a4779b90b5a77
+
+COUNT = 251
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 03720371a04962eaea0a852e69972858
+
+COUNT = 252
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 1f8a8133aa8ccf70e2bd3285831ca6b7
+
+COUNT = 253
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 27936bd27fb1468fc8b48bc483321725
+
+COUNT = 254
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = b07d4f3e2cd2ef2eb545980754dfea0f
+
+COUNT = 255
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
+IV = 00000000000000000000000000000000
+PLAINTEXT = 00000000000000000000000000000000
+CIPHERTEXT = 4bf85f1b5d54adbc307b0a048389adcb
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 8000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e35a6dcb19b201a01ebcfa8aa22b5759
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 1
+KEY = c000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b29169cdcf2d83e838125a12ee6aa400
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 2
+KEY = e000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d8f3a72fc3cdf74dfaf6c3e6b97b2fa6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 3
+KEY = f000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1c777679d50037c79491a94da76a9a35
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 4
+KEY = f800000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9cf4893ecafa0a0247a898e040691559
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 5
+KEY = fc00000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8fbb413703735326310a269bd3aa94b2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 6
+KEY = fe00000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 60e32246bed2b0e859e55c1cc6b26502
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 7
+KEY = ff00000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ec52a212f80a09df6317021bc2a9819e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 8
+KEY = ff80000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f23e5b600eb70dbccf6c0b1d9a68182c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 9
+KEY = ffc0000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a3f599d63a82a968c33fe26590745970
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 10
+KEY = ffe0000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d1ccb9b1337002cbac42c520b5d67722
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 11
+KEY = fff0000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cc111f6c37cf40a1159d00fb59fb0488
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 12
+KEY = fff8000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dc43b51ab609052372989a26e9cdd714
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 13
+KEY = fffc000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4dcede8da9e2578f39703d4433dc6459
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 14
+KEY = fffe000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1a4c1c263bbccfafc11782894685e3a8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 15
+KEY = ffff000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 937ad84880db50613423d6d527a2823d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 16
+KEY = ffff800000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 610b71dfc688e150d8152c5b35ebc14d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 17
+KEY = ffffc00000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 27ef2495dabf323885aab39c80f18d8b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 18
+KEY = ffffe00000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 633cafea395bc03adae3a1e2068e4b4e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 19
+KEY = fffff00000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6e1b482b53761cf631819b749a6f3724
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 20
+KEY = fffff80000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 976e6f851ab52c771998dbb2d71c75a9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 21
+KEY = fffffc0000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 85f2ba84f8c307cf525e124c3e22e6cc
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 22
+KEY = fffffe0000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6bcca98bf6a835fa64955f72de4115fe
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 23
+KEY = ffffff0000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2c75e2d36eebd65411f14fd0eb1d2a06
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 24
+KEY = ffffff8000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = bd49295006250ffca5100b6007a0eade
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 25
+KEY = ffffffc000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a190527d0ef7c70f459cd3940df316ec
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 26
+KEY = ffffffe000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = bbd1097a62433f79449fa97d4ee80dbf
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 27
+KEY = fffffff000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 07058e408f5b99b0e0f061a1761b5b3b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 28
+KEY = fffffff800000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5fd1f13fa0f31e37fabde328f894eac2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 29
+KEY = fffffffc00000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fc4af7c948df26e2ef3e01c1ee5b8f6f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 30
+KEY = fffffffe00000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 829fd7208fb92d44a074a677ee9861ac
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 31
+KEY = ffffffff00000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ad9fc613a703251b54c64a0e76431711
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 32
+KEY = ffffffff80000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 33ac9eccc4cc75e2711618f80b1548e8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 33
+KEY = ffffffffc0000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2025c74b8ad8f4cda17ee2049c4c902d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 34
+KEY = ffffffffe0000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f85ca05fe528f1ce9b790166e8d551e7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 35
+KEY = fffffffff0000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6f6238d8966048d4967154e0dad5a6c9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 36
+KEY = fffffffff8000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f2b21b4e7640a9b3346de8b82fb41e49
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 37
+KEY = fffffffffc000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f836f251ad1d11d49dc344628b1884e1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 38
+KEY = fffffffffe000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 077e9470ae7abea5a9769d49182628c3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 39
+KEY = ffffffffff000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e0dcc2d27fc9865633f85223cf0d611f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 40
+KEY = ffffffffff800000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = be66cfea2fecd6bf0ec7b4352c99bcaa
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 41
+KEY = ffffffffffc00000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = df31144f87a2ef523facdcf21a427804
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 42
+KEY = ffffffffffe00000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b5bb0f5629fb6aae5e1839a3c3625d63
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 43
+KEY = fffffffffff00000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3c9db3335306fe1ec612bdbfae6b6028
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 44
+KEY = fffffffffff80000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3dd5c34634a79d3cfcc8339760e6f5f4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 45
+KEY = fffffffffffc0000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 82bda118a3ed7af314fa2ccc5c07b761
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 46
+KEY = fffffffffffe0000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2937a64f7d4f46fe6fea3b349ec78e38
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 47
+KEY = ffffffffffff0000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 225f068c28476605735ad671bb8f39f3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 48
+KEY = ffffffffffff8000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ae682c5ecd71898e08942ac9aa89875c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 49
+KEY = ffffffffffffc000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5e031cb9d676c3022d7f26227e85c38f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 50
+KEY = ffffffffffffe000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a78463fb064db5d52bb64bfef64f2dda
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 51
+KEY = fffffffffffff000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8aa9b75e784593876c53a00eae5af52b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 52
+KEY = fffffffffffff800000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3f84566df23da48af692722fe980573a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 53
+KEY = fffffffffffffc00000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 31690b5ed41c7eb42a1e83270a7ff0e6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 54
+KEY = fffffffffffffe00000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 77dd7702646d55f08365e477d3590eda
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 55
+KEY = ffffffffffffff00000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4c022ac62b3cb78d739cc67b3e20bb7e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 56
+KEY = ffffffffffffff80000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 092fa137ce18b5dfe7906f550bb13370
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 57
+KEY = ffffffffffffffc0000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3e0cdadf2e68353c0027672c97144dd3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 58
+KEY = ffffffffffffffe0000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d8c4b200b383fc1f2b2ea677618a1d27
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 59
+KEY = fffffffffffffff0000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 11825f99b0e9bb3477c1c0713b015aac
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 60
+KEY = fffffffffffffff8000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f8b9fffb5c187f7ddc7ab10f4fb77576
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 61
+KEY = fffffffffffffffc000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ffb4e87a32b37d6f2c8328d3b5377802
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 62
+KEY = fffffffffffffffe000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d276c13a5d220f4da9224e74896391ce
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 63
+KEY = ffffffffffffffff000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 94efe7a0e2e031e2536da01df799c927
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 64
+KEY = ffffffffffffffff800000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8f8fd822680a85974e53a5a8eb9d38de
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 65
+KEY = ffffffffffffffffc00000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e0f0a91b2e45f8cc37b7805a3042588d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 66
+KEY = ffffffffffffffffe00000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 597a6252255e46d6364dbeeda31e279c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 67
+KEY = fffffffffffffffff00000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f51a0f694442b8f05571797fec7ee8bf
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 68
+KEY = fffffffffffffffff80000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9ff071b165b5198a93dddeebc54d09b5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 69
+KEY = fffffffffffffffffc0000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c20a19fd5758b0c4bc1a5df89cf73877
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 70
+KEY = fffffffffffffffffe0000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 97120166307119ca2280e9315668e96f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 71
+KEY = ffffffffffffffffff0000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4b3b9f1e099c2a09dc091e90e4f18f0a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 72
+KEY = ffffffffffffffffff8000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = eb040b891d4b37f6851f7ec219cd3f6d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 73
+KEY = ffffffffffffffffffc000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9f0fdec08b7fd79aa39535bea42db92a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 74
+KEY = ffffffffffffffffffe000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2e70f168fc74bf911df240bcd2cef236
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 75
+KEY = fffffffffffffffffff000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 462ccd7f5fd1108dbc152f3cacad328b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 76
+KEY = fffffffffffffffffff800000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a4af534a7d0b643a01868785d86dfb95
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 77
+KEY = fffffffffffffffffffc00000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ab980296197e1a5022326c31da4bf6f3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 78
+KEY = fffffffffffffffffffe00000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f97d57b3333b6281b07d486db2d4e20c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 79
+KEY = ffffffffffffffffffff00000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f33fa36720231afe4c759ade6bd62eb6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 80
+KEY = ffffffffffffffffffff80000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fdcfac0c02ca538343c68117e0a15938
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 81
+KEY = ffffffffffffffffffffc0000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ad4916f5ee5772be764fc027b8a6e539
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 82
+KEY = ffffffffffffffffffffe0000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2e16873e1678610d7e14c02d002ea845
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 83
+KEY = fffffffffffffffffffff0000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4e6e627c1acc51340053a8236d579576
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 84
+KEY = fffffffffffffffffffff8000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ab0c8410aeeead92feec1eb430d652cb
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 85
+KEY = fffffffffffffffffffffc000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e86f7e23e835e114977f60e1a592202e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 86
+KEY = fffffffffffffffffffffe000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e68ad5055a367041fade09d9a70a794b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 87
+KEY = ffffffffffffffffffffff000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0791823a3c666bb6162825e78606a7fe
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 88
+KEY = ffffffffffffffffffffff800000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dcca366a9bf47b7b868b77e25c18a364
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 89
+KEY = ffffffffffffffffffffffc00000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 684c9efc237e4a442965f84bce20247a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 90
+KEY = ffffffffffffffffffffffe00000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a858411ffbe63fdb9c8aa1bfaed67b52
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 91
+KEY = fffffffffffffffffffffff00000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 04bc3da2179c3015498b0e03910db5b8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 92
+KEY = fffffffffffffffffffffff80000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 40071eeab3f935dbc25d00841460260f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 93
+KEY = fffffffffffffffffffffffc0000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0ebd7c30ed2016e08ba806ddb008bcc8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 94
+KEY = fffffffffffffffffffffffe0000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 15c6becf0f4cec7129cbd22d1a79b1b8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 95
+KEY = ffffffffffffffffffffffff0000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0aeede5b91f721700e9e62edbf60b781
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 96
+KEY = ffffffffffffffffffffffff8000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 266581af0dcfbed1585e0a242c64b8df
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 97
+KEY = ffffffffffffffffffffffffc000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6693dc911662ae473216ba22189a511a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 98
+KEY = ffffffffffffffffffffffffe000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7606fa36d86473e6fb3a1bb0e2c0adf5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 99
+KEY = fffffffffffffffffffffffff000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 112078e9e11fbb78e26ffb8899e96b9a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 100
+KEY = fffffffffffffffffffffffff800000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 40b264e921e9e4a82694589ef3798262
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 101
+KEY = fffffffffffffffffffffffffc00000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8d4595cb4fa7026715f55bd68e2882f9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 102
+KEY = fffffffffffffffffffffffffe00000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b588a302bdbc09197df1edae68926ed9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 103
+KEY = ffffffffffffffffffffffffff00000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 33f7502390b8a4a221cfecd0666624ba
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 104
+KEY = ffffffffffffffffffffffffff80000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3d20253adbce3be2373767c4d822c566
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 105
+KEY = ffffffffffffffffffffffffffc0000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a42734a3929bf84cf0116c9856a3c18c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 106
+KEY = ffffffffffffffffffffffffffe0000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e3abc4939457422bb957da3c56938c6d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 107
+KEY = fffffffffffffffffffffffffff0000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 972bdd2e7c525130fadc8f76fc6f4b3f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 108
+KEY = fffffffffffffffffffffffffff8000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 84a83d7b94c699cbcb8a7d9b61f64093
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 109
+KEY = fffffffffffffffffffffffffffc000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ce61d63514aded03d43e6ebfc3a9001f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 110
+KEY = fffffffffffffffffffffffffffe000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6c839dd58eeae6b8a36af48ed63d2dc9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 111
+KEY = ffffffffffffffffffffffffffff000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cd5ece55b8da3bf622c4100df5de46f9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 112
+KEY = ffffffffffffffffffffffffffff800000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3b6f46f40e0ac5fc0a9c1105f800f48d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 113
+KEY = ffffffffffffffffffffffffffffc00000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ba26d47da3aeb028de4fb5b3a854a24b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 114
+KEY = ffffffffffffffffffffffffffffe00000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 87f53bf620d3677268445212904389d5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 115
+KEY = fffffffffffffffffffffffffffff00000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 10617d28b5e0f4605492b182a5d7f9f6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 116
+KEY = fffffffffffffffffffffffffffff80000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9aaec4fabbf6fae2a71feff02e372b39
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 117
+KEY = fffffffffffffffffffffffffffffc0000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3a90c62d88b5c42809abf782488ed130
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 118
+KEY = fffffffffffffffffffffffffffffe0000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f1f1c5a40899e15772857ccb65c7a09a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 119
+KEY = ffffffffffffffffffffffffffffff0000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 190843d29b25a3897c692ce1dd81ee52
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 120
+KEY = ffffffffffffffffffffffffffffff8000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a866bc65b6941d86e8420a7ffb0964db
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 121
+KEY = ffffffffffffffffffffffffffffffc000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8193c6ff85225ced4255e92f6e078a14
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 122
+KEY = ffffffffffffffffffffffffffffffe000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9661cb2424d7d4a380d547f9e7ec1cb9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 123
+KEY = fffffffffffffffffffffffffffffff000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 86f93d9ec08453a071e2e2877877a9c8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 124
+KEY = fffffffffffffffffffffffffffffff800000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 27eefa80ce6a4a9d598e3fec365434d2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 125
+KEY = fffffffffffffffffffffffffffffffc00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d62068444578e3ab39ce7ec95dd045dc
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 126
+KEY = fffffffffffffffffffffffffffffffe00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b5f71d4dd9a71fe5d8bc8ba7e6ea3048
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 127
+KEY = ffffffffffffffffffffffffffffffff00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6825a347ac479d4f9d95c5cb8d3fd7e9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 128
+KEY = ffffffffffffffffffffffffffffffff80000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e3714e94a5778955cc0346358e94783a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 129
+KEY = ffffffffffffffffffffffffffffffffc0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d836b44bb29e0c7d89fa4b2d4b677d2a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 130
+KEY = ffffffffffffffffffffffffffffffffe0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5d454b75021d76d4b84f873a8f877b92
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 131
+KEY = fffffffffffffffffffffffffffffffff0000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c3498f7eced2095314fc28115885b33f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 132
+KEY = fffffffffffffffffffffffffffffffff8000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6e668856539ad8e405bd123fe6c88530
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 133
+KEY = fffffffffffffffffffffffffffffffffc000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8680db7f3a87b8605543cfdbe6754076
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 134
+KEY = fffffffffffffffffffffffffffffffffe000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6c5d03b13069c3658b3179be91b0800c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 135
+KEY = ffffffffffffffffffffffffffffffffff000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ef1b384ac4d93eda00c92add0995ea5f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 136
+KEY = ffffffffffffffffffffffffffffffffff800000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = bf8115805471741bd5ad20a03944790f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 137
+KEY = ffffffffffffffffffffffffffffffffffc00000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c64c24b6894b038b3c0d09b1df068b0b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 138
+KEY = ffffffffffffffffffffffffffffffffffe00000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3967a10cffe27d0178545fbf6a40544b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 139
+KEY = fffffffffffffffffffffffffffffffffff00000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7c85e9c95de1a9ec5a5363a8a053472d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 140
+KEY = fffffffffffffffffffffffffffffffffff80000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a9eec03c8abec7ba68315c2c8c2316e0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 141
+KEY = fffffffffffffffffffffffffffffffffffc0000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cac8e414c2f388227ae14986fc983524
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 142
+KEY = fffffffffffffffffffffffffffffffffffe0000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5d942b7f4622ce056c3ce3ce5f1dd9d6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 143
+KEY = ffffffffffffffffffffffffffffffffffff0000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d240d648ce21a3020282c3f1b528a0b6
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 144
+KEY = ffffffffffffffffffffffffffffffffffff8000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 45d089c36d5c5a4efc689e3b0de10dd5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 145
+KEY = ffffffffffffffffffffffffffffffffffffc000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b4da5df4becb5462e03a0ed00d295629
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 146
+KEY = ffffffffffffffffffffffffffffffffffffe000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dcf4e129136c1a4b7a0f38935cc34b2b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 147
+KEY = fffffffffffffffffffffffffffffffffffff000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d9a4c7618b0ce48a3d5aee1a1c0114c4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 148
+KEY = fffffffffffffffffffffffffffffffffffff800000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ca352df025c65c7b0bf306fbee0f36ba
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 149
+KEY = fffffffffffffffffffffffffffffffffffffc00000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 238aca23fd3409f38af63378ed2f5473
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 150
+KEY = fffffffffffffffffffffffffffffffffffffe00000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 59836a0e06a79691b36667d5380d8188
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 151
+KEY = ffffffffffffffffffffffffffffffffffffff00000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 33905080f7acf1cdae0a91fc3e85aee4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 152
+KEY = ffffffffffffffffffffffffffffffffffffff80000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 72c9e4646dbc3d6320fc6689d93e8833
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 153
+KEY = ffffffffffffffffffffffffffffffffffffffc0000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ba77413dea5925b7f5417ea47ff19f59
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 154
+KEY = ffffffffffffffffffffffffffffffffffffffe0000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6cae8129f843d86dc786a0fb1a184970
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 155
+KEY = fffffffffffffffffffffffffffffffffffffff0000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fcfefb534100796eebbd990206754e19
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 156
+KEY = fffffffffffffffffffffffffffffffffffffff8000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8c791d5fdddf470da04f3e6dc4a5b5b5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 157
+KEY = fffffffffffffffffffffffffffffffffffffffc000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c93bbdc07a4611ae4bb266ea5034a387
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 158
+KEY = fffffffffffffffffffffffffffffffffffffffe000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c102e38e489aa74762f3efc5bb23205a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 159
+KEY = ffffffffffffffffffffffffffffffffffffffff000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 93201481665cbafc1fcc220bc545fb3d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 160
+KEY = ffffffffffffffffffffffffffffffffffffffff800000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4960757ec6ce68cf195e454cfd0f32ca
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 161
+KEY = ffffffffffffffffffffffffffffffffffffffffc00000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = feec7ce6a6cbd07c043416737f1bbb33
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 162
+KEY = ffffffffffffffffffffffffffffffffffffffffe00000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 11c5413904487a805d70a8edd9c35527
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 163
+KEY = fffffffffffffffffffffffffffffffffffffffff00000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 347846b2b2e36f1f0324c86f7f1b98e2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 164
+KEY = fffffffffffffffffffffffffffffffffffffffff80000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 332eee1a0cbd19ca2d69b426894044f0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 165
+KEY = fffffffffffffffffffffffffffffffffffffffffc0000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 866b5b3977ba6efa5128efbda9ff03cd
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 166
+KEY = fffffffffffffffffffffffffffffffffffffffffe0000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cc1445ee94c0f08cdee5c344ecd1e233
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 167
+KEY = ffffffffffffffffffffffffffffffffffffffffff0000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = be288319029363c2622feba4b05dfdfe
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 168
+KEY = ffffffffffffffffffffffffffffffffffffffffff8000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cfd1875523f3cd21c395651e6ee15e56
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 169
+KEY = ffffffffffffffffffffffffffffffffffffffffffc000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cb5a408657837c53bf16f9d8465dce19
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 170
+KEY = ffffffffffffffffffffffffffffffffffffffffffe000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ca0bf42cb107f55ccff2fc09ee08ca15
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 171
+KEY = fffffffffffffffffffffffffffffffffffffffffff000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fdd9bbb4a7dc2e4a23536a5880a2db67
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 172
+KEY = fffffffffffffffffffffffffffffffffffffffffff800000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ede447b362c484993dec9442a3b46aef
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 173
+KEY = fffffffffffffffffffffffffffffffffffffffffffc00000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 10dffb05904bff7c4781df780ad26837
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 174
+KEY = fffffffffffffffffffffffffffffffffffffffffffe00000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c33bc13e8de88ac25232aa7496398783
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 175
+KEY = ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ca359c70803a3b2a3d542e8781dea975
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 176
+KEY = ffffffffffffffffffffffffffffffffffffffffffff80000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = bcc65b526f88d05b89ce8a52021fdb06
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 177
+KEY = ffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = db91a38855c8c4643851fbfb358b0109
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 178
+KEY = ffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ca6e8893a114ae8e27d5ab03a5499610
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 179
+KEY = fffffffffffffffffffffffffffffffffffffffffffff0000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6629d2b8df97da728cdd8b1e7f945077
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 180
+KEY = fffffffffffffffffffffffffffffffffffffffffffff8000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4570a5a18cfc0dd582f1d88d5c9a1720
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 181
+KEY = fffffffffffffffffffffffffffffffffffffffffffffc000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 72bc65aa8e89562e3f274d45af1cd10b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 182
+KEY = fffffffffffffffffffffffffffffffffffffffffffffe000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 98551da1a6503276ae1c77625f9ea615
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 183
+KEY = ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0ddfe51ced7e3f4ae927daa3fe452cee
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 184
+KEY = ffffffffffffffffffffffffffffffffffffffffffffff800000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = db826251e4ce384b80218b0e1da1dd4c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 185
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2cacf728b88abbad7011ed0e64a1680c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 186
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffe00000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 330d8ee7c5677e099ac74c9994ee4cfb
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 187
+KEY = fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = edf61ae362e882ddc0167474a7a77f3a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 188
+KEY = fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6168b00ba7859e0970ecfd757efecf7c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 189
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d1415447866230d28bb1ea18a4cdfd02
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 190
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 516183392f7a8763afec68a060264141
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 191
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 77565c8d73cfd4130b4aa14d8911710f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 192
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 37232a4ed21ccc27c19c9610078cabac
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 193
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 804f32ea71828c7d329077e712231666
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 194
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d64424f23cb97215e9c2c6f28d29eab7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 195
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 023e82b533f68c75c238cebdb2ee89a2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 196
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffff800000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 193a3d24157a51f1ee0893f6777417e7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 197
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 84ecacfcd400084d078612b1945f2ef5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 198
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffe00000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1dcd8bb173259eb33a5242b0de31a455
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 199
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 35e9eddbc375e792c19992c19165012b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 200
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8a772231c01dfdd7c98e4cfddcc0807a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 201
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6eda7ff6b8319180ff0d6e65629d01c3
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 202
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c267ef0e2d01a993944dd397101413cb
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 203
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e9f80e9d845bcc0f62926af72eabca39
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 204
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6702990727aa0878637b45dcd3a3b074
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 205
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2e2e647d5360e09230a5d738ca33471e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 206
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1f56413c7add6f43d1d56e4f02190330
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 207
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 69cd0606e15af729d6bca143016d9842
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 208
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a085d7c1a500873a20099c4caa3c3f5b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 209
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4fc0d230f8891415b87b83f95f2e09d1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 210
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4327d08c523d8eba697a4336507d1f42
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 211
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7a15aab82701efa5ae36ab1d6b76290f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 212
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5bf0051893a18bb30e139a58fed0fa54
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 213
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 97e8adf65638fd9cdf3bc22c17fe4dbd
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 214
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1ee6ee326583a0586491c96418d1a35d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 215
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 26b549c2ec756f82ecc48008e529956b
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 216
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 70377b6da669b072129e057cc28e9ca5
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 217
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9c94b8b0cb8bcc919072262b3fa05ad9
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 218
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2fbb83dfd0d7abcb05cd28cad2dfb523
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 219
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 96877803de77744bb970d0a91f4debae
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 220
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7379f3370cf6e5ce12ae5969c8eea312
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 221
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 02dc99fa3d4f98ce80985e7233889313
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 222
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1e38e759075ba5cab6457da51844295a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 223
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 70bed8dbf615868a1f9d9b05d3e7a267
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 224
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 234b148b8cb1d8c32b287e896903d150
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 225
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 294b033df4da853f4be3e243f7e513f4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 226
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3f58c950f0367160adec45f2441e7411
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 227
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 37f655536a704e5ace182d742a820cf4
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 228
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ea7bd6bb63418731aeac790fe42d61e8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 229
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e74a4c999b4c064e48bb1e413f51e5ea
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 230
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ba9ebefdb4ccf30f296cecb3bc1943e8
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 231
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3194367a4898c502c13bb7478640a72d
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 232
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = da797713263d6f33a5478a65ef60d412
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 233
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d1ac39bb1ef86b9c1344f214679aa376
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 234
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2fdea9e650532be5bc0e7325337fd363
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 235
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d3a204dbd9c2af158b6ca67a5156ce4a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 236
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3a0a0e75a8da36735aee6684d965a778
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 237
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 52fc3e620492ea99641ea168da5b6d52
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 238
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d2e0c7f15b4772467d2cfc873000b2ca
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 239
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 563531135e0c4d70a38f8bdb190ba04e
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 240
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a8a39a0f5663f4c0fe5f2d3cafff421a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 241
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d94b5e90db354c1e42f61fabe167b2c0
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 242
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 50e6d3c9b6698a7cd276f96b1473f35a
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 243
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9338f08e0ebee96905d8f2e825208f43
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 244
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8b378c86672aa54a3a266ba19d2580ca
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 245
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cca7c3086f5f9511b31233da7cab9160
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 246
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5b40ff4ec9be536ba23035fa4f06064c
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 247
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 60eb5af8416b257149372194e8b88749
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 248
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2f005a8aed8a361c92e440c15520cbd1
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 249
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7b03627611678a997717578807a800e2
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 250
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cf78618f74f6f3696e0a4779b90b5a77
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 251
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 03720371a04962eaea0a852e69972858
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 252
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1f8a8133aa8ccf70e2bd3285831ca6b7
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 253
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 27936bd27fb1468fc8b48bc483321725
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 254
+KEY = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b07d4f3e2cd2ef2eb545980754dfea0f
+PLAINTEXT = 00000000000000000000000000000000
+
+COUNT = 255
+KEY = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4bf85f1b5d54adbc307b0a048389adcb
+PLAINTEXT = 00000000000000000000000000000000
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarTxt128.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarTxt128.rsp
new file mode 100644
index 0000000..5fc737c
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarTxt128.rsp
@@ -0,0 +1,1547 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS VarTxt test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 128
+# Generated on Fri Apr 22 15:11:33 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 80000000000000000000000000000000
+CIPHERTEXT = 3ad78e726c1ec02b7ebfe92b23d9ec34
+
+COUNT = 1
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = c0000000000000000000000000000000
+CIPHERTEXT = aae5939c8efdf2f04e60b9fe7117b2c2
+
+COUNT = 2
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = e0000000000000000000000000000000
+CIPHERTEXT = f031d4d74f5dcbf39daaf8ca3af6e527
+
+COUNT = 3
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = f0000000000000000000000000000000
+CIPHERTEXT = 96d9fd5cc4f07441727df0f33e401a36
+
+COUNT = 4
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = f8000000000000000000000000000000
+CIPHERTEXT = 30ccdb044646d7e1f3ccea3dca08b8c0
+
+COUNT = 5
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fc000000000000000000000000000000
+CIPHERTEXT = 16ae4ce5042a67ee8e177b7c587ecc82
+
+COUNT = 6
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fe000000000000000000000000000000
+CIPHERTEXT = b6da0bb11a23855d9c5cb1b4c6412e0a
+
+COUNT = 7
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ff000000000000000000000000000000
+CIPHERTEXT = db4f1aa530967d6732ce4715eb0ee24b
+
+COUNT = 8
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ff800000000000000000000000000000
+CIPHERTEXT = a81738252621dd180a34f3455b4baa2f
+
+COUNT = 9
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffc00000000000000000000000000000
+CIPHERTEXT = 77e2b508db7fd89234caf7939ee5621a
+
+COUNT = 10
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffe00000000000000000000000000000
+CIPHERTEXT = b8499c251f8442ee13f0933b688fcd19
+
+COUNT = 11
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fff00000000000000000000000000000
+CIPHERTEXT = 965135f8a81f25c9d630b17502f68e53
+
+COUNT = 12
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fff80000000000000000000000000000
+CIPHERTEXT = 8b87145a01ad1c6cede995ea3670454f
+
+COUNT = 13
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffc0000000000000000000000000000
+CIPHERTEXT = 8eae3b10a0c8ca6d1d3b0fa61e56b0b2
+
+COUNT = 14
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffe0000000000000000000000000000
+CIPHERTEXT = 64b4d629810fda6bafdf08f3b0d8d2c5
+
+COUNT = 15
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffff0000000000000000000000000000
+CIPHERTEXT = d7e5dbd3324595f8fdc7d7c571da6c2a
+
+COUNT = 16
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffff8000000000000000000000000000
+CIPHERTEXT = f3f72375264e167fca9de2c1527d9606
+
+COUNT = 17
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffc000000000000000000000000000
+CIPHERTEXT = 8ee79dd4f401ff9b7ea945d86666c13b
+
+COUNT = 18
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffe000000000000000000000000000
+CIPHERTEXT = dd35cea2799940b40db3f819cb94c08b
+
+COUNT = 19
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffff000000000000000000000000000
+CIPHERTEXT = 6941cb6b3e08c2b7afa581ebdd607b87
+
+COUNT = 20
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffff800000000000000000000000000
+CIPHERTEXT = 2c20f439f6bb097b29b8bd6d99aad799
+
+COUNT = 21
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffc00000000000000000000000000
+CIPHERTEXT = 625d01f058e565f77ae86378bd2c49b3
+
+COUNT = 22
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffe00000000000000000000000000
+CIPHERTEXT = c0b5fd98190ef45fbb4301438d095950
+
+COUNT = 23
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffff00000000000000000000000000
+CIPHERTEXT = 13001ff5d99806efd25da34f56be854b
+
+COUNT = 24
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffff80000000000000000000000000
+CIPHERTEXT = 3b594c60f5c8277a5113677f94208d82
+
+COUNT = 25
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffc0000000000000000000000000
+CIPHERTEXT = e9c0fc1818e4aa46bd2e39d638f89e05
+
+COUNT = 26
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffe0000000000000000000000000
+CIPHERTEXT = f8023ee9c3fdc45a019b4e985c7e1a54
+
+COUNT = 27
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffff0000000000000000000000000
+CIPHERTEXT = 35f40182ab4662f3023baec1ee796b57
+
+COUNT = 28
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffff8000000000000000000000000
+CIPHERTEXT = 3aebbad7303649b4194a6945c6cc3694
+
+COUNT = 29
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffc000000000000000000000000
+CIPHERTEXT = a2124bea53ec2834279bed7f7eb0f938
+
+COUNT = 30
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffe000000000000000000000000
+CIPHERTEXT = b9fb4399fa4facc7309e14ec98360b0a
+
+COUNT = 31
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffff000000000000000000000000
+CIPHERTEXT = c26277437420c5d634f715aea81a9132
+
+COUNT = 32
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffff800000000000000000000000
+CIPHERTEXT = 171a0e1b2dd424f0e089af2c4c10f32f
+
+COUNT = 33
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffc00000000000000000000000
+CIPHERTEXT = 7cadbe402d1b208fe735edce00aee7ce
+
+COUNT = 34
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffe00000000000000000000000
+CIPHERTEXT = 43b02ff929a1485af6f5c6d6558baa0f
+
+COUNT = 35
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffff00000000000000000000000
+CIPHERTEXT = 092faacc9bf43508bf8fa8613ca75dea
+
+COUNT = 36
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffff80000000000000000000000
+CIPHERTEXT = cb2bf8280f3f9742c7ed513fe802629c
+
+COUNT = 37
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffc0000000000000000000000
+CIPHERTEXT = 215a41ee442fa992a6e323986ded3f68
+
+COUNT = 38
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffe0000000000000000000000
+CIPHERTEXT = f21e99cf4f0f77cea836e11a2fe75fb1
+
+COUNT = 39
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffff0000000000000000000000
+CIPHERTEXT = 95e3a0ca9079e646331df8b4e70d2cd6
+
+COUNT = 40
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffff8000000000000000000000
+CIPHERTEXT = 4afe7f120ce7613f74fc12a01a828073
+
+COUNT = 41
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffc000000000000000000000
+CIPHERTEXT = 827f000e75e2c8b9d479beed913fe678
+
+COUNT = 42
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffe000000000000000000000
+CIPHERTEXT = 35830c8e7aaefe2d30310ef381cbf691
+
+COUNT = 43
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffff000000000000000000000
+CIPHERTEXT = 191aa0f2c8570144f38657ea4085ebe5
+
+COUNT = 44
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffff800000000000000000000
+CIPHERTEXT = 85062c2c909f15d9269b6c18ce99c4f0
+
+COUNT = 45
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffc00000000000000000000
+CIPHERTEXT = 678034dc9e41b5a560ed239eeab1bc78
+
+COUNT = 46
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffe00000000000000000000
+CIPHERTEXT = c2f93a4ce5ab6d5d56f1b93cf19911c1
+
+COUNT = 47
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffff00000000000000000000
+CIPHERTEXT = 1c3112bcb0c1dcc749d799743691bf82
+
+COUNT = 48
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffff80000000000000000000
+CIPHERTEXT = 00c55bd75c7f9c881989d3ec1911c0d4
+
+COUNT = 49
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffc0000000000000000000
+CIPHERTEXT = ea2e6b5ef182b7dff3629abd6a12045f
+
+COUNT = 50
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffe0000000000000000000
+CIPHERTEXT = 22322327e01780b17397f24087f8cc6f
+
+COUNT = 51
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffff0000000000000000000
+CIPHERTEXT = c9cacb5cd11692c373b2411768149ee7
+
+COUNT = 52
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffff8000000000000000000
+CIPHERTEXT = a18e3dbbca577860dab6b80da3139256
+
+COUNT = 53
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffc000000000000000000
+CIPHERTEXT = 79b61c37bf328ecca8d743265a3d425c
+
+COUNT = 54
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffe000000000000000000
+CIPHERTEXT = d2d99c6bcc1f06fda8e27e8ae3f1ccc7
+
+COUNT = 55
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffff000000000000000000
+CIPHERTEXT = 1bfd4b91c701fd6b61b7f997829d663b
+
+COUNT = 56
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffff800000000000000000
+CIPHERTEXT = 11005d52f25f16bdc9545a876a63490a
+
+COUNT = 57
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffc00000000000000000
+CIPHERTEXT = 3a4d354f02bb5a5e47d39666867f246a
+
+COUNT = 58
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffe00000000000000000
+CIPHERTEXT = d451b8d6e1e1a0ebb155fbbf6e7b7dc3
+
+COUNT = 59
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffff00000000000000000
+CIPHERTEXT = 6898d4f42fa7ba6a10ac05e87b9f2080
+
+COUNT = 60
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffff80000000000000000
+CIPHERTEXT = b611295e739ca7d9b50f8e4c0e754a3f
+
+COUNT = 61
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffc0000000000000000
+CIPHERTEXT = 7d33fc7d8abe3ca1936759f8f5deaf20
+
+COUNT = 62
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffe0000000000000000
+CIPHERTEXT = 3b5e0f566dc96c298f0c12637539b25c
+
+COUNT = 63
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffff0000000000000000
+CIPHERTEXT = f807c3e7985fe0f5a50e2cdb25c5109e
+
+COUNT = 64
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffff8000000000000000
+CIPHERTEXT = 41f992a856fb278b389a62f5d274d7e9
+
+COUNT = 65
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffc000000000000000
+CIPHERTEXT = 10d3ed7a6fe15ab4d91acbc7d0767ab1
+
+COUNT = 66
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffe000000000000000
+CIPHERTEXT = 21feecd45b2e675973ac33bf0c5424fc
+
+COUNT = 67
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffff000000000000000
+CIPHERTEXT = 1480cb3955ba62d09eea668f7c708817
+
+COUNT = 68
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffff800000000000000
+CIPHERTEXT = 66404033d6b72b609354d5496e7eb511
+
+COUNT = 69
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffc00000000000000
+CIPHERTEXT = 1c317a220a7d700da2b1e075b00266e1
+
+COUNT = 70
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffe00000000000000
+CIPHERTEXT = ab3b89542233f1271bf8fd0c0f403545
+
+COUNT = 71
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffff00000000000000
+CIPHERTEXT = d93eae966fac46dca927d6b114fa3f9e
+
+COUNT = 72
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffff80000000000000
+CIPHERTEXT = 1bdec521316503d9d5ee65df3ea94ddf
+
+COUNT = 73
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffc0000000000000
+CIPHERTEXT = eef456431dea8b4acf83bdae3717f75f
+
+COUNT = 74
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffe0000000000000
+CIPHERTEXT = 06f2519a2fafaa596bfef5cfa15c21b9
+
+COUNT = 75
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffff0000000000000
+CIPHERTEXT = 251a7eac7e2fe809e4aa8d0d7012531a
+
+COUNT = 76
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffff8000000000000
+CIPHERTEXT = 3bffc16e4c49b268a20f8d96a60b4058
+
+COUNT = 77
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffc000000000000
+CIPHERTEXT = e886f9281999c5bb3b3e8862e2f7c988
+
+COUNT = 78
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffe000000000000
+CIPHERTEXT = 563bf90d61beef39f48dd625fcef1361
+
+COUNT = 79
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffff000000000000
+CIPHERTEXT = 4d37c850644563c69fd0acd9a049325b
+
+COUNT = 80
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffff800000000000
+CIPHERTEXT = b87c921b91829ef3b13ca541ee1130a6
+
+COUNT = 81
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffc00000000000
+CIPHERTEXT = 2e65eb6b6ea383e109accce8326b0393
+
+COUNT = 82
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffe00000000000
+CIPHERTEXT = 9ca547f7439edc3e255c0f4d49aa8990
+
+COUNT = 83
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffff00000000000
+CIPHERTEXT = a5e652614c9300f37816b1f9fd0c87f9
+
+COUNT = 84
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffff80000000000
+CIPHERTEXT = 14954f0b4697776f44494fe458d814ed
+
+COUNT = 85
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffc0000000000
+CIPHERTEXT = 7c8d9ab6c2761723fe42f8bb506cbcf7
+
+COUNT = 86
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffe0000000000
+CIPHERTEXT = db7e1932679fdd99742aab04aa0d5a80
+
+COUNT = 87
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffff0000000000
+CIPHERTEXT = 4c6a1c83e568cd10f27c2d73ded19c28
+
+COUNT = 88
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffff8000000000
+CIPHERTEXT = 90ecbe6177e674c98de412413f7ac915
+
+COUNT = 89
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffc000000000
+CIPHERTEXT = 90684a2ac55fe1ec2b8ebd5622520b73
+
+COUNT = 90
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffe000000000
+CIPHERTEXT = 7472f9a7988607ca79707795991035e6
+
+COUNT = 91
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffff000000000
+CIPHERTEXT = 56aff089878bf3352f8df172a3ae47d8
+
+COUNT = 92
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffff800000000
+CIPHERTEXT = 65c0526cbe40161b8019a2a3171abd23
+
+COUNT = 93
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffc00000000
+CIPHERTEXT = 377be0be33b4e3e310b4aabda173f84f
+
+COUNT = 94
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffe00000000
+CIPHERTEXT = 9402e9aa6f69de6504da8d20c4fcaa2f
+
+COUNT = 95
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffff00000000
+CIPHERTEXT = 123c1f4af313ad8c2ce648b2e71fb6e1
+
+COUNT = 96
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffff80000000
+CIPHERTEXT = 1ffc626d30203dcdb0019fb80f726cf4
+
+COUNT = 97
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffc0000000
+CIPHERTEXT = 76da1fbe3a50728c50fd2e621b5ad885
+
+COUNT = 98
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffe0000000
+CIPHERTEXT = 082eb8be35f442fb52668e16a591d1d6
+
+COUNT = 99
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffff0000000
+CIPHERTEXT = e656f9ecf5fe27ec3e4a73d00c282fb3
+
+COUNT = 100
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffff8000000
+CIPHERTEXT = 2ca8209d63274cd9a29bb74bcd77683a
+
+COUNT = 101
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffc000000
+CIPHERTEXT = 79bf5dce14bb7dd73a8e3611de7ce026
+
+COUNT = 102
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffe000000
+CIPHERTEXT = 3c849939a5d29399f344c4a0eca8a576
+
+COUNT = 103
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffff000000
+CIPHERTEXT = ed3c0a94d59bece98835da7aa4f07ca2
+
+COUNT = 104
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffff800000
+CIPHERTEXT = 63919ed4ce10196438b6ad09d99cd795
+
+COUNT = 105
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffc00000
+CIPHERTEXT = 7678f3a833f19fea95f3c6029e2bc610
+
+COUNT = 106
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffe00000
+CIPHERTEXT = 3aa426831067d36b92be7c5f81c13c56
+
+COUNT = 107
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffff00000
+CIPHERTEXT = 9272e2d2cdd11050998c845077a30ea0
+
+COUNT = 108
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffff80000
+CIPHERTEXT = 088c4b53f5ec0ff814c19adae7f6246c
+
+COUNT = 109
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffc0000
+CIPHERTEXT = 4010a5e401fdf0a0354ddbcc0d012b17
+
+COUNT = 110
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffe0000
+CIPHERTEXT = a87a385736c0a6189bd6589bd8445a93
+
+COUNT = 111
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffff0000
+CIPHERTEXT = 545f2b83d9616dccf60fa9830e9cd287
+
+COUNT = 112
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffff8000
+CIPHERTEXT = 4b706f7f92406352394037a6d4f4688d
+
+COUNT = 113
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffc000
+CIPHERTEXT = b7972b3941c44b90afa7b264bfba7387
+
+COUNT = 114
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffe000
+CIPHERTEXT = 6f45732cf10881546f0fd23896d2bb60
+
+COUNT = 115
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffff000
+CIPHERTEXT = 2e3579ca15af27f64b3c955a5bfc30ba
+
+COUNT = 116
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffff800
+CIPHERTEXT = 34a2c5a91ae2aec99b7d1b5fa6780447
+
+COUNT = 117
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffc00
+CIPHERTEXT = a4d6616bd04f87335b0e53351227a9ee
+
+COUNT = 118
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffe00
+CIPHERTEXT = 7f692b03945867d16179a8cefc83ea3f
+
+COUNT = 119
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffff00
+CIPHERTEXT = 3bd141ee84a0e6414a26e7a4f281f8a2
+
+COUNT = 120
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffff80
+CIPHERTEXT = d1788f572d98b2b16ec5d5f3922b99bc
+
+COUNT = 121
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffffc0
+CIPHERTEXT = 0833ff6f61d98a57b288e8c3586b85a6
+
+COUNT = 122
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffffe0
+CIPHERTEXT = 8568261797de176bf0b43becc6285afb
+
+COUNT = 123
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffff0
+CIPHERTEXT = f9b0fda0c4a898f5b9e6f661c4ce4d07
+
+COUNT = 124
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffff8
+CIPHERTEXT = 8ade895913685c67c5269f8aae42983e
+
+COUNT = 125
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffffc
+CIPHERTEXT = 39bde67d5c8ed8a8b1c37eb8fa9f5ac0
+
+COUNT = 126
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffffe
+CIPHERTEXT = 5c005e72c1418c44f569f2ea33ba54f3
+
+COUNT = 127
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffffff
+CIPHERTEXT = 3f5b8cc9ea855a0afa7347d23e8d664e
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3ad78e726c1ec02b7ebfe92b23d9ec34
+PLAINTEXT = 80000000000000000000000000000000
+
+COUNT = 1
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = aae5939c8efdf2f04e60b9fe7117b2c2
+PLAINTEXT = c0000000000000000000000000000000
+
+COUNT = 2
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f031d4d74f5dcbf39daaf8ca3af6e527
+PLAINTEXT = e0000000000000000000000000000000
+
+COUNT = 3
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 96d9fd5cc4f07441727df0f33e401a36
+PLAINTEXT = f0000000000000000000000000000000
+
+COUNT = 4
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 30ccdb044646d7e1f3ccea3dca08b8c0
+PLAINTEXT = f8000000000000000000000000000000
+
+COUNT = 5
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 16ae4ce5042a67ee8e177b7c587ecc82
+PLAINTEXT = fc000000000000000000000000000000
+
+COUNT = 6
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b6da0bb11a23855d9c5cb1b4c6412e0a
+PLAINTEXT = fe000000000000000000000000000000
+
+COUNT = 7
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = db4f1aa530967d6732ce4715eb0ee24b
+PLAINTEXT = ff000000000000000000000000000000
+
+COUNT = 8
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a81738252621dd180a34f3455b4baa2f
+PLAINTEXT = ff800000000000000000000000000000
+
+COUNT = 9
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 77e2b508db7fd89234caf7939ee5621a
+PLAINTEXT = ffc00000000000000000000000000000
+
+COUNT = 10
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b8499c251f8442ee13f0933b688fcd19
+PLAINTEXT = ffe00000000000000000000000000000
+
+COUNT = 11
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 965135f8a81f25c9d630b17502f68e53
+PLAINTEXT = fff00000000000000000000000000000
+
+COUNT = 12
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8b87145a01ad1c6cede995ea3670454f
+PLAINTEXT = fff80000000000000000000000000000
+
+COUNT = 13
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8eae3b10a0c8ca6d1d3b0fa61e56b0b2
+PLAINTEXT = fffc0000000000000000000000000000
+
+COUNT = 14
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 64b4d629810fda6bafdf08f3b0d8d2c5
+PLAINTEXT = fffe0000000000000000000000000000
+
+COUNT = 15
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d7e5dbd3324595f8fdc7d7c571da6c2a
+PLAINTEXT = ffff0000000000000000000000000000
+
+COUNT = 16
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f3f72375264e167fca9de2c1527d9606
+PLAINTEXT = ffff8000000000000000000000000000
+
+COUNT = 17
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8ee79dd4f401ff9b7ea945d86666c13b
+PLAINTEXT = ffffc000000000000000000000000000
+
+COUNT = 18
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dd35cea2799940b40db3f819cb94c08b
+PLAINTEXT = ffffe000000000000000000000000000
+
+COUNT = 19
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6941cb6b3e08c2b7afa581ebdd607b87
+PLAINTEXT = fffff000000000000000000000000000
+
+COUNT = 20
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2c20f439f6bb097b29b8bd6d99aad799
+PLAINTEXT = fffff800000000000000000000000000
+
+COUNT = 21
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 625d01f058e565f77ae86378bd2c49b3
+PLAINTEXT = fffffc00000000000000000000000000
+
+COUNT = 22
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c0b5fd98190ef45fbb4301438d095950
+PLAINTEXT = fffffe00000000000000000000000000
+
+COUNT = 23
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 13001ff5d99806efd25da34f56be854b
+PLAINTEXT = ffffff00000000000000000000000000
+
+COUNT = 24
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3b594c60f5c8277a5113677f94208d82
+PLAINTEXT = ffffff80000000000000000000000000
+
+COUNT = 25
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e9c0fc1818e4aa46bd2e39d638f89e05
+PLAINTEXT = ffffffc0000000000000000000000000
+
+COUNT = 26
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f8023ee9c3fdc45a019b4e985c7e1a54
+PLAINTEXT = ffffffe0000000000000000000000000
+
+COUNT = 27
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 35f40182ab4662f3023baec1ee796b57
+PLAINTEXT = fffffff0000000000000000000000000
+
+COUNT = 28
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3aebbad7303649b4194a6945c6cc3694
+PLAINTEXT = fffffff8000000000000000000000000
+
+COUNT = 29
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a2124bea53ec2834279bed7f7eb0f938
+PLAINTEXT = fffffffc000000000000000000000000
+
+COUNT = 30
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b9fb4399fa4facc7309e14ec98360b0a
+PLAINTEXT = fffffffe000000000000000000000000
+
+COUNT = 31
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c26277437420c5d634f715aea81a9132
+PLAINTEXT = ffffffff000000000000000000000000
+
+COUNT = 32
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 171a0e1b2dd424f0e089af2c4c10f32f
+PLAINTEXT = ffffffff800000000000000000000000
+
+COUNT = 33
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7cadbe402d1b208fe735edce00aee7ce
+PLAINTEXT = ffffffffc00000000000000000000000
+
+COUNT = 34
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 43b02ff929a1485af6f5c6d6558baa0f
+PLAINTEXT = ffffffffe00000000000000000000000
+
+COUNT = 35
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 092faacc9bf43508bf8fa8613ca75dea
+PLAINTEXT = fffffffff00000000000000000000000
+
+COUNT = 36
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cb2bf8280f3f9742c7ed513fe802629c
+PLAINTEXT = fffffffff80000000000000000000000
+
+COUNT = 37
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 215a41ee442fa992a6e323986ded3f68
+PLAINTEXT = fffffffffc0000000000000000000000
+
+COUNT = 38
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f21e99cf4f0f77cea836e11a2fe75fb1
+PLAINTEXT = fffffffffe0000000000000000000000
+
+COUNT = 39
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 95e3a0ca9079e646331df8b4e70d2cd6
+PLAINTEXT = ffffffffff0000000000000000000000
+
+COUNT = 40
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4afe7f120ce7613f74fc12a01a828073
+PLAINTEXT = ffffffffff8000000000000000000000
+
+COUNT = 41
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 827f000e75e2c8b9d479beed913fe678
+PLAINTEXT = ffffffffffc000000000000000000000
+
+COUNT = 42
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 35830c8e7aaefe2d30310ef381cbf691
+PLAINTEXT = ffffffffffe000000000000000000000
+
+COUNT = 43
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 191aa0f2c8570144f38657ea4085ebe5
+PLAINTEXT = fffffffffff000000000000000000000
+
+COUNT = 44
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 85062c2c909f15d9269b6c18ce99c4f0
+PLAINTEXT = fffffffffff800000000000000000000
+
+COUNT = 45
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 678034dc9e41b5a560ed239eeab1bc78
+PLAINTEXT = fffffffffffc00000000000000000000
+
+COUNT = 46
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c2f93a4ce5ab6d5d56f1b93cf19911c1
+PLAINTEXT = fffffffffffe00000000000000000000
+
+COUNT = 47
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1c3112bcb0c1dcc749d799743691bf82
+PLAINTEXT = ffffffffffff00000000000000000000
+
+COUNT = 48
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 00c55bd75c7f9c881989d3ec1911c0d4
+PLAINTEXT = ffffffffffff80000000000000000000
+
+COUNT = 49
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ea2e6b5ef182b7dff3629abd6a12045f
+PLAINTEXT = ffffffffffffc0000000000000000000
+
+COUNT = 50
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 22322327e01780b17397f24087f8cc6f
+PLAINTEXT = ffffffffffffe0000000000000000000
+
+COUNT = 51
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c9cacb5cd11692c373b2411768149ee7
+PLAINTEXT = fffffffffffff0000000000000000000
+
+COUNT = 52
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a18e3dbbca577860dab6b80da3139256
+PLAINTEXT = fffffffffffff8000000000000000000
+
+COUNT = 53
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 79b61c37bf328ecca8d743265a3d425c
+PLAINTEXT = fffffffffffffc000000000000000000
+
+COUNT = 54
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d2d99c6bcc1f06fda8e27e8ae3f1ccc7
+PLAINTEXT = fffffffffffffe000000000000000000
+
+COUNT = 55
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1bfd4b91c701fd6b61b7f997829d663b
+PLAINTEXT = ffffffffffffff000000000000000000
+
+COUNT = 56
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 11005d52f25f16bdc9545a876a63490a
+PLAINTEXT = ffffffffffffff800000000000000000
+
+COUNT = 57
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3a4d354f02bb5a5e47d39666867f246a
+PLAINTEXT = ffffffffffffffc00000000000000000
+
+COUNT = 58
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d451b8d6e1e1a0ebb155fbbf6e7b7dc3
+PLAINTEXT = ffffffffffffffe00000000000000000
+
+COUNT = 59
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6898d4f42fa7ba6a10ac05e87b9f2080
+PLAINTEXT = fffffffffffffff00000000000000000
+
+COUNT = 60
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b611295e739ca7d9b50f8e4c0e754a3f
+PLAINTEXT = fffffffffffffff80000000000000000
+
+COUNT = 61
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7d33fc7d8abe3ca1936759f8f5deaf20
+PLAINTEXT = fffffffffffffffc0000000000000000
+
+COUNT = 62
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3b5e0f566dc96c298f0c12637539b25c
+PLAINTEXT = fffffffffffffffe0000000000000000
+
+COUNT = 63
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f807c3e7985fe0f5a50e2cdb25c5109e
+PLAINTEXT = ffffffffffffffff0000000000000000
+
+COUNT = 64
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 41f992a856fb278b389a62f5d274d7e9
+PLAINTEXT = ffffffffffffffff8000000000000000
+
+COUNT = 65
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 10d3ed7a6fe15ab4d91acbc7d0767ab1
+PLAINTEXT = ffffffffffffffffc000000000000000
+
+COUNT = 66
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 21feecd45b2e675973ac33bf0c5424fc
+PLAINTEXT = ffffffffffffffffe000000000000000
+
+COUNT = 67
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1480cb3955ba62d09eea668f7c708817
+PLAINTEXT = fffffffffffffffff000000000000000
+
+COUNT = 68
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 66404033d6b72b609354d5496e7eb511
+PLAINTEXT = fffffffffffffffff800000000000000
+
+COUNT = 69
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1c317a220a7d700da2b1e075b00266e1
+PLAINTEXT = fffffffffffffffffc00000000000000
+
+COUNT = 70
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ab3b89542233f1271bf8fd0c0f403545
+PLAINTEXT = fffffffffffffffffe00000000000000
+
+COUNT = 71
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d93eae966fac46dca927d6b114fa3f9e
+PLAINTEXT = ffffffffffffffffff00000000000000
+
+COUNT = 72
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1bdec521316503d9d5ee65df3ea94ddf
+PLAINTEXT = ffffffffffffffffff80000000000000
+
+COUNT = 73
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = eef456431dea8b4acf83bdae3717f75f
+PLAINTEXT = ffffffffffffffffffc0000000000000
+
+COUNT = 74
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 06f2519a2fafaa596bfef5cfa15c21b9
+PLAINTEXT = ffffffffffffffffffe0000000000000
+
+COUNT = 75
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 251a7eac7e2fe809e4aa8d0d7012531a
+PLAINTEXT = fffffffffffffffffff0000000000000
+
+COUNT = 76
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3bffc16e4c49b268a20f8d96a60b4058
+PLAINTEXT = fffffffffffffffffff8000000000000
+
+COUNT = 77
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e886f9281999c5bb3b3e8862e2f7c988
+PLAINTEXT = fffffffffffffffffffc000000000000
+
+COUNT = 78
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 563bf90d61beef39f48dd625fcef1361
+PLAINTEXT = fffffffffffffffffffe000000000000
+
+COUNT = 79
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4d37c850644563c69fd0acd9a049325b
+PLAINTEXT = ffffffffffffffffffff000000000000
+
+COUNT = 80
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b87c921b91829ef3b13ca541ee1130a6
+PLAINTEXT = ffffffffffffffffffff800000000000
+
+COUNT = 81
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2e65eb6b6ea383e109accce8326b0393
+PLAINTEXT = ffffffffffffffffffffc00000000000
+
+COUNT = 82
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9ca547f7439edc3e255c0f4d49aa8990
+PLAINTEXT = ffffffffffffffffffffe00000000000
+
+COUNT = 83
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a5e652614c9300f37816b1f9fd0c87f9
+PLAINTEXT = fffffffffffffffffffff00000000000
+
+COUNT = 84
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 14954f0b4697776f44494fe458d814ed
+PLAINTEXT = fffffffffffffffffffff80000000000
+
+COUNT = 85
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7c8d9ab6c2761723fe42f8bb506cbcf7
+PLAINTEXT = fffffffffffffffffffffc0000000000
+
+COUNT = 86
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = db7e1932679fdd99742aab04aa0d5a80
+PLAINTEXT = fffffffffffffffffffffe0000000000
+
+COUNT = 87
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4c6a1c83e568cd10f27c2d73ded19c28
+PLAINTEXT = ffffffffffffffffffffff0000000000
+
+COUNT = 88
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 90ecbe6177e674c98de412413f7ac915
+PLAINTEXT = ffffffffffffffffffffff8000000000
+
+COUNT = 89
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 90684a2ac55fe1ec2b8ebd5622520b73
+PLAINTEXT = ffffffffffffffffffffffc000000000
+
+COUNT = 90
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7472f9a7988607ca79707795991035e6
+PLAINTEXT = ffffffffffffffffffffffe000000000
+
+COUNT = 91
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 56aff089878bf3352f8df172a3ae47d8
+PLAINTEXT = fffffffffffffffffffffff000000000
+
+COUNT = 92
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 65c0526cbe40161b8019a2a3171abd23
+PLAINTEXT = fffffffffffffffffffffff800000000
+
+COUNT = 93
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 377be0be33b4e3e310b4aabda173f84f
+PLAINTEXT = fffffffffffffffffffffffc00000000
+
+COUNT = 94
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9402e9aa6f69de6504da8d20c4fcaa2f
+PLAINTEXT = fffffffffffffffffffffffe00000000
+
+COUNT = 95
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 123c1f4af313ad8c2ce648b2e71fb6e1
+PLAINTEXT = ffffffffffffffffffffffff00000000
+
+COUNT = 96
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1ffc626d30203dcdb0019fb80f726cf4
+PLAINTEXT = ffffffffffffffffffffffff80000000
+
+COUNT = 97
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 76da1fbe3a50728c50fd2e621b5ad885
+PLAINTEXT = ffffffffffffffffffffffffc0000000
+
+COUNT = 98
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 082eb8be35f442fb52668e16a591d1d6
+PLAINTEXT = ffffffffffffffffffffffffe0000000
+
+COUNT = 99
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e656f9ecf5fe27ec3e4a73d00c282fb3
+PLAINTEXT = fffffffffffffffffffffffff0000000
+
+COUNT = 100
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2ca8209d63274cd9a29bb74bcd77683a
+PLAINTEXT = fffffffffffffffffffffffff8000000
+
+COUNT = 101
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 79bf5dce14bb7dd73a8e3611de7ce026
+PLAINTEXT = fffffffffffffffffffffffffc000000
+
+COUNT = 102
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3c849939a5d29399f344c4a0eca8a576
+PLAINTEXT = fffffffffffffffffffffffffe000000
+
+COUNT = 103
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ed3c0a94d59bece98835da7aa4f07ca2
+PLAINTEXT = ffffffffffffffffffffffffff000000
+
+COUNT = 104
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 63919ed4ce10196438b6ad09d99cd795
+PLAINTEXT = ffffffffffffffffffffffffff800000
+
+COUNT = 105
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7678f3a833f19fea95f3c6029e2bc610
+PLAINTEXT = ffffffffffffffffffffffffffc00000
+
+COUNT = 106
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3aa426831067d36b92be7c5f81c13c56
+PLAINTEXT = ffffffffffffffffffffffffffe00000
+
+COUNT = 107
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9272e2d2cdd11050998c845077a30ea0
+PLAINTEXT = fffffffffffffffffffffffffff00000
+
+COUNT = 108
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 088c4b53f5ec0ff814c19adae7f6246c
+PLAINTEXT = fffffffffffffffffffffffffff80000
+
+COUNT = 109
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4010a5e401fdf0a0354ddbcc0d012b17
+PLAINTEXT = fffffffffffffffffffffffffffc0000
+
+COUNT = 110
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a87a385736c0a6189bd6589bd8445a93
+PLAINTEXT = fffffffffffffffffffffffffffe0000
+
+COUNT = 111
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 545f2b83d9616dccf60fa9830e9cd287
+PLAINTEXT = ffffffffffffffffffffffffffff0000
+
+COUNT = 112
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4b706f7f92406352394037a6d4f4688d
+PLAINTEXT = ffffffffffffffffffffffffffff8000
+
+COUNT = 113
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b7972b3941c44b90afa7b264bfba7387
+PLAINTEXT = ffffffffffffffffffffffffffffc000
+
+COUNT = 114
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6f45732cf10881546f0fd23896d2bb60
+PLAINTEXT = ffffffffffffffffffffffffffffe000
+
+COUNT = 115
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2e3579ca15af27f64b3c955a5bfc30ba
+PLAINTEXT = fffffffffffffffffffffffffffff000
+
+COUNT = 116
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 34a2c5a91ae2aec99b7d1b5fa6780447
+PLAINTEXT = fffffffffffffffffffffffffffff800
+
+COUNT = 117
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a4d6616bd04f87335b0e53351227a9ee
+PLAINTEXT = fffffffffffffffffffffffffffffc00
+
+COUNT = 118
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7f692b03945867d16179a8cefc83ea3f
+PLAINTEXT = fffffffffffffffffffffffffffffe00
+
+COUNT = 119
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3bd141ee84a0e6414a26e7a4f281f8a2
+PLAINTEXT = ffffffffffffffffffffffffffffff00
+
+COUNT = 120
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d1788f572d98b2b16ec5d5f3922b99bc
+PLAINTEXT = ffffffffffffffffffffffffffffff80
+
+COUNT = 121
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0833ff6f61d98a57b288e8c3586b85a6
+PLAINTEXT = ffffffffffffffffffffffffffffffc0
+
+COUNT = 122
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8568261797de176bf0b43becc6285afb
+PLAINTEXT = ffffffffffffffffffffffffffffffe0
+
+COUNT = 123
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f9b0fda0c4a898f5b9e6f661c4ce4d07
+PLAINTEXT = fffffffffffffffffffffffffffffff0
+
+COUNT = 124
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8ade895913685c67c5269f8aae42983e
+PLAINTEXT = fffffffffffffffffffffffffffffff8
+
+COUNT = 125
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 39bde67d5c8ed8a8b1c37eb8fa9f5ac0
+PLAINTEXT = fffffffffffffffffffffffffffffffc
+
+COUNT = 126
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5c005e72c1418c44f569f2ea33ba54f3
+PLAINTEXT = fffffffffffffffffffffffffffffffe
+
+COUNT = 127
+KEY = 00000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3f5b8cc9ea855a0afa7347d23e8d664e
+PLAINTEXT = ffffffffffffffffffffffffffffffff
+
diff --git a/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarTxt256.rsp b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarTxt256.rsp
new file mode 100644
index 0000000..8dcce28
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/KAT_AES/CBCVarTxt256.rsp
@@ -0,0 +1,1547 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS VarTxt test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 256
+# Generated on Fri Apr 22 15:11:38 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = 80000000000000000000000000000000
+CIPHERTEXT = ddc6bf790c15760d8d9aeb6f9a75fd4e
+
+COUNT = 1
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = c0000000000000000000000000000000
+CIPHERTEXT = 0a6bdc6d4c1e6280301fd8e97ddbe601
+
+COUNT = 2
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = e0000000000000000000000000000000
+CIPHERTEXT = 9b80eefb7ebe2d2b16247aa0efc72f5d
+
+COUNT = 3
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = f0000000000000000000000000000000
+CIPHERTEXT = 7f2c5ece07a98d8bee13c51177395ff7
+
+COUNT = 4
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = f8000000000000000000000000000000
+CIPHERTEXT = 7818d800dcf6f4be1e0e94f403d1e4c2
+
+COUNT = 5
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fc000000000000000000000000000000
+CIPHERTEXT = e74cd1c92f0919c35a0324123d6177d3
+
+COUNT = 6
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fe000000000000000000000000000000
+CIPHERTEXT = 8092a4dcf2da7e77e93bdd371dfed82e
+
+COUNT = 7
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ff000000000000000000000000000000
+CIPHERTEXT = 49af6b372135acef10132e548f217b17
+
+COUNT = 8
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ff800000000000000000000000000000
+CIPHERTEXT = 8bcd40f94ebb63b9f7909676e667f1e7
+
+COUNT = 9
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffc00000000000000000000000000000
+CIPHERTEXT = fe1cffb83f45dcfb38b29be438dbd3ab
+
+COUNT = 10
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffe00000000000000000000000000000
+CIPHERTEXT = 0dc58a8d886623705aec15cb1e70dc0e
+
+COUNT = 11
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fff00000000000000000000000000000
+CIPHERTEXT = c218faa16056bd0774c3e8d79c35a5e4
+
+COUNT = 12
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fff80000000000000000000000000000
+CIPHERTEXT = 047bba83f7aa841731504e012208fc9e
+
+COUNT = 13
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffc0000000000000000000000000000
+CIPHERTEXT = dc8f0e4915fd81ba70a331310882f6da
+
+COUNT = 14
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffe0000000000000000000000000000
+CIPHERTEXT = 1569859ea6b7206c30bf4fd0cbfac33c
+
+COUNT = 15
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffff0000000000000000000000000000
+CIPHERTEXT = 300ade92f88f48fa2df730ec16ef44cd
+
+COUNT = 16
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffff8000000000000000000000000000
+CIPHERTEXT = 1fe6cc3c05965dc08eb0590c95ac71d0
+
+COUNT = 17
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffc000000000000000000000000000
+CIPHERTEXT = 59e858eaaa97fec38111275b6cf5abc0
+
+COUNT = 18
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffe000000000000000000000000000
+CIPHERTEXT = 2239455e7afe3b0616100288cc5a723b
+
+COUNT = 19
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffff000000000000000000000000000
+CIPHERTEXT = 3ee500c5c8d63479717163e55c5c4522
+
+COUNT = 20
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffff800000000000000000000000000
+CIPHERTEXT = d5e38bf15f16d90e3e214041d774daa8
+
+COUNT = 21
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffc00000000000000000000000000
+CIPHERTEXT = b1f4066e6f4f187dfe5f2ad1b17819d0
+
+COUNT = 22
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffe00000000000000000000000000
+CIPHERTEXT = 6ef4cc4de49b11065d7af2909854794a
+
+COUNT = 23
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffff00000000000000000000000000
+CIPHERTEXT = ac86bc606b6640c309e782f232bf367f
+
+COUNT = 24
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffff80000000000000000000000000
+CIPHERTEXT = 36aff0ef7bf3280772cf4cac80a0d2b2
+
+COUNT = 25
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffc0000000000000000000000000
+CIPHERTEXT = 1f8eedea0f62a1406d58cfc3ecea72cf
+
+COUNT = 26
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffe0000000000000000000000000
+CIPHERTEXT = abf4154a3375a1d3e6b1d454438f95a6
+
+COUNT = 27
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffff0000000000000000000000000
+CIPHERTEXT = 96f96e9d607f6615fc192061ee648b07
+
+COUNT = 28
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffff8000000000000000000000000
+CIPHERTEXT = cf37cdaaa0d2d536c71857634c792064
+
+COUNT = 29
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffc000000000000000000000000
+CIPHERTEXT = fbd6640c80245c2b805373f130703127
+
+COUNT = 30
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffe000000000000000000000000
+CIPHERTEXT = 8d6a8afe55a6e481badae0d146f436db
+
+COUNT = 31
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffff000000000000000000000000
+CIPHERTEXT = 6a4981f2915e3e68af6c22385dd06756
+
+COUNT = 32
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffff800000000000000000000000
+CIPHERTEXT = 42a1136e5f8d8d21d3101998642d573b
+
+COUNT = 33
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffc00000000000000000000000
+CIPHERTEXT = 9b471596dc69ae1586cee6158b0b0181
+
+COUNT = 34
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffe00000000000000000000000
+CIPHERTEXT = 753665c4af1eff33aa8b628bf8741cfd
+
+COUNT = 35
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffff00000000000000000000000
+CIPHERTEXT = 9a682acf40be01f5b2a4193c9a82404d
+
+COUNT = 36
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffff80000000000000000000000
+CIPHERTEXT = 54fafe26e4287f17d1935f87eb9ade01
+
+COUNT = 37
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffc0000000000000000000000
+CIPHERTEXT = 49d541b2e74cfe73e6a8e8225f7bd449
+
+COUNT = 38
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffe0000000000000000000000
+CIPHERTEXT = 11a45530f624ff6f76a1b3826626ff7b
+
+COUNT = 39
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffff0000000000000000000000
+CIPHERTEXT = f96b0c4a8bc6c86130289f60b43b8fba
+
+COUNT = 40
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffff8000000000000000000000
+CIPHERTEXT = 48c7d0e80834ebdc35b6735f76b46c8b
+
+COUNT = 41
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffc000000000000000000000
+CIPHERTEXT = 2463531ab54d66955e73edc4cb8eaa45
+
+COUNT = 42
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffe000000000000000000000
+CIPHERTEXT = ac9bd8e2530469134b9d5b065d4f565b
+
+COUNT = 43
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffff000000000000000000000
+CIPHERTEXT = 3f5f9106d0e52f973d4890e6f37e8a00
+
+COUNT = 44
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffff800000000000000000000
+CIPHERTEXT = 20ebc86f1304d272e2e207e59db639f0
+
+COUNT = 45
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffc00000000000000000000
+CIPHERTEXT = e67ae6426bf9526c972cff072b52252c
+
+COUNT = 46
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffe00000000000000000000
+CIPHERTEXT = 1a518dddaf9efa0d002cc58d107edfc8
+
+COUNT = 47
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffff00000000000000000000
+CIPHERTEXT = ead731af4d3a2fe3b34bed047942a49f
+
+COUNT = 48
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffff80000000000000000000
+CIPHERTEXT = b1d4efe40242f83e93b6c8d7efb5eae9
+
+COUNT = 49
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffc0000000000000000000
+CIPHERTEXT = cd2b1fec11fd906c5c7630099443610a
+
+COUNT = 50
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffe0000000000000000000
+CIPHERTEXT = a1853fe47fe29289d153161d06387d21
+
+COUNT = 51
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffff0000000000000000000
+CIPHERTEXT = 4632154179a555c17ea604d0889fab14
+
+COUNT = 52
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffff8000000000000000000
+CIPHERTEXT = dd27cac6401a022e8f38f9f93e774417
+
+COUNT = 53
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffc000000000000000000
+CIPHERTEXT = c090313eb98674f35f3123385fb95d4d
+
+COUNT = 54
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffe000000000000000000
+CIPHERTEXT = cc3526262b92f02edce548f716b9f45c
+
+COUNT = 55
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffff000000000000000000
+CIPHERTEXT = c0838d1a2b16a7c7f0dfcc433c399c33
+
+COUNT = 56
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffff800000000000000000
+CIPHERTEXT = 0d9ac756eb297695eed4d382eb126d26
+
+COUNT = 57
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffc00000000000000000
+CIPHERTEXT = 56ede9dda3f6f141bff1757fa689c3e1
+
+COUNT = 58
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffe00000000000000000
+CIPHERTEXT = 768f520efe0f23e61d3ec8ad9ce91774
+
+COUNT = 59
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffff00000000000000000
+CIPHERTEXT = b1144ddfa75755213390e7c596660490
+
+COUNT = 60
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffff80000000000000000
+CIPHERTEXT = 1d7c0c4040b355b9d107a99325e3b050
+
+COUNT = 61
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffc0000000000000000
+CIPHERTEXT = d8e2bb1ae8ee3dcf5bf7d6c38da82a1a
+
+COUNT = 62
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffe0000000000000000
+CIPHERTEXT = faf82d178af25a9886a47e7f789b98d7
+
+COUNT = 63
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffff0000000000000000
+CIPHERTEXT = 9b58dbfd77fe5aca9cfc190cd1b82d19
+
+COUNT = 64
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffff8000000000000000
+CIPHERTEXT = 77f392089042e478ac16c0c86a0b5db5
+
+COUNT = 65
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffc000000000000000
+CIPHERTEXT = 19f08e3420ee69b477ca1420281c4782
+
+COUNT = 66
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffe000000000000000
+CIPHERTEXT = a1b19beee4e117139f74b3c53fdcb875
+
+COUNT = 67
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffff000000000000000
+CIPHERTEXT = a37a5869b218a9f3a0868d19aea0ad6a
+
+COUNT = 68
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffff800000000000000
+CIPHERTEXT = bc3594e865bcd0261b13202731f33580
+
+COUNT = 69
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffc00000000000000
+CIPHERTEXT = 811441ce1d309eee7185e8c752c07557
+
+COUNT = 70
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffe00000000000000
+CIPHERTEXT = 959971ce4134190563518e700b9874d1
+
+COUNT = 71
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffff00000000000000
+CIPHERTEXT = 76b5614a042707c98e2132e2e805fe63
+
+COUNT = 72
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffff80000000000000
+CIPHERTEXT = 7d9fa6a57530d0f036fec31c230b0cc6
+
+COUNT = 73
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffc0000000000000
+CIPHERTEXT = 964153a83bf6989a4ba80daa91c3e081
+
+COUNT = 74
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffe0000000000000
+CIPHERTEXT = a013014d4ce8054cf2591d06f6f2f176
+
+COUNT = 75
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffff0000000000000
+CIPHERTEXT = d1c5f6399bf382502e385eee1474a869
+
+COUNT = 76
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffff8000000000000
+CIPHERTEXT = 0007e20b8298ec354f0f5fe7470f36bd
+
+COUNT = 77
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffc000000000000
+CIPHERTEXT = b95ba05b332da61ef63a2b31fcad9879
+
+COUNT = 78
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffe000000000000
+CIPHERTEXT = 4620a49bd967491561669ab25dce45f4
+
+COUNT = 79
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffff000000000000
+CIPHERTEXT = 12e71214ae8e04f0bb63d7425c6f14d5
+
+COUNT = 80
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffff800000000000
+CIPHERTEXT = 4cc42fc1407b008fe350907c092e80ac
+
+COUNT = 81
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffc00000000000
+CIPHERTEXT = 08b244ce7cbc8ee97fbba808cb146fda
+
+COUNT = 82
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffe00000000000
+CIPHERTEXT = 39b333e8694f21546ad1edd9d87ed95b
+
+COUNT = 83
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffff00000000000
+CIPHERTEXT = 3b271f8ab2e6e4a20ba8090f43ba78f3
+
+COUNT = 84
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffff80000000000
+CIPHERTEXT = 9ad983f3bf651cd0393f0a73cccdea50
+
+COUNT = 85
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffc0000000000
+CIPHERTEXT = 8f476cbff75c1f725ce18e4bbcd19b32
+
+COUNT = 86
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffe0000000000
+CIPHERTEXT = 905b6267f1d6ab5320835a133f096f2a
+
+COUNT = 87
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffff0000000000
+CIPHERTEXT = 145b60d6d0193c23f4221848a892d61a
+
+COUNT = 88
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffff8000000000
+CIPHERTEXT = 55cfb3fb6d75cad0445bbc8dafa25b0f
+
+COUNT = 89
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffc000000000
+CIPHERTEXT = 7b8e7098e357ef71237d46d8b075b0f5
+
+COUNT = 90
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffe000000000
+CIPHERTEXT = 2bf27229901eb40f2df9d8398d1505ae
+
+COUNT = 91
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffff000000000
+CIPHERTEXT = 83a63402a77f9ad5c1e931a931ecd706
+
+COUNT = 92
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffff800000000
+CIPHERTEXT = 6f8ba6521152d31f2bada1843e26b973
+
+COUNT = 93
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffc00000000
+CIPHERTEXT = e5c3b8e30fd2d8e6239b17b44bd23bbd
+
+COUNT = 94
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffe00000000
+CIPHERTEXT = 1ac1f7102c59933e8b2ddc3f14e94baa
+
+COUNT = 95
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffff00000000
+CIPHERTEXT = 21d9ba49f276b45f11af8fc71a088e3d
+
+COUNT = 96
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffff80000000
+CIPHERTEXT = 649f1cddc3792b4638635a392bc9bade
+
+COUNT = 97
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffc0000000
+CIPHERTEXT = e2775e4b59c1bc2e31a2078c11b5a08c
+
+COUNT = 98
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffe0000000
+CIPHERTEXT = 2be1fae5048a25582a679ca10905eb80
+
+COUNT = 99
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffff0000000
+CIPHERTEXT = da86f292c6f41ea34fb2068df75ecc29
+
+COUNT = 100
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffff8000000
+CIPHERTEXT = 220df19f85d69b1b562fa69a3c5beca5
+
+COUNT = 101
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffc000000
+CIPHERTEXT = 1f11d5d0355e0b556ccdb6c7f5083b4d
+
+COUNT = 102
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffe000000
+CIPHERTEXT = 62526b78be79cb384633c91f83b4151b
+
+COUNT = 103
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffff000000
+CIPHERTEXT = 90ddbcb950843592dd47bbef00fdc876
+
+COUNT = 104
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffff800000
+CIPHERTEXT = 2fd0e41c5b8402277354a7391d2618e2
+
+COUNT = 105
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffc00000
+CIPHERTEXT = 3cdf13e72dee4c581bafec70b85f9660
+
+COUNT = 106
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffe00000
+CIPHERTEXT = afa2ffc137577092e2b654fa199d2c43
+
+COUNT = 107
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffff00000
+CIPHERTEXT = 8d683ee63e60d208e343ce48dbc44cac
+
+COUNT = 108
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffff80000
+CIPHERTEXT = 705a4ef8ba2133729c20185c3d3a4763
+
+COUNT = 109
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffc0000
+CIPHERTEXT = 0861a861c3db4e94194211b77ed761b9
+
+COUNT = 110
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffe0000
+CIPHERTEXT = 4b00c27e8b26da7eab9d3a88dec8b031
+
+COUNT = 111
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffff0000
+CIPHERTEXT = 5f397bf03084820cc8810d52e5b666e9
+
+COUNT = 112
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffff8000
+CIPHERTEXT = 63fafabb72c07bfbd3ddc9b1203104b8
+
+COUNT = 113
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffc000
+CIPHERTEXT = 683e2140585b18452dd4ffbb93c95df9
+
+COUNT = 114
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffe000
+CIPHERTEXT = 286894e48e537f8763b56707d7d155c8
+
+COUNT = 115
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffff000
+CIPHERTEXT = a423deabc173dcf7e2c4c53e77d37cd1
+
+COUNT = 116
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffff800
+CIPHERTEXT = eb8168313e1cfdfdb5e986d5429cf172
+
+COUNT = 117
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffc00
+CIPHERTEXT = 27127daafc9accd2fb334ec3eba52323
+
+COUNT = 118
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffe00
+CIPHERTEXT = ee0715b96f72e3f7a22a5064fc592f4c
+
+COUNT = 119
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffff00
+CIPHERTEXT = 29ee526770f2a11dcfa989d1ce88830f
+
+COUNT = 120
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffff80
+CIPHERTEXT = 0493370e054b09871130fe49af730a5a
+
+COUNT = 121
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffffc0
+CIPHERTEXT = 9b7b940f6c509f9e44a4ee140448ee46
+
+COUNT = 122
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffffe0
+CIPHERTEXT = 2915be4a1ecfdcbe3e023811a12bb6c7
+
+COUNT = 123
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffff0
+CIPHERTEXT = 7240e524bc51d8c4d440b1be55d1062c
+
+COUNT = 124
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffff8
+CIPHERTEXT = da63039d38cb4612b2dc36ba26684b93
+
+COUNT = 125
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffffc
+CIPHERTEXT = 0f59cb5a4b522e2ac56c1a64f558ad9a
+
+COUNT = 126
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = fffffffffffffffffffffffffffffffe
+CIPHERTEXT = 7bfe9d876c6d63c1d035da8fe21c409d
+
+COUNT = 127
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+PLAINTEXT = ffffffffffffffffffffffffffffffff
+CIPHERTEXT = acdace8078a32b1a182bfa4987ca1347
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ddc6bf790c15760d8d9aeb6f9a75fd4e
+PLAINTEXT = 80000000000000000000000000000000
+
+COUNT = 1
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0a6bdc6d4c1e6280301fd8e97ddbe601
+PLAINTEXT = c0000000000000000000000000000000
+
+COUNT = 2
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9b80eefb7ebe2d2b16247aa0efc72f5d
+PLAINTEXT = e0000000000000000000000000000000
+
+COUNT = 3
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7f2c5ece07a98d8bee13c51177395ff7
+PLAINTEXT = f0000000000000000000000000000000
+
+COUNT = 4
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7818d800dcf6f4be1e0e94f403d1e4c2
+PLAINTEXT = f8000000000000000000000000000000
+
+COUNT = 5
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e74cd1c92f0919c35a0324123d6177d3
+PLAINTEXT = fc000000000000000000000000000000
+
+COUNT = 6
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8092a4dcf2da7e77e93bdd371dfed82e
+PLAINTEXT = fe000000000000000000000000000000
+
+COUNT = 7
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 49af6b372135acef10132e548f217b17
+PLAINTEXT = ff000000000000000000000000000000
+
+COUNT = 8
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8bcd40f94ebb63b9f7909676e667f1e7
+PLAINTEXT = ff800000000000000000000000000000
+
+COUNT = 9
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fe1cffb83f45dcfb38b29be438dbd3ab
+PLAINTEXT = ffc00000000000000000000000000000
+
+COUNT = 10
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0dc58a8d886623705aec15cb1e70dc0e
+PLAINTEXT = ffe00000000000000000000000000000
+
+COUNT = 11
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c218faa16056bd0774c3e8d79c35a5e4
+PLAINTEXT = fff00000000000000000000000000000
+
+COUNT = 12
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 047bba83f7aa841731504e012208fc9e
+PLAINTEXT = fff80000000000000000000000000000
+
+COUNT = 13
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dc8f0e4915fd81ba70a331310882f6da
+PLAINTEXT = fffc0000000000000000000000000000
+
+COUNT = 14
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1569859ea6b7206c30bf4fd0cbfac33c
+PLAINTEXT = fffe0000000000000000000000000000
+
+COUNT = 15
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 300ade92f88f48fa2df730ec16ef44cd
+PLAINTEXT = ffff0000000000000000000000000000
+
+COUNT = 16
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1fe6cc3c05965dc08eb0590c95ac71d0
+PLAINTEXT = ffff8000000000000000000000000000
+
+COUNT = 17
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 59e858eaaa97fec38111275b6cf5abc0
+PLAINTEXT = ffffc000000000000000000000000000
+
+COUNT = 18
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2239455e7afe3b0616100288cc5a723b
+PLAINTEXT = ffffe000000000000000000000000000
+
+COUNT = 19
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3ee500c5c8d63479717163e55c5c4522
+PLAINTEXT = fffff000000000000000000000000000
+
+COUNT = 20
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d5e38bf15f16d90e3e214041d774daa8
+PLAINTEXT = fffff800000000000000000000000000
+
+COUNT = 21
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b1f4066e6f4f187dfe5f2ad1b17819d0
+PLAINTEXT = fffffc00000000000000000000000000
+
+COUNT = 22
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6ef4cc4de49b11065d7af2909854794a
+PLAINTEXT = fffffe00000000000000000000000000
+
+COUNT = 23
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ac86bc606b6640c309e782f232bf367f
+PLAINTEXT = ffffff00000000000000000000000000
+
+COUNT = 24
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 36aff0ef7bf3280772cf4cac80a0d2b2
+PLAINTEXT = ffffff80000000000000000000000000
+
+COUNT = 25
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1f8eedea0f62a1406d58cfc3ecea72cf
+PLAINTEXT = ffffffc0000000000000000000000000
+
+COUNT = 26
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = abf4154a3375a1d3e6b1d454438f95a6
+PLAINTEXT = ffffffe0000000000000000000000000
+
+COUNT = 27
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 96f96e9d607f6615fc192061ee648b07
+PLAINTEXT = fffffff0000000000000000000000000
+
+COUNT = 28
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cf37cdaaa0d2d536c71857634c792064
+PLAINTEXT = fffffff8000000000000000000000000
+
+COUNT = 29
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = fbd6640c80245c2b805373f130703127
+PLAINTEXT = fffffffc000000000000000000000000
+
+COUNT = 30
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8d6a8afe55a6e481badae0d146f436db
+PLAINTEXT = fffffffe000000000000000000000000
+
+COUNT = 31
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6a4981f2915e3e68af6c22385dd06756
+PLAINTEXT = ffffffff000000000000000000000000
+
+COUNT = 32
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 42a1136e5f8d8d21d3101998642d573b
+PLAINTEXT = ffffffff800000000000000000000000
+
+COUNT = 33
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9b471596dc69ae1586cee6158b0b0181
+PLAINTEXT = ffffffffc00000000000000000000000
+
+COUNT = 34
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 753665c4af1eff33aa8b628bf8741cfd
+PLAINTEXT = ffffffffe00000000000000000000000
+
+COUNT = 35
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9a682acf40be01f5b2a4193c9a82404d
+PLAINTEXT = fffffffff00000000000000000000000
+
+COUNT = 36
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 54fafe26e4287f17d1935f87eb9ade01
+PLAINTEXT = fffffffff80000000000000000000000
+
+COUNT = 37
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 49d541b2e74cfe73e6a8e8225f7bd449
+PLAINTEXT = fffffffffc0000000000000000000000
+
+COUNT = 38
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 11a45530f624ff6f76a1b3826626ff7b
+PLAINTEXT = fffffffffe0000000000000000000000
+
+COUNT = 39
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = f96b0c4a8bc6c86130289f60b43b8fba
+PLAINTEXT = ffffffffff0000000000000000000000
+
+COUNT = 40
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 48c7d0e80834ebdc35b6735f76b46c8b
+PLAINTEXT = ffffffffff8000000000000000000000
+
+COUNT = 41
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2463531ab54d66955e73edc4cb8eaa45
+PLAINTEXT = ffffffffffc000000000000000000000
+
+COUNT = 42
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ac9bd8e2530469134b9d5b065d4f565b
+PLAINTEXT = ffffffffffe000000000000000000000
+
+COUNT = 43
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3f5f9106d0e52f973d4890e6f37e8a00
+PLAINTEXT = fffffffffff000000000000000000000
+
+COUNT = 44
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 20ebc86f1304d272e2e207e59db639f0
+PLAINTEXT = fffffffffff800000000000000000000
+
+COUNT = 45
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e67ae6426bf9526c972cff072b52252c
+PLAINTEXT = fffffffffffc00000000000000000000
+
+COUNT = 46
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1a518dddaf9efa0d002cc58d107edfc8
+PLAINTEXT = fffffffffffe00000000000000000000
+
+COUNT = 47
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ead731af4d3a2fe3b34bed047942a49f
+PLAINTEXT = ffffffffffff00000000000000000000
+
+COUNT = 48
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b1d4efe40242f83e93b6c8d7efb5eae9
+PLAINTEXT = ffffffffffff80000000000000000000
+
+COUNT = 49
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cd2b1fec11fd906c5c7630099443610a
+PLAINTEXT = ffffffffffffc0000000000000000000
+
+COUNT = 50
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a1853fe47fe29289d153161d06387d21
+PLAINTEXT = ffffffffffffe0000000000000000000
+
+COUNT = 51
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4632154179a555c17ea604d0889fab14
+PLAINTEXT = fffffffffffff0000000000000000000
+
+COUNT = 52
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = dd27cac6401a022e8f38f9f93e774417
+PLAINTEXT = fffffffffffff8000000000000000000
+
+COUNT = 53
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c090313eb98674f35f3123385fb95d4d
+PLAINTEXT = fffffffffffffc000000000000000000
+
+COUNT = 54
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = cc3526262b92f02edce548f716b9f45c
+PLAINTEXT = fffffffffffffe000000000000000000
+
+COUNT = 55
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = c0838d1a2b16a7c7f0dfcc433c399c33
+PLAINTEXT = ffffffffffffff000000000000000000
+
+COUNT = 56
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0d9ac756eb297695eed4d382eb126d26
+PLAINTEXT = ffffffffffffff800000000000000000
+
+COUNT = 57
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 56ede9dda3f6f141bff1757fa689c3e1
+PLAINTEXT = ffffffffffffffc00000000000000000
+
+COUNT = 58
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 768f520efe0f23e61d3ec8ad9ce91774
+PLAINTEXT = ffffffffffffffe00000000000000000
+
+COUNT = 59
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b1144ddfa75755213390e7c596660490
+PLAINTEXT = fffffffffffffff00000000000000000
+
+COUNT = 60
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1d7c0c4040b355b9d107a99325e3b050
+PLAINTEXT = fffffffffffffff80000000000000000
+
+COUNT = 61
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d8e2bb1ae8ee3dcf5bf7d6c38da82a1a
+PLAINTEXT = fffffffffffffffc0000000000000000
+
+COUNT = 62
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = faf82d178af25a9886a47e7f789b98d7
+PLAINTEXT = fffffffffffffffe0000000000000000
+
+COUNT = 63
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9b58dbfd77fe5aca9cfc190cd1b82d19
+PLAINTEXT = ffffffffffffffff0000000000000000
+
+COUNT = 64
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 77f392089042e478ac16c0c86a0b5db5
+PLAINTEXT = ffffffffffffffff8000000000000000
+
+COUNT = 65
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 19f08e3420ee69b477ca1420281c4782
+PLAINTEXT = ffffffffffffffffc000000000000000
+
+COUNT = 66
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a1b19beee4e117139f74b3c53fdcb875
+PLAINTEXT = ffffffffffffffffe000000000000000
+
+COUNT = 67
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a37a5869b218a9f3a0868d19aea0ad6a
+PLAINTEXT = fffffffffffffffff000000000000000
+
+COUNT = 68
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = bc3594e865bcd0261b13202731f33580
+PLAINTEXT = fffffffffffffffff800000000000000
+
+COUNT = 69
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 811441ce1d309eee7185e8c752c07557
+PLAINTEXT = fffffffffffffffffc00000000000000
+
+COUNT = 70
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 959971ce4134190563518e700b9874d1
+PLAINTEXT = fffffffffffffffffe00000000000000
+
+COUNT = 71
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 76b5614a042707c98e2132e2e805fe63
+PLAINTEXT = ffffffffffffffffff00000000000000
+
+COUNT = 72
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7d9fa6a57530d0f036fec31c230b0cc6
+PLAINTEXT = ffffffffffffffffff80000000000000
+
+COUNT = 73
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 964153a83bf6989a4ba80daa91c3e081
+PLAINTEXT = ffffffffffffffffffc0000000000000
+
+COUNT = 74
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a013014d4ce8054cf2591d06f6f2f176
+PLAINTEXT = ffffffffffffffffffe0000000000000
+
+COUNT = 75
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = d1c5f6399bf382502e385eee1474a869
+PLAINTEXT = fffffffffffffffffff0000000000000
+
+COUNT = 76
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0007e20b8298ec354f0f5fe7470f36bd
+PLAINTEXT = fffffffffffffffffff8000000000000
+
+COUNT = 77
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = b95ba05b332da61ef63a2b31fcad9879
+PLAINTEXT = fffffffffffffffffffc000000000000
+
+COUNT = 78
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4620a49bd967491561669ab25dce45f4
+PLAINTEXT = fffffffffffffffffffe000000000000
+
+COUNT = 79
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 12e71214ae8e04f0bb63d7425c6f14d5
+PLAINTEXT = ffffffffffffffffffff000000000000
+
+COUNT = 80
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4cc42fc1407b008fe350907c092e80ac
+PLAINTEXT = ffffffffffffffffffff800000000000
+
+COUNT = 81
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 08b244ce7cbc8ee97fbba808cb146fda
+PLAINTEXT = ffffffffffffffffffffc00000000000
+
+COUNT = 82
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 39b333e8694f21546ad1edd9d87ed95b
+PLAINTEXT = ffffffffffffffffffffe00000000000
+
+COUNT = 83
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3b271f8ab2e6e4a20ba8090f43ba78f3
+PLAINTEXT = fffffffffffffffffffff00000000000
+
+COUNT = 84
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9ad983f3bf651cd0393f0a73cccdea50
+PLAINTEXT = fffffffffffffffffffff80000000000
+
+COUNT = 85
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8f476cbff75c1f725ce18e4bbcd19b32
+PLAINTEXT = fffffffffffffffffffffc0000000000
+
+COUNT = 86
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 905b6267f1d6ab5320835a133f096f2a
+PLAINTEXT = fffffffffffffffffffffe0000000000
+
+COUNT = 87
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 145b60d6d0193c23f4221848a892d61a
+PLAINTEXT = ffffffffffffffffffffff0000000000
+
+COUNT = 88
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 55cfb3fb6d75cad0445bbc8dafa25b0f
+PLAINTEXT = ffffffffffffffffffffff8000000000
+
+COUNT = 89
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7b8e7098e357ef71237d46d8b075b0f5
+PLAINTEXT = ffffffffffffffffffffffc000000000
+
+COUNT = 90
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2bf27229901eb40f2df9d8398d1505ae
+PLAINTEXT = ffffffffffffffffffffffe000000000
+
+COUNT = 91
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 83a63402a77f9ad5c1e931a931ecd706
+PLAINTEXT = fffffffffffffffffffffff000000000
+
+COUNT = 92
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 6f8ba6521152d31f2bada1843e26b973
+PLAINTEXT = fffffffffffffffffffffff800000000
+
+COUNT = 93
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e5c3b8e30fd2d8e6239b17b44bd23bbd
+PLAINTEXT = fffffffffffffffffffffffc00000000
+
+COUNT = 94
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1ac1f7102c59933e8b2ddc3f14e94baa
+PLAINTEXT = fffffffffffffffffffffffe00000000
+
+COUNT = 95
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 21d9ba49f276b45f11af8fc71a088e3d
+PLAINTEXT = ffffffffffffffffffffffff00000000
+
+COUNT = 96
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 649f1cddc3792b4638635a392bc9bade
+PLAINTEXT = ffffffffffffffffffffffff80000000
+
+COUNT = 97
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = e2775e4b59c1bc2e31a2078c11b5a08c
+PLAINTEXT = ffffffffffffffffffffffffc0000000
+
+COUNT = 98
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2be1fae5048a25582a679ca10905eb80
+PLAINTEXT = ffffffffffffffffffffffffe0000000
+
+COUNT = 99
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = da86f292c6f41ea34fb2068df75ecc29
+PLAINTEXT = fffffffffffffffffffffffff0000000
+
+COUNT = 100
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 220df19f85d69b1b562fa69a3c5beca5
+PLAINTEXT = fffffffffffffffffffffffff8000000
+
+COUNT = 101
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 1f11d5d0355e0b556ccdb6c7f5083b4d
+PLAINTEXT = fffffffffffffffffffffffffc000000
+
+COUNT = 102
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 62526b78be79cb384633c91f83b4151b
+PLAINTEXT = fffffffffffffffffffffffffe000000
+
+COUNT = 103
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 90ddbcb950843592dd47bbef00fdc876
+PLAINTEXT = ffffffffffffffffffffffffff000000
+
+COUNT = 104
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2fd0e41c5b8402277354a7391d2618e2
+PLAINTEXT = ffffffffffffffffffffffffff800000
+
+COUNT = 105
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 3cdf13e72dee4c581bafec70b85f9660
+PLAINTEXT = ffffffffffffffffffffffffffc00000
+
+COUNT = 106
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = afa2ffc137577092e2b654fa199d2c43
+PLAINTEXT = ffffffffffffffffffffffffffe00000
+
+COUNT = 107
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 8d683ee63e60d208e343ce48dbc44cac
+PLAINTEXT = fffffffffffffffffffffffffff00000
+
+COUNT = 108
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 705a4ef8ba2133729c20185c3d3a4763
+PLAINTEXT = fffffffffffffffffffffffffff80000
+
+COUNT = 109
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0861a861c3db4e94194211b77ed761b9
+PLAINTEXT = fffffffffffffffffffffffffffc0000
+
+COUNT = 110
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 4b00c27e8b26da7eab9d3a88dec8b031
+PLAINTEXT = fffffffffffffffffffffffffffe0000
+
+COUNT = 111
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 5f397bf03084820cc8810d52e5b666e9
+PLAINTEXT = ffffffffffffffffffffffffffff0000
+
+COUNT = 112
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 63fafabb72c07bfbd3ddc9b1203104b8
+PLAINTEXT = ffffffffffffffffffffffffffff8000
+
+COUNT = 113
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 683e2140585b18452dd4ffbb93c95df9
+PLAINTEXT = ffffffffffffffffffffffffffffc000
+
+COUNT = 114
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 286894e48e537f8763b56707d7d155c8
+PLAINTEXT = ffffffffffffffffffffffffffffe000
+
+COUNT = 115
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = a423deabc173dcf7e2c4c53e77d37cd1
+PLAINTEXT = fffffffffffffffffffffffffffff000
+
+COUNT = 116
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = eb8168313e1cfdfdb5e986d5429cf172
+PLAINTEXT = fffffffffffffffffffffffffffff800
+
+COUNT = 117
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 27127daafc9accd2fb334ec3eba52323
+PLAINTEXT = fffffffffffffffffffffffffffffc00
+
+COUNT = 118
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = ee0715b96f72e3f7a22a5064fc592f4c
+PLAINTEXT = fffffffffffffffffffffffffffffe00
+
+COUNT = 119
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 29ee526770f2a11dcfa989d1ce88830f
+PLAINTEXT = ffffffffffffffffffffffffffffff00
+
+COUNT = 120
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0493370e054b09871130fe49af730a5a
+PLAINTEXT = ffffffffffffffffffffffffffffff80
+
+COUNT = 121
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 9b7b940f6c509f9e44a4ee140448ee46
+PLAINTEXT = ffffffffffffffffffffffffffffffc0
+
+COUNT = 122
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 2915be4a1ecfdcbe3e023811a12bb6c7
+PLAINTEXT = ffffffffffffffffffffffffffffffe0
+
+COUNT = 123
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7240e524bc51d8c4d440b1be55d1062c
+PLAINTEXT = fffffffffffffffffffffffffffffff0
+
+COUNT = 124
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = da63039d38cb4612b2dc36ba26684b93
+PLAINTEXT = fffffffffffffffffffffffffffffff8
+
+COUNT = 125
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 0f59cb5a4b522e2ac56c1a64f558ad9a
+PLAINTEXT = fffffffffffffffffffffffffffffffc
+
+COUNT = 126
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = 7bfe9d876c6d63c1d035da8fe21c409d
+PLAINTEXT = fffffffffffffffffffffffffffffffe
+
+COUNT = 127
+KEY = 0000000000000000000000000000000000000000000000000000000000000000
+IV = 00000000000000000000000000000000
+CIPHERTEXT = acdace8078a32b1a182bfa4987ca1347
+PLAINTEXT = ffffffffffffffffffffffffffffffff
+
diff --git a/hwcryptokey-test/vectors/CAVP/aesmmt/CBCMMT128.rsp b/hwcryptokey-test/vectors/CAVP/aesmmt/CBCMMT128.rsp
new file mode 100644
index 0000000..5e293e1
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/aesmmt/CBCMMT128.rsp
@@ -0,0 +1,131 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS MMT test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 128
+# Generated on Fri Apr 22 15:11:33 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 1f8e4973953f3fb0bd6b16662e9a3c17
+IV = 2fe2b333ceda8f98f4a99b40d2cd34a8
+PLAINTEXT = 45cf12964fc824ab76616ae2f4bf0822
+CIPHERTEXT = 0f61c4d44c5147c03c195ad7e2cc12b2
+
+COUNT = 1
+KEY = 0700d603a1c514e46b6191ba430a3a0c
+IV = aad1583cd91365e3bb2f0c3430d065bb
+PLAINTEXT = 068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91
+CIPHERTEXT = c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00
+
+COUNT = 2
+KEY = 3348aa51e9a45c2dbe33ccc47f96e8de
+IV = 19153c673160df2b1d38c28060e59b96
+PLAINTEXT = 9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599
+CIPHERTEXT = d5aed6c9622ec451a15db12819952b6752501cf05cdbf8cda34a457726ded97818e1f127a28d72db5652749f0c6afee5
+
+COUNT = 3
+KEY = b7f3c9576e12dd0db63e8f8fac2b9a39
+IV = c80f095d8bb1a060699f7c19974a1aa0
+PLAINTEXT = 9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e
+CIPHERTEXT = 19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467
+
+COUNT = 4
+KEY = b6f9afbfe5a1562bba1368fc72ac9d9c
+IV = 3f9d5ebe250ee7ce384b0d00ee849322
+PLAINTEXT = db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1
+CIPHERTEXT = 10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9
+
+COUNT = 5
+KEY = bbe7b7ba07124ff1ae7c3416fe8b465e
+IV = 7f65b5ee3630bed6b84202d97fb97a1e
+PLAINTEXT = 2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd9110914011b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5f78f31ff7caf187
+CIPHERTEXT = 3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff5661a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60a70e0074fc11efe
+
+COUNT = 6
+KEY = 89a553730433f7e6d67d16d373bd5360
+IV = f724558db3433a523f4e51a5bea70497
+PLAINTEXT = 807bc4ea684eedcfdcca30180680b0f1ae2814f35f36d053c5aea6595a386c1442770f4d7297d8b91825ee7237241da8925dd594ccf676aecd46ca2068e8d37a3a0ec8a7d5185a201e663b5ff36ae197110188a23503763b8218826d23ced74b31e9f6e2d7fbfa6cb43420c7807a8625
+CIPHERTEXT = 406af1429a478c3d07e555c5287a60500d37fc39b68e5bbb9bafd6ddb223828561d6171a308d5b1a4551e8a5e7d572918d25c968d3871848d2f16635caa9847f38590b1df58ab5efb985f2c66cfaf86f61b3f9c0afad6c963c49cee9b8bc81a2ddb06c967f325515a4849eec37ce721a
+
+COUNT = 7
+KEY = c491ca31f91708458e29a925ec558d78
+IV = 9ef934946e5cd0ae97bd58532cb49381
+PLAINTEXT = cb6a787e0dec56f9a165957f81af336ca6b40785d9e94093c6190e5152649f882e874d79ac5e167bd2a74ce5ae088d2ee854f6539e0a94796b1e1bd4c9fcdbc79acbef4d01eeb89776d18af71ae2a4fc47dd66df6c4dbe1d1850e466549a47b636bcc7c2b3a62495b56bb67b6d455f1eebd9bfefecbca6c7f335cfce9b45cb9d
+CIPHERTEXT = 7b2931f5855f717145e00f152a9f4794359b1ffcb3e55f594e33098b51c23a6c74a06c1d94fded7fd2ae42c7db7acaef5844cb33aeddc6852585ed0020a6699d2cb53809cefd169148ce42292afab063443978306c582c18b9ce0da3d084ce4d3c482cfd8fcf1a85084e89fb88b40a084d5e972466d07666126fb761f84078f2
+
+COUNT = 8
+KEY = f6e87d71b0104d6eb06a68dc6a71f498
+IV = 1c245f26195b76ebebc2edcac412a2f8
+PLAINTEXT = f82bef3c73a6f7f80db285726d691db6bf55eec25a859d3ba0e0445f26b9bb3b16a3161ed1866e4dd8f2e5f8ecb4e46d74a7a78c20cdfc7bcc9e479ba7a0caba9438238ad0c01651d5d98de37f03ddce6e6b4bd4ab03cf9e8ed818aedfa1cf963b932067b97d776dce1087196e7e913f7448e38244509f0caf36bd8217e15336d35c149fd4e41707893fdb84014f8729
+CIPHERTEXT = b09512f3eff9ed0d85890983a73dadbb7c3678d52581be64a8a8fc586f490f2521297a478a0598040ebd0f5509fafb0969f9d9e600eaef33b1b93eed99687b167f89a5065aac439ce46f3b8d22d30865e64e45ef8cd30b6984353a844a11c8cd60dba0e8866b3ee30d24b3fa8a643b328353e06010fa8273c8fd54ef0a2b6930e5520aae5cd5902f9b86a33592ca4365
+
+COUNT = 9
+KEY = 2c14413751c31e2730570ba3361c786b
+IV = 1dbbeb2f19abb448af849796244a19d7
+PLAINTEXT = 40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd206225709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f
+CIPHERTEXT = 6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376d28b92548c68e06e6d994e2c1501ed297014e702cdefee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 6a7082cf8cda13eff48c8158dda206ae
+IV = bd4172934078c2011cb1f31cffaf486e
+CIPHERTEXT = f8eb31b31e374e960030cd1cadb0ef0c
+PLAINTEXT = 940bc76d61e2c49dddd5df7f37fcf105
+
+COUNT = 1
+KEY = 625eefa18a4756454e218d8bfed56e36
+IV = 73d9d0e27c2ec568fbc11f6a0998d7c8
+CIPHERTEXT = 5d6fed86f0c4fe59a078d6361a142812514b295dc62ff5d608a42ea37614e6a1
+PLAINTEXT = 360dc1896ce601dfb2a949250067aad96737847a4580ede2654a329b842fe81e
+
+COUNT = 2
+KEY = fd6e0b954ae2e3b723d6c9fcae6ab09b
+IV = f08b65c9f4dd950039941da2e8058c4e
+CIPHERTEXT = e29e3114c8000eb484395b256b1b3267894f290d3999819ff35da03e6463c186c4d7ebb964941f1986a2d69572fcaba8
+PLAINTEXT = a206385945b21f812a9475f47fddbb7fbdda958a8d14c0dbcdaec36e8b28f1f6ececa1ceae4ce17721d162c1d42a66c1
+
+COUNT = 3
+KEY = 7b1ab9144b0239315cd5eec6c75663bd
+IV = 0b1e74f45c17ff304d99c059ce5cde09
+CIPHERTEXT = d3f89b71e033070f9d7516a6cb4ea5ef51d6fb63d4f0fea089d0a60e47bbb3c2e10e9ba3b282c7cb79aefe3068ce228377c21a58fe5a0f8883d0dbd3d096beca
+PLAINTEXT = b968aeb199ad6b3c8e01f26c2edad444538c78bfa36ed68ca76123b8cdce615a01f6112bb80bfc3f17490578fb1f909a52e162637b062db04efee291a1f1af60
+
+COUNT = 4
+KEY = 36466b6bd25ea3857ea42f0cac1919b1
+IV = 7186fb6bdfa98a16189544b228f3bcd3
+CIPHERTEXT = 9ed957bd9bc52bba76f68cfbcde52157a8ca4f71ac050a3d92bdebbfd7c78316b4c9f0ba509fad0235fdafe90056ad115dfdbf08338b2acb1c807a88182dd2a882d1810d4302d598454e34ef2b23687d
+PLAINTEXT = 999983467c47bb1d66d7327ab5c58f61ddb09b93bd2460cb78cbc12b5fa1ea0c5f759ccc5e478697687012ff4673f6e61eecaeda0ccad2d674d3098c7d17f887b62b56f56b03b4d055bf3a4460e83efa
+
+COUNT = 5
+KEY = 89373ee6e28397640d5082eed4123239
+IV = 1a74d7c859672c804b82472f7e6d3c6b
+CIPHERTEXT = 1bcba44ddff503db7c8c2ec4c4eea0e827957740cce125c1e11769842fa97e25f1b89269e6d77923a512a358312f4ba1cd33f2d111280cd83e1ef9e7cf7036d55048d5c273652afa611cc81b4e9dac7b5078b7c4716062e1032ead1e3329588a
+PLAINTEXT = 45efd00daa4cdc8273ef785cae9e944a7664a2391e1e2c449f475acec0124bbc22944331678617408a1702917971f4654310ffb9229bec6173715ae512d37f93aaa6abf009f7e30d65669d1db0366b5bce4c7b00f871014f5753744a1878dc57
+
+COUNT = 6
+KEY = bab0cceddc0abd63e3f82e9fbff7b8aa
+IV = 68b9140f300490c5c942f66e777eb806
+CIPHERTEXT = c65b94b1f291fa9f0600f22c3c0432c895ad5d177bcccc9ea44e8ec339c9adf43855b326179d6d81aa36ef59462fd86127e9d81b0f286f93306bf74d4c79e47c1b3d4b74edd3a16290e3c63b742e41f20d66ceee794316bb63d3bd002712a1b136ba6185bd5c1dab81b07db90d2af5e5
+PLAINTEXT = c5585ff215bbb73ba5393440852fb199436de0d15e55c631f877670aa3eda9f672eb1f876f09544e63558436b8928000db2f02a5ad90f95b05ac4cf49e198e617e7678480fdf0efacc6aae691271e6cdd3541ebf719a1ccaedb24e2f80f92455dd5910cb5086b0960a3942ec182dcbd7
+
+COUNT = 7
+KEY = 9c702898efa44557b29ed283f5bc0293
+IV = cec6e1b82e8b2a591a9fa5ff1cf5cc51
+CIPHERTEXT = ba9f646755dacc22911f51d7de2f7e7cb0bc0b75257ea44fe883edb055c7c28ede04c3a0adcb10128ad4517d0093fa16bb0bcd2635e7a0ba92c7609bc8d8568002a7a983473724d256513aa7d51b477aabec1975ab5faf2872a6407e922180eff02f1ef86a4591c8bd3d143da6f0ef0e4806f94ace0d5b0151c99640fccbc843
+PLAINTEXT = 1d1f8d81bdc3e2c7cb057f408e6450000c5aaed3260ff1e87fbb6f324df6887ffd8f78d7e2a04c9ed9deda9d64482d2b002f4a2b78d8b4f691875c8295d4a64b22257ceaf713ed2f4b92530d7ad7151d629acda882b4829577a43990b0948c1149c22fe4273656d1b08833930e8b06709a94579a78fc220f7057bbc1fa9f6563
+
+COUNT = 8
+KEY = 5674636dbdb38f705f0b08c372ef4785
+IV = 3f20ce0509b57420d53b6be4d0b7f0a9
+CIPHERTEXT = 198351f453103face6655666fe90bdbd9630e3733b2d66c013a634e91f2bf015bd2d975d71b26322e44defa32d4e9dce50363557046ece08ba38f258dae5fd3e5049c647476c81e73482e40c171d89f9fea29452caf995733589b0061464fbd5dabe27dc5ea463a3deeb7dcb43664ae6a65c498c143883ab8e83b51e5410b181647602443dc3cfffe86f0205398fa83c
+PLAINTEXT = 6d40fd2f908f48ce19241b6b278b1b1676dffd4a97ce9f8a1574c33bc59237deb536bee376fd6c381e6987700e39283aa111cf1a59f26fae6fb6700bf012646a2ab80239bf5e1632329043aa87d7911978b36523a2bc0bed9a9737ccf7a00baa2f3822b4e9e742e168e7069290705fed2eb63aa044b78f97dd33a8d6b24741ec1fd8c8db79d93b884e762dba0f406961
+
+COUNT = 9
+KEY = 97a1025529b9925e25bbe78770ca2f99
+IV = d4b4eab92aa9637e87d366384ed6915c
+CIPHERTEXT = 22cdc3306fcd4d31ccd32720cbb61bad28d855670657c48c7b88c31f4fa1f93c01b57da90be63ead67d6a325525e6ed45083e6fb70a53529d1fa0f55653b942af59d78a2660361d63a7290155ac5c43312a25b235dacbbc863faf00940c99624076dfa44068e7c554c9038176953e571751dfc0954d41d113771b06466b1c8d13e0d4cb675ed58d1a619e1540970983781dc11d2dd8525ab5745958d615defda
+PLAINTEXT = e8b89150d8438bf5b17449d6ed26bd72127e10e4aa57cad85283e8359e089208e84921649f5b60ea21f7867cbc9620560c4c6238db021216db453c9943f1f1a60546173daef2557c3cdd855031b353d4bf176f28439e48785c37d38f270aa4a6faad2baabcb0c0b2d1dd5322937498ce803ba1148440a52e227ddba4872fe4d81d2d76a939d24755adb8a7b8452ceed2d179e1a5848f316f5c016300a390bfa7
+
diff --git a/hwcryptokey-test/vectors/CAVP/aesmmt/CBCMMT256.rsp b/hwcryptokey-test/vectors/CAVP/aesmmt/CBCMMT256.rsp
new file mode 100644
index 0000000..56fae61
--- /dev/null
+++ b/hwcryptokey-test/vectors/CAVP/aesmmt/CBCMMT256.rsp
@@ -0,0 +1,131 @@
+# CAVS 11.1
+# Config info for aes_values
+# AESVS MMT test data for CBC
+# State : Encrypt and Decrypt
+# Key Length : 256
+# Generated on Fri Apr 22 15:11:38 2011
+
+[ENCRYPT]
+
+COUNT = 0
+KEY = 6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907
+IV = 851e8764776e6796aab722dbb644ace8
+PLAINTEXT = 6282b8c05c5c1530b97d4816ca434762
+CIPHERTEXT = 6acc04142e100a65f51b97adf5172c41
+
+COUNT = 1
+KEY = dce26c6b4cfb286510da4eecd2cffe6cdf430f33db9b5f77b460679bd49d13ae
+IV = fdeaa134c8d7379d457175fd1a57d3fc
+PLAINTEXT = 50e9eee1ac528009e8cbcd356975881f957254b13f91d7c6662d10312052eb00
+CIPHERTEXT = 2fa0df722a9fd3b64cb18fb2b3db55ff2267422757289413f8f657507412a64c
+
+COUNT = 2
+KEY = fe8901fecd3ccd2ec5fdc7c7a0b50519c245b42d611a5ef9e90268d59f3edf33
+IV = bd416cb3b9892228d8f1df575692e4d0
+PLAINTEXT = 8d3aa196ec3d7c9b5bb122e7fe77fb1295a6da75abe5d3a510194d3a8a4157d5c89d40619716619859da3ec9b247ced9
+CIPHERTEXT = 608e82c7ab04007adb22e389a44797fed7de090c8c03ca8a2c5acd9e84df37fbc58ce8edb293e98f02b640d6d1d72464
+
+COUNT = 3
+KEY = 0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5
+IV = c0cd2bebccbb6c49920bd5482ac756e8
+PLAINTEXT = 8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c
+CIPHERTEXT = 05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594
+
+COUNT = 4
+KEY = 9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85
+IV = 11958dc6ab81e1c7f01631e9944e620f
+PLAINTEXT = c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf53e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3052d8b21c5561c8b660e
+CIPHERTEXT = 9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832ccdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc557e2b45b49ce05511e65
+
+COUNT = 5
+KEY = 73b8faf00b3302ac99855cf6f9e9e48518690a5906a4869d4dcf48d282faae2a
+IV = b3cb97a80a539912b8c21f450d3b9395
+PLAINTEXT = 3adea6e06e42c4f041021491f2775ef6378cb08824165edc4f6448e232175b60d0345b9f9c78df6596ec9d22b7b9e76e8f3c76b32d5d67273f1d83fe7a6fc3dd3c49139170fa5701b3beac61b490f0a9e13f844640c4500f9ad3087adfb0ae10
+CIPHERTEXT = ac3d6dbafe2e0f740632fd9e820bf6044cd5b1551cbb9cc03c0b25c39ccb7f33b83aacfca40a3265f2bbff879153448acacb88fcfb3bb7b10fe463a68c0109f028382e3e557b1adf02ed648ab6bb895df0205d26ebbfa9a5fd8cebd8e4bee3dc
+
+COUNT = 6
+KEY = 9ddf3745896504ff360a51a3eb49c01b79fccebc71c3abcb94a949408b05b2c9
+IV = e79026639d4aa230b5ccffb0b29d79bc
+PLAINTEXT = cf52e5c3954c51b94c9e38acb8c9a7c76aebdaa9943eae0a1ce155a2efdb4d46985d935511471452d9ee64d2461cb2991d59fc0060697f9a671672163230f367fed1422316e52d29eceacb8768f56d9b80f6d278093c9a8acd3cfd7edd8ebd5c293859f64d2f8486ae1bd593c65bc014
+CIPHERTEXT = 34df561bd2cfebbcb7af3b4b8d21ca5258312e7e2e4e538e35ad2490b6112f0d7f148f6aa8d522a7f3c61d785bd667db0e1dc4606c318ea4f26af4fe7d11d4dcff0456511b4aed1a0d91ba4a1fd6cd9029187bc5881a5a07fe02049d39368e83139b12825bae2c7be81e6f12c61bb5c5
+
+COUNT = 7
+KEY = 458b67bf212d20f3a57fce392065582dcefbf381aa22949f8338ab9052260e1d
+IV = 4c12effc5963d40459602675153e9649
+PLAINTEXT = 256fd73ce35ae3ea9c25dd2a9454493e96d8633fe633b56176dce8785ce5dbbb84dbf2c8a2eeb1e96b51899605e4f13bbc11b93bf6f39b3469be14858b5b720d4a522d36feed7a329c9b1e852c9280c47db8039c17c4921571a07d1864128330e09c308ddea1694e95c84500f1a61e614197e86a30ecc28df64ccb3ccf5437aa
+CIPHERTEXT = 90b7b9630a2378f53f501ab7beff039155008071bc8438e789932cfd3eb1299195465e6633849463fdb44375278e2fdb1310821e6492cf80ff15cb772509fb426f3aeee27bd4938882fd2ae6b5bd9d91fa4a43b17bb439ebbe59c042310163a82a5fe5388796eee35a181a1271f00be29b852d8fa759bad01ff4678f010594cd
+
+COUNT = 8
+KEY = d2412db0845d84e5732b8bbd642957473b81fb99ca8bff70e7920d16c1dbec89
+IV = 51c619fcf0b23f0c7925f400a6cacb6d
+PLAINTEXT = 026006c4a71a180c9929824d9d095b8faaa86fc4fa25ecac61d85ff6de92dfa8702688c02a282c1b8af4449707f22d75e91991015db22374c95f8f195d5bb0afeb03040ff8965e0e1339dba5653e174f8aa5a1b39fe3ac839ce307a4e44b4f8f1b0063f738ec18acdbff2ebfe07383e734558723e741f0a1836dafdf9de82210a9248bc113b3c1bc8b4e252ca01bd803
+CIPHERTEXT = 0254b23463bcabec5a395eb74c8fb0eb137a07bc6f5e9f61ec0b057de305714f8fa294221c91a159c315939b81e300ee902192ec5f15254428d8772f79324ec43298ca21c00b370273ee5e5ed90e43efa1e05a5d171209fe34f9f29237dba2a6726650fd3b1321747d1208863c6c3c6b3e2d879ab5f25782f08ba8f2abbe63e0bedb4a227e81afb36bb6645508356d34
+
+COUNT = 9
+KEY = 48be597e632c16772324c8d3fa1d9c5a9ecd010f14ec5d110d3bfec376c5532b
+IV = d6d581b8cf04ebd3b6eaa1b53f047ee1
+PLAINTEXT = 0c63d413d3864570e70bb6618bf8a4b9585586688c32bba0a5ecc1362fada74ada32c52acfd1aa7444ba567b4e7daaecf7cc1cb29182af164ae5232b002868695635599807a9a7f07a1f137e97b1e1c9dabc89b6a5e4afa9db5855edaa575056a8f4f8242216242bb0c256310d9d329826ac353d715fa39f80cec144d6424558f9f70b98c920096e0f2c855d594885a00625880e9dfb734163cecef72cf030b8
+CIPHERTEXT = fc5873e50de8faf4c6b84ba707b0854e9db9ab2e9f7d707fbba338c6843a18fc6facebaf663d26296fb329b4d26f18494c79e09e779647f9bafa87489630d79f4301610c2300c19dbf3148b7cac8c4f4944102754f332e92b6f7c5e75bc6179eb877a078d4719009021744c14f13fd2a55a2b9c44d18000685a845a4f632c7c56a77306efa66a24d05d088dcd7c13fe24fc447275965db9e4d37fbc9304448cd
+
+[DECRYPT]
+
+COUNT = 0
+KEY = 43e953b2aea08a3ad52d182f58c72b9c60fbe4a9ca46a3cb89e3863845e22c9e
+IV = ddbbb0173f1e2deb2394a62aa2a0240e
+CIPHERTEXT = d51d19ded5ca4ae14b2b20b027ffb020
+PLAINTEXT = 07270d0e63aa36daed8c6ade13ac1af1
+
+COUNT = 1
+KEY = addf88c1ab997eb58c0455288c3a4fa320ada8c18a69cc90aa99c73b174dfde6
+IV = 60cc50e0887532e0d4f3d2f20c3c5d58
+CIPHERTEXT = 6cb4e2f4ddf79a8e08c96c7f4040e8a83266c07fc88dd0074ee25b00d445985a
+PLAINTEXT = 98a8a9d84356bf403a9ccc384a06fe043dfeecb89e59ce0cb8bd0a495ef76cf0
+
+COUNT = 2
+KEY = 54682728db5035eb04b79645c64a95606abb6ba392b6633d79173c027c5acf77
+IV = 2eb94297772851963dd39a1eb95d438f
+CIPHERTEXT = e4046d05385ab789c6a72866e08350f93f583e2a005ca0faecc32b5cfc323d461c76c107307654db5566a5bd693e227c
+PLAINTEXT = 0faa5d01b9afad3bb519575daaf4c60a5ed4ca2ba20c625bc4f08799addcf89d19796d1eff0bd790c622dc22c1094ec7
+
+COUNT = 3
+KEY = 7482c47004aef406115ca5fd499788d582efc0b29dc9e951b1f959406693a54f
+IV = 485ebf2215d20b816ea53944829717ce
+CIPHERTEXT = 6c24f19b9c0b18d7126bf68090cb8ae72db3ca7eabb594f506aae7a2493e5326a5afae4ec4d109375b56e2b6ff4c9cf639e72c63dc8114c796df95b3c6b62021
+PLAINTEXT = 82fec664466d585023821c2e39a0c43345669a41244d05018a23d7159515f8ff4d88b01cd0eb83070d0077e065d74d7373816b61505718f8d4f270286a59d45e
+
+COUNT = 4
+KEY = 3ae38d4ebf7e7f6dc0a1e31e5efa7ca123fdc321e533e79fedd5132c5999ef5b
+IV = 36d55dc9edf8669beecd9a2a029092b9
+CIPHERTEXT = d50ea48c8962962f7c3d301fa9f877245026c204a7771292cddca1e7ffebbef00e86d72910b7d8a756dfb45c9f1040978bb748ca537edd90b670ecee375e15d98582b9f93b6355adc9f80f4fb2108fb9
+PLAINTEXT = 8d22db30c4253c3e3add9685c14d55b05f7cf7626c52cccfcbe9b99fd8913663b8b1f22e277a4cc3d0e7e978a34782eb876867556ad4728486d5e890ea738243e3700a696d6eb58cd81c0e60eb121c50
+
+COUNT = 5
+KEY = d30bfc0b2a19d5b8b6f8f46ab7f444ee136a7fa3fbdaf530cc3e8976339afcc4
+IV = 80be76a7f885d2c06b37d6a528fae0cd
+CIPHERTEXT = 31e4677a17aed120bd3af69fbb0e4b645b9e8c104e280b799ddd49f1e241c3ccb7d40e1c6ff226bf04f8049c51a86e2981cf1331c824d7d451746ccf77fc22fd3717001ee51913d81f7a06fb0037f309957579f695670f2c4c7397d2d990374e
+PLAINTEXT = 0b6e2a8213169b3b78db6de324e286f0366044e035c6970afbf0a1a5c32a05b24ba706cd9c6609737651a81b2bcf4c681dc0861983a5aec76e6c8b244112d64d489e84328974737394b83a39459011727162652b7aa793bfb1b71488b7dec96b
+
+COUNT = 6
+KEY = 64a256a663527ebea71f8d770990b4cee4a2d3afbfd33fb12c7ac300ef59e49a
+IV = 18cce9147f295c5c00dbe0424089d3b4
+CIPHERTEXT = d99771963b7ae5202e382ff8c06e035367909cd24fe5ada7f3d39bfaeb5de98b04eaf4989648e00112f0d2aadb8c5f2157b64581450359965140c141e5fb631e43469d65d1b7370eb3b396399fec32cced294a5eee46d6547f7bbd49dee148b4bc31d6c493cfd28f3908e36cb698629d
+PLAINTEXT = f7e0f79cfddd15ed3600ab2d29c56ba3c8e96d1a896aff6dec773e6ea4710a77f2f4ec646b76efda6428c175d007c84aa9f4b18c5e1bac5f27f7307b737655eee813f7e1f5880a37ac63ad1666e7883083b648454d45786f53ea3db1b5129291138abe40c79fcb7ab7c6f6b9ea133b5f
+
+COUNT = 7
+KEY = 31358e8af34d6ac31c958bbd5c8fb33c334714bffb41700d28b07f11cfe891e7
+IV = 144516246a752c329056d884daf3c89d
+CIPHERTEXT = b32e2b171b63827034ebb0d1909f7ef1d51c5f82c1bb9bc26bc4ac4dccdee8357dca6154c2510ae1c87b1b422b02b621bb06cac280023894fcff3406af08ee9be1dd72419beccddff77c722d992cdcc87e9c7486f56ab406ea608d8c6aeb060c64cf2785ad1a159147567e39e303370da445247526d95942bf4d7e88057178b0
+PLAINTEXT = cfc155a3967de347f58fa2e8bbeb4183d6d32f7427155e6ab39cddf2e627c572acae02f1f243f3b784e73e21e7e520eacd3befafbee814867334c6ee8c2f0ee7376d3c72728cde7813173dbdfe3357deac41d3ae2a04229c0262f2d109d01f5d03e7f848fb50c28849146c02a2f4ebf7d7ffe3c9d40e31970bf151873672ef2b
+
+COUNT = 8
+KEY = 5b4b69339891db4e3337c3486f439dfbd0fb2a782ca71ef0059819d51669d93c
+IV = 2b28a2d19ba9ecd149dae96622c21769
+CIPHERTEXT = ba21db8ec170fa4d73cfc381687f3fa188dd2d012bef48007f3dc88329e22ba32fe235a315be362546468b9db6af6705c6e5d4d36822f42883c08d4a994cc454a7db292c4ca1f4b62ebf8e479a5d545d6af9978d2cfee7bc80999192c2c8662ce9b4be11af40bd68f3e2d5685bb28c0f3dc08017c0aba8263e6fdc45ed7f9893bf14fd3a86c418a35c5667e642d59985
+PLAINTEXT = a0bb1d2fdeb7e6bf34c690fe7b72a5e9d65796aa57982fe340c286d6923dbddb426566ff58e9c0b3af52e4db446f6cc5daa5bfcf4e3c85db5a5638e670c370cce128db22c97542a64a63846f18a228d3462a11376dcb71f66ec52ebda474f7b6752915b0801797974bc51eb1218127fed60f1009430eb5089fb3ba5f28fad24c518ccddc2501393ceb6dffc46a159421
+
+COUNT = 9
+KEY = 87725bd43a45608814180773f0e7ab95a3c859d83a2130e884190e44d14c6996
+IV = e49651988ebbb72eb8bb80bb9abbca34
+CIPHERTEXT = 5b97a9d423f4b97413f388d9a341e727bb339f8e18a3fac2f2fb85abdc8f135deb30054a1afdc9b6ed7da16c55eba6b0d4d10c74e1d9a7cf8edfaeaa684ac0bd9f9d24ba674955c79dc6be32aee1c260b558ff07e3a4d49d24162011ff254db8be078e8ad07e648e6bf5679376cb4321a5ef01afe6ad8816fcc7634669c8c4389295c9241e45fff39f3225f7745032daeebe99d4b19bcb215d1bfdb36eda2c24
+PLAINTEXT = bfe5c6354b7a3ff3e192e05775b9b75807de12e38a626b8bf0e12d5fff78e4f1775aa7d792d885162e66d88930f9c3b2cdf8654f56972504803190386270f0aa43645db187af41fcea639b1f8026ccdd0c23e0de37094a8b941ecb7602998a4b2604e69fc04219585d854600e0ad6f99a53b2504043c08b1c3e214d17cde053cbdf91daa999ed5b47c37983ba3ee254bc5c793837daaa8c85cfc12f7f54f699f
+
diff --git a/hwcryptokey-test/vectors/NIST/CTR/ctr_128.rsp b/hwcryptokey-test/vectors/NIST/CTR/ctr_128.rsp
new file mode 100644
index 0000000..19e0d78
--- /dev/null
+++ b/hwcryptokey-test/vectors/NIST/CTR/ctr_128.rsp
@@ -0,0 +1,62 @@
+# F.5.1 CTR-AES128.Encrypt
+# test data for CTR
+# Key Length : 128
+
+[ENCRYPT]
+
+Block #1
+KEY = 2b7e151628aed2a6abf7158809cf4f3c
+IV = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+OUTPUTBLOCK = ec8cdf7398607cb0f2d21675ea9ea1e4
+PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
+CIPHERTEXT = 874d6191b620e3261bef6864990db6ce
+
+Block #2
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
+OUTPUTBLOCK = 362b7c3c6773516318a077d7fc5073ae
+PLAINTEXT = ae2d8a571e03ac9c9eb76fac45af8e51
+CIPHERTEXT = 9806f66b7970fdff8617187bb9fffdff
+
+Block #3
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
+OUTPUTBLOCK = 6a2cc3787889374fbeb4c81b17ba6c44
+PLAINTEXT = 30c81c46a35ce411e5fbc1191a0a52ef
+CIPHERTEXT = 5ae4df3edbd5d35e5b4f09020db03eab
+
+Block #4
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
+OUTPUTBLOCK = e89c399ff0f198c6d40a31db156cabfe
+PLAINTEXT = f69f2445df4f9b17ad2b417be66c3710
+CIPHERTEXT = 1e031dda2fbe03d1792170a0f3009cee
+
+
+# F.5.2 CTR-AES128.Decrypt
+
+[DECRYPT]
+
+Block #1
+KEY = 2b7e151628aed2a6abf7158809cf4f3c
+IV = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+OUTPUTBLOCK = ec8cdf7398607cb0f2d21675ea9ea1e4
+CIPHERTEXT = 874d6191b620e3261bef6864990db6ce
+PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
+
+Block #2
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
+OUTPUTBLOCK = 362b7c3c6773516318a077d7fc5073ae
+CIPHERTEXT = 9806f66b7970fdff8617187bb9fffdff
+PLAINTEXT = ae2d8a571e03ac9c9eb76fac45af8e51
+
+Block #3
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
+OUTPUTBLOCK = 6a2cc3787889374fbeb4c81b17ba6c44
+CIPHERTEXT = 5ae4df3edbd5d35e5b4f09020db03eab
+PLAINTEXT = 30c81c46a35ce411e5fbc1191a0a52ef
+
+Block #4
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
+OUTPUTBLOCK = e89c399ff0f198c6d40a31db156cabfe
+CIPHERTEXT = 1e031dda2fbe03d1792170a0f3009cee
+PLAINTEXT = f69f2445df4f9b17ad2b417be66c3710
diff --git a/hwcryptokey-test/vectors/NIST/CTR/ctr_256.rsp b/hwcryptokey-test/vectors/NIST/CTR/ctr_256.rsp
new file mode 100644
index 0000000..f207547
--- /dev/null
+++ b/hwcryptokey-test/vectors/NIST/CTR/ctr_256.rsp
@@ -0,0 +1,62 @@
+# F.5.5 CTR-AES256.Encrypt
+# test data for CTR
+# Key Length : 256
+
+[ENCRYPT]
+
+Block #1
+KEY = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
+IV = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+OUTPUTBLOCK = 0bdf7df1591716335e9a8b15c860c502
+PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
+CIPHERTEXT = 601ec313775789a5b7a7f504bbf3d228
+
+Block #2
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
+OUTPUTBLOCK = 5a6e699d536119065433863c8f657b94
+PLAINTEXT = ae2d8a571e03ac9c9eb76fac45af8e51
+CIPHERTEXT = f443e3ca4d62b59aca84e990cacaf5c5
+
+Block #3
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
+OUTPUTBLOCK = 1bc12c9c01610d5d0d8bd6a3378eca62
+PLAINTEXT = 30c81c46a35ce411e5fbc1191a0a52ef
+CIPHERTEXT = 2b0930daa23de94ce87017ba2d84988d
+
+Block #4
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
+OUTPUTBLOCK = 2956e1c8693536b1bee99c73a31576b6
+PLAINTEXT = f69f2445df4f9b17ad2b417be66c3710
+CIPHERTEXT = dfc9c58db67aada613c2dd08457941a6
+
+
+# F.5.6 CTR-AES256.Decrypt
+
+[DECRYPT]
+
+Block #1
+KEY = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
+IV = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
+OUTPUTBLOCK = 0bdf7df1591716335e9a8b15c860c502
+CIPHERTEXT = 601ec313775789a5b7a7f504bbf3d228
+PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
+
+Block #2
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
+OUTPUTBLOCK = 5a6e699d536119065433863c8f657b94
+CIPHERTEXT = f443e3ca4d62b59aca84e990cacaf5c5
+PLAINTEXT = ae2d8a571e03ac9c9eb76fac45af8e51
+
+Block #3
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
+OUTPUTBLOCK = 1bc12c9c01610d5d0d8bd6a3378eca62
+CIPHERTEXT = 2b0930daa23de94ce87017ba2d84988d
+PLAINTEXT = 30c81c46a35ce411e5fbc1191a0a52ef
+
+Block #4
+INPUTBLOCK = f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
+OUTPUTBLOCK = 2956e1c8693536b1bee99c73a31576b6
+CIPHERTEXT = dfc9c58db67aada613c2dd08457941a6
+PLAINTEXT = f69f2445df4f9b17ad2b417be66c3710
diff --git a/hwcryptokey-test/versioned_keys_explicit.rs b/hwcryptokey-test/versioned_keys_explicit.rs
index 2bb9e7d..0c5ac1a 100644
--- a/hwcryptokey-test/versioned_keys_explicit.rs
+++ b/hwcryptokey-test/versioned_keys_explicit.rs
@@ -43,24 +43,24 @@ mod tests {
     ];
 
     pub(crate) const VERSION_0_CLEAR_KEY: [u8; 256] = [
-        0xf7, 0xf3, 0x3f, 0x34, 0xfd, 0x4c, 0x09, 0xcf, 0xb2, 0x20, 0x8a, 0xcc, 0x08, 0xd8, 0x33,
-        0x97, 0x66, 0xeb, 0x65, 0xd2, 0xba, 0xd9, 0x48, 0x83, 0x79, 0x6d, 0x43, 0x09, 0x69, 0xe5,
-        0x2d, 0x54, 0x9b, 0xd8, 0xbb, 0xc0, 0xb9, 0xec, 0xe4, 0x90, 0x8b, 0x43, 0x57, 0x9b, 0x84,
-        0xad, 0x55, 0xd5, 0x68, 0x43, 0xc6, 0x1b, 0x01, 0x36, 0xca, 0x82, 0x6c, 0x96, 0xae, 0x5f,
-        0xca, 0xec, 0xc2, 0x48, 0x13, 0x5a, 0x72, 0x17, 0x20, 0x56, 0x9e, 0x3b, 0xe3, 0xe5, 0xbd,
-        0x20, 0x38, 0x56, 0x01, 0x8a, 0x32, 0x92, 0x47, 0xb1, 0x0f, 0x0e, 0x8f, 0x69, 0x1d, 0x7f,
-        0x33, 0x84, 0xb8, 0x46, 0x58, 0x0d, 0xf6, 0xa2, 0xb1, 0xc7, 0xe9, 0x7a, 0xbc, 0x18, 0xa9,
-        0x78, 0x70, 0x61, 0xff, 0x4b, 0x70, 0x41, 0x58, 0xdd, 0xbb, 0xcb, 0x71, 0x46, 0x92, 0x4d,
-        0xf2, 0x26, 0xe0, 0x20, 0x6d, 0x81, 0x4c, 0x82, 0x5a, 0x29, 0xee, 0x1e, 0x01, 0xb7, 0xd1,
-        0x8b, 0x32, 0xef, 0x00, 0x5e, 0x83, 0x1e, 0x30, 0x1d, 0xc4, 0xb2, 0x95, 0x5a, 0xa5, 0x75,
-        0x02, 0x9c, 0xae, 0xf5, 0x8e, 0x88, 0xd8, 0x94, 0xac, 0x9a, 0x04, 0x88, 0x6f, 0x38, 0x8b,
-        0x1b, 0x22, 0x5a, 0x33, 0x3e, 0xfb, 0x2e, 0xfd, 0x6f, 0xaa, 0x7d, 0xcd, 0xf1, 0xab, 0x61,
-        0x69, 0xc0, 0x54, 0x09, 0xf9, 0xe9, 0x43, 0xa1, 0x7f, 0x48, 0xf5, 0xe9, 0xfe, 0xf3, 0xd5,
-        0xd1, 0xdf, 0x0c, 0xe7, 0xc9, 0xd4, 0xfd, 0xe2, 0x31, 0x33, 0x6c, 0x71, 0xe1, 0xe0, 0x9b,
-        0x35, 0x1f, 0xea, 0x7a, 0x3e, 0xaa, 0x36, 0x70, 0xda, 0xb7, 0xcc, 0x5e, 0x1f, 0xe5, 0x70,
-        0xf6, 0x60, 0xe8, 0xa4, 0x8a, 0xa3, 0x1d, 0x08, 0x6a, 0xa6, 0xf9, 0x6c, 0xac, 0x5b, 0xa2,
-        0xa9, 0x45, 0x67, 0xae, 0x34, 0x55, 0xc0, 0xd0, 0xf5, 0x37, 0xde, 0xc6, 0x13, 0x06, 0x16,
-        0x82,
+        0xbb, 0x3c, 0xca, 0xca, 0x52, 0x68, 0x05, 0xae, 0xbe, 0xd9, 0x27, 0x98, 0xc8, 0x0e, 0xf0,
+        0xbd, 0xfb, 0x03, 0x77, 0x47, 0xe1, 0x68, 0x5b, 0x54, 0xad, 0x42, 0x80, 0x06, 0x83, 0x65,
+        0xeb, 0x69, 0x25, 0x22, 0x00, 0x5f, 0x7e, 0xa7, 0x56, 0xe8, 0xce, 0x44, 0x0b, 0xd0, 0x25,
+        0xcb, 0x29, 0x50, 0xf2, 0x4e, 0xda, 0x6a, 0xa3, 0x99, 0x47, 0x35, 0x14, 0x08, 0x3b, 0x57,
+        0x86, 0xb0, 0xfe, 0x58, 0xb8, 0x23, 0xe8, 0x7c, 0xee, 0x97, 0x84, 0x09, 0x57, 0xa9, 0xc2,
+        0xbe, 0xe1, 0xa2, 0xbb, 0xfe, 0xcb, 0x5d, 0xea, 0x01, 0xee, 0x93, 0x66, 0x71, 0xef, 0x5a,
+        0x02, 0x34, 0x9e, 0xb8, 0x38, 0xc1, 0x2d, 0xeb, 0x1b, 0xbe, 0x8e, 0x69, 0x6e, 0xbf, 0x82,
+        0x72, 0x4e, 0x28, 0x89, 0xda, 0x4a, 0x0c, 0xc4, 0xee, 0x6d, 0xd7, 0x3a, 0x1f, 0xb0, 0x3d,
+        0xcc, 0xff, 0x4a, 0x3b, 0x27, 0x49, 0xf3, 0x85, 0xd8, 0x67, 0xcb, 0x4b, 0x92, 0x5f, 0xce,
+        0xbb, 0xcb, 0xe1, 0xfe, 0x8a, 0xab, 0xc3, 0x54, 0xce, 0x44, 0xff, 0x36, 0xe1, 0x46, 0xce,
+        0x86, 0x25, 0xc0, 0x35, 0xe6, 0x7d, 0xdb, 0xab, 0x2d, 0xfc, 0x7e, 0xeb, 0xb0, 0x93, 0x79,
+        0x3d, 0x1b, 0x78, 0x64, 0x0d, 0x6f, 0x35, 0x40, 0xc1, 0xd2, 0x00, 0xfc, 0x2a, 0x14, 0xc3,
+        0xc2, 0x0f, 0x10, 0x56, 0x5b, 0x5c, 0xcb, 0xbe, 0x80, 0xdf, 0x08, 0x0d, 0x26, 0x18, 0x8f,
+        0xf6, 0x94, 0xf0, 0x8d, 0xb2, 0x29, 0x2e, 0xb9, 0x2d, 0xd0, 0x67, 0x57, 0xea, 0xed, 0x2f,
+        0xb0, 0x21, 0xfa, 0x67, 0x42, 0x4a, 0x6a, 0xae, 0xdd, 0x98, 0xc5, 0x1a, 0x6e, 0xf8, 0xfa,
+        0xf6, 0x44, 0x7f, 0x2f, 0x88, 0x6f, 0xe1, 0x60, 0x70, 0xa6, 0x08, 0xdf, 0xdf, 0xc1, 0x3f,
+        0x8c, 0xed, 0x42, 0x99, 0x15, 0x3b, 0xc7, 0x97, 0x61, 0xcd, 0xf6, 0x65, 0x77, 0xc6, 0x8e,
+        0x8d,
     ];
 
     fn connect() -> Result<Strong<dyn IHwCryptoKey>, StatusCode> {
diff --git a/hwcryptokey-test/versioned_keys_opaque.rs b/hwcryptokey-test/versioned_keys_opaque.rs
new file mode 100644
index 0000000..c0975dd
--- /dev/null
+++ b/hwcryptokey-test/versioned_keys_opaque.rs
@@ -0,0 +1,421 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#[cfg(test)]
+mod tests {
+    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+        types::{
+            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
+            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
+            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
+            SymmetricOperation::SymmetricOperation,
+            SymmetricOperationParameters::SymmetricOperationParameters,
+        },
+        CryptoOperation::CryptoOperation,
+        CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
+        CryptoOperationSet::CryptoOperationSet,
+        IHwCryptoKey::{
+            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
+            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
+            DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
+            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
+        },
+        IHwCryptoOperations::IHwCryptoOperations,
+        IOpaqueKey::IOpaqueKey,
+        KeyPolicy::KeyPolicy,
+        OperationParameters::OperationParameters,
+    };
+    use binder::{Status, StatusCode, Strong};
+    use rpcbinder::RpcSession;
+    use test::{assert_ok, expect};
+    use trusty_std::ffi::{CString, FallibleCString};
+
+    pub(crate) const RUST_DEVICE_KEY_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
+
+    pub(crate) const VERSION_0_DICE_POLICY: [u8; 120] = [
+        0x83, 0x58, 0x30, 0xa3, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x7a, 0x87,
+        0x07, 0x18, 0x72, 0x14, 0xb4, 0x1e, 0x69, 0x60, 0xc8, 0x6e, 0xfd, 0x8d, 0xdf, 0x6e, 0x48,
+        0xbd, 0x33, 0xa2, 0xdf, 0x6c, 0x76, 0x59, 0xdf, 0x82, 0x93, 0x3e, 0xf3, 0xa9, 0x6a, 0x23,
+        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0xa0, 0x58, 0x42, 0xea, 0xf7, 0x26, 0xfd, 0x2a, 0x06,
+        0x0a, 0x4b, 0x9e, 0x8c, 0xba, 0xf3, 0x41, 0x91, 0xac, 0x88, 0xfd, 0xc6, 0x23, 0xc3, 0x3f,
+        0x33, 0x64, 0x6d, 0x20, 0xb4, 0x18, 0x7a, 0x55, 0x7c, 0x4c, 0xdd, 0x64, 0x84, 0x54, 0x22,
+        0xec, 0xd9, 0x1d, 0x89, 0x49, 0xf3, 0xcb, 0x37, 0xfb, 0x1c, 0x49, 0x5a, 0xd5, 0xbc, 0xf6,
+        0x82, 0xd7, 0x82, 0xcc, 0x51, 0x00, 0x3b, 0x71, 0x0f, 0xde, 0xdb, 0x8a, 0xcf, 0x23, 0xf9,
+    ];
+
+    pub(crate) const ENCRYPTION_PAYLOAD: &str = "string to be encrypted";
+
+    pub(crate) const VERSION_0_ENCRYPTION_KNOWN_VALUE: [u8; 32] = [
+        0x68, 0xb6, 0xf7, 0xd8, 0x05, 0x91, 0x59, 0x42, 0x2c, 0xd1, 0x07, 0xd7, 0x81, 0xbf, 0xd0,
+        0x31, 0xeb, 0x39, 0x11, 0x68, 0xfc, 0xfb, 0x90, 0xd7, 0x82, 0x04, 0xeb, 0x98, 0x44, 0x4d,
+        0xcf, 0x0a,
+    ];
+
+    fn connect() -> Result<Strong<dyn IHwCryptoKey>, StatusCode> {
+        let port =
+            CString::try_new(RUST_DEVICE_KEY_SERVICE_PORT).expect("Failed to allocate port name");
+        RpcSession::new().setup_trusty_client(port.as_c_str())
+    }
+
+    fn do_cipher(
+        hw_crypto: &dyn IHwCryptoOperations,
+        key: Strong<dyn IOpaqueKey>,
+        direction: SymmetricOperation,
+        payload: Vec<u8>,
+    ) -> Result<Vec<u8>, Status> {
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        let input_data = OperationData::DataBuffer(payload);
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        let result = hw_crypto.processCommandList(&mut crypto_sets, &mut additional_error_info);
+        match result {
+            Ok(..) => {}
+            Err(e) => return Err(e),
+        }
+
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(result)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        Ok(result)
+    }
+
+    fn encrypt(
+        hw_crypto: &dyn IHwCryptoOperations,
+        key: Strong<dyn IOpaqueKey>,
+        payload: Vec<u8>,
+    ) -> Result<Vec<u8>, Status> {
+        do_cipher(hw_crypto, key, SymmetricOperation::ENCRYPT, payload)
+    }
+
+    fn decrypt(
+        hw_crypto: &dyn IHwCryptoOperations,
+        key: Strong<dyn IOpaqueKey>,
+        payload: Vec<u8>,
+    ) -> Result<Vec<u8>, Status> {
+        do_cipher(hw_crypto, key, SymmetricOperation::DECRYPT, payload)
+    }
+
+    #[test]
+    fn generate_new_policy_and_opaque_key() {
+        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
+        let hw_crypto =
+            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+
+        // Get the device bound key
+        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
+
+        // Generate the current derivation key and policy
+        let key_and_policy =
+            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
+        let DiceCurrentBoundKeyResult {
+            diceBoundKey: derivation_key1,
+            dicePolicyForKeyVersion: dice_policy,
+        } = key_and_policy;
+
+        expect!(derivation_key1.is_some(), "should have received a key");
+        expect!(dice_policy.len() > 0, "should have received a DICE policy");
+
+        // Derive an opaque key from returned current policy and derivation key
+        let policy = KeyPolicy {
+            usage: KeyUse::ENCRYPT_DECRYPT,
+            keyLifetime: KeyLifetime::HARDWARE,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
+            keyManagementKey: false,
+        };
+
+        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
+            .expect("couldn't serialize policy");
+        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);
+
+        let mut params = DerivedKeyParameters {
+            derivationKey: derivation_key1,
+            keyPolicy: key_policy,
+            context: "context".as_bytes().to_vec(),
+        };
+
+        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));
+
+        // Check key type
+        let derived_key1 = match derived_key1 {
+            DerivedKey::Opaque(k) => k,
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let derived_key1 = derived_key1.expect("key is missing");
+
+        // Baseline encryption operations
+        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
+
+        let encrypted_data =
+            encrypt(hw_crypto.as_ref(), derived_key1.clone(), clear_payload.clone())
+                .expect("encryption failure");
+        let clear_data = decrypt(hw_crypto.as_ref(), derived_key1.clone(), encrypted_data.clone())
+            .expect("decryption failure");
+
+        assert_eq!(clear_payload, clear_data, "decrypted data mismatch");
+
+        // Use dice policy to request same derivation key
+        let key_and_policy =
+            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy));
+        let DiceBoundKeyResult {
+            diceBoundKey: derivation_key2,
+            dicePolicyWasCurrent: dice_policy_current,
+        } = key_and_policy;
+
+        expect!(derivation_key2.is_some(), "should have received a key");
+        expect!(dice_policy_current, "policy should have been current");
+
+        // Generate derived key 2
+        params.derivationKey = derivation_key2;
+
+        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));
+
+        // Check key type
+        let derived_key2 = match derived_key2 {
+            DerivedKey::Opaque(k) => k,
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let derived_key2 = derived_key2.expect("key is missing");
+
+        let clear_data2 = decrypt(hw_crypto.as_ref(), derived_key2.clone(), encrypted_data.clone())
+            .expect("decryption failure");
+        assert_eq!(clear_payload, clear_data2, "decrypted data mismatch");
+
+        // If we request current dice policy again, we expect the same key, but different
+        // encryption of the returned policy. Note underlying policy is the same (latest),
+        // but encrypted byte array returned will be different
+
+        // Generate the current derivation key and policy again
+        let key_and_policy =
+            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
+        let DiceCurrentBoundKeyResult {
+            diceBoundKey: derivation_key3,
+            dicePolicyForKeyVersion: dice_policy3,
+        } = key_and_policy;
+
+        // We expect the dice policy to appear different due to encruption
+        assert_ne!(
+            dice_policy, dice_policy3,
+            "expected dice policies to appear different due to encryption"
+        );
+
+        // Ensure derived key from this policy matches previously generated derived key
+        params.derivationKey = derivation_key3;
+
+        let derived_key3 = assert_ok!(hw_device_key.deriveKey(&params));
+
+        // Check key type
+        let derived_key3 = match derived_key3 {
+            DerivedKey::Opaque(k) => k,
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let derived_key3 = derived_key3.expect("key is missing");
+
+        // Try encrypting same clear_payload and verify encrypted result is same
+        let encrypted_data3 =
+            encrypt(hw_crypto.as_ref(), derived_key3.clone(), clear_payload.clone())
+                .expect("encryption failure");
+        assert_eq!(encrypted_data3, encrypted_data, "unexpected encrypted data mismatch");
+
+        // try using key to decrypt earlier encryption result
+        let clear_data3 = decrypt(hw_crypto.as_ref(), derived_key3.clone(), encrypted_data.clone())
+            .expect("decryption failure");
+        assert_eq!(clear_data3, clear_payload, "unexpected data mismatch");
+    }
+
+    #[test]
+    fn old_dice_policy_generates_old_opaque_key_and_new_policy() {
+        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
+        let hw_crypto =
+            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+
+        // Get the device bound key
+        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
+
+        // Generate a derived key from version 0 dice policy
+        let key_and_policy = assert_ok!(
+            hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &VERSION_0_DICE_POLICY)
+        );
+        let DiceBoundKeyResult {
+            diceBoundKey: derivation_key,
+            dicePolicyWasCurrent: dice_policy_current,
+        } = key_and_policy;
+
+        // We expect version 0 should not be current
+        expect!(!dice_policy_current, "policy not expected to be current");
+
+        // Generate a key using version 0 dice policy
+        let policy = KeyPolicy {
+            usage: KeyUse::ENCRYPT_DECRYPT,
+            keyLifetime: KeyLifetime::HARDWARE,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
+            keyManagementKey: false,
+        };
+
+        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
+            .expect("couldn't serialize policy");
+        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);
+
+        let params = DerivedKeyParameters {
+            derivationKey: derivation_key,
+            keyPolicy: key_policy,
+            context: "context".as_bytes().to_vec(),
+        };
+
+        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
+
+        // Check key type
+        let derived_key = match derived_key {
+            DerivedKey::Opaque(k) => k,
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let derived_key = derived_key.expect("key is missing");
+
+        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
+        let encrypted_data =
+            encrypt(hw_crypto.as_ref(), derived_key.clone(), clear_payload.clone())
+                .expect("encryption failure");
+
+        // Check we got the old key and encryption results match expected for version 0 dice policy
+        assert_eq!(
+            encrypted_data,
+            VERSION_0_ENCRYPTION_KNOWN_VALUE.to_vec(),
+            "Unexpected encryption result"
+        );
+    }
+
+    #[test]
+    fn opaque_keys_unique_by_context() {
+        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
+        let hw_crypto =
+            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+
+        // Get the device bound key
+        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
+
+        // Generate the current derivation key and policy
+        let key_and_policy =
+            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
+        let DiceCurrentBoundKeyResult {
+            diceBoundKey: derivation_key,
+            dicePolicyForKeyVersion: dice_policy,
+        } = key_and_policy;
+
+        expect!(derivation_key.is_some(), "should have received a key");
+        expect!(dice_policy.len() > 0, "should have received a DICE policy");
+
+        let context1 = "context1";
+        let context2 = "context2";
+
+        // Get derived key for context1
+        let policy1 = KeyPolicy {
+            usage: KeyUse::ENCRYPT_DECRYPT,
+            keyLifetime: KeyLifetime::HARDWARE,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
+            keyManagementKey: false,
+        };
+
+        let cbor_policy1 = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy1)
+            .expect("couldn't serialize policy");
+        let key_policy1 = DerivedKeyPolicy::OpaqueKey(cbor_policy1);
+
+        let params1 = DerivedKeyParameters {
+            derivationKey: derivation_key.clone(),
+            keyPolicy: key_policy1,
+            context: context1.as_bytes().to_vec(),
+        };
+
+        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params1));
+
+        // Check key type
+        let derived_key1 = match derived_key1 {
+            DerivedKey::Opaque(k) => k,
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let derived_key1 = derived_key1.expect("key is missing");
+
+        // Context1 encryption
+        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
+        let encrypted_data1 =
+            encrypt(hw_crypto.as_ref(), derived_key1.clone(), clear_payload.clone())
+                .expect("encryption failure");
+
+        // Request key for context2 and verify key is different
+        let policy2 = KeyPolicy {
+            usage: KeyUse::ENCRYPT_DECRYPT,
+            keyLifetime: KeyLifetime::HARDWARE,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
+            keyManagementKey: false,
+        };
+
+        let cbor_policy2 = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy2)
+            .expect("couldn't serialize policy");
+        let key_policy2 = DerivedKeyPolicy::OpaqueKey(cbor_policy2);
+
+        let params2 = DerivedKeyParameters {
+            derivationKey: derivation_key.clone(),
+            keyPolicy: key_policy2,
+            context: context2.as_bytes().to_vec(),
+        };
+
+        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params2));
+
+        // Check key type
+        let derived_key2 = match derived_key2 {
+            DerivedKey::Opaque(k) => k,
+            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
+        };
+
+        let derived_key2 = derived_key2.expect("key is missing");
+
+        // Context2 encryption
+        let encrypted_data2 =
+            encrypt(hw_crypto.as_ref(), derived_key2.clone(), clear_payload.clone())
+                .expect("encryption failure");
+
+        // Verify encryption results are different
+        assert_ne!(encrypted_data2, encrypted_data1, "encrypted results should not match");
+    }
+}
diff --git a/hwrng-bench/main.c b/hwrng-bench/main.c
index 5332012..a58af4d 100644
--- a/hwrng-bench/main.c
+++ b/hwrng-bench/main.c
@@ -103,10 +103,14 @@ static void get_formatted_value_cb(char* buf,
     }
 }
 
+static uint64_t crypto_pmu_evt_arr[] = {PMU_EV_BR_MIS_PRED,
+                                        PMU_EV_INST_RETIRED};
+
 /*
  * Executed before each atomic execution of a BENCH(crypto, ...) Macro.
  */
 BENCH_SETUP(crypto) {
+    BENCH_INIT_PMU(crypto_pmu_evt_arr);
     /*
      * Let Framework know how to print param column header. Default is the
      * current param index. Will be reset to NULL after BENCH_TEARDOWN(crypto,
@@ -169,6 +173,14 @@ BENCH_RESULT(crypto, hwrng_hw_rand, time_micro_seconds) {
     return bench_get_duration_ns();
 }
 
+BENCH_RESULT(crypto, hwrng_hw_rand, cycle_counter) {
+    return bench_get_pmu_cnt(1);
+}
+
+BENCH_RESULT(crypto, hwrng_hw_rand, inst_retired) {
+    return bench_get_pmu_cnt(2);
+}
+
 BENCH_RESULT(crypto, hwrng_hw_rand, micro_sec_per_byte) {
     return bench_get_duration_ns() / BUF_SIZE;
 }
@@ -208,6 +220,14 @@ BENCH_RESULT(crypto, hwrng_fixed_total, micro_sec_per_byte) {
     return bench_get_duration_ns() / BUF_SIZE;
 }
 
+BENCH_RESULT(crypto, hwrng_fixed_total, cycle_counter) {
+    return bench_get_pmu_cnt(1);
+}
+
+BENCH_RESULT(crypto, hwrng_fixed_total, inst_retired) {
+    return bench_get_pmu_cnt(2);
+}
+
 /*
  * BENCH with 5 parameters (suite_name, test_name, nb_of_runs, params).
  * For each parameter in query_params, the inner content is run 100 times.
diff --git a/hwrng-bench/manifest.json b/hwrng-bench/manifest.json
index d3e5149..99e48f7 100644
--- a/hwrng-bench/manifest.json
+++ b/hwrng-bench/manifest.json
@@ -1,5 +1,5 @@
 {
     "uuid": "83e2c228-0789-40fb-82da-dc5f1bba8fe9",
-    "min_heap": 16384,
-    "min_stack": 16384
+    "min_heap": 65536,
+    "min_stack": 65536
 }
diff --git a/hwrng-unittest/main.c b/hwrng-unittest/main.c
index 3b2f115..6845ff5 100644
--- a/hwrng-unittest/main.c
+++ b/hwrng-unittest/main.c
@@ -27,7 +27,7 @@
 #include <uapi/err.h>
 
 static uint32_t _hist[256];
-static uint8_t _rng_buf[1024];
+static uint8_t _rng_buf[16384];
 
 static void hwrng_update_hist(uint8_t* data, unsigned int cnt) {
     for (unsigned int i = 0; i < cnt; i++) {
@@ -58,13 +58,19 @@ TEST(hwrng, show_data_test) {
     }
 }
 
+TEST(hwrng, large_buffer) {
+    int rc;
+    rc = trusty_rng_hw_rand(_rng_buf, sizeof(_rng_buf));
+    EXPECT_EQ(NO_ERROR, rc, "hwrng test");
+}
+
 TEST(hwrng, var_rng_req_test) {
     int rc;
     unsigned int i;
     size_t req_cnt;
     /* Issue 100 hwrng requests of variable sizes */
     for (i = 0; i < 100; i++) {
-        req_cnt = ((size_t)rand() % sizeof(_rng_buf)) + 1;
+        req_cnt = ((size_t)rand() % MIN(1024, sizeof(_rng_buf))) + 1;
         rc = trusty_rng_hw_rand(_rng_buf, req_cnt);
         EXPECT_EQ(NO_ERROR, rc, "hwrng test");
         if (rc != NO_ERROR) {
diff --git a/manifest-test/manifest_test.c b/manifest-test/manifest_test.c
index b12c972..9133c8c 100644
--- a/manifest-test/manifest_test.c
+++ b/manifest-test/manifest_test.c
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include <lk/macros.h>
+#include <sys/auxv.h>
 #include <sys/mman.h>
 #include <trusty/sys/mman.h>
 #include <trusty_unittest.h>
@@ -31,6 +33,8 @@
 #define TEST3_PHY_BASE_ADDR 0x70020000U
 #define TEST3_REG_SIZE 0x4U
 
+#define PAGE_SIZE getauxval(AT_PAGESZ)
+
 typedef struct manifest_test {
 } manifest_test_t;
 
@@ -74,7 +78,8 @@ TEST_F(manifest_test, mem_map_test_1) {
 
 test_abort:
     if (va_base != MAP_FAILED) {
-        munmap(va_base, TEST1_REG_SIZE);
+        EXPECT_EQ(NO_ERROR,
+                  munmap(va_base, ROUND_UP(TEST1_REG_SIZE, PAGE_SIZE)));
     }
 }
 
@@ -91,7 +96,8 @@ TEST_F(manifest_test, mem_map_test_2) {
 
 test_abort:
     if (va_base != MAP_FAILED) {
-        munmap(va_base, TEST2_REG_SIZE);
+        EXPECT_EQ(NO_ERROR,
+                  munmap(va_base, ROUND_UP(TEST2_REG_SIZE, PAGE_SIZE)));
     }
 }
 
@@ -108,7 +114,8 @@ TEST_F(manifest_test, mem_map_test_3) {
 
 test_abort:
     if (va_base != MAP_FAILED) {
-        munmap(va_base, TEST3_REG_SIZE);
+        EXPECT_EQ(NO_ERROR,
+                  munmap(va_base, ROUND_UP(TEST3_REG_SIZE, PAGE_SIZE)));
     }
 }
 
@@ -126,7 +133,7 @@ TEST_F(manifest_test, mem_map_test_small_size) {
 
 test_abort:
     if (va_base != MAP_FAILED) {
-        munmap(va_base, size);
+        EXPECT_EQ(NO_ERROR, munmap(va_base, ROUND_UP(size, PAGE_SIZE)));
     }
 }
 
@@ -140,7 +147,7 @@ TEST_F(manifest_test, mem_map_test_large_size) {
 
 test_abort:
     if (va_base != MAP_FAILED) {
-        munmap(va_base, size);
+        EXPECT_EQ(NO_ERROR, munmap(va_base, ROUND_UP(size, PAGE_SIZE)));
     }
 }
 
@@ -154,7 +161,8 @@ TEST_F(manifest_test, mem_map_test_unknown_id) {
 
 test_abort:
     if (va_base != MAP_FAILED) {
-        munmap(va_base, TEST1_REG_SIZE);
+        EXPECT_EQ(NO_ERROR,
+                  munmap(va_base, ROUND_UP(TEST1_REG_SIZE, PAGE_SIZE)));
     }
 }
 
diff --git a/memref-test/memref-test.c b/memref-test/memref-test.c
index 5ce9cbf..afdd358 100644
--- a/memref-test/memref-test.c
+++ b/memref-test/memref-test.c
@@ -195,10 +195,10 @@ TEST(memref, dup_map) {
 
 test_abort:
     if (dbuf && dbuf != MAP_FAILED) {
-        munmap((void*)dbuf, PAGE_SIZE);
+        EXPECT_EQ(0, munmap((void*)dbuf, PAGE_SIZE));
     }
     if (mbuf && mbuf != MAP_FAILED) {
-        munmap((void*)mbuf, PAGE_SIZE);
+        EXPECT_EQ(0, munmap((void*)mbuf, PAGE_SIZE));
     }
     close(dref);
     close(mref);
diff --git a/memref-test/receiver/receiver.c b/memref-test/receiver/receiver.c
index 927818c..7d90060 100644
--- a/memref-test/receiver/receiver.c
+++ b/memref-test/receiver/receiver.c
@@ -100,7 +100,11 @@ static int receiver_on_message(const struct tipc_port* port,
         strcpy(&out[skip * page_size], "Hello from Trusty!");
     }
 
-    munmap((void*)out, page_size * num_pages);
+    rc = munmap((void*)out, page_size * num_pages);
+    if (rc != NO_ERROR) {
+        TLOGE("munmap() failed: %d\n", rc);
+        return rc;
+    }
 
     close(handle);
 
diff --git a/rust_no_std/main.rs b/rust_no_std/main.rs
index 13a76e7..da20c31 100644
--- a/rust_no_std/main.rs
+++ b/rust_no_std/main.rs
@@ -28,7 +28,7 @@ use trusty_std::alloc::{FallibleVec, Vec};
 
 #[start]
 fn start(_argc: isize, _argv: *const *const u8) -> isize {
-    Vec::<u8>::try_with_capacity(128).unwrap();
+    <Vec<u8> as FallibleVec<u8>>::try_with_capacity(128).unwrap();
 
     let message = b"Hello from no_std Rust!\n";
     unsafe {
diff --git a/stats-test/consumer/consumer.cpp b/stats-test/consumer/consumer.cpp
index b16ae54..6c74ebf 100644
--- a/stats-test/consumer/consumer.cpp
+++ b/stats-test/consumer/consumer.cpp
@@ -202,7 +202,10 @@ static int test_ctl_on_message(const tipc_port* port,
         break;
     case CONSUMER_CTL_SHM_RECLAIM:
         if (ctx->shm_ptr) {
-            munmap((void*)ctx->shm_ptr, page_size);
+            int rc = munmap((void*)ctx->shm_ptr, page_size);
+            if (rc != NO_ERROR) {
+                TLOGW("munmap() failed: %d\n", rc);
+            }
             ctx->shm_ptr = nullptr;
         }
         break;
diff --git a/usertests-inc.mk b/usertests-inc.mk
index b5ac413..70655aa 100644
--- a/usertests-inc.mk
+++ b/usertests-inc.mk
@@ -16,13 +16,11 @@
 include trusty/user/app/sample/stats-test/usertests-inc.mk
 
 TRUSTY_USER_TESTS += \
-	trusty/user/app/sample/hwcryptohal/server/app \
 	trusty/user/app/sample/app-mgmt-test/client\
 	trusty/user/app/sample/binder-test/client \
 	trusty/user/app/sample/binder-test/service \
 	trusty/user/app/sample/hwcrypto-unittest \
 	trusty/user/app/sample/hwrng-unittest \
-	trusty/user/app/sample/hwrng-bench \
 	trusty/user/app/sample/manifest-test \
 	trusty/user/app/sample/memref-test \
 	trusty/user/app/sample/memref-test/lender \
@@ -34,7 +32,13 @@ TRUSTY_USER_TESTS += \
 	trusty/user/app/sample/skel2 \
 	trusty/user/app/sample/rust_no_std \
 
+ifneq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_USER_TESTS += \
+	trusty/user/app/sample/hwrng-bench
+endif
+
 TRUSTY_RUST_USER_TESTS += \
+	trusty/user/app/sample/hwcryptohal/common \
 	trusty/user/app/sample/hwcryptohal/server \
 	trusty/user/app/sample/hwcryptokey-test \
 	trusty/user/app/sample/memref-test/rust \
```

