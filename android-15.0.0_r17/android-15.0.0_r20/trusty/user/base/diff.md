```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..4d289e9
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_base",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/app/line-coverage/coverage.h b/app/line-coverage/coverage.h
index 55dfc45..300ff6a 100644
--- a/app/line-coverage/coverage.h
+++ b/app/line-coverage/coverage.h
@@ -23,8 +23,8 @@
 #include <string.h>
 #include <trusty/uuid.h>
 
-/* Assume we have no more than 64 TAs running at the same time */
-#define MAX_NUM_APPS 64
+/* Assume we have no more than 128 TAs running at the same time */
+#define MAX_NUM_APPS 128
 
 /**
  * struct srv_state - global state of the coverage server
diff --git a/app/metrics/client.h b/app/metrics/client.h
index 96f2284..2efcd08 100644
--- a/app/metrics/client.h
+++ b/app/metrics/client.h
@@ -16,11 +16,17 @@
 
 #pragma once
 
+#include <interface/metrics/metrics.h>
 #include <lib/tipc/tipc_srv.h>
 #include <string.h>
 
 __BEGIN_CDECLS
 
+struct metrics_crash_msg {
+    struct metrics_req req;
+    struct metrics_report_crash_req crash_args;
+} __attribute__((__packed__));
+
 /**
  * struct srv_state - global state of the metrics TA
  * @ns_handle:              Channel corresponding to Android metrics_d
diff --git a/app/metrics/consumer.c b/app/metrics/consumer.c
index 5ce6b88..e72363e 100644
--- a/app/metrics/consumer.c
+++ b/app/metrics/consumer.c
@@ -21,6 +21,7 @@
 #include <lib/tipc/tipc.h>
 #include <lib/tipc/tipc_srv.h>
 #include <metrics_consts.h>
+#include <openssl/sha.h>
 #include <stddef.h>
 #include <string.h>
 #include <trusty_log.h>
@@ -59,18 +60,50 @@ static int on_connect(const struct tipc_port* port,
     return NO_ERROR;
 }
 
+void hash_trusty_metrics(uint64_t metric, char *app_id, uint8_t *output) {
+
+    const unsigned char CONST_SALT[] = {
+    0xf2, 0xe7, 0x8c, 0x19, 0xa4, 0xd3, 0x5b, 0x68
+    };
+
+    /* Convert the metric to an array of uint8_t prepended with salt*/
+    uint8_t metric_arr[8 + UUID_STR_SIZE + sizeof(CONST_SALT)];
+
+    memcpy(metric_arr, app_id, UUID_STR_SIZE);
+    memcpy(metric_arr+UUID_STR_SIZE, CONST_SALT, sizeof(CONST_SALT));
+
+    for (size_t i = 0; i < 8; ++i) {
+        metric_arr[i+ UUID_STR_SIZE + sizeof(CONST_SALT)] = (metric >> (8 * i)) & 0xFF;
+    }
+
+    SHA512(metric_arr, sizeof(metric_arr), output);
+}
+
 static int on_message(const struct tipc_port* port, handle_t chan, void* ctx) {
     int rc;
     struct metrics_req req;
     uint8_t msg[METRICS_MAX_MSG_SIZE];
 
     memset(msg, 0, sizeof(msg));
-    int msg_size = tipc_recv1(chan, sizeof(req), msg, sizeof(msg));
+    int msg_size = tipc_recv1(chan, sizeof(req),  msg, sizeof(msg));
     if (msg_size < 0) {
         TLOGE("failed (%d) to receive metrics event\n", msg_size);
         return msg_size;
     }
 
+    uint32_t cmd;
+    cmd = ((struct metrics_req*)msg)->cmd;
+
+    if(cmd == METRICS_CMD_REPORT_CRASH) {
+        struct metrics_crash_msg *crash_msg = (struct metrics_crash_msg *)msg;
+        if (crash_msg->crash_args.is_hash) {
+            hash_trusty_metrics(crash_msg->crash_args.far, crash_msg->crash_args.app_id, crash_msg->crash_args.far_hash);
+            hash_trusty_metrics(crash_msg->crash_args.elr, crash_msg->crash_args.app_id, crash_msg->crash_args.elr_hash);
+            crash_msg->crash_args.far = 0;
+            crash_msg->crash_args.elr = 0;
+        }
+    }
+
     // Check if NS metricsd connected, if so forward it there.
     struct srv_state* state = get_srv_state(port);
     if(is_ns_connected(state)) {
@@ -84,8 +117,6 @@ static int on_message(const struct tipc_port* port, handle_t chan, void* ctx) {
         TLOGD("NS metrics daemon not connected\n");
     }
 
-    uint32_t cmd;
-    cmd = ((struct metrics_req*)msg)->cmd;
     struct metrics_resp resp = {
         .cmd = (cmd | METRICS_CMD_RESP_BIT)
     };
diff --git a/app/metrics/manifest.json b/app/metrics/manifest.json
index 62c33a0..51bc935 100644
--- a/app/metrics/manifest.json
+++ b/app/metrics/manifest.json
@@ -1,5 +1,19 @@
 {
     "uuid": "METRICS_UUID",
     "min_heap": 8192,
-    "min_stack": 8192
+    "min_stack": 8192,
+    "mgmt_flags": {
+        "restart_on_exit": true,
+        "deferred_start": true,
+        "non_critical_app" : true
+    },
+    "start_ports": [
+        {
+            "name": "com.android.trusty.metrics.consumer",
+            "flags": {
+                "allow_ta_connect": true,
+                "allow_ns_connect": true
+            }
+        }
+    ]
 }
diff --git a/app/metrics/rules.mk b/app/metrics/rules.mk
index d2963a3..6906735 100644
--- a/app/metrics/rules.mk
+++ b/app/metrics/rules.mk
@@ -25,11 +25,13 @@ MODULE_SRCS := \
 	$(LOCAL_DIR)/main.cpp \
 
 MODULE_LIBRARY_DEPS += \
+	external/boringssl \
 	trusty/kernel/lib/shared/binder_discover \
 	trusty/user/base/lib/libc-trusty \
 	trusty/user/base/lib/libstdc++-trusty \
 	trusty/user/base/lib/metrics_atoms \
 	trusty/user/base/lib/tipc \
+	trusty/user/base/lib/unittest \
 	trusty/user/base/interface/metrics \
 
 include make/trusted_app.mk
diff --git a/experimental/lib/tidl/include/lib/tidl/tidl.h b/experimental/lib/tidl/include/lib/tidl/tidl.h
index 5f7af19..e230c89 100644
--- a/experimental/lib/tidl/include/lib/tidl/tidl.h
+++ b/experimental/lib/tidl/include/lib/tidl/tidl.h
@@ -87,7 +87,7 @@ struct TIDL_PACKED_ATTR ResponseHeader {
 #if !defined(__QL_TIPC__)
 class TIDL_PACKED_ATTR ParcelFileDescriptor {
 public:
-    android::base::unique_fd handle;
+    TIDL_PACKED_ATTR android::base::unique_fd handle;
 
     // Handle methods
     static constexpr uint32_t num_handles = 1;
diff --git a/host/unittest/get_current_time_ns.c b/host/unittest/get_current_time_ns.c
new file mode 100644
index 0000000..71a8deb
--- /dev/null
+++ b/host/unittest/get_current_time_ns.c
@@ -0,0 +1,24 @@
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
+#include <stdint.h>
+#include <time.h>
+
+uint64_t get_current_time_ns(void) {
+    struct timespec ts;
+    clock_gettime(CLOCK_BOOTTIME, &ts);
+    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
+}
diff --git a/host/unittest/rules.mk b/host/unittest/rules.mk
new file mode 100644
index 0000000..d197a27
--- /dev/null
+++ b/host/unittest/rules.mk
@@ -0,0 +1,23 @@
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
+HOST_LIB_NAME := unittest
+
+HOST_LIB_SRCS := \
+	$(LOCAL_DIR)/get_current_time_ns.c \
+
+include make/host_lib.mk
diff --git a/interface/metrics/include/interface/metrics/metrics.h b/interface/metrics/include/interface/metrics/metrics.h
index 7aec213..a0b3491 100644
--- a/interface/metrics/include/interface/metrics/metrics.h
+++ b/interface/metrics/include/interface/metrics/metrics.h
@@ -48,6 +48,8 @@
 
 #define METRICS_PORT "com.android.trusty.metrics"
 
+#define HASH_SIZE_BYTES 64
+
 /**
  * enum metrics_cmd - command identifiers for metrics interface
  * @METRICS_CMD_RESP_BIT:             message is a response
@@ -117,10 +119,22 @@ struct metrics_report_exit_req {
  *          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  * @crash_reason: architecture-specific code representing the reason for the
  *                crash
+ * @far: Fault Address Register corresponding to the crash. It is set to 0 and
+ *       not always revealed
+ * @far_hash: Fault Address Register obfuscated, always revealed
+ * @elr: Exception Link Register corresponding to the crash. It is set to 0 and
+ *       not always revealed
+ * @elr_hash: Exception Link Register obfuscated, always revealed
+ * @is_hash: Boolean value indicating whether far and elr have been ob
  */
 struct metrics_report_crash_req {
     char app_id[UUID_STR_SIZE];
     uint32_t crash_reason;
+    uint64_t far;
+    uint8_t far_hash[HASH_SIZE_BYTES];
+    uint64_t elr;
+    uint8_t elr_hash[HASH_SIZE_BYTES];
+    bool is_hash;
 } __attribute__((__packed__));
 
 #define METRICS_MAX_APP_ID_LEN 256
diff --git a/interface/secure_storage/cpp/rules.mk b/interface/secure_storage/cpp/rules.mk
index aa808e3..9ea21a2 100644
--- a/interface/secure_storage/cpp/rules.mk
+++ b/interface/secure_storage/cpp/rules.mk
@@ -16,11 +16,12 @@
 LOCAL_DIR := $(GET_LOCAL_DIR)
 
 AIDL_DIR := \
-	hardware/interfaces/staging/security/see/storage/aidl
+	hardware/interfaces/security/see/storage/aidl/aidl_api/android.hardware.security.see.storage/current
 
 MODULE := $(LOCAL_DIR)
 
-MODULE_AIDL_FLAGS :=
+MODULE_AIDL_FLAGS := \
+	--stability=vintf \
 
 MODULE_AIDL_LANGUAGE := cpp
 
diff --git a/interface/secure_storage/rust/rules.mk b/interface/secure_storage/rust/rules.mk
index 49836ce..740616b 100644
--- a/interface/secure_storage/rust/rules.mk
+++ b/interface/secure_storage/rust/rules.mk
@@ -16,11 +16,12 @@
 LOCAL_DIR := $(GET_LOCAL_DIR)
 
 AIDL_DIR := \
-	hardware/interfaces/staging/security/see/storage/aidl
+	hardware/interfaces/security/see/storage/aidl/aidl_api/android.hardware.security.see.storage/current
 
 MODULE := $(LOCAL_DIR)
 
-MODULE_AIDL_FLAGS :=
+MODULE_AIDL_FLAGS := \
+	--stability=vintf \
 
 MODULE_AIDL_LANGUAGE := rust
 
diff --git a/lib/bssl-sys-rust/rules.mk b/lib/bssl-sys-rust/rules.mk
index 06eab03..c581390 100644
--- a/lib/bssl-sys-rust/rules.mk
+++ b/lib/bssl-sys-rust/rules.mk
@@ -56,8 +56,13 @@ MODULE_BINDGEN_FLAGS += \
 	--blocklist-function="OPENSSL_vasprintf" \
 
 # bssl-sys expects the bindgen output to be placed in BINDGEN_RS_FILE.
+# TODO: Remove MODULE_BINDGEN_OUTPUT_ENV_VAR once
+# https://boringssl-review.googlesource.com/c/boringssl/+/72487 rolls
+# to AOSP.
 MODULE_BINDGEN_OUTPUT_ENV_VAR := BINDGEN_RS_FILE
 
+MODULE_BINDGEN_OUTPUT_FILE_NAME := bindgen
+
 MODULE_INCLUDES += \
 	$(BSSL_SRC_DIR)/include \
 
diff --git a/lib/hwbcc/common/swbcc.c b/lib/hwbcc/common/swbcc.c
index a0af7e2..e7af267 100644
--- a/lib/hwbcc/common/swbcc.c
+++ b/lib/hwbcc/common/swbcc.c
@@ -50,7 +50,7 @@ struct dice_root_state {
     /* Unique Device Secret - A hardware backed secret */
     uint8_t UDS[DICE_CDI_SIZE];
     /* Public key of the key pair derived from a seed derived from UDS. */
-    uint8_t UDS_pub_key[DICE_PUBLIC_KEY_SIZE];
+    uint8_t UDS_pub_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
     /* Secret (of size: DICE_HIDDEN_SIZE) with factory reset life time. */
     uint8_t FRS[DICE_HIDDEN_SIZE];
     /**
@@ -87,12 +87,12 @@ static int dice_result_to_err(DiceResult result) {
 
 struct swbcc_session {
     uint8_t key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
-    uint8_t pub_key[DICE_PUBLIC_KEY_SIZE];
-    uint8_t priv_key[DICE_PRIVATE_KEY_SIZE];
+    uint8_t pub_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+    uint8_t priv_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
 
     uint8_t test_key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
-    uint8_t test_pub_key[DICE_PUBLIC_KEY_SIZE];
-    uint8_t test_priv_key[DICE_PRIVATE_KEY_SIZE];
+    uint8_t test_pub_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
+    uint8_t test_priv_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
 
     struct uuid client_uuid;
 };
@@ -191,10 +191,10 @@ int swbcc_glob_init(const uint8_t FRS[DICE_HIDDEN_SIZE],
      * the certificate chain for the child nodes. UDS private key is derived in
      * every DICE operation which uses it.
      */
-    uint8_t UDS_private_key[DICE_PRIVATE_KEY_SIZE];
-    result = DiceKeypairFromSeed(NULL, private_key_seed,
-                                 srv_state.dice_root.UDS_pub_key,
-                                 UDS_private_key);
+    uint8_t UDS_private_key[DICE_PRIVATE_KEY_BUFFER_SIZE];
+    result = DiceKeypairFromSeed(
+            NULL, kDicePrincipalAuthority, private_key_seed,
+            srv_state.dice_root.UDS_pub_key, UDS_private_key);
 
     rc = dice_result_to_err(result);
     if (rc != NO_ERROR) {
@@ -257,8 +257,9 @@ int swbcc_init(swbcc_session_t* s, const struct uuid* client) {
         goto err;
     }
 
-    result = DiceKeypairFromSeed(srv_state.dice_ctx, session->key_seed,
-                                 session->pub_key, session->priv_key);
+    result = DiceKeypairFromSeed(srv_state.dice_ctx, kDicePrincipalSubject,
+                                 session->key_seed, session->pub_key,
+                                 session->priv_key);
     rc = dice_result_to_err(result);
     if (rc != NO_ERROR) {
         TLOGE("Failed to generate keypair: %d\n", rc);
@@ -272,8 +273,9 @@ int swbcc_init(swbcc_session_t* s, const struct uuid* client) {
         goto err;
     }
 
-    result = DiceKeypairFromSeed(srv_state.dice_ctx, session->test_key_seed,
-                                 session->test_pub_key, session->test_priv_key);
+    result = DiceKeypairFromSeed(srv_state.dice_ctx, kDicePrincipalSubject,
+                                 session->test_key_seed, session->test_pub_key,
+                                 session->test_priv_key);
     rc = dice_result_to_err(result);
     if (rc != NO_ERROR) {
         TLOGE("Failed to generate test keypair: %d\n", rc);
@@ -445,8 +447,9 @@ int swbcc_get_bcc(swbcc_session_t s,
     *bcc_size = bcc_used;
 
     /* Encode first entry in the array which is a COSE_Key */
-    result = DiceCoseEncodePublicKey(srv_state.dice_ctx, pub_key, bcc_buf_size,
-                                     bcc, &bcc_used);
+    result =
+            DiceCoseEncodePublicKey(srv_state.dice_ctx, kDicePrincipalAuthority,
+                                    pub_key, bcc_buf_size, bcc, &bcc_used);
     rc = dice_result_to_err(result);
     if (rc != NO_ERROR) {
         TLOGE("Failed to encode public key: %d\n", rc);
diff --git a/lib/keymint-rust/wire/rules.mk b/lib/keymint-rust/wire/rules.mk
index c96467b..052a273 100644
--- a/lib/keymint-rust/wire/rules.mk
+++ b/lib/keymint-rust/wire/rules.mk
@@ -24,6 +24,7 @@ MODULE_CRATE_NAME := kmr_wire
 MODULE_RUSTFLAGS += \
 	--cfg 'feature="hal_v2"' \
 	--cfg 'feature="hal_v3"' \
+	--cfg 'feature="hal_v4"' \
 
 MODULE_LIBRARY_EXPORTED_DEPS += \
 	$(call FIND_CRATE,enumn) \
diff --git a/lib/libc-trusty/test/libc_test.c b/lib/libc-trusty/test/libc_test.c
index 84c51c4..527dbe2 100644
--- a/lib/libc-trusty/test/libc_test.c
+++ b/lib/libc-trusty/test/libc_test.c
@@ -882,6 +882,20 @@ TEST_F(libc, UnsignedOverflowMacros) {
 
 #define TEST_BUF_SIZE 64
 
+TEST_F(libc, PrepareDmaInvalidArgs) {
+    uint8_t buf[TEST_BUF_SIZE] = {0};
+    struct dma_pmem dma;
+
+    /* Zero size is invalid */
+    int rc = prepare_dma(buf, 0, DMA_FLAG_TO_DEVICE, &dma);
+    EXPECT_EQ(ERR_INVALID_ARGS, rc);
+
+    /* No struct dma_pmem should not be passed with NO_PMEM */
+    rc = prepare_dma(buf, TEST_BUF_SIZE, DMA_FLAG_TO_DEVICE | DMA_FLAG_NO_PMEM,
+                     &dma);
+    EXPECT_EQ(ERR_INVALID_ARGS, rc);
+}
+
 TEST_F(libc, PrepareDmaFailsOnMultipleCalls) {
     uint8_t buf[TEST_BUF_SIZE] = {0};
     struct dma_pmem dma;
diff --git a/lib/metrics_atoms/rules.mk b/lib/metrics_atoms/rules.mk
index 95961a7..06b2739 100644
--- a/lib/metrics_atoms/rules.mk
+++ b/lib/metrics_atoms/rules.mk
@@ -21,7 +21,7 @@ MODULE := $(LOCAL_DIR)
 # the build output. Otherwise, run the source script directly.
 PROTOC_PLUGIN_SOURCE := \
 	trusty/host/common/scripts/metrics_atoms_protoc_plugin/metrics_atoms_protoc_plugin.py
-PROTOC_PLUGIN_BINARY := \
+PROTOC_PLUGIN_BINARY ?= \
 	out/host/linux-x86/bin/trusty_metrics_atoms_protoc_plugin
 MODULE_PROTOC_PLUGIN := \
 	$(if $(wildcard $(PROTOC_PLUGIN_BINARY)),$(PROTOC_PLUGIN_BINARY),$(PROTOC_PLUGIN_SOURCE))
diff --git a/lib/openssl-rust/rules.mk b/lib/openssl-rust/rules.mk
index e4772cb..132fd81 100644
--- a/lib/openssl-rust/rules.mk
+++ b/lib/openssl-rust/rules.mk
@@ -17,12 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-# temporarily handle both old and new crate paths (b/266828817)
-ifneq ($(wildcard external/rust/crates/openssl/.*),)
-SRC_DIR := external/rust/crates/openssl
-else
-SRC_DIR := external/rust/crates/rust-openssl/openssl
-endif
+SRC_DIR := $(dir $(firstword $(wildcard external/rust/android-crates-io/crates/openssl/.* external/rust/crates/openssl/.* external/rust/crates/rust-openssl/openssl/.*)))
 
 MODULE_SRCS := $(SRC_DIR)/src/lib.rs
 
diff --git a/lib/pmu/aarch64 b/lib/pmu/aarch64
deleted file mode 120000
index 9adaa1c..0000000
--- a/lib/pmu/aarch64
+++ /dev/null
@@ -1 +0,0 @@
-../../../../kernel/lib/pmu/aarch64
\ No newline at end of file
diff --git a/lib/sancov/exemptlist b/lib/sancov/exemptlist
index 81ff69c..c4cd5b4 100644
--- a/lib/sancov/exemptlist
+++ b/lib/sancov/exemptlist
@@ -30,3 +30,8 @@ src:trusty/kernel/lib/unittest/*
 
 # NB: Be careful not to exclude trusty/user/base/lib/sancov/test/*. We need it
 # to be instrumented.
+
+# These fail to link with with clang 18+ with undefined symbol __sancov_gen_.*
+# Not sure why. Disable them for now.
+fun:*EventListener*
+fun:*GetNotDefaultOrNull*
diff --git a/lib/storage/storage.c b/lib/storage/storage.c
index 1a202b6..9f61f9f 100644
--- a/lib/storage/storage.c
+++ b/lib/storage/storage.c
@@ -258,6 +258,7 @@ ssize_t send_reqv(storage_session_t session,
 int storage_open_session(storage_session_t* session_p, const char* type) {
     long rc = connect(type, IPC_CONNECT_WAIT_FOR_PORT);
     if (rc < 0) {
+        *session_p = STORAGE_INVALID_SESSION;
         return rc;
     }
 
@@ -283,6 +284,8 @@ int storage_open_file(storage_session_t session,
     struct storage_file_open_resp rsp = {0};
     struct iovec rx[2] = {{&msg, sizeof(msg)}, {&rsp, sizeof(rsp)}};
 
+    *handle_p = make_file_handle(STORAGE_INVALID_SESSION, 0);
+
     ssize_t rc = send_reqv(session, tx, 3, rx, 2);
     rc = check_response(&msg, rc);
     if (rc < 0)
@@ -369,6 +372,7 @@ int storage_open_dir(storage_session_t session,
     struct storage_file_list_resp* resp;
 
     if (path && strlen(path)) {
+        *state = NULL;
         return ERR_NOT_FOUND; /* current server does not support directories */
     }
     *state = malloc(sizeof(**state));
@@ -600,6 +604,8 @@ int storage_get_file_size(file_handle_t fh, storage_off_t* size_p) {
     struct storage_file_get_size_resp rsp;
     struct iovec rx[2] = {{&msg, sizeof(msg)}, {&rsp, sizeof(rsp)}};
 
+    *size_p = 0;
+
     ssize_t rc = send_reqv(_to_session(fh), tx, 2, rx, 2);
     rc = check_response(&msg, rc);
     if (rc < 0)
diff --git a/lib/tipc/rust/rules.mk b/lib/tipc/rust/rules.mk
index 235583e..54873e0 100644
--- a/lib/tipc/rust/rules.mk
+++ b/lib/tipc/rust/rules.mk
@@ -26,8 +26,11 @@ MODULE_SDK_LIB_NAME := tipc-rust
 MODULE_INCLUDES += \
 	trusty/user/base/lib/tipc/test/include \
 
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,zerocopy) \
+
 MODULE_LIBRARY_EXPORTED_DEPS += \
-	external/rust/crates/arrayvec \
+	$(call FIND_CRATE,arrayvec) \
 	trusty/user/base/lib/libc-trusty \
 	$(call FIND_CRATE,log) \
 	trusty/user/base/lib/trusty-std \
diff --git a/lib/tipc/rust/src/serialization.rs b/lib/tipc/rust/src/serialization.rs
index d631824..f36dec4 100644
--- a/lib/tipc/rust/src/serialization.rs
+++ b/lib/tipc/rust/src/serialization.rs
@@ -1,6 +1,7 @@
 use crate::{Handle, TipcError};
 use core::fmt::Debug;
 use core::{mem, slice};
+use zerocopy::AsBytes;
 
 /// A helper provided by the transport handle for the message type to serialize
 /// into.
@@ -52,18 +53,22 @@ pub trait Serialize<'s> {
     ) -> Result<S::Ok, S::Error>;
 }
 
-impl<'s> Serialize<'s> for u32 {
-    fn serialize<'a: 's, S: Serializer<'s>>(
-        &'a self,
-        serializer: &mut S,
-    ) -> Result<S::Ok, S::Error> {
-        // SAFETY:
-        //  u32 is a trivial type with a
-        //  corresponding C representation
-        unsafe { serializer.serialize_as_bytes(self) }
-    }
+macro_rules! impl_numeric_serialize {
+    ($($t:ty),* $(,)?) => {$(
+        impl<'s> Serialize<'s> for $t {
+            fn serialize<'a: 's, S: Serializer<'s>>(
+                &'a self,
+                serializer: &mut S,
+            ) -> Result<S::Ok, S::Error> {
+                serializer.serialize_bytes(self.as_bytes())
+            }
+        }
+    )*}
 }
 
+// usize/isize are excluded as they have platform-dependent sizes.
+impl_numeric_serialize!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, f32, f64);
+
 impl<'s> Serialize<'s> for &'s [u8] {
     fn serialize<'a: 's, S: Serializer<'s>>(
         &'a self,
diff --git a/lib/tipc/rust/src/service.rs b/lib/tipc/rust/src/service.rs
index 3bd6682..41d51f9 100644
--- a/lib/tipc/rust/src/service.rs
+++ b/lib/tipc/rust/src/service.rs
@@ -789,7 +789,7 @@ impl<S: UnbufferedService> Dispatcher for SingleUnbufferedDispatcher<S> {
 /// ```
 #[macro_export]
 macro_rules! service_dispatcher {
-    (enum $name:ident $(<$elt: lifetime>)? {$($service:ident $(<$slt: lifetime>)? ),+ $(,)*}) => {
+    ($vis:vis enum $name:ident $(<$elt: lifetime>)? {$($service:ident $(<$slt: lifetime>)? ),+ $(,)*}) => {
         /// Dispatcher that routes incoming messages to the correct server based on what
         /// port the message was sent to.
         ///
@@ -797,20 +797,20 @@ macro_rules! service_dispatcher {
         /// message formats for the same [`Manager`]. By using this dispatcher,
         /// different servers can be bound to different ports using the same event loop
         /// in the manager.
-        struct $name<$($elt,)? const PORT_COUNT: usize> {
+        $vis struct $name<$($elt,)? const PORT_COUNT: usize> {
             ports: arrayvec::ArrayVec::<$crate::PortCfg, PORT_COUNT>,
             services: arrayvec::ArrayVec::<ServiceKind$(<$elt>)?, PORT_COUNT>,
         }
 
         impl<$($elt,)? const PORT_COUNT: usize> $name<$($elt,)? PORT_COUNT> {
-            fn new() -> $crate::Result<Self> {
+            pub fn new() -> $crate::Result<Self> {
                 Ok(Self {
                     ports: arrayvec::ArrayVec::<_, PORT_COUNT>::new(),
                     services: arrayvec::ArrayVec::<_, PORT_COUNT>::new(),
                 })
             }
 
-            fn add_service<T>(&mut self, service: alloc::rc::Rc<T>, port: $crate::PortCfg) -> $crate::Result<()>
+            pub fn add_service<T>(&mut self, service: alloc::rc::Rc<T>, port: $crate::PortCfg) -> $crate::Result<()>
             where ServiceKind$(<$elt>)? : From<alloc::rc::Rc<T>> {
                 if self.ports.is_full() || self.services.is_full() {
                     return Err($crate::TipcError::OutOfBounds);
@@ -824,7 +824,7 @@ macro_rules! service_dispatcher {
             }
         }
 
-        enum ServiceKind$(<$elt>)? {
+        $vis enum ServiceKind$(<$elt>)? {
             $($service(alloc::rc::Rc<$service$(<$slt>)?>)),+
         }
 
@@ -836,7 +836,7 @@ macro_rules! service_dispatcher {
             }
         )+
 
-        enum ConnectionKind$(<$elt>)?  {
+        $vis enum ConnectionKind$(<$elt>)?  {
             $($service(<$service$(<$slt>)? as $crate::UnbufferedService>::Connection)),+
         }
 
@@ -1207,8 +1207,8 @@ mod test {
     use super::{PortCfg, Service};
     use crate::handle::test::{first_free_handle_index, MAX_USER_HANDLES};
     use crate::{
-        ConnectResult, Deserialize, Handle, Manager, MessageResult, Result, Serialize, Serializer,
-        TipcError, UnbufferedService, Uuid,
+        ConnectResult, Deserialize, Handle, Manager, MessageResult, Result, TipcError,
+        UnbufferedService, Uuid,
     };
     use test::{expect, expect_eq};
     use trusty_std::alloc::FallibleVec;
@@ -1376,15 +1376,6 @@ mod test {
         }
     }
 
-    impl<'s> Serialize<'s> for i32 {
-        fn serialize<'a: 's, S: Serializer<'s>>(
-            &'a self,
-            serializer: &mut S,
-        ) -> core::result::Result<S::Ok, S::Error> {
-            unsafe { serializer.serialize_as_bytes(self) }
-        }
-    }
-
     impl Deserialize for i32 {
         type Error = TipcError;
 
@@ -1539,7 +1530,7 @@ mod multiservice_with_lifetimes_tests {
 
     const SRV_PATH_BASE: &str = "com.android.ipc-unittest-lifetimes";
 
-    struct Service1<'a> {
+    pub(crate) struct Service1<'a> {
         phantom: PhantomData<&'a u32>,
     }
 
@@ -1567,7 +1558,7 @@ mod multiservice_with_lifetimes_tests {
         }
     }
 
-    struct Service2<'a> {
+    pub(crate) struct Service2<'a> {
         phantom: PhantomData<&'a u32>,
     }
 
@@ -1596,7 +1587,7 @@ mod multiservice_with_lifetimes_tests {
     }
 
     service_dispatcher! {
-        enum TestServiceLifetimeDispatcher<'a> {
+        pub(crate) enum TestServiceLifetimeDispatcher<'a> {
             Service1<'a>,
             Service2<'a>,
         }
diff --git a/lib/trusty-std/src/lib.rs b/lib/trusty-std/src/lib.rs
index 1474261..5406172 100644
--- a/lib/trusty-std/src/lib.rs
+++ b/lib/trusty-std/src/lib.rs
@@ -32,12 +32,13 @@
 #![feature(allocator_api)]
 #![feature(alloc_error_handler)]
 #![feature(alloc_layout_extra)]
+#![feature(cfg_version)]
 #![feature(core_intrinsics)]
 // min_specialization is only used to optimize CString::try_new(), so we can
 // remove it if needed
 #![feature(min_specialization)]
 #![feature(new_uninit)]
-#![feature(panic_info_message)]
+#![cfg_attr(not(version("1.81")), feature(panic_info_message))]
 #![feature(slice_internals)]
 #![feature(slice_ptr_get)]
 
diff --git a/lib/unittest-rust/src/lib.rs b/lib/unittest-rust/src/lib.rs
index 693c299..116c863 100644
--- a/lib/unittest-rust/src/lib.rs
+++ b/lib/unittest-rust/src/lib.rs
@@ -32,6 +32,7 @@
 //! # Trusty Rust Testing Framework
 
 use core::cell::RefCell;
+use libc::{clock_gettime, CLOCK_BOOTTIME};
 use log::{Log, Metadata, Record};
 use tipc::{
     ConnectResult, Handle, Manager, MessageResult, PortCfg, Serialize, Serializer, Service, Uuid,
@@ -59,6 +60,15 @@ extern "Rust" {
     static TEST_PORT: &'static str;
 }
 
+fn get_time_ns() -> u64 {
+    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
+
+    // Safety: Passing valid pointer to variable ts which lives past end of call
+    unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts) };
+
+    ts.tv_sec as u64 * 1_000_000_000u64 + ts.tv_nsec as u64
+}
+
 /// Initialize a test service for this crate.
 ///
 /// Including an invocation of this macro exactly once is required to configure a
@@ -180,6 +190,10 @@ fn print_status(test: &TestDesc, msg: &str) {
     log::info!("[ {} ] {}", msg, test.name);
 }
 
+fn print_status_with_duration(test: &TestDesc, msg: &str, duration_ms: u64) {
+    log::info!("[ {} ] {} ({} ms)", msg, test.name, duration_ms);
+}
+
 struct TestService {
     tests: Vec<TestDescAndFn>,
 }
@@ -302,14 +316,18 @@ impl Service for TestService {
     ) -> tipc::Result<ConnectResult<Self::Connection>> {
         LOGGER.connect(handle)?;
 
+        log::info!("[==========] Running {} tests from 1 test suite.\n", self.tests.len());
+
         let mut passed_tests = 0;
         let mut failed_tests = 0;
         let mut skipped_tests = 0;
         let mut total_ran = 0;
+        let mut total_duration_ms = 0;
         for test in &self.tests {
             CONTEXT.reset();
             total_ran += 1;
             print_status(&test.desc, "RUN     ");
+            let start_time_ns = get_time_ns();
             match test.testfn {
                 StaticTestFn(f) => f(),
                 StaticBenchFn(f) => {
@@ -318,14 +336,16 @@ impl Service for TestService {
                 }
                 _ => panic!("non-static tests passed to test::test_main_static"),
             }
+            let duration_ms = (get_time_ns() - start_time_ns) / 1_000_000u64;
+            total_duration_ms += duration_ms;
             if CONTEXT.skipped() {
-                print_status(&test.desc, " SKIPPED");
+                print_status_with_duration(&test.desc, " SKIPPED", duration_ms);
                 skipped_tests += 1;
             } else if CONTEXT.all_ok() {
-                print_status(&test.desc, "      OK");
+                print_status_with_duration(&test.desc, "      OK", duration_ms);
                 passed_tests += 1;
             } else {
-                print_status(&test.desc, " FAILED ");
+                print_status_with_duration(&test.desc, " FAILED ", duration_ms);
                 failed_tests += 1;
             }
             if CONTEXT.hard_fail() {
@@ -333,7 +353,7 @@ impl Service for TestService {
             }
         }
 
-        log::info!("[==========] {} tests ran.", total_ran);
+        log::info!("[==========] {} tests ran ({} ms total).", total_ran, total_duration_ms);
         if passed_tests > 0 {
             log::info!("[  PASSED  ] {} tests.", passed_tests);
         }
diff --git a/lib/unittest/include/lib/unittest/unittest.h b/lib/unittest/include/lib/unittest/unittest.h
index c68e098..e4ef1b0 100644
--- a/lib/unittest/include/lib/unittest/unittest.h
+++ b/lib/unittest/include/lib/unittest/unittest.h
@@ -21,14 +21,6 @@
 #include <stdbool.h>
 #include <trusty_ipc.h>
 
-/*
- * This function returns a time in nanoseconds based on hardware counters
- * it is expected to:
- *  - Be non-wrapping or have very long (years) roll-over period
- *  - Have a resolution below 100ns
- */
-uint64_t get_current_time_ns(void);
-
 #define PORT_TEST(suite_name, port_name_string)           \
     __BEGIN_CDECLS                                        \
     static bool run_##suite_name(struct unittest* test) { \
diff --git a/make/aidl.mk b/make/aidl.mk
index 665b219..e2e082b 100644
--- a/make/aidl.mk
+++ b/make/aidl.mk
@@ -63,7 +63,7 @@ endif
 
 MODULE_AIDL_INCLUDES ?=
 AIDL_SRCS := $(call TOBUILDDIR,$(patsubst %.aidl,%.$(AIDL_EXT),$(MODULE_AIDLS)))
-AIDL_RUST_GLUE_TOOL := system/tools/aidl/build/aidl_rust_glue.py
+AIDL_RUST_GLUE_TOOL ?= system/tools/aidl/build/aidl_rust_glue.py
 MODULE_AIDL_INCLUDES += $(foreach dir,$(sort $(foreach src,$(MODULE_AIDLS),$(call GET_AIDL_PACKAGE_ROOT,$(src)))), -I $(patsubst %/,%,$(dir)))
 
 # TODO: support multiple, disparate packages; for AIDL interfaces with package paths,
@@ -123,8 +123,8 @@ $(AIDL_ROOT_RS): $(AIDL_SRCS)
 
 MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust \
-	external/rust/crates/async-trait \
-	external/rust/crates/lazy_static \
+	$(call FIND_CRATE,async-trait) \
+	$(call FIND_CRATE,lazy_static) \
 
 # The AIDL compiler marks an aidl_data variable as mutable and rustc complains
 MODULE_RUSTFLAGS += -Aunused-mut -Aunused-variables
@@ -146,5 +146,4 @@ AIDL_EXT :=
 AIDL_HEADER_DIR :=
 AIDL_SRCS :=
 AIDL_TOOL :=
-AIDL_RUST_GLUE_TOOL :=
 AIDL_ROOT_RS :=
diff --git a/make/bindgen.mk b/make/bindgen.mk
index e31d44c..596d8de 100644
--- a/make/bindgen.mk
+++ b/make/bindgen.mk
@@ -28,6 +28,7 @@
 # MODULE_BINDGEN_FLAGS
 # MODULE_BINDGEN_OUTPUT_ENV_VAR
 # MODULE_BINDGEN_SRC_HEADER
+# MODULE_BINDGEN_OUTPUT_FILE_NAME
 
 ifeq ($(strip $(MODULE_BINDGEN_SRC_HEADER)),)
 $(error $(MODULE): MODULE_BINDGEN_SRC_HEADER is required to use bindgen.mk)
@@ -35,7 +36,11 @@ endif
 
 BINDGEN := $(CLANG_TOOLS_BINDIR)/bindgen
 
+ifeq ($(strip $(MODULE_BINDGEN_OUTPUT_FILE_NAME)),)
 MODULE_BINDGEN_OUTPUT_FILE := $(call TOBUILDDIR,$(patsubst %.h,%.rs,$(MODULE_BINDGEN_SRC_HEADER)))
+else
+MODULE_BINDGEN_OUTPUT_FILE := $(call TOBUILDDIR,$(dir $(MODULE_BINDGEN_SRC_HEADER))$(MODULE_BINDGEN_OUTPUT_FILE_NAME).rs)
+endif
 
 # Trusty rust is all no_std
 ifeq ($(MODULE_IS_KERNEL),true)
@@ -65,17 +70,31 @@ endif
 
 -include $(MODULE_BINDGEN_OUTPUT_FILE).d
 
+MODULE_BINDGEN_DEFINES := $(MODULE_DEFINES)
+MODULE_BINDGEN_DEFINES += MODULE_BINDGEN_FLAGS=\"$(call clean_defines,$(MODULE_BINDGEN_FLAGS))\"
+MODULE_BINDGEN_DEFINES += BINDGEN_MODULE_COMPILEFLAGS=\"$(call clean_defines,$(BINDGEN_MODULE_COMPILEFLAGS))\"
+MODULE_BINDGEN_DEFINES += BINDGEN_MODULE_INCLUDES=\"$(call clean_defines,$(BINDGEN_MODULE_INCLUDES))\"
+
+MODULE_BINDGEN_CONFIG := $(call TOBUILDDIR,$(dir $(MODULE_BINDGEN_SRC_HEADER))/module_bindgen_config.h)
+$(MODULE_BINDGEN_CONFIG): MODULE_BINDGEN_DEFINES:=$(MODULE_BINDGEN_DEFINES)
+$(MODULE_BINDGEN_CONFIG): MODULE:=$(MODULE)
+$(MODULE_BINDGEN_CONFIG): configheader
+	@$(call INFO_DONE,$(MODULE),generating bindgen config header, $@)
+	@$(call MAKECONFIGHEADER,$@,MODULE_BINDGEN_DEFINES)
+
 $(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN := $(BINDGEN)
 $(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN_MODULE_COMPILEFLAGS := $(BINDGEN_MODULE_COMPILEFLAGS)
 $(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN_MODULE_INCLUDES := $(addprefix -I,$(MODULE_INCLUDES))
 $(MODULE_BINDGEN_OUTPUT_FILE): ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
 $(MODULE_BINDGEN_OUTPUT_FILE): DEFINES := $(addprefix -D,$(MODULE_DEFINES))
 $(MODULE_BINDGEN_OUTPUT_FILE): MODULE_BINDGEN_FLAGS := $(MODULE_BINDGEN_FLAGS)
-$(MODULE_BINDGEN_OUTPUT_FILE): $(MODULE_BINDGEN_SRC_HEADER) $(BINDGEN) $(MODULE_SRCDEPS) $(CONFIGHEADER)
+$(MODULE_BINDGEN_OUTPUT_FILE): RUSTFMT_PATH := $(RUST_BINDIR)/rustfmt
+$(MODULE_BINDGEN_OUTPUT_FILE): $(MODULE_BINDGEN_SRC_HEADER) $(BINDGEN) $(MODULE_SRCDEPS) $(CONFIGHEADER) $(MODULE_BINDGEN_CONFIG)
 	@$(MKDIR)
 	$(NOECHO)
 	CLANG_PATH=$(BINDGEN_CLANG_PATH) \
 	LIBCLANG_PATH=$(BINDGEN_LIBCLANG_PATH) \
+	RUSTFMT=$(RUSTFMT_PATH) \
 	$(BINDGEN) $< -o $@.tmp $(MODULE_BINDGEN_FLAGS) --depfile $@.d -- $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(BINDGEN_MODULE_COMPILEFLAGS) $(BINDGEN_MODULE_INCLUDES) $(GLOBAL_INCLUDES) $(DEFINES)
 	@$(call TESTANDREPLACEFILE,$@.tmp,$@)
 
@@ -84,14 +103,24 @@ MODULE_SRCDEPS += $(MODULE_BINDGEN_OUTPUT_FILE)
 ifeq ($(MODULE_BINDGEN_OUTPUT_ENV_VAR),)
 MODULE_BINDGEN_OUTPUT_ENV_VAR := BINDGEN_INC_FILE
 endif
-MODULE_RUST_ENV := $(MODULE_RUST_ENV) $(MODULE_BINDGEN_OUTPUT_ENV_VAR)=$(MODULE_BINDGEN_OUTPUT_FILE)
+
+# MODULE_BINDGEN_OUTPUT_ENV_VAR is not compatible with Soong as Soong does not allow
+# custom `envflags`. bindgen modules should resort to using `MODULE_BINDGEN_OUTPUT_FILE`
+# and `include!(concat!(env!("OUT_DIR"), "/{MODULE_BINDGEN_OUTPUT_FILE}"))` to include
+# the generated bindgen file.
+MODULE_RUST_ENV := $(MODULE_RUST_ENV) $(MODULE_BINDGEN_OUTPUT_ENV_VAR)=$(MODULE_BINDGEN_OUTPUT_FILE) OUT_DIR=$(dir $(MODULE_BINDGEN_OUTPUT_FILE))
+
+$(info $(MODULE_BINDGEN_OUTPUT_FILE))
 
 MODULE_BINDGEN_ALLOW_FILES :=
 MODULE_BINDGEN_ALLOW_FUNCTIONS :=
 MODULE_BINDGEN_ALLOW_TYPES :=
 MODULE_BINDGEN_ALLOW_VARS :=
+MODULE_BINDGEN_CONFIG :=
 MODULE_BINDGEN_CTYPES_PREFIX :=
+MODULE_BINDGEN_DEFINES :=
 MODULE_BINDGEN_OUTPUT_ENV_VAR :=
+MODULE_BINDGEN_OUTPUT_FILE_NAME :=
 MODULE_BINDGEN_SRC_HEADER :=
 
 BINDGEN :=
diff --git a/make/common_flags.mk b/make/common_flags.mk
index 30f05c6..473189a 100644
--- a/make/common_flags.mk
+++ b/make/common_flags.mk
@@ -46,6 +46,7 @@ ifneq ($(ASLR), false)
 	MODULE_COMPILEFLAGS += -fPIC
 	MODULE_RUSTFLAGS += -C relocation-model=pic
 else
+	MODULE_COMPILEFLAGS += -fno-PIC -fno-PIE
 	MODULE_RUSTFLAGS += -C relocation-model=static
 endif
 
diff --git a/make/protoc_plugin.mk b/make/protoc_plugin.mk
index ba2d232..98bda65 100644
--- a/make/protoc_plugin.mk
+++ b/make/protoc_plugin.mk
@@ -25,7 +25,7 @@
 # MODULE_PROTO_PACKAGE: a path that matches the directory structure of
 #                       the PROTO package utilized in the module.
 
-PROTOC_TOOL := $(firstword $(wildcard out/host/linux-x86/bin/aprotoc prebuilts/libprotobuf/bin/protoc))
+PROTOC_TOOL ?= $(firstword $(wildcard out/host/linux-x86/bin/aprotoc prebuilts/libprotobuf/bin/protoc))
 
 ifeq ($(PROTOC_TOOL),)
 $(error No PROTOC_TOOL. Please build the aprotoc or checkout with trusty manifest)
diff --git a/make/trusted_app.mk b/make/trusted_app.mk
index 7d0b9af..ca7b7e4 100644
--- a/make/trusted_app.mk
+++ b/make/trusted_app.mk
@@ -159,13 +159,13 @@ $(TRUSTY_APP_SYMS_ELF): $(TRUSTY_APP_RUST_MAIN_SRC) $(TRUSTY_APP_RUST_SRCDEPS) $
 	@$(MKDIR)
 	@$(call ECHO,$(TRUSTY_APP_LOG_NAME),compiling,$<)
 ifeq ($(call TOBOOL,$(MODULE_RUST_USE_CLIPPY)),true)
-	$(NOECHO) set -e ; \
+	+$(NOECHO) set -e ; \
 		TEMP_CLIPPY_DIR=$$(mktemp -d) ;\
 		mkdir -p $(dir $$TEMP_CLIPPY_DIR/$@) ;\
 		$(MODULE_RUST_ENV) $(CLIPPY_DRIVER) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< -o $$TEMP_CLIPPY_DIR/$@ ;\
 		rm -rf $$TEMP_CLIPPY_DIR
 endif
-	$(NOECHO)$(MODULE_RUST_ENV) $(RUSTC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< --emit "dep-info=$@.d" -o $@
+	+$(NOECHO)$(MODULE_RUST_ENV) $(RUSTC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< --emit "dep-info=$@.d" -o $@
 	@$(call ECHO_DONE_SILENT,$(TRUSTY_APP_LOG_NAME),compiling,$<)
 
 -include $(TRUSTY_APP_SYMS_ELF).d
diff --git a/make/userspace_recurse.mk b/make/userspace_recurse.mk
index 45a39db..f8a310b 100644
--- a/make/userspace_recurse.mk
+++ b/make/userspace_recurse.mk
@@ -152,8 +152,7 @@ SAVED_$(MODULE)_AIDL_EXT := $(AIDL_EXT)
 SAVED_$(MODULE)_AIDL_HEADER_DIR := $(AIDL_HEADER_DIR)
 SAVED_$(MODULE)_AIDL_SRCS := $(AIDL_SRCS)
 SAVED_$(MODULE)_AIDL_TOOL := $(AIDL_TOOL)
-SAVED_$(MODULE)_AIDL_RUST_GLUE_TOOL := $(AIDL_RUST_GLUE_TOOL)
-SAVED_$(MODULE)_AIDL_ROOT_RS := $(AIDL_RUST_GLUE_TOOL)
+SAVED_$(MODULE)_AIDL_ROOT_RS := $(AIDL_ROOT_RS)
 
 SAVED_$(MODULE)_DEPENDENCY_MODULE := $(DEPENDENCY_MODULE)
 SAVED_$(MODULE)_EXPORT_DEPENDENCY_MODULE := $(EXPORT_DEPENDENCY_MODULE)
@@ -254,7 +253,6 @@ AIDL_EXT :=
 AIDL_HEADER_DIR :=
 AIDL_SRCS :=
 AIDL_TOOL :=
-AIDL_RUST_GLUE_TOOL :=
 AIDL_ROOT_RS :=
 
 ALLMODULES :=
@@ -364,7 +362,6 @@ AIDL_EXT := $(SAVED_$(MODULE)_AIDL_EXT)
 AIDL_HEADER_DIR := $(SAVED_$(MODULE)_AIDL_HEADER_DIR)
 AIDL_SRCS := $(SAVED_$(MODULE)_AIDL_SRCS)
 AIDL_TOOL := $(SAVED_$(MODULE)_AIDL_TOOL)
-AIDL_RUST_GLUE_TOOL := $(SAVED_$(MODULE)_AIDL_RUST_GLUE_TOOL)
 AIDL_ROOT_RS := $(SAVED_$(MODULE)_AIDL_ROOT_RS)
 
 DEPENDENCY_MODULE := $(SAVED_$(MODULE)_DEPENDENCY_MODULE)
```

