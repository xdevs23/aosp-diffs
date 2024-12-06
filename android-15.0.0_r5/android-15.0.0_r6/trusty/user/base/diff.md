```diff
diff --git a/app/acvp/acvp.cpp b/app/acvp/acvp.cpp
index 6716019..8833b3d 100644
--- a/app/acvp/acvp.cpp
+++ b/app/acvp/acvp.cpp
@@ -229,7 +229,10 @@ bool TrustyAcvpTool::MapShm(handle_t shm, size_t size) {
 
 void TrustyAcvpTool::MessageCleanup() {
     if (arg_buffer_) {
-        munmap((void*)arg_buffer_, arg_buffer_size_);
+        int rc = munmap((void*)arg_buffer_, arg_buffer_size_);
+        if (rc != NO_ERROR) {
+            TLOGW("munmap() failed: %d\n", rc);
+        }
         arg_buffer_ = NULL;
     }
 
diff --git a/app/apploader/apploader.c b/app/apploader/apploader.c
index 50ac327..9c3cc76 100644
--- a/app/apploader/apploader.c
+++ b/app/apploader/apploader.c
@@ -269,6 +269,7 @@ static uint32_t apploader_send_secure_load_command(
 
 static uint32_t apploader_copy_package(handle_t req_handle,
                                        handle_t secure_chan,
+                                       uint64_t package_size,
                                        uint64_t aligned_size,
                                        uint8_t** out_package) {
     uint32_t resp_error;
@@ -305,12 +306,17 @@ static uint32_t apploader_copy_package(handle_t req_handle,
     }
 
     assert(out_package);
-    memcpy(resp_package, req_package, aligned_size);
+    assert(package_size <= aligned_size);
+    memcpy(resp_package, req_package, package_size);
+    memset(resp_package + package_size, 0, aligned_size - package_size);
     *out_package = resp_package;
     resp_error = APPLOADER_NO_ERROR;
 
-err_resp_mmap:
-    munmap(req_package, aligned_size);
+err_resp_mmap:;
+    int rc = munmap(req_package, aligned_size);
+    if (rc != NO_ERROR) {
+        TLOGW("munmap() failed: %d\n", rc);
+    }
 err_req_mmap:
     close(secure_mem_handle);
 err_invalid_secure_mem_handle:
@@ -384,8 +390,8 @@ static int apploader_handle_cmd_load_app(handle_t chan,
 
     uint32_t copy_error;
     uint8_t* package;
-    copy_error = apploader_copy_package(req_handle, secure_chan, aligned_size,
-                                        &package);
+    copy_error = apploader_copy_package(
+            req_handle, secure_chan, req->package_size, aligned_size, &package);
     if (copy_error != APPLOADER_NO_ERROR) {
         TLOGE("Failed to copy package from client\n");
         resp_error = copy_error;
@@ -480,7 +486,11 @@ static int apploader_handle_cmd_load_app(handle_t chan,
 
     ptrdiff_t elf_offset = pkg_meta.elf_start - package;
     ptrdiff_t manifest_offset = pkg_meta.manifest_start - package;
-    munmap(package, aligned_size);
+    rc = munmap(package, aligned_size);
+    if (rc != NO_ERROR) {
+        TLOGW("munmap() failed: %d\n", rc);
+    }
+
     package = NULL;
 
     /* Validate the relocated offsets */
@@ -502,7 +512,10 @@ err_no_load:
     }
 
     if (package) {
-        munmap(package, aligned_size);
+        rc = munmap(package, aligned_size);
+        if (rc != NO_ERROR) {
+            TLOGW("munmap() failed: %d\n", rc);
+        }
     }
 err_copy_package:
     close(secure_chan);
diff --git a/app/apploader/tests/apploader_test.c b/app/apploader/tests/apploader_test.c
index a58d36f..97e53a7 100644
--- a/app/apploader/tests/apploader_test.c
+++ b/app/apploader/tests/apploader_test.c
@@ -17,6 +17,7 @@
 #include <interface/apploader/apploader.h>
 #include <interface/apploader/apploader_secure.h>
 #include <inttypes.h>
+#include <lib/rng/trusty_rng.h>
 #include <lib/system_state/system_state.h>
 #include <lib/tipc/tipc.h>
 #include <lib/unittest/unittest.h>
@@ -515,6 +516,50 @@ TEST_F(apploader_user, AppEncryptionTest) {
 test_abort:;
 }
 
+extern char integrity_test_app_start[], integrity_test_app_end[];
+
+TEST_F(apploader_user, LoadCmdCorruptImage) {
+    uint32_t error = APPLOADER_NO_ERROR;
+
+    const uint8_t bits_per_byte = 8;
+    const size_t max_bit_flip_count = 1 << 9;
+    uint8_t* const app_buf = (void*)integrity_test_app_start;
+    const size_t app_size = integrity_test_app_end - integrity_test_app_start;
+
+    unsigned int seed;
+    int rc = trusty_rng_hw_rand((uint8_t*)&seed, sizeof seed);
+    ASSERT_EQ(rc, NO_ERROR);
+    srand(seed);
+
+    for (size_t i = 0; i < max_bit_flip_count; ++i) {
+        const size_t bit_offset = rand() % (app_size * bits_per_byte);
+        const size_t byte_offset = bit_offset / bits_per_byte;
+        const uint8_t bit_offset_in_byte = bit_offset % bits_per_byte;
+        const uint8_t mask = 1 << bit_offset_in_byte;
+
+        app_buf[byte_offset] ^= mask;
+        error = load_test_app(_state->channel, integrity_test_app_start,
+                              integrity_test_app_end);
+
+        ASSERT_EQ(false, HasFailure());
+        ASSERT_EQ(error, APPLOADER_ERR_VERIFICATION_FAILED,
+                  "Unexpected signature verification success. "
+                  "Offending byte::bit: %zu::%d (bit offset: %zu) of "
+                  "total bytes: %zu\n",
+                  byte_offset, (int)bit_offset_in_byte, bit_offset, app_size);
+
+        app_buf[byte_offset] ^= mask; /* Restore the flipped bit */
+    }
+
+    error = load_test_app(_state->channel, integrity_test_app_start,
+                          integrity_test_app_end);
+    ASSERT_EQ(false, HasFailure());
+    ASSERT_EQ(true, error == APPLOADER_NO_ERROR ||
+                            error == APPLOADER_ERR_ALREADY_EXISTS);
+
+test_abort:;
+}
+
 typedef struct apploader_service {
     handle_t channel;
 } apploader_service_t;
@@ -605,7 +650,7 @@ TEST_F(apploader_service, GetMemory) {
 
 test_abort:
     if (buf) {
-        munmap(buf, page_size);
+        EXPECT_EQ(NO_ERROR, munmap(buf, page_size));
     }
 }
 
@@ -758,7 +803,7 @@ TEST_F(apploader_service, LoadCmdHoldMapping) {
 
 test_abort:
     if (buf) {
-        munmap(buf, buf_size);
+        EXPECT_EQ(NO_ERROR, munmap(buf, buf_size));
     }
 }
 
@@ -771,7 +816,7 @@ TEST_F(apploader_service, BadLoadCmdImageELFHeader) {
 
     /* Fill the image contents with 0x5a, so the ELF header check fails */
     memset(buf, 0x5a, buf_size);
-    munmap(buf, buf_size);
+    EXPECT_EQ(NO_ERROR, munmap(buf, buf_size));
     buf = NULL;
 
     uint32_t error;
@@ -788,7 +833,7 @@ TEST_F(apploader_service, BadLoadCmdImageELFHeader) {
 
 test_abort:
     if (buf) {
-        munmap(buf, buf_size);
+        EXPECT_EQ(NO_ERROR, munmap(buf, buf_size));
     }
 }
 
diff --git a/app/apploader/tests/integrity_test_app/integrity_test_app.c b/app/apploader/tests/integrity_test_app/integrity_test_app.c
new file mode 100644
index 0000000..801fdcc
--- /dev/null
+++ b/app/apploader/tests/integrity_test_app/integrity_test_app.c
@@ -0,0 +1,19 @@
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
+int main(void) {
+    return 0;
+}
diff --git a/app/apploader/tests/integrity_test_app/manifest.json b/app/apploader/tests/integrity_test_app/manifest.json
new file mode 100644
index 0000000..da2f8fa
--- /dev/null
+++ b/app/apploader/tests/integrity_test_app/manifest.json
@@ -0,0 +1,5 @@
+{
+    "uuid": "6e321238-1c38-42af-9a3e-008a6083c410",
+    "min_heap": 4096,
+    "min_stack": 4096
+}
diff --git a/app/apploader/tests/integrity_test_app/rules.mk b/app/apploader/tests/integrity_test_app/rules.mk
new file mode 100644
index 0000000..3cf58af
--- /dev/null
+++ b/app/apploader/tests/integrity_test_app/rules.mk
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
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/integrity_test_app.c \
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/base/lib/libc-trusty \
+
+include make/trusted_app.mk
diff --git a/app/apploader/tests/rules.mk b/app/apploader/tests/rules.mk
index 4ba5b5e..9b6025c 100644
--- a/app/apploader/tests/rules.mk
+++ b/app/apploader/tests/rules.mk
@@ -25,6 +25,7 @@ MODULE_SRCS += \
 
 MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/libc-trusty \
+	trusty/user/base/lib/rng \
 	trusty/user/base/lib/system_state \
 	trusty/user/base/lib/tipc \
 	trusty/user/base/lib/unittest \
@@ -58,6 +59,9 @@ ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_OPTIONAL := \
 ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_REQUIRED := \
 	$(APPLOADER_TESTS_DIR)/encryption_test_apps/unencrypted_app/encryption_required/encryption_required.app
 
+INTEGRITY_TEST_APP := \
+	$(APPLOADER_TESTS_DIR)/integrity_test_app/integrity_test_app.app
+
 MODULE_ASMFLAGS += \
 		-DVERSION_TEST_APP_V1=\"$(VERSION_TEST_APP_V1)\" \
 		-DVERSION_TEST_APP_V2=\"$(VERSION_TEST_APP_V2)\" \
@@ -70,6 +74,7 @@ MODULE_ASMFLAGS += \
 		-DENCRYPTION_TEST_APP_ENCRYPTED_APP_ENCRYPTION_REQUIRED=\"$(ENCRYPTION_TEST_APP_ENCRYPTED_APP_ENCRYPTION_REQUIRED)\" \
 		-DENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_OPTIONAL=\"$(ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_OPTIONAL)\" \
 		-DENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_REQUIRED=\"$(ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_REQUIRED)\" \
+		-DINTEGRITY_TEST_APP=\"$(INTEGRITY_TEST_APP)\" \
 
 MODULE_SRCDEPS += \
        $(VERSION_TEST_APP_V1) \
@@ -83,5 +88,6 @@ MODULE_SRCDEPS += \
 	   $(ENCRYPTION_TEST_APP_ENCRYPTED_APP_ENCRYPTION_REQUIRED) \
 	   $(ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_OPTIONAL) \
 	   $(ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_REQUIRED) \
+	   $(INTEGRITY_TEST_APP) \
 
 include make/trusted_app.mk
diff --git a/app/apploader/tests/test_apps.S b/app/apploader/tests/test_apps.S
index 91aed60..b82874d 100644
--- a/app/apploader/tests/test_apps.S
+++ b/app/apploader/tests/test_apps.S
@@ -99,3 +99,10 @@ encryption_test_app_unencrypted_app_encryption_optional_end:
 encryption_test_app_unencrypted_app_encryption_required_start:
 .incbin ENCRYPTION_TEST_APP_UNENCRYPTED_APP_ENCRYPTION_REQUIRED
 encryption_test_app_unencrypted_app_encryption_required_end:
+
+.global integrity_test_app_start, integrity_test_app_end
+.hidden integrity_test_app_start, integrity_test_app_end
+.balign 4096
+integrity_test_app_start:
+.incbin INTEGRITY_TEST_APP
+integrity_test_app_end:
diff --git a/app/metrics/rules.mk b/app/metrics/rules.mk
index e538b81..d2963a3 100644
--- a/app/metrics/rules.mk
+++ b/app/metrics/rules.mk
@@ -31,9 +31,5 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/metrics_atoms \
 	trusty/user/base/lib/tipc \
 	trusty/user/base/interface/metrics \
-	trusty/user/base/interface/stats/nw \
-	trusty/user/base/interface/stats/tz \
-	trusty/user/base/interface/stats_setter \
-	frameworks/native/libs/binder/trusty \
 
 include make/trusted_app.mk
diff --git a/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h b/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
index f525e03..05c86f3 100644
--- a/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
+++ b/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
@@ -536,6 +536,15 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_MSG_WAIT SMC_FASTCALL_NR_SHARED_MEMORY(0x6B)
 
+/**
+ * SMC_FC_FFA_MSG_RUN - SMC opcode to allocate cycles to an endpoint
+ *
+ * Register arguments:
+ *
+ * * w1:     SP/VM ID in [31:16], vCPU in [15:0]
+ */
+#define SMC_FC_FFA_RUN SMC_FASTCALL_NR_SHARED_MEMORY(0x6D)
+
 /**
  * SMC_FC_FFA_MSG_SEND_DIRECT_REQ - 32 bit SMC opcode to send direct message as
  *                                  a request
@@ -761,6 +770,26 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_MEM_FRAG_TX SMC_FASTCALL_NR_SHARED_MEMORY(0x7B)
 
+/**
+ * SMC_FC_FFA_CONSOLE_LOG - SMC opcode to log to console
+ *
+ * Register arguments:
+ *
+ * * w1:  Count of characters
+ * * w2/x2-w7/x7: Packed characters
+ *
+ * Return:
+ * * w0:     &SMC_FC_FFA_SUCCESS
+ *
+ * or
+ *
+ * * w0:     &SMC_FC_FFA_ERROR
+ * * w2:     Error code (&enum ffa_error)
+ * * w3:     Num characters logged (if w2 is RETRY)
+ */
+#define SMC_FC_FFA_CONSOLE_LOG SMC_FASTCALL_NR_SHARED_MEMORY(0x8A)
+#define SMC_FC64_FFA_CONSOLE_LOG SMC_FASTCALL64_NR_SHARED_MEMORY(0x8A)
+
 /* FF-A v1.1 */
 /**
  * SMC_FC64_FFA_SECONDARY_EP_REGISTER - SMC opcode to register secondary
diff --git a/interface/keymaster/include/interface/keymaster/keymaster.h b/interface/keymaster/include/interface/keymaster/keymaster.h
index 9585c52..f9d4a12 100644
--- a/interface/keymaster/include/interface/keymaster/keymaster.h
+++ b/interface/keymaster/include/interface/keymaster/keymaster.h
@@ -28,6 +28,7 @@
 #define KM_REQ_SHIFT 2U
 #define KM_GET_AUTH_TOKEN_KEY (0U << KM_REQ_SHIFT)
 #define KM_GET_DEVICE_INFO (1U << KM_REQ_SHIFT)
+#define KM_GET_UDS_CERTS (2U << KM_REQ_SHIFT)
 #define KM_SET_ATTESTATION_IDS_SECURE (0xc000 << KM_REQ_SHIFT)
 
 /**
diff --git a/interface/secure_storage/cpp/rules.mk b/interface/secure_storage/cpp/rules.mk
index 8884343..aa808e3 100644
--- a/interface/secure_storage/cpp/rules.mk
+++ b/interface/secure_storage/cpp/rules.mk
@@ -27,20 +27,16 @@ MODULE_AIDL_LANGUAGE := cpp
 MODULE_AIDL_PACKAGE := android/hardware/security/see/storage
 
 MODULE_AIDLS := \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Availability.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CreationMode.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/DeleteOptions.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileAvailability.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileIntegrity.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileMode.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileProperties.aidl \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Filesystem.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IDir.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IFile.aidl \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Integrity.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ISecureStorage.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IStorageSession.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/OpenOptions.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ReadIntegrity.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/RenameOptions.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Tamper.aidl \
 
 MODULE_EXPORT_INCLUDES := \
 	$(LOCAL_DIR)/include \
diff --git a/interface/secure_storage/rust/rules.mk b/interface/secure_storage/rust/rules.mk
index cccdb44..49836ce 100644
--- a/interface/secure_storage/rust/rules.mk
+++ b/interface/secure_storage/rust/rules.mk
@@ -29,19 +29,15 @@ MODULE_CRATE_NAME := android_hardware_security_see_storage
 MODULE_AIDL_PACKAGE := android/hardware/security/see/storage
 
 MODULE_AIDLS := \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Availability.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CreationMode.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/DeleteOptions.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileAvailability.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileIntegrity.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileMode.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/FileProperties.aidl \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Filesystem.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IDir.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IFile.aidl \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Integrity.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ISecureStorage.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IStorageSession.aidl \
 	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/OpenOptions.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ReadIntegrity.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/RenameOptions.aidl \
-	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Tamper.aidl \
 
 include make/aidl.mk
diff --git a/lib/apploader_package/cose.cpp b/lib/apploader_package/cose.cpp
index ce4bfae..3b86faf 100644
--- a/lib/apploader_package/cose.cpp
+++ b/lib/apploader_package/cose.cpp
@@ -198,39 +198,15 @@ static bool ecdsaSignatureDerToCose(
         return false;
     }
 
-    const BIGNUM* rBn;
-    const BIGNUM* sBn;
-    ECDSA_SIG_get0(sig.get(), &rBn, &sBn);
-
-    /*
-     * Older versions of OpenSSL also do not have BN_bn2binpad,
-     * so we need to use BN_bn2bin with the correct offsets.
-     * Each of the output values is a 32-byte big-endian number,
-     * while the inputs are BIGNUMs stored in host format.
-     * We can insert the padding ourselves by zeroing the output array,
-     * then placing the output of BN_bn2bin so its end aligns
-     * with the end of the 32-byte big-endian number.
-     */
-    auto rBnSize = BN_num_bytes(rBn);
-    if (rBnSize < 0 || static_cast<size_t>(rBnSize) > kEcdsaValueSize) {
-        COSE_PRINT_ERROR("Invalid ECDSA r value size (%d)\n", rBnSize);
-        return false;
-    }
-    auto sBnSize = BN_num_bytes(sBn);
-    if (sBnSize < 0 || static_cast<size_t>(sBnSize) > kEcdsaValueSize) {
-        COSE_PRINT_ERROR("Invalid ECDSA s value size (%d)\n", sBnSize);
-        return false;
-    }
-
     ecdsaCoseSignature.clear();
-    ecdsaCoseSignature.resize(kEcdsaSignatureSize, 0);
-    if (BN_bn2bin(rBn, ecdsaCoseSignature.data() + kEcdsaValueSize - rBnSize) !=
-        rBnSize) {
+    ecdsaCoseSignature.resize(kEcdsaSignatureSize);
+    if (!BN_bn2bin_padded(ecdsaCoseSignature.data(), kEcdsaValueSize,
+                          ECDSA_SIG_get0_r(sig.get()))) {
         COSE_PRINT_ERROR("Error encoding r\n");
         return false;
     }
-    if (BN_bn2bin(sBn, ecdsaCoseSignature.data() + kEcdsaSignatureSize -
-                               sBnSize) != sBnSize) {
+    if (!BN_bn2bin_padded(ecdsaCoseSignature.data() + kEcdsaValueSize,
+                          kEcdsaValueSize, ECDSA_SIG_get0_s(sig.get()))) {
         COSE_PRINT_ERROR("Error encoding s\n");
         return false;
     }
diff --git a/lib/coverage/common/cov_shm.c b/lib/coverage/common/cov_shm.c
index 1287e56..acf0753 100644
--- a/lib/coverage/common/cov_shm.c
+++ b/lib/coverage/common/cov_shm.c
@@ -84,7 +84,10 @@ int cov_shm_mmap(struct cov_shm* shm, handle_t memref, size_t len) {
 void cov_shm_munmap(struct cov_shm* shm) {
     assert(cov_shm_is_mapped(shm));
 
-    munmap(shm->base, shm->len);
+    int rc = munmap(shm->base, shm->len);
+    if (rc != NO_ERROR) {
+        TLOGW("failed to munmap() shared memory (rc=%d)\n", rc);
+    }
     close(shm->memref);
     shm->memref = INVALID_IPC_HANDLE;
     shm->base = NULL;
diff --git a/lib/hwaes/srv/hwaes_server.c b/lib/hwaes/srv/hwaes_server.c
index e94b03a..ccadec6 100644
--- a/lib/hwaes/srv/hwaes_server.c
+++ b/lib/hwaes/srv/hwaes_server.c
@@ -146,7 +146,10 @@ static int hwaes_map_shm(size_t num,
 static void hwaes_unmap_shm(size_t num, struct shm* shms) {
     for (size_t i = 0; i < num; i++) {
         if (shms[i].size) {
-            munmap(shms[i].base, shms[i].size);
+            int rc = munmap(shms[i].base, shms[i].size);
+            if (rc != NO_ERROR) {
+                TLOGW("munmap() failed: %d\n", rc);
+            }
         }
     }
 }
diff --git a/lib/hwbcc/client/rules.mk b/lib/hwbcc/client/rules.mk
index 2d59146..c511691 100644
--- a/lib/hwbcc/client/rules.mk
+++ b/lib/hwbcc/client/rules.mk
@@ -16,6 +16,8 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
+MODULE_SDK_LIB_NAME := hwbcc_client
+
 MODULE_SRCS := \
 	$(LOCAL_DIR)/hwbcc.c \
 
diff --git a/lib/hwbcc/common/include/lib/hwbcc/common/swbcc.h b/lib/hwbcc/common/include/lib/hwbcc/common/swbcc.h
index f9565d1..7e6806f 100644
--- a/lib/hwbcc/common/include/lib/hwbcc/common/swbcc.h
+++ b/lib/hwbcc/common/include/lib/hwbcc/common/swbcc.h
@@ -47,6 +47,13 @@ int swbcc_glob_init(const uint8_t FRS[DICE_HIDDEN_SIZE],
 
 int swbcc_init(swbcc_session_t* s, const struct uuid* client);
 
+/**
+ * swbcc_get_client() - Get UUID of session client.
+ * @s                 - swbcc session data
+ * @client            - uuid of swbcc session client
+ */
+void swbcc_get_client(const swbcc_session_t s, struct uuid* client);
+
 void swbcc_close(swbcc_session_t s);
 
 int swbcc_sign_key(swbcc_session_t s,
diff --git a/lib/hwbcc/common/swbcc.c b/lib/hwbcc/common/swbcc.c
index 81f82cd..a0af7e2 100644
--- a/lib/hwbcc/common/swbcc.c
+++ b/lib/hwbcc/common/swbcc.c
@@ -288,6 +288,11 @@ err:
     return rc;
 }
 
+void swbcc_get_client(swbcc_session_t s, struct uuid* client) {
+    struct swbcc_session* session = (struct swbcc_session*)s;
+    memcpy(client, &session->client_uuid, sizeof(struct uuid));
+}
+
 int swbcc_ns_deprivilege(swbcc_session_t s) {
     srv_state.ns_deprivileged = true;
     return NO_ERROR;
diff --git a/lib/hwbcc/test/main.cpp b/lib/hwbcc/test/main.cpp
index 5377544..cb57b2c 100644
--- a/lib/hwbcc/test/main.cpp
+++ b/lib/hwbcc/test/main.cpp
@@ -60,6 +60,14 @@ TEST_F_TEARDOWN(swbcc) {
     swbcc_close(_state->s);
 }
 
+TEST_F(swbcc, get_client) {
+    struct uuid client;
+    swbcc_get_client(_state->s, &client);
+    ASSERT_EQ(memcmp(&client, &self_uuid, sizeof(struct uuid)), 0);
+
+test_abort:;
+}
+
 TEST_F(swbcc, mac) {
     int rc;
     uint8_t cose_sign1[HWBCC_MAX_RESP_PAYLOAD_SIZE];
diff --git a/lib/keybox/client/rules.mk b/lib/keybox/client/rules.mk
index 66f95fe..df5daab 100644
--- a/lib/keybox/client/rules.mk
+++ b/lib/keybox/client/rules.mk
@@ -16,6 +16,8 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
+MODULE_SDK_LIB_NAME := keybox_client
+
 MODULE_SRCS := \
     $(LOCAL_DIR)/client.c \
 
diff --git a/lib/keymaster/include/lib/keymaster/keymaster.h b/lib/keymaster/include/lib/keymaster/keymaster.h
index fd0ae99..c765e47 100644
--- a/lib/keymaster/include/lib/keymaster/keymaster.h
+++ b/lib/keymaster/include/lib/keymaster/keymaster.h
@@ -91,4 +91,17 @@ int keymaster_validate_auth_token(keymaster_session_t session,
 int keymaster_get_device_info(keymaster_session_t session,
                               uint8_t** info_buffer_p,
                               uint32_t* size_p);
+
+/**
+ * keymaster_get_uds_certs() - Return UDS certificates.
+ * @session: An open keymaster_session_t.
+ * @cert_buffer_p: A buffer to be populated with the UDS certs.
+ *                 Ownership of this pointer is transferred to the caller and
+ *                 must be deallocated with a call to free().
+ * @size_p: Set to the allocated size of info_buffer_p.
+ * @return: NO_ERROR on success.
+ */
+int keymaster_get_uds_certs(keymaster_session_t session,
+                            uint8_t** cert_buffer_p,
+                            uint32_t* size_p);
 __END_CDECLS
diff --git a/lib/keymaster/keymaster.c b/lib/keymaster/keymaster.c
index b49f27b..2342829 100644
--- a/lib/keymaster/keymaster.c
+++ b/lib/keymaster/keymaster.c
@@ -236,6 +236,68 @@ err_bad_cbor:
     return rc;
 }
 
+int keymaster_get_uds_certs(keymaster_session_t session,
+                            uint8_t** cert_buffer_p,
+                            uint32_t* size_p) {
+    uint8_t* data = NULL;
+    uint32_t data_len = 0;
+    long rc =
+            keymaster_send_command(session, KM_GET_UDS_CERTS, &data, &data_len);
+    if (rc != NO_ERROR) {
+        return rc;
+    }
+
+    // The first four bytes (native endian) after the (consumed) command code
+    // indicate the error code for the command (0 for success).
+    if (data_len < sizeof(uint32_t)) {
+        TLOGE("%s: UDS certs return code wrong length: %zu, expected >= %zu\n",
+              __func__, (size_t)data_len, sizeof(uint32_t));
+        rc = ERR_BAD_LEN;
+        goto exit;
+    }
+    uint32_t errcode = *(uint32_t*)data;
+    if (errcode != 0) {
+        TLOGE("%s: UDS certs retrieval failed: %u\n", __func__, errcode);
+        rc = ERR_FAULT;
+        goto exit;
+    }
+
+    // Remainder of message is the UDS certs, starting with a 32-bit (native
+    // endian) length.
+    uint32_t remaining_len = data_len - sizeof(uint32_t);
+    uint8_t* rest = data + sizeof(uint32_t);
+    if (remaining_len < sizeof(uint32_t)) {
+        TLOGE("%s: UDS cert data wrong length: %zu, expected >= %zu\n",
+              __func__, (size_t)remaining_len, sizeof(uint32_t));
+        rc = ERR_BAD_LEN;
+        goto exit;
+    }
+
+    *size_p = *(uint32_t*)rest;
+    remaining_len -= sizeof(uint32_t);
+    rest += sizeof(uint32_t);
+    if (*size_p != remaining_len) {
+        TLOGE("%s: UDS cert data inconsistent length: claims %zu, %zu remaining\n",
+              __func__, (size_t)(*size_p), (size_t)remaining_len);
+        rc = ERR_BAD_LEN;
+        goto exit;
+    }
+
+    // Allocate space for just the UDS certs.
+    *cert_buffer_p = malloc(*size_p);
+    if (*cert_buffer_p == NULL) {
+        TLOGE("%s: out of memory (%zu)\n", __func__, (size_t)(*size_p));
+        rc = ERR_NO_MEMORY;
+        goto exit;
+    }
+    memcpy(*cert_buffer_p, rest, *size_p);
+
+exit:
+    // Always free the (prefixed) response buffer.
+    free(data);
+    return rc;
+}
+
 static int mint_hmac(uint8_t* key,
                      size_t key_size,
                      uint8_t* message,
diff --git a/lib/keymint-rust/boringssl/rules.mk b/lib/keymint-rust/boringssl/rules.mk
index 1b9bdf8..f02e715 100644
--- a/lib/keymint-rust/boringssl/rules.mk
+++ b/lib/keymint-rust/boringssl/rules.mk
@@ -23,7 +23,6 @@ MODULE_CRATE_NAME := kmr_crypto_boring
 
 MODULE_RUSTFLAGS += \
 	--cfg 'soong' \
-	--allow rustdoc::broken-intra-doc-links \
 
 MODULE_LIBRARY_EXPORTED_DEPS += \
 	trusty/user/base/lib/bssl-sys-rust \
diff --git a/lib/keymint-rust/common/rules.mk b/lib/keymint-rust/common/rules.mk
index eb860f4..5d5397d 100644
--- a/lib/keymint-rust/common/rules.mk
+++ b/lib/keymint-rust/common/rules.mk
@@ -21,9 +21,6 @@ MODULE_SRCS := system/keymint/common/src/lib.rs
 
 MODULE_CRATE_NAME := kmr_common
 
-MODULE_RUSTFLAGS += \
-	--allow rustdoc::broken-intra-doc-links \
-
 MODULE_LIBRARY_EXPORTED_DEPS += \
 	$(call FIND_CRATE,enumn) \
 	trusty/user/base/host/keymint-rust/derive \
diff --git a/lib/keymint-rust/ta/rules.mk b/lib/keymint-rust/ta/rules.mk
index 48057ce..b2a8f8c 100644
--- a/lib/keymint-rust/ta/rules.mk
+++ b/lib/keymint-rust/ta/rules.mk
@@ -21,9 +21,6 @@ MODULE_SRCS := system/keymint/ta/src/lib.rs
 
 MODULE_CRATE_NAME := kmr_ta
 
-MODULE_RUSTFLAGS += \
-	--allow rustdoc::broken-intra-doc-links \
-
 MODULE_LIBRARY_EXPORTED_DEPS += \
 	$(call FIND_CRATE,ciborium) \
 	$(call FIND_CRATE,ciborium-io) \
diff --git a/lib/keymint-rust/wire/rules.mk b/lib/keymint-rust/wire/rules.mk
index 685a26a..c96467b 100644
--- a/lib/keymint-rust/wire/rules.mk
+++ b/lib/keymint-rust/wire/rules.mk
@@ -26,7 +26,7 @@ MODULE_RUSTFLAGS += \
 	--cfg 'feature="hal_v3"' \
 
 MODULE_LIBRARY_EXPORTED_DEPS += \
-    $(call FIND_CRATE,enumn) \
+	$(call FIND_CRATE,enumn) \
 	trusty/user/base/host/keymint-rust/derive \
 	$(call FIND_CRATE,ciborium-io) \
 	$(call FIND_CRATE,ciborium) \
diff --git a/lib/libcompiler_builtins-rust/rules.mk b/lib/libcompiler_builtins-rust/rules.mk
index 113e552..86472c1 100644
--- a/lib/libcompiler_builtins-rust/rules.mk
+++ b/lib/libcompiler_builtins-rust/rules.mk
@@ -41,6 +41,9 @@ MODULE_RUSTFLAGS += \
 MODULE_RUSTFLAGS += \
 	-A unstable-name-collisions
 
+# Int and Float traits have some unused internal methods (for now)
+MODULE_RUSTFLAGS += -A dead-code
+
 MODULE_ADD_IMPLICIT_DEPS := false
 
 MODULE_SKIP_DOCS := true
diff --git a/lib/libcore-rust/rules.mk b/lib/libcore-rust/rules.mk
index 86463a7..b6632e7 100644
--- a/lib/libcore-rust/rules.mk
+++ b/lib/libcore-rust/rules.mk
@@ -28,6 +28,14 @@ MODULE_RUST_EDITION := 2021
 MODULE_RUSTFLAGS += \
 	-Z force-unstable-if-unmarked \
 
+# Allow targets to further reduce rust footprint by removing panic information
+ifeq (true,$(call TOBOOL,$(RUST_USE_PANIC_IMMEDIATE_ABORT)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="panic_immediate_abort"' \
+	-A dead_code \
+
+endif
+
 MODULE_ADD_IMPLICIT_DEPS := false
 
 include make/library.mk
diff --git a/lib/libstd-rust/rules.mk b/lib/libstd-rust/rules.mk
index fe1c0a6..dd2ccc7 100644
--- a/lib/libstd-rust/rules.mk
+++ b/lib/libstd-rust/rules.mk
@@ -52,6 +52,15 @@ MODULE_RUSTFLAGS += \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# Allow targets to further reduce rust footprint by removing panic information
+ifeq (true,$(call TOBOOL,$(RUST_USE_PANIC_IMMEDIATE_ABORT)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="panic_immediate_abort"' \
+	-A unused-imports \
+	-A unused-unsafe \
+
+endif
+
 # `STD_ENV_ARCH` needs to be set when building libstd. For ARM64 `ARCH` needs to
 # be translated to the architecture name that rustc expects, but for the
 # remaining targets `ARCH` already matches. This will need to be updated
diff --git a/lib/line-coverage/shm.c b/lib/line-coverage/shm.c
index f588a3a..5d64a00 100644
--- a/lib/line-coverage/shm.c
+++ b/lib/line-coverage/shm.c
@@ -88,7 +88,7 @@ int setup_shm(void) {
     int event = READ_ONCE(*app_mailbox);
 
     if (event != COVERAGE_MAILBOX_RECORD_READY) {
-        TLOGE("NS memory not shared yet\n");
+        TLOGD("NS memory not shared yet\n");
         return -1;
     }
     if (cov_shm_is_mapped(&ctx.data)) {
diff --git a/lib/pmu/aarch64 b/lib/pmu/aarch64
new file mode 120000
index 0000000..9adaa1c
--- /dev/null
+++ b/lib/pmu/aarch64
@@ -0,0 +1 @@
+../../../../kernel/lib/pmu/aarch64
\ No newline at end of file
diff --git a/lib/pmu/include b/lib/pmu/include
new file mode 120000
index 0000000..81ba4ea
--- /dev/null
+++ b/lib/pmu/include
@@ -0,0 +1 @@
+../../../../kernel/lib/pmu/include
\ No newline at end of file
diff --git a/lib/pmu/rules.mk b/lib/pmu/rules.mk
new file mode 100644
index 0000000..b909c03
--- /dev/null
+++ b/lib/pmu/rules.mk
@@ -0,0 +1,22 @@
+# Copyright (C) 2018 The Android Open Source Project
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
+MODULE_EXPORT_INCLUDES += $(LOCAL_DIR)/include/
+
+include make/library.mk
diff --git a/lib/scudo/test/srv/scudo_app.cpp b/lib/scudo/test/srv/scudo_app.cpp
index b9a3674..2989fd5 100644
--- a/lib/scudo/test/srv/scudo_app.cpp
+++ b/lib/scudo/test/srv/scudo_app.cpp
@@ -333,7 +333,7 @@ static int scudo_on_message(const struct tipc_port* port,
         if (mapped != MAP_FAILED) {
             TLOGI("Tagged memref should have failed\n");
             msg.cmd = SCUDO_TEST_FAIL;
-            munmap((void*)mapped, memrefsize);
+            (void)munmap((void*)mapped, memrefsize);
             close(memref);
             break;
         }
@@ -348,7 +348,7 @@ static int scudo_on_message(const struct tipc_port* port,
             break;
         }
         *mapped = 0x77;
-        munmap((void*)mapped, memrefsize);
+        (void)munmap((void*)mapped, memrefsize);
         close(memref);
         break;
     }
@@ -372,7 +372,7 @@ static int scudo_on_message(const struct tipc_port* port,
             break;
         }
         *mapped = 0x77;
-        munmap((void*)mapped, memrefsize);
+        (void)munmap((void*)mapped, memrefsize);
         close(memref);
         break;
     }
diff --git a/lib/secure_fb/secure_fb.c b/lib/secure_fb/secure_fb.c
index b569e5d..0da2b7d 100644
--- a/lib/secure_fb/secure_fb.c
+++ b/lib/secure_fb/secure_fb.c
@@ -50,7 +50,10 @@ static void free_secure_fb_session(struct secure_fb_session* s) {
     for (size_t i = 0; i < SECURE_FB_MAX_FBS; ++i) {
         uint8_t** buffer = &s->fbs[i].fb_info.buffer;
         if (*buffer) {
-            munmap(*buffer, s->fbs[i].fb_info.size);
+            int rc = munmap(*buffer, s->fbs[i].fb_info.size);
+            if (rc != NO_ERROR) {
+                TLOGW("munmap() failed: %d\n", rc);
+            }
             *buffer = NULL;
         }
     }
@@ -140,7 +143,10 @@ err:
     for (size_t i = 0; i < num_fbs; i++) {
         fb = &fbs[i];
         if (fb->fb_info.buffer) {
-            munmap(fb->fb_info.buffer, fb->fb_info.size);
+            int rc = munmap(fb->fb_info.buffer, fb->fb_info.size);
+            if (rc != NO_ERROR) {
+                TLOGW("munmap() failed: %d\n", rc);
+            }
         }
         memset(fb, 0, sizeof(*fb));
     }
diff --git a/lib/smc/tests/smc_test.c b/lib/smc/tests/smc_test.c
index b1c35eb..e52d500 100644
--- a/lib/smc/tests/smc_test.c
+++ b/lib/smc/tests/smc_test.c
@@ -263,8 +263,10 @@ TEST_F(smc, GENERIC_ARM64_PLATFORM_ONLY_TEST(validate_dma_arguments)) {
 
     /* fallthrough */
 test_abort:
-    finish_dma(va_base, len, dma_flags);
-    munmap(va_base, len);
+    if (va_base != MAP_FAILED) {
+        EXPECT_EQ(NO_ERROR, finish_dma(va_base, len, dma_flags));
+        EXPECT_EQ(NO_ERROR, munmap(va_base, len));
+    }
 }
 
 PORT_TEST(smc, "com.android.trusty.smc.test");
diff --git a/lib/spi/srv/tipc/tipc.c b/lib/spi/srv/tipc/tipc.c
index 67146ef..6be86c8 100644
--- a/lib/spi/srv/tipc/tipc.c
+++ b/lib/spi/srv/tipc/tipc.c
@@ -46,7 +46,10 @@ static inline bool shm_is_mapped(struct chan_ctx* ctx) {
 
 static inline void shm_unmap(struct chan_ctx* ctx) {
     if (shm_is_mapped(ctx)) {
-        munmap(ctx->shm.buf, ctx->shm.capacity);
+        int rc = munmap(ctx->shm.buf, ctx->shm.capacity);
+        if (rc != NO_ERROR) {
+            TLOGW("munmap() failed: %d\n", rc);
+        }
         mb_destroy(&ctx->shm);
         close(ctx->shm_handle);
         ctx->shm_handle = INVALID_IPC_HANDLE;
@@ -117,7 +120,7 @@ static int handle_msg_shm_map_req(handle_t chan,
                                   struct chan_ctx* ctx,
                                   struct spi_shm_map_req* shm_req,
                                   handle_t shm_handle) {
-    int rc = NO_ERROR;
+    int rc1, rc = NO_ERROR;
     void* shm_base;
 
     shm_unmap(ctx);
@@ -148,7 +151,10 @@ static int handle_msg_shm_map_req(handle_t chan,
     return NO_ERROR;
 
 err_resp:
-    munmap(shm_base, shm_req->len);
+    rc1 = munmap(shm_base, shm_req->len);
+    if (rc1 != NO_ERROR) {
+        TLOGW("munmap() failed: %d\n", rc);
+    }
 err_mmap:
     return rc;
 }
@@ -307,7 +313,12 @@ int add_spi_service(struct tipc_hset* hset,
             return ERR_INVALID_ARGS;
         }
 
-        rc = tipc_add_service(hset, &ports[i], 1, 1, &spi_dev_ops);
+#if TEST_BUILD
+        const uint32_t max_chan_cnt = 2;
+#else
+        const uint32_t max_chan_cnt = 1;
+#endif
+        rc = tipc_add_service(hset, &ports[i], 1, max_chan_cnt, &spi_dev_ops);
         if (rc != NO_ERROR) {
             return rc;
         }
diff --git a/lib/tipc/rust/src/serialization.rs b/lib/tipc/rust/src/serialization.rs
index 81cf78f..d631824 100644
--- a/lib/tipc/rust/src/serialization.rs
+++ b/lib/tipc/rust/src/serialization.rs
@@ -64,6 +64,15 @@ impl<'s> Serialize<'s> for u32 {
     }
 }
 
+impl<'s> Serialize<'s> for &'s [u8] {
+    fn serialize<'a: 's, S: Serializer<'s>>(
+        &'a self,
+        serializer: &mut S,
+    ) -> Result<S::Ok, S::Error> {
+        serializer.serialize_bytes(self)
+    }
+}
+
 /// A type that can deserialize itself from a sequence of bytes and handles.
 pub trait Deserialize: Sized {
     type Error: From<TipcError> + Debug;
diff --git a/lib/tipc/rust/src/service.rs b/lib/tipc/rust/src/service.rs
index cb9ed88..3bd6682 100644
--- a/lib/tipc/rust/src/service.rs
+++ b/lib/tipc/rust/src/service.rs
@@ -77,6 +77,7 @@ pub struct PortCfg {
     msg_queue_len: u32,
     msg_max_size: u32,
     flags: u32,
+    uuid_allow_list: Option<&'static [Uuid]>,
 }
 
 impl PortCfg {
@@ -87,6 +88,7 @@ impl PortCfg {
             msg_queue_len: 1,
             msg_max_size: 4096,
             flags: 0,
+            uuid_allow_list: None,
         })
     }
 
@@ -94,7 +96,7 @@ impl PortCfg {
     ///
     /// This version takes ownership of the path and does not allocate.
     pub fn new_raw(path: CString) -> Self {
-        Self { path, msg_queue_len: 1, msg_max_size: 4096, flags: 0 }
+        Self { path, msg_queue_len: 1, msg_max_size: 4096, flags: 0, uuid_allow_list: None }
     }
 
     /// Set the message queue length for this port configuration
@@ -118,6 +120,12 @@ impl PortCfg {
     pub fn allow_ta_connect(self) -> Self {
         Self { flags: self.flags | sys::IPC_PORT_ALLOW_TA_CONNECT as u32, ..self }
     }
+
+    /// Filter allowable UUID connections. Leaving this unset will allow connection from any peer
+    /// UUID. Services should handle any additional filtering they need.
+    pub fn allowed_uuids(self, uuids: &'static [Uuid]) -> Self {
+        Self { uuid_allow_list: Some(uuids), ..self }
+    }
 }
 
 impl TryClone for PortCfg {
@@ -1061,6 +1069,9 @@ impl<
                 | TipcError::SystemError(Error::TimedOut)
                 | TipcError::SystemError(Error::ChannelClosed)
 
+                // returned when peer UUID connection is not allowed.
+                | TipcError::SystemError(Error::NotAllowed)
+
                 // These are always caused by the client and so shouldn't be treated as an
                 // internal error or cause the event loop to exit.
                 | TipcError::ChannelClosed
@@ -1165,7 +1176,13 @@ impl<
         // initialized the peer structure.
         let peer = unsafe { Uuid(peer.assume_init()) };
 
-        // TODO: Implement access control
+        // Check against access control list if we were given one
+        if let Some(uuids) = cfg.uuid_allow_list {
+            if !uuids.contains(&peer) {
+                error!("UUID {peer:?} isn't supported.\n");
+                return Err(TipcError::SystemError(trusty_sys::Error::NotAllowed));
+            }
+        }
 
         let connection_data = self.dispatcher.on_connect(&cfg, &connection_handle, &peer)?;
         if let ConnectResult::Accept(data) = connection_data {
diff --git a/lib/tipc/tipc_srv.c b/lib/tipc/tipc_srv.c
index d2674fa..b640170 100644
--- a/lib/tipc/tipc_srv.c
+++ b/lib/tipc/tipc_srv.c
@@ -302,6 +302,31 @@ static void port_event_handler_proc(const struct uevent* ev, void* ctx) {
     }
 }
 
+/*
+ * Validate trusty service operations.
+ *
+ * Trusty service operations must satisfy the following requirements:
+ * - service operations is a required parameter and must not be NULL
+ * - on_message callback is mandatory and must be implemented by the service
+ *
+ * This function validates the above service operations requirements are met
+ * by the passed service operation structure, and returns true; otherwise, it
+ * returns false.
+ */
+static bool is_valid_tipc_srv_ops(const struct tipc_srv_ops* ops) {
+    if (!ops) {
+        TLOGE("Required service specific operations is NULL\n");
+        return false;
+    }
+
+    if (!ops->on_message) {
+        TLOGE("on_message callback is mandatory and cannot be NULL\n");
+        return false;
+    }
+
+    return true;
+}
+
 /*
  *  Add new TIPC service to handle set
  */
@@ -320,11 +345,16 @@ int tipc_add_service(struct tipc_hset* hset,
         return ERR_INVALID_ARGS;
     }
 
-    if (!hset || !ports || !num_ports || !ops) {
+    if (!hset || !ports || !num_ports) {
         TLOGE("required parameter is missing\n");
         return ERR_INVALID_ARGS;
     }
 
+    if (!is_valid_tipc_srv_ops(ops)) {
+        TLOGE("Service operations failed validation\n");
+        return ERR_INVALID_ARGS;
+    }
+
     /* allocate new service */
     srv = calloc(1,
                  sizeof(struct tipc_srv) + sizeof(struct port_ctx) * num_ports);
diff --git a/lib/unittest-rust/rules.mk b/lib/unittest-rust/rules.mk
index 758e673..894a4b0 100644
--- a/lib/unittest-rust/rules.mk
+++ b/lib/unittest-rust/rules.mk
@@ -27,4 +27,8 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-log \
 
+ifeq (true,$(call TOBOOL,$(BENCHMARK_MACHINE_READABLE)))
+MODULE_RUSTFLAGS += --cfg 'feature="machine_readable"'
+endif
+
 include make/library.mk
diff --git a/lib/unittest-rust/src/bench.rs b/lib/unittest-rust/src/bench.rs
index 6de8311..b793f9e 100644
--- a/lib/unittest-rust/src/bench.rs
+++ b/lib/unittest-rust/src/bench.rs
@@ -1,18 +1,167 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-/// Placeholder struct because we don't support benchmarking (yet).
-pub struct Bencher;
+// Copyright 2012-2016 The Rust Project Developers. See the COPYRIGHT
+// file at the top-level directory of this distribution and at
+// http://rust-lang.org/COPYRIGHT.
+//
+// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
+// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
+// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
+// option. This file may not be copied, modified, or distributed
+// except according to those terms.
+
+// Benchmarking code is taken from the bencher crate in the Android tree at
+// https://android.googlesource.com/platform/external/rust/crates/bencher.
+// Some modifications have been made to adapt it for use in Rust test TAs
+// generated by the unittest-rust library.
+
+use core::cmp;
+use core::time::Duration;
+
+use crate::stats;
+
+/// Manager of the benchmarking runs.
+///
+/// This is fed into functions marked with `#[bench]` to allow for
+/// set-up & tear-down before running a piece of code repeatedly via a
+/// call to `iter`.
+#[derive(Copy, Clone)]
+pub struct Bencher {
+    iterations: u64,
+    dur: Duration,
+    pub bytes: u64,
+}
+
+// TODO(b/357115387): Replace with std::time::Instant::now().
+fn get_time_ns() -> u64 {
+    let mut secure_time_ns = 0i64;
+    // Safety: external syscall gets valid raw pointer to a `i64` as defined
+    // in the Trusty syscall table at
+    // https://android.googlesource.com/trusty/lk/trusty/+/refs/heads/main/lib/trusty/include/syscall_table.h
+    unsafe { trusty_sys::gettime(0, 0, &mut secure_time_ns) };
+    secure_time_ns as u64
+}
+
+#[derive(Clone, PartialEq)]
+pub struct BenchSamples {
+    pub ns_iter_summ: stats::Summary,
+    mb_s: usize,
+}
+
+impl Bencher {
+    /// Callback for benchmark functions to run in their body.
+    pub fn iter<T, F>(&mut self, mut inner: F)
+    where
+        F: FnMut() -> T,
+    {
+        let start = get_time_ns();
+        let k = self.iterations;
+        for _ in 0..k {
+            core::hint::black_box(inner());
+        }
+        self.dur = Duration::from_nanos(get_time_ns() - start);
+    }
+
+    pub fn ns_elapsed(&mut self) -> u64 {
+        self.dur.as_secs() * 1_000_000_000 + (self.dur.subsec_nanos() as u64)
+    }
+
+    pub fn ns_per_iter(&mut self) -> u64 {
+        if self.iterations == 0 {
+            0
+        } else {
+            self.ns_elapsed() / cmp::max(self.iterations, 1)
+        }
+    }
+
+    pub fn bench_n<F>(&mut self, n: u64, f: F)
+    where
+        F: FnOnce(&mut Bencher),
+    {
+        self.iterations = n;
+        f(self);
+    }
+
+    // This is a more statistics-driven benchmark algorithm
+    pub fn auto_bench<F>(&mut self, mut f: F) -> stats::Summary
+    where
+        F: FnMut(&mut Bencher),
+    {
+        // Initial bench run to get ballpark figure.
+        let mut n = 1;
+        self.bench_n(n, |x| f(x));
+        let cold = self.ns_per_iter();
+
+        // Try to estimate iter count for 1ms falling back to 1m
+        // iterations if first run took < 1ns.
+        if cold == 0 {
+            n = 1_000_000;
+        } else {
+            n = 1_000_000 / cmp::max(cold, 1);
+        }
+        // if the first run took more than 1ms we don't want to just
+        // be left doing 0 iterations on every loop. The unfortunate
+        // side effect of not being able to do as many runs is
+        // automatically handled by the statistical analysis below
+        // (i.e. larger error bars).
+        if n == 0 {
+            n = 1;
+        }
+
+        let mut total_run = Duration::new(0, 0);
+        let samples: &mut [f64] = &mut [0.0_f64; 50];
+        loop {
+            let loop_start = get_time_ns();
+
+            for p in &mut *samples {
+                self.bench_n(n, |x| f(x));
+                *p = self.ns_per_iter() as f64;
+            }
+
+            stats::winsorize(samples, 5.0);
+            let summ = stats::Summary::new(cold as f64, samples);
+
+            for p in &mut *samples {
+                self.bench_n(5 * n, |x| f(x));
+                *p = self.ns_per_iter() as f64;
+            }
+
+            stats::winsorize(samples, 5.0);
+            let summ5 = stats::Summary::new(cold as f64, samples);
+            let loop_run = Duration::from_nanos(get_time_ns() - loop_start);
+
+            // If we've run for 100ms and seem to have converged to a
+            // stable median.
+            if loop_run > Duration::from_millis(100)
+                && summ.median_abs_dev_pct < 1.0
+                && summ.median - summ5.median < summ5.median_abs_dev
+            {
+                return summ5;
+            }
+
+            total_run += loop_run;
+            // Longest we ever run for is 3s.
+            if total_run > Duration::from_secs(3) {
+                return summ5;
+            }
+
+            // If we overflow here just return the results so far. We check a
+            // multiplier of 10 because we're about to multiply by 2 and the
+            // next iteration of the loop will also multiply by 5 (to calculate
+            // the summ5 result)
+            n = match n.checked_mul(10) {
+                Some(_) => n * 2,
+                None => return summ5,
+            };
+        }
+    }
+}
+
+pub fn benchmark<F>(f: F) -> BenchSamples
+where
+    F: FnMut(&mut Bencher),
+{
+    let mut bs = Bencher { iterations: 0, dur: Duration::new(0, 0), bytes: 0 };
+    let ns_iter_summ = bs.auto_bench(f);
+    let ns_iter = cmp::max(ns_iter_summ.median as u64, 1);
+    let mb_s = bs.bytes * 1000 / ns_iter;
+    BenchSamples { ns_iter_summ: ns_iter_summ, mb_s: mb_s as usize }
+}
diff --git a/lib/unittest-rust/src/lib.rs b/lib/unittest-rust/src/lib.rs
index 11b4152..693c299 100644
--- a/lib/unittest-rust/src/lib.rs
+++ b/lib/unittest-rust/src/lib.rs
@@ -50,6 +50,7 @@ mod bench;
 mod context;
 mod macros;
 mod options;
+mod stats;
 mod types;
 
 use context::CONTEXT;
@@ -183,6 +184,112 @@ struct TestService {
     tests: Vec<TestDescAndFn>,
 }
 
+#[cfg(not(feature = "machine_readable"))]
+fn print_samples(_test: &TestDesc, bs: &bench::BenchSamples) {
+    use core::fmt::Write;
+
+    struct FmtCounter {
+        chars: usize,
+    }
+
+    impl FmtCounter {
+        fn new() -> FmtCounter {
+            FmtCounter { chars: 0 }
+        }
+    }
+
+    impl core::fmt::Write for FmtCounter {
+        fn write_str(&mut self, s: &str) -> core::fmt::Result {
+            self.chars += s.chars().count();
+            Ok(())
+        }
+    }
+
+    let min = bs.ns_iter_summ.min as u64;
+    let avg = bs.ns_iter_summ.mean as u64;
+    let max = bs.ns_iter_summ.max as u64;
+    let cold = bs.ns_iter_summ.cold as u64;
+
+    let mut min_fc = FmtCounter::new();
+    if let Err(_) = core::write!(min_fc, "{}", min) {
+        return;
+    }
+    let mut avg_fc = FmtCounter::new();
+    if let Err(_) = core::write!(avg_fc, "{}", avg) {
+        return;
+    }
+    let mut max_fc = FmtCounter::new();
+    if let Err(_) = core::write!(max_fc, "{}", max) {
+        return;
+    }
+    let mut cold_fc = FmtCounter::new();
+    if let Err(_) = core::write!(cold_fc, "{}", cold) {
+        return;
+    }
+    log::info!(
+        "{:-<width$}",
+        "-",
+        width = min_fc.chars + avg_fc.chars + max_fc.chars + cold_fc.chars + 16
+    );
+    log::info!(
+        "|Metric    |{:minw$}|{:avgw$}|{:maxw$}|{:coldw$}|",
+        "Min",
+        "Avg",
+        "Max",
+        "Cold",
+        minw = min_fc.chars,
+        avgw = avg_fc.chars,
+        maxw = max_fc.chars,
+        coldw = cold_fc.chars
+    );
+    log::info!(
+        "{:-<width$}",
+        "-",
+        width = min_fc.chars + avg_fc.chars + max_fc.chars + cold_fc.chars + 16
+    );
+    log::info!("|time_nanos|{:3}|{:3}|{:3}|{:4}|", min, avg, max, cold);
+    log::info!(
+        "{:-<width$}",
+        "-",
+        width = min_fc.chars + avg_fc.chars + max_fc.chars + cold_fc.chars + 16
+    );
+}
+
+#[cfg(feature = "machine_readable")]
+fn print_samples(test: &TestDesc, bs: &bench::BenchSamples) {
+    let min = bs.ns_iter_summ.min as u64;
+    let avg = bs.ns_iter_summ.mean as u64;
+    let max = bs.ns_iter_summ.max as u64;
+    let cold = bs.ns_iter_summ.cold as u64;
+
+    let (suite, bench) =
+        test.name.as_slice().rsplit_once("::").unwrap_or((test.name.as_slice(), ""));
+    log::info!("{{\"schema_version\": 3,");
+    log::info!("\"suite_name\": \"{}\",", suite);
+    log::info!("\"bench_name\": \"{}\",", bench);
+    log::info!(
+        "\"results\": \
+        [{{\"metric_name\": \"time_nanos\", \
+        \"min\": \"{}\", \
+        \"max\": \"{}\", \
+        \"avg\": \"{}\", \
+        \"cold\": \"{}\", \
+        \"raw_min\": {}, \
+        \"raw_max\": {}, \
+        \"raw_avg\": {}, \
+        \"raw_cold\": {}}}",
+        min,
+        max,
+        avg,
+        cold,
+        min,
+        max,
+        avg,
+        cold,
+    );
+    log::info!("]}}");
+}
+
 impl Service for TestService {
     type Connection = ();
     type Message = ();
@@ -205,7 +312,10 @@ impl Service for TestService {
             print_status(&test.desc, "RUN     ");
             match test.testfn {
                 StaticTestFn(f) => f(),
-                StaticBenchFn(_f) => panic!("Test harness does not support benchmarking"),
+                StaticBenchFn(f) => {
+                    let bs = bench::benchmark(|harness| f(harness));
+                    print_samples(&test.desc, &bs);
+                }
                 _ => panic!("non-static tests passed to test::test_main_static"),
             }
             if CONTEXT.skipped() {
diff --git a/lib/unittest-rust/src/stats.rs b/lib/unittest-rust/src/stats.rs
new file mode 100644
index 0000000..c8af337
--- /dev/null
+++ b/lib/unittest-rust/src/stats.rs
@@ -0,0 +1,902 @@
+// Copyright 2012 The Rust Project Developers. See the COPYRIGHT
+// file at the top-level directory of this distribution and at
+// http://rust-lang.org/COPYRIGHT.
+//
+// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
+// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
+// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
+// option. This file may not be copied, modified, or distributed
+// except according to those terms.
+
+#![allow(missing_docs)]
+#![allow(deprecated)] // Float
+#![allow(unused)]
+
+use core::cmp::Ordering::{self, Equal, Greater, Less};
+use core::mem;
+
+fn local_cmp(x: f64, y: f64) -> Ordering {
+    // arbitrarily decide that NaNs are larger than everything.
+    if y.is_nan() {
+        Less
+    } else if x.is_nan() {
+        Greater
+    } else if x < y {
+        Less
+    } else if x == y {
+        Equal
+    } else {
+        Greater
+    }
+}
+
+fn local_sort(v: &mut [f64]) {
+    v.sort_by(|x: &f64, y: &f64| local_cmp(*x, *y));
+}
+
+/// Trait that provides simple descriptive statistics on a univariate set of numeric samples.
+pub trait Stats {
+    /// Sum of the samples.
+    ///
+    /// Note: this method sacrifices performance at the altar of accuracy
+    /// Depends on IEEE-754 arithmetic guarantees. See proof of correctness at:
+    /// ["Adaptive Precision Floating-Point Arithmetic and Fast Robust Geometric Predicates"]
+    /// (http://www.cs.cmu.edu/~quake-papers/robust-arithmetic.ps)
+    fn sum(&self) -> f64;
+
+    /// Minimum value of the samples.
+    fn min(&self) -> f64;
+
+    /// Maximum value of the samples.
+    fn max(&self) -> f64;
+
+    /// Arithmetic mean (average) of the samples: sum divided by sample-count.
+    ///
+    /// See: https://en.wikipedia.org/wiki/Arithmetic_mean
+    fn mean(&self) -> f64;
+
+    /// Median of the samples: value separating the lower half of the samples from the higher half.
+    /// Equal to `self.percentile(50.0)`.
+    ///
+    /// See: https://en.wikipedia.org/wiki/Median
+    fn median(&self) -> f64;
+
+    /// Variance of the samples: bias-corrected mean of the squares of the differences of each
+    /// sample from the sample mean. Note that this calculates the _sample variance_ rather than the
+    /// population variance, which is assumed to be unknown. It therefore corrects the `(n-1)/n`
+    /// bias that would appear if we calculated a population variance, by dividing by `(n-1)` rather
+    /// than `n`.
+    ///
+    /// See: https://en.wikipedia.org/wiki/Variance
+    fn var(&self) -> f64;
+
+    /// Standard deviation: the square root of the sample variance.
+    ///
+    /// Note: this is not a robust statistic for non-normal distributions. Prefer the
+    /// `median_abs_dev` for unknown distributions.
+    ///
+    /// See: https://en.wikipedia.org/wiki/Standard_deviation
+    fn std_dev(&self) -> f64;
+
+    /// Standard deviation as a percent of the mean value. See `std_dev` and `mean`.
+    ///
+    /// Note: this is not a robust statistic for non-normal distributions. Prefer the
+    /// `median_abs_dev_pct` for unknown distributions.
+    fn std_dev_pct(&self) -> f64;
+
+    /// Scaled median of the absolute deviations of each sample from the sample median. This is a
+    /// robust (distribution-agnostic) estimator of sample variability. Use this in preference to
+    /// `std_dev` if you cannot assume your sample is normally distributed. Note that this is scaled
+    /// by the constant `1.4826` to allow its use as a consistent estimator for the standard
+    /// deviation.
+    ///
+    /// See: http://en.wikipedia.org/wiki/Median_absolute_deviation
+    fn median_abs_dev(&self) -> f64;
+
+    /// Median absolute deviation as a percent of the median. See `median_abs_dev` and `median`.
+    fn median_abs_dev_pct(&self) -> f64;
+
+    /// Percentile: the value below which `pct` percent of the values in `self` fall. For example,
+    /// percentile(95.0) will return the value `v` such that 95% of the samples `s` in `self`
+    /// satisfy `s <= v`.
+    ///
+    /// Calculated by linear interpolation between closest ranks.
+    ///
+    /// See: http://en.wikipedia.org/wiki/Percentile
+    fn percentile(&self, pct: f64) -> f64;
+
+    /// Quartiles of the sample: three values that divide the sample into four equal groups, each
+    /// with 1/4 of the data. The middle value is the median. See `median` and `percentile`. This
+    /// function may calculate the 3 quartiles more efficiently than 3 calls to `percentile`, but
+    /// is otherwise equivalent.
+    ///
+    /// See also: https://en.wikipedia.org/wiki/Quartile
+    fn quartiles(&self) -> (f64, f64, f64);
+
+    /// Inter-quartile range: the difference between the 25th percentile (1st quartile) and the 75th
+    /// percentile (3rd quartile). See `quartiles`.
+    ///
+    /// See also: https://en.wikipedia.org/wiki/Interquartile_range
+    fn iqr(&self) -> f64;
+}
+
+/// Extracted collection of all the summary statistics of a sample set.
+#[derive(Clone, PartialEq)]
+#[allow(missing_docs)]
+pub struct Summary {
+    pub cold: f64,
+    pub sum: f64,
+    pub min: f64,
+    pub max: f64,
+    pub mean: f64,
+    pub median: f64,
+    pub var: f64,
+    pub std_dev: f64,
+    pub std_dev_pct: f64,
+    pub median_abs_dev: f64,
+    pub median_abs_dev_pct: f64,
+    pub quartiles: (f64, f64, f64),
+    pub iqr: f64,
+}
+
+impl Summary {
+    /// Construct a new summary of a sample set.
+    pub fn new(cold: f64, samples: &[f64]) -> Summary {
+        Summary {
+            cold: cold,
+            sum: samples.sum(),
+            min: samples.min(),
+            max: samples.max(),
+            mean: samples.mean(),
+            median: samples.median(),
+            var: samples.var(),
+            std_dev: samples.std_dev(),
+            std_dev_pct: samples.std_dev_pct(),
+            median_abs_dev: samples.median_abs_dev(),
+            median_abs_dev_pct: samples.median_abs_dev_pct(),
+            quartiles: samples.quartiles(),
+            iqr: samples.iqr(),
+        }
+    }
+}
+
+impl Stats for [f64] {
+    // FIXME #11059 handle NaN, inf and overflow
+    fn sum(&self) -> f64 {
+        let mut partials = vec![];
+
+        for &x in self {
+            let mut x = x;
+            let mut j = 0;
+            // This inner loop applies `hi`/`lo` summation to each
+            // partial so that the list of partial sums remains exact.
+            for i in 0..partials.len() {
+                let mut y: f64 = partials[i];
+                if x.abs() < y.abs() {
+                    mem::swap(&mut x, &mut y);
+                }
+                // Rounded `x+y` is stored in `hi` with round-off stored in
+                // `lo`. Together `hi+lo` are exactly equal to `x+y`.
+                let hi = x + y;
+                let lo = y - (hi - x);
+                if lo != 0.0 {
+                    partials[j] = lo;
+                    j += 1;
+                }
+                x = hi;
+            }
+            if j >= partials.len() {
+                partials.push(x);
+            } else {
+                partials[j] = x;
+                partials.truncate(j + 1);
+            }
+        }
+        let zero: f64 = 0.0;
+        partials.iter().fold(zero, |p, q| p + *q)
+    }
+
+    fn min(&self) -> f64 {
+        assert!(!self.is_empty());
+        self.iter().fold(self[0], |p, q| p.min(*q))
+    }
+
+    fn max(&self) -> f64 {
+        assert!(!self.is_empty());
+        self.iter().fold(self[0], |p, q| p.max(*q))
+    }
+
+    fn mean(&self) -> f64 {
+        assert!(!self.is_empty());
+        self.sum() / (self.len() as f64)
+    }
+
+    fn median(&self) -> f64 {
+        self.percentile(50 as f64)
+    }
+
+    fn var(&self) -> f64 {
+        if self.len() < 2 {
+            0.0
+        } else {
+            let mean = self.mean();
+            let mut v: f64 = 0.0;
+            for s in self {
+                let x = *s - mean;
+                v += x * x;
+            }
+            // NB: this is _supposed to be_ len-1, not len. If you
+            // change it back to len, you will be calculating a
+            // population variance, not a sample variance.
+            let denom = (self.len() - 1) as f64;
+            v / denom
+        }
+    }
+
+    fn std_dev(&self) -> f64 {
+        self.var().sqrt()
+    }
+
+    fn std_dev_pct(&self) -> f64 {
+        let hundred = 100 as f64;
+        (self.std_dev() / self.mean()) * hundred
+    }
+
+    fn median_abs_dev(&self) -> f64 {
+        let med = self.median();
+        let abs_devs: Vec<f64> = self.iter().map(|&v| (med - v).abs()).collect();
+        // This constant is derived by smarter statistics brains than me, but it is
+        // consistent with how R and other packages treat the MAD.
+        let number = 1.4826;
+        abs_devs.median() * number
+    }
+
+    fn median_abs_dev_pct(&self) -> f64 {
+        let hundred = 100 as f64;
+        (self.median_abs_dev() / self.median()) * hundred
+    }
+
+    fn percentile(&self, pct: f64) -> f64 {
+        let mut tmp = self.to_vec();
+        local_sort(&mut tmp);
+        percentile_of_sorted(&tmp, pct)
+    }
+
+    fn quartiles(&self) -> (f64, f64, f64) {
+        let mut tmp = self.to_vec();
+        local_sort(&mut tmp);
+        let first = 25f64;
+        let a = percentile_of_sorted(&tmp, first);
+        let secound = 50f64;
+        let b = percentile_of_sorted(&tmp, secound);
+        let third = 75f64;
+        let c = percentile_of_sorted(&tmp, third);
+        (a, b, c)
+    }
+
+    fn iqr(&self) -> f64 {
+        let (a, _, c) = self.quartiles();
+        c - a
+    }
+}
+
+// Helper function: extract a value representing the `pct` percentile of a sorted sample-set, using
+// linear interpolation. If samples are not sorted, return nonsensical value.
+fn percentile_of_sorted(sorted_samples: &[f64], pct: f64) -> f64 {
+    assert!(!sorted_samples.is_empty());
+    if sorted_samples.len() == 1 {
+        return sorted_samples[0];
+    }
+    let zero: f64 = 0.0;
+    assert!(zero <= pct);
+    let hundred = 100f64;
+    assert!(pct <= hundred);
+    if pct == hundred {
+        return sorted_samples[sorted_samples.len() - 1];
+    }
+    let length = (sorted_samples.len() - 1) as f64;
+    let rank = (pct / hundred) * length;
+    let lrank = rank.floor();
+    let d = rank - lrank;
+    let n = lrank as usize;
+    let lo = sorted_samples[n];
+    let hi = sorted_samples[n + 1];
+    lo + (hi - lo) * d
+}
+
+/// Winsorize a set of samples, replacing values above the `100-pct` percentile
+/// and below the `pct` percentile with those percentiles themselves. This is a
+/// way of minimizing the effect of outliers, at the cost of biasing the sample.
+/// It differs from trimming in that it does not change the number of samples,
+/// just changes the values of those that are outliers.
+///
+/// See: http://en.wikipedia.org/wiki/Winsorising
+pub fn winsorize(samples: &mut [f64], pct: f64) {
+    let mut tmp = samples.to_vec();
+    local_sort(&mut tmp);
+    let lo = percentile_of_sorted(&tmp, pct);
+    let hundred = 100 as f64;
+    let hi = percentile_of_sorted(&tmp, hundred - pct);
+    for samp in samples {
+        if *samp > hi {
+            *samp = hi
+        } else if *samp < lo {
+            *samp = lo
+        }
+    }
+}
+
+// Test vectors generated from R, using the script src/etc/stat-test-vectors.r.
+
+#[cfg(test)]
+mod tests {
+    use stats::Stats;
+    use stats::Summary;
+    use std::f64;
+    use std::io;
+    use std::io::prelude::*;
+
+    macro_rules! assert_approx_eq {
+        ($a:expr, $b:expr) => {{
+            let (a, b) = (&$a, &$b);
+            assert!((*a - *b).abs() < 1.0e-6, "{} is not approximately equal to {}", *a, *b);
+        }};
+    }
+
+    fn check(samples: &[f64], summ: &Summary) {
+        let summ2 = Summary::new(samples);
+
+        let mut w = io::sink();
+        let w = &mut w;
+        (write!(w, "\n")).unwrap();
+
+        assert_eq!(summ.sum, summ2.sum);
+        assert_eq!(summ.min, summ2.min);
+        assert_eq!(summ.max, summ2.max);
+        assert_eq!(summ.mean, summ2.mean);
+        assert_eq!(summ.median, summ2.median);
+
+        // We needed a few more digits to get exact equality on these
+        // but they're within float epsilon, which is 1.0e-6.
+        assert_approx_eq!(summ.var, summ2.var);
+        assert_approx_eq!(summ.std_dev, summ2.std_dev);
+        assert_approx_eq!(summ.std_dev_pct, summ2.std_dev_pct);
+        assert_approx_eq!(summ.median_abs_dev, summ2.median_abs_dev);
+        assert_approx_eq!(summ.median_abs_dev_pct, summ2.median_abs_dev_pct);
+
+        assert_eq!(summ.quartiles, summ2.quartiles);
+        assert_eq!(summ.iqr, summ2.iqr);
+    }
+
+    #[test]
+    fn test_min_max_nan() {
+        let xs = &[1.0, 2.0, f64::NAN, 3.0, 4.0];
+        let summary = Summary::new(xs);
+        assert_eq!(summary.min, 1.0);
+        assert_eq!(summary.max, 4.0);
+    }
+
+    #[test]
+    fn test_norm2() {
+        let val = &[958.0000000000, 924.0000000000];
+        let summ = &Summary {
+            sum: 1882.0000000000,
+            min: 924.0000000000,
+            max: 958.0000000000,
+            mean: 941.0000000000,
+            median: 941.0000000000,
+            var: 578.0000000000,
+            std_dev: 24.0416305603,
+            std_dev_pct: 2.5549022912,
+            median_abs_dev: 25.2042000000,
+            median_abs_dev_pct: 2.6784484591,
+            quartiles: (932.5000000000, 941.0000000000, 949.5000000000),
+            iqr: 17.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_norm10narrow() {
+        let val = &[
+            966.0000000000,
+            985.0000000000,
+            1110.0000000000,
+            848.0000000000,
+            821.0000000000,
+            975.0000000000,
+            962.0000000000,
+            1157.0000000000,
+            1217.0000000000,
+            955.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 9996.0000000000,
+            min: 821.0000000000,
+            max: 1217.0000000000,
+            mean: 999.6000000000,
+            median: 970.5000000000,
+            var: 16050.7111111111,
+            std_dev: 126.6914010938,
+            std_dev_pct: 12.6742097933,
+            median_abs_dev: 102.2994000000,
+            median_abs_dev_pct: 10.5408964451,
+            quartiles: (956.7500000000, 970.5000000000, 1078.7500000000),
+            iqr: 122.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_norm10medium() {
+        let val = &[
+            954.0000000000,
+            1064.0000000000,
+            855.0000000000,
+            1000.0000000000,
+            743.0000000000,
+            1084.0000000000,
+            704.0000000000,
+            1023.0000000000,
+            357.0000000000,
+            869.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 8653.0000000000,
+            min: 357.0000000000,
+            max: 1084.0000000000,
+            mean: 865.3000000000,
+            median: 911.5000000000,
+            var: 48628.4555555556,
+            std_dev: 220.5186059170,
+            std_dev_pct: 25.4846418487,
+            median_abs_dev: 195.7032000000,
+            median_abs_dev_pct: 21.4704552935,
+            quartiles: (771.0000000000, 911.5000000000, 1017.2500000000),
+            iqr: 246.2500000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_norm10wide() {
+        let val = &[
+            505.0000000000,
+            497.0000000000,
+            1591.0000000000,
+            887.0000000000,
+            1026.0000000000,
+            136.0000000000,
+            1580.0000000000,
+            940.0000000000,
+            754.0000000000,
+            1433.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 9349.0000000000,
+            min: 136.0000000000,
+            max: 1591.0000000000,
+            mean: 934.9000000000,
+            median: 913.5000000000,
+            var: 239208.9888888889,
+            std_dev: 489.0899599142,
+            std_dev_pct: 52.3146817750,
+            median_abs_dev: 611.5725000000,
+            median_abs_dev_pct: 66.9482758621,
+            quartiles: (567.2500000000, 913.5000000000, 1331.2500000000),
+            iqr: 764.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_norm25verynarrow() {
+        let val = &[
+            991.0000000000,
+            1018.0000000000,
+            998.0000000000,
+            1013.0000000000,
+            974.0000000000,
+            1007.0000000000,
+            1014.0000000000,
+            999.0000000000,
+            1011.0000000000,
+            978.0000000000,
+            985.0000000000,
+            999.0000000000,
+            983.0000000000,
+            982.0000000000,
+            1015.0000000000,
+            1002.0000000000,
+            977.0000000000,
+            948.0000000000,
+            1040.0000000000,
+            974.0000000000,
+            996.0000000000,
+            989.0000000000,
+            1015.0000000000,
+            994.0000000000,
+            1024.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 24926.0000000000,
+            min: 948.0000000000,
+            max: 1040.0000000000,
+            mean: 997.0400000000,
+            median: 998.0000000000,
+            var: 393.2066666667,
+            std_dev: 19.8294393937,
+            std_dev_pct: 1.9888308788,
+            median_abs_dev: 22.2390000000,
+            median_abs_dev_pct: 2.2283567134,
+            quartiles: (983.0000000000, 998.0000000000, 1013.0000000000),
+            iqr: 30.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_exp10a() {
+        let val = &[
+            23.0000000000,
+            11.0000000000,
+            2.0000000000,
+            57.0000000000,
+            4.0000000000,
+            12.0000000000,
+            5.0000000000,
+            29.0000000000,
+            3.0000000000,
+            21.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 167.0000000000,
+            min: 2.0000000000,
+            max: 57.0000000000,
+            mean: 16.7000000000,
+            median: 11.5000000000,
+            var: 287.7888888889,
+            std_dev: 16.9643416875,
+            std_dev_pct: 101.5828843560,
+            median_abs_dev: 13.3434000000,
+            median_abs_dev_pct: 116.0295652174,
+            quartiles: (4.2500000000, 11.5000000000, 22.5000000000),
+            iqr: 18.2500000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_exp10b() {
+        let val = &[
+            24.0000000000,
+            17.0000000000,
+            6.0000000000,
+            38.0000000000,
+            25.0000000000,
+            7.0000000000,
+            51.0000000000,
+            2.0000000000,
+            61.0000000000,
+            32.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 263.0000000000,
+            min: 2.0000000000,
+            max: 61.0000000000,
+            mean: 26.3000000000,
+            median: 24.5000000000,
+            var: 383.5666666667,
+            std_dev: 19.5848580967,
+            std_dev_pct: 74.4671410520,
+            median_abs_dev: 22.9803000000,
+            median_abs_dev_pct: 93.7971428571,
+            quartiles: (9.5000000000, 24.5000000000, 36.5000000000),
+            iqr: 27.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_exp10c() {
+        let val = &[
+            71.0000000000,
+            2.0000000000,
+            32.0000000000,
+            1.0000000000,
+            6.0000000000,
+            28.0000000000,
+            13.0000000000,
+            37.0000000000,
+            16.0000000000,
+            36.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 242.0000000000,
+            min: 1.0000000000,
+            max: 71.0000000000,
+            mean: 24.2000000000,
+            median: 22.0000000000,
+            var: 458.1777777778,
+            std_dev: 21.4050876611,
+            std_dev_pct: 88.4507754589,
+            median_abs_dev: 21.4977000000,
+            median_abs_dev_pct: 97.7168181818,
+            quartiles: (7.7500000000, 22.0000000000, 35.0000000000),
+            iqr: 27.2500000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_exp25() {
+        let val = &[
+            3.0000000000,
+            24.0000000000,
+            1.0000000000,
+            19.0000000000,
+            7.0000000000,
+            5.0000000000,
+            30.0000000000,
+            39.0000000000,
+            31.0000000000,
+            13.0000000000,
+            25.0000000000,
+            48.0000000000,
+            1.0000000000,
+            6.0000000000,
+            42.0000000000,
+            63.0000000000,
+            2.0000000000,
+            12.0000000000,
+            108.0000000000,
+            26.0000000000,
+            1.0000000000,
+            7.0000000000,
+            44.0000000000,
+            25.0000000000,
+            11.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 593.0000000000,
+            min: 1.0000000000,
+            max: 108.0000000000,
+            mean: 23.7200000000,
+            median: 19.0000000000,
+            var: 601.0433333333,
+            std_dev: 24.5161851301,
+            std_dev_pct: 103.3565983562,
+            median_abs_dev: 19.2738000000,
+            median_abs_dev_pct: 101.4410526316,
+            quartiles: (6.0000000000, 19.0000000000, 31.0000000000),
+            iqr: 25.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_binom25() {
+        let val = &[
+            18.0000000000,
+            17.0000000000,
+            27.0000000000,
+            15.0000000000,
+            21.0000000000,
+            25.0000000000,
+            17.0000000000,
+            24.0000000000,
+            25.0000000000,
+            24.0000000000,
+            26.0000000000,
+            26.0000000000,
+            23.0000000000,
+            15.0000000000,
+            23.0000000000,
+            17.0000000000,
+            18.0000000000,
+            18.0000000000,
+            21.0000000000,
+            16.0000000000,
+            15.0000000000,
+            31.0000000000,
+            20.0000000000,
+            17.0000000000,
+            15.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 514.0000000000,
+            min: 15.0000000000,
+            max: 31.0000000000,
+            mean: 20.5600000000,
+            median: 20.0000000000,
+            var: 20.8400000000,
+            std_dev: 4.5650848842,
+            std_dev_pct: 22.2037202539,
+            median_abs_dev: 5.9304000000,
+            median_abs_dev_pct: 29.6520000000,
+            quartiles: (17.0000000000, 20.0000000000, 24.0000000000),
+            iqr: 7.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_pois25lambda30() {
+        let val = &[
+            27.0000000000,
+            33.0000000000,
+            34.0000000000,
+            34.0000000000,
+            24.0000000000,
+            39.0000000000,
+            28.0000000000,
+            27.0000000000,
+            31.0000000000,
+            28.0000000000,
+            38.0000000000,
+            21.0000000000,
+            33.0000000000,
+            36.0000000000,
+            29.0000000000,
+            37.0000000000,
+            32.0000000000,
+            34.0000000000,
+            31.0000000000,
+            39.0000000000,
+            25.0000000000,
+            31.0000000000,
+            32.0000000000,
+            40.0000000000,
+            24.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 787.0000000000,
+            min: 21.0000000000,
+            max: 40.0000000000,
+            mean: 31.4800000000,
+            median: 32.0000000000,
+            var: 26.5933333333,
+            std_dev: 5.1568724372,
+            std_dev_pct: 16.3814245145,
+            median_abs_dev: 5.9304000000,
+            median_abs_dev_pct: 18.5325000000,
+            quartiles: (28.0000000000, 32.0000000000, 34.0000000000),
+            iqr: 6.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_pois25lambda40() {
+        let val = &[
+            42.0000000000,
+            50.0000000000,
+            42.0000000000,
+            46.0000000000,
+            34.0000000000,
+            45.0000000000,
+            34.0000000000,
+            49.0000000000,
+            39.0000000000,
+            28.0000000000,
+            40.0000000000,
+            35.0000000000,
+            37.0000000000,
+            39.0000000000,
+            46.0000000000,
+            44.0000000000,
+            32.0000000000,
+            45.0000000000,
+            42.0000000000,
+            37.0000000000,
+            48.0000000000,
+            42.0000000000,
+            33.0000000000,
+            42.0000000000,
+            48.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 1019.0000000000,
+            min: 28.0000000000,
+            max: 50.0000000000,
+            mean: 40.7600000000,
+            median: 42.0000000000,
+            var: 34.4400000000,
+            std_dev: 5.8685603004,
+            std_dev_pct: 14.3978417577,
+            median_abs_dev: 5.9304000000,
+            median_abs_dev_pct: 14.1200000000,
+            quartiles: (37.0000000000, 42.0000000000, 45.0000000000),
+            iqr: 8.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_pois25lambda50() {
+        let val = &[
+            45.0000000000,
+            43.0000000000,
+            44.0000000000,
+            61.0000000000,
+            51.0000000000,
+            53.0000000000,
+            59.0000000000,
+            52.0000000000,
+            49.0000000000,
+            51.0000000000,
+            51.0000000000,
+            50.0000000000,
+            49.0000000000,
+            56.0000000000,
+            42.0000000000,
+            52.0000000000,
+            51.0000000000,
+            43.0000000000,
+            48.0000000000,
+            48.0000000000,
+            50.0000000000,
+            42.0000000000,
+            43.0000000000,
+            42.0000000000,
+            60.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 1235.0000000000,
+            min: 42.0000000000,
+            max: 61.0000000000,
+            mean: 49.4000000000,
+            median: 50.0000000000,
+            var: 31.6666666667,
+            std_dev: 5.6273143387,
+            std_dev_pct: 11.3913245723,
+            median_abs_dev: 4.4478000000,
+            median_abs_dev_pct: 8.8956000000,
+            quartiles: (44.0000000000, 50.0000000000, 52.0000000000),
+            iqr: 8.0000000000,
+        };
+        check(val, summ);
+    }
+    #[test]
+    fn test_unif25() {
+        let val = &[
+            99.0000000000,
+            55.0000000000,
+            92.0000000000,
+            79.0000000000,
+            14.0000000000,
+            2.0000000000,
+            33.0000000000,
+            49.0000000000,
+            3.0000000000,
+            32.0000000000,
+            84.0000000000,
+            59.0000000000,
+            22.0000000000,
+            86.0000000000,
+            76.0000000000,
+            31.0000000000,
+            29.0000000000,
+            11.0000000000,
+            41.0000000000,
+            53.0000000000,
+            45.0000000000,
+            44.0000000000,
+            98.0000000000,
+            98.0000000000,
+            7.0000000000,
+        ];
+        let summ = &Summary {
+            sum: 1242.0000000000,
+            min: 2.0000000000,
+            max: 99.0000000000,
+            mean: 49.6800000000,
+            median: 45.0000000000,
+            var: 1015.6433333333,
+            std_dev: 31.8691595957,
+            std_dev_pct: 64.1488719719,
+            median_abs_dev: 45.9606000000,
+            median_abs_dev_pct: 102.1346666667,
+            quartiles: (29.0000000000, 45.0000000000, 79.0000000000),
+            iqr: 50.0000000000,
+        };
+        check(val, summ);
+    }
+
+    #[test]
+    fn test_sum_f64s() {
+        assert_eq!([0.5f64, 3.2321f64, 1.5678f64].sum(), 5.2999);
+    }
+    #[test]
+    fn test_sum_f64_between_ints_that_sum_to_0() {
+        assert_eq!([1e30f64, 1.2f64, -1e30f64].sum(), 1.2);
+    }
+}
diff --git a/lib/unittest/rules.mk b/lib/unittest/rules.mk
index b1f3223..afe50aa 100644
--- a/lib/unittest/rules.mk
+++ b/lib/unittest/rules.mk
@@ -17,10 +17,10 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-MODULE_SRCS := \
-	$(LOCAL_DIR)/unittest.c
+MODULE_SRCS := $(LOCAL_DIR)/unittest.c
 
-MODULE_EXPORT_INCLUDES += $(LOCAL_DIR)/include/
+MODULE_EXPORT_INCLUDES += 	$(LOCAL_DIR)/include/ \
+							$(LOCAL_DIR)/../pmu/include/
 
 MODULE_LIBRARY_DEPS := \
 	trusty/user/base/interface/line-coverage \
@@ -28,5 +28,6 @@ MODULE_LIBRARY_DEPS := \
 	trusty/user/base/lib/line-coverage \
 	trusty/user/base/lib/libc-trusty \
 	trusty/user/base/lib/tipc \
+	trusty/user/base/lib/pmu
 
 include make/library.mk
diff --git a/make/library.mk b/make/library.mk
index 6ca4795..98e2732 100644
--- a/make/library.mk
+++ b/make/library.mk
@@ -154,6 +154,11 @@ include make/trusted_app.mk
 
 $(call INFO_DONE_SILENT,$(MODULE_RUST_LOG_NAME),processing)
 
+else
+
+MODULE_RUST_TESTS := false
+BUILD_AS_RUST_TEST_MODULE :=
+
 endif
 endif
 else # Not building rust test app
@@ -455,6 +460,20 @@ define CRATE_CONFIG :=
 	"deps": [
 		$(call STRIP_TRAILING_COMMA,$(foreach dep,$(sort $(MODULE_LIBRARY_DEPS) $(MODULE_LIBRARY_EXPORTED_DEPS)),\
 				$(if $(_MODULES_$(dep)_RUST_STEM),{"name": "$(_MODULES_$(dep)_RUST_STEM)"$(COMMA) "crate": $(_MODULES_$(dep)_CRATE_INDEX)}$(COMMA))))
+	],
+	"cfg": [
+		$(call STRIP_TRAILING_COMMA,\
+			$(foreach cfg, \
+				$(filter --cfg=%, \
+					# Look for any cfg flags that are separated by a space and coerce to '='
+					$(shell echo "$(MODULE_RUSTFLAGS) $(GLOBAL_SHARED_RUSTFLAGS)" \
+						| sed -e 's/--cfg /--cfg=/g'\
+					)\
+			# Now that we only have cfgs, remove the --cfg and setup escaped quotations around cfgs that have values
+			),"$(shell echo $(cfg) \
+				| sed -e 's/--cfg=//g' \
+				| sed -E 's/=(.*)/=\\\\\x22\1\\\\\x22/g'\
+				)"$(COMMA)))
 	]
 },
 
diff --git a/make/protoc_plugin.mk b/make/protoc_plugin.mk
index 641c7c8..ba2d232 100644
--- a/make/protoc_plugin.mk
+++ b/make/protoc_plugin.mk
@@ -25,7 +25,11 @@
 # MODULE_PROTO_PACKAGE: a path that matches the directory structure of
 #                       the PROTO package utilized in the module.
 
-PROTOC_TOOL := $(if $(wildcard out/host/linux-x86/bin/aprotoc),out/host/linux-x86/bin/aprotoc,prebuilts/libprotobuf/bin/protoc)
+PROTOC_TOOL := $(firstword $(wildcard out/host/linux-x86/bin/aprotoc prebuilts/libprotobuf/bin/protoc))
+
+ifeq ($(PROTOC_TOOL),)
+$(error No PROTOC_TOOL. Please build the aprotoc or checkout with trusty manifest)
+endif
 
 ifeq ($(MODULE_PROTOC_PLUGIN),)
 $(error No MODULE_PROTOC_PLUGIN provided for $(MODULE))
diff --git a/usertests-inc.mk b/usertests-inc.mk
index 23d2300..c89420f 100644
--- a/usertests-inc.mk
+++ b/usertests-inc.mk
@@ -34,8 +34,6 @@ TRUSTY_USER_TESTS += \
 	trusty/user/base/lib/dlmalloc/test/srv \
 	trusty/user/base/app/metrics/test/crasher \
 	trusty/user/base/app/hwaes-unittest \
-	trusty/user/base/app/hwaes-benchmark \
-	trusty/user/base/app/swaes-benchmark \
 	trusty/user/base/lib/hwbcc/test \
 	trusty/user/base/lib/keymaster/test \
 	trusty/user/base/lib/libc-trusty/test \
@@ -47,6 +45,11 @@ TRUSTY_USER_TESTS += \
 	trusty/user/base/app/cfi-test \
 	trusty/user/base/app/cfi-test/cfi-crasher \
 
+ifneq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_USER_TESTS += \
+	trusty/user/base/app/hwaes-benchmark \
+	trusty/user/base/app/swaes-benchmark
+endif
 
 ifeq (false,$(call TOBOOL,$(CONFIRMATIONUI_DISABLED)))
 TRUSTY_USER_TESTS += \
@@ -86,6 +89,7 @@ TRUSTY_LOADABLE_USER_TASKS += \
 	trusty/user/base/app/apploader/tests/encryption_test_apps/encrypted_app/encryption_required \
 	trusty/user/base/app/apploader/tests/encryption_test_apps/unencrypted_app/encryption_optional \
 	trusty/user/base/app/apploader/tests/encryption_test_apps/unencrypted_app/encryption_required \
+	trusty/user/base/app/apploader/tests/integrity_test_app \
 
 TRUSTY_LOADABLE_USER_TESTS += \
 	trusty/user/base/app/trusty-crasher \
```

