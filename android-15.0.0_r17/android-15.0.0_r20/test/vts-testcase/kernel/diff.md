```diff
diff --git a/abi/Android.bp b/abi/Android.bp
index 6b2fba0..f2ea848 100644
--- a/abi/Android.bp
+++ b/abi/Android.bp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 package {
+    default_team: "trendy_team_native_tools_libraries",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/abi/src/com/android/tests/abi/KernelAbilistTest.java b/abi/src/com/android/tests/abi/KernelAbilistTest.java
index 315b12a..418bab8 100644
--- a/abi/src/com/android/tests/abi/KernelAbilistTest.java
+++ b/abi/src/com/android/tests/abi/KernelAbilistTest.java
@@ -46,6 +46,19 @@ public class KernelAbilistTest extends BaseHostJUnit4Test {
             return;
         }
 
+        // Allow OEMs to keep shipping 32/64 mixed systems if they update their
+        // vendor partition to a newer API level, as long as the device was
+        // first launched before this VSR requirement was added in API 34.
+        // (In that case they wouldn't get the `api_level < 34` early return
+        // that comes next because they updated their vendor partition.)
+        String ro_board_first_api_level = getProp("ro.board.first_api_level");
+        if (!ro_board_first_api_level.isEmpty()) {
+            int originalVsr = Integer.parseInt(ro_board_first_api_level);
+            int deviceFirstLaunched = Integer.parseInt(getProp("ro.product.first_api_level"));
+            boolean isUsingOldBsp = deviceFirstLaunched != originalVsr;
+            if (originalVsr < 34 && isUsingOldBsp) return;
+        }
+
         // ro.vendor.api_level is the VSR requirement API level
         // calculated from ro.product.first_api_level, ro.board.api_level,
         // and ro.board.first_api_level.
diff --git a/api/bpf_native_test/BpfTest.cpp b/api/bpf_native_test/BpfTest.cpp
deleted file mode 100644
index 1b55cdf..0000000
--- a/api/bpf_native_test/BpfTest.cpp
+++ /dev/null
@@ -1,236 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless requied by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- *
- */
-
-#define LOG_TAG "BpfTest"
-
-#include <arpa/inet.h>
-#include <assert.h>
-#include <errno.h>
-#include <inttypes.h>
-#include <linux/pfkeyv2.h>
-#include <netinet/in.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <sys/types.h>
-
-#include <thread>
-
-#include <android-base/file.h>
-#include <android-base/stringprintf.h>
-#include <android-base/unique_fd.h>
-#include <gtest/gtest.h>
-#include <utils/Log.h>
-
-#include "bpf/BpfMap.h"
-#include "bpf/BpfUtils.h"
-#include "kern.h"
-#include "libbpf_android.h"
-
-using android::base::unique_fd;
-using namespace android::bpf;
-
-namespace android {
-
-TEST(BpfTest, bpfMapPinTest) {
-  EXPECT_EQ(0, setrlimitForTest());
-  const char* bpfMapPath = "/sys/fs/bpf/testMap";
-  int ret = access(bpfMapPath, F_OK);
-  if (!ret) {
-    ASSERT_EQ(0, remove(bpfMapPath));
-  } else {
-    ASSERT_EQ(errno, ENOENT);
-  }
-
-  android::base::unique_fd mapfd(createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t),
-                                           sizeof(uint32_t), 10,
-                                           BPF_F_NO_PREALLOC));
-  ASSERT_LT(0, mapfd) << "create map failed with error: " << strerror(errno);
-  ASSERT_EQ(0, bpfFdPin(mapfd, bpfMapPath))
-      << "pin map failed with error: " << strerror(errno);
-  ASSERT_EQ(0, access(bpfMapPath, F_OK));
-  ASSERT_EQ(0, remove(bpfMapPath));
-}
-
-#define BPF_SRC_PATH "/data/local/tmp"
-
-#if defined(__aarch64__) || defined(__x86_64__)
-#define BPF_SRC_NAME "/64/kern.o"
-#else
-#define BPF_SRC_NAME "/32/kern.o"
-#endif
-
-#define BPF_PATH "/sys/fs/bpf"
-#define TEST_PROG_PATH BPF_PATH "/prog_kern_skfilter_test"
-#define TEST_STATS_MAP_A_PATH BPF_PATH "/map_kern_test_stats_map_A"
-#define TEST_STATS_MAP_B_PATH BPF_PATH "/map_kern_test_stats_map_B"
-#define TEST_CONFIGURATION_MAP_PATH BPF_PATH "/map_kern_test_configuration_map"
-
-constexpr int ACTIVE_MAP_KEY = 1;
-const int NUM_CPUS = sysconf(_SC_NPROCESSORS_ONLN);
-const int NUM_SOCKETS = std::min(NUM_CPUS, MAX_NUM_SOCKETS);
-
-class BpfRaceTest : public ::testing::Test {
- protected:
-  BpfRaceTest() {}
-  BpfMap<uint64_t, stats_value> cookieStatsMap[2];
-  BpfMap<uint32_t, uint32_t> configurationMap;
-  bool stop;
-  std::thread *tds = new std::thread[NUM_SOCKETS];
-
-  static void workerThread(int prog_fd, bool *stop) {
-    struct sockaddr_in6 remote = {.sin6_family = AF_INET6};
-    struct sockaddr_in6 local;
-    uint64_t j = 0;
-    int recvSock, sendSock, recv_len;
-    char buf[strlen("msg: 18446744073709551615")];
-    int res;
-    socklen_t slen = sizeof(remote);
-
-    recvSock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
-    EXPECT_NE(-1, recvSock);
-    std::string address = android::base::StringPrintf("::1");
-    EXPECT_NE(0, inet_pton(AF_INET6, address.c_str(), &remote.sin6_addr));
-    EXPECT_NE(-1, bind(recvSock, (struct sockaddr *)&remote, sizeof(remote)));
-    EXPECT_EQ(0, getsockname(recvSock, (struct sockaddr *)&remote, &slen));
-    sendSock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
-    EXPECT_NE(-1, sendSock) << "send socket create failed!\n";
-    EXPECT_NE(-1, setsockopt(recvSock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
-                             sizeof(prog_fd)))
-        << "attach bpf program failed: "
-        << android::base::StringPrintf("%s\n", strerror(errno));
-
-    // Keep sending and receiving packet until test end.
-    while (!*stop) {
-      std::string id = android::base::StringPrintf("msg: %" PRIu64 "\n", j);
-      res = sendto(sendSock, &id, id.length(), 0, (struct sockaddr *)&remote,
-                   slen);
-      EXPECT_EQ(id.size(), res);
-      recv_len = recvfrom(recvSock, &buf, sizeof(buf), 0,
-                          (struct sockaddr *)&local, &slen);
-      EXPECT_EQ(id.size(), recv_len);
-    }
-  }
-
-  void SetUp() {
-    EXPECT_EQ(0, setrlimitForTest());
-    int ret = access(TEST_PROG_PATH, R_OK);
-    // Always create a new program and remove the pinned program after program
-    // loading is done.
-    if (ret == 0) {
-      remove(TEST_PROG_PATH);
-    }
-    std::string progSrcPath = BPF_SRC_PATH BPF_SRC_NAME;
-    // 0 != 2 means ENOENT - ie. missing bpf program.
-    ASSERT_EQ(0, access(progSrcPath.c_str(), R_OK) ? errno : 0);
-    bool critical = false;
-    ASSERT_EQ(0, android::bpf::loadProg(progSrcPath.c_str(), &critical));
-    ASSERT_EQ(true, critical);
-
-    errno = 0;
-    int prog_fd = retrieveProgram(TEST_PROG_PATH);
-    EXPECT_EQ(0, errno);
-    ASSERT_LE(3, prog_fd);
-
-    EXPECT_RESULT_OK(cookieStatsMap[0].init(TEST_STATS_MAP_A_PATH));
-    EXPECT_RESULT_OK(cookieStatsMap[1].init(TEST_STATS_MAP_B_PATH));
-    EXPECT_RESULT_OK(configurationMap.init(TEST_CONFIGURATION_MAP_PATH));
-    EXPECT_TRUE(cookieStatsMap[0].isValid());
-    EXPECT_TRUE(cookieStatsMap[1].isValid());
-    EXPECT_TRUE(configurationMap.isValid());
-    EXPECT_RESULT_OK(configurationMap.writeValue(ACTIVE_MAP_KEY, 0, BPF_ANY));
-
-    // Start several threads to send and receive packets with an eBPF program
-    // attached to the socket.
-    stop = false;
-
-    for (int i = 0; i < NUM_SOCKETS; i++) {
-      tds[i] = std::thread(workerThread, prog_fd, &stop);
-    }
-  }
-
-  void TearDown() {
-    // Stop the threads and clean up the program.
-    stop = true;
-    for (int i = 0; i < NUM_SOCKETS; i++) {
-      if (tds[i].joinable()) tds[i].join();
-    }
-    delete [] tds;
-    remove(TEST_PROG_PATH);
-    remove(TEST_STATS_MAP_A_PATH);
-    remove(TEST_STATS_MAP_B_PATH);
-    remove(TEST_CONFIGURATION_MAP_PATH);
-  }
-
-  void swapAndCleanStatsMap(bool expectSynchronized, int seconds) {
-    uint64_t i = 0;
-    auto test_start = std::chrono::system_clock::now();
-    while ((std::chrono::duration_cast<std::chrono::milliseconds>(
-                std::chrono::system_clock::now() - test_start)
-                .count() /
-            1000) < seconds) {
-      // Check if the vacant map is empty based on the current configuration.
-      auto isEmpty = cookieStatsMap[i].isEmpty();
-      ASSERT_RESULT_OK(isEmpty);
-      if (expectSynchronized) {
-        // The map should always be empty because synchronizeKernelRCU should
-        // ensure that the BPF programs running on all cores have seen the write
-        // to the configuration map that tells them to write to the other map.
-        // If it's not empty, fail.
-        ASSERT_TRUE(isEmpty.value())
-            << "Race problem between stats clean and updates";
-      } else if (!isEmpty.value()) {
-        // We found a race condition, which is expected (eventually) because
-        // we're not calling synchronizeKernelRCU. Pass the test.
-        break;
-      }
-
-      // Change the configuration and wait for rcu grace period.
-      i ^= 1;
-      ASSERT_RESULT_OK(configurationMap.writeValue(ACTIVE_MAP_KEY, i, BPF_ANY));
-      if (expectSynchronized) {
-        EXPECT_EQ(0, synchronizeKernelRCU());
-      }
-
-      // Clean up the previous map after map swap.
-      EXPECT_RESULT_OK(cookieStatsMap[i].clear());
-    }
-    if (!expectSynchronized) {
-      auto test_end = std::chrono::system_clock::now();
-      auto diffSec = test_end - test_start;
-      auto msec =
-          std::chrono::duration_cast<std::chrono::milliseconds>(diffSec);
-      EXPECT_GE(seconds, (double)(msec.count() / 1000.0))
-          << "Race problem didn't happen before time out";
-    }
-  }
-};
-
-// Verify the race problem disappear when the kernel call synchronize_rcu
-// after changing the active map.
-TEST_F(BpfRaceTest, testRaceWithBarrier) {
-  swapAndCleanStatsMap(true, 30);
-}
-
-// Confirm the race problem exists when the kernel doesn't call synchronize_rcu
-// after changing the active map.
-// This test is flaky. Race not triggering isn't really a bug per say...
-// Maybe we should just outright delete this test...
-TEST_F(BpfRaceTest, DISABLED_testRaceWithoutBarrier) {
-  swapAndCleanStatsMap(false, 240);
-}
-
-}  // namespace android
diff --git a/api/bpf_native_test/OWNERS b/api/bpf_native_test/OWNERS
deleted file mode 100644
index c53d0c4..0000000
--- a/api/bpf_native_test/OWNERS
+++ /dev/null
@@ -1,3 +0,0 @@
-# Bug component: 31808
-set noparent
-file:platform/system/bpf:main:/OWNERS_bpf
diff --git a/api/bpf_native_test/kern.c b/api/bpf_native_test/kern.c
deleted file mode 100644
index 81c3a98..0000000
--- a/api/bpf_native_test/kern.c
+++ /dev/null
@@ -1,57 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
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
-#include "bpf_net_helpers.h"
-#include "kern.h"
-
-DEFINE_BPF_MAP(test_configuration_map, HASH, uint32_t, uint32_t, 1)
-DEFINE_BPF_MAP(test_stats_map_A, HASH, uint64_t, stats_value, MAX_NUM_SOCKETS)
-DEFINE_BPF_MAP(test_stats_map_B, HASH, uint64_t, stats_value, MAX_NUM_SOCKETS)
-
-#define DEFINE_UPDATE_INGRESS_STATS(the_map)                               \
-  static inline void update_ingress_##the_map(struct __sk_buff* skb) {     \
-    uint64_t sock_cookie = bpf_get_socket_cookie(skb);                     \
-    stats_value* value = bpf_##the_map##_lookup_elem(&sock_cookie);        \
-    if (!value) {                                                          \
-      stats_value newValue = {};                                           \
-      bpf_##the_map##_update_elem(&sock_cookie, &newValue, BPF_NOEXIST);   \
-      value = bpf_##the_map##_lookup_elem(&sock_cookie);                   \
-    }                                                                      \
-    if (value) {                                                           \
-      __sync_fetch_and_add(&value->rxPackets, 1);                          \
-      __sync_fetch_and_add(&value->rxBytes, skb->len);                     \
-    }                                                                      \
-  }
-
-DEFINE_UPDATE_INGRESS_STATS(test_stats_map_A)
-DEFINE_UPDATE_INGRESS_STATS(test_stats_map_B)
-
-DEFINE_BPF_PROG("skfilter/test", AID_ROOT, AID_ROOT, ingress_prog)
-(struct __sk_buff* skb) {
-  uint32_t key = 1;
-  uint32_t* config = bpf_test_configuration_map_lookup_elem(&key);
-  if (config) {
-    if (*config) {
-      update_ingress_test_stats_map_A(skb);
-    } else {
-      update_ingress_test_stats_map_B(skb);
-    }
-  }
-  return skb->len;
-}
-
-LICENSE("Apache 2.0");
-CRITICAL("bpf_native_test");
diff --git a/api/bpf_native_test/kern.h b/api/bpf_native_test/kern.h
deleted file mode 100644
index b7c5dd7..0000000
--- a/api/bpf_native_test/kern.h
+++ /dev/null
@@ -1,25 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
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
-#include <stdint.h>
-
-const int MAX_NUM_SOCKETS = 8;  // Max available number of threads per device.
-
-typedef struct {
-  uint64_t rxPackets;
-  uint64_t rxBytes;
-  uint64_t txPackets;
-  uint64_t txBytes;
-} stats_value;
diff --git a/api/drop_caches_prop/Android.bp b/api/drop_caches_prop/Android.bp
index 96cfb2c..4a60e92 100644
--- a/api/drop_caches_prop/Android.bp
+++ b/api/drop_caches_prop/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_treble",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/api/sysfs/Android.bp b/api/sysfs/Android.bp
index fbf5b7c..5d62c54 100644
--- a/api/sysfs/Android.bp
+++ b/api/sysfs/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/bow/Android.bp b/bow/Android.bp
index 282ef27..5ac351f 100644
--- a/bow/Android.bp
+++ b/bow/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/checkpoint/Android.bp b/checkpoint/Android.bp
index c8c6857..7097bed 100644
--- a/checkpoint/Android.bp
+++ b/checkpoint/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_treble",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/dynamic_partitions/Android.bp b/dynamic_partitions/Android.bp
index 3778d9c..3b88460 100644
--- a/dynamic_partitions/Android.bp
+++ b/dynamic_partitions/Android.bp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/encryption/Android.bp b/encryption/Android.bp
index 911d4da..8dfa7f9 100644
--- a/encryption/Android.bp
+++ b/encryption/Android.bp
@@ -53,6 +53,7 @@ cc_test {
         "liblzma",
     ],
     test_suites: [
+        "automotive-sdv-tests",
         "general-tests",
         "vts",
     ],
diff --git a/encryption/Keymaster.cpp b/encryption/Keymaster.cpp
index 306d37e..eba8691 100644
--- a/encryption/Keymaster.cpp
+++ b/encryption/Keymaster.cpp
@@ -59,11 +59,12 @@ static bool logKeystore2ExceptionIfPresent(::ndk::ScopedAStatus& rc,
 }
 
 Keymaster::Keymaster() {
-  ::ndk::SpAIBinder binder(AServiceManager_getService(keystore2_service_name));
+  ::ndk::SpAIBinder binder(
+      AServiceManager_waitForService(keystore2_service_name));
   auto keystore2Service = ks2::IKeystoreService::fromBinder(binder);
 
   if (!keystore2Service) {
-    LOG(ERROR) << "Vold unable to connect to keystore2.";
+    LOG(ERROR) << "Unable to connect to keystore2.";
     return;
   }
 
@@ -81,15 +82,15 @@ Keymaster::Keymaster() {
   auto rc = keystore2Service->getSecurityLevel(
       km::SecurityLevel::TRUSTED_ENVIRONMENT, &securityLevel);
   if (logKeystore2ExceptionIfPresent(rc, "getSecurityLevel"))
-    LOG(ERROR) << "Vold unable to get security level from keystore2.";
+    LOG(ERROR) << "Unable to get security level from keystore2.";
 }
 
 bool Keymaster::generateKey(const km::AuthorizationSet& inParams,
                             std::string* key) {
   ks2::KeyDescriptor in_key = {
       .domain = ks2::Domain::BLOB,
-      .alias = std::nullopt,
       .nspace = ROOT_NAMESPACE,
+      .alias = std::nullopt,
       .blob = std::nullopt,
   };
   ks2::KeyMetadata keyMetadata;
@@ -114,8 +115,8 @@ bool Keymaster::importKey(const km::AuthorizationSet& inParams,
                           const std::string& key, std::string* outKeyBlob) {
   ks2::KeyDescriptor key_desc = {
       .domain = ks2::Domain::BLOB,
-      .alias = std::nullopt,
       .nspace = ROOT_NAMESPACE,
+      .alias = std::nullopt,
       .blob = std::nullopt,
   };
   std::vector<uint8_t> key_vec(key.begin(), key.end());
@@ -141,8 +142,8 @@ bool Keymaster::exportKey(const std::string& kmKey, std::string* key) {
   bool ret = false;
   ks2::KeyDescriptor storageKey = {
       .domain = ks2::Domain::BLOB,
-      .alias = std::nullopt,
       .nspace = ROOT_NAMESPACE,
+      .alias = std::nullopt,
   };
   storageKey.blob =
       std::make_optional<std::vector<uint8_t>>(kmKey.begin(), kmKey.end());
diff --git a/encryption/utils.cpp b/encryption/utils.cpp
index 41430f3..e47aac2 100644
--- a/encryption/utils.cpp
+++ b/encryption/utils.cpp
@@ -16,6 +16,7 @@
 
 // Utility functions for VtsKernelEncryptionTest.
 
+#include <algorithm>
 #include <fstream>
 
 #include <LzmaLib.h>
@@ -44,10 +45,19 @@ using namespace android::dm;
 
 namespace android {
 namespace kernel {
+
+enum KdfVariant {
+  KDF_VARIANT_V1 = 0,
+  KDF_VARIANT_LEGACY = 1,
+  KDF_VARIANT_REARRANGED = 2,
+  KDF_VARIANT_COUNT,
+};
+
 // Context in fixed input string comprises of software provided context,
 // padding to eight bytes (if required) and the key policy.
 static const std::vector<std::vector<uint8_t>> HwWrappedEncryptionKeyContexts =
     {
+        // "v1"
         {'i',  'n',  'l',  'i',  'n',  'e',  ' ',  'e',  'n', 'c', 'r', 'y',
          'p',  't',  'i',  'o',  'n',  ' ',  'k',  'e',  'y', 0x0, 0x0, 0x0,
          0x00, 0x00, 0x00, 0x02, 0x43, 0x00, 0x82, 0x50, 0x0, 0x0, 0x0, 0x0},
@@ -55,24 +65,92 @@ static const std::vector<std::vector<uint8_t>> HwWrappedEncryptionKeyContexts =
         // Environment(TEE)".
         // Where as above caters ( "all latest targets" || ("legacy && kdf
         // not tied to TEE)).
+        // "legacykdf"
         {'i',  'n',  'l',  'i',  'n',  'e',  ' ',  'e',  'n', 'c', 'r', 'y',
          'p',  't',  'i',  'o',  'n',  ' ',  'k',  'e',  'y', 0x0, 0x0, 0x0,
          0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0x82, 0x18, 0x0, 0x0, 0x0, 0x0},
+        // "rearranged"
+        {
+            'i',  'n',  'l',  'i',  'n',  'e',  ' ',  'e',  'n',
+            'c',  'r',  'y',  'p',  't',  'i',  'o',  'n',  ' ',
+            's',  't',  'o',  'r',  'a',  'g',  'e',  'k',  'e',
+            'y',  ' ',  'c',  't',  'x',  0x00, 0x00, 0x00, 0x00,
+            0x00, 0x10, 0x70, 0x18, 0x72, 0x00, 0x00, 0x00, 0x00,
+        }};
+
+static const std::vector<std::vector<uint8_t>> HwWrappedEncryptionKeyLabels = {
+    // "v1"
+    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
+    // "legacykdf"
+    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
+    // "rearranged"
+    {
+        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+    },
 };
 
-static bool GetKdfContext(std::vector<uint8_t> *ctx) {
+static const std::vector<std::vector<uint8_t>> SwSecretContexts = {
+    // "v1"
+    {
+        'r',  'a',  'w',  ' ',  's', 'e', 'c',  'r',  'e',  't',
+        0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x00, 0x00, 0x00, 0x02,
+        0x17, 0x00, 0x80, 0x50, 0x0, 0x0, 0x0,  0x0,
+    },
+    // "legacykdf"
+    {
+        'r',  'a',  'w',  ' ',  's', 'e', 'c',  'r',  'e',  't',
+        0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x00, 0x00, 0x00, 0x02,
+        0x17, 0x00, 0x80, 0x50, 0x0, 0x0, 0x0,  0x0,
+    },
+    // "rearranged"
+    {
+        'd', 'e', 'r', 'i', 'v', 'e', ' ', 'r', 'a', 'w', ' ',
+        's', 'e', 'c', 'r', 'e', 't', ' ', 'c', 'o', 'n', 't',
+        'e', 'x', 't', ' ', 'a', 'b', 'c', 'd', 'e', 'f',
+    }};
+
+static const std::vector<std::vector<uint8_t>> SwSecretLabels = {
+    // "v1"
+    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
+    // "legacykdf"
+    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
+    // "rearranged"
+    {
+        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+    },
+};
+
+static bool GetKdfVariantId(KdfVariant *kdf_id) {
   std::string kdf =
       android::base::GetProperty("ro.crypto.hw_wrapped_keys.kdf", "v1");
+
   if (kdf == "v1") {
-    *ctx = HwWrappedEncryptionKeyContexts[0];
-    return true;
-  }
-  if (kdf == "legacykdf") {
-    *ctx = HwWrappedEncryptionKeyContexts[1];
-    return true;
+    *kdf_id = KDF_VARIANT_V1;
+  } else if (kdf == "legacykdf") {
+    *kdf_id = KDF_VARIANT_LEGACY;
+  } else if (kdf == "rearranged") {
+    *kdf_id = KDF_VARIANT_REARRANGED;
+  } else {
+    ADD_FAILURE() << "Unknown KDF: " << kdf;
+    return false;
   }
-  ADD_FAILURE() << "Unknown KDF: " << kdf;
-  return false;
+  return true;
+}
+
+static void GetKdfContextLabelByKdfId(KdfVariant kdf_id,
+                                      std::vector<uint8_t> *ctx,
+                                      std::vector<uint8_t> *lbl) {
+  *ctx = HwWrappedEncryptionKeyContexts[kdf_id];
+  *lbl = HwWrappedEncryptionKeyLabels[kdf_id];
+}
+
+static void GetSwSecretContextLabelByKdfId(KdfVariant kdf_id,
+                                           std::vector<uint8_t> *ctx,
+                                           std::vector<uint8_t> *lbl) {
+  *ctx = SwSecretContexts[kdf_id];
+  *lbl = SwSecretLabels[kdf_id];
 }
 
 // Offset in bytes to the filesystem superblock, relative to the beginning of
@@ -465,7 +543,28 @@ static void PushBigEndian32(uint32_t val, std::vector<uint8_t> *vec) {
   }
 }
 
-static void GetFixedInputString(uint32_t counter,
+static void RearrangeFixedInputString(
+    KdfVariant kdf_id, std::vector<uint8_t> *fixed_input_string) {
+  if (kdf_id != KDF_VARIANT_REARRANGED) {
+    return;
+  }
+
+  // Rearrange the fixed-input string, reversing the order that the blocks are
+  // processed:
+  // ABCD-EFGH-IJKL-MNO
+  // into
+  // LMNO-HIJK-DEFG-ABC
+  size_t len = fixed_input_string->size();
+  std::vector<uint8_t> tmp(len);
+  for (size_t j = 0; j < len; j += kAesBlockSize) {
+    size_t to_copy = std::min((size_t)kAesBlockSize, len - j);
+    std::copy(fixed_input_string->cbegin() + len - j - to_copy,
+              fixed_input_string->cbegin() + len - j, tmp.begin() + j);
+  }
+  std::copy(tmp.cbegin(), tmp.cend(), fixed_input_string->begin());
+}
+
+static void GetFixedInputString(KdfVariant kdf_id, uint32_t counter,
                                 const std::vector<uint8_t> &label,
                                 const std::vector<uint8_t> &context,
                                 uint32_t derived_key_len,
@@ -477,18 +576,24 @@ static void GetFixedInputString(uint32_t counter,
   fixed_input_string->insert(fixed_input_string->end(), context.begin(),
                              context.end());
   PushBigEndian32(derived_key_len, fixed_input_string);
+
+  // If applicable, rearrange the fixed-input string
+  RearrangeFixedInputString(kdf_id, fixed_input_string);
 }
 
-static bool AesCmacKdfHelper(const std::vector<uint8_t> &key,
+static bool AesCmacKdfHelper(KdfVariant kdf_id, const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &label,
                              const std::vector<uint8_t> &context,
                              uint32_t output_key_size,
                              std::vector<uint8_t> *output_data) {
+  GTEST_LOG_(INFO) << "KDF ID = " << kdf_id;
   output_data->resize(output_key_size);
   for (size_t count = 0; count < (output_key_size / kAesBlockSize); count++) {
     std::vector<uint8_t> fixed_input_string;
-    GetFixedInputString(count + 1, label, context, (output_key_size * 8),
-                        &fixed_input_string);
+    GetFixedInputString(kdf_id, count + 1, label, context,
+                        (output_key_size * 8), &fixed_input_string);
+    GTEST_LOG_(INFO) << "Fixed Input (block: " << count
+                     << "): " << BytesToHex(fixed_input_string);
     if (!AES_CMAC(output_data->data() + (kAesBlockSize * count), key.data(),
                   key.size(), fixed_input_string.data(),
                   fixed_input_string.size())) {
@@ -500,30 +605,128 @@ static bool AesCmacKdfHelper(const std::vector<uint8_t> &key,
   return true;
 }
 
+static bool DeriveHwWrappedEncryptionKeyByKdfId(
+    KdfVariant kdf_id, const std::vector<uint8_t> &master_key,
+    std::vector<uint8_t> *enc_key) {
+  std::vector<uint8_t> ctx;
+  std::vector<uint8_t> label;
+  GetKdfContextLabelByKdfId(kdf_id, &ctx, &label);
+  return AesCmacKdfHelper(kdf_id, master_key, label, ctx, kAes256XtsKeySize,
+                          enc_key);
+}
+
 bool DeriveHwWrappedEncryptionKey(const std::vector<uint8_t> &master_key,
                                   std::vector<uint8_t> *enc_key) {
-  std::vector<uint8_t> label{0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
-                             0x00, 0x00, 0x00, 0x00, 0x20};
+  KdfVariant kdf_id;
+  if (!GetKdfVariantId(&kdf_id)) {
+    return false;
+  }
+  return DeriveHwWrappedEncryptionKeyByKdfId(kdf_id, master_key, enc_key);
+}
 
+static bool DeriveHwWrappedRawSecretByKdfId(
+    KdfVariant kdf_id, const std::vector<uint8_t> &master_key,
+    std::vector<uint8_t> *secret) {
   std::vector<uint8_t> ctx;
-
-  if (!GetKdfContext(&ctx)) return false;
-
-  return AesCmacKdfHelper(master_key, label, ctx, kAes256XtsKeySize, enc_key);
+  std::vector<uint8_t> label;
+  GetSwSecretContextLabelByKdfId(kdf_id, &ctx, &label);
+  return AesCmacKdfHelper(kdf_id, master_key, label, ctx, kAes256KeySize,
+                          secret);
 }
 
 bool DeriveHwWrappedRawSecret(const std::vector<uint8_t> &master_key,
                               std::vector<uint8_t> *secret) {
-  std::vector<uint8_t> label{0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
-                             0x00, 0x00, 0x00, 0x00, 0x20};
-  // Context in fixed input string comprises of software provided context,
-  // padding to eight bytes (if required) and the key policy.
-  std::vector<uint8_t> context = {'r',  'a',  'w',  ' ',  's',  'e',  'c',
-                                  'r',  'e',  't',  0x0,  0x0,  0x0,  0x0,
-                                  0x0,  0x0,  0x00, 0x00, 0x00, 0x02, 0x17,
-                                  0x00, 0x80, 0x50, 0x0,  0x0,  0x0,  0x0};
-
-  return AesCmacKdfHelper(master_key, label, context, kAes256KeySize, secret);
+  KdfVariant kdf_id;
+  if (!GetKdfVariantId(&kdf_id)) {
+    return false;
+  }
+  return DeriveHwWrappedRawSecretByKdfId(kdf_id, master_key, secret);
+}
+
+TEST(UtilsTest, TestKdfVariants) {
+  std::vector<KdfVariant> kdf_ids = {
+      KDF_VARIANT_V1,
+      KDF_VARIANT_LEGACY,
+      KDF_VARIANT_REARRANGED,
+  };
+
+  std::vector<std::vector<uint8_t>> expected_keys = {
+      // "v1"
+      {
+          0xcb, 0xe5, 0xdb, 0x40, 0x21, 0x5a, 0x3d, 0x38, 0x6d, 0x61, 0xe5,
+          0x4e, 0xf2, 0xf8, 0xa7, 0x81, 0x4b, 0x00, 0xba, 0xcf, 0x35, 0xb3,
+          0x16, 0xf8, 0x8e, 0x68, 0xe8, 0x9a, 0x47, 0xab, 0xba, 0xb4, 0x83,
+          0x4c, 0x27, 0xda, 0xc8, 0xa9, 0x1a, 0xe1, 0xc3, 0x30, 0x4f, 0x31,
+          0xb5, 0xf2, 0x20, 0x2c, 0x14, 0x98, 0x96, 0x61, 0xba, 0xfc, 0xcc,
+          0x56, 0xcf, 0x62, 0x12, 0xd8, 0xb1, 0xf7, 0x26, 0x91,
+      },
+      // "legacykdf"
+      {
+          0x63, 0x61, 0xf8, 0x02, 0xb3, 0x7a, 0xa6, 0x4a, 0x07, 0x57, 0x84,
+          0xbe, 0xde, 0x23, 0x41, 0xf1, 0xd9, 0x23, 0x6e, 0x64, 0x6c, 0x70,
+          0x46, 0x0f, 0x15, 0xb3, 0x7c, 0xe5, 0xff, 0x43, 0xa5, 0x4f, 0x15,
+          0xd9, 0x56, 0x93, 0x34, 0x3d, 0x52, 0x8b, 0x67, 0x37, 0x2a, 0x7f,
+          0x38, 0x3e, 0xd8, 0xe7, 0xc4, 0x5e, 0xd0, 0x89, 0x9e, 0x02, 0x82,
+          0x54, 0x53, 0xc9, 0x41, 0x9a, 0xaf, 0xa3, 0x69, 0x5f,
+      },
+      // "rearranged"
+      {
+          0xdb, 0xa0, 0xa6, 0x7e, 0x47, 0x1b, 0xe3, 0x9f, 0xd1, 0xec, 0x28,
+          0x99, 0x45, 0xf5, 0x21, 0x45, 0xdf, 0x12, 0x93, 0x7a, 0x0b, 0x42,
+          0x91, 0x5f, 0x7c, 0x71, 0x1f, 0xeb, 0x47, 0x40, 0x3e, 0x6a, 0xe5,
+          0xb7, 0xb5, 0x29, 0x68, 0xa8, 0xcc, 0x63, 0x5d, 0x10, 0xab, 0x8b,
+          0x87, 0x24, 0xef, 0x5d, 0xec, 0x62, 0x36, 0xd8, 0x1a, 0x1b, 0x38,
+          0x78, 0x08, 0xc4, 0x07, 0xce, 0x01, 0xc5, 0x63, 0x88,
+      },
+  };
+
+  std::vector<std::vector<uint8_t>> expected_secrets = {
+      // "v1"
+      {
+          0xe2, 0x6f, 0xb1, 0x9b, 0x4f, 0xb6, 0x26, 0x6f, 0xc7, 0xc5, 0xfc,
+          0x96, 0x54, 0xef, 0xad, 0x64, 0x3c, 0xfe, 0xbc, 0x64, 0xc0, 0x97,
+          0x34, 0x11, 0x55, 0x19, 0x55, 0x95, 0xc2, 0x8d, 0x5e, 0xc9,
+      },
+      // "legacykdf"
+      {
+          0xe2, 0x6f, 0xb1, 0x9b, 0x4f, 0xb6, 0x26, 0x6f, 0xc7, 0xc5, 0xfc,
+          0x96, 0x54, 0xef, 0xad, 0x64, 0x3c, 0xfe, 0xbc, 0x64, 0xc0, 0x97,
+          0x34, 0x11, 0x55, 0x19, 0x55, 0x95, 0xc2, 0x8d, 0x5e, 0xc9,
+      },
+      // "rearranged"
+      {
+          0x4e, 0xf0, 0x6e, 0x6a, 0xa9, 0x84, 0x10, 0x46, 0x67, 0x86, 0x3f,
+          0x15, 0x08, 0x7c, 0x12, 0xbb, 0xfb, 0x8e, 0x47, 0x15, 0x14, 0x5b,
+          0xc0, 0x6b, 0x59, 0x82, 0xab, 0xd4, 0x19, 0x83, 0x85, 0xb4,
+      },
+  };
+
+  ASSERT_EQ(kdf_ids.size(), KDF_VARIANT_COUNT);
+  ASSERT_EQ(expected_keys.size(), KDF_VARIANT_COUNT);
+  ASSERT_EQ(expected_secrets.size(), KDF_VARIANT_COUNT);
+
+  const std::vector<uint8_t> master_key = {
+      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+  };
+
+  GTEST_LOG_(INFO) << "Master Key: " << BytesToHex(master_key);
+  for (size_t i = 0; i < KDF_VARIANT_COUNT; i++) {
+    std::vector<uint8_t> out_key;
+    EXPECT_TRUE(
+        DeriveHwWrappedEncryptionKeyByKdfId(kdf_ids[i], master_key, &out_key));
+    GTEST_LOG_(INFO) << "Key        (id: " << i << "): " << BytesToHex(out_key);
+    GTEST_LOG_(INFO) << "Exp Key    (id: " << i
+                     << "): " << BytesToHex(expected_keys[i]);
+    EXPECT_EQ(out_key, expected_keys[i]);
+    std::vector<uint8_t> out_sec;
+    EXPECT_TRUE(
+        DeriveHwWrappedRawSecretByKdfId(kdf_ids[i], master_key, &out_sec));
+    GTEST_LOG_(INFO) << "Secret     (id: " << i << "): " << BytesToHex(out_sec);
+    GTEST_LOG_(INFO) << "Exp Secret (id: " << i
+                     << "): " << BytesToHex(expected_secrets[i]);
+    EXPECT_EQ(out_sec, expected_secrets[i]);
+  }
 }
 
 }  // namespace kernel
diff --git a/api/bpf_native_test/Android.bp b/f2fs/Android.bp
similarity index 60%
rename from api/bpf_native_test/Android.bp
rename to f2fs/Android.bp
index 94f07dd..662520d 100644
--- a/api/bpf_native_test/Android.bp
+++ b/f2fs/Android.bp
@@ -1,5 +1,5 @@
 //
-// Copyright (C) 2018 The Android Open Source Project
+// Copyright (C) 2020 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -15,25 +15,20 @@
 //
 
 package {
-    default_team: "trendy_team_fwk_core_networking",
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
 cc_defaults {
-    name: "binary_bpf_defaults",
-    srcs: ["BpfTest.cpp"],
+    name: "binary_f2fs_defaults",
+    srcs: ["F2fsTest.cpp"],
     shared_libs: [
-        "libcutils",
-        "libutils",
-        "liblog",
         "libbase",
+        "liblog",
+        "liblogwrap",
     ],
     static_libs: [
-        "libbpf_bcc",
-        "libbpf_android",
-        "libbpf_minimal",
-        "libnetdutils",
-        "libtestUtil",
+        "libdm",
     ],
     cflags: [
         "-fno-strict-aliasing",
@@ -41,24 +36,18 @@ cc_defaults {
         "-Werror",
         "-Wno-unused-variable",
     ],
-    data: [
-        ":kern.o",
-    ],
-
-}
-
-bpf {
-    name: "kern.o",
-    include_dirs: ["packages/modules/Connectivity/bpf/progs"],
-    srcs: ["kern.c"],
 }
 
 cc_test {
-    name: "bpf_module_test",
-    defaults: ["binary_bpf_defaults"],
-    test_config: "bpf_module_test.xml",
+    name: "f2fs_test",
+    defaults: ["binary_f2fs_defaults"],
+    test_config: "f2fs_test.xml",
     test_suites: [
         "general-tests",
-        "vts",
     ],
 }
+
+cc_test {
+    name: "vts_test_binary_f2fs",
+    defaults: ["binary_f2fs_defaults"],
+}
diff --git a/f2fs/F2fsTest.cpp b/f2fs/F2fsTest.cpp
new file mode 100644
index 0000000..19f2981
--- /dev/null
+++ b/f2fs/F2fsTest.cpp
@@ -0,0 +1,217 @@
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
+ *
+ */
+#include <android-base/logging.h>
+#include <gtest/gtest.h>
+
+#include <libdm/loop_control.h>
+#include <logwrap/logwrap.h>
+
+#include <sys/ioctl.h>
+#include <sys/mount.h>
+#include <sys/stat.h>
+
+#include <linux/f2fs.h>
+#include <linux/fs.h>
+
+#include <chrono>
+#include <fstream>
+
+using LoopDevice = android::dm::LoopDevice;
+using namespace std::chrono_literals;
+
+static const char* kMkfsPath = "/system/bin/make_f2fs";
+static const char* kMountPath = "/system/bin/mount";
+static const char* kUmountPath = "/system/bin/umount";
+
+static const char* kTestFilePath = "/data/local/tmp/mnt/test";
+
+namespace android {
+
+class F2fsTest : public testing::Test {
+  void SetUp() override {
+    int fd = open("/data/local/tmp/img", O_RDWR | O_TRUNC | O_CREAT,
+                  (S_IRWXU | S_IRGRP | S_IROTH));
+    int flags = FS_COMPR_FL;
+    int res;
+
+    ASSERT_NE(fd, -1);
+    res = ftruncate(fd, 100 << 20);  // 100 MB
+    ASSERT_EQ(res, 0);
+    close(fd);
+
+    const char* make_fs_argv[] = {
+        kMkfsPath,
+        "-f",
+        "-O",
+        "extra_attr",
+        "-O",
+        "project_quota",
+        "-O",
+        "compression",
+        "-g",
+        "android",
+        "/data/local/tmp/img",
+    };
+    res = logwrap_fork_execvp(arraysize(make_fs_argv), make_fs_argv, nullptr,
+                              false, LOG_KLOG, true, nullptr);
+    ASSERT_EQ(res, 0);
+    mkdir("/data/local/tmp/mnt", (S_IRWXU | S_IRGRP | S_IROTH));
+
+    LoopDevice loop_dev("/data/local/tmp/img", 10s);
+    ASSERT_TRUE(loop_dev.valid());
+
+    ASSERT_EQ(mount(loop_dev.device().c_str(), "data/local/tmp/mnt", "f2fs", 0,
+                    "compress_mode=user"),
+              0);
+    test_data1 = malloc(4096);
+    ASSERT_NE(test_data1, nullptr);
+    memset(test_data1, 0x41, 4096);
+    test_data2 = malloc(4096);
+    ASSERT_NE(test_data2, nullptr);
+    memset(test_data2, 0x61, 4096);
+  }
+  void TearDown() override {
+    ASSERT_EQ(umount2("/data/local/tmp/mnt", MNT_DETACH), 0);
+    ASSERT_EQ(unlink("/data/local/tmp/img"), 0);
+    ASSERT_EQ(rmdir("/data/local/tmp/mnt"), 0);
+    free(test_data1);
+    free(test_data2);
+  }
+
+ protected:
+  void* test_data1;
+  void* test_data2;
+};
+
+TEST_F(F2fsTest, test_normal_lseek) {
+  char buf[4096];
+  int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
+                (S_IRWXU | S_IRGRP | S_IROTH));
+  ASSERT_NE(fd, -1);
+
+  ASSERT_EQ(lseek(fd, 1024 * 4096, SEEK_SET), 1024 * 4096);
+  for (int i = 0; i < 1024; i++) {
+    ASSERT_EQ(write(fd, test_data1, 4096), 4096);
+  }
+  fsync(fd);
+  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 0);
+  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * 4096);
+  lseek(fd, 0, SEEK_SET);
+  write(fd, test_data2, 4096);
+  fsync(fd);
+  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 0);
+
+  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 4096);
+  ASSERT_EQ(lseek(fd, 5000, SEEK_DATA), 1024 * 4096);
+}
+
+TEST_F(F2fsTest, test_compressed_lseek) {
+  char buf[4096];
+
+  int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
+                (S_IRWXU | S_IRGRP | S_IROTH));
+  ASSERT_NE(fd, -1);
+
+  int flags = FS_COMPR_FL;
+  ASSERT_NE(ioctl(fd, FS_IOC_SETFLAGS, &flags), -1);
+  ASSERT_EQ(lseek(fd, 1024 * 4096, SEEK_SET), 1024 * 4096);
+  for (int i = 0; i < 1024; i++) {
+    ASSERT_EQ(write(fd, test_data1, 4096), 4096);
+  }
+  fsync(fd);
+  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 0);
+  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * 4096);
+  ASSERT_NE(ioctl(fd, F2FS_IOC_COMPRESS_FILE), -1);
+  lseek(fd, 0, SEEK_SET);
+  write(fd, test_data2, 4096);
+  fsync(fd);
+  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 0);
+  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 4096);
+  ASSERT_EQ(lseek(fd, 5000, SEEK_DATA), 1024 * 4096);
+}
+
+TEST_F(F2fsTest, test_sparse_decompress) {
+  char buf[4096];
+  int res;
+
+  int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
+                (S_IRWXU | S_IRGRP | S_IROTH));
+  ASSERT_NE(fd, -1);
+  int flags = FS_COMPR_FL;
+
+  ASSERT_NE(fd, -1);
+
+  ASSERT_NE(ioctl(fd, FS_IOC_SETFLAGS, &flags), -1);
+  res = lseek(fd, 1024 * 4096, SEEK_SET);
+  ASSERT_EQ(res, 1024 * 4096);
+  for (int i = 0; i < 1024; i++) {
+    res = write(fd, test_data1, 4096);
+    ASSERT_EQ(res, 4096);
+  }
+  fsync(fd);
+  ASSERT_NE(ioctl(fd, F2FS_IOC_COMPRESS_FILE), -1);
+  lseek(fd, 0, SEEK_SET);
+  write(fd, test_data2, 4096);
+  fsync(fd);
+  int pid = fork();
+  if (pid == 0) {
+    // If this fails, we must reset the device or it will be left in a bad state
+    exit(ioctl(fd, F2FS_IOC_DECOMPRESS_FILE));
+  }
+  int status;
+  int time = 0;
+  while (time < 50) {
+    res = waitpid(pid, &status, WNOHANG);
+    if (res) {
+      ASSERT_EQ(pid, res);
+      ASSERT_EQ(WIFEXITED(status), true);
+      ASSERT_EQ(WEXITSTATUS(status), 0);
+      break;
+    }
+    sleep(5);
+    time += 5;
+  }
+  if (!res) {
+    std::ofstream reboot_trigger("/proc/sysrq-trigger");
+    reboot_trigger << "c";
+    reboot_trigger.close();
+    return;
+  }
+  close(fd);
+  // Check for corruption
+  fd = open(kTestFilePath, O_RDONLY);
+  ASSERT_NE(fd, -1);
+  res = read(fd, buf, 4096);
+  ASSERT_EQ(res, 4096);
+  ASSERT_EQ(memcmp(buf, test_data2, 4096), 0);
+
+  char empty_buf[4096];
+  memset(empty_buf, 0, 4096);
+  for (int i = 1; i < 1024; i++) {
+    res = read(fd, buf, 4096);
+    ASSERT_EQ(res, 4096);
+    ASSERT_EQ(memcmp(buf, empty_buf, 4096), 0);
+  }
+  for (int i = 0; i < 1024; i++) {
+    res = read(fd, buf, 4096);
+    ASSERT_EQ(res, 4096);
+    ASSERT_EQ(memcmp(buf, test_data1, 4096), 0);
+  }
+  close(fd);
+}
+
+}  // namespace android
diff --git a/api/bpf_native_test/bpf_module_test.xml b/f2fs/f2fs_test.xml
similarity index 68%
rename from api/bpf_native_test/bpf_module_test.xml
rename to f2fs/f2fs_test.xml
index 602b453..66e9aa0 100644
--- a/api/bpf_native_test/bpf_module_test.xml
+++ b/f2fs/f2fs_test.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2019 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,17 +13,14 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Config for bpf_module_test">
+<configuration description="Config for f2fs_test">
     <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
     <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
         <option name="cleanup" value="true" />
-        <option name="push" value="bpf_module_test->/data/local/tmp/bpf_module_test" />
-        <option name="push" value="kern.o->/data/local/tmp/32/kern.o" />
-        <option name="push" value="kern.o->/data/local/tmp/64/kern.o" />
+        <option name="push" value="f2fs_test->/data/local/tmp/f2fs_test" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
-        <option name="module-name" value="bpf_module_test" />
-        <option name="native-test-timeout" value="10m"/>
+        <option name="module-name" value="f2fs_test" />
     </test>
 </configuration>
diff --git a/fuse_bpf/Android.bp b/fuse_bpf/Android.bp
index 95e35a9..8a6936a 100644
--- a/fuse_bpf/Android.bp
+++ b/fuse_bpf/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/fuse_bpf/vts_kernel_fuse_bpf_test.py b/fuse_bpf/vts_kernel_fuse_bpf_test.py
index 53ee771..111fcc5 100644
--- a/fuse_bpf/vts_kernel_fuse_bpf_test.py
+++ b/fuse_bpf/vts_kernel_fuse_bpf_test.py
@@ -38,7 +38,7 @@ class VtsKernelFuseBpfTest(unittest.TestCase):
         except:
             pass
         out_running, err, return_code = self.dut.Execute("getprop ro.fuse.bpf.is_running")
-        # Devices that are grandfathered into using sdcardfs are unable to simply swap to fuse-bpf
+        # Legacy devices that are using sdcardfs are unable to simply swap to fuse-bpf
         out_sdcardfs, err, return_code = self.dut.Execute("mount | grep \"type sdcardfs\"")
         self.assertTrue(first_api_level < 34 or out_sdcardfs.strip() != "" or out_running.strip() == "true",
                            "fuse-bpf is disabled")
diff --git a/gki/Android.bp b/gki/Android.bp
index 5e803c3..9390ea7 100644
--- a/gki/Android.bp
+++ b/gki/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/gki/eol_enforcement_test.cpp b/gki/eol_enforcement_test.cpp
index dd01d95..4724b33 100644
--- a/gki/eol_enforcement_test.cpp
+++ b/gki/eol_enforcement_test.cpp
@@ -30,6 +30,7 @@
 #include <vintf/VintfObject.h>
 
 using android::vintf::KernelVersion;
+using android::vintf::Level;
 using android::vintf::RuntimeInfo;
 using android::vintf::Version;
 using android::vintf::VintfObject;
@@ -125,6 +126,10 @@ TEST_F(EolEnforcementTest, KernelNotEol) {
   if (kernel_version.dropMinor() < Version{5, 4}) {
     branch_name = std::format("android-{}.{}", kernel_version.version,
                               kernel_version.majorRev);
+  } else if (kernel_version.dropMinor() == Version{5, 4} &&
+             VintfObject::GetInstance()->getKernelLevel() == Level::R) {
+    // Kernel release string on Android 11 is not GKI compatible.
+    branch_name = "android11-5.4";
   } else {
     const auto kernel_release = android::kver::KernelRelease::Parse(
         android::vintf::VintfObject::GetRuntimeInfo()->osRelease(),
diff --git a/isa/Android.bp b/isa/Android.bp
index 4750a6e..72aa28d 100644
--- a/isa/Android.bp
+++ b/isa/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/loop/Android.bp b/loop/Android.bp
index 35756f2..6b6ee04 100644
--- a/loop/Android.bp
+++ b/loop/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/ltp/testcase/Android.bp b/ltp/testcase/Android.bp
deleted file mode 100644
index 2f06c08..0000000
--- a/ltp/testcase/Android.bp
+++ /dev/null
@@ -1,169 +0,0 @@
-//
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-sh_test {
-    name: "vts_ltp_test_arm_64",
-    src: "phony_ltp_test_arm64.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_arm_64",
-}
-
-genrule {
-    name: "ltp_config_arm_64",
-    out: ["vts_ltp_test_arm_64.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch arm --bitness 64 --low-mem False --hwasan False $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_arm_64_lowmem",
-    src: "phony_ltp_test_arm64_lowmem.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_arm_64_lowmem",
-}
-
-genrule {
-    name: "ltp_config_arm_64_lowmem",
-    out: ["vts_ltp_test_arm_64_lowmem.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch arm --bitness 64 --low-mem True --hwasan False $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_arm_64_hwasan",
-    src: "phony_ltp_test_arm64_hwasan.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_arm_64_hwasan",
-}
-
-genrule {
-    name: "ltp_config_arm_64_hwasan",
-    out: ["vts_ltp_test_arm_64_hwasan.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch arm --bitness 64 --low-mem False --hwasan True $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_arm_64_lowmem_hwasan",
-    src: "phony_ltp_test_arm64_lowmem_hwasan.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_arm_64_lowmem_hwasan",
-}
-
-genrule {
-    name: "ltp_config_arm_64_lowmem_hwasan",
-    out: ["vts_ltp_test_arm_64_lowmem_hwasan.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch arm --bitness 64 --low-mem True --hwasan True $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_arm",
-    src: "phony_ltp_test_arm.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_arm",
-}
-
-genrule {
-    name: "ltp_config_arm",
-    out: ["vts_ltp_test_arm.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch arm --bitness 32 --low-mem False --hwasan False $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_arm_lowmem",
-    src: "phony_ltp_test_arm_lowmem.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_arm_lowmem",
-}
-
-genrule {
-    name: "ltp_config_arm_lowmem",
-    out: ["vts_ltp_test_arm_lowmem.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch arm --bitness 32 --low-mem True --hwasan False $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_riscv_64",
-    src: "phony_ltp_test_riscv64.sh",
-    test_suites: ["vts"],
-    test_config: ":ltp_config_riscv_64",
-}
-
-genrule {
-    name: "ltp_config_riscv_64",
-    out: ["vts_ltp_test_riscv_64.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch riscv --bitness 64 --low-mem False --hwasan False $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_x86_64",
-    src: "phony_ltp_test_x86_64.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_x86_64",
-}
-
-genrule {
-    name: "ltp_config_x86_64",
-    out: ["vts_ltp_test_x86_64.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch x86 --bitness 64 --low-mem False --hwasan False $(out)",
-}
-
-sh_test {
-    name: "vts_ltp_test_x86",
-    src: "phony_ltp_test_x86.sh",
-    test_suites: [
-        "general-tests",
-        "vts"
-    ],
-    test_config: ":ltp_config_x86",
-}
-
-genrule {
-    name: "ltp_config_x86",
-    out: ["vts_ltp_test_x86.xml"],
-    tools: ["gen_ltp_config"],
-    cmd: "$(location gen_ltp_config) --arch x86 --bitness 32 --low-mem False --hwasan False $(out)",
-}
diff --git a/ltp/testcase/phony_ltp_test_arm.sh b/ltp/testcase/phony_ltp_test_arm.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm64.sh b/ltp/testcase/phony_ltp_test_arm64.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm64_hwasan.sh b/ltp/testcase/phony_ltp_test_arm64_hwasan.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm64_lowmem.sh b/ltp/testcase/phony_ltp_test_arm64_lowmem.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm64_lowmem_hwasan.sh b/ltp/testcase/phony_ltp_test_arm64_lowmem_hwasan.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm_hwasan.sh b/ltp/testcase/phony_ltp_test_arm_hwasan.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm_lowmem.sh b/ltp/testcase/phony_ltp_test_arm_lowmem.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_arm_lowmem_hwasan.sh b/ltp/testcase/phony_ltp_test_arm_lowmem_hwasan.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_riscv64.sh b/ltp/testcase/phony_ltp_test_riscv64.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_x86.sh b/ltp/testcase/phony_ltp_test_x86.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/phony_ltp_test_x86_64.sh b/ltp/testcase/phony_ltp_test_x86_64.sh
deleted file mode 100644
index e69de29..0000000
diff --git a/ltp/testcase/tools/Android.bp b/ltp/testcase/tools/Android.bp
index 3d443a9..c467b71 100644
--- a/ltp/testcase/tools/Android.bp
+++ b/ltp/testcase/tools/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/ltp/testcase/tools/configs/disabled_tests.py b/ltp/testcase/tools/configs/disabled_tests.py
index 750261b..aeae9b3 100644
--- a/ltp/testcase/tools/configs/disabled_tests.py
+++ b/ltp/testcase/tools/configs/disabled_tests.py
@@ -57,12 +57,6 @@ DISABLED_TESTS = {
     'syscalls.epoll_pwait01_64bit',  # b/277586905
     'syscalls.epoll_pwait04_32bit',  # b/241310858
     'syscalls.epoll_pwait04_64bit',  # b/241310858
-    'syscalls.inotify07_32bit',  # b/191773884
-    'syscalls.inotify07_64bit',  # b/191773884
-    'syscalls.inotify08_32bit',  # b/191748474
-    'syscalls.inotify08_64bit',  # b/191748474
-    'syscalls.inotify12_32bit',  # b/259561911
-    'syscalls.inotify12_64bit',  # b/259561911
     'syscalls.io_pgetevents01_32bit',  # b/191247131
     'syscalls.io_pgetevents02_32bit',  # b/191247132
     'syscalls.ioctl_loop01_32bit',  # b/191224819
diff --git a/ltp/testcase/tools/configs/stable_tests.py b/ltp/testcase/tools/configs/stable_tests.py
index 627e509..21199c7 100644
--- a/ltp/testcase/tools/configs/stable_tests.py
+++ b/ltp/testcase/tools/configs/stable_tests.py
@@ -684,6 +684,8 @@ STABLE_TESTS = {
     'syscalls.alarm06_64bit': True,
     'syscalls.alarm07_32bit': True,
     'syscalls.alarm07_64bit': True,
+    'syscalls.arch_prctl01_32bit': False,
+    'syscalls.arch_prctl01_64bit': False,
     'syscalls.asyncio02_32bit': False,
     'syscalls.asyncio02_64bit': False,
     'syscalls.bdflush01_32bit': True,
@@ -1174,10 +1176,6 @@ STABLE_TESTS = {
     'syscalls.fcntl27_64_32bit': True,
     'syscalls.fcntl27_64_64bit': True,
     'syscalls.fcntl27_64bit': True,
-    'syscalls.fcntl28_32bit': True,
-    'syscalls.fcntl28_64_32bit': True,
-    'syscalls.fcntl28_64_64bit': True,
-    'syscalls.fcntl28_64bit': True,
     'syscalls.fcntl29_32bit': True,
     'syscalls.fcntl29_64_32bit': True,
     'syscalls.fcntl29_64_64bit': True,
@@ -1424,6 +1422,8 @@ STABLE_TESTS = {
     'syscalls.getgroups03_64bit': True,
     'syscalls.gethostname01_32bit': False,
     'syscalls.gethostname01_64bit': False,
+    'syscalls.gethostname02_32bit': False,
+    'syscalls.gethostname02_64bit': False,
     'syscalls.getitimer01_32bit': True,
     'syscalls.getitimer01_64bit': True,
     'syscalls.getitimer02_32bit': True,
@@ -1460,6 +1460,8 @@ STABLE_TESTS = {
     'syscalls.getrandom03_64bit': True,
     'syscalls.getrandom04_32bit': True,
     'syscalls.getrandom04_64bit': True,
+    'syscalls.getrandom05_32bit': True,
+    'syscalls.getrandom05_64bit': True,
     'syscalls.getresgid01_16_32bit': False,
     'syscalls.getresgid01_16_64bit': False,
     'syscalls.getresgid01_32bit': True,
@@ -1536,18 +1538,26 @@ STABLE_TESTS = {
     'syscalls.inotify01_64bit': True,
     'syscalls.inotify02_32bit': True,
     'syscalls.inotify02_64bit': True,
+    'syscalls.inotify03_32bit': True,
+    'syscalls.inotify03_64bit': True,
     'syscalls.inotify04_32bit': True,
     'syscalls.inotify04_64bit': True,
     'syscalls.inotify05_32bit': True,
     'syscalls.inotify05_64bit': True,
     'syscalls.inotify06_32bit': True,
     'syscalls.inotify06_64bit': True,
+    'syscalls.inotify07_32bit': True,
+    'syscalls.inotify07_64bit': True,
+    'syscalls.inotify08_32bit': True,
+    'syscalls.inotify08_64bit': True,
     'syscalls.inotify09_32bit': True,
     'syscalls.inotify09_64bit': True,
     'syscalls.inotify10_32bit': True,
     'syscalls.inotify10_64bit': True,
     'syscalls.inotify11_32bit': True,
     'syscalls.inotify11_64bit': True,
+    'syscalls.inotify12_32bit': True,
+    'syscalls.inotify12_64bit': True,
     'syscalls.inotify_init1_01_32bit': True,
     'syscalls.inotify_init1_01_64bit': True,
     'syscalls.inotify_init1_02_32bit': True,
@@ -1780,8 +1790,6 @@ STABLE_TESTS = {
     'syscalls.mkdir03_64bit': True,
     'syscalls.mkdir04_32bit': True,
     'syscalls.mkdir04_64bit': True,
-    'syscalls.mkdir05A_32bit': True,
-    'syscalls.mkdir05A_64bit': True,
     'syscalls.mkdir05_32bit': True,
     'syscalls.mkdir05_64bit': True,
     'syscalls.mkdir09_32bit': True,
@@ -1820,6 +1828,8 @@ STABLE_TESTS = {
     'syscalls.mlock03_64bit': True,
     'syscalls.mlock04_32bit': True,
     'syscalls.mlock04_64bit': True,
+    'syscalls.mlock05_32bit': True,
+    'syscalls.mlock05_64bit': True,
     'syscalls.mlock201_32bit': False,  # b/112477378
     'syscalls.mlock201_64bit': False,  # b/112477378
     'syscalls.mlock202_32bit': False,  # b/112477378
@@ -2749,6 +2759,10 @@ STABLE_TESTS = {
     'syscalls.splice05_64bit': True,
     'syscalls.splice06_32bit': False,
     'syscalls.splice06_64bit': False,
+    'syscalls.splice08_32bit': False,
+    'syscalls.splice08_64bit': False,
+    'syscalls.splice09_32bit': False,
+    'syscalls.splice09_64bit': False,
     'syscalls.ssetmask01_32bit': False,
     'syscalls.ssetmask01_64bit': False,
     'syscalls.stat01_32bit': True,
@@ -2815,12 +2829,12 @@ STABLE_TESTS = {
     'syscalls.swapoff01_64bit': True,
     'syscalls.swapoff02_32bit': True,
     'syscalls.swapoff02_64bit': True,
-    'syscalls.swapon01_32bit': True,
-    'syscalls.swapon01_64bit': True,
-    'syscalls.swapon02_32bit': True,
-    'syscalls.swapon02_64bit': True,
-    'syscalls.swapon03_32bit': True,
-    'syscalls.swapon03_64bit': True,
+    'syscalls.swapon01_32bit': False,
+    'syscalls.swapon01_64bit': False,
+    'syscalls.swapon02_32bit': False,
+    'syscalls.swapon02_64bit': False,
+    'syscalls.swapon03_32bit': False,
+    'syscalls.swapon03_64bit': False,
     'syscalls.switch01_32bit': False,
     'syscalls.switch01_64bit': False,
     'syscalls.symlink01_32bit': True,
@@ -2965,6 +2979,8 @@ STABLE_TESTS = {
     'syscalls.unlink07_64bit': True,
     'syscalls.unlink08_32bit': True,
     'syscalls.unlink08_64bit': True,
+    'syscalls.unlink09_32bit': True,
+    'syscalls.unlink09_64bit': True,
     'syscalls.unlinkat01_32bit': True,
     'syscalls.unlinkat01_64bit': True,
     'syscalls.unshare01_32bit': True,
@@ -2977,8 +2993,6 @@ STABLE_TESTS = {
     'syscalls.ustat01_64bit': False,  # b/112484619
     'syscalls.ustat02_32bit': True,
     'syscalls.ustat02_64bit': False,  # b/112484619
-    'syscalls.utime01A_32bit': True,
-    'syscalls.utime01A_64bit': True,
     'syscalls.utime01_32bit': True,
     'syscalls.utime01_64bit': True,
     'syscalls.utime02_32bit': True,
@@ -2991,6 +3005,8 @@ STABLE_TESTS = {
     'syscalls.utime05_64bit': True,
     'syscalls.utime06_32bit': True,
     'syscalls.utime06_64bit': True,
+    'syscalls.utime07_32bit': True,
+    'syscalls.utime07_64bit': True,
     'syscalls.utimes01_32bit': True,
     'syscalls.utimes01_64bit': True,
     'syscalls.vfork01_32bit': True,
@@ -3041,14 +3057,10 @@ STABLE_TESTS = {
     'syscalls.waitid11_64bit': True,
     'syscalls.waitpid01_32bit': True,
     'syscalls.waitpid01_64bit': True,
-    'syscalls.waitpid02_32bit': True,
-    'syscalls.waitpid02_64bit': True,
     'syscalls.waitpid03_32bit': True,
     'syscalls.waitpid03_64bit': True,
     'syscalls.waitpid04_32bit': True,
     'syscalls.waitpid04_64bit': True,
-    'syscalls.waitpid05_32bit': True,
-    'syscalls.waitpid05_64bit': True,
     'syscalls.waitpid06_32bit': True,
     'syscalls.waitpid06_64bit': True,
     'syscalls.waitpid07_32bit': True,
diff --git a/ltp/testcase/tools/gen_ltp_config.py b/ltp/testcase/tools/gen_ltp_config.py
index 0da59d4..71e0d96 100755
--- a/ltp/testcase/tools/gen_ltp_config.py
+++ b/ltp/testcase/tools/gen_ltp_config.py
@@ -54,19 +54,19 @@ if __name__ == '__main__':
                             dest='is_low_mem',
                             type=str,
                             choices=['True', 'False'],
-                            required=True,
+                            default='False',
                             help="Target device is low memory device")
     arg_parser.add_argument('--hwasan',
                             dest='is_hwasan',
                             type=str,
                             choices=['True', 'False'],
-                            required=True,
+                            default='False',
                             help="Target device is hwasan")
     arg_parser.add_argument('--staging',
                             dest='run_staging',
                             type=str,
                             choices=['True', 'False'],
-                            default="False",
+                            default='False',
                             help="Run all the tests, except from the disabled ones")
     arg_parser.add_argument('output_file_path',
                             help="Path for the output file")
diff --git a/ltp/testcase/tools/ltp_configs.py b/ltp/testcase/tools/ltp_configs.py
index dfd22ab..467814e 100644
--- a/ltp/testcase/tools/ltp_configs.py
+++ b/ltp/testcase/tools/ltp_configs.py
@@ -35,6 +35,20 @@ TMPDIR = os.path.join(TMP, 'tmpdir')
 # File name suffix for low memory scenario group scripts
 LOW_MEMORY_SCENARIO_GROUP_SUFFIX = '_low_mem'
 
+TARGET_LIST = {
+    'x86': {
+        '32': 'x86',
+        '64': 'x86_64',
+    },
+    'arm': {
+        '32': 'arm',
+        '64': 'x86_64',
+    },
+    'riscv': {
+        '64': 'riscv64',
+    }
+}
+
 # Requirement to testcase dictionary.
 REQUIREMENTS_TO_TESTCASE = {
     ltp_enums.Requirements.LOOP_DEVICE_SUPPORT: [
@@ -81,7 +95,7 @@ REQUIREMENT_TO_TESTSUITE = {}
 # List of LTP test suites to run
 TEST_SUITES = [
     'can',
-    'cap_bounds',
+    'capability',
     'commands',
     'containers',
     'controllers',
@@ -89,14 +103,12 @@ TEST_SUITES = [
     'cve',
     'dio',
     'fcntl-locktests_android',
-    'filecaps',
     'fs',
     'fs_bind',
     'fs_perms_simple',
     'hugetlb',
     'hyperthreading',
     'input',
-    'io',
     'ipc',
     'kernel_misc',
     'math',
@@ -105,7 +117,6 @@ TEST_SUITES = [
     'power_management_tests',
     'pty',
     'sched',
-    'securebits',
     'syscalls',
     'tracing',
 ]
@@ -113,21 +124,19 @@ TEST_SUITES = [
 # List of LTP test suites to run
 TEST_SUITES_LOW_MEM = [
     'can',
-    'cap_bounds',
+    'capability',
     'commands',
     'containers',
     'cpuhotplug',
     'cve',
     'dio',
     'fcntl-locktests_android',
-    'filecaps',
     'fs',
     'fs_bind',
     'fs_perms_simple',
     'hugetlb',
     'hyperthreading',
     'input',
-    'io',
     'ipc',
     'kernel_misc',
     'math',
@@ -136,7 +145,6 @@ TEST_SUITES_LOW_MEM = [
     'power_management_tests',
     'pty',
     'sched_low_mem',
-    'securebits',
     'syscalls',
     'tracing',
 ]
diff --git a/ltp/testcase/tools/ltp_test_cases.py b/ltp/testcase/tools/ltp_test_cases.py
index 07682eb..346b774 100644
--- a/ltp/testcase/tools/ltp_test_cases.py
+++ b/ltp/testcase/tools/ltp_test_cases.py
@@ -27,8 +27,7 @@ from configs import disabled_tests
 from common import filter_utils
 from typing import Set, Optional, List, Callable
 
-ltp_test_template = '        <option name="test-command-line" key="%s" value="&env_setup_cmd; ;' \
-                    ' cd &ltp_bin_dir; ; %s" />'
+ltp_test_template = '        <option name="test-command-line" key="%s" value="&ltp_env;; cd $LTPROOT; %s" />'
 
 class LtpTestCases(object):
     """Load a ltp vts testcase definition file and parse it into a generator.
@@ -252,12 +251,28 @@ class LtpTestCases(object):
                     mandatory_test_cases.append(ltp_test_line)
                 else:
                     skippable_test_cases.append(ltp_test_line)
-        nativetest_bit_path = '64' if n_bit == '64' else ''
+
+        module = 'vts_ltp_test'
+        if arch == 'x86' and n_bit == '64':
+            target = f'{arch}_{n_bit}'
+            module += f'_{arch}_{n_bit}'
+        elif n_bit == '32':
+            target = arch
+            module += f'_{arch}'
+        else:
+            target = f'{arch}{n_bit}'
+            module += f'_{arch}_{n_bit}'
+        if is_low_mem:
+            module += '_lowmem'
+        if is_hwasan:
+            module += '_hwasan'
+
         config_lines = config_lines.format(
-            nativetest_bit_path=nativetest_bit_path,
+            target=target,
             module_controller_option=module_controller_option,
             mandatory_test_cases='\n'.join(mandatory_test_cases),
-            skippable_test_cases='\n'.join(skippable_test_cases))
+            skippable_test_cases='\n'.join(skippable_test_cases),
+            MODULE=module)
         with open(output_file, 'w') as f:
             f.write(config_lines)
 
diff --git a/ltp/testcase/tools/template/template.xml b/ltp/testcase/tools/template/template.xml
index facd709..bf3f06b 100644
--- a/ltp/testcase/tools/template/template.xml
+++ b/ltp/testcase/tools/template/template.xml
@@ -11,10 +11,8 @@
      limitations under the License.
 -->
 <!DOCTYPE configuration [
-    <!ENTITY ltp_root "/data/local/tmp/ltp">
-    <!ENTITY ltp_dir "/data/local/tmp/ltp/DATA/nativetest{nativetest_bit_path}/ltp">
-    <!ENTITY ltp_bin_dir "&ltp_dir;/testcases/bin">
-    <!ENTITY env_setup_cmd "export TMP=&ltp_dir;/tmp LTPTMP=&ltp_dir;/tmp/ltptemp PATH=/system/bin:&ltp_dir;/testcases/bin LTP_DEV_FS_TYPE=ext4 TMPBASE=&ltp_dir;/tmp/tmpbase TMPDIR=&ltp_dir;/tmp/tmpdir LTPROOT=&ltp_dir; ">
+<!ENTITY ltp_dir "/data/local/tmp/{MODULE}">
+<!ENTITY ltp_env "export LTPROOT=/data/local/tmp/{MODULE}/{target} LTP_DEV_FS_TYPE=ext4; export PATH=/system/bin:$LTPROOT TMP=$LTPROOT/tmp; export TMPBASE=$TMP/tmpbase LTPTMP=$TMP/ltptemp TMPDIR=$TMP/tmpdir">
 ]>
 <configuration description="Runs vts_ltp_test.">
     <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
@@ -26,25 +24,20 @@
 
     <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
         <option name="cleanup" value="true" />
-        <!-- LTP tests must be pushed to `/data/local/tmp/ltp` which has the right security context setting.
-          Any other directory might not work. -->
-        <option name="push" value="vts_kernel_ltp_tests->&ltp_root;" />
+        <option name="push-file" key="{MODULE}" value="&ltp_dir;" />
+        <option name="post-push" value='chmod -R 755 &ltp_dir;;  find &ltp_dir; -type f | xargs grep -l -e "bin/sh" -e "bin/bash" | xargs sed -i -e "s?/bin/echo?echo?" -i -e "s?#!/bin/sh?#!/system/bin/sh?" -i -e "s?#!/bin/bash?#!/system/bin/sh?" -i -e "s?bs=1M?#bs=1m?"' />
     </target_preparer>
 
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
-        <option name="run-command" value='find &ltp_dir; -type f | xargs grep -l -e "bin/sh" -e "bin/bash" | xargs sed -i -e "s?/bin/echo?echo?" -i -e "s?#!/bin/sh?#!/system/bin/sh?" -i -e "s?#!/bin/bash?#!/system/bin/sh?" -i -e "s?bs=1M?#bs=1m?"' />
-        <option name="run-command" value='mkdir -p &ltp_dir;/tmp; chmod 777 &ltp_dir;/tmp' />
-        <option name="run-command" value='mkdir -p &ltp_dir;/tmp/tmpbase; chmod 777 &ltp_dir;/tmp/tmpbase' />
-        <option name="run-command" value='mkdir -p &ltp_dir;/tmp/ltptemp; chmod 777 &ltp_dir;/tmp/ltptemp' />
-        <option name="run-command" value='mkdir -p &ltp_dir;/tmp/tmpdir; chmod 777 &ltp_dir;/tmp/tmpdir' />
-         <!-- Apply the right security context for kernel tests to work. -->
-        <option name="run-command" value='restorecon -F -R &ltp_root;' />
-        <option name="teardown-command" value="rm -rf &ltp_dir;/tmp" />
+        <option name="run-command" value='&ltp_env;; mkdir -p $LTPROOT/testcases/bin/data; mkdir -p $TMP; mkdir -p $TMPBASE; mkdir -p $LTPTMP; mkdir -p $TMPDIR; chmod -R 777 $TMP; restorecon -F -R $LTPROOT' />
+        <option name="teardown-command" value="rm -rf &ltp_dir;/{target}/tmp" />
     </target_preparer>
 
     <!-- Mandatory tests (must pass and cannot skip). -->
     <test class="com.android.tradefed.testtype.binary.KernelTargetTest">
         <option name="skip-binary-check" value="true" />
+        <option name="abort-if-device-lost" value="true" />
+        <option name="abort-if-root-lost" value="true" />
         <!-- Set binary timeout to be 18 min which is greater than the default 5 min timeout. Otherwise TF will retry to the command and attempt to do device recovery. -->
         <option name="per-binary-timeout" value="1080000" />
 {mandatory_test_cases}
@@ -54,6 +47,8 @@
         <!-- Identify LTP's TCONF code (incompatible configuration) as a skip. -->
         <option name="exit-code-skip" value="32" />
         <option name="skip-binary-check" value="true" />
+        <option name="abort-if-device-lost" value="true" />
+        <option name="abort-if-root-lost" value="true" />
         <!-- Set binary timeout to be 18 min which is greater than the default 5 min timeout. Otherwise TF will retry to the command and attempt to do device recovery. -->
         <option name="per-binary-timeout" value="1080000" />
 {skippable_test_cases}
diff --git a/pagesize_16kb/Android.bp b/pagesize_16kb/Android.bp
index 9347728..14aa17f 100644
--- a/pagesize_16kb/Android.bp
+++ b/pagesize_16kb/Android.bp
@@ -33,6 +33,7 @@ cc_test {
 
     static_libs: [
         "libelf64",
+        "libprocinfo",
     ],
 
     shared_libs: [
diff --git a/pagesize_16kb/Vts16KPageSizeTest.cpp b/pagesize_16kb/Vts16KPageSizeTest.cpp
index 589964c..6c98bdd 100644
--- a/pagesize_16kb/Vts16KPageSizeTest.cpp
+++ b/pagesize_16kb/Vts16KPageSizeTest.cpp
@@ -15,10 +15,12 @@
  */
 
 #include <android-base/properties.h>
+#include <android-base/test_utils.h>
 #include <android/api-level.h>
 #include <elf.h>
 #include <gtest/gtest.h>
 #include <libelf64/parse.h>
+#include <procinfo/process_map.h>
 
 class Vts16KPageSizeTest : public ::testing::Test {
   protected:
@@ -153,3 +155,61 @@ TEST_F(Vts16KPageSizeTest, ProductPageSize) {
 TEST_F(Vts16KPageSizeTest, BootPageSize) {
     ASSERT_EQ(BootPageSize(), getpagesize());
 }
+
+/**
+ * Check that the process VMAs are page aligned. This is mostly to ensure
+ * x86_64 16KiB page size emulation is working correctly.
+ */
+TEST_F(Vts16KPageSizeTest, ProcessVmasArePageAligned) {
+    ASSERT_TRUE(android::procinfo::ReadProcessMaps(
+            getpid(), [&](const android::procinfo::MapInfo& mapinfo) {
+                EXPECT_EQ(mapinfo.start % getpagesize(), 0u) << mapinfo.start;
+                EXPECT_EQ(mapinfo.end % getpagesize(), 0u) << mapinfo.end;
+            }));
+}
+
+/**
+ * The platform ELFs are built with separate loadable segments.
+ * This means that the ELF mappings should be completely covered by
+ * the backing file, and should not generate a SIGBUS on reading.
+ */
+void fault_file_pages(const android::procinfo::MapInfo& mapinfo) {
+    std::vector<uint8_t> first_bytes;
+
+    for (size_t i = mapinfo.start; i < mapinfo.end; i += getpagesize()) {
+        first_bytes.push_back(*(reinterpret_cast<uint8_t*>(i)));
+    }
+
+    if (first_bytes.size() > 0) exit(0);
+
+    exit(1);
+}
+
+/**
+ * Ensure that apps don't crash with SIGBUS when attempting to read
+ * file mapped platform ELFs.
+ */
+TEST_F(Vts16KPageSizeTest, CanReadProcessFileMappedContents) {
+    // random accesses may trigger MTE on hwasan builds
+    SKIP_WITH_HWASAN;
+
+    std::vector<android::procinfo::MapInfo> maps;
+
+    ASSERT_TRUE(android::procinfo::ReadProcessMaps(
+            getpid(), [&](const android::procinfo::MapInfo& mapinfo) {
+                if ((mapinfo.flags & PROT_READ) == 0) return;
+
+                // Don't check anonymous mapping.
+                if (!android::base::StartsWith(mapinfo.name, "/")) return;
+
+                // Skip devices
+                if (android::base::StartsWith(mapinfo.name, "/dev/")) return;
+
+                maps.push_back(mapinfo);
+            }));
+
+    for (const auto& map : maps) {
+        ASSERT_EXIT(fault_file_pages(map), ::testing::ExitedWithCode(0), "")
+                << "Failed to read maps: " << map.name;
+    }
+}
diff --git a/sdcardfs/Android.bp b/sdcardfs/Android.bp
index be6f537..af0624c 100644
--- a/sdcardfs/Android.bp
+++ b/sdcardfs/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/virtual_ab/Android.bp b/virtual_ab/Android.bp
index e171502..181bfe1 100644
--- a/virtual_ab/Android.bp
+++ b/virtual_ab/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
```

