```diff
diff --git a/client/NetdClient.cpp b/client/NetdClient.cpp
index 287526c9..a33c6805 100644
--- a/client/NetdClient.cpp
+++ b/client/NetdClient.cpp
@@ -462,6 +462,7 @@ extern "C" unsigned getNetworkForProcess() {
 
 extern "C" int setNetworkForSocket(unsigned netId, int socketFd) {
     CHECK_SOCKET_IS_MARKABLE(socketFd);
+    netId &= ~NETID_USE_LOCAL_NAMESERVERS;
     FwmarkCommand command = {FwmarkCommand::SELECT_NETWORK, netId, 0, 0};
     return FwmarkClient().send(&command, socketFd, nullptr);
 }
diff --git a/server/Controllers.cpp b/server/Controllers.cpp
index ea348973..48d0c509 100644
--- a/server/Controllers.cpp
+++ b/server/Controllers.cpp
@@ -60,6 +60,7 @@ static constexpr char CONNMARK_MANGLE_OUTPUT[] = "connmark_mangle_OUTPUT";
 static const std::vector<const char*> FILTER_INPUT = {
         // Bandwidth should always be early in input chain, to make sure we
         // correctly count incoming traffic against data plan.
+        OEM_IPTABLES_FILTER_INPUT,
         BandwidthController::LOCAL_INPUT,
         FirewallController::LOCAL_INPUT,
 };
@@ -331,12 +332,14 @@ void Controllers::init() {
 
     if (int ret = RouteController::Init(NetworkController::LOCAL_NET_ID)) {
         gLog.error("Failed to initialize RouteController (%s)", strerror(-ret));
+        exit(2);
     }
     gLog.info("Initializing RouteController: %" PRId64 "us", s.getTimeAndResetUs());
 
     netdutils::Status xStatus = XfrmController::Init();
     if (!isOk(xStatus)) {
         gLog.error("Failed to initialize XfrmController (%s)", netdutils::toString(xStatus).c_str());
+        exit(3);
     };
     gLog.info("Initializing XfrmController: %" PRId64 "us", s.getTimeAndResetUs());
 }
diff --git a/server/ControllersTest.cpp b/server/ControllersTest.cpp
index 05527d4d..b6a28d3a 100644
--- a/server/ControllersTest.cpp
+++ b/server/ControllersTest.cpp
@@ -74,6 +74,8 @@ TEST_F(ControllersTest, TestInitIptablesRules) {
              "*filter\n"
              ":INPUT -\n"
              "-F INPUT\n"
+             ":oem_in -\n"
+             "-A INPUT -j oem_in\n"
              ":bw_INPUT -\n"
              "-A INPUT -j bw_INPUT\n"
              ":fw_INPUT -\n"
diff --git a/server/NetdNativeService.cpp b/server/NetdNativeService.cpp
index 1bfea3da..69e744e0 100644
--- a/server/NetdNativeService.cpp
+++ b/server/NetdNativeService.cpp
@@ -375,24 +375,9 @@ binder::Status NetdNativeService::networkRejectNonSecureVpn(
     return statusFromErrcode(err);
 }
 
-binder::Status NetdNativeService::socketDestroy(const std::vector<UidRangeParcel>& uids,
-                                                const std::vector<int32_t>& skipUids) {
-    ENFORCE_NETWORK_STACK_PERMISSIONS();
-
-    SockDiag sd;
-    if (!sd.open()) {
-        return binder::Status::fromServiceSpecificError(EIO,
-                String8("Could not open SOCK_DIAG socket"));
-    }
-
-    UidRanges uidRanges(uids);
-    int err = sd.destroySockets(uidRanges, std::set<uid_t>(skipUids.begin(), skipUids.end()),
-                                true /* excludeLoopback */);
-    if (err) {
-        return binder::Status::fromServiceSpecificError(-err,
-                String8::format("destroySockets: %s", strerror(-err)));
-    }
-    return binder::Status::ok();
+binder::Status NetdNativeService::socketDestroy(const std::vector<UidRangeParcel>&,
+                                                const std::vector<int32_t>&) {
+    DEPRECATED;
 }
 
 binder::Status NetdNativeService::tetherApplyDnsInterfaces(bool *ret) {
@@ -443,16 +428,6 @@ void setTetherStatsParcelVecByInterface(std::vector<TetherStatsParcel>* tetherSt
     }
 }
 
-std::vector<std::string> tetherStatsParcelVecToStringVec(std::vector<TetherStatsParcel>* tVec) {
-    std::vector<std::string> result;
-    for (const auto& t : *tVec) {
-        result.push_back(StringPrintf("%s:%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64,
-                                      t.iface.c_str(), t.rxBytes, t.rxPackets, t.txBytes,
-                                      t.txPackets));
-    }
-    return result;
-}
-
 }  // namespace
 
 binder::Status NetdNativeService::tetherGetStats(
@@ -463,7 +438,6 @@ binder::Status NetdNativeService::tetherGetStats(
         return asBinderStatus(statsList);
     }
     setTetherStatsParcelVecByInterface(tetherStatsParcelVec, statsList.value());
-    auto statsResults = tetherStatsParcelVecToStringVec(tetherStatsParcelVec);
     return binder::Status::ok();
 }
 
diff --git a/server/NetworkController.cpp b/server/NetworkController.cpp
index 85112bb6..b2362428 100644
--- a/server/NetworkController.cpp
+++ b/server/NetworkController.cpp
@@ -468,7 +468,7 @@ int NetworkController::createVirtualNetwork(unsigned netId, bool secure, NativeV
         return -EEXIST;
     }
 
-    if (vpnType < NativeVpnType::SERVICE || NativeVpnType::OEM < vpnType) {
+    if (vpnType < NativeVpnType::SERVICE || NativeVpnType::OEM_LEGACY < vpnType) {
         ALOGE("invalid vpnType %d", static_cast<int>(vpnType));
         return -EINVAL;
     }
diff --git a/server/SockDiag.cpp b/server/SockDiag.cpp
index ef3a840b..34ae2dbf 100644
--- a/server/SockDiag.cpp
+++ b/server/SockDiag.cpp
@@ -57,15 +57,6 @@ namespace {
 
 static const bool isUser = (android::base::GetProperty("ro.build.type", "") == "user");
 
-int getAdbPort() {
-    return android::base::GetIntProperty("service.adb.tcp.port", 0);
-}
-
-bool isAdbSocket(const inet_diag_msg *msg, int adbPort) {
-    return adbPort > 0 && msg->id.idiag_sport == htons(adbPort) &&
-        (msg->idiag_uid == AID_ROOT || msg->idiag_uid == AID_SHELL);
-}
-
 int checkError(int fd) {
     struct {
         nlmsghdr h;
@@ -430,36 +421,6 @@ int SockDiag::destroySockets(uint8_t proto, const uid_t uid, bool excludeLoopbac
     return 0;
 }
 
-int SockDiag::destroySockets(const UidRanges& uidRanges, const std::set<uid_t>& skipUids,
-                             bool excludeLoopback) {
-    mSocketsDestroyed = 0;
-    Stopwatch s;
-
-    auto shouldDestroy = [&] (uint8_t, const inet_diag_msg *msg) {
-        return msg != nullptr &&
-               uidRanges.hasUid(msg->idiag_uid) &&
-               skipUids.find(msg->idiag_uid) == skipUids.end() &&
-               !(excludeLoopback && isLoopbackSocket(msg)) &&
-               !isAdbSocket(msg, getAdbPort());
-    };
-
-    iovec iov[] = {
-        { nullptr, 0 },
-    };
-
-    if (int ret = destroyLiveSockets(shouldDestroy, "UID", iov, ARRAY_SIZE(iov))) {
-        return ret;
-    }
-
-    if (mSocketsDestroyed > 0) {
-        ALOGI("Destroyed %d sockets for %s skip={%s} in %" PRId64 "us", mSocketsDestroyed,
-              uidRanges.toString().c_str(), android::base::Join(skipUids, " ").c_str(),
-              s.timeTakenUs());
-    }
-
-    return 0;
-}
-
 // Destroys all "live" (CONNECTED, SYN_SENT, SYN_RECV) TCP sockets on the specified netId where:
 // 1. The opening app no longer has permission to use this network, or:
 // 2. The opening app does have permission, but did not explicitly select this network.
diff --git a/server/SockDiag.h b/server/SockDiag.h
index 240e4e5d..8f729d2c 100644
--- a/server/SockDiag.h
+++ b/server/SockDiag.h
@@ -73,9 +73,6 @@ class SockDiag {
     int destroySockets(const char* addrstr, int ifindex);
     // Destroys all sockets for the given protocol and UID.
     int destroySockets(uint8_t proto, uid_t uid, bool excludeLoopback);
-    // Destroys all "live" (CONNECTED, SYN_SENT, SYN_RECV) TCP sockets for the given UID ranges.
-    int destroySockets(const UidRanges& uidRanges, const std::set<uid_t>& skipUids,
-                       bool excludeLoopback);
     // Destroys all "live" (CONNECTED, SYN_SENT, SYN_RECV) TCP sockets that no longer have
     // the permissions required by the specified network.
     int destroySocketsLackingPermission(unsigned netId, Permission permission,
diff --git a/server/SockDiagTest.cpp b/server/SockDiagTest.cpp
index 864d08d5..9c191e53 100644
--- a/server/SockDiagTest.cpp
+++ b/server/SockDiagTest.cpp
@@ -270,8 +270,6 @@ enum MicroBenchmarkTestType {
     ADDRESS,
     UID,
     UID_EXCLUDE_LOOPBACK,
-    UIDRANGE,
-    UIDRANGE_EXCLUDE_LOOPBACK,
     PERMISSION,
 };
 
@@ -281,8 +279,6 @@ const char *testTypeName(MicroBenchmarkTestType mode) {
         TO_STRING_TYPE(ADDRESS);
         TO_STRING_TYPE(UID);
         TO_STRING_TYPE(UID_EXCLUDE_LOOPBACK);
-        TO_STRING_TYPE(UIDRANGE);
-        TO_STRING_TYPE(UIDRANGE_EXCLUDE_LOOPBACK);
         TO_STRING_TYPE(PERMISSION);
     }
 #undef TO_STRING_TYPE
@@ -336,8 +332,6 @@ protected:
             return ADDRESS_SOCKETS;
         case UID:
         case UID_EXCLUDE_LOOPBACK:
-        case UIDRANGE:
-        case UIDRANGE_EXCLUDE_LOOPBACK:
             return UID_SOCKETS;
         case PERMISSION:
             return ARRAY_SIZE(permissionTestcases);
@@ -348,9 +342,7 @@ protected:
         MicroBenchmarkTestType mode = GetParam();
         switch (mode) {
         case UID:
-        case UID_EXCLUDE_LOOPBACK:
-        case UIDRANGE:
-        case UIDRANGE_EXCLUDE_LOOPBACK: {
+        case UID_EXCLUDE_LOOPBACK: {
             uid_t uid = START_UID + i;
             return fchown(s, uid, -1);
         }
@@ -382,16 +374,6 @@ protected:
                         strerror(-ret);
                 break;
             }
-            case UIDRANGE:
-            case UIDRANGE_EXCLUDE_LOOPBACK: {
-                bool excludeLoopback = (mode == UIDRANGE_EXCLUDE_LOOPBACK);
-                const char *uidRangeStrings[] = { "8005-8012", "8042", "8043", "8090-8099" };
-                std::set<uid_t> skipUids { 8007, 8043, 8098, 8099 };
-                UidRanges uidRanges;
-                uidRanges.parseFrom(ARRAY_SIZE(uidRangeStrings), (char **) uidRangeStrings);
-                ret = mSd.destroySockets(uidRanges, skipUids, excludeLoopback);
-                break;
-            }
             case PERMISSION: {
                 ret = mSd.destroySocketsLackingPermission(TEST_NETID, PERMISSION_NETWORK, false);
                 break;
@@ -407,20 +389,7 @@ protected:
                 return true;
             case UID:
                 return i == CLOSE_UID - START_UID;
-            case UIDRANGE: {
-                uid_t uid = i + START_UID;
-                // Skip UIDs in skipUids.
-                if (uid == 8007 || uid == 8043 || uid == 8098 || uid == 8099) {
-                    return false;
-                }
-                // Include UIDs in uidRanges.
-                if ((8005 <= uid && uid <= 8012) || uid == 8042 || (8090 <= uid && uid <= 8099)) {
-                    return true;
-                }
-                return false;
-            }
             case UID_EXCLUDE_LOOPBACK:
-            case UIDRANGE_EXCLUDE_LOOPBACK:
                 return false;
             case PERMISSION:
                 if (permissionTestcases[i].netId != 42) return false;
@@ -525,9 +494,7 @@ TEST_P(SockDiagMicroBenchmarkTest, TestMicroBenchmark) {
 constexpr int SockDiagMicroBenchmarkTest::CLOSE_UID;
 
 INSTANTIATE_TEST_CASE_P(Address, SockDiagMicroBenchmarkTest,
-                        testing::Values(ADDRESS, UID, UIDRANGE,
-                                        UID_EXCLUDE_LOOPBACK, UIDRANGE_EXCLUDE_LOOPBACK,
-                                        PERMISSION));
+                        testing::Values(ADDRESS, UID, UID_EXCLUDE_LOOPBACK, PERMISSION));
 
 }  // namespace net
 }  // namespace android
diff --git a/server/main.cpp b/server/main.cpp
index b0c5406d..d27fd76a 100644
--- a/server/main.cpp
+++ b/server/main.cpp
@@ -122,19 +122,16 @@ bool initDnsResolver() {
 
 int main() {
     Stopwatch s;
-    gLog.info("netd 1.0 starting");
+    gLog.info("netd starting");
 
     android::net::process::removePidFile(PID_FILE_PATH);
-    gLog.info("Pid file removed");
     android::net::process::blockSigPipe();
-    gLog.info("SIGPIPE is blocked");
 
     // Before we do anything that could fork, mark CLOEXEC the UNIX sockets that we get from init.
     // FrameworkListener does this on initialization as well, but we only initialize these
     // components after having initialized other subsystems that can fork.
     for (const auto& sock : {DNSPROXYLISTENER_SOCKET_NAME, FwmarkServer::SOCKET_NAME}) {
         setCloseOnExec(sock);
-        gLog.info("setCloseOnExec(%s)", sock);
     }
 
     std::string cg2_path;
diff --git a/server/netd.rc b/server/netd.rc
index d8250c2d..d564c0e2 100644
--- a/server/netd.rc
+++ b/server/netd.rc
@@ -3,6 +3,8 @@ service netd /system/bin/netd
     capabilities CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER IPC_LOCK KILL NET_ADMIN NET_BIND_SERVICE NET_RAW SETUID SETGID
     user root
     group root net_admin
+    # apparently some older kernels do not honour CAP_IPC_LOCK for eBPF map allocation
+    rlimit memlock 1073741824 1073741824
     socket dnsproxyd stream 0660 root inet
     socket mdns stream 0660 root system
     socket fwmarkd stream 0660 root inet
diff --git a/server/oem_iptables_hook.cpp b/server/oem_iptables_hook.cpp
index 39a62856..1973d291 100644
--- a/server/oem_iptables_hook.cpp
+++ b/server/oem_iptables_hook.cpp
@@ -14,62 +14,5 @@
  * limitations under the License.
  */
 
-#include <stdio.h>
-#include <stdlib.h>
-#include <sys/types.h>
-#include <sys/wait.h>
-#include <errno.h>
-#include <string.h>
-#include <unistd.h>
-
-#include <string>
-
-#define LOG_TAG "OemIptablesHook"
-#include <log/log.h>
-#include "NetdConstants.h"
-
-namespace {
-
-const char OEM_SCRIPT_PATH[] = "/system/bin/oem-iptables-init.sh";
-
-bool oemCleanupHooks() {
-    static const std::string cmd4 =
-            "*filter\n"
-            ":oem_out -\n"
-            ":oem_fwd -\n"
-            "COMMIT\n"
-            "*nat\n"
-            ":oem_nat_pre -\n"
-            "COMMIT\n";
-
-    static const std::string cmd6 =
-            "*filter\n"
-            ":oem_out -\n"
-            ":oem_fwd -\n"
-            "COMMIT\n";
-
-    return (execIptablesRestore(V4, cmd4) == 0 && execIptablesRestore(V6, cmd6) == 0);
-}
-
-bool oemInitChains() {
-    int ret = system(OEM_SCRIPT_PATH);  // NOLINT(cert-env33-c)
-    if ((-1 == ret) || (0 != WEXITSTATUS(ret))) {
-        ALOGE("%s failed: %s", OEM_SCRIPT_PATH, strerror(errno));
-        oemCleanupHooks();
-        return false;
-    }
-    return true;
-}
-
-}  // namespace
-
 void setupOemIptablesHook() {
-    if (0 == access(OEM_SCRIPT_PATH, R_OK | X_OK)) {
-        // The call to oemCleanupHooks() is superfluous when done on bootup,
-        // but is needed for the case where netd has crashed/stopped and is
-        // restarted.
-        if (oemCleanupHooks() && oemInitChains()) {
-            ALOGI("OEM iptable hook installed.");
-        }
-    }
 }
diff --git a/server/oem_iptables_hook.h b/server/oem_iptables_hook.h
index 5297b388..fb239acd 100644
--- a/server/oem_iptables_hook.h
+++ b/server/oem_iptables_hook.h
@@ -17,6 +17,7 @@
 #ifndef _OEM_IPTABLES_HOOK_H
 #define _OEM_IPTABLES_HOOK_H
 
+#define OEM_IPTABLES_FILTER_INPUT "oem_in"
 #define OEM_IPTABLES_FILTER_OUTPUT "oem_out"
 #define OEM_IPTABLES_FILTER_FORWARD "oem_fwd"
 #define OEM_IPTABLES_NAT_PREROUTING "oem_nat_pre"
diff --git a/tests/Android.bp b/tests/Android.bp
index 01806b5c..abad1343 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -103,7 +103,6 @@ cc_test {
         "liblog",
         "libnetd_client",
         "libnetutils",
-        "libprocessgroup",
         "libssl",
         "libsysutils",
         "libutils",
diff --git a/tests/binder_test.cpp b/tests/binder_test.cpp
index ad04ed30..e906340b 100644
--- a/tests/binder_test.cpp
+++ b/tests/binder_test.cpp
@@ -995,49 +995,6 @@ void checkSocketpairClosed(int clientSocket, int acceptedSocket) {
     EXPECT_EQ(ECONNRESET, err);
 }
 
-TEST_F(NetdBinderTest, SocketDestroy) {
-    unique_fd clientSocket, serverSocket, acceptedSocket;
-    ASSERT_NO_FATAL_FAILURE(fakeRemoteSocketPair(&clientSocket, &serverSocket, &acceptedSocket));
-
-    // Pick a random UID in the system UID range.
-    constexpr int baseUid = AID_APP - 2000;
-    static_assert(baseUid > 0, "Not enough UIDs? Please fix this test.");
-    int uid = baseUid + 500 + arc4random_uniform(1000);
-    EXPECT_EQ(0, fchown(clientSocket, uid, -1));
-
-    // UID ranges that don't contain uid.
-    std::vector<UidRangeParcel> uidRanges = {
-            makeUidRangeParcel(baseUid + 42, baseUid + 449),
-            makeUidRangeParcel(baseUid + 1536, AID_APP - 4),
-            makeUidRangeParcel(baseUid + 498, uid - 1),
-            makeUidRangeParcel(uid + 1, baseUid + 1520),
-    };
-    // A skip list that doesn't contain UID.
-    std::vector<int32_t> skipUids { baseUid + 123, baseUid + 1600 };
-
-    // Close sockets. Our test socket should be intact.
-    EXPECT_TRUE(mNetd->socketDestroy(uidRanges, skipUids).isOk());
-    checkSocketpairOpen(clientSocket, acceptedSocket);
-
-    // UID ranges that do contain uid.
-    uidRanges = {
-            makeUidRangeParcel(baseUid + 42, baseUid + 449),
-            makeUidRangeParcel(baseUid + 1536, AID_APP - 4),
-            makeUidRangeParcel(baseUid + 498, baseUid + 1520),
-    };
-    // Add uid to the skip list.
-    skipUids.push_back(uid);
-
-    // Close sockets. Our test socket should still be intact because it's in the skip list.
-    EXPECT_TRUE(mNetd->socketDestroy(uidRanges, skipUids).isOk());
-    checkSocketpairOpen(clientSocket, acceptedSocket);
-
-    // Now remove uid from skipUids, and close sockets. Our test socket should have been closed.
-    skipUids.resize(skipUids.size() - 1);
-    EXPECT_TRUE(mNetd->socketDestroy(uidRanges, skipUids).isOk());
-    checkSocketpairClosed(clientSocket, acceptedSocket);
-}
-
 TEST_F(NetdBinderTest, SocketDestroyLinkLocal) {
     // Add the same link-local address to two interfaces.
     const char* kLinkLocalAddress = "fe80::ace:d00d";
@@ -5671,6 +5628,8 @@ TEST_F(NetdBinderTest, BypassVpnWithNetId) {
         ScopedUidChange change(TEST_UID1);
         unique_fd sock(socket(AF_INET6, SOCK_DGRAM, 0));
         EXPECT_EQ(0, setNetworkForSocket(VPN_NETID, sock));
+        // 0x80000000 is NETID_USE_LOCAL_NAMESERVERS and should just be ignored
+        EXPECT_EQ(0, setNetworkForSocket(VPN_NETID | 0x80000000, sock));
         EXPECT_EQ(-EPERM, setNetworkForSocket(SYSTEM_DEFAULT_NETID, sock));
         EXPECT_EQ(-EPERM, setNetworkForSocket(OTHER_NETID, sock));
 
diff --git a/tests/kernel_test.cpp b/tests/kernel_test.cpp
index ce7d3cc6..f607d139 100644
--- a/tests/kernel_test.cpp
+++ b/tests/kernel_test.cpp
@@ -17,11 +17,13 @@
 
 #include <unistd.h>
 
+#include <android-base/properties.h>
 #include <gtest/gtest.h>
 #include <vintf/VintfObject.h>
 
 #include <fstream>
 #include <string>
+#include <unordered_set>
 
 #include "bpf/KernelUtils.h"
 
@@ -30,12 +32,26 @@ namespace net {
 
 namespace {
 
+using ::android::base::GetProperty;
 using ::android::vintf::RuntimeInfo;
 using ::android::vintf::VintfObject;
 
 class KernelConfigVerifier final {
   public:
-    KernelConfigVerifier() : mRuntimeInfo(VintfObject::GetRuntimeInfo()) {}
+    KernelConfigVerifier() : mRuntimeInfo(VintfObject::GetRuntimeInfo()) {
+        std::ifstream procModules("/proc/modules", std::ios::in);
+        if (!procModules) {
+            // Return early, this will likely cause the test to fail. However, gtest FAIL() cannot
+            // be used outside of an actual test method.
+            return;
+        }
+        std::string modline;
+        while (std::getline(procModules, modline)) {
+            // modline contains a single line read from /proc/modules. For example:
+            // virtio_snd 45056 0 - Live 0x0000000000000000 (E)
+            mLoadedModules.emplace(modline.substr(0, modline.find(' ')));
+        }
+    }
 
     bool hasOption(const std::string& option) const {
         const auto& configMap = mRuntimeInfo->kernelConfigs();
@@ -55,10 +71,19 @@ class KernelConfigVerifier final {
         return false;
     }
 
+    bool isAvailable(const std::string& option, const std::string& koName) const {
+        return hasOption(option) || mLoadedModules.contains(koName);
+    }
+
   private:
     std::shared_ptr<const RuntimeInfo> mRuntimeInfo;
+    std::unordered_set<std::string> mLoadedModules;
 };
 
+bool isCuttlefish() {
+    return GetProperty("ro.product.board", "") == "cutf";
+}
+
 }  // namespace
 
 /**
@@ -82,8 +107,6 @@ TEST(KernelTest, TestRequireBpfUnprivDefaultOn) {
 }
 
 TEST(KernelTest, TestBpfJitAlwaysOn) {
-    if (bpf::isKernel32Bit() && !bpf::isAtLeastKernelVersion(5, 16, 0))
-        GTEST_SKIP() << "Exempt on obsolete 32-bit kernels.";
     KernelConfigVerifier configVerifier;
     ASSERT_TRUE(configVerifier.hasOption("CONFIG_BPF_JIT_ALWAYS_ON"));
 }
@@ -112,18 +135,13 @@ TEST(KernelTest, TestX86Kernel64Bit) {
     ASSERT_TRUE(bpf::isKernel64Bit());
 }
 
-// Android W requires 64-bit userspace on new 6.7+ kernels.
-TEST(KernelTest, TestUser64Bit) {
+// Android 25Q2 requires 64-bit userspace on new 6.7+ kernels.
+TEST(KernelTest, DISABLED_TestUser64Bit) {
     if (!bpf::isAtLeastKernelVersion(6, 7, 0)) GTEST_SKIP() << "Exempt on < 6.7 kernel.";
     ASSERT_TRUE(bpf::isUserspace64bit());
 }
 
-// Android V requires 4.19+
-TEST(KernelTest, TestKernel419) {
-    ASSERT_TRUE(bpf::isAtLeastKernelVersion(4, 19, 0));
-}
-
-// Android W requires 5.4+
+// Android 25Q2 requires 5.4+
 TEST(KernelTest, TestKernel54) {
     ASSERT_TRUE(bpf::isAtLeastKernelVersion(5, 4, 0));
 }
@@ -152,13 +170,12 @@ static bool isGSI() {
     ASSERT_TRUE(bpf::isAtLeastKernelVersion((major), (minor), (sub))); \
 } while (0)
 
-TEST(KernelTest, TestMinRequiredLTS_4_19) { ifIsKernelThenMinLTS(4, 19, 236); }
-TEST(KernelTest, TestMinRequiredLTS_5_4)  { ifIsKernelThenMinLTS(5, 4, 186); }
-TEST(KernelTest, TestMinRequiredLTS_5_10) { ifIsKernelThenMinLTS(5, 10, 199); }
-TEST(KernelTest, TestMinRequiredLTS_5_15) { ifIsKernelThenMinLTS(5, 15, 136); }
-TEST(KernelTest, TestMinRequiredLTS_6_1)  { ifIsKernelThenMinLTS(6, 1, 57); }
-TEST(KernelTest, TestMinRequiredLTS_6_6)  { ifIsKernelThenMinLTS(6, 6, 0); }
-TEST(KernelTest, TestMinRequiredLTS_6_12) { ifIsKernelThenMinLTS(6, 12, 0); }
+TEST(KernelTest, TestMinRequiredLTS_5_4)  { ifIsKernelThenMinLTS(5, 4, 277); }
+TEST(KernelTest, TestMinRequiredLTS_5_10) { ifIsKernelThenMinLTS(5, 10, 210); }
+TEST(KernelTest, TestMinRequiredLTS_5_15) { ifIsKernelThenMinLTS(5, 15, 149); }
+TEST(KernelTest, TestMinRequiredLTS_6_1)  { ifIsKernelThenMinLTS(6, 1, 78); }
+TEST(KernelTest, TestMinRequiredLTS_6_6)  { ifIsKernelThenMinLTS(6, 6, 30); }
+TEST(KernelTest, TestMinRequiredLTS_6_12) { ifIsKernelThenMinLTS(6, 12, 13); }
 
 TEST(KernelTest, TestSupportsAcceptRaMinLft) {
     if (isGSI()) GTEST_SKIP() << "Meaningless on GSI due to ancient kernels.";
@@ -166,6 +183,22 @@ TEST(KernelTest, TestSupportsAcceptRaMinLft) {
     ASSERT_TRUE(exists("/proc/sys/net/ipv6/conf/default/accept_ra_min_lft"));
 }
 
+TEST(KernelTest, TestSupportsBpfLsm) {
+    if (isGSI()) GTEST_SKIP() << "Meaningless on GSI due to ancient kernels.";
+    if (!bpf::isAtLeastKernelVersion(6, 2, 0)) GTEST_SKIP() << "Too old base kernel.";
+    KernelConfigVerifier configVerifier;
+    ASSERT_TRUE(configVerifier.hasOption("CONFIG_BPF_LSM"));
+}
+
+// https://source.android.com/docs/compatibility/15/android-15-cdd#7452_ipv6 C-0-6
+// MUST provide third-party applications with direct IPv6 connectivity to the
+// network when connected to an IPv6 network, without any form of address
+// or port translation happening locally on the device.
+TEST(KernelTest, TestNoIpv6Nat) {
+    KernelConfigVerifier configVerifier;
+    ASSERT_FALSE(configVerifier.hasOption("CONFIG_IP6_NF_NAT"));
+}
+
 TEST(KernelTest, TestSupportsCommonUsbEthernetDongles) {
     KernelConfigVerifier configVerifier;
     if (!configVerifier.hasModule("CONFIG_USB")) GTEST_SKIP() << "Exempt without USB support.";
@@ -185,5 +218,27 @@ TEST(KernelTest, TestSupportsCommonUsbEthernetDongles) {
     }
 }
 
+/**
+ * In addition to TestSupportsCommonUsbEthernetDongles, ensure that USB CDC host drivers are either
+ * builtin or loaded on physical devices.
+ */
+// TODO: check for hasSystemFeature(FEATURE_USB_HOST)
+TEST(KernelTest, TestSupportsUsbCdcHost) {
+    KernelConfigVerifier configVerifier;
+    // TODO: Load these modules on cuttlefish.
+    if (isCuttlefish()) GTEST_SKIP() << "Exempt on cuttlefish";
+
+    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_NET_CDC_NCM", "cdc_ncm"));
+    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_NET_CDC_EEM", "cdc_eem"));
+    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_NET_CDCETHER", "cdc_ether"));
+}
+
+// TODO: check for hasSystemFeature(FEATURE_USB_ACCESSORY)
+TEST(KernelTest, TestSupportsUsbNcmGadget) {
+    KernelConfigVerifier configVerifier;
+    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_F_NCM", "usb_f_ncm"));
+    EXPECT_TRUE(configVerifier.hasOption("CONFIG_USB_CONFIGFS_NCM"));
+}
+
 }  // namespace net
 }  // namespace android
```

