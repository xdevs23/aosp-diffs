```diff
diff --git a/client/NetdClient.cpp b/client/NetdClient.cpp
index a33c6805..8f38abf6 100644
--- a/client/NetdClient.cpp
+++ b/client/NetdClient.cpp
@@ -148,8 +148,10 @@ int netdClientAccept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags)
 }
 
 int netdClientConnect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
-    const bool shouldSetFwmark = shouldMarkSocket(sockfd, addr);
-    if (shouldSetFwmark) {
+    if (!shouldMarkSocket(sockfd, addr)) {
+        // get this out of the way to avoid initializing a stopwatch
+        return libcConnect(sockfd, addr, addrlen);
+    } else {
         FwmarkCommand command = {FwmarkCommand::ON_CONNECT, 0, 0, 0};
         FwmarkConnectInfo connectInfo(0, 0, addr);
         int error = FwmarkClient().send(&command, sockfd, &connectInfo);
@@ -159,21 +161,22 @@ int netdClientConnect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
             return -1;
         }
     }
+
     // Latency measurement does not include time of sending commands to Fwmark
     Stopwatch s;
     const int ret = libcConnect(sockfd, addr, addrlen);
     // Save errno so it isn't clobbered by sending ON_CONNECT_COMPLETE
     const int connectErrno = errno;
     const auto latencyMs = static_cast<unsigned>(s.timeTakenUs() / 1000);
+
     // Send an ON_CONNECT_COMPLETE command that includes sockaddr and connect latency for reporting
-    if (shouldSetFwmark) {
-        FwmarkConnectInfo connectInfo(ret == 0 ? 0 : connectErrno, latencyMs, addr);
-        // TODO: get the netId from the socket mark once we have continuous benchmark runs
-        FwmarkCommand command = {FwmarkCommand::ON_CONNECT_COMPLETE, /* netId (ignored) */ 0,
-                                 /* uid (filled in by the server) */ 0, 0};
-        // Ignore return value since it's only used for logging
-        FwmarkClient().send(&command, sockfd, &connectInfo);
-    }
+    FwmarkConnectInfo connectInfo(ret == 0 ? 0 : connectErrno, latencyMs, addr);
+    // TODO: get the netId from the socket mark once we have continuous benchmark runs
+    FwmarkCommand command = {FwmarkCommand::ON_CONNECT_COMPLETE, /* netId (ignored) */ 0,
+                             /* uid (filled in by the server) */ 0, 0};
+    // Ignore return value since it's only used for logging
+    FwmarkClient().send(&command, sockfd, &connectInfo);
+
     errno = connectErrno;
     return ret;
 }
diff --git a/netutils_wrappers/NetUtilsWrapper-1.0.cpp b/netutils_wrappers/NetUtilsWrapper-1.0.cpp
index 6b891643..02d1239e 100644
--- a/netutils_wrappers/NetUtilsWrapper-1.0.cpp
+++ b/netutils_wrappers/NetUtilsWrapper-1.0.cpp
@@ -41,7 +41,7 @@
 
 // List of net utils wrapped by this program
 // The list MUST be in descending order of string length
-const char *netcmds[] = {
+static const char *const netcmds[] = {
     "ip6tables",
     "iptables",
     "ndc",
@@ -51,7 +51,7 @@ const char *netcmds[] = {
 };
 
 // List of regular expressions of expected commands.
-const char *EXPECTED_REGEXPS[] = {
+static const char *const EXPECTED_REGEXPS[] = {
 #define CMD "^" SYSTEM_DIRNAME
     // Create, delete, and manage OEM networks.
     CMD "ndc network (create|destroy) (oem|handle)[0-9]+( |$)",
@@ -70,6 +70,7 @@ const char *EXPECTED_REGEXPS[] = {
     // Manage vendor interfaces.
     CMD "tc .* dev " VENDOR_IFACE,
     CMD "ip( -4| -6)? (addr|address) (add|del|delete|flush).* dev " VENDOR_IFACE,
+    CMD "ip link set dev " VENDOR_IFACE,
 
     // Other activities observed on current devices. In future releases, these should be supported
     // in a way that is less likely to interfere with general Android networking behaviour.
diff --git a/server/Android.bp b/server/Android.bp
index e77554b0..78d1f1d9 100644
--- a/server/Android.bp
+++ b/server/Android.bp
@@ -118,11 +118,13 @@ cc_defaults {
         "mdns_aidl_interface-V1-cpp",
         "netd_event_listener_interface-V1-cpp",
         "oemnetd_aidl_interface-cpp",
+        "libaconfig_storage_read_api_cc",
     ],
     static_libs: [
         "libip_checksum",
         "libnetd_server",
         "libtcutils",
+        "android.net.platform.flags-aconfig-cc",
     ],
     srcs: [
         "DummyNetwork.cpp",
diff --git a/server/FirewallController.cpp b/server/FirewallController.cpp
index 57c6ac24..c5b025a7 100644
--- a/server/FirewallController.cpp
+++ b/server/FirewallController.cpp
@@ -44,16 +44,16 @@ namespace net {
 
 auto FirewallController::execIptablesRestore = ::execIptablesRestore;
 
-const char* FirewallController::TABLE = "filter";
+const char FirewallController::TABLE[] = "filter";
 
-const char* FirewallController::LOCAL_INPUT = "fw_INPUT";
-const char* FirewallController::LOCAL_OUTPUT = "fw_OUTPUT";
-const char* FirewallController::LOCAL_FORWARD = "fw_FORWARD";
+const char FirewallController::LOCAL_INPUT[] = "fw_INPUT";
+const char FirewallController::LOCAL_OUTPUT[] = "fw_OUTPUT";
+const char FirewallController::LOCAL_FORWARD[] = "fw_FORWARD";
 
 // ICMPv6 types that are required for any form of IPv6 connectivity to work. Note that because the
 // fw_dozable chain is called from both INPUT and OUTPUT, this includes both packets that we need
 // to be able to send (e.g., RS, NS), and packets that we need to receive (e.g., RA, NA).
-const char* FirewallController::ICMPV6_TYPES[] = {
+const char* const FirewallController::ICMPV6_TYPES[] = {
     "packet-too-big",
     "router-solicitation",
     "router-advertisement",
diff --git a/server/FirewallController.h b/server/FirewallController.h
index a7558300..cfdd08ce 100644
--- a/server/FirewallController.h
+++ b/server/FirewallController.h
@@ -52,13 +52,13 @@ public:
 
   static std::string makeCriticalCommands(IptablesTarget target, const char* chainName);
 
-  static const char* TABLE;
+  static const char TABLE[];
 
-  static const char* LOCAL_INPUT;
-  static const char* LOCAL_OUTPUT;
-  static const char* LOCAL_FORWARD;
+  static const char LOCAL_INPUT[];
+  static const char LOCAL_OUTPUT[];
+  static const char LOCAL_FORWARD[];
 
-  static const char* ICMPV6_TYPES[];
+  static const char* const ICMPV6_TYPES[];
 
   std::mutex lock;
 
diff --git a/server/NetworkController.cpp b/server/NetworkController.cpp
index b2362428..4ca49618 100644
--- a/server/NetworkController.cpp
+++ b/server/NetworkController.cpp
@@ -29,9 +29,8 @@
 
 #include <android-base/strings.h>
 #include <cutils/misc.h>  // FIRST_APPLICATION_UID
-#include <netd_resolv/resolv.h>
 #include <net/if.h>
-#include "log/log.h"
+#include <netd_resolv/resolv.h>
 
 #include "Controllers.h"
 #include "DummyNetwork.h"
@@ -42,12 +41,17 @@
 #include "TcUtils.h"
 #include "UnreachableNetwork.h"
 #include "VirtualNetwork.h"
+#include "log/log.h"
 #include "netdutils/DumpWriter.h"
 #include "netdutils/Utils.h"
 #include "netid_client.h"
 
 #define DBG 0
 
+#include <android_net_platform_flags.h>
+
+namespace netflags = android::net::platform::flags;
+
 using android::netdutils::DumpWriter;
 using android::netdutils::getIfaceNames;
 
@@ -670,6 +674,9 @@ int NetworkController::removeRoute(unsigned netId, const char* interface, const
 }
 
 void NetworkController::addInterfaceAddress(unsigned ifIndex, const char* address) {
+    if (netflags::connectivity_service_destroy_socket()) {
+        return;
+    }
     ScopedWLock lock(mRWLock);
     if (ifIndex == 0) {
         ALOGE("Attempting to add address %s without ifindex", address);
@@ -680,6 +687,10 @@ void NetworkController::addInterfaceAddress(unsigned ifIndex, const char* addres
 
 // Returns whether we should call SOCK_DESTROY on the removed address.
 bool NetworkController::removeInterfaceAddress(unsigned ifindex, const char* address) {
+    if (netflags::connectivity_service_destroy_socket()) {
+        // SOCK_DESTROY on the removed address will be triggered from Connectivity module.
+        return false;
+    }
     ScopedWLock lock(mRWLock);
     // First, update mAddressToIfindices map
     auto ifindicesIter = mAddressToIfindices.find(address);
@@ -787,14 +798,16 @@ void NetworkController::dump(DumpWriter& dw) {
     }
     dw.decIndent();
 
-    dw.blankline();
-    dw.println("Interface addresses:");
-    dw.incIndent();
-    for (const auto& i : mAddressToIfindices) {
-        dw.println("address: %s ifindices: [%s]", i.first.c_str(),
-                android::base::Join(i.second, ", ").c_str());
+    if (!netflags::connectivity_service_destroy_socket()) {
+        dw.blankline();
+        dw.println("Interface addresses:");
+        dw.incIndent();
+        for (const auto& i : mAddressToIfindices) {
+            dw.println("address: %s ifindices: [%s]", i.first.c_str(),
+                       android::base::Join(i.second, ", ").c_str());
+        }
+        dw.decIndent();
     }
-    dw.decIndent();
 
     dw.blankline();
     dw.println("Permission of users:");
diff --git a/server/NetworkController.h b/server/NetworkController.h
index c3e2667c..645ab5dc 100644
--- a/server/NetworkController.h
+++ b/server/NetworkController.h
@@ -208,8 +208,8 @@ public:
     // TODO: Does not track IP addresses present when netd is started or restarts after a crash.
     // This is not a problem for its intended use (tracking IP addresses on VPN interfaces), but
     // we should fix it.
+    // This map is deprecated, if flag connectivityServiceDestroySocket is enabled.
     std::unordered_map<std::string, std::unordered_set<unsigned>> mAddressToIfindices;
-
 };
 
 }  // namespace android::net
diff --git a/server/PhysicalNetwork.cpp b/server/PhysicalNetwork.cpp
index 161fa2a7..5a969906 100644
--- a/server/PhysicalNetwork.cpp
+++ b/server/PhysicalNetwork.cpp
@@ -21,8 +21,11 @@
 #include "RouteController.h"
 #include "SockDiag.h"
 
+#include <android_net_platform_flags.h>
 #include "log/log.h"
 
+namespace netflags = android::net::platform::flags;
+
 namespace android::net {
 
 namespace {
@@ -70,6 +73,11 @@ Permission PhysicalNetwork::getPermission() const {
 }
 
 int PhysicalNetwork::destroySocketsLackingPermission(Permission permission) {
+    if (netflags::connectivity_service_destroy_socket()) {
+        // This will be done in ConnectivityService.
+        return 0;
+    }
+
     if (permission == PERMISSION_NONE) return 0;
 
     SockDiag sd;
diff --git a/server/RouteController.cpp b/server/RouteController.cpp
index d7a6e834..3f5ed70a 100644
--- a/server/RouteController.cpp
+++ b/server/RouteController.cpp
@@ -120,7 +120,7 @@ constexpr bool IMPLICIT = false;
 // END CONSTANTS ----------------------------------------------------------------------------------
 
 static const char* actionName(uint16_t action) {
-    static const char *ops[4] = {"adding", "deleting", "getting", "???"};
+    static const char *const ops[4] = {"adding", "deleting", "getting", "???"};
     return ops[action % 4];
 }
 
diff --git a/server/RouteController.h b/server/RouteController.h
index a56d4e05..d789d35b 100644
--- a/server/RouteController.h
+++ b/server/RouteController.h
@@ -202,7 +202,7 @@ public:
     friend class RouteControllerTest;
 
     // An expandable array for fixed local prefix though it's only one element now.
-    static constexpr const char* V4_FIXED_LOCAL_PREFIXES[] = {
+    static constexpr const char* const V4_FIXED_LOCAL_PREFIXES[] = {
             // The multicast range is 224.0.0.0/4 but only limit it to 224.0.0.0/24 since the IPv4
             // definitions are not as precise as for IPv6, it is the only range that the standards
             // (RFC 2365 and RFC 5771) specify is link-local and must not be forwarded.
diff --git a/server/SockDiagTest.cpp b/server/SockDiagTest.cpp
index 9c191e53..0a6e1e84 100644
--- a/server/SockDiagTest.cpp
+++ b/server/SockDiagTest.cpp
@@ -55,7 +55,7 @@ uint16_t bindAndListen(int s) {
 }
 
 const char *tcpStateName(uint8_t state) {
-    static const char *states[] = {
+    static const char *const states[] = {
         "???",
         "TCP_ESTABLISHED",
         "TCP_SYN_SENT",
diff --git a/tests/binder_test.cpp b/tests/binder_test.cpp
index e906340b..25b7d38d 100644
--- a/tests/binder_test.cpp
+++ b/tests/binder_test.cpp
@@ -1877,7 +1877,7 @@ TEST_F(NetdBinderTest, NetworkAddRemoveRouteToLocalExcludeTable) {
 
     // This should ba aligned with V4_FIXED_LOCAL_PREFIXES in system/netd/server/RouteController.cpp
     // An expandable array for fixed local prefix though it's only one element now.
-    static const char* kV4LocalPrefixes[] = {"224.0.0.0/24"};
+    static const char* const kV4LocalPrefixes[] = {"224.0.0.0/24"};
 
     // Add test physical network
     const auto& config = makeNativeNetworkConfig(TEST_NETID1, NativeNetworkType::PHYSICAL,
diff --git a/tests/kernel_test.cpp b/tests/kernel_test.cpp
index f607d139..36b7d758 100644
--- a/tests/kernel_test.cpp
+++ b/tests/kernel_test.cpp
@@ -15,6 +15,7 @@
  *
  */
 
+#include <time.h>
 #include <unistd.h>
 
 #include <android-base/properties.h>
@@ -121,10 +122,10 @@ TEST(KernelTest, TestHaveEfficientUnalignedAccess) {
 /* Android 14/U should only launch on 64-bit kernels
  *   T launches on 5.10/5.15
  *   U launches on 5.15/6.1
- * So >=5.16 implies isKernel64Bit()
+ * So >=5.16 has always implied isKernel64Bit(),
+ * but with 25Q3 we make it unconditional.
  */
 TEST(KernelTest, TestKernel64Bit) {
-    if (!bpf::isAtLeastKernelVersion(5, 16, 0)) GTEST_SKIP() << "Exempt on < 5.16 kernel.";
     ASSERT_TRUE(bpf::isKernel64Bit());
 }
 
@@ -141,9 +142,9 @@ TEST(KernelTest, DISABLED_TestUser64Bit) {
     ASSERT_TRUE(bpf::isUserspace64bit());
 }
 
-// Android 25Q2 requires 5.4+
-TEST(KernelTest, TestKernel54) {
-    ASSERT_TRUE(bpf::isAtLeastKernelVersion(5, 4, 0));
+// Android 25Q3 requires 5.10+
+TEST(KernelTest, TestKernel510) {
+    ASSERT_TRUE(bpf::isAtLeastKernelVersion(5, 10, 0));
 }
 
 // RiscV is not yet supported: make it fail VTS.
@@ -179,7 +180,6 @@ TEST(KernelTest, TestMinRequiredLTS_6_12) { ifIsKernelThenMinLTS(6, 12, 13); }
 
 TEST(KernelTest, TestSupportsAcceptRaMinLft) {
     if (isGSI()) GTEST_SKIP() << "Meaningless on GSI due to ancient kernels.";
-    if (!bpf::isAtLeastKernelVersion(5, 10, 0)) GTEST_SKIP() << "Too old base kernel.";
     ASSERT_TRUE(exists("/proc/sys/net/ipv6/conf/default/accept_ra_min_lft"));
 }
 
@@ -240,5 +240,16 @@ TEST(KernelTest, TestSupportsUsbNcmGadget) {
     EXPECT_TRUE(configVerifier.hasOption("CONFIG_USB_CONFIGFS_NCM"));
 }
 
+TEST(KernelTest, TimeDoesNotOverflow) {
+    errno = 0;
+    time_t now = time(nullptr);
+    ASSERT_NE(now, -1);  // Check if time() failed
+    ASSERT_EQ(errno, 0);  // Check if errno was set (shouldn't be on success)
+
+    ASSERT_GE(now, 1744912772);  // 2025-04-17 17:59:32 UTC
+    time_t future = now + 10 * 365 * 24 * 60 * 60; // 10 years
+    ASSERT_GE(future, now);  // check for wrap-around
+}
+
 }  // namespace net
 }  // namespace android
diff --git a/tests/sock_diag_test.cpp b/tests/sock_diag_test.cpp
index 5d142dc4..c9ab5db5 100644
--- a/tests/sock_diag_test.cpp
+++ b/tests/sock_diag_test.cpp
@@ -47,7 +47,7 @@ uint16_t bindAndListen(int s) {
 }
 
 const char *tcpStateName(uint8_t state) {
-    static const char *states[] = {
+    static const char *const states[] = {
         "???",
         "TCP_ESTABLISHED",
         "TCP_SYN_SENT",
```

