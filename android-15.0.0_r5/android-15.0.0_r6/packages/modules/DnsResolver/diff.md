```diff
diff --git a/Android.bp b/Android.bp
index 6811aa46..e1cd41ac 100644
--- a/Android.bp
+++ b/Android.bp
@@ -501,7 +501,6 @@ rust_ffi_static {
         "libanyhow",
         "libbase64_rust",
         "libfutures",
-        "liblazy_static",
         "liblibc",
         "liblog_rust",
         "libquiche_static",
diff --git a/DnsTlsTransport.cpp b/DnsTlsTransport.cpp
index de40aac1..1f094f6c 100644
--- a/DnsTlsTransport.cpp
+++ b/DnsTlsTransport.cpp
@@ -299,11 +299,9 @@ bool DnsTlsTransport::validate(const DnsTlsServer& server, uint32_t mark) {
     //
     // For instance, with latencyFactor = 3 and latencyOffsetMs = 10, if UDP probe latency is 5 ms,
     // DoT probe latency must less than 25 ms.
-    const bool isAtLeastR = getApiLevel() >= 30;
-    int latencyFactor = Experiments::getInstance()->getFlag("dot_validation_latency_factor",
-                                                            (isAtLeastR ? 3 : -1));
+    int latencyFactor = Experiments::getInstance()->getFlag("dot_validation_latency_factor", 3);
     int latencyOffsetMs = Experiments::getInstance()->getFlag("dot_validation_latency_offset_ms",
-                                                              (isAtLeastR ? 100 : -1));
+                                                              100);
     const bool shouldCompareUdpLatency =
             server.name.empty() &&
             (latencyFactor >= 0 && latencyOffsetMs >= 0 && latencyFactor + latencyOffsetMs != 0);
diff --git a/PrivateDnsConfiguration.cpp b/PrivateDnsConfiguration.cpp
index cb1a8987..bbed734b 100644
--- a/PrivateDnsConfiguration.cpp
+++ b/PrivateDnsConfiguration.cpp
@@ -115,7 +115,8 @@ PrivateDnsModes convertEnumType(PrivateDnsMode mode) {
 int PrivateDnsConfiguration::set(int32_t netId, uint32_t mark,
                                  const std::vector<std::string>& unencryptedServers,
                                  const std::vector<std::string>& encryptedServers,
-                                 const std::string& name, const std::string& caCert) {
+                                 const std::string& name, const std::string& caCert,
+                                 const std::optional<DohParamsParcel> dohParams) {
     LOG(DEBUG) << "PrivateDnsConfiguration::set(" << netId << ", 0x" << std::hex << mark << std::dec
                << ", " << encryptedServers.size() << ", " << name << ")";
 
@@ -142,7 +143,7 @@ int PrivateDnsConfiguration::set(int32_t netId, uint32_t mark,
         return n;
     }
 
-    return setDoh(netId, mark, encryptedServers, name, caCert);
+    return setDoh(netId, mark, encryptedServers, name, caCert, dohParams);
 }
 
 int PrivateDnsConfiguration::setDot(int32_t netId, uint32_t mark,
@@ -220,7 +221,7 @@ PrivateDnsStatus PrivateDnsConfiguration::getStatusLocked(unsigned netId) const
     auto it = mDohTracker.find(netId);
     if (it != mDohTracker.end()) {
         status.dohServersMap.emplace(IPSockAddr::toIPSockAddr(it->second.ipAddr, kDohPort),
-                                     it->second.status);
+                                     DohServerInfo(it->second.httpsTemplate, it->second.status));
     }
 
     return status;
@@ -271,7 +272,7 @@ NetworkDnsServerSupportReported PrivateDnsConfiguration::getStatusForMetrics(uns
             bool validated = std::any_of(status.dohServersMap.begin(), status.dohServersMap.end(),
                                          [&target](const auto& entry) {
                                              return entry.first == target &&
-                                                    entry.second == Validation::success;
+                                                    entry.second.status == Validation::success;
                                          });
             Server* server = event.mutable_servers()->add_server();
             server->set_protocol(PROTO_DOH);
@@ -594,13 +595,10 @@ void PrivateDnsConfiguration::initDohLocked() {
 
 int PrivateDnsConfiguration::setDoh(int32_t netId, uint32_t mark,
                                     const std::vector<std::string>& servers,
-                                    const std::string& name, const std::string& caCert) {
+                                    const std::string& name, const std::string& caCert,
+                                    const std::optional<DohParamsParcel> dohParams) {
     LOG(DEBUG) << "PrivateDnsConfiguration::setDoh(" << netId << ", 0x" << std::hex << mark
                << std::dec << ", " << servers.size() << ", " << name << ")";
-    if (servers.empty()) {
-        clearDoh(netId);
-        return 0;
-    }
 
     const NetworkType networkType = resolv_get_network_types_for_net(netId);
     const PrivateDnsStatus status = getStatusLocked(netId);
@@ -608,15 +606,15 @@ int PrivateDnsConfiguration::setDoh(int32_t netId, uint32_t mark,
     // Sort the input servers to prefer IPv6.
     const std::vector<std::string> sortedServers = sortServers(servers);
 
-    initDohLocked();
-
-    const auto& doh = makeDohIdentity(sortedServers, name);
+    const auto& doh = makeDohIdentity(sortedServers, name, dohParams);
     if (!doh.ok()) {
         LOG(INFO) << __func__ << ": No suitable DoH server found";
         clearDoh(netId);
         return 0;
     }
 
+    initDohLocked();
+
     auto it = mDohTracker.find(netId);
     // Skip if the same server already exists and its status == success.
     if (it != mDohTracker.end() && it->second == doh.value() &&
@@ -649,17 +647,37 @@ void PrivateDnsConfiguration::clearDoh(unsigned netId) {
 }
 
 base::Result<PrivateDnsConfiguration::DohIdentity> PrivateDnsConfiguration::makeDohIdentity(
-        const std::vector<std::string>& servers, const std::string& name) const {
-    for (const auto& entry : mAvailableDoHProviders) {
-        const auto& dohId = entry.getDohIdentity(servers, name);
-        if (!dohId.ok()) continue;
-
-        // Since the DnsResolver is expected to be configured by the system server, add the
-        // restriction to prevent ResolverTestProvider from being used other than testing.
-        if (entry.requireRootPermission && AIBinder_getCallingUid() != AID_ROOT) continue;
-
-        return dohId;
+        const std::vector<std::string>& servers, const std::string& name,
+        const std::optional<DohParamsParcel> dohParams) const {
+    // 1. Use the DoH servers discovered from DDR.
+    // TODO(b/240259333): check whether dohPath is empty instead of whether dohPath equals to
+    // "/dns-query{?dns}".
+    if (dohParams && !dohParams->ips.empty() && !dohParams->name.empty() &&
+        dohParams->dohpath == "/dns-query{?dns}") {
+        // Sort the servers to prefer IPv6.
+        const std::vector<std::string> sortedServers = sortServers(dohParams->ips);
+        return DohIdentity{
+                .httpsTemplate = fmt::format("https://{}/dns-query", dohParams->name),
+                .ipAddr = sortedServers[0],
+                .host = dohParams->name,
+                .status = Validation::in_process,
+        };
+    }
+
+    // 2. If DDR is not supported/enabled (dohParams unset), look up `mAvailableDoHProviders`.
+    if (!dohParams) {
+        for (const auto& entry : mAvailableDoHProviders) {
+            const auto& dohId = entry.getDohIdentity(servers, name);
+            if (!dohId.ok()) continue;
+
+            // Since the DnsResolver is expected to be configured by the system server, add the
+            // restriction to prevent ResolverTestProvider from being used other than testing.
+            if (entry.requireRootPermission && AIBinder_getCallingUid() != AID_ROOT) continue;
+
+            return dohId;
+        }
     }
+
     return Errorf("Cannot make a DohIdentity from current DNS configuration");
 }
 
diff --git a/PrivateDnsConfiguration.h b/PrivateDnsConfiguration.h
index 7d4f7efb..4cae0c25 100644
--- a/PrivateDnsConfiguration.h
+++ b/PrivateDnsConfiguration.h
@@ -22,6 +22,8 @@
 #include <mutex>
 #include <vector>
 
+#include <aidl/android/net/resolv/aidl/DohParamsParcel.h>
+
 #include <android-base/format.h>
 #include <android-base/logging.h>
 #include <android-base/result.h>
@@ -42,13 +44,21 @@ namespace net {
 
 PrivateDnsModes convertEnumType(PrivateDnsMode mode);
 
+struct DohServerInfo {
+    std::string httpsTemplate;
+    Validation status;
+
+    DohServerInfo(const std::string httpsTemplate, Validation status)
+        : httpsTemplate(httpsTemplate), status(status) {}
+};
+
 struct PrivateDnsStatus {
     PrivateDnsMode mode;
 
     // TODO: change the type to std::vector<DnsTlsServer>.
     std::map<DnsTlsServer, Validation, AddressComparator> dotServersMap;
 
-    std::map<netdutils::IPSockAddr, Validation> dohServersMap;
+    std::map<netdutils::IPSockAddr, DohServerInfo> dohServersMap;
 
     std::list<DnsTlsServer> validatedServers() const {
         std::list<DnsTlsServer> servers;
@@ -62,8 +72,8 @@ struct PrivateDnsStatus {
     }
 
     bool hasValidatedDohServers() const {
-        for (const auto& [_, status] : dohServersMap) {
-            if (status == Validation::success) {
+        for (const auto& [_, info] : dohServersMap) {
+            if (info.status == Validation::success) {
                 return true;
             }
         }
@@ -72,6 +82,9 @@ struct PrivateDnsStatus {
 };
 
 class PrivateDnsConfiguration {
+  private:
+    using DohParamsParcel = aidl::android::net::resolv::aidl::DohParamsParcel;
+
   public:
     static constexpr int kDohQueryDefaultTimeoutMs = 30000;
     static constexpr int kDohProbeDefaultTimeoutMs = 60000;
@@ -104,7 +117,8 @@ class PrivateDnsConfiguration {
 
     int set(int32_t netId, uint32_t mark, const std::vector<std::string>& unencryptedServers,
             const std::vector<std::string>& encryptedServers, const std::string& name,
-            const std::string& caCert) EXCLUDES(mPrivateDnsLock);
+            const std::string& caCert, const std::optional<DohParamsParcel> dohParams)
+            EXCLUDES(mPrivateDnsLock);
 
     void initDoh() EXCLUDES(mPrivateDnsLock);
 
@@ -171,7 +185,8 @@ class PrivateDnsConfiguration {
 
     void initDohLocked() REQUIRES(mPrivateDnsLock);
     int setDoh(int32_t netId, uint32_t mark, const std::vector<std::string>& servers,
-               const std::string& name, const std::string& caCert) REQUIRES(mPrivateDnsLock);
+               const std::string& name, const std::string& caCert,
+               const std::optional<DohParamsParcel> dohParams) REQUIRES(mPrivateDnsLock);
     void clearDoh(unsigned netId) REQUIRES(mPrivateDnsLock);
 
     mutable std::mutex mPrivateDnsLock;
@@ -290,9 +305,12 @@ class PrivateDnsConfiguration {
              false},
     }};
 
-    // Makes a DohIdentity by looking up the `mAvailableDoHProviders` by `servers` and `name`.
+    // Makes a DohIdentity if
+    //   1. `dohParams` has some valid value, or
+    //   2. `servers` and `name` match up `mAvailableDoHProviders`.
     base::Result<DohIdentity> makeDohIdentity(const std::vector<std::string>& servers,
-                                              const std::string& name) const
+                                              const std::string& name,
+                                              const std::optional<DohParamsParcel> dohParams) const
             REQUIRES(mPrivateDnsLock);
 
     // For the metrics. Store the current DNS server list in the same order as what is passed
diff --git a/PrivateDnsConfigurationTest.cpp b/PrivateDnsConfigurationTest.cpp
index 78fc48fd..bd42ae6d 100644
--- a/PrivateDnsConfigurationTest.cpp
+++ b/PrivateDnsConfigurationTest.cpp
@@ -33,6 +33,17 @@ class PrivateDnsConfigurationTest : public NetNativeTestBase {
   public:
     using ServerIdentity = PrivateDnsConfiguration::ServerIdentity;
 
+    class WrappedPrivateDnsConfiguration : public PrivateDnsConfiguration {
+      public:
+        int set(int32_t netId, uint32_t mark, const std::vector<std::string>& unencryptedServers,
+                const std::vector<std::string>& encryptedServers) {
+            // TODO(b/240259333): Add test coverage for dohParamsParcel.
+            return PrivateDnsConfiguration::set(netId, mark, unencryptedServers, encryptedServers,
+                                                {} /* name */, {} /* caCert */,
+                                                std::nullopt /* dohParamsParcel */);
+        }
+    };
+
     static void SetUpTestSuite() {
         // stopServer() will be called in their destructor.
         ASSERT_TRUE(tls1.startServer());
@@ -83,7 +94,7 @@ class PrivateDnsConfigurationTest : public NetNativeTestBase {
     void TearDown() {
         // Reset the state for the next test.
         resolv_delete_cache_for_net(kNetId);
-        mPdc.set(kNetId, kMark, {}, {}, {}, {});
+        mPdc.set(kNetId, kMark, {}, {});
     }
 
   protected:
@@ -138,7 +149,7 @@ class PrivateDnsConfigurationTest : public NetNativeTestBase {
     static constexpr char kServer2[] = "127.0.2.3";
 
     MockObserver mObserver;
-    inline static PrivateDnsConfiguration mPdc;
+    inline static WrappedPrivateDnsConfiguration mPdc;
 
     // TODO: Because incorrect CAs result in validation failed in strict mode, have
     // PrivateDnsConfiguration run mocked code rather than DnsTlsTransport::validate().
@@ -154,7 +165,7 @@ TEST_F(PrivateDnsConfigurationTest, ValidationSuccess) {
     EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::in_process, kNetId));
     EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::success, kNetId));
 
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
     expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
     ASSERT_TRUE(PollForCondition([&]() { return mObserver.runningThreads == 0; }));
@@ -167,7 +178,7 @@ TEST_F(PrivateDnsConfigurationTest, ValidationFail_Opportunistic) {
     EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::in_process, kNetId));
     EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::fail, kNetId));
 
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
     expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
     // Strictly wait for all of the validation finish; otherwise, the test can crash somehow.
@@ -183,7 +194,7 @@ TEST_F(PrivateDnsConfigurationTest, Revalidation_Opportunistic) {
     EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::in_process, kNetId));
     EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::success, kNetId));
 
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
     expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
     ASSERT_TRUE(PollForCondition([&]() { return mObserver.runningThreads == 0; }));
 
@@ -216,25 +227,25 @@ TEST_F(PrivateDnsConfigurationTest, ValidationBlock) {
     {
         testing::InSequence seq;
         EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::in_process, kNetId));
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
         ASSERT_TRUE(PollForCondition([&]() { return mObserver.runningThreads == 1; }));
         expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
         EXPECT_CALL(mObserver, onValidationStateUpdate(kServer2, Validation::in_process, kNetId));
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer2}, {}, {}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer2}), 0);
         ASSERT_TRUE(PollForCondition([&]() { return mObserver.runningThreads == 2; }));
         mObserver.removeFromServerStateMap(kServer1);
         expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
         // No duplicate validation as long as not in OFF mode; otherwise, an unexpected
         // onValidationStateUpdate() will be caught.
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1, kServer2}, {}, {}), 0);
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer2}, {}, {}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1, kServer2}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer2}), 0);
         expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
         // The status keeps unchanged if pass invalid arguments.
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {"invalid_addr"}, {}, {}), -EINVAL);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {"invalid_addr"}), -EINVAL);
         expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
     }
 
@@ -260,12 +271,12 @@ TEST_F(PrivateDnsConfigurationTest, Validation_NetworkDestroyedOrOffMode) {
 
         testing::InSequence seq;
         EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::in_process, kNetId));
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
         ASSERT_TRUE(PollForCondition([&]() { return mObserver.runningThreads == 1; }));
         expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
         if (config == "OFF") {
-            EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {}, {}, {}), 0);
+            EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {}), 0);
         } else if (config == "NETWORK_DESTROYED") {
             mPdc.clear(kNetId);
         }
@@ -289,10 +300,10 @@ TEST_F(PrivateDnsConfigurationTest, NoValidation) {
         EXPECT_THAT(status.dotServersMap, testing::IsEmpty());
     };
 
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {"invalid_addr"}, {}, {}), -EINVAL);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {"invalid_addr"}), -EINVAL);
     expectStatus();
 
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {}, {}, {}), 0);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {}), 0);
     expectStatus();
 }
 
@@ -336,7 +347,7 @@ TEST_F(PrivateDnsConfigurationTest, RequestValidation) {
             ASSERT_TRUE(backend.stopServer());
             EXPECT_CALL(mObserver, onValidationStateUpdate(kServer1, Validation::fail, kNetId));
         }
-        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+        EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
         expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
         // Wait until the validation state is transitioned.
@@ -382,7 +393,7 @@ TEST_F(PrivateDnsConfigurationTest, GetPrivateDns) {
     // Suppress the warning.
     EXPECT_CALL(mObserver, onValidationStateUpdate).Times(2);
 
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}, {}, {}), 0);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {}, {kServer1}), 0);
     expectPrivateDnsStatus(PrivateDnsMode::OPPORTUNISTIC);
 
     EXPECT_TRUE(hasPrivateDnsServer(ServerIdentity(server1), kNetId));
@@ -403,7 +414,7 @@ TEST_F(PrivateDnsConfigurationTest, GetStatusForMetrics) {
 
     // Set 1 unencrypted server and 2 encrypted servers (one will pass DoT validation; the other
     // will fail. Both of them don't support DoH).
-    EXPECT_EQ(mPdc.set(kNetId, kMark, {kServer2}, {kServer1, kServer2}, {}, {}), 0);
+    EXPECT_EQ(mPdc.set(kNetId, kMark, {kServer2}, {kServer1, kServer2}), 0);
     ASSERT_TRUE(PollForCondition([&]() { return mObserver.runningThreads == 0; }));
 
     // Get the metric before call clear().
diff --git a/ResolverController.cpp b/ResolverController.cpp
index 0994cf60..1eb38a55 100644
--- a/ResolverController.cpp
+++ b/ResolverController.cpp
@@ -215,9 +215,9 @@ int ResolverController::setResolverConfiguration(const ResolverParamsParcel& res
     // applies to UID 0, dns_mark is assigned for default network rathan the VPN. (note that it's
     // possible that a VPN doesn't have any DNS servers but DoT servers in DNS strict mode)
     auto& privateDnsConfiguration = PrivateDnsConfiguration::getInstance();
-    int err = privateDnsConfiguration.set(resolverParams.netId, netcontext.app_mark,
-                                          resolverParams.servers, tlsServers,
-                                          resolverParams.tlsName, resolverParams.caCertificate);
+    int err = privateDnsConfiguration.set(
+            resolverParams.netId, netcontext.app_mark, resolverParams.servers, tlsServers,
+            resolverParams.tlsName, resolverParams.caCertificate, resolverParams.dohParams);
 
     if (err != 0) {
         return err;
@@ -349,9 +349,9 @@ void ResolverController::dump(DumpWriter& dw, unsigned netId) {
         const auto privateDnsStatus = PrivateDnsConfiguration::getInstance().getStatus(netId);
         dw.println("Private DNS mode: %s", getPrivateDnsModeString(privateDnsStatus.mode));
         if (privateDnsStatus.dotServersMap.size() == 0) {
-            dw.println("No Private DNS servers configured");
+            dw.println("No DoT servers configured");
         } else {
-            dw.println("Private DNS configuration (%u entries)",
+            dw.println("DoT configuration (%u entries)",
                        static_cast<uint32_t>(privateDnsStatus.dotServersMap.size()));
             dw.incIndent();
             for (const auto& [server, validation] : privateDnsStatus.dotServersMap) {
@@ -360,6 +360,19 @@ void ResolverController::dump(DumpWriter& dw, unsigned netId) {
             }
             dw.decIndent();
         }
+        if (privateDnsStatus.dohServersMap.size() == 0) {
+            dw.println("No DoH servers configured");
+        } else {
+            // TODO: print the hostname and URL as well.
+            dw.println("DoH configuration (%u entries)",
+                       static_cast<uint32_t>(privateDnsStatus.dohServersMap.size()));
+            dw.incIndent();
+            for (const auto& [server, info] : privateDnsStatus.dohServersMap) {
+                dw.println("%s url{%s} status{%s}", server.toString().c_str(),
+                           info.httpsTemplate.c_str(), validationStatusToString(info.status));
+            }
+            dw.decIndent();
+        }
         dw.println("Concurrent DNS query timeout: %d", wait_for_pending_req_timeout_count);
         resolv_netconfig_dump(dw, netId);
     }
diff --git a/doh/connection/driver.rs b/doh/connection/driver.rs
index 833d9150..060fee4e 100644
--- a/doh/connection/driver.rs
+++ b/doh/connection/driver.rs
@@ -107,6 +107,7 @@ pub struct Request {
 /// HTTP/3 Response
 pub struct Stream {
     /// Response headers
+    #[allow(dead_code)]
     pub headers: Vec<h3::Header>,
     /// Response body
     pub data: Vec<u8>,
diff --git a/doh/network/driver.rs b/doh/network/driver.rs
index cad5584e..eb081077 100644
--- a/doh/network/driver.rs
+++ b/doh/network/driver.rs
@@ -60,6 +60,7 @@ pub enum Status {
     /// Network is believed to be working
     Live,
     /// Network is broken, reason as argument
+    #[allow(dead_code)]
     Failed(Arc<anyhow::Error>),
 }
 
diff --git a/doh/tests/doh_frontend/Android.bp b/doh/tests/doh_frontend/Android.bp
index 156fb5cc..76bd47a2 100644
--- a/doh/tests/doh_frontend/Android.bp
+++ b/doh/tests/doh_frontend/Android.bp
@@ -20,7 +20,6 @@ rust_ffi_static {
         "libandroid_logger",
         "libanyhow",
         "libquiche",
-        "liblazy_static",
         "libtokio",
         "libbase64_rust",
     ],
diff --git a/doh/tests/doh_frontend/src/dns_https_frontend.rs b/doh/tests/doh_frontend/src/dns_https_frontend.rs
index d3c538d4..f987c9c8 100644
--- a/doh/tests/doh_frontend/src/dns_https_frontend.rs
+++ b/doh/tests/doh_frontend/src/dns_https_frontend.rs
@@ -20,28 +20,27 @@ use super::client::{ClientMap, ConnectionID, CONN_ID_LEN, DNS_HEADER_SIZE, MAX_U
 use super::config::{Config, QUICHE_IDLE_TIMEOUT_MS};
 use super::stats::Stats;
 use anyhow::{bail, ensure, Result};
-use lazy_static::lazy_static;
 use log::{debug, error, warn};
 use std::fs::File;
 use std::io::Write;
 use std::os::unix::io::{AsRawFd, FromRawFd};
-use std::sync::{Arc, Mutex};
+use std::sync::{Arc, LazyLock, Mutex};
 use std::time::Duration;
 use tokio::net::UdpSocket;
 use tokio::runtime::{Builder, Runtime};
 use tokio::sync::{mpsc, oneshot};
 use tokio::task::JoinHandle;
 
-lazy_static! {
-    static ref RUNTIME_STATIC: Arc<Runtime> = Arc::new(
+static RUNTIME_STATIC: LazyLock<Arc<Runtime>> = LazyLock::new(|| {
+    Arc::new(
         Builder::new_multi_thread()
             .worker_threads(1)
             .enable_all()
             .thread_name("DohFrontend")
             .build()
-            .expect("Failed to create tokio runtime")
-    );
-}
+            .expect("Failed to create tokio runtime"),
+    )
+});
 
 /// Command used by worker_thread itself.
 #[derive(Debug)]
diff --git a/getaddrinfo.cpp b/getaddrinfo.cpp
index 8d9ed6d4..3f3166da 100644
--- a/getaddrinfo.cpp
+++ b/getaddrinfo.cpp
@@ -227,8 +227,9 @@ static int have_ipv6(unsigned mark, uid_t uid, bool mdns) {
             .sin6_addr.s6_addr = {// 2000::
                                   0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
     sockaddr_union addr = {.sin6 = sin6_test};
-    sockaddr sa;
-    return _find_src_addr(&addr.sa, &sa, mark, uid, /*allow_v6_linklocal=*/mdns) == 1;
+    sockaddr_storage sa;
+    return _find_src_addr(&addr.sa, (struct sockaddr*)&sa, mark, uid,
+                          /*allow_v6_linklocal=*/mdns) == 1;
 }
 
 static int have_ipv4(unsigned mark, uid_t uid) {
@@ -237,8 +238,9 @@ static int have_ipv4(unsigned mark, uid_t uid) {
             .sin_addr.s_addr = __constant_htonl(0x08080808L)  // 8.8.8.8
     };
     sockaddr_union addr = {.sin = sin_test};
-    sockaddr sa;
-    return _find_src_addr(&addr.sa, &sa, mark, uid, /*(don't care) allow_v6_linklocal=*/false) == 1;
+    sockaddr_storage sa;
+    return _find_src_addr(&addr.sa, (struct sockaddr*)&sa, mark, uid,
+                          /*(don't care) allow_v6_linklocal=*/false) == 1;
 }
 
 // Internal version of getaddrinfo(), but limited to AI_NUMERICHOST.
diff --git a/tests/Android.bp b/tests/Android.bp
index 1e1ecbfc..068125ba 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -55,7 +55,6 @@ cc_binary_host {
     srcs: ["pbtxt2pb_converter_host.cpp"],
     static_libs: [
         "golddata_proto_host",
-        "libc++fs",
         "libprotobuf-cpp-full",
     ],
 }
@@ -214,7 +213,6 @@ cc_test {
     ],
     static_libs: [
         "dnsresolver_aidl_interface-lateststable-ndk",
-        "libc++fs",
         "libconnectivity_native_test_utils",
         "libcrypto_static",
         "libcutils",
diff --git a/tests/resolv_gold_test.cpp b/tests/resolv_gold_test.cpp
index c372a890..bafbd51b 100644
--- a/tests/resolv_gold_test.cpp
+++ b/tests/resolv_gold_test.cpp
@@ -107,7 +107,7 @@ class TestBase : public NetNativeTestBase {
         fwmark.permission = PERMISSION_SYSTEM;
         ASSERT_EQ(privateDnsConfiguration.set(TEST_NETID, fwmark.intValue,
                                               {} /* unencrypted resolvers */, tlsServers,
-                                              tlsHostname, caCert),
+                                              tlsHostname, caCert, std::nullopt),
                   0);
         ASSERT_EQ(resolv_set_nameservers(TEST_NETID, servers, domains, kParams, std::nullopt), 0);
     }
diff --git a/tests/resolv_gold_test_config.xml b/tests/resolv_gold_test_config.xml
index 3c34d6ce..270dc0b0 100644
--- a/tests/resolv_gold_test_config.xml
+++ b/tests/resolv_gold_test_config.xml
@@ -33,5 +33,6 @@
        <option name="runtime-hint" value="10m" />
        <!-- test-timeout unit is ms, value = 10 min -->
        <option name="native-test-timeout" value="600000" />
+       <option name="force-no-test-error" value="false" />
    </test>
 </configuration>
diff --git a/tests/resolv_integration_test.cpp b/tests/resolv_integration_test.cpp
index b9090571..84ce160e 100644
--- a/tests/resolv_integration_test.cpp
+++ b/tests/resolv_integration_test.cpp
@@ -170,8 +170,6 @@ struct NameserverStats {
     int rtt_avg = -1;
 };
 
-const bool isAtLeastR = (getApiLevel() >= 30);
-
 #define SKIP_IF_KERNEL_VERSION_LOWER_THAN(major, minor, sub)                                  \
     do {                                                                                      \
         if (!android::bpf::isAtLeastKernelVersion(major, minor, sub))                         \
@@ -4476,18 +4474,10 @@ TEST_F(ResolverTest, BlockDnsQueryWithUidRule) {
     int res2 = getAsyncResponse(fd2, &rcode, buf2, MAXPACKET);
     int res1 = getAsyncResponse(fd1, &rcode, buf1, MAXPACKET);
     // If API level >= 30 (R+), these queries should be blocked.
-    if (isAtLeastR) {
-        EXPECT_EQ(res2, -ECONNREFUSED);
-        EXPECT_EQ(res1, -ECONNREFUSED);
-        ExpectDnsEvent(INetdEventListener::EVENT_RES_NSEND, EAI_SYSTEM, "howdy.example.com", {});
-        ExpectDnsEvent(INetdEventListener::EVENT_RES_NSEND, EAI_SYSTEM, "howdy.example.com", {});
-    } else {
-        EXPECT_GT(res2, 0);
-        EXPECT_EQ("::1.2.3.4", toString(buf2, res2, AF_INET6));
-        EXPECT_GT(res1, 0);
-        EXPECT_EQ("1.2.3.4", toString(buf1, res1, AF_INET));
-        // To avoid flaky test, do not evaluate DnsEvent since event order is not guaranteed.
-    }
+    EXPECT_EQ(res2, -ECONNREFUSED);
+    EXPECT_EQ(res1, -ECONNREFUSED);
+    ExpectDnsEvent(INetdEventListener::EVENT_RES_NSEND, EAI_SYSTEM, "howdy.example.com", {});
+    ExpectDnsEvent(INetdEventListener::EVENT_RES_NSEND, EAI_SYSTEM, "howdy.example.com", {});
 }
 
 TEST_F(ResolverTest, GetAddrinfo_BlockDnsQueryWithUidRule) {
@@ -4523,20 +4513,11 @@ TEST_F(ResolverTest, GetAddrinfo_BlockDnsQueryWithUidRule) {
         SCOPED_TRACE(td.hname);
         ScopeBlockedUIDRule scopeBlockUidRule(netdService, TEST_UID);
         // If API level >= 30 (R+), these queries should be blocked.
-        if (isAtLeastR) {
-            addrinfo* result = nullptr;
-            // getaddrinfo() in bionic would convert all errors to EAI_NODATA
-            // except EAI_SYSTEM.
-            EXPECT_EQ(EAI_NODATA, getaddrinfo(td.hname, nullptr, &hints, &result));
-            ExpectDnsEvent(INetdEventListener::EVENT_GETADDRINFO, td.expectedErrorCode, td.hname,
-                           {});
-        } else {
-            ScopedAddrinfo result = safe_getaddrinfo(td.hname, nullptr, &hints);
-            EXPECT_NE(nullptr, result);
-            EXPECT_THAT(ToStrings(result),
-                        testing::UnorderedElementsAreArray({"1.2.3.4", "::1.2.3.4"}));
-            // To avoid flaky test, do not evaluate DnsEvent since event order is not guaranteed.
-        }
+        addrinfo* result = nullptr;
+        // getaddrinfo() in bionic would convert all errors to EAI_NODATA
+        // except EAI_SYSTEM.
+        EXPECT_EQ(EAI_NODATA, getaddrinfo(td.hname, nullptr, &hints, &result));
+        ExpectDnsEvent(INetdEventListener::EVENT_GETADDRINFO, td.expectedErrorCode, td.hname, {});
     }
 }
 
@@ -4575,15 +4556,8 @@ TEST_F(ResolverTest, EnforceDnsUid) {
         const int res2 = getAsyncResponse(fd2, &rcode, buf2, MAXPACKET);
         const int res1 = getAsyncResponse(fd1, &rcode, buf, MAXPACKET);
         // If API level >= 30 (R+), the query should be blocked.
-        if (isAtLeastR) {
-            EXPECT_EQ(res2, -ECONNREFUSED);
-            EXPECT_EQ(res1, -ECONNREFUSED);
-        } else {
-            EXPECT_GT(res2, 0);
-            EXPECT_EQ("::1.2.3.4", toString(buf2, res2, AF_INET6));
-            EXPECT_GT(res1, 0);
-            EXPECT_EQ("1.2.3.4", toString(buf, res1, AF_INET));
-        }
+        EXPECT_EQ(res2, -ECONNREFUSED);
+        EXPECT_EQ(res1, -ECONNREFUSED);
     }
 
     memset(buf, 0, MAXPACKET);
@@ -5040,15 +5014,9 @@ TEST_F(ResolverTest, TlsServerRevalidation) {
         // This test is sensitive to the number of queries sent in DoT validation.
         int latencyFactor;
         int latencyOffsetMs;
-        if (isAtLeastR) {
-            // The feature is enabled by default in R.
-            latencyFactor = std::stoi(GetProperty(kDotValidationLatencyFactorFlag, "3"));
-            latencyOffsetMs = std::stoi(GetProperty(kDotValidationLatencyOffsetMsFlag, "100"));
-        } else {
-            // The feature is disabled by default in Q.
-            latencyFactor = std::stoi(GetProperty(kDotValidationLatencyFactorFlag, "-1"));
-            latencyOffsetMs = std::stoi(GetProperty(kDotValidationLatencyOffsetMsFlag, "-1"));
-        }
+        // The feature is enabled by default in R.
+        latencyFactor = std::stoi(GetProperty(kDotValidationLatencyFactorFlag, "3"));
+        latencyOffsetMs = std::stoi(GetProperty(kDotValidationLatencyOffsetMsFlag, "100"));
         const bool dotValidationExtraProbes = (config.dnsMode == "OPPORTUNISTIC") &&
                                               (latencyFactor >= 0 && latencyOffsetMs >= 0 &&
                                                latencyFactor + latencyOffsetMs != 0);
@@ -6293,15 +6261,13 @@ TEST_F(ResolverTest, BlockDnsQueryUidDoesNotLeadToBadServer) {
     // If api level >= 30 (R+), expect all query packets to be blocked, hence we should not see any
     // of their stats show up. Otherwise, all queries should succeed.
     const std::vector<NameserverStats> expectedDnsStats = {
-            NameserverStats(listen_addr1)
-                    .setSuccesses(isAtLeastR ? 0 : setupParams.maxSamples)
-                    .setRttAvg(isAtLeastR ? -1 : 1),
+            NameserverStats(listen_addr1).setSuccesses(0).setRttAvg(-1),
             NameserverStats(listen_addr2),
     };
     expectStatsEqualTo(expectedDnsStats);
     // If api level >= 30 (R+), expect server won't receive any queries,
     // otherwise expect 20 == 10 * (setupParams.domains.size() + 1) queries.
-    EXPECT_EQ(dns1.queries().size(), isAtLeastR ? 0U : 10 * (setupParams.domains.size() + 1));
+    EXPECT_EQ(dns1.queries().size(), 0U);
     EXPECT_EQ(dns2.queries().size(), 0U);
 }
 
diff --git a/tests/resolv_private_dns_test.cpp b/tests/resolv_private_dns_test.cpp
index 1f5a2328..01c46507 100644
--- a/tests/resolv_private_dns_test.cpp
+++ b/tests/resolv_private_dns_test.cpp
@@ -43,6 +43,7 @@
 #include <poll.h>
 #include "NetdClient.h"
 
+using aidl::android::net::resolv::aidl::DohParamsParcel;
 using aidl::android::net::resolv::aidl::IDnsResolverUnsolicitedEventListener;
 using android::base::GetProperty;
 using android::base::ReadFdToString;
@@ -1344,6 +1345,7 @@ TEST_F(PrivateDnsDohTest, ReceiveResetStream) {
 
 // Tests that, given an IP address with an allowed DoH provider name, PrivateDnsConfiguration
 // attempts to probe the server for DoH.
+// This test is representative of DoH using DDR in opportunistic mode.
 TEST_F(PrivateDnsDohTest, UseDohAsLongAsHostnameMatch) {
     // "example.com" is an allowed DoH provider name defined in
     // PrivateDnsConfiguration::mAvailableDoHProviders.
@@ -1368,5 +1370,74 @@ TEST_F(PrivateDnsDohTest, UseDohAsLongAsHostnameMatch) {
                                                           .build()));
     EXPECT_TRUE(WaitForDotValidationFailure(someOtherIp));
     EXPECT_TRUE(WaitForDohValidationFailure(someOtherIp));
+
+    // Disable DoT and DoH. This ensures that when DoT is re-enabled right afterwards, the test
+    // observes a validation failure.
+    ASSERT_TRUE(
+            mDnsClient.SetResolversFromParcel(ResolverParams::Builder().setDotServers({}).build()));
+
+    // If DDR is enabled and reports no results (empty DoH params), don't probe for DoH.
+    DohParamsParcel emptyDohParams = {};
+    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(ResolverParams::Builder()
+                                                          .setDotServers({someOtherIp})
+                                                          .setPrivateDnsProvider(allowedDohName)
+                                                          .setDohParams(emptyDohParams)
+                                                          .build()));
+    EXPECT_TRUE(WaitForDotValidationFailure(someOtherIp));
+    EXPECT_FALSE(WaitForDohValidationFailure(someOtherIp));
+
+    EXPECT_FALSE(hasUncaughtPrivateDnsValidation(someOtherIp));
+}
+
+// Tests that if DDR is enabled, but returns no parameters, that DoH is not enabled.
+TEST_F(PrivateDnsDohTest, DdrEnabledButNoResponse) {
+    // "example.com" is an allowed DoH provider name defined in
+    // PrivateDnsConfiguration::mAvailableDoHProviders.
+    constexpr char allowedDohName[] = "example.com";
+    constexpr char someOtherIp[] = "127.99.99.99";
+
+    // If DDR is enabled and reports no results (empty DoH params), don't probe for DoH.
+    DohParamsParcel emptyDohParams = {};
+    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(ResolverParams::Builder()
+                                                          .setDotServers({someOtherIp})
+                                                          .setPrivateDnsProvider(allowedDohName)
+                                                          .setDohParams(emptyDohParams)
+                                                          .build()));
+    EXPECT_TRUE(WaitForDotValidationFailure(someOtherIp));
+    EXPECT_FALSE(WaitForDohValidationFailure(someOtherIp));
+
     EXPECT_FALSE(hasUncaughtPrivateDnsValidation(someOtherIp));
 }
+// Tests DoH with a hostname.
+// This test is representative of DoH using DDR in strict mode.
+TEST_F(PrivateDnsDohTest, DohParamsParcel) {
+    // Because the test doesn't support serving DoH in strict mode, it cannot check for actual DoH
+    // queries, it can only check for validation attempts.
+    constexpr char name[] = "example.com";
+    constexpr char dohIp[] = "127.99.99.99";
+    DohParamsParcel dohParams = {
+            .name = name,
+            .ips = {dohIp},
+            .dohpath = "/dns-query{?dns}",
+            .port = 443,
+    };
+
+    // Only DoH enabled.
+    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(
+            ResolverParams::Builder().setDohParams(dohParams).build()));
+    EXPECT_FALSE(WaitForDotValidationFailure(dohIp));
+    EXPECT_TRUE(WaitForDohValidationFailure(dohIp));
+
+    // Both DoT and DoH enabled.
+    constexpr char dotIp[] = "127.88.88.88";
+    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(ResolverParams::Builder()
+                                                          .setPrivateDnsProvider(name)
+                                                          .setDotServers({dotIp})
+                                                          .setDohParams(dohParams)
+                                                          .build()));
+    EXPECT_TRUE(WaitForDotValidationFailure(dotIp));
+    EXPECT_TRUE(WaitForDohValidationFailure(dohIp));
+
+    EXPECT_FALSE(hasUncaughtPrivateDnsValidation(dohIp));
+    EXPECT_FALSE(hasUncaughtPrivateDnsValidation(dotIp));
+}
```

