```diff
diff --git a/Android.bp b/Android.bp
index e1cd41ac..caeb89fa 100644
--- a/Android.bp
+++ b/Android.bp
@@ -162,6 +162,10 @@ aidl_interface {
             version: "15",
             imports: ["netd_event_listener_interface-V1"],
         },
+        {
+            version: "16",
+            imports: ["netd_event_listener_interface-V1"],
+        },
 
     ],
     frozen: true,
@@ -423,7 +427,7 @@ doh_rust_deps = [
     "liblibc",
     "liblog_rust",
     "libring",
-    "libstatslog_rust",
+    "libstatslog_dns_resolver_rust",
     "libthiserror",
     "libtokio",
     "liburl",
@@ -505,7 +509,7 @@ rust_ffi_static {
         "liblog_rust",
         "libquiche_static",
         "libring",
-        "libstatslog_rust",
+        "libstatslog_dns_resolver_rust",
         "libthiserror",
         "libtokio",
         "liburl",
diff --git a/Dns64Configuration.cpp b/Dns64Configuration.cpp
index c09ce368..69605b51 100644
--- a/Dns64Configuration.cpp
+++ b/Dns64Configuration.cpp
@@ -160,8 +160,8 @@ bool Dns64Configuration::doRfc7050PrefixDiscovery(const android_net_context& net
     // handling and the resolver event logging.
     struct addrinfo* res = nullptr;
     NetworkDnsEventReported event;
-    const int status =
-            resolv_getaddrinfo(kIPv4OnlyHost, nullptr, &hints, &netcontext, &res, &event);
+    const int status = resolv_getaddrinfo(kIPv4OnlyHost, nullptr, &hints, &netcontext,
+                                          APP_SOCKET_NONE, &res, &event);
     ScopedAddrinfo result(res);
     if (status != 0) {
         LOG(WARNING) << "(" << cfg->netId << ", " << cfg->discoveryId << ") plat_prefix/dns("
diff --git a/DnsProxyListener.cpp b/DnsProxyListener.cpp
index 04c59212..302cfd99 100644
--- a/DnsProxyListener.cpp
+++ b/DnsProxyListener.cpp
@@ -671,13 +671,14 @@ typedef int (*IsUidBlockedFn)(uid_t, bool);
 IsUidBlockedFn ADnsHelper_isUidNetworkingBlocked;
 
 IsUidBlockedFn resolveIsUidNetworkingBlockedFn() {
-    // Related BPF maps were mainlined from T.
-    if (!isAtLeastT()) return nullptr;
+    // Related BPF maps were mainlined from T, but we want to init on S too.
+    if (!isAtLeastS()) return nullptr;
 
     // TODO: Check whether it is safe to shared link the .so without using dlopen when the carrier
     // APEX module (tethering) is fully released.
     void* handle = dlopen("libcom.android.tethering.dns_helper.so", RTLD_NOW | RTLD_LOCAL);
     if (!handle) {
+        // Can happen if the tethering apex is ancient.
         LOG(WARNING) << __func__ << ": " << dlerror();
         return nullptr;
     }
@@ -685,15 +686,19 @@ IsUidBlockedFn resolveIsUidNetworkingBlockedFn() {
     InitFn ADnsHelper_init = reinterpret_cast<InitFn>(dlsym(handle, "ADnsHelper_init"));
     if (!ADnsHelper_init) {
         LOG(ERROR) << __func__ << ": " << dlerror();
-        // TODO: Change to abort() when NDK is finalized
-        return nullptr;
+        abort();
     }
     const int ret = (*ADnsHelper_init)();
     if (ret) {
+        // On S/Sv2 this can fail if tethering apex is too old, ignore it.
+        if (ret == -EOPNOTSUPP && !isAtLeastT()) return nullptr;
         LOG(ERROR) << __func__ << ": ADnsHelper_init failed " << strerror(-ret);
         abort();
     }
 
+    // Related BPF maps were only mainlined from T.
+    if (!isAtLeastT()) return nullptr;
+
     IsUidBlockedFn f =
             reinterpret_cast<IsUidBlockedFn>(dlsym(handle, "ADnsHelper_isUidNetworkingBlocked"));
     if (!f) {
@@ -886,7 +891,8 @@ void DnsProxyListener::GetAddrInfoHandler::doDns64Synthesis(int32_t* rv, addrinf
         mHints->ai_family = AF_INET;
         // Don't need to do freeaddrinfo(res) before starting new DNS lookup because previous
         // DNS lookup is failed with error EAI_NODATA.
-        *rv = resolv_getaddrinfo(host, service, mHints.get(), &mNetContext, res, event);
+        *rv = resolv_getaddrinfo(host, service, mHints.get(), &mNetContext, mClient->getSocket(),
+                                 res, event);
         if (*rv) {
             *rv = EAI_NODATA;  // return original error code
             return;
@@ -924,7 +930,8 @@ void DnsProxyListener::GetAddrInfoHandler::run() {
         const char* host = mHost.starts_with('^') ? nullptr : mHost.c_str();
         const char* service = mService.starts_with('^') ? nullptr : mService.c_str();
         if (evaluate_domain_name(mNetContext, host)) {
-            rv = resolv_getaddrinfo(host, service, mHints.get(), &mNetContext, &result, &event);
+            rv = resolv_getaddrinfo(host, service, mHints.get(), &mNetContext, mClient->getSocket(),
+                                    &result, &event);
             doDns64Synthesis(&rv, &result, &event);
         } else {
             rv = EAI_SYSTEM;
@@ -1135,7 +1142,8 @@ void DnsProxyListener::ResNSendHandler::run() {
         ansLen = -ECONNREFUSED;
     } else if (startQueryLimiter(uid)) {
         if (evaluate_domain_name(mNetContext, rr_name.c_str())) {
-            ansLen = resolv_res_nsend(&mNetContext, std::span(msg.data(), msgLen), ansBuf, &rcode,
+            ansLen = resolv_res_nsend(&mNetContext, mClient->getSocket(),
+                                      std::span(msg.data(), msgLen), ansBuf, &rcode,
                                       static_cast<ResNsendFlags>(mFlags), &event);
         } else {
             // TODO(b/307048182): It should return -errno.
@@ -1310,7 +1318,8 @@ void DnsProxyListener::GetHostByNameHandler::doDns64Synthesis(int32_t* rv, hoste
 
     // If caller wants IPv6 answers but no data, try to query IPv4 answers for synthesis
     const char* name = mName.starts_with('^') ? nullptr : mName.c_str();
-    *rv = resolv_gethostbyname(name, AF_INET, hbuf, buf, buflen, &mNetContext, hpp, event);
+    *rv = resolv_gethostbyname(name, AF_INET, hbuf, buf, buflen, &mNetContext, mClient->getSocket(),
+                               hpp, event);
     if (*rv) {
         *rv = EAI_NODATA;  // return original error code
         return;
@@ -1341,8 +1350,8 @@ void DnsProxyListener::GetHostByNameHandler::run() {
     } else if (startQueryLimiter(uid)) {
         const char* name = mName.starts_with('^') ? nullptr : mName.c_str();
         if (evaluate_domain_name(mNetContext, name)) {
-            rv = resolv_gethostbyname(name, mAf, &hbuf, tmpbuf, sizeof tmpbuf, &mNetContext, &hp,
-                                      &event);
+            rv = resolv_gethostbyname(name, mAf, &hbuf, tmpbuf, sizeof tmpbuf, &mNetContext,
+                                      mClient->getSocket(), &hp, &event);
             doDns64Synthesis(&rv, &hbuf, tmpbuf, sizeof tmpbuf, &hp, &event);
         } else {
             rv = EAI_SYSTEM;
@@ -1470,8 +1479,8 @@ void DnsProxyListener::GetHostByAddrHandler::doDns64ReverseLookup(hostent* hbuf,
 
     // Remove NAT64 prefix and do reverse DNS query
     struct in_addr v4addr = {.s_addr = v6addr.s6_addr32[3]};
-    resolv_gethostbyaddr(&v4addr, sizeof(v4addr), AF_INET, hbuf, buf, buflen, &mNetContext, hpp,
-                         event);
+    resolv_gethostbyaddr(&v4addr, sizeof(v4addr), AF_INET, hbuf, buf, buflen, &mNetContext,
+                         mClient->getSocket(), hpp, event);
     if (*hpp && (*hpp)->h_addr_list[0]) {
         // Replace IPv4 address with original queried IPv6 address in place. The space has
         // reserved by dns_gethtbyaddr() and netbsd_gethostent_r() in
@@ -1513,7 +1522,8 @@ void DnsProxyListener::GetHostByAddrHandler::run() {
             rv = EAI_SYSTEM;
         } else {
             rv = resolv_gethostbyaddr(&mAddress, mAddressLen, mAddressFamily, &hbuf, tmpbuf,
-                                      sizeof tmpbuf, &mNetContext, &hp, &event);
+                                      sizeof tmpbuf, &mNetContext, mClient->getSocket(), &hp,
+                                      &event);
             doDns64ReverseLookup(&hbuf, tmpbuf, sizeof tmpbuf, &hp, &event);
         }
         endQueryLimiter(uid);
diff --git a/Experiments.h b/Experiments.h
index db58630c..04d8a36d 100644
--- a/Experiments.h
+++ b/Experiments.h
@@ -67,6 +67,7 @@ class Experiments {
             "max_cache_entries",
             "max_queries_global",
             "mdns_resolution",
+            "no_retry_after_cancel",
             "parallel_lookup_sleep_time",
             "retransmission_time_interval",
             "retry_count",
diff --git a/aidl_api/dnsresolver_aidl_interface/16/.hash b/aidl_api/dnsresolver_aidl_interface/16/.hash
new file mode 100644
index 00000000..6595053f
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/.hash
@@ -0,0 +1 @@
+e34a3eebf1e6d28421568d69b08f851431a4d990
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/IDnsResolver.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/IDnsResolver.aidl
new file mode 100644
index 00000000..5c4e970c
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/IDnsResolver.aidl
@@ -0,0 +1,71 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net;
+/* @hide */
+interface IDnsResolver {
+  boolean isAlive();
+  void registerEventListener(android.net.metrics.INetdEventListener listener);
+  void setResolverConfiguration(in android.net.ResolverParamsParcel resolverParams);
+  void getResolverInfo(int netId, out @utf8InCpp String[] servers, out @utf8InCpp String[] domains, out @utf8InCpp String[] tlsServers, out int[] params, out int[] stats, out int[] wait_for_pending_req_timeout_count);
+  void startPrefix64Discovery(int netId);
+  void stopPrefix64Discovery(int netId);
+  @utf8InCpp String getPrefix64(int netId);
+  void createNetworkCache(int netId);
+  void destroyNetworkCache(int netId);
+  void setLogSeverity(int logSeverity);
+  void flushNetworkCache(int netId);
+  void setPrefix64(int netId, @utf8InCpp String prefix);
+  void registerUnsolicitedEventListener(android.net.resolv.aidl.IDnsResolverUnsolicitedEventListener listener);
+  void setResolverOptions(int netId, in android.net.ResolverOptionsParcel optionParams);
+  void setAllowBypassPrivateDnsOnNetwork(int netId, int uid, boolean allowed);
+  const int RESOLVER_PARAMS_SAMPLE_VALIDITY = 0;
+  const int RESOLVER_PARAMS_SUCCESS_THRESHOLD = 1;
+  const int RESOLVER_PARAMS_MIN_SAMPLES = 2;
+  const int RESOLVER_PARAMS_MAX_SAMPLES = 3;
+  const int RESOLVER_PARAMS_BASE_TIMEOUT_MSEC = 4;
+  const int RESOLVER_PARAMS_RETRY_COUNT = 5;
+  const int RESOLVER_PARAMS_COUNT = 6;
+  const int RESOLVER_STATS_SUCCESSES = 0;
+  const int RESOLVER_STATS_ERRORS = 1;
+  const int RESOLVER_STATS_TIMEOUTS = 2;
+  const int RESOLVER_STATS_INTERNAL_ERRORS = 3;
+  const int RESOLVER_STATS_RTT_AVG = 4;
+  const int RESOLVER_STATS_LAST_SAMPLE_TIME = 5;
+  const int RESOLVER_STATS_USABLE = 6;
+  const int RESOLVER_STATS_COUNT = 7;
+  const int DNS_RESOLVER_LOG_VERBOSE = 0;
+  const int DNS_RESOLVER_LOG_DEBUG = 1;
+  const int DNS_RESOLVER_LOG_INFO = 2;
+  const int DNS_RESOLVER_LOG_WARNING = 3;
+  const int DNS_RESOLVER_LOG_ERROR = 4;
+  const int TC_MODE_DEFAULT = 0;
+  const int TC_MODE_UDP_TCP = 1;
+  const int TRANSPORT_UNKNOWN = (-1) /* -1 */;
+  const int TRANSPORT_CELLULAR = 0;
+  const int TRANSPORT_WIFI = 1;
+  const int TRANSPORT_BLUETOOTH = 2;
+  const int TRANSPORT_ETHERNET = 3;
+  const int TRANSPORT_VPN = 4;
+  const int TRANSPORT_WIFI_AWARE = 5;
+  const int TRANSPORT_LOWPAN = 6;
+  const int TRANSPORT_TEST = 7;
+  const int TRANSPORT_USB = 8;
+  const int TRANSPORT_THREAD = 9;
+  const int TRANSPORT_SATELLITE = 10;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverHostsParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverHostsParcel.aidl
new file mode 100644
index 00000000..2a1c748f
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverHostsParcel.aidl
@@ -0,0 +1,25 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net;
+/* @hide */
+@JavaDerive(equals=true)
+parcelable ResolverHostsParcel {
+  @utf8InCpp String ipAddr;
+  @utf8InCpp String hostName = "";
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverOptionsParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverOptionsParcel.aidl
new file mode 100644
index 00000000..b07263f8
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverOptionsParcel.aidl
@@ -0,0 +1,26 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net;
+/* @hide */
+@JavaDerive(equals=true, toString=true)
+parcelable ResolverOptionsParcel {
+  android.net.ResolverHostsParcel[] hosts = {};
+  int tcMode = 0;
+  boolean enforceDnsUid = false;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverParamsParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverParamsParcel.aidl
new file mode 100644
index 00000000..f0dfbdc3
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/ResolverParamsParcel.aidl
@@ -0,0 +1,42 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net;
+/* @hide */
+@JavaDerive(equals=true, toString=true)
+parcelable ResolverParamsParcel {
+  int netId;
+  int sampleValiditySeconds;
+  int successThreshold;
+  int minSamples;
+  int maxSamples;
+  int baseTimeoutMsec;
+  int retryCount;
+  @utf8InCpp String[] servers;
+  @utf8InCpp String[] domains;
+  @utf8InCpp String tlsName;
+  @utf8InCpp String[] tlsServers;
+  @utf8InCpp String[] tlsFingerprints = {};
+  @utf8InCpp String caCertificate = "";
+  int tlsConnectTimeoutMs = 0;
+  @nullable android.net.ResolverOptionsParcel resolverOptions;
+  int[] transportTypes = {};
+  boolean meteredNetwork = false;
+  @nullable android.net.resolv.aidl.DohParamsParcel dohParams;
+  @utf8InCpp String[] interfaceNames = {};
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/DnsHealthEventParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/DnsHealthEventParcel.aidl
new file mode 100644
index 00000000..d32be919
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/DnsHealthEventParcel.aidl
@@ -0,0 +1,26 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net.resolv.aidl;
+/* @hide */
+@JavaDerive(toString=true)
+parcelable DnsHealthEventParcel {
+  int netId;
+  int healthResult;
+  int[] successRttMicros;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/DohParamsParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/DohParamsParcel.aidl
new file mode 100644
index 00000000..ba1ea747
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/DohParamsParcel.aidl
@@ -0,0 +1,27 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net.resolv.aidl;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @JavaOnlyImmutable
+parcelable DohParamsParcel {
+  String name = "";
+  String[] ips = {};
+  String dohpath = "";
+  int port = (-1) /* -1 */;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/IDnsResolverUnsolicitedEventListener.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/IDnsResolverUnsolicitedEventListener.aidl
new file mode 100644
index 00000000..32963dfd
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/IDnsResolverUnsolicitedEventListener.aidl
@@ -0,0 +1,33 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net.resolv.aidl;
+/* @hide */
+interface IDnsResolverUnsolicitedEventListener {
+  oneway void onDnsHealthEvent(in android.net.resolv.aidl.DnsHealthEventParcel dnsHealthEvent);
+  oneway void onNat64PrefixEvent(in android.net.resolv.aidl.Nat64PrefixEventParcel nat64PrefixEvent);
+  oneway void onPrivateDnsValidationEvent(in android.net.resolv.aidl.PrivateDnsValidationEventParcel privateDnsValidationEvent);
+  const int DNS_HEALTH_RESULT_OK = 0;
+  const int DNS_HEALTH_RESULT_TIMEOUT = 255;
+  const int PREFIX_OPERATION_ADDED = 1;
+  const int PREFIX_OPERATION_REMOVED = 2;
+  const int VALIDATION_RESULT_SUCCESS = 1;
+  const int VALIDATION_RESULT_FAILURE = 2;
+  const int PROTOCOL_DOT = 1;
+  const int PROTOCOL_DOH = 2;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/Nat64PrefixEventParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/Nat64PrefixEventParcel.aidl
new file mode 100644
index 00000000..2daccb0e
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/Nat64PrefixEventParcel.aidl
@@ -0,0 +1,27 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net.resolv.aidl;
+/* @hide */
+@JavaDerive(toString=true)
+parcelable Nat64PrefixEventParcel {
+  int netId;
+  int prefixOperation;
+  @utf8InCpp String prefixAddress;
+  int prefixLength;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/PrivateDnsValidationEventParcel.aidl b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/PrivateDnsValidationEventParcel.aidl
new file mode 100644
index 00000000..f3bfbc76
--- /dev/null
+++ b/aidl_api/dnsresolver_aidl_interface/16/android/net/resolv/aidl/PrivateDnsValidationEventParcel.aidl
@@ -0,0 +1,28 @@
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.net.resolv.aidl;
+/* @hide */
+@JavaDerive(toString=true)
+parcelable PrivateDnsValidationEventParcel {
+  int netId;
+  @utf8InCpp String ipAddress;
+  @utf8InCpp String hostname;
+  int validation;
+  int protocol;
+}
diff --git a/aidl_api/dnsresolver_aidl_interface/current/android/net/IDnsResolver.aidl b/aidl_api/dnsresolver_aidl_interface/current/android/net/IDnsResolver.aidl
index 5f1adbb6..5c4e970c 100644
--- a/aidl_api/dnsresolver_aidl_interface/current/android/net/IDnsResolver.aidl
+++ b/aidl_api/dnsresolver_aidl_interface/current/android/net/IDnsResolver.aidl
@@ -33,6 +33,7 @@ interface IDnsResolver {
   void setPrefix64(int netId, @utf8InCpp String prefix);
   void registerUnsolicitedEventListener(android.net.resolv.aidl.IDnsResolverUnsolicitedEventListener listener);
   void setResolverOptions(int netId, in android.net.ResolverOptionsParcel optionParams);
+  void setAllowBypassPrivateDnsOnNetwork(int netId, int uid, boolean allowed);
   const int RESOLVER_PARAMS_SAMPLE_VALIDITY = 0;
   const int RESOLVER_PARAMS_SUCCESS_THRESHOLD = 1;
   const int RESOLVER_PARAMS_MIN_SAMPLES = 2;
diff --git a/apex/Android.bp b/apex/Android.bp
index 82302dd1..92b96870 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -22,6 +22,14 @@ package {
     default_applicable_licenses: ["packages_modules_DnsResolver_license"],
 }
 
+prebuilt_root {
+    name: "NetBpfLoad-S.flag",
+    src: "NetBpfLoad-S.flag",
+    filename: "NetBpfLoad-S.flag",
+    install_in_root: true,  // ie. in root of apex, not under 'root'
+    installable: false,
+}
+
 apex {
     name: "com.android.resolv",
     manifest: "manifest.json",
@@ -40,6 +48,10 @@ apex {
     // Whether it actually will be compressed is controlled on per-device basis.
     compressible: true,
 
+    prebuilts: [
+        "NetBpfLoad-S.flag",
+    ],
+
     // IMPORTANT:  q-launched-apex-module enables the build system to make
     // sure the package compatible to Android 10 in two ways:
     // - build the APEX package compatible to Android 10
diff --git a/apex/NetBpfLoad-S.flag b/apex/NetBpfLoad-S.flag
new file mode 100644
index 00000000..e69de29b
diff --git a/binder/android/net/IDnsResolver.aidl b/binder/android/net/IDnsResolver.aidl
index 34de515a..fcb32c7e 100644
--- a/binder/android/net/IDnsResolver.aidl
+++ b/binder/android/net/IDnsResolver.aidl
@@ -246,4 +246,19 @@ interface IDnsResolver {
      *         unix errno.
      */
     void setResolverOptions(int netId, in ResolverOptionsParcel optionParams);
+
+    /**
+     * Set whether to allow the UID to explicitly bypass the private DNS rule on a given network.
+     *
+     * Throws ServiceSpecificException with error code EEXISTS when trying to add a bypass rule
+     * that already exists, and ENOENT when trying to remove a bypass rule that does not exist or
+     * when there is no known network with this netId.
+     *
+     * @param netId the netId where the UID is allowed or disallowed to bypass private DNS.
+     * @param uid the UID.
+     * @param allowed whether to allow or disallow the operation.
+     * @throws ServiceSpecificException in case of failure, with an error code indicating the
+     *         cause of the failure.
+     */
+    void setAllowBypassPrivateDnsOnNetwork(int netId, int uid, boolean allowed);
 }
diff --git a/doh/metrics.rs b/doh/metrics.rs
index 9b7a96b1..7a79d81a 100644
--- a/doh/metrics.rs
+++ b/doh/metrics.rs
@@ -17,7 +17,7 @@
 use crate::connection::driver::Cause;
 use crate::connection::driver::HandshakeInfo;
 use crate::connection::driver::HandshakeResult;
-use statslog_rust::network_dns_handshake_reported::{
+use statslog_dns_resolver_rust::network_dns_handshake_reported::{
     Cause as StatsdCause, NetworkDnsHandshakeReported, NetworkType as StatsdNetworkType,
     PrivateDnsMode as StatsdPrivateDnsMode, Protocol as StatsdProtocol, Result as StatsdResult,
 };
diff --git a/doh/tests/doh_frontend/Android.bp b/doh/tests/doh_frontend/Android.bp
index 76bd47a2..8f023b0a 100644
--- a/doh/tests/doh_frontend/Android.bp
+++ b/doh/tests/doh_frontend/Android.bp
@@ -14,7 +14,7 @@ rust_ffi_static {
     srcs: ["src/mod.rs"],
     edition: "2018",
 
-    rlibs: [
+    rustlibs: [
         "liblibc",
         "liblog_rust",
         "libandroid_logger",
@@ -23,7 +23,7 @@ rust_ffi_static {
         "libtokio",
         "libbase64_rust",
     ],
-
+    prefer_rlib: true,
     // TODO(b/194022174): this is a workaround for resolv_integration_test to run on Q devices.
     whole_static_libs: ["libunwind"],
 }
diff --git a/doh/tests/doh_frontend/src/dns_https_frontend.rs b/doh/tests/doh_frontend/src/dns_https_frontend.rs
index f987c9c8..38dd726a 100644
--- a/doh/tests/doh_frontend/src/dns_https_frontend.rs
+++ b/doh/tests/doh_frontend/src/dns_https_frontend.rs
@@ -224,12 +224,11 @@ impl DohFrontend {
             self.command_tx.is_some(),
             "command_tx is None because worker thread not yet initialized"
         );
-        return self
-            .command_tx
+        self.command_tx
             .as_ref()
             .unwrap()
             .send(ControlCommand::StatsClearQueries)
-            .or_else(|e| bail!(e));
+            .or_else(|e| bail!(e))
     }
 
     fn init_worker_thread_params(&mut self) -> Result<WorkerParams> {
diff --git a/getaddrinfo.cpp b/getaddrinfo.cpp
index 3f3166da..ce97c855 100644
--- a/getaddrinfo.cpp
+++ b/getaddrinfo.cpp
@@ -116,15 +116,17 @@ const Explore explore_options[] = {
 #define PTON_MAX 16
 
 struct res_target {
-    struct res_target* next;
     const char* name;                                                  // domain name
     int qclass, qtype;                                                 // class and type of query
     std::vector<uint8_t> answer = std::vector<uint8_t>(MAXPACKET, 0);  // buffer to put answer
     int n = 0;                                                         // result length
+    // ResState this query should be run within
+    ResState* res_state;
 };
 
 static int explore_fqdn(const struct addrinfo*, const char*, const char*, struct addrinfo**,
-                        const struct android_net_context*, NetworkDnsEventReported* event);
+                        const struct android_net_context*, std::optional<int> app_socket,
+                        NetworkDnsEventReported* event);
 static int explore_null(const struct addrinfo*, const char*, struct addrinfo**);
 static int explore_numeric(const struct addrinfo*, const char*, const char*, struct addrinfo**,
                            const char*);
@@ -140,8 +142,8 @@ static int ip6_str2scopeid(const char*, struct sockaddr_in6*, uint32_t*);
 static struct addrinfo* getanswer(const std::vector<uint8_t>&, int, const char*, int,
                                   const struct addrinfo*, int* herrno);
 static int dns_getaddrinfo(const char* name, const addrinfo* pai,
-                           const android_net_context* netcontext, addrinfo** rv,
-                           NetworkDnsEventReported* event);
+                           const android_net_context* netcontext, std::optional<int> app_socket,
+                           addrinfo** rv, NetworkDnsEventReported* event);
 static void _sethtent(FILE**);
 static void _endhtent(FILE**);
 static struct addrinfo* _gethtent(FILE**, const char*, const struct addrinfo*);
@@ -151,9 +153,11 @@ static bool files_getaddrinfo(const size_t netid, const char* name, const addrin
 static int _find_src_addr(const struct sockaddr*, struct sockaddr*, unsigned, uid_t,
                           bool allow_v6_linklocal);
 
-static int res_searchN(const char* name, res_target* target, ResState* res, int* herrno);
-static int res_querydomainN(const char* name, const char* domain, res_target* target, ResState* res,
-                            int* herrno);
+static int res_searchN(const char* name, std::span<res_target> queries,
+                       std::span<std::string> search_domains, bool is_mdns,
+                       android::net::NetworkDnsEventReported* event, int* herrno);
+static int res_querydomainN(const char* name, const char* domain, std::span<res_target> queries,
+                            android::net::NetworkDnsEventReported* event, int* herrno);
 
 const char* const ai_errlist[] = {
         "Success",
@@ -212,16 +216,7 @@ void freeaddrinfo(struct addrinfo* ai) {
     }
 }
 
-/*
- * The following functions determine whether IPv4 or IPv6 connectivity is
- * available in order to implement AI_ADDRCONFIG.
- *
- * Strictly speaking, AI_ADDRCONFIG should not look at whether connectivity is
- * available, but whether addresses of the specified family are "configured
- * on the local system". However, bionic doesn't currently support getifaddrs,
- * so checking for connectivity is the next best thing.
- */
-static int have_ipv6(unsigned mark, uid_t uid, bool mdns) {
+static bool have_global_ipv6_connectivity(unsigned mark, uid_t uid) {
     static const struct sockaddr_in6 sin6_test = {
             .sin6_family = AF_INET6,
             .sin6_addr.s6_addr = {// 2000::
@@ -229,10 +224,31 @@ static int have_ipv6(unsigned mark, uid_t uid, bool mdns) {
     sockaddr_union addr = {.sin6 = sin6_test};
     sockaddr_storage sa;
     return _find_src_addr(&addr.sa, (struct sockaddr*)&sa, mark, uid,
-                          /*allow_v6_linklocal=*/mdns) == 1;
+                          /*allow_v6_linklocal=*/false) == 1;
 }
 
-static int have_ipv4(unsigned mark, uid_t uid) {
+static bool have_local_ipv6_connectivity(unsigned mark, uid_t uid, int netid) {
+    // IPv6 link-local addresses require a scope identifier to be correctly defined. This forces us
+    // to loop through all interfaces included within |netid|.
+    std::vector<std::string> interface_names = resolv_get_interface_names(netid);
+    for (const auto& interface_name : interface_names) {
+        const struct sockaddr_in6 sin6_test = {
+                .sin6_family = AF_INET6,
+                .sin6_addr.s6_addr =
+                        {// fe80::
+                         0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
+                .sin6_scope_id = if_nametoindex(interface_name.c_str())};
+        sockaddr_union addr = {.sin6 = sin6_test};
+        sockaddr_storage sa;
+        if (_find_src_addr(&addr.sa, (struct sockaddr*)&sa, mark, uid,
+                           /*allow_v6_linklocal=*/true) == 1) {
+            return true;
+        }
+    }
+    return false;
+}
+
+static bool have_ipv4_connectivity(unsigned mark, uid_t uid) {
     static const struct sockaddr_in sin_test = {
             .sin_family = AF_INET,
             .sin_addr.s_addr = __constant_htonl(0x08080808L)  // 8.8.8.8
@@ -304,6 +320,17 @@ int validateHints(const addrinfo* _Nonnull hints) {
     return 0;
 }
 
+void fill_sin6_scope_id_if_needed(const res_target& query, addrinfo* addr_info) {
+    if (addr_info->ai_family != AF_INET6) {
+        return;
+    }
+
+    sockaddr_in6* sin6 = reinterpret_cast<sockaddr_in6*>(addr_info->ai_addr);
+    if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
+        sin6->sin6_scope_id = query.res_state->target_interface_index_for_mdns;
+    }
+}
+
 }  // namespace
 
 int android_getaddrinfofornetcontext(const char* hostname, const char* servname,
@@ -381,7 +408,8 @@ int android_getaddrinfofornetcontext(const char* hostname, const char* servname,
             break;
         }
 
-        return resolv_getaddrinfo(hostname, servname, hints, netcontext, res, event);
+        return resolv_getaddrinfo(hostname, servname, hints, netcontext, APP_SOCKET_NONE, res,
+                                  event);
     } while (0);
 
     if (error) {
@@ -394,7 +422,8 @@ int android_getaddrinfofornetcontext(const char* hostname, const char* servname,
 }
 
 int resolv_getaddrinfo(const char* _Nonnull hostname, const char* servname, const addrinfo* hints,
-                       const android_net_context* _Nonnull netcontext, addrinfo** _Nonnull res,
+                       const android_net_context* _Nonnull netcontext,
+                       std::optional<int> app_socket, addrinfo** _Nonnull res,
                        NetworkDnsEventReported* _Nonnull event) {
     if (hostname == nullptr && servname == nullptr) return EAI_NONAME;
     if (hostname == nullptr) return EAI_NODATA;
@@ -430,7 +459,8 @@ int resolv_getaddrinfo(const char* _Nonnull hostname, const char* servname, cons
 
         LOG(DEBUG) << __func__ << ": explore_fqdn(): ai_family=" << tmp.ai_family
                    << " ai_socktype=" << tmp.ai_socktype << " ai_protocol=" << tmp.ai_protocol;
-        error = explore_fqdn(&tmp, hostname, servname, &cur->ai_next, netcontext, event);
+        error = explore_fqdn(&tmp, hostname, servname, &cur->ai_next, netcontext, app_socket,
+                             event);
 
         while (cur->ai_next) cur = cur->ai_next;
     }
@@ -447,7 +477,7 @@ int resolv_getaddrinfo(const char* _Nonnull hostname, const char* servname, cons
 // FQDN hostname, DNS lookup
 static int explore_fqdn(const addrinfo* pai, const char* hostname, const char* servname,
                         addrinfo** res, const android_net_context* netcontext,
-                        NetworkDnsEventReported* event) {
+                        std::optional<int> app_socket, NetworkDnsEventReported* event) {
     assert(pai != nullptr);
     // hostname may be nullptr
     // servname may be nullptr
@@ -460,7 +490,7 @@ static int explore_fqdn(const addrinfo* pai, const char* hostname, const char* s
     if ((error = get_portmatch(pai, servname))) return error;
 
     if (!files_getaddrinfo(netcontext->dns_netid, hostname, pai, &result)) {
-        error = dns_getaddrinfo(hostname, pai, netcontext, &result, event);
+        error = dns_getaddrinfo(hostname, pai, netcontext, app_socket, &result, event);
     }
     if (error) {
         freeaddrinfo(result);
@@ -1384,55 +1414,89 @@ error:
 }
 
 static int dns_getaddrinfo(const char* name, const addrinfo* pai,
-                           const android_net_context* netcontext, addrinfo** rv,
-                           NetworkDnsEventReported* event) {
-    res_target q = {};
-    res_target q2 = {};
-    ResState res(netcontext, event);
+                           const android_net_context* netcontext, std::optional<int> app_socket,
+                           addrinfo** rv, NetworkDnsEventReported* event) {
+    std::vector<res_target> queries;
+    ResState res(netcontext, app_socket, event);
+
     setMdnsFlag(name, res.netid, &(res.flags));
+    bool is_mdns = isMdnsResolution(res.flags);
+
+    bool query_ipv6 = false;
+    bool query_ipv4 = false;
+
+    if (pai->ai_family == AF_UNSPEC) {
+        query_ipv6 = true;
+        query_ipv4 = true;
+        if (pai->ai_flags & AI_ADDRCONFIG) {
+            // Strictly speaking, AI_ADDRCONFIG should not look at whether connectivity is
+            // available, but whether addresses of the specified family are "configured on the local
+            // system". However, bionic doesn't currently support getifaddrs, so checking for
+            // connectivity is the next best thing.
+            query_ipv6 = have_global_ipv6_connectivity(netcontext->app_mark, netcontext->uid) ||
+                         (is_mdns && have_local_ipv6_connectivity(netcontext->app_mark,
+                                                                  netcontext->uid, res.netid));
+            query_ipv4 = have_ipv4_connectivity(netcontext->app_mark, netcontext->uid);
+        }
+    } else if (pai->ai_family == AF_INET) {
+        query_ipv4 = true;
+    } else if (pai->ai_family == AF_INET6) {
+        query_ipv6 = true;
+    } else {
+        return EAI_FAMILY;
+    }
 
-    switch (pai->ai_family) {
-        case AF_UNSPEC: {
-            /* prefer IPv6 */
-            q.name = name;
-            q.qclass = C_IN;
-            int query_ipv6 = 1, query_ipv4 = 1;
-            if (pai->ai_flags & AI_ADDRCONFIG) {
-                query_ipv6 = have_ipv6(netcontext->app_mark, netcontext->uid,
-                                       isMdnsResolution(res.flags));
-                query_ipv4 = have_ipv4(netcontext->app_mark, netcontext->uid);
-            }
-            if (query_ipv6) {
-                q.qtype = T_AAAA;
-                if (query_ipv4) {
-                    q.next = &q2;
-                    q2.name = name;
-                    q2.qclass = C_IN;
-                    q2.qtype = T_A;
-                }
-            } else if (query_ipv4) {
-                q.qtype = T_A;
-            } else {
-                return EAI_NODATA;
-            }
-            break;
+    resolv_populate_res_for_net(&res);
+
+    std::vector<ResState> res_states;
+    if (is_mdns) {
+        // resolv_get_interface_names is also called within have_local_ipv6_connectivity. This is
+        // racy and the two could return different values. Having said that, the race condition is
+        // benign for the following reasons:
+        // 1. The first call is to figure out whether to send out an AAAA query.
+        // 2. The second call is to figure out which interfaces to the queries to.
+        // With the above in mind, if these value don't match only the following can happen:
+        // 1. The second call returns interfaces that didn't exist before. In this scenario, we will
+        //    send the query onto this additional interface. This is a good thing.
+        // 2. The second call returns an interface that didn't exist before. In this scenario, we
+        //    will not send the query onto this interface anymore. This is a good thing.
+        // One could argue that whether we're sending out an AAAA query or not is also affected by
+        // these network topology changes. But that is a race condition that cannot be avoided, as
+        // it could also happen while this code is returning results to the caller.
+        std::vector<std::string> interface_names = resolv_get_interface_names(res.netid);
+        for (const auto& interface_name : interface_names) {
+            res_states.emplace_back(res.clone(event)).target_interface_index_for_mdns =
+                    if_nametoindex(interface_name.c_str());
         }
-        case AF_INET:
-            q.name = name;
-            q.qclass = C_IN;
-            q.qtype = T_A;
-            break;
-        case AF_INET6:
-            q.name = name;
-            q.qclass = C_IN;
-            q.qtype = T_AAAA;
-            break;
-        default:
-            return EAI_FAMILY;
+    } else {
+        res_states.emplace_back(res.clone(event));
+    }
+
+    for (auto& res_state : res_states) {
+        if (query_ipv6) {
+            res_target ipv6_query;
+            ipv6_query.name = name;
+            ipv6_query.qclass = C_IN;
+            ipv6_query.qtype = T_AAAA;
+            ipv6_query.res_state = &res_state;
+            queries.push_back(ipv6_query);
+        }
+        if (query_ipv4) {
+            res_target ipv4_query;
+            ipv4_query.name = name;
+            ipv4_query.qclass = C_IN;
+            ipv4_query.qtype = T_A;
+            ipv4_query.res_state = &res_state;
+            queries.push_back(ipv4_query);
+        }
+    }
+    if (queries.empty()) {
+        return EAI_NODATA;
     }
 
     int he;
-    if (res_searchN(name, &q, &res, &he) < 0) {
+    // TODO: Refactor search_domains and event out of ResState (they really should not be there).
+    if (res_searchN(name, queries, res.search_domains, is_mdns, res.event, &he) < 0) {
         // Return h_errno (he) to catch more detailed errors rather than EAI_NODATA.
         // Note that res_searchN() doesn't set the pair NETDB_INTERNAL and errno.
         // See also herrnoToAiErrno().
@@ -1441,15 +1505,17 @@ static int dns_getaddrinfo(const char* name, const addrinfo* pai,
 
     addrinfo sentinel = {};
     addrinfo* cur = &sentinel;
-    addrinfo* ai = getanswer(q.answer, q.n, q.name, q.qtype, pai, &he);
-    if (ai) {
-        cur->ai_next = ai;
-        while (cur && cur->ai_next) cur = cur->ai_next;
-    }
-    if (q.next) {
-        ai = getanswer(q2.answer, q2.n, q2.name, q2.qtype, pai, &he);
-        if (ai) cur->ai_next = ai;
+    for (const auto& query : queries) {
+        addrinfo* ai = getanswer(query.answer, query.n, query.name, query.qtype, pai, &he);
+        if (ai) {
+            cur->ai_next = ai;
+            while (cur && cur->ai_next) {
+                cur = cur->ai_next;
+                fill_sin6_scope_id_if_needed(query, cur);
+            }
+        }
     }
+
     if (sentinel.ai_next == NULL) {
         // Note that getanswer() doesn't set the pair NETDB_INTERNAL and errno.
         // See also herrnoToAiErrno().
@@ -1668,19 +1734,23 @@ QueryResult doQuery(const char* name, res_target* t, ResState* res,
 }  // namespace
 
 // This function runs doQuery() for each res_target in parallel.
-// The `target`, which is set in dns_getaddrinfo(), contains at most two res_target.
-static int res_queryN_parallel(const char* name, res_target* target, ResState* res, int* herrno) {
+static int res_queryN_parallel(const char* name, std::span<res_target> queries,
+                               android::net::NetworkDnsEventReported* event, int* herrno) {
     std::vector<std::future<QueryResult>> results;
-    results.reserve(2);
     std::chrono::milliseconds sleepTimeMs{};
-    for (res_target* t = target; t; t = t->next) {
-        results.emplace_back(std::async(std::launch::async, doQuery, name, t, res, sleepTimeMs));
-        // Avoiding gateways drop packets if queries are sent too close together
-        // Only needed if we have multiple queries in a row.
-        if (t->next) {
+    bool is_first_iteration = true;
+    for (auto& query : queries) {
+        results.emplace_back(std::async(std::launch::async, doQuery, name, &query, query.res_state,
+                                        sleepTimeMs));
+        if (is_first_iteration) {
+            // Avoiding gateways drop packets if queries are sent too close together
+            // Only needed if we have multiple queries in a row.
+            is_first_iteration = false;
             int sleepFlag = Experiments::getInstance()->getFlag("parallel_lookup_sleep_time",
                                                                 SLEEP_TIME_MS);
-            if (sleepFlag > 1000) sleepFlag = 1000;
+            if (sleepFlag > 1000) {
+                sleepFlag = 1000;
+            }
             sleepTimeMs = std::chrono::milliseconds(sleepFlag);
         }
     }
@@ -1694,7 +1764,7 @@ static int res_queryN_parallel(const char* name, res_target* target, ResState* r
             *herrno = r.herrno;
             return -1;
         }
-        res->event->MergeFrom(r.event);
+        event->MergeFrom(r.event);
         ancount += r.ancount;
         rcode = r.rcode;
         errno = r.qerrno;
@@ -1714,7 +1784,9 @@ static int res_queryN_parallel(const char* name, res_target* target, ResState* r
  * If enabled, implement search rules until answer or unrecoverable failure
  * is detected.  Error code, if any, is left in *herrno.
  */
-static int res_searchN(const char* name, res_target* target, ResState* res, int* herrno) {
+static int res_searchN(const char* name, std::span<res_target> queries,
+                       std::span<std::string> search_domains, bool is_mdns,
+                       android::net::NetworkDnsEventReported* event, int* herrno) {
     const char* cp;
     HEADER* hp;
     uint32_t dots;
@@ -1722,9 +1794,9 @@ static int res_searchN(const char* name, res_target* target, ResState* res, int*
     int got_nodata = 0, got_servfail = 0, tried_as_is = 0;
 
     assert(name != NULL);
-    assert(target != NULL);
+    assert(!queries.empty());
 
-    hp = (HEADER*)(void*)target->answer.data();
+    hp = (HEADER*)(void*)queries.front().answer.data();
 
     errno = 0;
     *herrno = HOST_NOT_FOUND; /* default, if we never query */
@@ -1732,13 +1804,10 @@ static int res_searchN(const char* name, res_target* target, ResState* res, int*
     for (cp = name; *cp; cp++) dots += (*cp == '.');
     const bool trailing_dot = (cp > name && *--cp == '.') ? true : false;
 
-    /*
-     * If there are dots in the name already, let's just give it a try
-     * 'as is'.  The threshold can be set with the "ndots" option.
-     */
+    // If there are dots in the name already, let's just give it a try 'as is'.
     saved_herrno = -1;
-    if (dots >= res->ndots) {
-        ret = res_querydomainN(name, NULL, target, res, herrno);
+    if (dots >= NDOTS) {
+        ret = res_querydomainN(name, NULL, queries, event, herrno);
         if (ret > 0) return (ret);
         saved_herrno = *herrno;
         tried_as_is++;
@@ -1746,19 +1815,13 @@ static int res_searchN(const char* name, res_target* target, ResState* res, int*
 
     /*
      * We do at least one level of search if
-     *	 - there is no dot, or
-     *	 - there is at least one dot and there is no trailing dot.
+     * - there is no dot, or
+     * - there is at least one dot and there is no trailing dot.
      * - this is not a .local mDNS lookup.
      */
-    if ((!dots || (dots && !trailing_dot)) && !isMdnsResolution(res->flags)) {
-        /* Unfortunately we need to set stuff up before
-         * the domain stuff is tried.  Will have a better
-         * fix after thread pools are used.
-         */
-        resolv_populate_res_for_net(res);
-
-        for (const auto& domain : res->search_domains) {
-            ret = res_querydomainN(name, domain.c_str(), target, res, herrno);
+    if ((!dots || (dots && !trailing_dot)) && !is_mdns) {
+        for (const auto& domain : search_domains) {
+            ret = res_querydomainN(name, domain.c_str(), queries, event, herrno);
             if (ret > 0) return ret;
 
             /*
@@ -1802,7 +1865,7 @@ static int res_searchN(const char* name, res_target* target, ResState* res, int*
      * name or whether it ends with a dot.
      */
     if (!tried_as_is) {
-        ret = res_querydomainN(name, NULL, target, res, herrno);
+        ret = res_querydomainN(name, NULL, queries, event, herrno);
         if (ret > 0) return ret;
     }
 
@@ -1825,8 +1888,8 @@ static int res_searchN(const char* name, res_target* target, ResState* res, int*
 
 // Perform a call on res_query on the concatenation of name and domain,
 // removing a trailing dot from name if domain is NULL.
-static int res_querydomainN(const char* name, const char* domain, res_target* target, ResState* res,
-                            int* herrno) {
+static int res_querydomainN(const char* name, const char* domain, std::span<res_target> queries,
+                            android::net::NetworkDnsEventReported* event, int* herrno) {
     char nbuf[MAXDNAME];
     const char* longname = nbuf;
     size_t n, d;
@@ -1854,5 +1917,5 @@ static int res_querydomainN(const char* name, const char* domain, res_target* ta
         }
         snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
     }
-    return res_queryN_parallel(longname, target, res, herrno);
+    return res_queryN_parallel(longname, queries, event, herrno);
 }
diff --git a/getaddrinfo.h b/getaddrinfo.h
index 4d84d889..3651c0c5 100644
--- a/getaddrinfo.h
+++ b/getaddrinfo.h
@@ -27,8 +27,8 @@ int android_getaddrinfofornetcontext(const char* hostname, const char* servname,
 
 // This is the DNS proxy entry point for getaddrinfo().
 int resolv_getaddrinfo(const char* hostname, const char* servname, const addrinfo* hints,
-                       const android_net_context* netcontext, addrinfo** res,
-                       android::net::NetworkDnsEventReported*);
+                       const android_net_context* netcontext, std::optional<int> app_socket,
+                       addrinfo** res, android::net::NetworkDnsEventReported*);
 
 // Sort the linked list starting at sentinel->ai_next in RFC6724 order.
 void resolv_rfc6724_sort(struct addrinfo* list_sentinel, unsigned mark, uid_t uid);
diff --git a/gethnamaddr.cpp b/gethnamaddr.cpp
index b7fef8b2..9a4e0ed4 100644
--- a/gethnamaddr.cpp
+++ b/gethnamaddr.cpp
@@ -94,8 +94,8 @@ typedef union {
 
 static void pad_v4v6_hostent(struct hostent* hp, char** bpp, char* ep);
 static int dns_gethtbyaddr(const unsigned char* uaddr, int len, int af,
-                           const android_net_context* netcontext, getnamaddr* info,
-                           NetworkDnsEventReported* event);
+                           const android_net_context* netcontext, std::optional<int> app_socket,
+                           getnamaddr* info, NetworkDnsEventReported* event);
 static int dns_gethtbyname(ResState* res, const char* name, int af, getnamaddr* info);
 
 #define BOUNDED_INCR(x)      \
@@ -371,14 +371,14 @@ nospc:
 }
 
 int resolv_gethostbyname(const char* name, int af, hostent* hp, char* buf, size_t buflen,
-                         const android_net_context* netcontext, hostent** result,
-                         NetworkDnsEventReported* event) {
+                         const android_net_context* netcontext, std::optional<int> app_socket,
+                         hostent** result, NetworkDnsEventReported* event) {
     if (name == nullptr || hp == nullptr) {
         return EAI_SYSTEM;
     }
 
     getnamaddr info;
-    ResState res(netcontext, event);
+    ResState res(netcontext, app_socket, event);
 
     setMdnsFlag(name, res.netid, &(res.flags));
 
@@ -463,7 +463,8 @@ fake:
 
 int resolv_gethostbyaddr(const void* _Nonnull addr, socklen_t len, int af, hostent* hp, char* buf,
                          size_t buflen, const struct android_net_context* netcontext,
-                         hostent** result, NetworkDnsEventReported* event) {
+                         std::optional<int> app_socket, hostent** result,
+                         NetworkDnsEventReported* event) {
     const uint8_t* uaddr = (const uint8_t*)addr;
     socklen_t size;
     struct getnamaddr info;
@@ -503,7 +504,7 @@ int resolv_gethostbyaddr(const void* _Nonnull addr, socklen_t len, int af, hoste
     info.buf = buf;
     info.buflen = buflen;
     if (_hf_gethtbyaddr(uaddr, len, af, &info)) {
-        int error = dns_gethtbyaddr(uaddr, len, af, netcontext, &info, event);
+        int error = dns_gethtbyaddr(uaddr, len, af, netcontext, app_socket, &info, event);
         if (error != 0) return error;
     }
     *result = hp;
@@ -651,8 +652,8 @@ static int dns_gethtbyname(ResState* res, const char* name, int addr_type, getna
 }
 
 static int dns_gethtbyaddr(const unsigned char* uaddr, int len, int af,
-                           const android_net_context* netcontext, getnamaddr* info,
-                           NetworkDnsEventReported* event) {
+                           const android_net_context* netcontext, std::optional<int> app_socket,
+                           getnamaddr* info, NetworkDnsEventReported* event) {
     char qbuf[MAXDNAME + 1], *qp, *ep;
     int n;
     int advance;
@@ -696,7 +697,7 @@ static int dns_gethtbyaddr(const unsigned char* uaddr, int len, int af,
 
     auto buf = std::make_unique<querybuf>();
 
-    ResState res(netcontext, event);
+    ResState res(netcontext, app_socket, event);
     int he;
     n = res_nquery(&res, qbuf, C_IN, T_PTR, {buf->buf, (int)sizeof(buf->buf)}, &he);
     if (n < 0) {
diff --git a/gethnamaddr.h b/gethnamaddr.h
index 06546127..b65973b8 100644
--- a/gethnamaddr.h
+++ b/gethnamaddr.h
@@ -29,10 +29,11 @@
 
 // This is the entry point for the gethostbyname() family of legacy calls.
 int resolv_gethostbyname(const char* name, int af, hostent* hp, char* buf, size_t buflen,
-                         const android_net_context* netcontext, hostent** result,
-                         android::net::NetworkDnsEventReported* event);
+                         const android_net_context* netcontext, std::optional<int> app_socket,
+                         hostent** result, android::net::NetworkDnsEventReported* event);
 
 // This is the entry point for the gethostbyaddr() family of legacy calls.
 int resolv_gethostbyaddr(const void* addr, socklen_t len, int af, hostent* hp, char* buf,
-                         size_t buflen, const android_net_context* netcontext, hostent** result,
+                         size_t buflen, const android_net_context* netcontext,
+                         std::optional<int> app_socket, hostent** result,
                          android::net::NetworkDnsEventReported* event);
diff --git a/include/netd_resolv/resolv.h b/include/netd_resolv/resolv.h
index 2535f4e8..36fa9f94 100644
--- a/include/netd_resolv/resolv.h
+++ b/include/netd_resolv/resolv.h
@@ -44,6 +44,13 @@
  */
 #define MARK_UNSET 0u
 
+/*
+ * Passing APP_SOCKET_NONE as the app_socket in getaddrinfo, gethostbyname,
+ * gethostbyaddr, res_nsend means that the query is not tied to a listening socket
+ * in a querying process, and it will not be cancellable based on a socket state.
+ */
+constexpr std::optional<int> APP_SOCKET_NONE = std::nullopt;
+
 #define NET_CONTEXT_INVALID_UID ((uid_t)-1)
 #define NET_CONTEXT_INVALID_PID ((pid_t)-1)
 
diff --git a/libs/statslog_dns_resolver/Android.bp b/libs/statslog_dns_resolver/Android.bp
new file mode 100644
index 00000000..d2c53c9d
--- /dev/null
+++ b/libs/statslog_dns_resolver/Android.bp
@@ -0,0 +1,48 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Autogenerate the class (and respective headers) with logging methods and constants
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+genrule {
+    name: "statslog_dns_resolver.rs",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --module resolv --rustHeaderCrate statslog_rust_header --rust $(genDir)/statslog_dns_resolver.rs",
+    out: [
+        "statslog_dns_resolver.rs",
+    ],
+}
+
+rust_library {
+    name: "libstatslog_dns_resolver_rust",
+    crate_name: "statslog_dns_resolver_rust",
+    srcs: [
+        "statslog_wrapper.rs",
+        ":statslog_dns_resolver.rs",
+    ],
+    rustlibs: [
+        "libstatslog_rust_header",
+        "libstatspull_bindgen",
+    ],
+    flags: [
+        "-A clippy::needless-lifetimes",
+    ],
+    apex_available: [
+        "com.android.resolv",
+    ],
+    min_sdk_version: "29",
+}
diff --git a/libs/statslog_dns_resolver/statslog_wrapper.rs b/libs/statslog_dns_resolver/statslog_wrapper.rs
new file mode 100644
index 00000000..93dc84a3
--- /dev/null
+++ b/libs/statslog_dns_resolver/statslog_wrapper.rs
@@ -0,0 +1,20 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#![allow(clippy::too_many_arguments)]
+#![allow(clippy::undocumented_unsafe_blocks)]
+#![allow(missing_docs)]
+#![allow(unused)]
+
+include!(concat!(env!("OUT_DIR"), "/statslog_dns_resolver.rs"));
diff --git a/res_query.cpp b/res_query.cpp
index be176b6c..c893db0f 100644
--- a/res_query.cpp
+++ b/res_query.cpp
@@ -218,13 +218,10 @@ int res_nsearch(ResState* statp, const char* name, /* domain name */
     for (cp = name; *cp != '\0'; cp++) dots += (*cp == '.');
     const bool trailing_dot = (cp > name && *--cp == '.') ? true : false;
 
-    /*
-     * If there are enough dots in the name, let's just give it a
-     * try 'as is'. The threshold can be set with the "ndots" option.
-     * Also, query 'as is', if there is a trailing dot in the name.
-     */
+    // If there are enough dots in the name, let's just give it a try 'as is'.
+    // Also, query 'as is', if there is a trailing dot in the name.
     saved_herrno = -1;
-    if (dots >= statp->ndots || trailing_dot) {
+    if (dots >= NDOTS || trailing_dot) {
         ret = res_nquerydomain(statp, name, NULL, cl, type, answer, herrno);
         if (ret > 0 || trailing_dot) return ret;
         saved_herrno = *herrno;
diff --git a/res_send.cpp b/res_send.cpp
index 554ace6f..ae688fbb 100644
--- a/res_send.cpp
+++ b/res_send.cpp
@@ -151,6 +151,7 @@ using android::netdutils::Slice;
 using android::netdutils::Stopwatch;
 using std::span;
 
+// Order matters: we put IPv6 first to prioritize that.
 const std::vector<IPSockAddr> mdns_addrs = {IPSockAddr::toIPSockAddr("ff02::fb", 5353),
                                             IPSockAddr::toIPSockAddr("224.0.0.251", 5353)};
 
@@ -160,7 +161,7 @@ static int send_dg(ResState* statp, res_params* params, span<const uint8_t> msg,
 static int send_vc(ResState* statp, res_params* params, span<const uint8_t> msg, span<uint8_t> ans,
                    int* terrno, size_t ns, int* rcode);
 static int send_mdns(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int* terrno,
-                     int* rcode);
+                     int* rcode, IPSockAddr* receivedMdnsAddr);
 static void dump_error(const char*, const struct sockaddr*);
 
 static int sock_eq(struct sockaddr*, struct sockaddr*);
@@ -436,6 +437,19 @@ static bool isNetworkRestricted(int terrno) {
     return (terrno == EPERM);
 }
 
+static bool isClientStreamSocketClosed(std::optional<int> fd) {
+    if (!fd.has_value()) return false;
+    if (!android::net::Experiments::getInstance()->getFlag("no_retry_after_cancel", 0)) {
+        return false;
+    }
+    struct pollfd fds{
+            // POLLHUP is always included in events but is specified explicitly here
+            .fd = fd.value(),
+            .events = POLLHUP,
+    };
+    return (poll(&fds, 1, /* timeout=*/0) > 0) && (fds.revents & POLLHUP);
+}
+
 int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int* rcode,
               uint32_t flags, std::chrono::milliseconds sleepTimeMs) {
     LOG(DEBUG) << __func__;
@@ -448,36 +462,23 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
     }
     res_pquery(msg);
 
-    int anslen = 0;
-    Stopwatch cacheStopwatch;
-    ResolvCacheStatus cache_status = resolv_cache_lookup(statp->netid, msg, ans, &anslen, flags);
-    const int32_t cacheLatencyUs = saturate_cast<int32_t>(cacheStopwatch.timeTakenUs());
-    if (cache_status == RESOLV_CACHE_FOUND) {
-        HEADER* hp = (HEADER*)(void*)ans.data();
-        *rcode = hp->rcode;
-        DnsQueryEvent* dnsQueryEvent = addDnsQueryEvent(statp->event);
-        dnsQueryEvent->set_latency_micros(cacheLatencyUs);
-        dnsQueryEvent->set_cache_hit(static_cast<CacheStatus>(cache_status));
-        dnsQueryEvent->set_type(getQueryType(msg));
-        return anslen;
-    } else if (cache_status != RESOLV_CACHE_UNSUPPORTED) {
-        // had a cache miss for a known network, so populate the thread private
-        // data so the normal resolve path can do its thing
-        resolv_populate_res_for_net(statp);
-    }
-
-    // MDNS
+    // TODO(b/394031336): Implement caching for mDNS.
+    // The DNS cache keys by netid, ignoring the interface queries get routed towards. This is fine
+    // for unicast DNS requests, where:
+    // 1. We always send a single query per type (i.e., even if a network has multiple interfaces,
+    // we will send a single A and AAAA query).
+    // 2. Results cannot be IPv6 link-local addresses
+    // It is not fine for mDNS, where both things can happen.
     if (isMdnsResolution(statp->flags)) {
         // Use an impossible error code as default value.
         int terrno = ETIME;
         int resplen = 0;
         *rcode = RCODE_INTERNAL_ERROR;
         Stopwatch queryStopwatch;
-        resplen = send_mdns(statp, msg, ans, &terrno, rcode);
-        const IPSockAddr& receivedMdnsAddr =
-                (getQueryType(msg) == NS_T_AAAA) ? mdns_addrs[0] : mdns_addrs[1];
+        IPSockAddr receivedMdnsAddr;
+        resplen = send_mdns(statp, msg, ans, &terrno, rcode, &receivedMdnsAddr);
         DnsQueryEvent* mDnsQueryEvent = addDnsQueryEvent(statp->event);
-        mDnsQueryEvent->set_cache_hit(static_cast<CacheStatus>(cache_status));
+        mDnsQueryEvent->set_cache_hit(static_cast<CacheStatus>(RESOLV_CACHE_NOTFOUND));
         mDnsQueryEvent->set_latency_micros(saturate_cast<int32_t>(queryStopwatch.timeTakenUs()));
         mDnsQueryEvent->set_ip_version(ipFamilyToIPVersion(receivedMdnsAddr.family()));
         mDnsQueryEvent->set_rcode(static_cast<NsRcode>(*rcode));
@@ -489,14 +490,28 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
         if (resplen > 0) {
             LOG(DEBUG) << __func__ << ": got answer from mDNS:";
             res_pquery(ans.first(resplen));
-
-            if (cache_status == RESOLV_CACHE_NOTFOUND) {
-                resolv_cache_add(statp->netid, msg, std::span(ans.data(), resplen));
-            }
             return resplen;
         }
     }
 
+    int anslen = 0;
+    Stopwatch cacheStopwatch;
+    ResolvCacheStatus cache_status = resolv_cache_lookup(statp->netid, msg, ans, &anslen, flags);
+    const int32_t cacheLatencyUs = saturate_cast<int32_t>(cacheStopwatch.timeTakenUs());
+    if (cache_status == RESOLV_CACHE_FOUND) {
+        HEADER* hp = (HEADER*)(void*)ans.data();
+        *rcode = hp->rcode;
+        DnsQueryEvent* dnsQueryEvent = addDnsQueryEvent(statp->event);
+        dnsQueryEvent->set_latency_micros(cacheLatencyUs);
+        dnsQueryEvent->set_cache_hit(static_cast<CacheStatus>(cache_status));
+        dnsQueryEvent->set_type(getQueryType(msg));
+        return anslen;
+    } else if (cache_status != RESOLV_CACHE_UNSUPPORTED) {
+        // had a cache miss for a known network, so populate the thread private
+        // data so the normal resolve path can do its thing
+        resolv_populate_res_for_net(statp);
+    }
+
     if (statp->nameserverCount() == 0) {
         // We have no nameservers configured and it's not a MDNS resolution, so there's no
         // point trying. Tell the cache the query failed, or any retries and anyone else
@@ -576,6 +591,15 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
     int terrno = ETIME;
     // plaintext DNS
     for (int attempt = 0; attempt < retryTimes; ++attempt) {
+        if (attempt > 0 && isClientStreamSocketClosed(statp->app_socket)) {
+            // Stop retrying if the remote end is not listening for answers anymore. Only do that
+            // for retries and not the initial query to minimize latency (although the check is very
+            // cheap) in the vast majority of cases where queries are not immediately cancelled, and
+            // to make testing easier so tests can cancel immediately and reliably expect one query.
+            // This could also cancel before the first attempt if private DNS was already tried and
+            // this is a fallback, but this is not done here for simplicity.
+            break;
+        }
         for (size_t ns = 0; ns < statp->nsaddrs.size(); ++ns) {
             if (!usable_servers[ns]) continue;
 
@@ -1209,55 +1233,78 @@ static int send_dg(ResState* statp, res_params* params, span<const uint8_t> msg,
 // return length - when receiving valid packets.
 // return 0      - when mdns packets transfer error.
 static int send_mdns(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int* terrno,
-                     int* rcode) {
-    const sockaddr_storage ss = (getQueryType(msg) == NS_T_AAAA) ? mdns_addrs[0] : mdns_addrs[1];
-    const sockaddr* mdnsap = reinterpret_cast<const sockaddr*>(&ss);
-    unique_fd fd;
+                     int* rcode, IPSockAddr* receivedMdnsAddr) {
+    for (const auto& mdns_addr : mdns_addrs) {
+        const sockaddr_storage ss = mdns_addr;
+        *receivedMdnsAddr = mdns_addr;
+        const sockaddr* mdnsap = reinterpret_cast<const sockaddr*>(&ss);
+        unique_fd fd;
+
+        if (setupUdpSocket(statp, mdnsap, &fd, terrno) <= 0) return 0;
+
+        if (statp->target_interface_index_for_mdns != 0) {
+            if (mdnsap->sa_family == AF_INET) {
+                struct ip_mreqn mreqn = {};
+                mreqn.imr_ifindex = statp->target_interface_index_for_mdns;
+                if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) < 0) {
+                    *terrno = errno;
+                    continue;
+                }
+            } else if (mdnsap->sa_family == AF_INET6) {
+                if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
+                               &statp->target_interface_index_for_mdns,
+                               sizeof(statp->target_interface_index_for_mdns)) < 0) {
+                    *terrno = errno;
+                    continue;
+                }
+            }
+        }
 
-    if (setupUdpSocket(statp, mdnsap, &fd, terrno) <= 0) return 0;
+        if (sendto(fd, msg.data(), msg.size(), 0, mdnsap, sockaddrSize(mdnsap)) !=
+            static_cast<ptrdiff_t>(msg.size())) {
+            *terrno = errno;
+            continue;
+        }
+        // RFC 6762: Typically, the timeout would also be shortened to two or three seconds.
+        const struct timespec finish = evAddTime(evNowTime(), {2, 2000000});
 
-    if (sendto(fd, msg.data(), msg.size(), 0, mdnsap, sockaddrSize(mdnsap)) !=
-        static_cast<ptrdiff_t>(msg.size())) {
-        *terrno = errno;
-        return 0;
-    }
-    // RFC 6762: Typically, the timeout would also be shortened to two or three seconds.
-    const struct timespec finish = evAddTime(evNowTime(), {2, 2000000});
+        // Wait for reply.
+        if (retrying_poll(fd, POLLIN, &finish) <= 0) {
+            *terrno = errno;
+            if (*terrno == ETIMEDOUT) *rcode = RCODE_TIMEOUT;
+            LOG(ERROR) << __func__ << ": " << ((*terrno == ETIMEDOUT) ? "timeout" : "poll failed");
+            continue;
+        }
 
-    // Wait for reply.
-    if (retrying_poll(fd, POLLIN, &finish) <= 0) {
-        *terrno = errno;
-        if (*terrno == ETIMEDOUT) *rcode = RCODE_TIMEOUT;
-        LOG(ERROR) << __func__ << ": " << ((*terrno == ETIMEDOUT) ? "timeout" : "poll failed");
-        return 0;
-    }
+        sockaddr_storage from;
+        socklen_t fromlen = sizeof(from);
+        int resplen = recvfrom(fd, ans.data(), ans.size(), 0, (sockaddr*)(void*)&from, &fromlen);
 
-    sockaddr_storage from;
-    socklen_t fromlen = sizeof(from);
-    int resplen = recvfrom(fd, ans.data(), ans.size(), 0, (sockaddr*)(void*)&from, &fromlen);
+        if (resplen <= 0) {
+            *terrno = errno;
+            continue;
+        }
 
-    if (resplen <= 0) {
-        *terrno = errno;
-        return 0;
-    }
+        if (resplen < HFIXEDSZ) {
+            // Undersized message.
+            LOG(ERROR) << __func__ << ": undersized: " << resplen;
+            *terrno = EMSGSIZE;
+            continue;
+        }
 
-    if (resplen < HFIXEDSZ) {
-        // Undersized message.
-        LOG(ERROR) << __func__ << ": undersized: " << resplen;
-        *terrno = EMSGSIZE;
-        return 0;
-    }
+        HEADER* anhp = (HEADER*)(void*)ans.data();
+        if (anhp->tc) {
+            LOG(DEBUG) << __func__ << ": truncated answer";
+            *terrno = E2BIG;
+            continue;
+        }
 
-    HEADER* anhp = (HEADER*)(void*)ans.data();
-    if (anhp->tc) {
-        LOG(DEBUG) << __func__ << ": truncated answer";
-        *terrno = E2BIG;
-        return 0;
+        *rcode = anhp->rcode;
+        *terrno = 0;
+        return resplen;
     }
 
-    *rcode = anhp->rcode;
-    *terrno = 0;
-    return resplen;
+    return 0;
 }
 
 static void dump_error(const char* str, const struct sockaddr* address) {
@@ -1455,11 +1502,11 @@ int res_tls_send(const std::list<DnsTlsServer>& tlsServers, ResState* statp, con
     }
 }
 
-int resolv_res_nsend(const android_net_context* netContext, span<const uint8_t> msg,
-                     span<uint8_t> ans, int* rcode, uint32_t flags,
+int resolv_res_nsend(const android_net_context* netContext, std::optional<int> app_socket,
+                     span<const uint8_t> msg, span<uint8_t> ans, int* rcode, uint32_t flags,
                      NetworkDnsEventReported* event) {
     assert(event != nullptr);
-    ResState res(netContext, event);
+    ResState res(netContext, app_socket, event);
     resolv_populate_res_for_net(&res);
     *rcode = NOERROR;
     return res_nsend(&res, msg, ans, rcode, flags);
diff --git a/res_send.h b/res_send.h
index f3c0dfdf..c817370f 100644
--- a/res_send.h
+++ b/res_send.h
@@ -22,6 +22,6 @@
 #include "stats.pb.h"
 
 // Query dns with raw msg
-int resolv_res_nsend(const android_net_context* netContext, std::span<const uint8_t> msg,
-                     std::span<uint8_t> ans, int* rcode, uint32_t flags,
-                     android::net::NetworkDnsEventReported* event);
+int resolv_res_nsend(const android_net_context* netContext, std::optional<int> app_socket,
+                     std::span<const uint8_t> msg, std::span<uint8_t> ans, int* rcode,
+                     uint32_t flags, android::net::NetworkDnsEventReported* event);
diff --git a/resolv_private.h b/resolv_private.h
index 3c6461f4..db10959a 100644
--- a/resolv_private.h
+++ b/resolv_private.h
@@ -87,13 +87,19 @@ union sockaddr_union {
     struct sockaddr_in sin;
     struct sockaddr_in6 sin6;
 };
+
 constexpr int MAXPACKET = 8 * 1024;
 
+// Threshold for initial abs. query
+inline constexpr int NDOTS = 1;
+
 struct ResState {
-    ResState(const android_net_context* netcontext, android::net::NetworkDnsEventReported* dnsEvent)
+    ResState(const android_net_context* netcontext, std::optional<int> app_socket,
+             android::net::NetworkDnsEventReported* dnsEvent)
         : netid(netcontext->dns_netid),
           uid(netcontext->uid),
           pid(netcontext->pid),
+          app_socket(app_socket),
           mark(netcontext->dns_mark),
           event(dnsEvent),
           netcontext_flags(netcontext->flags) {}
@@ -105,10 +111,10 @@ struct ResState {
         copy.netid = netid;
         copy.uid = uid;
         copy.pid = pid;
+        copy.app_socket = app_socket;
         copy.search_domains = search_domains;
         copy.nsaddrs = nsaddrs;
         copy.udpsocks_ts = udpsocks_ts;
-        copy.ndots = ndots;
         copy.mark = mark;
         copy.tcp_nssock_ts = tcp_nssock_ts;
         copy.flags = flags;
@@ -117,6 +123,7 @@ struct ResState {
         copy.tc_mode = tc_mode;
         copy.enforce_dns_uid = enforce_dns_uid;
         copy.sort_nameservers = sort_nameservers;
+        copy.target_interface_index_for_mdns = target_interface_index_for_mdns;
         return copy;
     }
     void closeSockets() {
@@ -134,11 +141,11 @@ struct ResState {
     unsigned netid;                             // NetId: cache key and socket mark
     uid_t uid;                                  // uid of the app that sent the DNS lookup
     pid_t pid;                                  // pid of the app that sent the DNS lookup
+    std::optional<int> app_socket;              // Communication socket with the querier process
     std::vector<std::string> search_domains{};  // domains to search
     std::vector<android::netdutils::IPSockAddr> nsaddrs;
     std::array<timespec, MAXNS> udpsocks_ts;    // The creation time of the UDP sockets
     android::base::unique_fd udpsocks[MAXNS];   // UDP sockets to nameservers
-    unsigned ndots : 4 = 1;                     // threshold for initial abs. query
     unsigned mark;                              // Socket mark to be used by all DNS query sockets
     android::base::unique_fd tcp_nssock;        // TCP socket (but why not one per nameserver?)
     timespec tcp_nssock_ts = {};                // The creation time of the TCP socket
@@ -148,6 +155,7 @@ struct ResState {
     int tc_mode = 0;
     bool enforce_dns_uid = false;
     bool sort_nameservers = false;              // True if nsaddrs has been sorted.
+    int target_interface_index_for_mdns;
     // clang-format on
 
   private:
@@ -242,8 +250,7 @@ inline void resolv_tag_socket(int sock, uid_t uid, pid_t pid) {
         }
     }
 
-    // fchown() apps' uid only in R+, since it's incompatible with Q's ebpf vpn isolation feature.
-    if (fchown(sock, (android::net::gApiLevel >= 30) ? uid : AID_DNS, -1) == -1) {
+    if (fchown(sock, uid, -1) == -1) {
         PLOG(WARNING) << "Failed to chown socket";
     }
 }
diff --git a/tests/dns_responder/dns_responder_client_ndk.cpp b/tests/dns_responder/dns_responder_client_ndk.cpp
index b69ce183..5fc888c5 100644
--- a/tests/dns_responder/dns_responder_client_ndk.cpp
+++ b/tests/dns_responder/dns_responder_client_ndk.cpp
@@ -53,6 +53,12 @@ ResolverParams::Builder::Builder() {
     mParcel.caCertificate = kCaCert;
     mParcel.resolverOptions = ResolverOptionsParcel{};  // optional, must be explicitly set.
     mParcel.dohParams = std::nullopt;
+    // This is currently not configurable. Tests relying on DnsResponderClient, are currently
+    // creating a network with no interfaces. They then end up relying on local communication to
+    // receive and send DNS queries. Adding "lo" as an interface for |TEST_NETID| makes that
+    // dependency explicit, allowing mDNS multicast queries to be sent via
+    // IP_MULTICAST_IF/IPV6_MULTICAST_IF.
+    mParcel.interfaceNames = {"lo"};
 }
 
 void DnsResponderClient::SetupMappings(unsigned numHosts, const std::vector<std::string>& domains,
diff --git a/tests/fuzzer/resolv_getaddrinfo_fuzzer.cpp b/tests/fuzzer/resolv_getaddrinfo_fuzzer.cpp
index a80c3358..6b368e86 100644
--- a/tests/fuzzer/resolv_getaddrinfo_fuzzer.cpp
+++ b/tests/fuzzer/resolv_getaddrinfo_fuzzer.cpp
@@ -20,7 +20,8 @@ void TestResolvGetaddrinfo(FuzzedDataProvider& fdp) {
     NetworkDnsEventReported event;
 
     resolv_getaddrinfo(hostname.c_str(), fdp.ConsumeBool() ? servname.c_str() : nullptr,
-                       fdp.ConsumeBool() ? &hints : nullptr, &mNetContext, &result, &event);
+                       fdp.ConsumeBool() ? &hints : nullptr, &mNetContext, APP_SOCKET_NONE, &result,
+                       &event);
     netdutils::ScopedAddrinfo result_cleanup(result);
 }
 
diff --git a/tests/fuzzer/resolv_gethostbyaddr_fuzzer.cpp b/tests/fuzzer/resolv_gethostbyaddr_fuzzer.cpp
index 63ad46bc..159cda73 100644
--- a/tests/fuzzer/resolv_gethostbyaddr_fuzzer.cpp
+++ b/tests/fuzzer/resolv_gethostbyaddr_fuzzer.cpp
@@ -17,8 +17,8 @@ void TestResolvGethostbyaddr(FuzzedDataProvider& fdp) {
     hostent* hp;
     NetworkDnsEventReported event;
 
-    resolv_gethostbyaddr(&v6addr, mAddressLen, af, &hbuf, tmpbuf, sizeof(tmpbuf), &mNetContext, &hp,
-                         &event);
+    resolv_gethostbyaddr(&v6addr, mAddressLen, af, &hbuf, tmpbuf, sizeof(tmpbuf), &mNetContext,
+                         APP_SOCKET_NONE, &hp, &event);
 }
 
 }  // namespace
diff --git a/tests/fuzzer/resolv_gethostbyname_fuzzer.cpp b/tests/fuzzer/resolv_gethostbyname_fuzzer.cpp
index d05eba5c..b6dc946c 100644
--- a/tests/fuzzer/resolv_gethostbyname_fuzzer.cpp
+++ b/tests/fuzzer/resolv_gethostbyname_fuzzer.cpp
@@ -19,7 +19,7 @@ void TestResolvGethostbyname(FuzzedDataProvider& fdp) {
     NetworkDnsEventReported event;
 
     resolv_gethostbyname(fdp.ConsumeBool() ? hostname.c_str() : nullptr, af, &hbuf, tmpbuf,
-                         sizeof(tmpbuf), &mNetContext, &hp, &event);
+                         sizeof(tmpbuf), &mNetContext, APP_SOCKET_NONE, &hp, &event);
 }
 
 }  // namespace
diff --git a/tests/resolv_callback_unit_test.cpp b/tests/resolv_callback_unit_test.cpp
index 391951b9..3e245373 100644
--- a/tests/resolv_callback_unit_test.cpp
+++ b/tests/resolv_callback_unit_test.cpp
@@ -156,32 +156,21 @@ TEST_F(CallbackTest, tagSocketCallback) {
     const addrinfo hints = {.ai_family = AF_INET};
     NetworkDnsEventReported event;
     // tagSocketCallback will be called.
-    const int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, &result, &event);
+    const int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                      &result, &event);
     ScopedAddrinfo result_cleanup(result);
     EXPECT_EQ(testUid, TEST_UID);
     EXPECT_EQ(rv, 0);
 }
 
 TEST_F(CallbackTest, tagSocketFchown) {
-    const uint64_t tmpApiLevel = gApiLevel;
-
     // Expect the given socket will be fchown() with given uid.
-    gApiLevel = 30;  // R
     unique_fd sk(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
     EXPECT_GE(sk, 3);
     resolv_tag_socket(sk, TEST_UID, -1);
     struct stat sb;
     EXPECT_EQ(fstat(sk, &sb), 0);
     EXPECT_EQ(sb.st_uid, TEST_UID);
-
-    // Expect the given socket will be fchown() with AID_DNS.
-    gApiLevel = 29;  // Q
-    resolv_tag_socket(sk, TEST_UID, -1);
-    EXPECT_EQ(fstat(sk, &sb), 0);
-    EXPECT_EQ(sb.st_uid, static_cast<uid_t>(AID_DNS));
-
-    // restore API level.
-    gApiLevel = tmpApiLevel;
 }
 
 }  // end of namespace android::net
diff --git a/tests/resolv_gold_test.cpp b/tests/resolv_gold_test.cpp
index bafbd51b..8a44153c 100644
--- a/tests/resolv_gold_test.cpp
+++ b/tests/resolv_gold_test.cpp
@@ -198,8 +198,8 @@ class TestBase : public NetNativeTestBase {
         addrinfo* res = nullptr;
         const android_net_context netcontext = GetNetContext(protocol);
         NetworkDnsEventReported event;
-        const int rv =
-                resolv_getaddrinfo(args.host().c_str(), nullptr, &hints, &netcontext, &res, &event);
+        const int rv = resolv_getaddrinfo(args.host().c_str(), nullptr, &hints, &netcontext,
+                                          APP_SOCKET_NONE, &res, &event);
         ScopedAddrinfo result(res);
         ASSERT_EQ(rv, goldtest.result().return_code());
         VerifyAddress(goldtest, result);
@@ -213,8 +213,9 @@ class TestBase : public NetNativeTestBase {
         char tmpbuf[MAXPACKET];
         const android_net_context netcontext = GetNetContext(protocol);
         NetworkDnsEventReported event;
-        const int rv = resolv_gethostbyname(args.host().c_str(), args.family(), &hbuf, tmpbuf,
-                                            sizeof(tmpbuf), &netcontext, &hp, &event);
+        const int rv =
+                resolv_gethostbyname(args.host().c_str(), args.family(), &hbuf, tmpbuf,
+                                     sizeof(tmpbuf), &netcontext, APP_SOCKET_NONE, &hp, &event);
         ASSERT_EQ(rv, goldtest.result().return_code());
         VerifyAddress(goldtest, hp);
     }
@@ -291,7 +292,8 @@ TEST_F(ResolvGetAddrInfo, RemovePacketMapping) {
     addrinfo* res = nullptr;
     const addrinfo hints = {.ai_family = AF_INET};
     NetworkDnsEventReported event;
-    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
+    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, APP_SOCKET_NONE,
+                                &res, &event);
     ScopedAddrinfo result(res);
     ASSERT_NE(result, nullptr);
     ASSERT_EQ(rv, 0);
@@ -301,7 +303,8 @@ TEST_F(ResolvGetAddrInfo, RemovePacketMapping) {
     dns.removeMappingBinaryPacket(kHelloExampleComQueryV4);
 
     // Expect to have no answer in DNS query result.
-    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
+    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, APP_SOCKET_NONE, &res,
+                            &event);
     result.reset(res);
     ASSERT_EQ(result, nullptr);
     ASSERT_EQ(rv, EAI_NODATA);
@@ -319,7 +322,8 @@ TEST_F(ResolvGetAddrInfo, ReplacePacketMapping) {
     addrinfo* res = nullptr;
     const addrinfo hints = {.ai_family = AF_INET};
     NetworkDnsEventReported event;
-    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
+    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, APP_SOCKET_NONE,
+                                &res, &event);
     ScopedAddrinfo result(res);
     ASSERT_NE(result, nullptr);
     ASSERT_EQ(rv, 0);
@@ -351,7 +355,8 @@ TEST_F(ResolvGetAddrInfo, ReplacePacketMapping) {
     dns.addMappingBinaryPacket(kHelloExampleComQueryV4, newHelloExampleComResponseV4);
 
     // Expect that DNS query returns new IPv4 address 5.6.7.8.
-    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
+    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, APP_SOCKET_NONE, &res,
+                            &event);
     result.reset(res);
     ASSERT_NE(result, nullptr);
     ASSERT_EQ(rv, 0);
@@ -378,8 +383,8 @@ TEST_F(ResolvGetAddrInfo, BasicTlsQuery) {
     // the second query of different socket type are responded by the cache.
     const addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
     NetworkDnsEventReported event;
-    const int rv =
-            resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontextTls, &res, &event);
+    const int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontextTls,
+                                      APP_SOCKET_NONE, &res, &event);
     ScopedAddrinfo result(res);
     ASSERT_EQ(rv, 0);
     EXPECT_EQ(GetNumQueries(dns, kHelloExampleCom), 2U);
diff --git a/tests/resolv_integration_test.cpp b/tests/resolv_integration_test.cpp
index 84ce160e..6854a0c0 100644
--- a/tests/resolv_integration_test.cpp
+++ b/tests/resolv_integration_test.cpp
@@ -76,6 +76,9 @@
 #include "tests/tun_forwarder.h"
 #include "tests/unsolicited_listener/unsolicited_event_listener.h"
 
+using ::testing::IsNull;
+using ::testing::NotNull;
+
 // This mainline module test still needs to be able to run on pre-S devices,
 // and thus may run across pre-4.9 non-eBPF capable devices like the Pixel 2.
 #define SKIP_IF_BPF_NOT_SUPPORTED                           \
@@ -406,6 +409,8 @@ class ResolverTest : public NetNativeTestBase {
         return fmt::format("127.0.100.{}", (++counter & 0xff));
     }
 
+    void runCancelledQueryTest(bool expectCancelled);
+
     DnsResponderClient mDnsClient;
 
     bool mIsResolverOptionIPCSupported = false;
@@ -3023,6 +3028,51 @@ TEST_F(ResolverTest, Async_VerifyQueryID) {
     EXPECT_EQ(1U, GetNumQueries(dns, host_name));
 }
 
+void ResolverTest::runCancelledQueryTest(bool expectCancelled) {
+    resetNetwork();
+    constexpr char listen_addr[] = "127.0.0.4";
+    constexpr char host_name_1[] = "howdy1.example.com.";
+    constexpr char host_name_2[] = "howdy2.example.com.";
+    const std::vector<DnsRecord> records = {
+            {host_name_1, ns_type::ns_t_aaaa, "::1.2.3.4"},
+            {host_name_2, ns_type::ns_t_aaaa, "::1.2.3.4"},
+    };
+
+    test::DNSResponder dns(listen_addr);
+    StartDns(dns, records);
+    dns.setResponseProbability(0.0);
+    std::vector<std::string> servers = {listen_addr};
+    ASSERT_TRUE(mDnsClient.SetResolversForNetwork(servers));
+
+    int fd1 = resNetworkQuery(TEST_NETID, host_name_1, ns_c_in, ns_t_aaaa, 0);
+    int fd2 = resNetworkQuery(TEST_NETID, host_name_2, ns_c_in, ns_t_aaaa, 0);
+
+    // Immediately cancel the first query
+    resNetworkCancel(fd1);
+
+    expectAnswersNotValid(fd2, -ETIMEDOUT);
+
+    if (expectCancelled) {
+        // Expect multiple retries on the second query, but only one attempt on the first one
+        EXPECT_GT(GetNumQueries(dns, host_name_2), 1U);
+        EXPECT_EQ(1U, GetNumQueries(dns, host_name_1));
+    } else {
+        // The queries are not actually cancelled and multiple are sent. Poll as in some cases the
+        // timeout for query 2 will come before queries are done for query 1.
+        EXPECT_TRUE(PollForCondition([&]() { return GetNumQueries(dns, host_name_1) > 1U; }));
+    }
+}
+
+TEST_F(ResolverTest, Async_CancelledQuery) {
+    ScopedSystemProperties sp(kNoRetryAfterCancelFlag, "1");
+    ASSERT_NO_FATAL_FAILURE(runCancelledQueryTest(/*expectCancelled=*/true));
+}
+
+TEST_F(ResolverTest, Async_CancelledQueryWithFlagDisabled) {
+    ScopedSystemProperties sp(kNoRetryAfterCancelFlag, "0");
+    ASSERT_NO_FATAL_FAILURE(runCancelledQueryTest(/*expectCancelled=*/false));
+}
+
 // This test checks that the resolver should not generate the request containing OPT RR when using
 // cleartext DNS. If we query the DNS server not supporting EDNS0 and it reponds with
 // FORMERR_ON_EDNS, we will fallback to no EDNS0 and try again. If the server does no response, we
@@ -6407,7 +6457,9 @@ TEST_F(ResolverTest, MdnsGetHostByName) {
 
     test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv4.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
+    mdnsv6.addMapping(host_name, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
 
     ASSERT_TRUE(mdnsv4.startServer());
@@ -6439,27 +6491,33 @@ TEST_F(ResolverTest, MdnsGetHostByName) {
 
             // No response for "nonexistent.local".
             result = gethostbyname2("nonexistent.local", config.ai_family);
-            ASSERT_TRUE(result == nullptr);
-            test::DNSResponder& mdns = config.ai_family == AF_INET ? mdnsv4 : mdnsv6;
-            EXPECT_EQ(1U, GetNumQueries(mdns, nonexistent_host_name));
-            mdns.clearQueries();
+            ASSERT_THAT(result, IsNull());
+            EXPECT_EQ(1U, GetNumQueries(mdnsv6, nonexistent_host_name));
+            EXPECT_EQ(0U, GetNumQueries(mdnsv4, nonexistent_host_name));
+            mdnsv6.clearQueries();
+            mdnsv4.clearQueries();
             EXPECT_EQ(HOST_NOT_FOUND, h_errno);
 
             // Normal mDns query
             result = gethostbyname2("hello.local", config.ai_family);
-            ASSERT_FALSE(result == nullptr);
-            EXPECT_EQ(1U, GetNumQueries(mdns, host_name));
+            ASSERT_THAT(result, NotNull());
+            EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
             int length = config.ai_family == AF_INET ? 4 : 16;
             ASSERT_EQ(length, result->h_length);
-            ASSERT_FALSE(result->h_addr_list[0] == nullptr);
+            ASSERT_THAT(result->h_addr_list[0], NotNull());
             EXPECT_EQ(config.expected_addr, ToString(result));
-            EXPECT_TRUE(result->h_addr_list[1] == nullptr);
-            mdns.clearQueries();
+            EXPECT_THAT(result->h_addr_list[1], IsNull());
+            mdnsv6.clearQueries();
+            mdnsv4.clearQueries();
 
             // Ensure the query result is still cached.
+            // TODO(b/394031336): caching is currently disabled while we work on a cache that
+            // supports keying by interface. Update values once re-enabled.
             result = gethostbyname2("hello.local", config.ai_family);
-            EXPECT_EQ(0U, GetNumQueries(mdnsv4, "hello.local."));
-            ASSERT_FALSE(result == nullptr);
+            EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+            EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+            ASSERT_THAT(result, NotNull());
             EXPECT_EQ(config.expected_addr, ToString(result));
             ASSERT_TRUE(mDnsClient.resolvService()->flushNetworkCache(TEST_NETID).isOk());
         }
@@ -6506,6 +6564,8 @@ TEST_F(ResolverTest, MdnsGetHostByName_transportTypes) {
     test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
     mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv4.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
+    mdnsv6.addMapping(host_name, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
     ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
@@ -6540,10 +6600,12 @@ TEST_F(ResolverTest, MdnsGetHostByName_transportTypes) {
             result = gethostbyname2("hello.local", config.ai_family);
             ASSERT_FALSE(result == nullptr);
             if (tpConfig.useMdns) {
-                EXPECT_EQ(1U, GetNumQueries(mdns, host_name));
+                EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
                 EXPECT_EQ(0U, GetNumQueries(dns, host_name));
             } else {
-                EXPECT_EQ(0U, GetNumQueries(mdns, host_name));
+                EXPECT_EQ(0U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
                 EXPECT_EQ(1U, GetNumQueries(dns, host_name));
             }
             int length = config.ai_family == AF_INET ? 4 : 16;
@@ -6552,14 +6614,15 @@ TEST_F(ResolverTest, MdnsGetHostByName_transportTypes) {
             EXPECT_EQ(config.expected_addr, ToString(result));
             EXPECT_TRUE(result->h_addr_list[1] == nullptr);
 
-            mdns.clearQueries();
+            mdnsv4.clearQueries();
+            mdnsv6.clearQueries();
             dns.clearQueries();
             ASSERT_TRUE(mDnsClient.resolvService()->flushNetworkCache(TEST_NETID).isOk());
         }
     }
 }
 
-TEST_F(ResolverTest, MdnsGetHostByName_cnames) {
+TEST_F(ResolverTest, MdnsGetHostByName_cnames_IPv6ResponderIsPrioritized) {
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char v4addr[] = "127.0.0.3";
     constexpr char host_name[] = "hello.local.";
@@ -6612,14 +6675,74 @@ TEST_F(ResolverTest, MdnsGetHostByName_cnames) {
         }
         // The size of "Non-cname type" record in DNS records is 2
         ASSERT_EQ(cnamecount, records.size() - 2);
-        test::DNSResponder& mdns = config.ai_family == AF_INET ? mdnsv4 : mdnsv6;
-        EXPECT_EQ(1U, mdnsv4.queries().size()) << mdns.dumpQueries();
+        EXPECT_EQ(1U, mdnsv6.queries().size()) << mdnsv6.dumpQueries();
+        EXPECT_EQ(0U, mdnsv4.queries().size()) << mdnsv4.dumpQueries();
         int length = config.ai_family == AF_INET ? 4 : 16;
         ASSERT_EQ(length, result->h_length);
 
         ASSERT_FALSE(result->h_addr_list[0] == nullptr);
         EXPECT_EQ(config.expected_addr, ToString(result));
         EXPECT_TRUE(result->h_addr_list[1] == nullptr);
+        mdnsv4.clearQueries();
+        mdnsv6.clearQueries();
+    }
+}
+
+TEST_F(ResolverTest, MdnsGetHostByName_cnames_FallbacksToIPv4Responder) {
+    constexpr char v6addr[] = "::127.0.0.3";
+    constexpr char v4addr[] = "127.0.0.3";
+    constexpr char host_name[] = "hello.local.";
+    const std::vector<DnsRecord> records = {
+            {"hi.local.", ns_type::ns_t_cname, "a.local."},
+            {"a.local.", ns_type::ns_t_cname, "b.local."},
+            {"b.local.", ns_type::ns_t_cname, "c.local."},
+            {"c.local.", ns_type::ns_t_cname, "d.local."},
+            {"d.local.", ns_type::ns_t_cname, "e.local."},
+            {"e.local.", ns_type::ns_t_cname, host_name},
+            {host_name, ns_type::ns_t_a, v4addr},
+            {host_name, ns_type::ns_t_aaaa, v6addr},
+    };
+    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
+    for (const auto& r : records) {
+        mdnsv4.addMapping(r.host_name, r.type, r.addr);
+    }
+    ASSERT_TRUE(mdnsv4.startServer());
+    ASSERT_TRUE(mDnsClient.SetResolversForNetwork());
+    mdnsv4.clearQueries();
+
+    static const struct TestConfig {
+        int ai_family;
+        const std::string expected_addr;
+    } testConfigs[]{
+            {AF_INET, v4addr},
+            {AF_INET6, v6addr},
+    };
+
+    for (const auto& config : testConfigs) {
+        size_t cnamecount = 0;
+        // using gethostbyname2() to resolve ipv4 hello.local. to 127.0.0.3
+        // or ipv6 hello.local. to ::127.0.0.3.
+        // Ensure the v4 address and cnames are correct
+        const hostent* result;
+        result = gethostbyname2("hi.local", config.ai_family);
+        ASSERT_FALSE(result == nullptr);
+
+        for (int i = 0; result != nullptr && result->h_aliases[i] != nullptr; i++) {
+            std::string domain_name =
+                    records[i].host_name.substr(0, records[i].host_name.size() - 1);
+            EXPECT_EQ(result->h_aliases[i], domain_name);
+            cnamecount++;
+        }
+        // The size of "Non-cname type" record in DNS records is 2
+        ASSERT_EQ(cnamecount, records.size() - 2);
+        EXPECT_EQ(1U, mdnsv4.queries().size()) << mdnsv4.dumpQueries();
+        int length = config.ai_family == AF_INET ? 4 : 16;
+        ASSERT_EQ(length, result->h_length);
+
+        ASSERT_FALSE(result->h_addr_list[0] == nullptr);
+        EXPECT_EQ(config.expected_addr, ToString(result));
+        EXPECT_TRUE(result->h_addr_list[1] == nullptr);
+        mdnsv4.clearQueries();
     }
 }
 
@@ -6653,13 +6776,15 @@ TEST_F(ResolverTest, MdnsGetHostByName_cnamesInfiniteLoop) {
     ASSERT_TRUE(result == nullptr);
 }
 
-TEST_F(ResolverTest, MdnsGetAddrInfo) {
+TEST_F(ResolverTest, MdnsGetAddrInfo_IPv6ResponderIsPrioritized) {
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char v4addr[] = "127.0.0.3";
     constexpr char host_name[] = "hello.local.";
     test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
     mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv4.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
+    mdnsv6.addMapping(host_name, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
     ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
@@ -6691,31 +6816,117 @@ TEST_F(ResolverTest, MdnsGetAddrInfo) {
 
             EXPECT_TRUE(result != nullptr);
             if (config.ai_family == AF_INET) {
-                EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-                mdnsv4.clearQueries();
+                EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
             } else if (config.ai_family == AF_INET6) {
+                EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
                 EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
-                mdnsv6.clearQueries();
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
             } else if (config.ai_family == AF_UNSPEC) {
-                EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-                EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
-                mdnsv4.clearQueries();
-                mdnsv6.clearQueries();
+                EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
             }
+            mdnsv4.clearQueries();
+            mdnsv6.clearQueries();
             std::string result_str = ToString(result);
             EXPECT_THAT(ToStrings(result),
                         testing::UnorderedElementsAreArray(config.expected_addr));
 
             // Ensure the query results are still cached.
+            // TODO(b/394031336): caching is currently disabled while we work on a cache that
+            // supports keying by interface. Update values once re-enabled.
             result = safe_getaddrinfo("hello.local", nullptr, &hints);
             EXPECT_TRUE(result != nullptr);
-            if (config.ai_family == AF_INET)
+            if (config.ai_family == AF_INET) {
                 EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
-            else if (config.ai_family == AF_INET6)
-                EXPECT_EQ(0U, GetNumQueries(mdnsv6, host_name));
-            else if (config.ai_family == AF_UNSPEC) {
+                EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
+            } else if (config.ai_family == AF_INET6) {
                 EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
-                EXPECT_EQ(0U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
+            } else if (config.ai_family == AF_UNSPEC) {
+                EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
+                EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
+            }
+            result_str = ToString(result);
+            EXPECT_THAT(ToStrings(result),
+                        testing::UnorderedElementsAreArray(config.expected_addr));
+            ASSERT_TRUE(mDnsClient.resolvService()->flushNetworkCache(TEST_NETID).isOk());
+        }
+    }
+}
+
+TEST_F(ResolverTest, MdnsGetAddrInfo_FallbacksToIPv4Responder) {
+    constexpr char v6addr[] = "::127.0.0.3";
+    constexpr char v4addr[] = "127.0.0.3";
+    constexpr char host_name[] = "hello.local.";
+    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
+    mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv4.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
+    ASSERT_TRUE(mdnsv4.startServer());
+
+    std::vector<bool> keep_listening_udp_enable = {false, true};
+    for (int value : keep_listening_udp_enable) {
+        if (value == true) {
+            // Set keep_listening_udp enable
+            ScopedSystemProperties sp(kKeepListeningUdpFlag, "1");
+            // Re-setup test network to make experiment flag take effect.
+            resetNetwork();
+        }
+
+        ASSERT_TRUE(mDnsClient.SetResolversForNetwork());
+        static const struct TestConfig {
+            int ai_family;
+            const std::vector<std::string> expected_addr;
+        } testConfigs[]{
+                {AF_INET, {v4addr}},
+                {AF_INET6, {v6addr}},
+                {AF_UNSPEC, {v4addr, v6addr}},
+        };
+
+        for (const auto& config : testConfigs) {
+            mdnsv4.clearQueries();
+            addrinfo hints = {.ai_family = config.ai_family, .ai_socktype = SOCK_DGRAM};
+            ScopedAddrinfo result = safe_getaddrinfo("hello.local", nullptr, &hints);
+
+            EXPECT_TRUE(result != nullptr);
+            if (config.ai_family == AF_INET) {
+                EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_a, host_name), 1U);
+            } else if (config.ai_family == AF_INET6) {
+                EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_aaaa, host_name), 1U);
+            } else if (config.ai_family == AF_UNSPEC) {
+                EXPECT_EQ(2U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_a, host_name), 1U);
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_aaaa, host_name), 1U);
+            }
+            mdnsv4.clearQueries();
+            std::string result_str = ToString(result);
+            EXPECT_THAT(ToStrings(result),
+                        testing::UnorderedElementsAreArray(config.expected_addr));
+
+            // Ensure the query results are still cached.
+            // TODO(b/394031336): caching is currently disabled while we work on a cache that
+            // supports keying by interface. Update values once re-enabled.
+            result = safe_getaddrinfo("hello.local", nullptr, &hints);
+            EXPECT_TRUE(result != nullptr);
+            if (config.ai_family == AF_INET) {
+                EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_a, host_name), 1U);
+            } else if (config.ai_family == AF_INET6) {
+                EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_aaaa, host_name), 1U);
+            } else if (config.ai_family == AF_UNSPEC) {
+                EXPECT_EQ(2U, GetNumQueries(mdnsv4, host_name));
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_a, host_name), 1U);
+                EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_aaaa, host_name), 1U);
             }
             result_str = ToString(result);
             EXPECT_THAT(ToStrings(result),
@@ -6731,7 +6942,7 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_transportTypes) {
     constexpr char host_name[] = "hello.local.";
     test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
-    mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv6.addMapping(host_name, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
     ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
@@ -6765,24 +6976,34 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_transportTypes) {
 
             EXPECT_TRUE(result != nullptr);
             if (tpConfig.useMdns) {
+                EXPECT_EQ(0U, GetNumQueries(dns, host_name));
                 if (config.ai_family == AF_INET) {
-                    EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-                    EXPECT_EQ(0U, GetNumQueries(mdnsv6, host_name));
+                    EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+                    EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
                 } else if (config.ai_family == AF_INET6) {
                     EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
                     EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
                 } else {
-                    EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-                    EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+                    EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+                    EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
+                    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
+                    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
                 }
-                EXPECT_EQ(0U, GetNumQueries(dns, host_name));
             } else {
                 EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
                 EXPECT_EQ(0U, GetNumQueries(mdnsv6, host_name));
-                if (config.ai_family == AF_INET || config.ai_family == AF_INET6) {
+                if (config.ai_family == AF_INET) {
                     EXPECT_EQ(1U, GetNumQueries(dns, host_name));
+                    EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_a, host_name), 1U);
+                } else if (config.ai_family == AF_INET6) {
+                    EXPECT_EQ(1U, GetNumQueries(dns, host_name));
+                    EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_aaaa, host_name), 1U);
                 } else {
                     EXPECT_EQ(2U, GetNumQueries(dns, host_name));
+                    EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_a, host_name), 1U);
+                    EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_aaaa, host_name), 1U);
                 }
             }
             std::string result_str = ToString(result);
@@ -6823,7 +7044,6 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnames) {
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char v4addr[] = "127.0.0.3";
     constexpr char host_name[] = "hello.local.";
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
     const std::vector<DnsRecord> records = {
             {"hi.local.", ns_type::ns_t_cname, "a.local."},
@@ -6835,13 +7055,9 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnames) {
             {host_name, ns_type::ns_t_a, v4addr},
             {host_name, ns_type::ns_t_aaaa, v6addr},
     };
-    for (const auto& r : records) {
-        mdnsv4.addMapping(r.host_name, r.type, r.addr);
-    }
     for (const auto& r : records) {
         mdnsv6.addMapping(r.host_name, r.type, r.addr);
     }
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_TRUE(mDnsClient.SetResolversForNetwork());
 
@@ -6854,7 +7070,6 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnames) {
             {AF_UNSPEC, {v4addr, v6addr}},
     };
     for (const auto& config : testConfigs) {
-        mdnsv4.clearQueries();
         mdnsv6.clearQueries();
         addrinfo hints = {.ai_family = config.ai_family, .ai_socktype = SOCK_DGRAM};
         ScopedAddrinfo result = safe_getaddrinfo("hi.local", nullptr, &hints);
@@ -6865,19 +7080,17 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnames) {
 
 TEST_F(ResolverTest, MdnsGetAddrInfo_cnamesNoIpAddress) {
     constexpr char host_name[] = "hello.local.";
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
-    mdnsv4.addMapping(host_name, ns_type::ns_t_cname, "a.local.");
     mdnsv6.addMapping(host_name, ns_type::ns_t_cname, "a.local.");
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_TRUE(mDnsClient.SetResolversForNetwork());
 
+    mdnsv6.clearQueries();
     addrinfo hints = {.ai_family = AF_INET};
     ScopedAddrinfo result = safe_getaddrinfo("hello.local", nullptr, &hints);
     EXPECT_TRUE(result == nullptr);
 
-    mdnsv4.clearQueries();
+    mdnsv6.clearQueries();
     hints = {.ai_family = AF_INET6};
     result = safe_getaddrinfo("hello.local", nullptr, &hints);
     EXPECT_TRUE(result == nullptr);
@@ -6890,11 +7103,8 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnamesNoIpAddress) {
 
 TEST_F(ResolverTest, MdnsGetAddrInfo_cnamesIllegalRdata) {
     constexpr char host_name[] = "hello.local.";
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
-    mdnsv4.addMapping(host_name, ns_type::ns_t_cname, ".!#?");
     mdnsv6.addMapping(host_name, ns_type::ns_t_cname, ".!#?");
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_TRUE(mDnsClient.SetResolversForNetwork());
 
@@ -6902,7 +7112,7 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnamesIllegalRdata) {
     ScopedAddrinfo result = safe_getaddrinfo("hello.local", nullptr, &hints);
     EXPECT_TRUE(result == nullptr);
 
-    mdnsv4.clearQueries();
+    mdnsv6.clearQueries();
     hints = {.ai_family = AF_INET6};
     result = safe_getaddrinfo("hello.local", nullptr, &hints);
     EXPECT_TRUE(result == nullptr);
@@ -6913,8 +7123,7 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_cnamesIllegalRdata) {
     EXPECT_TRUE(result == nullptr);
 }
 
-// Test if .local resolution will try unicast when multicast is failed.
-TEST_F(ResolverTest, MdnsGetAddrInfo_fallback) {
+TEST_F(ResolverTest, MdnsGetAddrInfo_FallbacksToUnicastDNS) {
     constexpr char v6addr[] = "::1.2.3.4";
     constexpr char v4addr[] = "1.2.3.4";
     constexpr char host_name[] = "hello.local.";
@@ -6951,16 +7160,28 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_fallback) {
         EXPECT_TRUE(result != nullptr);
         if (config.ai_family == AF_INET) {
             EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-            EXPECT_EQ(0U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_a, host_name), 1U);
+            EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
             EXPECT_EQ(1U, GetNumQueries(dns, host_name));
+            EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_a, host_name), 1U);
         } else if (config.ai_family == AF_INET6) {
-            EXPECT_EQ(0U, GetNumQueries(mdnsv4, host_name));
+            EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
+            EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_aaaa, host_name), 1U);
             EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
             EXPECT_EQ(1U, GetNumQueries(dns, host_name));
+            EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_aaaa, host_name), 1U);
         } else {
-            EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-            EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(2U, GetNumQueries(mdnsv4, host_name));
+            EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_a, host_name), 1U);
+            EXPECT_EQ(GetNumQueriesForType(mdnsv4, ns_type::ns_t_aaaa, host_name), 1U);
+            EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 1U);
+            EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
             EXPECT_EQ(2U, GetNumQueries(dns, host_name));
+            EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_a, host_name), 1U);
+            EXPECT_EQ(GetNumQueriesForType(dns, ns_type::ns_t_aaaa, host_name), 1U);
         }
         EXPECT_THAT(ToStrings(result), testing::UnorderedElementsAreArray(config.expected_addr));
 
@@ -6997,7 +7218,7 @@ TEST_F(ResolverTest, MdnsGetAddrInfo_fallback) {
 
 class ResolverMultinetworkTest : public ResolverTest {
   protected:
-    enum class ConnectivityType { V4, V6, V4V6 };
+    enum class ConnectivityType { V4, V6, V4V6, NONE };
     static constexpr int TEST_NETID_BASE = 10000;
 
     struct DnsServerPair {
@@ -7312,6 +7533,74 @@ Result<std::shared_ptr<test::DNSResponder>> ResolverMultinetworkTest::setupDns(
     return dnsSvPair->dnsServer;
 }
 
+/* Setup a DnsResponder that can be queried (and will reply) via the TUN interface associated to the
+ * network. Returns the IP address that should be used when sending DNS queries, so that they will
+ * go through the TUN interface.
+ *
+ * This is done in the following way for the request:
+ *
+ * +--------------+
+ * |              |
+ * | DnsResponder |----> Listens on |real_responder_address|
+ * |              |      ^
+ * +--------------+      |
+ *                    +--+
+ *                    |
+ *                 +-----+
+ *                 |     |<----------------------------------------------------+
+ *                 |     |                                                     |
+ *                 |     |--> Swaps source address for |fake_resolver_address|-+
+ *                 | TUN |     this is necessary to make sure the response will
+ *                 |     |     also go through TUN (and not directly to
+ *                 |     |     DnsResolver)
+ *                 |     |    Swaps dest address for |real_responder_address|
+ *                 |     |     this is necessary for the query to reach
+ *                 |     |     DnsResponder once injected back into the kernel
+ *                 +-----+
+ *                    ^
+ *                    |
+ * +-------------+    +--+
+ * |             |       |
+ * |             |----> Sends queries
+ * | DnsResolver |        from |real_resolver_address|
+ * |             |        to   |fake_responder_address|
+ * |             |
+ * +-------------+
+ *
+ * While, for the response:
+ *
+ * +--------------+
+ * |              |
+ * |              |----> Sends reply
+ * | DnsResponder |        from |real_responder_address|
+ * |              |        to |fake_resolver_address|
+ * |              |        |
+ * +--------------+        |
+ *                    +----+
+ *                    |
+ *                    v
+ *                 +-----+
+ *                 |     |--> Swaps source address for |fake_responder_address|
+ *                 |     |     this is necessary to make sure the response will
+ *                 |     |     go to the socket where DnsResolver is waiting for
+ *                 |     |     the response
+ *                 | TUN |    Swaps dest address for |real_resolver_address|
+ *                 |     |     this is necessary to make sure the response will
+ *                 |     |     go to the socket where DnsResolver is waiting for
+ *                 |     |     the response
+ *                 |     |     |
+ *                 |     |<----+
+ *                 +-----+
+ *                    ^
+ *                    |
+ * +-------------+    +--+
+ * |             |       |
+ * |             |----> Sends query
+ * | DnsResolver |        from |real_resolver_address|
+ * |             |        to   |fake_responder_address|
+ * |             |
+ * +-------------+
+ */
 Result<ResolverMultinetworkTest::DnsServerPair> ResolverMultinetworkTest::ScopedNetwork::addDns(
         ConnectivityType type) {
     const int index = mDnsServerPairs.size();
@@ -7322,24 +7611,34 @@ Result<ResolverMultinetworkTest::DnsServerPair> ResolverMultinetworkTest::Scoped
                                                      : &ScopedNetwork::makeIpv6AddrString,
                       this, std::placeholders::_1);
 
-    std::string src1 = makeIpString(1);            // The address from which the resolver will send.
-    std::string dst1 = makeIpString(
-            index + 100 +
-            (mNetId - TEST_NETID_BASE));           // The address to which the resolver will send.
-    std::string src2 = dst1;                       // The address translated from src1.
-    std::string dst2 = makeIpString(
-            index + 200 + (mNetId - TEST_NETID_BASE));  // The address translated from dst2.
+    std::string real_resolver_address = makeIpString(1);
+    // |fake_responder_address| and |fake_resolver_address| are used only to make sure queries go
+    // through TUN, no entity is listening on them. As such, they can be mapped to the same IP
+    // address.
+    std::string fake_responder_address = makeIpString(index + 100 + (mNetId - TEST_NETID_BASE));
+    std::string fake_resolver_address = fake_responder_address;
+    std::string real_responder_address = makeIpString(index + 200 + (mNetId - TEST_NETID_BASE));
 
-    if (!mTunForwarder->addForwardingRule({src1, dst1}, {src2, dst2}) ||
-        !mTunForwarder->addForwardingRule({dst2, src2}, {dst1, src1})) {
-        return Errorf("Failed to add the rules ({}, {}, {}, {})", src1, dst1, src2, dst2);
+    if (!mTunForwarder->addForwardingRule({real_resolver_address, fake_responder_address},
+                                          {fake_resolver_address, real_responder_address})) {
+        return Errorf("Failed to add the rule - from:({}, {}), to: ({}, {})", real_resolver_address,
+                      fake_responder_address, fake_resolver_address, real_responder_address);
+    }
+    if (!mTunForwarder->addForwardingRule({real_responder_address, fake_resolver_address},
+                                          {fake_responder_address, real_resolver_address})) {
+        return Errorf("Failed to add the rule - from:({}, {}), to: ({}, {})",
+                      real_responder_address, fake_resolver_address, fake_responder_address,
+                      real_resolver_address);
     }
 
-    if (!mNetdSrv->interfaceAddAddress(mIfname, dst2, prefixLen).isOk()) {
-        return Errorf("interfaceAddAddress({}, {}, {}) failed", mIfname, dst2, prefixLen);
+    if (!mNetdSrv->interfaceAddAddress(mIfname, real_responder_address, prefixLen).isOk()) {
+        return Errorf("interfaceAddAddress({}, {}, {}) failed", mIfname, real_responder_address,
+                      prefixLen);
     }
 
-    return mDnsServerPairs.emplace_back(std::make_shared<test::DNSResponder>(mNetId, dst2), dst1);
+    return mDnsServerPairs.emplace_back(
+            std::make_shared<test::DNSResponder>(mNetId, real_responder_address),
+            fake_responder_address);
 }
 
 bool ResolverMultinetworkTest::ScopedNetwork::setDnsConfiguration() const {
@@ -7740,72 +8039,133 @@ TEST_F(ResolverMultinetworkTest, PerAppDefaultNetwork) {
     }
 }
 
-// Do not send AAAA query when IPv6 address is link-local with a default route.
-TEST_F(ResolverMultinetworkTest, IPv6LinkLocalWithDefaultRoute) {
+TEST_F(ResolverMultinetworkTest, AI_ADDRCONFIG_DnsWithLinkLocalIPv6AndDefaultRouteDoesNotSendAAAA) {
+    // Kernel 4.4 does not provide an IPv6 link-local address when an interface is added to a
+    // network. Skip it because v6 link-local address is a prerequisite for this test.
+    SKIP_IF_KERNEL_VERSION_LOWER_THAN(4, 9, 0);
+
     constexpr char host_name[] = "ohayou.example.com.";
-    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::V4);
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
     ASSERT_RESULT_OK(network.init());
 
-    // Add IPv6 default route
     ASSERT_TRUE(mDnsClient.netdService()
                         ->networkAddRoute(network.netId(), network.ifname(), "::/0", "")
                         .isOk());
 
-    const Result<DnsServerPair> dnsPair = network.addIpv4Dns();
+    const Result<DnsServerPair> dnsPair = network.addIpv6Dns();
     ASSERT_RESULT_OK(dnsPair);
-    StartDns(*dnsPair->dnsServer, {{host_name, ns_type::ns_t_a, "192.0.2.0"},
+    StartDns(*dnsPair->dnsServer, {{host_name, ns_type::ns_t_aaaa, "192.0.2.0"},
                                    {host_name, ns_type::ns_t_aaaa, "2001:db8:cafe:d00d::31"}});
 
     ASSERT_TRUE(network.setDnsConfiguration());
     ASSERT_TRUE(network.startTunForwarder());
 
-    auto result = android_getaddrinfofornet_wrapper(host_name, network.netId());
-    ASSERT_RESULT_OK(result);
-    ScopedAddrinfo ai_result(std::move(result.value()));
-    EXPECT_EQ(ToString(ai_result), "192.0.2.0");
-    EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_a, host_name), 1U);
-    EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_aaaa, host_name), 0U);
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_flags = AI_ADDRCONFIG,
+            .ai_family = AF_UNSPEC,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("ohayou.example.com", nullptr, &hints, network.netId(),
+                                       MARK_UNSET, &result);
+    EXPECT_EQ(rv, EAI_NODATA);
+    EXPECT_EQ(result, nullptr);
+    EXPECT_EQ(GetNumQueries(*dnsPair->dnsServer, host_name), 0U);
+}
+
+TEST_F(ResolverMultinetworkTest, AI_ADDRCONFIG_DnsWithGlobalIPv6AndDefaultRouteSendsAAAA) {
+    constexpr char v6addr[] = "2001:db8:cafe:d00d::31";
+    constexpr char v4addr[] = "192.0.2.0";
+    constexpr char host_name[] = "ohayou.example.com.";
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
+    ASSERT_RESULT_OK(network.init());
+
+    ASSERT_TRUE(mDnsClient.netdService()
+                        ->networkAddRoute(network.netId(), network.ifname(), "::/0", "")
+                        .isOk());
 
-    EXPECT_TRUE(mDnsClient.resolvService()->flushNetworkCache(network.netId()).isOk());
-    dnsPair->dnsServer->clearQueries();
+    const Result<DnsServerPair> dnsPair = network.addIpv6Dns();
+    ASSERT_RESULT_OK(dnsPair);
+    StartDns(*dnsPair->dnsServer,
+             {{host_name, ns_type::ns_t_aaaa, v4addr}, {host_name, ns_type::ns_t_aaaa, v6addr}});
+
+    ASSERT_TRUE(network.setDnsConfiguration());
+    ASSERT_TRUE(network.startTunForwarder());
 
-    // Add an IPv6 global address. Resolver starts issuing AAAA queries as well as A queries.
     const std::string v6Addr = network.makeIpv6AddrString(1);
     EXPECT_TRUE(
             mDnsClient.netdService()->interfaceAddAddress(network.ifname(), v6Addr, 128).isOk());
     // Ensuring that address is applied. This is required for mainline test (b/249225311).
     usleep(1000 * 1000);
 
-    result = android_getaddrinfofornet_wrapper(host_name, network.netId());
-    ASSERT_RESULT_OK(result);
-    ScopedAddrinfo ai_results(std::move(result.value()));
-    std::vector<std::string> result_strs = ToStrings(ai_results);
-    EXPECT_THAT(result_strs,
-                testing::UnorderedElementsAreArray({"192.0.2.0", "2001:db8:cafe:d00d::31"}));
-    EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_a, host_name), 1U);
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_flags = AI_ADDRCONFIG,
+            .ai_family = AF_UNSPEC,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("ohayou.example.com", nullptr, &hints, network.netId(),
+                                       MARK_UNSET, &result);
+    EXPECT_EQ(rv, 0);
+    EXPECT_NE(result, nullptr);
+    EXPECT_EQ(ToString(result), v6addr);
+    EXPECT_EQ(GetNumQueries(*dnsPair->dnsServer, host_name), 1U);
+    EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_a, host_name), 0U);
     EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_aaaa, host_name), 1U);
 }
 
-// v6 mdns is expected to be sent when the IPv6 address is a link-local with a default route.
-TEST_F(ResolverMultinetworkTest, MdnsIPv6LinkLocalWithDefaultRoute) {
+TEST_F(ResolverMultinetworkTest,
+       AI_ADDRCONFIG_DnsWithLinkLocalIPv6AndNoDefaultRouteDoesNotSendAAAA) {
     // Kernel 4.4 does not provide an IPv6 link-local address when an interface is added to a
     // network. Skip it because v6 link-local address is a prerequisite for this test.
     SKIP_IF_KERNEL_VERSION_LOWER_THAN(4, 9, 0);
 
+    constexpr char v6addr[] = "2001:db8:cafe:d00d::31";
+    constexpr char v4addr[] = "192.0.2.0";
+    constexpr char host_name[] = "ohayou.example.com.";
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
+    ASSERT_RESULT_OK(network.init());
+
+    const Result<DnsServerPair> dnsPair = network.addIpv6Dns();
+    ASSERT_RESULT_OK(dnsPair);
+    StartDns(*dnsPair->dnsServer,
+             {{host_name, ns_type::ns_t_a, v4addr}, {host_name, ns_type::ns_t_aaaa, v6addr}});
+
+    ASSERT_TRUE(network.setDnsConfiguration());
+    ASSERT_TRUE(network.startTunForwarder());
+
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_flags = AI_ADDRCONFIG,
+            .ai_family = AF_UNSPEC,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("ohayou.example.com", nullptr, &hints, network.netId(),
+                                       MARK_UNSET, &result);
+    EXPECT_EQ(rv, EAI_NODATA);
+    EXPECT_EQ(result, nullptr);
+    EXPECT_EQ(GetNumQueries(*dnsPair->dnsServer, host_name), 0U);
+}
+
+TEST_F(ResolverMultinetworkTest, AI_ADDRCONFIG_MdnsWithLinkLocalIPv6AndDefaultRouteSendsAAAA) {
+    // Kernel 4.4 does not provide an link-local IPv6 address when an interface is added to a
+    // network. Skip it because v6 link-local address is a prerequisite for this test.
+    SKIP_IF_KERNEL_VERSION_LOWER_THAN(4, 9, 0);
+
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char v4addr[] = "127.0.0.3";
     constexpr char host_name[] = "hello.local.";
-    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::V4);
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
     ASSERT_RESULT_OK(network.init());
 
-    // Add IPv6 default route
     ASSERT_TRUE(mDnsClient.netdService()
                         ->networkAddRoute(network.netId(), network.ifname(), "::/0", "")
                         .isOk());
     // Ensuring that routing is applied. This is required for mainline test (b/247693272).
     usleep(1000 * 1000);
 
-    const Result<DnsServerPair> dnsPair = network.addIpv4Dns();
+    // Created only to confirm that no Unicast DNS queries are sent.
+    const Result<DnsServerPair> dnsPair = network.addIpv6Dns();
     ASSERT_RESULT_OK(dnsPair);
     StartDns(*dnsPair->dnsServer, {});
 
@@ -7819,16 +8179,144 @@ TEST_F(ResolverMultinetworkTest, MdnsIPv6LinkLocalWithDefaultRoute) {
     StartDns(mdnsv4, {{host_name, ns_type::ns_t_a, v4addr}});
     StartDns(mdnsv6, {{host_name, ns_type::ns_t_aaaa, v6addr}});
 
-    auto result = android_getaddrinfofornet_wrapper("hello.local", network.netId());
-    ASSERT_RESULT_OK(result);
-    ScopedAddrinfo ai_result(std::move(result.value()));
-    EXPECT_THAT(ToStrings(ai_result), testing::UnorderedElementsAreArray({v4addr, v6addr}));
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_flags = AI_ADDRCONFIG,
+            .ai_family = AF_UNSPEC,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("hello.local", nullptr, &hints, network.netId(), MARK_UNSET,
+                                       &result);
+    EXPECT_EQ(rv, 0);
+    EXPECT_NE(result, nullptr);
+    EXPECT_EQ(ToString(result), v6addr);
+    EXPECT_EQ(GetNumQueries(mdnsv4, host_name), 0U);
+    EXPECT_EQ(GetNumQueries(mdnsv6, host_name), 1U);
+    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 0U);
+    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
+    // Confirm no unicast DNS queries.
+    EXPECT_EQ(GetNumQueries(*dnsPair->dnsServer, host_name), 0U);
+}
+
+TEST_F(ResolverMultinetworkTest, AI_ADDRCONFIG_MdnsWithLinkLocalIPv6AndNoDefaultRouteSendsAAAA) {
+    // Kernel 4.4 does not provide an IPv6 link-local address when an interface is added to a
+    // network. Skip it because v6 link-local address is a prerequisite for this test.
+    SKIP_IF_KERNEL_VERSION_LOWER_THAN(4, 9, 0);
+
+    constexpr char v6addr[] = "::127.0.0.3";
+    constexpr char v4addr[] = "127.0.0.3";
+    constexpr char host_name[] = "hello.local.";
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
+    ASSERT_RESULT_OK(network.init());
+
+    // Created only to confirm that no Unicast DNS queries are sent.
+    const Result<DnsServerPair> dnsPair = network.addIpv6Dns();
+    ASSERT_RESULT_OK(dnsPair);
+    StartDns(*dnsPair->dnsServer, {});
+
+    ASSERT_TRUE(network.setDnsConfiguration());
+    ASSERT_TRUE(network.startTunForwarder());
+
+    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
+    test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
+    mdnsv4.setNetwork(network.netId());
+    mdnsv6.setNetwork(network.netId());
+    StartDns(mdnsv4, {{host_name, ns_type::ns_t_a, v4addr}});
+    StartDns(mdnsv6, {{host_name, ns_type::ns_t_aaaa, v6addr}});
 
-    // make sure queries were sent & received via mdns.
-    EXPECT_EQ(GetNumQueries(mdnsv4, host_name), 1U);
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_flags = AI_ADDRCONFIG,
+            .ai_family = AF_UNSPEC,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("hello.local", nullptr, &hints, network.netId(), MARK_UNSET,
+                                       &result);
+    EXPECT_EQ(rv, 0);
+    EXPECT_NE(result, nullptr);
+    EXPECT_EQ(ToString(result), v6addr);
     EXPECT_EQ(GetNumQueries(mdnsv6, host_name), 1U);
-    EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_a, host_name), 0U);
-    EXPECT_EQ(GetNumQueriesForType(*dnsPair->dnsServer, ns_type::ns_t_aaaa, host_name), 0U);
+    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_a, host_name), 0U);
+    EXPECT_EQ(GetNumQueriesForType(mdnsv6, ns_type::ns_t_aaaa, host_name), 1U);
+    // Confirm no unicast DNS queries.
+    EXPECT_EQ(GetNumQueries(*dnsPair->dnsServer, host_name), 0U);
+}
+
+TEST_F(ResolverMultinetworkTest, getaddrinfo_PopulatesScopeIDWhenMdnsReturnsLinkLocalResult) {
+    // Kernel 4.4 does not provide an IPv6 link-local address when an interface is added to a
+    // network. Skip it because v6 link-local address is a prerequisite for this test.
+    SKIP_IF_KERNEL_VERSION_LOWER_THAN(4, 9, 0);
+
+    constexpr char v6addr[] = "fe80::";
+    constexpr char v4addr[] = "127.0.0.3";
+    constexpr char host_name[] = "hello.local.";
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
+    ASSERT_RESULT_OK(network.init());
+
+    ASSERT_TRUE(network.setDnsConfiguration());
+    ASSERT_TRUE(network.startTunForwarder());
+
+    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
+    test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
+    mdnsv4.setNetwork(network.netId());
+    mdnsv6.setNetwork(network.netId());
+    StartDns(mdnsv4, {{host_name, ns_type::ns_t_a, v4addr}});
+    StartDns(mdnsv6, {{host_name, ns_type::ns_t_aaaa, v6addr}});
+
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_family = AF_INET6,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("hello.local", nullptr, &hints, network.netId(), MARK_UNSET,
+                                       &result);
+    EXPECT_EQ(rv, 0);
+    EXPECT_NE(result, nullptr);
+    EXPECT_EQ(ToString(result), "fe80::%lo");
+    EXPECT_EQ(result->ai_family, AF_INET6);
+    const auto* sin6 = reinterpret_cast<sockaddr_in6*>(result->ai_addr);
+    EXPECT_NE(sin6->sin6_scope_id, 0U);
+    EXPECT_EQ(sin6->sin6_scope_id, if_nametoindex("lo"));
+}
+
+TEST_F(ResolverMultinetworkTest, getaddrinfo_DoesNotPopulateScopeIDWhenDnsReturnsLinkLocalResult) {
+    constexpr char v6addr[] = "fe80::";
+    constexpr char v4addr[] = "192.0.2.0";
+    constexpr char host_name[] = "ohayou.example.com.";
+    ScopedPhysicalNetwork network = CreateScopedPhysicalNetwork(ConnectivityType::NONE);
+    ASSERT_RESULT_OK(network.init());
+
+    ASSERT_TRUE(mDnsClient.netdService()
+                        ->networkAddRoute(network.netId(), network.ifname(), "::/0", "")
+                        .isOk());
+
+    const Result<DnsServerPair> dnsPair = network.addIpv6Dns();
+    ASSERT_RESULT_OK(dnsPair);
+    StartDns(*dnsPair->dnsServer,
+             {{host_name, ns_type::ns_t_aaaa, v4addr}, {host_name, ns_type::ns_t_aaaa, v6addr}});
+
+    ASSERT_TRUE(network.setDnsConfiguration());
+    ASSERT_TRUE(network.startTunForwarder());
+
+    const std::string v6Addr = network.makeIpv6AddrString(1);
+    EXPECT_TRUE(
+            mDnsClient.netdService()->interfaceAddAddress(network.ifname(), v6Addr, 128).isOk());
+    // Ensuring that address is applied. This is required for mainline test (b/249225311).
+    usleep(1000 * 1000);
+
+    addrinfo* result = nullptr;
+    const addrinfo hints = {
+            .ai_family = AF_INET6,
+            .ai_socktype = SOCK_STREAM,
+    };
+    int rv = android_getaddrinfofornet("ohayou.example.com", nullptr, &hints, network.netId(),
+                                       MARK_UNSET, &result);
+    EXPECT_EQ(rv, 0);
+    EXPECT_NE(result, nullptr);
+    EXPECT_EQ(ToString(result), "fe80::");
+    EXPECT_EQ(result->ai_family, AF_INET6);
+    const auto* sin6 = reinterpret_cast<sockaddr_in6*>(result->ai_addr);
+    EXPECT_EQ(sin6->sin6_scope_id, 0U);
 }
 
 TEST_F(ResolverTest, NegativeValueInExperimentFlag) {
diff --git a/tests/resolv_private_dns_test.cpp b/tests/resolv_private_dns_test.cpp
index 01c46507..7b14a3be 100644
--- a/tests/resolv_private_dns_test.cpp
+++ b/tests/resolv_private_dns_test.cpp
@@ -503,8 +503,8 @@ TEST_P(TransportParameterizedTest, MdnsGetAddrInfo_fallback) {
     dns.clearQueries();
 
     EXPECT_NO_FAILURE(sendQueryAndCheckResult("hello.local"));
-    EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-    EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+    EXPECT_EQ(2U, GetNumQueries(mdnsv4, host_name));
+    EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
     if (testParamHasDoh()) {
         EXPECT_NO_FAILURE(expectQueries(0 /* dns */, 0 /* dot */, 2 /* doh */));
     } else {
@@ -520,8 +520,8 @@ TEST_P(TransportParameterizedTest, MdnsGetAddrInfo_fallback) {
     mdnsv6.clearQueries();
 
     EXPECT_NO_FAILURE(sendQueryAndCheckResult("hello.local"));
-    EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-    EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+    EXPECT_EQ(2U, GetNumQueries(mdnsv4, host_name));
+    EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
     if (testParamHasDoh()) {
         EXPECT_NO_FAILURE(expectQueries(2 /* dns */, 0 /* dot */, 2 /* doh */));
     } else {
diff --git a/tests/resolv_test_utils.h b/tests/resolv_test_utils.h
index fcd4c131..64aa1911 100644
--- a/tests/resolv_test_utils.h
+++ b/tests/resolv_test_utils.h
@@ -189,6 +189,7 @@ const std::string kDotValidationLatencyOffsetMsFlag(kFlagPrefix +
 const std::string kFailFastOnUidNetworkBlockingFlag(kFlagPrefix +
                                                     "fail_fast_on_uid_network_blocking");
 const std::string kKeepListeningUdpFlag(kFlagPrefix + "keep_listening_udp");
+const std::string kNoRetryAfterCancelFlag(kFlagPrefix + "no_retry_after_cancel");
 const std::string kParallelLookupSleepTimeFlag(kFlagPrefix + "parallel_lookup_sleep_time");
 const std::string kRetransIntervalFlag(kFlagPrefix + "retransmission_time_interval");
 const std::string kRetryCountFlag(kFlagPrefix + "retry_count");
@@ -458,6 +459,12 @@ inline int resolv_set_nameservers(
     params.maxSamples = res_params.max_samples;
     params.baseTimeoutMsec = res_params.base_timeout_msec;
     params.retryCount = res_params.retry_count;
+    // This is currently not configurable. Tests relying on DnsResponderClient, are currently
+    // creating a network with no interfaces. They then end up relying on local communication to
+    // receive and send DNS queries. Adding "lo" as an interface for |TEST_NETID| makes that
+    // dependency explicit, allowing mDNS multicast queries to be sent via
+    // IP_MULTICAST_IF/IPV6_MULTICAST_IF.
+    params.interfaceNames = {"lo"};
 
     return resolv_set_nameservers(params);
 }
diff --git a/tests/resolv_unit_test.cpp b/tests/resolv_unit_test.cpp
index e9868ccd..4df753d3 100644
--- a/tests/resolv_unit_test.cpp
+++ b/tests/resolv_unit_test.cpp
@@ -165,7 +165,7 @@ TEST_F(ResolvGetAddrInfoTest, InvalidParameters) {
         addrinfo* result = nullptr;
         NetworkDnsEventReported event;
         int rv = resolv_getaddrinfo(nullptr /*hostname*/, nullptr /*servname*/, nullptr /*hints*/,
-                                    &mNetcontext, &result, &event);
+                                    &mNetcontext, APP_SOCKET_NONE, &result, &event);
         ScopedAddrinfo result_cleanup(result);
         EXPECT_EQ(EAI_NONAME, rv);
     }
@@ -220,7 +220,7 @@ TEST_F(ResolvGetAddrInfoTest, InvalidParameters) {
         };
         NetworkDnsEventReported event;
         int rv = resolv_getaddrinfo("localhost", nullptr /*servname*/, &hints, &mNetcontext,
-                                    &result, &event);
+                                    APP_SOCKET_NONE, &result, &event);
         ScopedAddrinfo result_cleanup(result);
         EXPECT_EQ(config.expected_eai_error, rv);
     }
@@ -239,7 +239,7 @@ TEST_F(ResolvGetAddrInfoTest, InvalidParameters_Family) {
         };
         NetworkDnsEventReported event;
         int rv = resolv_getaddrinfo("localhost", nullptr /*servname*/, &hints, &mNetcontext,
-                                    &result, &event);
+                                    APP_SOCKET_NONE, &result, &event);
         ScopedAddrinfo result_cleanup(result);
         EXPECT_EQ(EAI_FAMILY, rv);
     }
@@ -266,8 +266,8 @@ TEST_F(ResolvGetAddrInfoTest, InvalidParameters_SocketType) {
                                              service ? service : "service is nullptr"));
                     addrinfo* result = nullptr;
                     NetworkDnsEventReported event;
-                    int rv = resolv_getaddrinfo("localhost", service, &hints, &mNetcontext, &result,
-                                                &event);
+                    int rv = resolv_getaddrinfo("localhost", service, &hints, &mNetcontext,
+                                                APP_SOCKET_NONE, &result, &event);
                     ScopedAddrinfo result_cleanup(result);
                     EXPECT_EQ(EAI_SOCKTYPE, rv);
                 }
@@ -316,7 +316,7 @@ TEST_F(ResolvGetAddrInfoTest, InvalidParameters_MeaningfulSocktypeAndProtocolCom
                 };
                 NetworkDnsEventReported event;
                 int rv = resolv_getaddrinfo("localhost", nullptr /*servname*/, &hints, &mNetcontext,
-                                            &result, &event);
+                                            APP_SOCKET_NONE, &result, &event);
                 ScopedAddrinfo result_cleanup(result);
                 EXPECT_EQ(EAI_BADHINTS, rv);
             }
@@ -391,8 +391,8 @@ TEST_F(ResolvGetAddrInfoTest, InvalidParameters_PortNameAndNumber) {
 
         addrinfo* result = nullptr;
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("localhost", config.servname, &hints, &mNetcontext, &result,
-                                    &event);
+        int rv = resolv_getaddrinfo("localhost", config.servname, &hints, &mNetcontext,
+                                    APP_SOCKET_NONE, &result, &event);
         ScopedAddrinfo result_cleanup(result);
         EXPECT_EQ(config.expected_eai_error, rv);
     }
@@ -469,7 +469,8 @@ TEST_F(ResolvGetAddrInfoTest, AlphabeticalHostname_NoData) {
     addrinfo* result = nullptr;
     const addrinfo hints = {.ai_family = AF_INET6};
     NetworkDnsEventReported event;
-    int rv = resolv_getaddrinfo("v4only", nullptr, &hints, &mNetcontext, &result, &event);
+    int rv = resolv_getaddrinfo("v4only", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE, &result,
+                                &event);
     EXPECT_THAT(event, NetworkDnsEventEq(fromNetworkDnsEventReportedStr(event_ipv6)));
     ScopedAddrinfo result_cleanup(result);
     EXPECT_LE(1U, GetNumQueries(dns, v4_host_name));
@@ -567,7 +568,8 @@ TEST_F(ResolvGetAddrInfoTest, AlphabeticalHostname) {
         addrinfo* result = nullptr;
         const addrinfo hints = {.ai_family = config.ai_family};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("sawadee", nullptr, &hints, &mNetcontext, &result, &event);
+        int rv = resolv_getaddrinfo("sawadee", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &result, &event);
         EXPECT_THAT(event,
                     NetworkDnsEventEq(fromNetworkDnsEventReportedStr(config.expected_event)));
         ScopedAddrinfo result_cleanup(result);
@@ -610,7 +612,8 @@ TEST_F(ResolvGetAddrInfoTest, IllegalHostname) {
             addrinfo* res = nullptr;
             const addrinfo hints = {.ai_family = family};
             NetworkDnsEventReported event;
-            int rv = resolv_getaddrinfo(hostname, nullptr, &hints, &mNetcontext, &res, &event);
+            int rv = resolv_getaddrinfo(hostname, nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                        &res, &event);
             ScopedAddrinfo result(res);
             EXPECT_EQ(nullptr, result);
             EXPECT_EQ(EAI_FAIL, rv);
@@ -649,7 +652,8 @@ TEST_F(ResolvGetAddrInfoTest, ServerResponseError) {
         addrinfo* result = nullptr;
         const addrinfo hints = {.ai_family = AF_UNSPEC};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo(host_name, nullptr, &hints, &mNetcontext, &result, &event);
+        int rv = resolv_getaddrinfo(host_name, nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &result, &event);
         EXPECT_EQ(config.expected_eai_error, rv);
     }
 }
@@ -855,7 +859,8 @@ TEST_F(ResolvGetAddrInfoTest, ServerTimeout) {
     addrinfo* result = nullptr;
     const addrinfo hints = {.ai_family = AF_UNSPEC};
     NetworkDnsEventReported event;
-    int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, &result, &event);
+    int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE, &result,
+                                &event);
     EXPECT_THAT(event, NetworkDnsEventEq(fromNetworkDnsEventReportedStr(expected_event)));
     EXPECT_EQ(NETD_RESOLV_TIMEOUT, rv);
 }
@@ -877,7 +882,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
                  rcode: 0,
                  type: 1,
                  cache_hit: 1,
-                 ip_version: 1,
+                 ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
                  dns_server_index: 0,
@@ -928,7 +933,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
                  rcode: 0,
                  type: 1,
                  cache_hit: 1,
-                 ip_version: 1,
+                 ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
                  dns_server_index: 0,
@@ -939,11 +944,9 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
              }
         })Event";
 
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
-    mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv6.addMapping(host_name, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_EQ(0, SetResolvers());
 
@@ -959,26 +962,25 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
 
     for (const auto& config : testConfigs) {
         SCOPED_TRACE(fmt::format("family: {}", config.ai_family));
-        mdnsv4.clearQueries();
         mdnsv6.clearQueries();
 
         addrinfo* result = nullptr;
         const addrinfo hints = {.ai_family = config.ai_family, .ai_socktype = SOCK_DGRAM};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("hello.local", nullptr, &hints, &mNetcontext, &result, &event);
+        int rv = resolv_getaddrinfo("hello.local", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &result, &event);
         EXPECT_THAT(event,
                     NetworkDnsEventEq(fromNetworkDnsEventReportedStr(config.expected_event)));
         ScopedAddrinfo result_cleanup(result);
 
         if (config.ai_family == AF_UNSPEC) {
             EXPECT_EQ(0, rv);
-            EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
-            EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
+            EXPECT_EQ(2U, GetNumQueries(mdnsv6, host_name));
             const std::vector<std::string> result_strs = ToStrings(result);
             EXPECT_THAT(result_strs, testing::UnorderedElementsAreArray(config.expected_addr));
         } else if (config.ai_family == AF_INET) {
             EXPECT_EQ(0, rv);
-            EXPECT_EQ(1U, GetNumQueries(mdnsv4, host_name));
+            EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
             const std::vector<std::string> result_strs = ToStrings(result);
             EXPECT_THAT(result_strs, testing::UnorderedElementsAreArray(config.expected_addr));
         } else if (config.ai_family == AF_INET6) {
@@ -995,12 +997,9 @@ TEST_F(ResolvGetAddrInfoTest, MdnsIllegalHostname) {
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char v4addr[] = "127.0.0.3";
 
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_EQ(0, SetResolvers());
-    mdnsv4.clearQueries();
     mdnsv6.clearQueries();
 
     constexpr char illegalHostname[] = "hello^.local.";
@@ -1013,7 +1012,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsIllegalHostname) {
     //
     // In this example, querying "hello^.local" should get no address because
     // "hello^.local" has an illegal char '^' in the middle of label.
-    mdnsv4.addMapping(illegalHostname, ns_type::ns_t_a, v4addr);
+    mdnsv6.addMapping(illegalHostname, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(illegalHostname, ns_type::ns_t_aaaa, v6addr);
 
     for (const auto& family : {AF_INET, AF_INET6, AF_UNSPEC}) {
@@ -1021,7 +1020,8 @@ TEST_F(ResolvGetAddrInfoTest, MdnsIllegalHostname) {
         addrinfo* result = nullptr;
         const addrinfo hints = {.ai_family = family};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("hello^.local", nullptr, &hints, &mNetcontext, &result, &event);
+        int rv = resolv_getaddrinfo("hello^.local", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &result, &event);
         ScopedAddrinfo result_cleanup(result);
         EXPECT_EQ(nullptr, result);
         EXPECT_EQ(EAI_FAIL, rv);
@@ -1047,7 +1047,8 @@ TEST_F(ResolvGetAddrInfoTest, MdnsResponderTimeout) {
         addrinfo* result = nullptr;
         const addrinfo hints = {.ai_family = family};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("hello.local", nullptr, &hints, &mNetcontext, &result, &event);
+        int rv = resolv_getaddrinfo("hello.local", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &result, &event);
         EXPECT_EQ(NETD_RESOLV_TIMEOUT, rv);
     }
 }
@@ -1082,7 +1083,8 @@ TEST_F(ResolvGetAddrInfoTest, CnamesNoIpAddress) {
         addrinfo* res = nullptr;
         const addrinfo hints = {.ai_family = config.family};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo(config.name, nullptr, &hints, &mNetcontext, &res, &event);
+        int rv = resolv_getaddrinfo(config.name, nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &res, &event);
         ScopedAddrinfo result(res);
         EXPECT_EQ(nullptr, result);
         EXPECT_EQ(EAI_FAIL, rv);
@@ -1132,7 +1134,8 @@ TEST_F(ResolvGetAddrInfoTest, CnamesBrokenChainByIllegalCname) {
             addrinfo* res = nullptr;
             const addrinfo hints = {.ai_family = family};
             NetworkDnsEventReported event;
-            int rv = resolv_getaddrinfo(config.name, nullptr, &hints, &mNetcontext, &res, &event);
+            int rv = resolv_getaddrinfo(config.name, nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                        &res, &event);
             ScopedAddrinfo result(res);
             EXPECT_EQ(nullptr, result);
             EXPECT_EQ(EAI_FAIL, rv);
@@ -1153,7 +1156,8 @@ TEST_F(ResolvGetAddrInfoTest, CnamesInfiniteLoop) {
         addrinfo* res = nullptr;
         const addrinfo hints = {.ai_family = family};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, &res, &event);
+        int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE, &res,
+                                    &event);
         ScopedAddrinfo result(res);
         EXPECT_EQ(nullptr, result);
         EXPECT_EQ(EAI_FAIL, rv);
@@ -1183,7 +1187,8 @@ TEST_F(ResolvGetAddrInfoTest, MultiAnswerSections) {
         // the second query of different socket type are responded by the cache.
         const addrinfo hints = {.ai_family = family, .ai_socktype = SOCK_STREAM};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, &res, &event);
+        int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE, &res,
+                                    &event);
         ScopedAddrinfo result(res);
         ASSERT_NE(nullptr, result);
         ASSERT_EQ(0, rv);
@@ -1320,7 +1325,8 @@ TEST_F(ResolvGetAddrInfoTest, TruncatedResponse) {
         addrinfo* result = nullptr;
         const addrinfo hints = {.ai_family = config.ai_family};
         NetworkDnsEventReported event;
-        int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, &result, &event);
+        int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE,
+                                    &result, &event);
         EXPECT_THAT(event,
                     NetworkDnsEventEq(fromNetworkDnsEventReportedStr(config.expected_event)));
         ScopedAddrinfo result_cleanup(result);
@@ -1364,7 +1370,8 @@ TEST_F(ResolvGetAddrInfoTest, OverlengthResp) {
     addrinfo* result = nullptr;
     const addrinfo hints = {.ai_family = AF_INET};
     NetworkDnsEventReported event;
-    int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, &result, &event);
+    int rv = resolv_getaddrinfo("hello", nullptr, &hints, &mNetcontext, APP_SOCKET_NONE, &result,
+                                &event);
     ScopedAddrinfo result_cleanup(result);
     EXPECT_EQ(rv, EAI_FAIL);
     EXPECT_TRUE(result == nullptr);
@@ -1444,7 +1451,7 @@ TEST_F(GetHostByNameForNetContextTest, AlphabeticalHostname) {
         char tmpbuf[MAXPACKET];
         NetworkDnsEventReported event;
         int rv = resolv_gethostbyname("jiababuei", config.ai_family, &hbuf, tmpbuf, sizeof(tmpbuf),
-                                      &mNetcontext, &hp, &event);
+                                      &mNetcontext, APP_SOCKET_NONE, &hp, &event);
         EXPECT_THAT(event,
                     NetworkDnsEventEq(fromNetworkDnsEventReportedStr(config.expected_event)));
         EXPECT_EQ(0, rv);
@@ -1488,7 +1495,7 @@ TEST_F(GetHostByNameForNetContextTest, IllegalHostname) {
             char tmpbuf[MAXPACKET];
             NetworkDnsEventReported event;
             int rv = resolv_gethostbyname(hostname, family, &hbuf, tmpbuf, sizeof(tmpbuf),
-                                          &mNetcontext, &hp, &event);
+                                          &mNetcontext, APP_SOCKET_NONE, &hp, &event);
             EXPECT_EQ(nullptr, hp);
             EXPECT_EQ(EAI_FAIL, rv);
         }
@@ -1510,7 +1517,7 @@ TEST_F(GetHostByNameForNetContextTest, NoData) {
     char tmpbuf[MAXPACKET];
     NetworkDnsEventReported event;
     int rv = resolv_gethostbyname("v4only", AF_INET6, &hbuf, tmpbuf, sizeof tmpbuf, &mNetcontext,
-                                  &hp, &event);
+                                  APP_SOCKET_NONE, &hp, &event);
     EXPECT_LE(1U, GetNumQueries(dns, v4_host_name));
     EXPECT_EQ(nullptr, hp);
     EXPECT_EQ(EAI_NODATA, rv);
@@ -1551,7 +1558,7 @@ TEST_F(GetHostByNameForNetContextTest, ServerResponseError) {
         char tmpbuf[MAXPACKET];
         NetworkDnsEventReported event;
         int rv = resolv_gethostbyname(host_name, AF_INET, &hbuf, tmpbuf, sizeof tmpbuf,
-                                      &mNetcontext, &hp, &event);
+                                      &mNetcontext, APP_SOCKET_NONE, &hp, &event);
         EXPECT_EQ(nullptr, hp);
         EXPECT_EQ(config.expected_eai_error, rv);
     }
@@ -1571,7 +1578,7 @@ TEST_F(GetHostByNameForNetContextTest, ServerTimeout) {
     char tmpbuf[MAXPACKET];
     NetworkDnsEventReported event;
     int rv = resolv_gethostbyname(host_name, AF_INET, &hbuf, tmpbuf, sizeof tmpbuf, &mNetcontext,
-                                  &hp, &event);
+                                  APP_SOCKET_NONE, &hp, &event);
     EXPECT_EQ(NETD_RESOLV_TIMEOUT, rv);
 }
 
@@ -1603,7 +1610,7 @@ TEST_F(GetHostByNameForNetContextTest, CnamesNoIpAddress) {
         char tmpbuf[MAXPACKET];
         NetworkDnsEventReported event;
         int rv = resolv_gethostbyname(config.name, config.family, &hbuf, tmpbuf, sizeof tmpbuf,
-                                      &mNetcontext, &hp, &event);
+                                      &mNetcontext, APP_SOCKET_NONE, &hp, &event);
         EXPECT_EQ(nullptr, hp);
         EXPECT_EQ(EAI_FAIL, rv);
     }
@@ -1654,7 +1661,7 @@ TEST_F(GetHostByNameForNetContextTest, CnamesBrokenChainByIllegalCname) {
             char tmpbuf[MAXPACKET];
             NetworkDnsEventReported event;
             int rv = resolv_gethostbyname(config.name, family, &hbuf, tmpbuf, sizeof tmpbuf,
-                                          &mNetcontext, &hp, &event);
+                                          &mNetcontext, APP_SOCKET_NONE, &hp, &event);
             EXPECT_EQ(nullptr, hp);
             EXPECT_EQ(EAI_FAIL, rv);
         }
@@ -1676,7 +1683,7 @@ TEST_F(GetHostByNameForNetContextTest, CnamesInfiniteLoop) {
         char tmpbuf[MAXPACKET];
         NetworkDnsEventReported event;
         int rv = resolv_gethostbyname("hello", family, &hbuf, tmpbuf, sizeof tmpbuf, &mNetcontext,
-                                      &hp, &event);
+                                      APP_SOCKET_NONE, &hp, &event);
         EXPECT_EQ(nullptr, hp);
         EXPECT_EQ(EAI_FAIL, rv);
     }
@@ -1699,7 +1706,7 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
                  rcode: 0,
                  type: 1,
                  cache_hit: 1,
-                 ip_version: 1,
+                 ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
                  dns_server_index: 0,
@@ -1732,13 +1739,11 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
              }
         })Event";
 
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
 
-    mdnsv4.addMapping(host_name, ns_type::ns_t_a, v4addr);
+    mdnsv6.addMapping(host_name, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
 
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_EQ(0, SetResolvers());
 
@@ -1757,22 +1762,25 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
         hostent hbuf;
         char tmpbuf[MAXPACKET];
         NetworkDnsEventReported event;
-        int rv = resolv_gethostbyname("hello.local", config.ai_family, &hbuf, tmpbuf,
-                                      sizeof(tmpbuf), &mNetcontext, &result, &event);
+        mdnsv6.clearQueries();
+        int rv =
+                resolv_gethostbyname("hello.local", config.ai_family, &hbuf, tmpbuf, sizeof(tmpbuf),
+                                     &mNetcontext, APP_SOCKET_NONE, &result, &event);
         EXPECT_THAT(event,
                     NetworkDnsEventEq(fromNetworkDnsEventReportedStr(config.expected_event)));
         EXPECT_EQ(0, rv);
-        test::DNSResponder& mdns = config.ai_family == AF_INET ? mdnsv4 : mdnsv6;
-        EXPECT_EQ(1U, GetNumQueries(mdns, host_name));
-        mdns.clearQueries();
+        EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
         std::vector<std::string> result_strs = ToStrings(result);
         EXPECT_THAT(result_strs, testing::UnorderedElementsAreArray(config.expected_addr));
 
         // Ensure the query result is still cached.
+        // TODO(b/394031336): caching is currently disabled while we work on a cache that supports
+        // keying by interface. Update values once re-enabled.
+        mdnsv6.clearQueries();
         rv = resolv_gethostbyname("hello.local", config.ai_family, &hbuf, tmpbuf, sizeof(tmpbuf),
-                                  &mNetcontext, &result, &event);
+                                  &mNetcontext, APP_SOCKET_NONE, &result, &event);
         EXPECT_EQ(0, rv);
-        EXPECT_EQ(0U, GetNumQueries(mdns, host_name));
+        EXPECT_EQ(1U, GetNumQueries(mdnsv6, host_name));
         result_strs = ToStrings(result);
         EXPECT_THAT(result_strs, testing::UnorderedElementsAreArray(config.expected_addr));
     }
@@ -1781,12 +1789,9 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
 TEST_F(GetHostByNameForNetContextTest, MdnsIllegalHostname) {
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char v4addr[] = "127.0.0.3";
-    test::DNSResponder mdnsv4("127.0.0.3", test::kDefaultMdnsListenService);
     test::DNSResponder mdnsv6("::1", test::kDefaultMdnsListenService);
-    ASSERT_TRUE(mdnsv4.startServer());
     ASSERT_TRUE(mdnsv6.startServer());
     ASSERT_EQ(0, SetResolvers());
-    mdnsv4.clearQueries();
     mdnsv6.clearQueries();
 
     constexpr char illegalHostname[] = "hello^.local.";
@@ -1799,7 +1804,7 @@ TEST_F(GetHostByNameForNetContextTest, MdnsIllegalHostname) {
     //
     // In this example, querying "hello^.local" should get no address because
     // "hello^.local" has an illegal char '^' in the middle of label.
-    mdnsv4.addMapping(illegalHostname, ns_type::ns_t_a, v4addr);
+    mdnsv6.addMapping(illegalHostname, ns_type::ns_t_a, v4addr);
     mdnsv6.addMapping(illegalHostname, ns_type::ns_t_aaaa, v6addr);
 
     SCOPED_TRACE(fmt::format("family: {}, illegalHostname: {}", AF_INET6, illegalHostname));
@@ -1808,13 +1813,13 @@ TEST_F(GetHostByNameForNetContextTest, MdnsIllegalHostname) {
     char tmpbuf[MAXPACKET];
     NetworkDnsEventReported event;
     int rv = resolv_gethostbyname("hello^.local", AF_INET6, &hbuf, tmpbuf, sizeof(tmpbuf),
-                                  &mNetcontext, &result, &event);
+                                  &mNetcontext, APP_SOCKET_NONE, &result, &event);
     EXPECT_EQ(nullptr, result);
     EXPECT_EQ(EAI_FAIL, rv);
 
     SCOPED_TRACE(fmt::format("family: {}, illegalHostname: {}", AF_INET, illegalHostname));
     rv = resolv_gethostbyname("hello^.local", AF_INET, &hbuf, tmpbuf, sizeof(tmpbuf), &mNetcontext,
-                              &result, &event);
+                              APP_SOCKET_NONE, &result, &event);
     EXPECT_EQ(nullptr, result);
     EXPECT_EQ(EAI_FAIL, rv);
 }
@@ -1840,7 +1845,7 @@ TEST_F(GetHostByNameForNetContextTest, MdnsResponderTimeout) {
         char tmpbuf[MAXPACKET];
         NetworkDnsEventReported event;
         int rv = resolv_gethostbyname("hello.local", family, &hbuf, tmpbuf, sizeof tmpbuf,
-                                      &mNetcontext, &result, &event);
+                                      &mNetcontext, APP_SOCKET_NONE, &result, &event);
         EXPECT_EQ(NETD_RESOLV_TIMEOUT, rv);
     }
 }
diff --git a/util.h b/util.h
index 8c03b470..3a9914b3 100644
--- a/util.h
+++ b/util.h
@@ -62,6 +62,11 @@ inline bool isDebuggable() {
     return android::base::GetBoolProperty("ro.debuggable", false);
 }
 
+inline bool isAtLeastS() {
+    const static bool isAtLeastS = android::modules::sdklevel::IsAtLeastS();
+    return isAtLeastS;
+}
+
 inline bool isAtLeastT() {
     const static bool isAtLeastT = android::modules::sdklevel::IsAtLeastT();
     return isAtLeastT;
```

