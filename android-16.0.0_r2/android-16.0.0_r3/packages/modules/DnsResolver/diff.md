```diff
diff --git a/Android.bp b/Android.bp
index caeb89fa..655243c3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,7 +54,7 @@ cc_library_headers {
     ],
 }
 
-dnsresolver_aidl_interface_lateststable_version = "V15"
+dnsresolver_aidl_interface_lateststable_version = "V16"
 
 cc_library_static {
     name: "dnsresolver_aidl_interface-lateststable-ndk",
@@ -257,6 +257,11 @@ cc_library {
         symbol_file: "libnetd_resolv.map.txt",
     },
     defaults: ["netd_defaults"],
+    generated_headers: [
+        "cxx-bridge-header",
+        "libdns_proxy_cxx_bridge_header",
+    ],
+    generated_sources: ["libdns_proxy_cxx_bridge_source"],
     srcs: [
         "getaddrinfo.cpp",
         "gethnamaddr.cpp",
@@ -272,6 +277,7 @@ cc_library {
         "Dns64Configuration.cpp",
         "DnsProxyListener.cpp",
         "DnsQueryLog.cpp",
+        "DnsProxy.cpp",
         "DnsResolver.cpp",
         "DnsResolverService.cpp",
         "DnsStats.cpp",
@@ -285,6 +291,7 @@ cc_library {
         "PrivateDnsConfiguration.cpp",
         "ResolverController.cpp",
         "ResolverEventReporter.cpp",
+        "dns_proxy/net_context_client.cpp",
     ],
     // Link most things statically to minimize our dependence on system ABIs.
     stl: "libc++_static",
@@ -293,6 +300,7 @@ cc_library {
         "libbase",
         "libcutils",
         "libnetdutils",
+        "libdns_proxy_ffi",
         "libdoh_ffi",
         "libmodules-utils-build",
         "libprotobuf-cpp-lite",
@@ -517,3 +525,74 @@ rust_ffi_static {
 
     whole_static_libs: ["libunwind"],
 }
+
+rust_defaults {
+    name: "libdns_proxy_defaults",
+    rlibs: [
+        "libbytes",
+        "libfutures",
+        "liblog_rust",
+        "libnix",
+        "libnum_enum",
+        "librand",
+        "libsocket2",
+        "libthiserror",
+        "libtokio",
+    ],
+    proc_macros: [
+        "libasync_trait",
+    ],
+}
+
+genrule {
+    name: "libdns_proxy_cxx_bridge_header",
+    tools: ["cxxbridge"],
+    cmd: "$(location cxxbridge) $(in) --header >> $(out)",
+    srcs: ["dns_proxy/ffi.rs"],
+    out: ["dns_proxy_cxx_bridge.rs.h"],
+}
+
+genrule {
+    name: "libdns_proxy_cxx_bridge_source",
+    tools: ["cxxbridge"],
+    cmd: "$(location cxxbridge) $(in) >> $(out)",
+    srcs: ["dns_proxy/ffi.rs"],
+    out: ["dns_proxy_cxx_bridge.rs.cpp"],
+}
+
+rust_ffi_static {
+    name: "libdns_proxy_ffi",
+    crate_name: "dns_proxy",
+    srcs: ["dns_proxy/lib.rs"],
+    edition: "2021",
+
+    defaults: ["libdns_proxy_defaults"],
+    features: [
+        "android-ffi",
+    ],
+    rlibs: [
+        "libandroid_logger",
+        "libcxx",
+    ],
+    prefer_rlib: true,
+
+    apex_available: [
+        "com.android.resolv",
+    ],
+    min_sdk_version: "30",
+}
+
+rust_test {
+    name: "libdns_proxy_host_tests",
+    srcs: ["dns_proxy/lib.rs"],
+    edition: "2021",
+    device_supported: false,
+    host_supported: true,
+    defaults: ["libdns_proxy_defaults"],
+    rlibs: [
+        "libmockall",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+}
diff --git a/DnsProxy.cpp b/DnsProxy.cpp
new file mode 100644
index 00000000..ef878f81
--- /dev/null
+++ b/DnsProxy.cpp
@@ -0,0 +1,84 @@
+// Copyright 2025 The Android Open Source Project
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
+#include "DnsProxy.h"
+#include <cstdint>
+#include <memory>
+#include "DnsResolver.h"
+#include "dns_proxy_cxx_bridge.rs.h"
+#include "include/netd_resolv/resolv.h"
+
+namespace android {
+namespace net {
+namespace dns_proxy_ffi {
+
+// getDnsMark must be thread-safe since it is used in DnsMarkCallback.
+uint32_t getDnsMark(ResolverNetdCallbacks& resNetdCallbacks, uint32_t netId, uint32_t uid) {
+    android_net_context netContext;
+    // Safety: get_network_context is thread-safe since the implementation is
+    // behind a mutex lock.
+    resNetdCallbacks.get_network_context(netId, uid, &netContext);
+    return netContext.dns_mark;
+}
+
+// Safety: thread-safe since it is a lambda wrapper of a thread-safe function.
+DnsMarkCallback makeDnsMarkCallback(ResolverNetdCallbacks resNetdCallbacks) {
+    return [resNetdCallbacks = std::move(resNetdCallbacks)](uint32_t netId, uint32_t uid) mutable {
+        return getDnsMark(resNetdCallbacks, netId, uid);
+    };
+}
+
+// getNameServers must be thread-safe since it is used in NameServersCallback.
+std::unique_ptr<std::vector<std::string>> getNameServers(DnsResolver& dnsResolv, uint32_t netId) {
+    std::vector<std::string> res_servers;
+    std::vector<std::string> res_domains;
+    std::vector<std::string> res_tls_servers;
+    std::vector<std::string> res_interface_names;
+    std::vector<int32_t> params32;
+    std::vector<int32_t> stats32;
+    int32_t wait_for_pending_req_timeout_count32 = 0;
+    // Safety: getResolverInfo is thread-safe since in its implementation, mutex
+    // lock is applied when shared information is accessed.
+    dnsResolv.resolverCtrl.getResolverInfo(netId, &res_servers, &res_domains, &res_tls_servers,
+                                           &res_interface_names, &params32, &stats32,
+                                           &wait_for_pending_req_timeout_count32);
+    return std::make_unique<std::vector<std::string>>(std::move(res_servers));
+}
+
+// Safety: thread-safe since it is a lambda wrapper of a thread-safe function.
+NameServersCallback makeNameServersCallback(DnsResolver& dnsResolv) {
+    return [&dnsResolv](uint32_t netId) { return getNameServers(dnsResolv, netId); };
+}
+
+DnsProxy::DnsProxy(DnsMarkCallback&& dnsMarkCallback, NameServersCallback&& nameServersCallback)
+    : mServer(proxy_server_new(std::make_unique<DnsMarkCallback>(dnsMarkCallback),
+                               std::make_unique<NameServersCallback>(nameServersCallback))) {}
+
+// Default constructor depending on DnsResolver global variables.
+DnsProxy::DnsProxy()
+    : DnsProxy(makeDnsMarkCallback(android::net::gResNetdCallbacks),
+               makeNameServersCallback(*android::net::gDnsResolv)) {}
+
+void DnsProxy::configureDnsProxy(uint32_t upstreamNetId, uint32_t uid, uint32_t downstreamIfIndex,
+                                 uint16_t downstreamPort) {
+    mServer->configure_dns_proxy_ffi(upstreamNetId, uid, downstreamIfIndex, downstreamPort);
+}
+
+void DnsProxy::stopDnsProxy(uint32_t downstreamIfIndex, uint16_t downstreamPort) {
+    mServer->stop_dns_proxy_ffi(downstreamIfIndex, downstreamPort);
+}
+
+}  // namespace dns_proxy_ffi
+}  // namespace net
+}  // namespace android
diff --git a/DnsProxy.h b/DnsProxy.h
new file mode 100644
index 00000000..e8544622
--- /dev/null
+++ b/DnsProxy.h
@@ -0,0 +1,59 @@
+// Copyright 2025 The Android Open Source Project
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
+// DNS Proxy AIDL header.
+
+#pragma once
+
+#include <cstdint>
+#include <functional>
+#include <memory>
+#include <mutex>
+#include <vector>
+
+#include "DnsResolver.h"
+#include "rust/cxx.h"
+
+namespace android {
+namespace net {
+namespace dns_proxy_ffi {
+// The DnsMarkCallback implementation must be thread-safe as it is passed
+// between threads, and may be concurrently accessed.
+using DnsMarkCallback = std::function<uint32_t(uint32_t netId, uint32_t uid)>;
+// The NameServersCallback implementation must be thread-safe as it is passed
+// between threads, and may be concurrently accessed.
+using NameServersCallback =
+        std::function<std::unique_ptr<std::vector<std::string>>(uint32_t netId)>;
+
+struct DnsProxyServer;
+
+class DnsProxy {
+  public:
+    // Default constructor depending on DnsResolver global variables.
+    DnsProxy();
+    DnsProxy(DnsMarkCallback&& dnsMarkCallback, NameServersCallback&& nameServersCallback);
+
+    DnsProxy(DnsProxy const&) = delete;
+    void operator=(DnsProxy const&) = delete;
+
+    void configureDnsProxy(uint32_t upstreamNetId, uint32_t uid, uint32_t downstreamIfIndex,
+                           uint16_t downstreamPort);
+    void stopDnsProxy(uint32_t downstreamIfIndex, uint16_t downstreamPort);
+
+  private:
+    rust::Box<DnsProxyServer> mServer;
+};
+}  // namespace dns_proxy_ffi
+}  // namespace net
+}  // namespace android
diff --git a/DnsProxyListener.cpp b/DnsProxyListener.cpp
index 302cfd99..79875107 100644
--- a/DnsProxyListener.cpp
+++ b/DnsProxyListener.cpp
@@ -122,13 +122,17 @@ bool queryingViaTls(unsigned dns_netid) {
     }
 }
 
-bool hasPermissionToBypassPrivateDns(uid_t uid) {
+bool hasPermissionToBypassPrivateDns(unsigned netid, uid_t uid) {
     static_assert(AID_SYSTEM >= 0 && AID_SYSTEM < FIRST_APPLICATION_UID,
                   "Calls from AID_SYSTEM must not result in a permission check to avoid deadlock.");
     if (uid >= 0 && uid < FIRST_APPLICATION_UID) {
         return true;
     }
 
+    if (resolv_is_uid_allowed_bypass_private_dns_on_network(netid, uid)) {
+        return true;
+    }
+
     for (const char* const permission :
          {PERM_CONNECTIVITY_USE_RESTRICTED_NETWORKS, PERM_NETWORK_BYPASS_PRIVATE_DNS,
           PERM_MAINLINE_NETWORK_STACK}) {
@@ -140,7 +144,8 @@ bool hasPermissionToBypassPrivateDns(uid_t uid) {
 }
 
 void maybeFixupNetContext(android_net_context* ctx, pid_t pid) {
-    if (requestingUseLocalNameservers(ctx->flags) && !hasPermissionToBypassPrivateDns(ctx->uid)) {
+    if (requestingUseLocalNameservers(ctx->flags) &&
+        !hasPermissionToBypassPrivateDns(ctx->dns_netid, ctx->uid)) {
         // Not permitted; clear the flag.
         ctx->flags &= ~NET_CONTEXT_FLAG_USE_LOCAL_NAMESERVERS;
     }
@@ -156,6 +161,18 @@ void maybeFixupNetContext(android_net_context* ctx, pid_t pid) {
     ctx->pid = pid;
 }
 
+uint32_t maybeFixupFlags(int flags, uid_t uid) {
+    if (uid >= FIRST_APPLICATION_UID) {
+        // Restrict non-public flags to privileged applications
+        flags &= ~RESOLV_TRY_ALL_USABLE_SERVERS;
+    }
+    if (flags & ANDROID_RESOLV_NO_RETRY) {
+        // Trying all usable servers does not make sense with no retry
+        flags &= ~RESOLV_TRY_ALL_USABLE_SERVERS;
+    }
+    return flags;
+}
+
 void addIpAddrWithinLimit(std::vector<std::string>* ip_addrs, const sockaddr* addr,
                           socklen_t addrlen);
 
@@ -802,7 +819,7 @@ static bool sendLenAndData(SocketClient* c, const int len, const void* data) {
 }
 
 // Returns true on success
-static bool sendhostent(SocketClient* c, hostent* hp) {
+static bool sendhostent(SocketClient* c, const hostent* hp) {
     bool success = true;
     int i;
     if (hp->h_name != nullptr) {
@@ -1081,6 +1098,7 @@ int DnsProxyListener::ResNSendCommand::runCommand(SocketClient* cli, int argc, c
         sendBE32(cli, -EINVAL);
         return -1;
     }
+    flags = maybeFixupFlags(flags, uid);
 
     const bool useLocalNameservers = checkAndClearUseLocalNameserversFlag(&netId);
 
@@ -1291,6 +1309,23 @@ int DnsProxyListener::GetHostByNameCmd::runCommand(SocketClient* cli, int argc,
         netcontext.flags |= NET_CONTEXT_FLAG_USE_LOCAL_NAMESERVERS;
     }
 
+    // Hardcode / fastpath 'localhost' resolution (ignores netid and network blocks).
+    if (name == "localhost" && af == AF_INET) {
+        static const char * const alias_list[] = { nullptr };
+        static const char loopback4[16] = { 127,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0 };  // 0-pad to v6
+        static const char * const addr_list[] = { loopback4, nullptr };
+        static const hostent hbuf = {
+            .h_name = const_cast<char*>("localhost"),
+            .h_aliases = const_cast<char**>(alias_list),
+            .h_addrtype = AF_INET,
+            .h_length = 4, // length of AF_INET address
+            .h_addr_list = const_cast<char**>(addr_list),
+        };
+        cli->sendCode(ResponseCode::DnsProxyQueryResult);  // returns 0 on success, but ignored
+        sendhostent(cli, &hbuf);  // returns 'true' on success, but ignored
+        return 0;
+    }
+
     (new GetHostByNameHandler(cli, name, af, netcontext))->spawn();
     return 0;
 }
diff --git a/DnsResolverService.cpp b/DnsResolverService.cpp
index 6750037c..971e502c 100644
--- a/DnsResolverService.cpp
+++ b/DnsResolverService.cpp
@@ -309,5 +309,15 @@ binder_status_t DnsResolverService::dump(int fd, const char** args, uint32_t num
     return statusFromErrcode(resolv_set_options(netId, options));
 }
 
+::ndk::ScopedAStatus DnsResolverService::setAllowBypassPrivateDnsOnNetwork(int32_t netId, int uid,
+                                                                           bool allowed) {
+    // Locking happens in res_cache.cpp functions.
+    ENFORCE_NETWORK_STACK_PERMISSIONS();
+
+    int res = resolv_set_allow_bypass_private_dns_on_network(netId, uid, allowed);
+
+    return statusFromErrcode(res);
+}
+
 }  // namespace net
 }  // namespace android
diff --git a/DnsResolverService.h b/DnsResolverService.h
index 8acd2319..951d3ed9 100644
--- a/DnsResolverService.h
+++ b/DnsResolverService.h
@@ -43,6 +43,8 @@ class DnsResolverService : public aidl::android::net::BnDnsResolver {
             const std::shared_ptr<
                     aidl::android::net::resolv::aidl::IDnsResolverUnsolicitedEventListener>&
                     listener) override;
+    ::ndk::ScopedAStatus setAllowBypassPrivateDnsOnNetwork(int32_t netId, int uid,
+                                                           bool allowed) override;
 
     // Resolver commands.
     ::ndk::ScopedAStatus setResolverConfiguration(
diff --git a/apex/Android.bp b/apex/Android.bp
index 92b96870..af843f7f 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -59,6 +59,11 @@ apex {
     // - build artifacts (lib/javalib/bin) against Android 10 SDK
     //   so that the artifacts can run.
     defaults: ["q-launched-dcla-enabled-apex-module"],
+
+    licenses: [
+        "packages_modules_DnsResolver_license",
+        "opensourcerequest",
+    ],
 }
 
 apex_key {
@@ -69,6 +74,6 @@ apex_key {
 
 android_app_certificate {
     name: "com.android.resolv.certificate",
-    // will use cert.pk8 and cert.x509.pem
-    certificate: "testcert",
+    // will use com.android.resolv.pk8 and com.android.resolv.x509.pem
+    certificate: "com.android.resolv",
 }
diff --git a/apex/testcert.pk8 b/apex/com.android.resolv.pk8
similarity index 100%
rename from apex/testcert.pk8
rename to apex/com.android.resolv.pk8
diff --git a/apex/testcert.x509.pem b/apex/com.android.resolv.x509.pem
similarity index 100%
rename from apex/testcert.x509.pem
rename to apex/com.android.resolv.x509.pem
diff --git a/dns_proxy/Cargo.toml b/dns_proxy/Cargo.toml
new file mode 100644
index 00000000..37afa5e9
--- /dev/null
+++ b/dns_proxy/Cargo.toml
@@ -0,0 +1,50 @@
+# Copyright 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+#! dns-proxy cargo build.
+
+[package]
+edition = "2021"
+rust-version = "1.84"
+name = "android_dns_proxy"
+version = "0.0.1"
+
+[dependencies]
+android_logger = { version = "^0.14.1", optional = true }
+async-trait = "^0.1.86"
+bytes = "^1.10"
+cxx = { version = "^1.0", optional = true }
+futures = "^0.3.31"
+log = "^0.4.25"
+mockall = "^0.13.1"
+num_enum = "^0.7.3"
+nix = { version = "^0.29.0", features = ["fs", "net", "user"] }
+rand = { version = "^0.9.1", features = ["std", "std_rng"] }
+socket2 = "0.5.8"
+thiserror = "^2.0.11"
+tokio = { version = "^1.42.0", features = ["macros", "net", "rt", "rt-multi-thread", "sync", "time"] }
+
+[features]
+default = []
+android-ffi = ["dep:android_logger", "dep:cxx"]
+
+[lib]
+name = "android_dns_proxy"
+path = "lib.rs"
+
+# It follows the default Rust lints on Android. (Ref: build/soong/rust/config/lints.go)
+[lints.rust]
+missing_docs = "deny"
+unsafe_op_in_unsafe_fn = "deny"
+warnings = "deny"
diff --git a/dns_proxy/ffi.rs b/dns_proxy/ffi.rs
new file mode 100644
index 00000000..40b3f473
--- /dev/null
+++ b/dns_proxy/ffi.rs
@@ -0,0 +1,158 @@
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
+//! DNS Proxy C FFI .
+
+use std::net::IpAddr;
+
+use cxx::UniquePtr;
+
+use crate::server::NetContextClient;
+use crate::server::Server;
+use crate::server::UpstreamParam;
+
+#[cxx::bridge(namespace = "android::net::dns_proxy_ffi")]
+#[allow(clippy::needless_maybe_sized)]
+mod cpp2rust {
+    unsafe extern "C++" {
+        include!("dns_proxy/net_context_client.h");
+
+        type DnsMarkCallback;
+        type NameServersCallback;
+
+        /// Gets the DNS mark given the net_id of the DNS and uid of the requesting app.
+        fn get_dns_mark(callback: &DnsMarkCallback, net_id: u32, uid: u32) -> u32;
+
+        /// Gets the nameservers given the net_id of the DNS.
+        ///
+        /// Returns the vector of IP addresses literals (e.g.: {"8.8.8.8"})
+        /// return value wrapped in UniquePtr since rust cannot obtain a C++ vector by value.
+        fn get_name_servers(
+            callback: &NameServersCallback,
+            net_id: u32,
+        ) -> UniquePtr<CxxVector<CxxString>>;
+    }
+    extern "Rust" {
+        type DnsProxyServer;
+
+        /// Constructs the DNS proxy server.
+        /// Returns a pointer to the DNS proxy instance.
+        fn proxy_server_new(
+            dns_mark_callback: UniquePtr<DnsMarkCallback>,
+            name_server_callback: UniquePtr<NameServersCallback>,
+        ) -> Box<DnsProxyServer>;
+
+        /// Starts or updates the DNS proxy for an interface on a port.
+        fn configure_dns_proxy_ffi(
+            self: &DnsProxyServer,
+            upstream_net_id: u32,
+            uid: u32,
+            downstream_if_index: u32,
+            downstream_port: u16,
+        );
+
+        /// Stops the DNS proxy for an interface on a port.
+        fn stop_dns_proxy_ffi(
+            self: &DnsProxyServer,
+            downstream_if_index: u32,
+            downstream_port: u16,
+        );
+    }
+}
+
+// Safety: The C++ code which constructs the callback must guarantee that it can be moved between
+// threads: no usage of thread-local resources.
+unsafe impl Send for cpp2rust::DnsMarkCallback {}
+// Safety: The C++ code which constructs the callback must guarantee that it can be concurrently
+// referenced from different threads.
+unsafe impl Sync for cpp2rust::DnsMarkCallback {}
+// Safety: The C++ code which constructs the callback must guarantee that it can be moved between
+// threads: no usage of thread-local resources.
+unsafe impl Send for cpp2rust::NameServersCallback {}
+// Safety: The C++ code which constructs the callback must guarantee that it can be concurrently
+// referenced from different threads.
+unsafe impl Sync for cpp2rust::NameServersCallback {}
+
+struct AndroidNetContextClient {
+    dns_mark_callback: UniquePtr<cpp2rust::DnsMarkCallback>,
+    name_servers_callback: UniquePtr<cpp2rust::NameServersCallback>,
+}
+
+impl AndroidNetContextClient {
+    fn new(
+        dns_mark_callback: UniquePtr<cpp2rust::DnsMarkCallback>,
+        name_servers_callback: UniquePtr<cpp2rust::NameServersCallback>,
+    ) -> Self {
+        Self { dns_mark_callback, name_servers_callback }
+    }
+}
+
+// Manual Debug implementation required for ContextClient trait.
+impl std::fmt::Debug for AndroidNetContextClient {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("AndroidNetContextClient").finish()
+    }
+}
+
+impl NetContextClient for AndroidNetContextClient {
+    fn get_dns_mark(&self, upstream_param: &UpstreamParam) -> u32 {
+        let callback = self.dns_mark_callback.as_ref().expect("DNS mark callback pointer is null");
+        cpp2rust::get_dns_mark(callback, upstream_param.upstream_net_id, upstream_param.uid)
+    }
+
+    fn get_name_servers(&self, upstream_param: &UpstreamParam) -> Vec<std::net::IpAddr> {
+        let callback =
+            self.name_servers_callback.as_ref().expect("Name server callback pointer is null");
+        cpp2rust::get_name_servers(callback, upstream_param.upstream_net_id)
+            .into_iter()
+            .map(|ns| {
+                ns.to_string_lossy()
+                    .into_owned()
+                    .parse::<IpAddr>()
+                    .expect("Name server address parse fail")
+            })
+            .collect()
+    }
+}
+
+type DnsProxyServer = Server; // Opaque type required for FFI.
+
+fn proxy_server_new(
+    net_context_callback: UniquePtr<cpp2rust::DnsMarkCallback>,
+    name_server_callback: UniquePtr<cpp2rust::NameServersCallback>,
+) -> Box<DnsProxyServer> {
+    Box::new(
+        Server::new(AndroidNetContextClient::new(net_context_callback, name_server_callback))
+            .expect("DNS proxy start failed"),
+    )
+}
+
+impl DnsProxyServer {
+    fn configure_dns_proxy_ffi(
+        &self,
+        upstream_net_id: u32,
+        uid: u32,
+        downstream_if_index: u32,
+        downstream_port: u16,
+    ) {
+        self.configure_dns_proxy(upstream_net_id, uid, downstream_if_index, downstream_port)
+            .expect("Configure DNS proxy failed")
+    }
+
+    fn stop_dns_proxy_ffi(&self, downstream_if_index: u32, downstream_port: u16) {
+        self.stop_dns_proxy(downstream_if_index, downstream_port).expect("Stop DNS proxy failed")
+    }
+}
diff --git a/dns_proxy/lib.rs b/dns_proxy/lib.rs
new file mode 100644
index 00000000..8035713b
--- /dev/null
+++ b/dns_proxy/lib.rs
@@ -0,0 +1,24 @@
+// Copyright 2025 The Android Open Source Project
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
+//! DNS proxy for the Android DnsResolver module.
+
+// Some code may not be used during the development.
+// TODO (b/379992903): Remove this after library is completed.
+#![allow(dead_code)]
+
+#[cfg(feature = "android-ffi")]
+mod ffi;
+pub(crate) mod packet;
+mod server;
diff --git a/dns_proxy/net_context_client.cpp b/dns_proxy/net_context_client.cpp
new file mode 100644
index 00000000..6d14a098
--- /dev/null
+++ b/dns_proxy/net_context_client.cpp
@@ -0,0 +1,35 @@
+// Copyright 2025 The Android Open Source Project
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
+//! Implementation of FFI for net context. Build under libnetd_resolv.
+
+#include "net_context_client.h"
+#include "dns_proxy_cxx_bridge.rs.h"
+
+namespace android {
+namespace net {
+namespace dns_proxy_ffi {
+
+uint32_t get_dns_mark(const DnsMarkCallback& callback, uint32_t netId, uint32_t uid) {
+    return callback(netId, uid);
+}
+
+std::unique_ptr<std::vector<std::string>> get_name_servers(const NameServersCallback& callback,
+                                                           uint32_t netId) {
+    return callback(netId);
+}
+
+}  // namespace dns_proxy_ffi
+}  // namespace net
+}  // namespace android
diff --git a/dns_proxy/net_context_client.h b/dns_proxy/net_context_client.h
new file mode 100644
index 00000000..1490f292
--- /dev/null
+++ b/dns_proxy/net_context_client.h
@@ -0,0 +1,36 @@
+// Copyright 2025 The Android Open Source Project
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
+// C++-side signature of cpp2rust cxx bridge in dns_proxy/ffi.rs.
+
+#pragma once
+
+#include <cstdint>
+#include <functional>
+#include <memory>
+#include <vector>
+
+#include "DnsProxy.h"
+
+namespace android {
+namespace net {
+namespace dns_proxy_ffi {
+uint32_t get_dns_mark(const DnsMarkCallback& callback, uint32_t netId, uint32_t uid);
+// Signature follows definition in dns_proxy/ffi.rs. The unique pointer wrapper
+// is required since C++ vector cannot be passed to rust directly.
+std::unique_ptr<std::vector<std::string>> get_name_servers(const NameServersCallback& callback,
+                                                           uint32_t netId);
+}  // namespace dns_proxy_ffi
+}  // namespace net
+}  // namespace android
diff --git a/dns_proxy/packet.rs b/dns_proxy/packet.rs
new file mode 100644
index 00000000..3d26465e
--- /dev/null
+++ b/dns_proxy/packet.rs
@@ -0,0 +1,345 @@
+// Copyright 2025 The Android Open Source Project
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
+//! DNS packet definition.
+
+use bytes::Buf;
+use bytes::BufMut;
+use num_enum::FromPrimitive;
+use num_enum::IntoPrimitive;
+use thiserror::Error;
+
+const DNS_HEADER_LEN: usize = 12;
+
+/// Error type for packet
+#[derive(Clone, Debug, Error, PartialEq, Eq)]
+pub enum PacketError {
+    /// Packet shorter than header size
+    #[error("Packet shorter than header size")]
+    PacketTooShort,
+}
+
+/// Result type for packet
+pub type PacketResult<T> = std::result::Result<T, PacketError>;
+
+/// A DnsPacket is a wrapping of a DNS packet in bytes with its header parsed.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct DnsPacket {
+    /// DNS Header
+    header: DnsHeader,
+    /// The raw packet, including the header
+    raw: Vec<u8>,
+}
+
+/// Parse raw as DNS packet. Only the validity of the header is checked.
+impl TryFrom<Vec<u8>> for DnsPacket {
+    type Error = PacketError;
+    fn try_from(raw: Vec<u8>) -> PacketResult<Self> {
+        let header: DnsHeader = raw.as_slice().try_into()?;
+        Ok(Self { header, raw })
+    }
+}
+
+impl DnsPacket {
+    /// Get the raw packet.
+    pub fn as_bytes(&self) -> &[u8] {
+        &self.raw
+    }
+
+    /// Gets the header.
+    pub fn header(&self) -> &DnsHeader {
+        &self.header
+    }
+}
+
+/// A DnsHeader is parsed from the first 12 bytes of a packet datagram with
+/// the following fields:
+///
+///  1  1  1  1  1  1
+///  5  4  3  2  1  0  9  8  7  6  5  4  3  2  1  0
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                      ID                       |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |QR|   OPCODE  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                    QDCOUNT                    |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                    ANCOUNT                    |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                    NSCOUNT                    |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                    ARCOUNT                    |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+pub(crate) struct DnsHeader {
+    /// ID
+    pub id: u16,
+    // flags:
+    /// QR is response (or query)
+    pub qr_is_response: bool,
+    /// Opcode
+    pub opcode: Opcode,
+    /// AA: Authoritative answer
+    pub aa: bool,
+    /// TC: Truncation
+    pub tc: bool,
+    /// RD: Recursion Desired
+    pub rd: bool,
+    /// RA: Recursion Available
+    pub ra: bool,
+    /// AD: Authentic Data
+    pub ad: bool,
+    /// CD: Checking Disabled
+    pub cd: bool,
+    /// Rcode
+    pub rcode: Rcode,
+    /// Query count
+    pub qd_count: u16,
+    /// Answer count
+    pub an_count: u16,
+    /// Name server resource records count
+    pub ns_count: u16,
+    /// Additional records count
+    pub ar_count: u16,
+}
+
+impl TryFrom<&[u8]> for DnsHeader {
+    type Error = PacketError;
+    fn try_from(mut raw: &[u8]) -> PacketResult<Self> {
+        if raw.len() < DNS_HEADER_LEN {
+            return Err(PacketError::PacketTooShort);
+        }
+
+        let id = raw.get_u16();
+        let flags = raw.get_u16();
+        let qd_count = raw.get_u16();
+        let an_count = raw.get_u16();
+        let ns_count = raw.get_u16();
+        let ar_count = raw.get_u16();
+        Ok(Self {
+            id,
+            qr_is_response: flags >> 15 & 0x1 != 0,
+            opcode: (flags >> 11 & 0xf).into(),
+            aa: flags >> 10 & 0x1 != 0,
+            tc: flags >> 9 & 0x1 != 0,
+            rd: flags >> 8 & 0x1 != 0,
+            ra: flags >> 7 & 0x1 != 0,
+            ad: flags >> 5 & 0x1 != 0,
+            cd: flags >> 4 & 0x1 != 0,
+            rcode: (flags & 0xf).into(),
+            qd_count,
+            an_count,
+            ns_count,
+            ar_count,
+        })
+    }
+}
+
+impl From<DnsHeader> for [u8; DNS_HEADER_LEN] {
+    fn from(value: DnsHeader) -> Self {
+        let mut bytes = [0u8; DNS_HEADER_LEN];
+        let mut bytes_mut = bytes.as_mut_slice();
+        bytes_mut.put_u16(value.id);
+        let flags: u16 = (value.qr_is_response as u16) << 15
+            | u16::from(value.opcode) << 11
+            | (value.aa as u16) << 10
+            | (value.tc as u16) << 9
+            | (value.rd as u16) << 8
+            | (value.ra as u16) << 7
+            | (value.ad as u16) << 5
+            | (value.cd as u16) << 4
+            | u16::from(value.rcode);
+        bytes_mut.put_u16(flags);
+        bytes_mut.put_u16(value.qd_count);
+        bytes_mut.put_u16(value.an_count);
+        bytes_mut.put_u16(value.ns_count);
+        bytes_mut.put_u16(value.ar_count);
+        bytes
+    }
+}
+
+/// OPCODE of a DNS packet. Ref: RFC6895
+#[repr(u16)]
+#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
+pub(crate) enum Opcode {
+    /// DNS Query
+    Query = 0,
+    /// Inverse DNS query
+    IQuery = 1,
+    /// Server status request
+    Status = 2,
+    /// Notification of zone change (Ref: RFC1996)
+    Notify = 4,
+    /// Dynamic DNS updates (Ref: RFC2136)
+    Update = 5,
+    /// Other unspecified Opcode
+    #[num_enum(catch_all)]
+    Unspecified(u16),
+}
+
+/// RCODE to a DNS Opcode::Query and valid response to it.
+#[repr(u16)]
+#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
+pub(crate) enum Rcode {
+    /// No error
+    NoError = 0,
+    /// Format error
+    FormErr = 1,
+    /// Server failure
+    ServFail = 2,
+    /// Name error
+    NXDomain = 3,
+    /// Not implemented
+    NotImp = 4,
+    /// Refused
+    Refused = 5,
+    /// Domain ought not to exist but does exist
+    YXDomain = 6,
+    /// RR ought not to exist but does exist
+    YXRRSet = 7,
+    /// RR ought to exist but does not exist
+    NXRRSet = 8,
+    /// Server is not authoritative for the zone
+    NotAuth = 9,
+    /// Name used in the prerequisite or update section is not within the zone
+    NotZone = 10,
+    /// Other unspecified Rcode
+    #[num_enum(catch_all)]
+    Unspecified(u16),
+}
+
+#[cfg(test)]
+pub(crate) mod tests {
+    use super::*;
+
+    /// A valid DNS query for test.
+    pub const TEST_VALID_DNS_QUERY: [u8; 49] = [
+        0x3b, 0x1e, // ID
+        0x01,
+        0x20, // flags (QR=0, opcode=Query, AA=0, TC=0, RD=1, RA=0, AD=1, CD=0, RCODE=NOERROR)
+        0x00, 0x01, // query count
+        0x00, 0x00, // answer count
+        0x00, 0x00, // name server resource records count
+        0x00, 0x01, // additional records count
+        0x04, 0x63, 0x73, 0x64, 0x6e, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
+        0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x4f,
+        0x51, 0x32, 0x69, 0x09, 0x11, 0x9e, 0x21,
+    ];
+
+    #[test]
+    fn test_query_packet_parse() {
+        let test_query_packet = DnsPacket::try_from(TEST_VALID_DNS_QUERY.to_vec()).unwrap();
+        assert_eq!(test_query_packet.as_bytes(), TEST_VALID_DNS_QUERY.as_slice());
+    }
+
+    #[test]
+    fn test_too_short_packet_parse() {
+        let short_packet = TEST_VALID_DNS_QUERY[0..11].to_vec();
+        assert_eq!(DnsPacket::try_from(short_packet).unwrap_err(), PacketError::PacketTooShort);
+    }
+
+    // Tests that for a valid DnsHeader, it is invariant after a serialization and parse cycle.
+    #[test]
+    fn test_dns_header_serde_invariant() {
+        let header_bytes: [u8; DNS_HEADER_LEN] = [
+            0xde,
+            0xad, // DNS ID
+            0b1010_1101,
+            0b0010_1000, // DNS flags
+            0x00,
+            0x01, // QD_COUNT
+            0x00,
+            0x00, // AN_COUNT
+            0x00,
+            0x00, // NS_COUNT
+            0x00,
+            0x01, // AR_COUNT
+        ];
+        let header = DnsHeader {
+            id: 0xdead,
+            qr_is_response: true,
+            opcode: Opcode::Update,
+            aa: true,
+            tc: false,
+            rd: true,
+            ra: false,
+            ad: true,
+            cd: false,
+            rcode: Rcode::NXRRSet,
+            qd_count: 1,
+            an_count: 0,
+            ns_count: 0,
+            ar_count: 1,
+        };
+        assert_eq!(DnsHeader::try_from(header_bytes.as_slice()).unwrap(), header);
+        assert_eq!(header_bytes, <[u8; DNS_HEADER_LEN]>::from(header));
+    }
+
+    /// Tests that for a DnsHeader with unspecified OPCODE and RCODE does not throw error.
+    #[test]
+    fn test_dns_header_unspecified_values() {
+        let header_bytes: [u8; DNS_HEADER_LEN] = [
+            0xde,
+            0xad, // DNS ID
+            0b1110_1101,
+            0b0010_1110, // DNS flags
+            0x00,
+            0x02, // QD_COUNT
+            0x00,
+            0x00, // AN_COUNT
+            0x00,
+            0x03, // NS_COUNT
+            0x00,
+            0x01, // AR_COUNT
+        ];
+        let header = DnsHeader {
+            id: 0xdead,
+            qr_is_response: true,
+            opcode: Opcode::Unspecified(0b1101),
+            aa: true,
+            tc: false,
+            rd: true,
+            ra: false,
+            ad: true,
+            cd: false,
+            rcode: Rcode::Unspecified(0b1110),
+            qd_count: 2,
+            an_count: 0,
+            ns_count: 3,
+            ar_count: 1,
+        };
+        assert_eq!(DnsHeader::try_from(header_bytes.as_slice()).unwrap(), header);
+        assert_eq!(header_bytes, <[u8; DNS_HEADER_LEN]>::from(header));
+    }
+
+    /// Tests that a packet is rejected when it is too short.
+    #[test]
+    fn test_dns_header_short() {
+        let header_bytes: [u8; DNS_HEADER_LEN - 1] = [
+            0xde,
+            0xad, // DNS ID
+            0b1010_1101,
+            0b0010_1000, // DNS flags
+            0x00,
+            0x01, // QD_COUNT
+            0x00,
+            0x00, // AN_COUNT
+            0x00,
+            0x00, // NS_COUNT
+            0x00,
+        ];
+
+        DnsHeader::try_from(header_bytes.as_slice()).unwrap_err();
+    }
+}
diff --git a/dns_proxy/server.rs b/dns_proxy/server.rs
new file mode 100644
index 00000000..e5074a87
--- /dev/null
+++ b/dns_proxy/server.rs
@@ -0,0 +1,235 @@
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
+//! DNS proxy server implementation.
+
+use std::io::Error as IoError;
+use std::net::IpAddr;
+use std::thread;
+
+#[cfg(test)]
+use mockall::automock;
+use nix::errno::Errno;
+use thiserror::Error;
+use tokio::runtime::Builder as RuntimeBuilder;
+use tokio::sync::mpsc;
+use tokio::sync::mpsc::error::SendError;
+use tokio::sync::oneshot;
+use tokio::sync::oneshot::error::RecvError;
+
+use crate::packet::PacketError;
+
+mod driver;
+use driver::Driver;
+use driver::UdpDnsQuery;
+
+// TODO: clean up and reduce the number of error types.
+/// Error type for server
+#[derive(Debug, Error)]
+pub enum Error {
+    /// Io Errors:
+    #[error(transparent)]
+    Io(#[from] IoError),
+    #[error(transparent)]
+    Errno(#[from] Errno),
+    /// Command send error:
+    #[error(transparent)]
+    CommandSend(#[from] SendError<Command>),
+    /// DNS response does not match query sent
+    #[error("DNS response does not match query sent")]
+    DnsResponseMismatch,
+    /// No name server on upstream
+    #[error("No name server on upstream")]
+    NoNameServer,
+    /// Packet error
+    #[error(transparent)]
+    Packet(#[from] PacketError),
+    /// Query send error:
+    #[error("Query send error: {0}")]
+    QuerySend(String),
+    /// Receive response error:
+    #[error(transparent)]
+    ReceiveResponse(#[from] RecvError),
+    /// Server already stopped
+    #[error("Server already stopped")]
+    ServerStopped,
+}
+
+// Manual implementation required since UdpDnsQuery is not `Send`.
+impl From<SendError<UdpDnsQuery>> for Error {
+    fn from(e: SendError<UdpDnsQuery>) -> Self {
+        Error::QuerySend(e.to_string())
+    }
+}
+
+/// Result type for server
+pub type Result<T> = std::result::Result<T, Error>;
+
+/// DownstreamIndexPort is the pair of interface index and port number that uniquely
+/// identifies a downstream.
+#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
+pub(super) struct DownstreamIndexPort {
+    pub if_index: u32,
+    pub port: u16,
+}
+
+impl DownstreamIndexPort {
+    /// Constructor.
+    pub fn new(if_index: u32, port: u16) -> Self {
+        Self { if_index, port }
+    }
+}
+
+/// Commands for controlling Server
+#[derive(Debug)]
+pub(crate) enum Command {
+    /// Start or update the DNS proxy on the DownstreamIndexPort pair with
+    /// configuration parameters for upstream.
+    ConfigureDnsProxy {
+        /// The interface index and port number pair of the downstream.
+        index_port: DownstreamIndexPort,
+        /// The configuration parameters to be used to retrrieve net context when building upstram.
+        upstream_param: UpstreamParam,
+        /// Sender for the result of the command.
+        response_tx: oneshot::Sender<Result<()>>,
+    },
+    /// Stops the DNS proxy on the DownstreamIndexPort pair.
+    StopDnsProxy {
+        /// The interface index and port number pair of the downstream.
+        index_port: DownstreamIndexPort,
+        /// Sender for the result of the command.
+        response_tx: oneshot::Sender<Result<()>>,
+    },
+    /// Forwards the UDP query
+    ForwardUdpQuery(UdpDnsQuery),
+}
+
+/// Parameters to configure upstream, which is used to retrieve net context when
+/// pakcets are forwarded.
+#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+pub(super) struct UpstreamParam {
+    /// The UID on behalf of which to forward packets received on this downstrem interface.
+    pub uid: u32,
+    /// The network ID of the upstream network for sending DNS queries.
+    pub upstream_net_id: u32,
+}
+
+impl UpstreamParam {
+    /// Constructor.
+    pub fn new(uid: u32, upstream_net_id: u32) -> Self {
+        Self { uid, upstream_net_id }
+    }
+}
+
+/// NetContextClient gets the net context for upstream configuration.
+#[cfg_attr(test, automock)]
+pub(crate) trait NetContextClient: Send + Sync + std::fmt::Debug {
+    /// Returns the name servers given |upstream_param|.
+    fn get_name_servers(&self, upstream_param: &UpstreamParam) -> Vec<IpAddr>;
+
+    /// Returns the DNS fwmark for the upstream sockets.
+    fn get_dns_mark(&self, upstream_param: &UpstreamParam) -> u32;
+}
+
+/// Interface class for operating with DNS Proxy Server.
+#[derive(Debug)]
+pub struct Server {
+    command_tx: mpsc::Sender<Command>,
+    join_handle: thread::JoinHandle<()>,
+}
+
+impl Server {
+    /// Creates a server running a current thread runtime.
+    pub fn new(net_context_client: impl NetContextClient + 'static) -> Result<Server> {
+        let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;
+        let (command_tx, command_rx) = mpsc::channel(100 /* capacity */);
+        let weak_command_tx = command_tx.clone().downgrade();
+        let join_handle = thread::spawn(move || {
+            runtime.block_on(async {
+                Driver::new(net_context_client, weak_command_tx, command_rx).drive().await
+            });
+        });
+        Ok(Server { command_tx, join_handle })
+    }
+
+    /// Stops Server, return after the Driver stops.
+    pub fn stop(self) {
+        drop(self.command_tx);
+        let _ = self.join_handle.join();
+    }
+
+    /// Configures the DNS proxy and blocks the calling thread until the operation completes.
+    pub fn configure_dns_proxy(
+        &self,
+        upstream_net_id: u32,
+        uid: u32,
+        downstream_if_index: u32,
+        downstream_port: u16,
+    ) -> Result<()> {
+        let (response_tx, response_rx) = oneshot::channel();
+        self.command_tx.blocking_send(Command::ConfigureDnsProxy {
+            index_port: DownstreamIndexPort::new(downstream_if_index, downstream_port),
+            upstream_param: UpstreamParam::new(uid, upstream_net_id),
+            response_tx,
+        })?;
+        response_rx.blocking_recv()?
+    }
+
+    // Stops DNS proxy on the interface-port pair.
+    pub fn stop_dns_proxy(&self, downstream_if_index: u32, downstream_port: u16) -> Result<()> {
+        let (response_tx, response_rx) = oneshot::channel();
+        self.command_tx.blocking_send(Command::StopDnsProxy {
+            index_port: DownstreamIndexPort::new(downstream_if_index, downstream_port),
+            response_tx,
+        })?;
+        response_rx.blocking_recv()?
+    }
+}
+
+#[cfg(test)]
+pub mod tests {
+    use std::sync::atomic::AtomicU16;
+
+    use super::*;
+
+    static TEST_PORT: AtomicU16 = AtomicU16::new(10000);
+
+    /// Gets the next port number to be used by the unit test
+    pub fn next_test_port() -> u16 {
+        TEST_PORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
+    }
+
+    /// Checks that the server can be created and deleted.
+    #[test]
+    fn server_new_delete() {
+        let server = Server::new(MockNetContextClient::new()).unwrap();
+        server.stop();
+    }
+
+    /// Checks that the server can be created, added with a downstream, and deleted.
+    #[test]
+    fn server_new_listen_delete() {
+        let server = Server::new(MockNetContextClient::new()).unwrap();
+        let test_port = next_test_port();
+        server
+            .configure_dns_proxy(
+                /*upstream_net_id*/ 1, /*uid*/ 1000, /*downstream_if_index*/ 1,
+                test_port,
+            )
+            .unwrap();
+        server.stop();
+    }
+}
diff --git a/dns_proxy/server/driver.rs b/dns_proxy/server/driver.rs
new file mode 100644
index 00000000..398c373f
--- /dev/null
+++ b/dns_proxy/server/driver.rs
@@ -0,0 +1,332 @@
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
+//! Provides a backing task to implement a Server
+
+use std::collections::hash_map::Entry as HashMapEntry;
+use std::collections::HashMap;
+use std::net::IpAddr;
+use std::net::Ipv6Addr;
+use std::net::SocketAddr;
+use std::os::fd::AsFd;
+use std::os::fd::AsRawFd;
+use std::sync::Arc;
+use std::sync::Weak;
+
+use log::error;
+use log::info;
+use nix::libc::c_int;
+use nix::libc::setsockopt;
+use nix::sys::socket::recv;
+use nix::sys::socket::MsgFlags;
+use rand::rngs::ThreadRng;
+use rand::seq::IndexedRandom;
+use socket2::Domain;
+use socket2::Protocol;
+use socket2::Socket;
+use socket2::Type;
+use tokio::net::UdpSocket;
+use tokio::sync::mpsc;
+use tokio::task::JoinHandle;
+
+use crate::packet::DnsPacket;
+
+use super::Command;
+use super::DownstreamIndexPort;
+use super::Error;
+use super::NetContextClient;
+use super::Result;
+use super::UpstreamParam;
+
+// TODO(b/409455084): workaround while waiting for upstream changes.
+const SO_BINDTOIFINDEX: c_int = 62;
+
+/// UdpDnsQuery is a DNS query packet with client address and downstream information attached.
+#[derive(Debug)]
+pub(crate) struct UdpDnsQuery {
+    /// The query packet received from the client.
+    query_packet: DnsPacket,
+    /// the interface and port of downstream from where query is received.
+    index_port: DownstreamIndexPort,
+    /// The address of the client, used to send reply back to client.
+    client_addr: SocketAddr,
+    /// A weak reference to the socket to be used to send reply back to client.
+    resp_socket: Weak<UdpSocket>,
+}
+
+#[derive(Debug)]
+pub(super) struct Driver<C: NetContextClient> {
+    /// NetContext client
+    net_context_client: C,
+    /// Weak Command sender
+    weak_command_tx: mpsc::WeakSender<Command>,
+    /// Command receiver.
+    command_rx: mpsc::Receiver<Command>,
+    /// Map of DownstreamIndexPort pair to the upstream parameters.
+    upstream_map: HashMap<DownstreamIndexPort, UpstreamParam>,
+    /// Map of DownstreamIndexPort pair to the handle of UDP socket it is listening to.
+    downstream_task_handles_map: HashMap<DownstreamIndexPort, JoinHandle<Result<()>>>,
+    /// Random number generator
+    rng: ThreadRng,
+}
+
+impl<C: NetContextClient> Driver<C> {
+    pub fn new(
+        net_context_client: C,
+        weak_command_tx: mpsc::WeakSender<Command>,
+        command_rx: mpsc::Receiver<Command>,
+    ) -> Self {
+        Self {
+            net_context_client,
+            weak_command_tx,
+            command_rx,
+            upstream_map: HashMap::new(),
+            downstream_task_handles_map: HashMap::new(),
+            rng: rand::rng(),
+        }
+    }
+
+    pub async fn drive(mut self) -> Option<()> {
+        loop {
+            self.drive_once().await?;
+        }
+    }
+
+    /// Drive the event once. Returns `Some(())` if the loop shall continue,
+    /// None if it shall terminate.
+    async fn drive_once(&mut self) -> Option<()> {
+        if let Some(command) = self.command_rx.recv().await {
+            self.handle_cmd(command).await
+        } else {
+            info!("Exit DnsProxy due to all DnsProxyCommand transceiver out of scope");
+            self.stop_listen_on_all_ports().await;
+            None
+        }
+    }
+
+    async fn handle_cmd(&mut self, cmd: Command) -> Option<()> {
+        match cmd {
+            Command::ConfigureDnsProxy { index_port, upstream_param, response_tx } => {
+                let _ = response_tx
+                    .send(self.handle_configure_dns_proxy_cmd(index_port, upstream_param));
+                Some(())
+            }
+            Command::StopDnsProxy { index_port, response_tx } => {
+                let _ = response_tx.send(self.handle_stop_dns_proxy_cmd(&index_port).await);
+                Some(())
+            }
+            Command::ForwardUdpQuery(udp_dns_query) => {
+                if let Err(e) = self.handle_udp_dns_query(udp_dns_query) {
+                    error!("Error handling UDP query: {}", e);
+                }
+                Some(())
+            }
+        }
+    }
+
+    fn handle_configure_dns_proxy_cmd(
+        &mut self,
+        index_port: DownstreamIndexPort,
+        upstream_param: UpstreamParam,
+    ) -> Result<()> {
+        self.upstream_map.insert(index_port, upstream_param);
+        if let HashMapEntry::Vacant(vacant_entry) =
+            self.downstream_task_handles_map.entry(index_port)
+        {
+            let socket = build_udp_socket(&index_port)?;
+            let handle = spawn_downstream_udp_socket(
+                self.weak_command_tx.clone(),
+                Arc::new(socket),
+                index_port,
+            );
+            vacant_entry.insert(handle);
+        }
+        Ok(())
+    }
+
+    async fn handle_stop_dns_proxy_cmd(&mut self, index_port: &DownstreamIndexPort) -> Result<()> {
+        self.upstream_map.remove(index_port);
+        if let Some(handle) = self.downstream_task_handles_map.remove(index_port) {
+            handle.abort();
+            let _ = handle.await;
+        }
+        Ok(())
+    }
+
+    async fn stop_listen_on_all_ports(&mut self) {
+        let handles: Vec<_> =
+            self.downstream_task_handles_map.drain().map(|(_, handle)| handle).collect();
+        for handle in handles {
+            handle.abort();
+            let _ = handle.await;
+        }
+    }
+
+    fn handle_udp_dns_query(&mut self, query: UdpDnsQuery) -> Result<()> {
+        let upstream_param = match self.upstream_map.get(&query.index_port) {
+            Some(p) => p.to_owned(),
+            None => return Ok(()),
+        };
+        let socket = self.configure_upstream_udp_socket(&upstream_param)?;
+        tokio::spawn(async move {
+            if let Err(e) = resolve_and_send_udp(socket, query).await {
+                error!("Error resolving and sending UDP query: {}", e);
+            }
+        });
+        Ok(())
+    }
+
+    fn configure_upstream_udp_socket(
+        &mut self,
+        upstream_param: &UpstreamParam,
+    ) -> Result<UdpSocket> {
+        let name_servers = self.net_context_client.get_name_servers(upstream_param);
+        let name_server = name_servers.choose(&mut self.rng).ok_or(Error::NoNameServer)?;
+        let domain = if name_server.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
+        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
+        socket.set_nonblocking(true)?;
+        let mark = self.net_context_client.get_dns_mark(upstream_param);
+        socket.set_mark(mark)?;
+        // TODO(b:379992903): randomize port selection.
+        socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from_bits(0)), 0).into())?;
+        socket.connect(&SocketAddr::new(*name_server, 53).into())?;
+        Ok(UdpSocket::from_std(socket.into())?)
+    }
+}
+
+fn build_udp_socket(index_port: &DownstreamIndexPort) -> Result<UdpSocket> {
+    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
+    set_downstream_sockopts(&socket, index_port.if_index)?;
+    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from_bits(0)), index_port.port).into())?;
+    Ok(UdpSocket::from_std(socket.into())?)
+}
+
+fn set_downstream_sockopts(socket: &Socket, if_index: u32) -> Result<()> {
+    socket.set_nonblocking(true)?;
+    if if_index > 0 {
+        // TODO(409455084): workaround while waiting for upstream changes.
+        // Safety: setting if_index is safe since we own the FD and if_index is fixed length.
+        unsafe {
+            setsockopt(
+                socket.as_fd().as_raw_fd(),
+                nix::libc::SOL_SOCKET,
+                SO_BINDTOIFINDEX,
+                &if_index as *const _ as *const nix::libc::c_void,
+                std::mem::size_of::<c_int>() as nix::libc::socklen_t,
+            );
+        }
+    }
+    Ok(())
+}
+
+/// UdpSocket extension trait for implementing UdpSocket functionality that is missing in
+/// tokio::net::UdpSocket.
+trait UdpSocketExt {
+    /// A version of try_recv that accepts flags.
+    ///
+    /// This function is usually paired with readable(). See UdpSocket::try_recv for details.
+    fn try_recv_flags(&self, buf: &mut [u8], flags: MsgFlags) -> std::io::Result<usize>;
+}
+
+impl UdpSocketExt for UdpSocket {
+    fn try_recv_flags(&self, buf: &mut [u8], flags: MsgFlags) -> std::io::Result<usize> {
+        // UdpSocket::try_io() is required to consume the readable readiness event of the
+        // UdpSocket. See notes on "Cancel safety" in UdpSocket::readable().
+        self.try_io(tokio::io::Interest::READABLE, || {
+            let fd = self.as_raw_fd();
+            recv(fd, buf, flags).map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
+        })
+    }
+}
+
+/// Receives an arbitrarily-sized UDP packet into an appropriately sized buffer and returns it.
+///
+/// Note that this function does not currently return DnsPacket directly as DnsPacket::try_from()
+/// errors are handled differently (i.e. they are ignored) from recv errors.
+async fn udp_recv(socket: &UdpSocket) -> Result<(Vec<u8>, SocketAddr)> {
+    // Properly supporting EDNS(0) requires query parsing. Instead, use MSG_PEEK|MSG_TRUNC to
+    // figure out the size of the incoming packet before reading it.
+    // Note that there is no async version of recv() that allows passing in flags in
+    // tokio::net::UdpSocket.
+    // TODO: move this code into a socket wrapper struct.
+    let len = loop {
+        // It is possible for readable().await? to return but for the arriving packet to fail
+        // checksum validation. As without checksum offload, validation happens only when recv() is
+        // called (usually while the packet is being copied from the skb to the user buffer). If
+        // this happens, recv() returns POSIX error EAGAIN, equivalent to io::ErrorKind::WouldBlock.
+        socket.readable().await?;
+        match socket.try_recv_flags(&mut [], MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC) {
+            Ok(len) => break len,
+            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
+            Err(e) => return Err(e.into()),
+        }
+    };
+    let mut buf = vec![0u8; len];
+    // At this point, try_recv_from() is guaranteed to pass checksum validation, as it has already
+    // been performed by recv() above.
+    // TODO: consider logging (or dropping the packet) if the actual size did not match size.
+    let (_, from) = socket.try_recv_from(&mut buf)?;
+    Ok((buf, from))
+}
+
+async fn resolve_and_send_udp(socket: UdpSocket, query: UdpDnsQuery) -> Result<()> {
+    // TODO (b:379992903): randomize DNS ID.
+    let query_dns_id = query.query_packet.header().id;
+    socket.send(query.query_packet.as_bytes()).await?;
+
+    let (buf, _) = udp_recv(&socket).await?;
+    // TODO: if try_from() or the subsequent ID comparison fails, udp_recv() should be called again
+    // until the packet is received or some timeout occurs.
+    // Alternatively, consider responding with a ServFail.
+    let response = DnsPacket::try_from(buf)?;
+    if response.header().id != query_dns_id {
+        return Err(Error::DnsResponseMismatch);
+    }
+    if let Some(resp_socket) = query.resp_socket.upgrade() {
+        resp_socket.send_to(response.as_bytes(), query.client_addr).await?;
+    }
+    Ok(())
+}
+
+/// Create downstream UDP socket that sends `UdpDnsQuery` through |query_tx|.
+fn spawn_downstream_udp_socket(
+    weak_command_tx: mpsc::WeakSender<Command>,
+    socket: Arc<UdpSocket>,
+    index_port: DownstreamIndexPort,
+) -> JoinHandle<Result<()>> {
+    tokio::spawn(async move {
+        loop {
+            let (buf, client_addr) = udp_recv(&socket).await?;
+            let query_packet = match DnsPacket::try_from(buf) {
+                Ok(query_packet) => query_packet,
+                // The received packet is not a DnsPacket. Continue.
+                Err(_) => continue,
+            };
+
+            let command_tx = match weak_command_tx.upgrade() {
+                Some(t) => t,
+                None => return Err(Error::ServerStopped),
+            };
+
+            let resp_socket = Arc::downgrade(&socket);
+            let query = UdpDnsQuery { query_packet, index_port, client_addr, resp_socket };
+
+            // If command_tx.send() fails, it means that the receiver half has been closed (i.e.
+            // the server is being stopped)..
+            command_tx.send(Command::ForwardUdpQuery(query)).await?;
+        }
+    })
+}
diff --git a/include/netd_resolv/resolv.h b/include/netd_resolv/resolv.h
index 36fa9f94..5b545a32 100644
--- a/include/netd_resolv/resolv.h
+++ b/include/netd_resolv/resolv.h
@@ -44,6 +44,19 @@
  */
 #define MARK_UNSET 0u
 
+/**
+ * Internal ResNsendFlags to query every configured DNS server to find an answer, even
+ * if some servers indicate the name cannot be resolved.
+ *
+ * Any reply that is not NOERROR, such as NXDOMAIN, or does not have answer records
+ * (NODATA), will cause the resolver to try other usable servers (servers that do not
+ * have a high failure rate), instead of returning the error immediately.
+ *
+ * This is not expected to be used by apps (it is currently restricted to UIDs below
+ * FIRST_APP_UID), so it is not part of the NDK.
+ */
+constexpr int RESOLV_TRY_ALL_USABLE_SERVERS = 1 << 31;
+
 /*
  * Passing APP_SOCKET_NONE as the app_socket in getaddrinfo, gethostbyname,
  * gethostbyaddr, res_nsend means that the query is not tied to a listening socket
diff --git a/res_cache.cpp b/res_cache.cpp
index 66053737..03fa48d5 100644
--- a/res_cache.cpp
+++ b/res_cache.cpp
@@ -1066,6 +1066,10 @@ struct NetConfig {
     std::vector<int32_t> transportTypes;
     bool metered = false;
     std::vector<std::string> interfaceNames;
+
+    // A set of UIDs which are allowed to bypass the private DNS rule on this
+    // given network.
+    std::set<uid_t> uids_allow_bypass_private_dns_set;
 };
 
 /* gets cache associated with a network, or NULL if none exists */
@@ -2140,3 +2144,25 @@ bool resolv_is_metered_network(unsigned netid) {
     }
     return false;
 }
+
+bool resolv_is_uid_allowed_bypass_private_dns_on_network(unsigned netid, uid_t uid) {
+    std::lock_guard guard(cache_mutex);
+    const auto config = find_netconfig_locked(netid);
+
+    if (config == nullptr) return false;
+    return config->uids_allow_bypass_private_dns_set.find(uid) !=
+           config->uids_allow_bypass_private_dns_set.cend();
+}
+
+int resolv_set_allow_bypass_private_dns_on_network(unsigned netid, uid_t uid, bool allowed) {
+    std::lock_guard guard(cache_mutex);
+    const auto config = find_netconfig_locked(netid);
+
+    if (config == nullptr) return -ENOENT;
+
+    if (allowed) {
+        return config->uids_allow_bypass_private_dns_set.emplace(uid).second ? 0 : -EEXIST;
+    } else {
+        return config->uids_allow_bypass_private_dns_set.erase(uid) ? 0 : -ENOENT;
+    }
+}
diff --git a/res_send.cpp b/res_send.cpp
index ae688fbb..907584f8 100644
--- a/res_send.cpp
+++ b/res_send.cpp
@@ -95,6 +95,7 @@
 #include <string.h>
 #include <time.h>
 #include <unistd.h>
+#include <numeric>
 #include <span>
 
 #include <android-base/logging.h>
@@ -450,6 +451,14 @@ static bool isClientStreamSocketClosed(std::optional<int> fd) {
     return (poll(&fds, 1, /* timeout=*/0) > 0) && (fds.revents & POLLHUP);
 }
 
+static bool isErrorOrNoDataAnswer(int rcode, span<uint8_t> ans) {
+    if (rcode != NOERROR) {
+        return true;
+    }
+    // NODATA responses have NOERROR rcode but no answer record (NODATA is not a rcode).
+    return reinterpret_cast<const HEADER*>(ans.data())->ancount == 0;
+}
+
 int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int* rcode,
               uint32_t flags, std::chrono::milliseconds sleepTimeMs) {
     LOG(DEBUG) << __func__;
@@ -478,7 +487,7 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
         IPSockAddr receivedMdnsAddr;
         resplen = send_mdns(statp, msg, ans, &terrno, rcode, &receivedMdnsAddr);
         DnsQueryEvent* mDnsQueryEvent = addDnsQueryEvent(statp->event);
-        mDnsQueryEvent->set_cache_hit(static_cast<CacheStatus>(RESOLV_CACHE_NOTFOUND));
+        mDnsQueryEvent->set_cache_hit(static_cast<CacheStatus>(RESOLV_CACHE_UNSUPPORTED));
         mDnsQueryEvent->set_latency_micros(saturate_cast<int32_t>(queryStopwatch.timeTakenUs()));
         mDnsQueryEvent->set_ip_version(ipFamilyToIPVersion(receivedMdnsAddr.family()));
         mDnsQueryEvent->set_rcode(static_cast<NsRcode>(*rcode));
@@ -584,8 +593,11 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
 
     // Send request, RETRY times, or until successful.
     int retryTimes = (flags & ANDROID_RESOLV_NO_RETRY) ? 1 : params.retry_count;
+    bool tryAllServers = (flags & RESOLV_TRY_ALL_USABLE_SERVERS);
     int useTcp = msg.size() > PACKETSZ;
     int gotsomewhere = 0;
+    int firstErrorRcode = NOERROR;
+    std::vector<uint8_t> firstErrorAns;
 
     // Use an impossible error code as default value
     int terrno = ETIME;
@@ -686,6 +698,15 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
                 statp->closeSockets();
                 return -terrno;
             }
+            if (tryAllServers && isErrorOrNoDataAnswer(*rcode, ans)) {
+                // Do not query this server again, but continue querying
+                usable_servers[ns] = false;
+                if (firstErrorAns.empty()) {
+                    firstErrorRcode = *rcode;
+                    firstErrorAns.assign(ans.data(), ans.data() + resplen);
+                }
+                continue;
+            }
 
             LOG(DEBUG) << __func__ << ": got answer:";
             res_pquery(ans.first(resplen));
@@ -697,6 +718,20 @@ int res_nsend(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int*
             return (resplen);
         }  // for each ns
     }  // for each retry
+
+    bool tryAllServersGotError =
+            firstErrorAns.size() &&
+            std::accumulate(usable_servers, usable_servers + statp->nsaddrs.size(), 0) == 0;
+    if (tryAllServersGotError) {
+        std::copy(firstErrorAns.begin(), firstErrorAns.end(), ans.data());
+        int resplen = firstErrorAns.size();
+        *rcode = firstErrorRcode;
+
+        LOG(DEBUG) << __func__ << ": returning first error after trying all servers:";
+        res_pquery(ans.first(resplen));
+        return resplen;
+    }
+
     statp->closeSockets();
     terrno = useTcp ? terrno : gotsomewhere ? ETIMEDOUT : ECONNREFUSED;
     // TODO: Remove errno once callers stop using it
@@ -1234,6 +1269,13 @@ static int send_dg(ResState* statp, res_params* params, span<const uint8_t> msg,
 // return 0      - when mdns packets transfer error.
 static int send_mdns(ResState* statp, span<const uint8_t> msg, span<uint8_t> ans, int* terrno,
                      int* rcode, IPSockAddr* receivedMdnsAddr) {
+    // Always query the IPv6 multicast address for mDNS first, regardless of
+    // the state of IPv4/IPv6 connectivity.
+    // This works for IPv4 only networks since we won't receive a "successful"
+    // mDNS answer (either sendto will fail, or we won't receive a response),
+    // in which case we will fallback onto IPv4.
+    // This won't always lead to the best performance, but it was deemed
+    // preferable due to the much simpler code.
     for (const auto& mdns_addr : mdns_addrs) {
         const sockaddr_storage ss = mdns_addr;
         *receivedMdnsAddr = mdns_addr;
diff --git a/resolv_cache.h b/resolv_cache.h
index 487b7327..e6574a0a 100644
--- a/resolv_cache.h
+++ b/resolv_cache.h
@@ -148,3 +148,11 @@ bool resolv_is_enforceDnsUid_enabled_network(unsigned netid);
 
 // Return true if the network is metered.
 bool resolv_is_metered_network(unsigned netid);
+
+// Return true if the private DNS rule can be bypassed by this specific uid on this
+// network.
+bool resolv_is_uid_allowed_bypass_private_dns_on_network(unsigned netid, uid_t uid);
+
+// Set whether or not to allow the UID to explicitly bypass the private DNS rule on a given
+// network.
+int resolv_set_allow_bypass_private_dns_on_network(unsigned netid, uid_t uid, bool allowed);
diff --git a/tests/Android.bp b/tests/Android.bp
index 068125ba..ca3e4766 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -249,6 +249,9 @@ cc_test {
     host_required: [
         "net-tests-utils-host-common",
     ],
+    host_common_data: [
+        ":net-tests-utils-host-common",
+    ],
 }
 
 cc_test {
@@ -371,6 +374,9 @@ cc_test {
     host_required: [
         "net-tests-utils-host-common",
     ],
+    host_common_data: [
+        ":net-tests-utils-host-common",
+    ],
     data: [":ConnectivityTestPreparer"],
 }
 
diff --git a/tests/dnsresolver_binder_test.cpp b/tests/dnsresolver_binder_test.cpp
index c911c2f9..01af6a08 100644
--- a/tests/dnsresolver_binder_test.cpp
+++ b/tests/dnsresolver_binder_test.cpp
@@ -65,6 +65,8 @@ using android::netdutils::Stopwatch;
 // TODO: make this dynamic and stop depending on implementation details.
 // Sync from TEST_NETID in dns_responder_client.cpp as resolv_integration_test.cpp does.
 constexpr int TEST_NETID = 30;
+constexpr int TEST_NETID_2 = 31;  // not created yet
+constexpr int TEST_UID = 99999;
 
 class DnsResolverBinderTest : public NetNativeTestBase {
   public:
@@ -671,3 +673,41 @@ TEST_F(DnsResolverBinderTest, InterfaceNamesInDumpsys) {
     ASSERT_EQ(android::OK, ret) << "Error dumping service: " << android::statusToString(ret);
     EXPECT_EQ("[myinterface0, myinterface1]", getNetworkInterfaceNames(TEST_NETID, lines));
 }
+
+TEST_F(DnsResolverBinderTest, SetAllowBypassPrivateDnsOnNetwork) {
+    SKIP_IF_REMOTE_VERSION_LESS_THAN(mDnsResolver.get(), 16);
+
+    // Allow bypassing the private DNS rule for a UID on a nonexistent network.
+    ::ndk::ScopedAStatus status = mDnsResolver->setAllowBypassPrivateDnsOnNetwork(
+            TEST_NETID_2, TEST_UID, true /* allowed */);
+    ASSERT_FALSE(status.isOk());
+    ASSERT_EQ(ENOENT, status.getServiceSpecificError());
+
+    // Disallow bypassing the private DNS rule for a UID on a nonexistent network.
+    status = mDnsResolver->setAllowBypassPrivateDnsOnNetwork(TEST_NETID_2, TEST_UID,
+                                                             false /* allowed */);
+    ASSERT_FALSE(status.isOk());
+    ASSERT_EQ(ENOENT, status.getServiceSpecificError());
+
+    // Allow bypassing the private DNS rule for a UID on a created network.
+    status = mDnsResolver->setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID,
+                                                             true /* allowed */);
+    ASSERT_TRUE(status.isOk()) << status.getMessage();
+
+    // Allow bypassing the private DNS rule for a existent UID again.
+    status = mDnsResolver->setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID,
+                                                             true /* allowed */);
+    ASSERT_FALSE(status.isOk());
+    ASSERT_EQ(EEXIST, status.getServiceSpecificError());
+
+    // Disallow bypassing the private DNS rule for a existent UID.
+    status = mDnsResolver->setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID,
+                                                             false /* allowed */);
+    ASSERT_TRUE(status.isOk()) << status.getMessage();
+
+    // Disallow bypassing the private DNS rule for a nonexistent UID.
+    status = mDnsResolver->setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID,
+                                                             false /* allowed */);
+    ASSERT_FALSE(status.isOk());
+    ASSERT_EQ(ENOENT, status.getServiceSpecificError());
+}
diff --git a/tests/fuzzer/resolv_service_fuzzer.cpp b/tests/fuzzer/resolv_service_fuzzer.cpp
index 1c6f87f9..cdd892d0 100644
--- a/tests/fuzzer/resolv_service_fuzzer.cpp
+++ b/tests/fuzzer/resolv_service_fuzzer.cpp
@@ -36,6 +36,8 @@ extern "C" int LLVMFuzzerInitialize(int /**argc*/, char /****argv*/) {
 }
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+    // TODO(b/183141167): need to rewrite 'dump' to avoid SIGPIPE.
+    signal(SIGPIPE, SIG_IGN);
     auto resolverService = ::ndk::SharedRefBase::make<DnsResolverService>();
     fuzzService(resolverService->asBinder().get(), FuzzedDataProvider(data, size));
 
diff --git a/tests/resolv_cache_unit_test.cpp b/tests/resolv_cache_unit_test.cpp
index ef9ecb30..2cc80006 100644
--- a/tests/resolv_cache_unit_test.cpp
+++ b/tests/resolv_cache_unit_test.cpp
@@ -217,6 +217,14 @@ class ResolvCacheTest : public NetNativeTestBase {
 
     int cacheFlush(uint32_t netId) { return resolv_flush_cache_for_net(netId); }
 
+    bool isUidAllowedBypassPrivateDnsOnNetwork(int netid, unsigned uid) {
+        return resolv_is_uid_allowed_bypass_private_dns_on_network(netid, uid);
+    }
+
+    int setAllowBypassPrivateDnsOnNetwork(int netid, unsigned uid, bool allowed) {
+        return resolv_set_allow_bypass_private_dns_on_network(netid, uid, allowed);
+    }
+
     void expectCacheStats(const std::string& msg, uint32_t netId, const CacheStats& expected) {
         int nscount = -1;
         sockaddr_storage servers[MAXNS];
@@ -995,6 +1003,36 @@ TEST_F(ResolvCacheTest, IsNetworkMetered) {
     EXPECT_FALSE(resolv_is_metered_network(TEST_NETID + 2));
 }
 
+TEST_F(ResolvCacheTest, setAllowBypassingPrivateDnsOnNetwork) {
+    // Create the cache for the test network.
+    EXPECT_EQ(0, cacheCreate(TEST_NETID));
+    EXPECT_TRUE(has_named_cache(TEST_NETID));
+
+    // Allow bypassing the private DNS rule for a UID on a nonexistent network.
+    EXPECT_EQ(-ENOENT,
+              setAllowBypassPrivateDnsOnNetwork(TEST_NETID_2, TEST_UID, true /* allowed */));
+    EXPECT_FALSE(isUidAllowedBypassPrivateDnsOnNetwork(TEST_NETID_2, TEST_UID));
+
+    // Allow bypassing the private DNS rule for a UID on a created network.
+    EXPECT_EQ(0, setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID, true /* allowed */));
+    EXPECT_TRUE(isUidAllowedBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID));
+
+    // Allow bypassing the private DNS rule for a UID on a created network
+    // again.
+    EXPECT_EQ(-EEXIST, setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID, true /* allowed */));
+    EXPECT_TRUE(isUidAllowedBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID));
+
+    // Disallow bypassing the private DNS rule for a UID on a created network.
+    EXPECT_EQ(0, setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID, false /* allowed */));
+    EXPECT_FALSE(isUidAllowedBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID));
+
+    // Disallow bypassing the private DNS rule for a UID on a created network
+    // again.
+    EXPECT_EQ(-ENOENT,
+              setAllowBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID, false /* allowed */));
+    EXPECT_FALSE(isUidAllowedBypassPrivateDnsOnNetwork(TEST_NETID, TEST_UID));
+}
+
 namespace {
 
 constexpr int EAI_OK = 0;
diff --git a/tests/resolv_integration_test.cpp b/tests/resolv_integration_test.cpp
index 6854a0c0..886b346e 100644
--- a/tests/resolv_integration_test.cpp
+++ b/tests/resolv_integration_test.cpp
@@ -64,9 +64,10 @@
 #include "Experiments.h"
 #include "NetdClient.h"
 #include "ResolverStats.h"
-#include "netid_client.h"  // NETID_UNSET
-#include "params.h"        // MAXNS
-#include "stats.h"         // RCODE_TIMEOUT
+#include "netd_resolv/resolv.h"  // RESOLV_TRY_ALL_USABLE_SERVERS
+#include "netid_client.h"        // NETID_UNSET
+#include "params.h"              // MAXNS
+#include "stats.h"               // RCODE_TIMEOUT
 #include "tests/dns_metrics_listener/dns_metrics_listener.h"
 #include "tests/dns_responder/dns_responder.h"
 #include "tests/dns_responder/dns_responder_client_ndk.h"
@@ -411,6 +412,9 @@ class ResolverTest : public NetNativeTestBase {
 
     void runCancelledQueryTest(bool expectCancelled);
 
+    int runTryAllServersTest(const test::DNSResponder& server_1, const test::DNSResponder& server_2,
+                             std::string* answer);
+
     DnsResponderClient mDnsClient;
 
     bool mIsResolverOptionIPCSupported = false;
@@ -3040,9 +3044,15 @@ void ResolverTest::runCancelledQueryTest(bool expectCancelled) {
 
     test::DNSResponder dns(listen_addr);
     StartDns(dns, records);
+    // Set the server to unresponsive
     dns.setResponseProbability(0.0);
-    std::vector<std::string> servers = {listen_addr};
-    ASSERT_TRUE(mDnsClient.SetResolversForNetwork(servers));
+    dns.setErrorRcode(static_cast<ns_rcode>(-1));
+
+    ResolverParamsParcel setupParams = DnsResponderClient::GetDefaultResolverParamsParcel();
+    setupParams.retryCount = 2;
+    setupParams.baseTimeoutMsec = 50;
+    setupParams.servers = {listen_addr};
+    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(setupParams));
 
     int fd1 = resNetworkQuery(TEST_NETID, host_name_1, ns_c_in, ns_t_aaaa, 0);
     int fd2 = resNetworkQuery(TEST_NETID, host_name_2, ns_c_in, ns_t_aaaa, 0);
@@ -3053,8 +3063,8 @@ void ResolverTest::runCancelledQueryTest(bool expectCancelled) {
     expectAnswersNotValid(fd2, -ETIMEDOUT);
 
     if (expectCancelled) {
-        // Expect multiple retries on the second query, but only one attempt on the first one
-        EXPECT_GT(GetNumQueries(dns, host_name_2), 1U);
+        // Expect 2 retries on the second query, but only one attempt on the first one
+        EXPECT_EQ(2U, GetNumQueries(dns, host_name_2));
         EXPECT_EQ(1U, GetNumQueries(dns, host_name_1));
     } else {
         // The queries are not actually cancelled and multiple are sent. Poll as in some cases the
@@ -3073,6 +3083,168 @@ TEST_F(ResolverTest, Async_CancelledQueryWithFlagDisabled) {
     ASSERT_NO_FATAL_FAILURE(runCancelledQueryTest(/*expectCancelled=*/false));
 }
 
+int ResolverTest::runTryAllServersTest(const test::DNSResponder& server_1,
+                                       const test::DNSResponder& server_2, std::string* answer) {
+    ResolverParamsParcel setupParams = DnsResponderClient::GetDefaultResolverParamsParcel();
+    setupParams.retryCount = 2;
+    setupParams.baseTimeoutMsec = 50;
+    setupParams.servers = {server_1.listen_address(), server_2.listen_address()};
+    setupParams.tlsServers.clear();
+    EXPECT_TRUE(mDnsClient.SetResolversFromParcel(setupParams));
+
+    int fd = resNetworkQuery(TEST_NETID, kHelloExampleCom, ns_c_in, ns_t_a,
+                             RESOLV_TRY_ALL_USABLE_SERVERS);
+    int rcode;
+    uint8_t buf[MAXPACKET] = {};
+    int res = getAsyncResponse(fd, &rcode, buf, MAXPACKET);
+    if (res < 0) {
+        return res;
+    }
+    if (res > 0 && answer) {
+        *answer = toString(buf, res, AF_INET);
+    }
+    return rcode;
+}
+
+TEST_F(ResolverTest, TryAllServers_OneServerSucceeds_Success) {
+    test::DNSResponder nxdomain_server("127.0.0.4");
+    nxdomain_server.setResponseProbability(0.0);
+    nxdomain_server.setErrorRcode(ns_rcode::ns_r_nxdomain);
+    StartDns(nxdomain_server, {});
+    test::DNSResponder noerror_server("127.0.0.5");
+    const std::vector<DnsRecord> records = {
+            {kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4},
+    };
+    StartDns(noerror_server, records);
+
+    ASSERT_NO_FATAL_FAILURE({
+        std::string answer;
+        int rcode = runTryAllServersTest(nxdomain_server, noerror_server, &answer);
+        EXPECT_EQ(ns_rcode::ns_r_noerror, rcode);
+        EXPECT_EQ(kHelloExampleComAddrV4, answer);
+        EXPECT_EQ(1U, GetNumQueriesForType(nxdomain_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(1U, GetNumQueriesForType(noerror_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
+TEST_F(ResolverTest, TryAllServers_AllError_ReturnFirstError) {
+    test::DNSResponder nxdomain_server("127.0.0.4");
+    nxdomain_server.setResponseProbability(0.0);
+    nxdomain_server.setErrorRcode(ns_rcode::ns_r_nxdomain);
+    StartDns(nxdomain_server, {});
+    test::DNSResponder notauth_server("127.0.0.5");
+    notauth_server.setResponseProbability(0.0);
+    notauth_server.setErrorRcode(ns_rcode::ns_r_notauth);
+    StartDns(notauth_server, {});
+
+    ASSERT_NO_FATAL_FAILURE({
+        int rcode = runTryAllServersTest(nxdomain_server, notauth_server, nullptr);
+        EXPECT_EQ(ns_rcode::ns_r_nxdomain, rcode);
+        EXPECT_EQ(1U, GetNumQueriesForType(nxdomain_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(1U, GetNumQueriesForType(notauth_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
+TEST_F(ResolverTest, TryAllServers_OneServerTimesOut_ReturnTimeout) {
+    test::DNSResponder nxdomain_server("127.0.0.4");
+    nxdomain_server.setResponseProbability(0.0);
+    nxdomain_server.setErrorRcode(ns_rcode::ns_r_nxdomain);
+    StartDns(nxdomain_server, {});
+    test::DNSResponder timeout_server("127.0.0.5");
+    timeout_server.setResponseProbability(0.0);
+    timeout_server.setErrorRcode(static_cast<ns_rcode>(-1));
+    StartDns(timeout_server, {});
+
+    ASSERT_NO_FATAL_FAILURE({
+        int rcode = runTryAllServersTest(nxdomain_server, timeout_server, nullptr);
+        EXPECT_EQ(-ETIMEDOUT, rcode);
+        EXPECT_EQ(1U, GetNumQueriesForType(nxdomain_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(2U, GetNumQueriesForType(timeout_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
+TEST_F(ResolverTest, TryAllServers_NoData_QueriesNextServer) {
+    test::DNSResponder nodata_server("127.0.0.4", test::kDefaultListenService,
+                                     test::kDefaultErrorCode,
+                                     test::DNSResponder::MappingType::DNS_HEADER);
+    test::DNSHeader header(kDefaultDnsHeader);
+    nodata_server.addMappingDnsHeader(kHelloExampleCom, ns_type::ns_t_a, header);
+    StartDns(nodata_server, {});
+    test::DNSResponder noerror_server("127.0.0.5");
+    const std::vector<DnsRecord> records = {
+            {kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4},
+    };
+    StartDns(noerror_server, records);
+
+    ASSERT_NO_FATAL_FAILURE({
+        std::string answer;
+        int rcode = runTryAllServersTest(nodata_server, noerror_server, &answer);
+        EXPECT_EQ(ns_rcode::ns_r_noerror, rcode);
+        EXPECT_EQ(kHelloExampleComAddrV4, answer);
+        EXPECT_EQ(1U, GetNumQueriesForType(nodata_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(1U, GetNumQueriesForType(noerror_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
+TEST_F(ResolverTest, TryAllServers_OnlyTcpFails_UdpSucceedsOnNextServer) {
+    test::DNSResponder truncated_server("127.0.0.4");
+    truncated_server.setResponseProbability(1, IPPROTO_UDP);
+    truncated_server.setResponseProbability(0, IPPROTO_TCP);
+    truncated_server.setErrorRcode(ns_rcode::ns_r_nxdomain);
+    StartDns(truncated_server, kLargeCnameChainRecords);
+    test::DNSResponder noerror_server("127.0.0.5");
+    const std::vector<DnsRecord> records = {
+            {kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4},
+    };
+    StartDns(noerror_server, records);
+
+    ASSERT_NO_FATAL_FAILURE({
+        std::string answer;
+        int rcode = runTryAllServersTest(truncated_server, noerror_server, &answer);
+        EXPECT_EQ(ns_rcode::ns_r_noerror, rcode);
+        EXPECT_EQ(kHelloExampleComAddrV4, answer);
+        EXPECT_EQ(2U, GetNumQueriesForType(truncated_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(1U, GetNumQueriesForType(noerror_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
+TEST_F(ResolverTest, TryAllServers_TcpFailsFirst_ReturnFirstError) {
+    test::DNSResponder truncated_server("127.0.0.4");
+    truncated_server.setResponseProbability(1.0, IPPROTO_UDP);
+    truncated_server.setResponseProbability(0.0, IPPROTO_TCP);
+    truncated_server.setErrorRcode(ns_rcode::ns_r_nxdomain);
+    StartDns(truncated_server, kLargeCnameChainRecords);
+    test::DNSResponder notauth_server("127.0.0.5");
+    notauth_server.setResponseProbability(0.0);
+    notauth_server.setErrorRcode(ns_rcode::ns_r_notauth);
+    StartDns(notauth_server, {});
+
+    ASSERT_NO_FATAL_FAILURE({
+        std::string answer;
+        int rcode = runTryAllServersTest(truncated_server, notauth_server, &answer);
+        EXPECT_EQ(ns_rcode::ns_r_nxdomain, rcode);
+        EXPECT_EQ(2U, GetNumQueriesForType(truncated_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(1U, GetNumQueriesForType(notauth_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
+TEST_F(ResolverTest, TryAllServers_TcpFallbackSucceeds_Success) {
+    test::DNSResponder nxdomain_server("127.0.0.4");
+    nxdomain_server.setResponseProbability(0.0);
+    nxdomain_server.setErrorRcode(ns_rcode::ns_r_nxdomain);
+    StartDns(nxdomain_server, {});
+    test::DNSResponder truncated_server("127.0.0.5");
+    StartDns(truncated_server, kLargeCnameChainRecords);
+
+    ASSERT_NO_FATAL_FAILURE({
+        std::string answer;
+        int rcode = runTryAllServersTest(nxdomain_server, truncated_server, &answer);
+        EXPECT_EQ(ns_rcode::ns_r_noerror, rcode);
+        EXPECT_EQ(1U, GetNumQueriesForType(nxdomain_server, ns_type::ns_t_a, kHelloExampleCom));
+        EXPECT_EQ(2U, GetNumQueriesForType(truncated_server, ns_type::ns_t_a, kHelloExampleCom));
+    });
+}
+
 // This test checks that the resolver should not generate the request containing OPT RR when using
 // cleartext DNS. If we query the DNS server not supporting EDNS0 and it reponds with
 // FORMERR_ON_EDNS, we will fallback to no EDNS0 and try again. If the server does no response, we
diff --git a/tests/resolv_unit_test.cpp b/tests/resolv_unit_test.cpp
index 4df753d3..933b1442 100644
--- a/tests/resolv_unit_test.cpp
+++ b/tests/resolv_unit_test.cpp
@@ -869,10 +869,12 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
     constexpr char v4addr[] = "127.0.0.3";
     constexpr char v6addr[] = "::127.0.0.3";
     constexpr char host_name[] = "hello.local.";
+
     // Following fields will not be verified during the test in proto NetworkDnsEventReported.
     // So don't need to config those values: event_type, return_code, latency_micros,
     // hints_ai_flags, res_nsend_flags, network_type, private_dns_modes.
-
+    // TODO(b/394031336): mDNS currently disables caching, cache_hit is set
+    // accordingly to RESOLV_CACHE_UNSUPPORTED == 0
     constexpr char event_ipv4[] = R"Event(
              NetworkDnsEventReported {
              dns_query_events:
@@ -881,7 +883,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
                 {
                  rcode: 0,
                  type: 1,
-                 cache_hit: 1,
+                 cache_hit: 0,
                  ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
@@ -893,6 +895,8 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
              }
         })Event";
 
+    // TODO(b/394031336): mDNS currently disables caching, cache_hit is set
+    // accordingly to RESOLV_CACHE_UNSUPPORTED == 0
     constexpr char event_ipv6[] = R"Event(
              NetworkDnsEventReported {
              dns_query_events:
@@ -901,7 +905,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
                 {
                  rcode: 0,
                  type: 28,
-                 cache_hit: 1,
+                 cache_hit: 0,
                  ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
@@ -913,6 +917,8 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
              }
         })Event";
 
+    // TODO(b/394031336): mDNS currently disables caching, cache_hit is set
+    // accordingly to RESOLV_CACHE_UNSUPPORTED == 0
     constexpr char event_ipv4v6[] = R"Event(
              NetworkDnsEventReported {
              dns_query_events:
@@ -921,7 +927,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
                 {
                  rcode: 0,
                  type: 28,
-                 cache_hit: 1,
+                 cache_hit: 0,
                  ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
@@ -932,7 +938,7 @@ TEST_F(ResolvGetAddrInfoTest, MdnsAlphabeticalHostname) {
                 {
                  rcode: 0,
                  type: 1,
-                 cache_hit: 1,
+                 cache_hit: 0,
                  ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
@@ -1697,6 +1703,8 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
     // Following fields will not be verified during the test in proto NetworkDnsEventReported.
     // So don't need to config those values: event_type, return_code, latency_micros,
     // hints_ai_flags, res_nsend_flags, network_type, private_dns_modes.
+    // TODO(b/394031336): mDNS currently disables caching, cache_hit is set
+    // accordingly to RESOLV_CACHE_UNSUPPORTED == 0
     constexpr char event_ipv4[] = R"Event(
              NetworkDnsEventReported {
              dns_query_events:
@@ -1705,7 +1713,7 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
                 {
                  rcode: 0,
                  type: 1,
-                 cache_hit: 1,
+                 cache_hit: 0,
                  ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
@@ -1718,6 +1726,8 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
              }
         })Event";
 
+    // TODO(b/394031336): mDNS currently disables caching, cache_hit is set
+    // accordingly to RESOLV_CACHE_UNSUPPORTED == 0
     constexpr char event_ipv6[] = R"Event(
              NetworkDnsEventReported {
              dns_query_events:
@@ -1726,7 +1736,7 @@ TEST_F(GetHostByNameForNetContextTest, MdnsAlphabeticalHostname) {
                 {
                  rcode: 0,
                  type: 28,
-                 cache_hit: 1,
+                 cache_hit: 0,
                  ip_version: 2,
                  protocol: 5,
                  retry_times: 0,
```

