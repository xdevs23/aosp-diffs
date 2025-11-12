```diff
diff --git a/Android.bp b/Android.bp
index 7a7e4915..2d4305f1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,12 +30,6 @@ license {
     ],
 }
 
-tidy_errors = [
-    "-*",
-    "bugprone-inaccurate-erase",
-    "bugprone-use-after-move",
-]
-
 cc_defaults {
     name: "adb_defaults",
 
@@ -104,10 +98,6 @@ cc_defaults {
             ],
         },
     },
-
-    tidy: true,
-    tidy_checks: tidy_errors,
-    tidy_checks_as_errors: tidy_errors,
 }
 
 cc_defaults {
@@ -279,12 +269,13 @@ cc_library_host_static {
         "client/auth.cpp",
         "client/adb_wifi.cpp",
         "client/detach.cpp",
+        "client/discovered_services.cpp",
+        "client/mdns_tracker.cpp",
         "client/usb_libusb.cpp",
         "client/usb_libusb_device.cpp",
         "client/usb_libusb_hotplug.cpp",
         "client/usb_libusb_inhouse_hotplug.cpp",
         "client/transport_emulator.cpp",
-        "client/mdnsresponder_client.cpp",
         "client/mdns_utils.cpp",
         "client/transport_mdns.cpp",
         "client/transport_usb.cpp",
@@ -324,7 +315,6 @@ cc_library_host_static {
         "libcutils",
         "libdiagnose_usb",
         "liblog",
-        "libmdnssd",
         "libopenscreen-discovery",
         "libopenscreen-platform-impl",
         "libprotobuf-cpp-lite",
@@ -373,6 +363,8 @@ cc_test_host {
     name: "adb_test",
     defaults: ["adb_defaults"],
     srcs: libadb_test_srcs + [
+        "client/commandline_test.cpp",
+        "client/discovered_services_test.cpp",
         "client/mdns_utils_test.cpp",
         "test_utils/test_utils.cpp",
     ],
@@ -383,6 +375,7 @@ cc_test_host {
         "libadb_host_protos",
         "libadb_pairing_auth_static",
         "libadb_pairing_connection_static",
+        "libapp_processes_protos_full",
         "libadb_protos_static",
         "libadb_sysdeps",
         "libadb_tls_connection_static",
@@ -392,7 +385,6 @@ cc_test_host {
         "libcutils",
         "libdiagnose_usb",
         "liblog",
-        "libmdnssd",
         "libopenscreen-discovery",
         "libopenscreen-platform-impl",
         "libprotobuf-cpp-full",
@@ -480,7 +472,6 @@ cc_defaults {
         "liblog",
         "liblog",
         "liblz4",
-        "libmdnssd",
         "libopenscreen-discovery",
         "libopenscreen-platform-impl",
         "libprotobuf-cpp-full",
@@ -574,6 +565,7 @@ cc_library_static {
         "daemon/auth.cpp",
         "daemon/jdwp_service.cpp",
         "daemon/logging.cpp",
+        "daemon/mdns.cpp",
         "daemon/transport_socket_server.cpp",
     ],
 
@@ -581,6 +573,7 @@ cc_library_static {
 
     static_libs: [
         "libdiagnose_usb",
+        "libmdnssd",
     ],
 
     shared_libs: [
@@ -613,9 +606,13 @@ cc_library_static {
                 "daemon/usb_ffs.cpp",
                 "daemon/watchdog.cpp",
             ],
+            shared_libs: [
+                "adbd_flags_c_lib",
+            ],
         },
         recovery: {
             exclude_shared_libs: [
+                "adbd_flags_c_lib",
                 "libadb_pairing_auth",
                 "libadb_pairing_connection",
                 "libapp_processes_protos_lite",
@@ -665,6 +662,7 @@ cc_library {
         "libbrotli",
         "libdiagnose_usb",
         "liblz4",
+        "libmdnssd",
         "libprotobuf-cpp-lite",
         "libzstd",
     ],
@@ -692,10 +690,10 @@ cc_library {
             srcs: [
                 "daemon/abb_service.cpp",
                 "daemon/framebuffer_service.cpp",
-                "daemon/mdns.cpp",
                 "daemon/restart_service.cpp",
             ],
             shared_libs: [
+                "adbd_flags_c_lib",
                 "libmdnssd",
                 "libselinux",
             ],
@@ -708,6 +706,7 @@ cc_library {
                 "daemon/abb_service.cpp",
             ],
             exclude_shared_libs: [
+                "adbd_flags_c_lib",
                 "libadb_pairing_auth",
                 "libadb_pairing_connection",
             ],
@@ -838,6 +837,9 @@ cc_binary {
             static_libs: [
                 "android_trade_in_mode_flags_cc_lib",
             ],
+            shared_libs: [
+                "adbd_flags_c_lib",
+            ],
         },
     },
 }
@@ -876,6 +878,9 @@ phony {
         "libadbd_fs.recovery",
         "reboot.recovery",
     ],
+    // This property is needed to inform Soong that the module and its deps are
+    // installed as part of the recovery partition.
+    recovery: true,
 }
 
 cc_binary {
@@ -1051,7 +1056,6 @@ cc_library_host_static {
         "libcutils",
         "libdiagnose_usb",
         "liblog",
-        "libmdnssd",
         "libusb",
         "libutils",
         "libz",
@@ -1094,7 +1098,6 @@ cc_test_host {
         "libdiagnose_usb",
         "libfastdeploy_host",
         "liblog",
-        "libmdnssd",
         "libopenscreen-discovery",
         "libopenscreen-platform-impl",
         "libprotobuf-cpp-full",
@@ -1117,3 +1120,20 @@ cc_test_host {
         "fastdeploy/testdata/sample.cd",
     ],
 }
+
+aconfig_declarations {
+    name: "adbd_flags",
+    container: "com.android.adbd",
+    package: "com.android.adbd.flags",
+    srcs: ["adbd_flags.aconfig"],
+}
+
+cc_aconfig_library {
+    name: "adbd_flags_c_lib",
+    aconfig_declarations: "adbd_flags",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.adbd",
+    ],
+    min_sdk_version: "apex_inherit",
+}
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be1..c8dbf77f 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -3,6 +3,3 @@ clang_format = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
-
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/adb.cpp b/adb.cpp
index a2406761..3f7d7ae3 100644
--- a/adb.cpp
+++ b/adb.cpp
@@ -432,12 +432,11 @@ static void handle_new_connection(atransport* t, apacket* p) {
 #endif
 }
 
-void handle_packet(apacket *p, atransport *t)
-{
-    D("handle_packet() %c%c%c%c", ((char*) (&(p->msg.command)))[0],
-            ((char*) (&(p->msg.command)))[1],
-            ((char*) (&(p->msg.command)))[2],
-            ((char*) (&(p->msg.command)))[3]);
+void handle_packet(apacket* p, atransport* t) {
+    VLOG(PACKETS) << std::format("packet <-- {}{}{}{}", ((char*)(&(p->msg.command)))[0],
+                                 ((char*)(&(p->msg.command)))[1], ((char*)(&(p->msg.command)))[2],
+                                 ((char*)(&(p->msg.command)))[3]);
+
     print_packet("recv", p);
     CHECK_EQ(p->payload.size(), p->msg.data_length);
 
@@ -1360,12 +1359,8 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
         }
         status.set_usb_backend_forced(getenv("ADB_LIBUSB") != nullptr);
 
-        if (using_bonjour()) {
-            status.set_mdns_backend(adb::proto::AdbServerStatus::BONJOUR);
-        } else {
-            status.set_mdns_backend(adb::proto::AdbServerStatus::OPENSCREEN);
-        }
-        status.set_mdns_backend_forced(getenv("ADB_MDNS_OPENSCREEN") != nullptr);
+        status.set_mdns_backend(adb::proto::AdbServerStatus::OPENSCREEN);
+        status.set_mdns_backend_forced(false);
 
         status.set_version(std::string(PLATFORM_TOOLS_VERSION));
         status.set_build(android::build::GetBuildNumber());
@@ -1375,6 +1370,8 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
         status.set_burst_mode(burst_mode_enabled());
         status.set_trace_level(get_trace_setting());
         status.set_mdns_enabled(mdns::is_enabled());
+        status.set_keystore_path(adb_auth_get_userkey_path());
+        status.set_known_hosts_path(get_user_known_hosts_path());
 
         std::string server_status_string;
         status.SerializeToString(&server_status_string);
diff --git a/adb_auth.h b/adb_auth.h
index 38312211..46707b40 100644
--- a/adb_auth.h
+++ b/adb_auth.h
@@ -46,6 +46,9 @@ void send_auth_response(const char* token, size_t token_size, atransport* t);
 int adb_tls_set_certificate(SSL* ssl);
 void adb_auth_tls_handshake(atransport* t);
 
+// Return the location where the host stores its keys
+std::string adb_auth_get_userkey_path();
+
 #else // !ADB_HOST
 
 extern bool auth_required;
diff --git a/adb_mdns.cpp b/adb_mdns.cpp
index c5bb9aab..c5228036 100644
--- a/adb_mdns.cpp
+++ b/adb_mdns.cpp
@@ -26,10 +26,7 @@
 
 #include "adb_trace.h"
 
-#define ADB_FULL_MDNS_SERVICE_TYPE(atype) ("_" atype "._tcp")
-const char* kADBDNSServices[] = {ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_SERVICE_TYPE),
-                                 ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_PAIRING_TYPE),
-                                 ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_CONNECT_TYPE)};
+const char* kADBDNSServices[] = {ADB_SERVICE_TCP, ADB_SERVICE_PAIR, ADB_SERVICE_TLS};
 
 #if ADB_HOST
 namespace {
diff --git a/adb_mdns.h b/adb_mdns.h
index e2da4b51..48213c95 100644
--- a/adb_mdns.h
+++ b/adb_mdns.h
@@ -29,6 +29,11 @@
 #define ADB_MDNS_SERVICE_TYPE "adb"
 #define ADB_MDNS_TLS_PAIRING_TYPE "adb-tls-pairing"
 #define ADB_MDNS_TLS_CONNECT_TYPE "adb-tls-connect"
+#define ADB_FULL_MDNS_SERVICE_TYPE(atype) ("_" atype "._tcp")
+
+#define ADB_SERVICE_TCP ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_SERVICE_TYPE)
+#define ADB_SERVICE_TLS ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_CONNECT_TYPE)
+#define ADB_SERVICE_PAIR ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_PAIRING_TYPE)
 
 // Client/service versions are initially defined to be matching,
 // but may go out of sync as different clients and services
@@ -41,9 +46,6 @@ constexpr int kADBSecurePairingServiceRefIndex = 1;
 constexpr int kADBSecureConnectServiceRefIndex = 2;
 constexpr int kNumADBDNSServices = 3;
 
-extern const char* _Nonnull kADBSecurePairingServiceTxtRecord;
-extern const char* _Nonnull kADBSecureConnectServiceTxtRecord;
-
 extern const char* _Nonnull kADBDNSServices[kNumADBDNSServices];
 extern const char* _Nonnull kADBDNSServiceTxtRecords[kNumADBDNSServices];
 
@@ -64,35 +66,12 @@ std::optional<int> adb_DNSServiceIndexByName(std::string_view reg_type);
 // See ADB_MDNS_AUTO_CONNECT environment variable for more info.
 bool adb_DNSServiceShouldAutoConnect(std::string_view service_name, std::string_view instance_name);
 
-void mdns_cleanup();
 std::string mdns_check();
 std::string mdns_list_discovered_services();
 
-struct MdnsInfo {
-    std::string service_name;
-    std::string service_type;
-    std::string addr;
-    uint16_t port = 0;
-
-    MdnsInfo(std::string_view name, std::string_view type, std::string_view addr, uint16_t port)
-        : service_name(name), service_type(type), addr(addr), port(port) {}
-};
-
-std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name);
-std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name);
-
-// TODO: Remove once openscreen has support for bonjour client APIs.
-struct AdbMdnsResponderFuncs {
-    std::string (*_Nonnull mdns_check)();
-    std::string (*_Nonnull mdns_list_discovered_services)();
-    std::optional<MdnsInfo> (*_Nonnull mdns_get_connect_service_info)(const std::string&);
-    std::optional<MdnsInfo> (*_Nonnull mdns_get_pairing_service_info)(const std::string&);
-    void (*_Nonnull mdns_cleanup)();
-    bool (*_Nonnull adb_secure_connect_by_service_name)(const std::string&);
-};  // AdbBonjourCallbacks
+std::optional<mdns::ServiceInfo> mdns_get_connect_service_info(const std::string& name);
+std::optional<mdns::ServiceInfo> mdns_get_pairing_service_info(const std::string& name);
 
-// TODO: Remove once openscreen has support for bonjour client APIs.
-// Start mdns discovery using MdnsResponder backend. Fills in AdbMdnsResponderFuncs for adb mdns
-// related functions.
-AdbMdnsResponderFuncs StartMdnsResponderDiscovery();
+// Return the location where adb host stores paired devices
+std::string get_user_known_hosts_path();
 #endif  // ADB_HOST
diff --git a/adbd_flags.aconfig b/adbd_flags.aconfig
new file mode 100644
index 00000000..4510debd
--- /dev/null
+++ b/adbd_flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.adbd.flags"
+container: "com.android.adbd"
+
+flag {
+  name: "adbd_restrict_vsock_local_cid"
+  namespace: "adb"
+  description: "This flag is for restricting local CID access via vsock socket in adbd"
+  bug: "414473085"
+}
diff --git a/apex/Android.bp b/apex/Android.bp
index ca99d8c6..7cf0e5ff 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -37,6 +37,10 @@ apex {
     defaults: [
         "com.android.adbd-defaults",
     ],
+    licenses: [
+        "packages_modules_adb_license",
+        "opensourcerequest",
+    ],
 }
 
 // adbd apex with INT_MAX version code, to allow for upgrade/rollback testing.
diff --git a/bugreport_test.cpp b/bugreport_test.cpp
index a6be2036..f98bb17f 100644
--- a/bugreport_test.cpp
+++ b/bugreport_test.cpp
@@ -72,10 +72,10 @@ class OnStandardStreamsCallbackAction : public ActionInterface<OnStandardStreams
     }
     virtual Result Perform(const ArgumentTuple& args) {
         if (type_ == kStreamStdout) {
-            ::std::tr1::get<0>(args)->OnStdout(output_.c_str(), output_.size());
+            ::std::tr1::get<0>(args)->OnStdoutReceived(output_.c_str(), output_.size());
         }
         if (type_ == kStreamStderr) {
-            ::std::tr1::get<0>(args)->OnStderr(output_.c_str(), output_.size());
+            ::std::tr1::get<0>(args)->OnStderrReceived(output_.c_str(), output_.size());
         }
     }
 
@@ -84,13 +84,13 @@ class OnStandardStreamsCallbackAction : public ActionInterface<OnStandardStreams
     std::string output_;
 };
 
-// Matcher used to emulated StandardStreamsCallbackInterface.OnStdout(buffer,
+// Matcher used to emulated StandardStreamsCallbackInterface.OnStdoutReceived(buffer,
 // length)
 Action<OnStandardStreamsCallbackFunction> WriteOnStdout(const std::string& output) {
     return MakeAction(new OnStandardStreamsCallbackAction(kStreamStdout, output));
 }
 
-// Matcher used to emulated StandardStreamsCallbackInterface.OnStderr(buffer,
+// Matcher used to emulated StandardStreamsCallbackInterface.OnStderrReceived(buffer,
 // length)
 Action<OnStandardStreamsCallbackFunction> WriteOnStderr(const std::string& output) {
     return MakeAction(new OnStandardStreamsCallbackAction(kStreamStderr, output));
diff --git a/client/adb_install.cpp b/client/adb_install.cpp
index 566bdb53..0ad4aa8c 100644
--- a/client/adb_install.cpp
+++ b/client/adb_install.cpp
@@ -304,7 +304,9 @@ static int install_app_incremental(int argc, const char** argv, bool wait, bool
     incremental::Args passthrough_args = {};
     for (int i = 0; i < argc; ++i) {
         const auto arg = std::string_view(argv[i]);
-        if (android::base::EndsWithIgnoreCase(arg, ".apk"sv)) {
+        if (android::base::EndsWithIgnoreCase(arg, ".apk"sv) ||
+            android::base::EndsWithIgnoreCase(arg, kDmExtension) ||
+            android::base::EndsWithIgnoreCase(arg, kSdmExtension)) {
             last_apk = i;
             if (first_apk == -1) {
                 first_apk = i;
@@ -538,10 +540,8 @@ static int install_multiple_app_streamed(int argc, const char** argv) {
         }
 
         if (android::base::EndsWithIgnoreCase(file, ".apk") ||
-            android::base::EndsWithIgnoreCase(
-                    file, ".dm") ||  // dex metadata, for cloud profile and cloud verification
-            android::base::EndsWithIgnoreCase(
-                    file, ".sdm") ||  // secure dex metadata, for cloud compilation
+            android::base::EndsWithIgnoreCase(file, kDmExtension) ||
+            android::base::EndsWithIgnoreCase(file, kSdmExtension) ||
             android::base::EndsWithIgnoreCase(file, ".fsv_sig") ||
             android::base::EndsWithIgnoreCase(file, ".idsig")) {  // v4 external signature
             struct stat sb;
diff --git a/client/adb_install.h b/client/adb_install.h
index 99466041..1c29dc4b 100644
--- a/client/adb_install.h
+++ b/client/adb_install.h
@@ -17,6 +17,12 @@
 #pragma once
 
 #include <string>
+#include <string_view>
+
+// secure dex metadata, for cloud compilation
+constexpr std::string_view kSdmExtension = ".sdm";
+// dex metadata, for cloud profile and cloud verification
+constexpr std::string_view kDmExtension = ".dm";
 
 int install_app(int argc, const char** argv);
 int install_multiple_app(int argc, const char** argv);
diff --git a/client/adb_wifi.cpp b/client/adb_wifi.cpp
index d79cbffe..f42f3088 100644
--- a/client/adb_wifi.cpp
+++ b/client/adb_wifi.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include "adb_wifi.h"
+#include "client/adb_wifi.h"
 
 #include <fstream>
 #include <random>
@@ -94,7 +94,7 @@ bool SafeReplaceFile(std::string_view old_file, std::string_view new_file) {
     return true;
 }
 
-static std::string get_user_known_hosts_path() {
+std::string get_user_known_hosts_path() {
     return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adb_known_hosts.pb";
 }
 
@@ -102,7 +102,6 @@ bool load_known_hosts_from_file(const std::string& path, adb::proto::AdbKnownHos
     // Check for file existence.
     struct stat buf;
     if (stat(path.c_str(), &buf) == -1) {
-        LOG(INFO) << "Known hosts file [" << path << "] does not exist...";
         return false;
     }
 
@@ -200,7 +199,7 @@ void adb_wifi_pair_device(const std::string& host, const std::string& password,
     auto priv_key = adb_auth_get_user_privkey();
     auto x509_cert = GenerateX509Certificate(priv_key.get());
     if (!x509_cert) {
-        LOG(ERROR) << "Unable to create X509 certificate for pairing";
+        response = "Unable to create X509 certificate for pairing";
         return;
     }
     auto cert_str = X509ToPEMString(x509_cert.get());
@@ -226,10 +225,9 @@ void adb_wifi_pair_device(const std::string& host, const std::string& password,
 
     PairingResultWaiter waiter;
     std::unique_lock<std::mutex> lock(waiter.mutex_);
-    if (!client->Start(mdns_info.has_value()
-                               ? android::base::StringPrintf("%s:%d", mdns_info->addr.c_str(),
-                                                             mdns_info->port)
-                               : host,
+    if (!client->Start(mdns_info.has_value() ? std::format("{}:{}", mdns_info->v4_address_string(),
+                                                           mdns_info->port)
+                                             : host,
                        waiter.OnResult, &waiter)) {
         response = "Failed: Unable to start pairing client.";
         return;
diff --git a/adb_wifi.h b/client/adb_wifi.h
similarity index 84%
rename from adb_wifi.h
rename to client/adb_wifi.h
index 8ad30506..8e67b456 100644
--- a/adb_wifi.h
+++ b/client/adb_wifi.h
@@ -21,17 +21,6 @@
 
 #include "adb.h"
 
-#if ADB_HOST
-
 void adb_wifi_pair_device(const std::string& host, const std::string& password,
                           std::string& response);
 bool adb_wifi_is_known_host(const std::string& host);
-
-#else  // !ADB_HOST
-
-struct AdbdAuthContext;
-
-void adbd_wifi_init(AdbdAuthContext* ctx);
-void adbd_wifi_secure_connect(atransport* t);
-
-#endif
diff --git a/client/auth.cpp b/client/auth.cpp
index 5b837526..6ce3d8b6 100644
--- a/client/auth.cpp
+++ b/client/auth.cpp
@@ -202,12 +202,12 @@ static bool load_keys(const std::string& path, bool allow_dir = true) {
     return false;
 }
 
-static std::string get_user_key_path() {
+std::string adb_auth_get_userkey_path() {
     return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adbkey";
 }
 
 static bool load_userkey() {
-    std::string path = get_user_key_path();
+    std::string path = adb_auth_get_userkey_path();
     if (path.empty()) {
         PLOG(ERROR) << "Error getting user key filename";
         return false;
@@ -233,6 +233,10 @@ static std::set<std::string> get_vendor_keys() {
 
     std::set<std::string> result;
     for (const auto& path : android::base::Split(adb_keys_path, ENV_PATH_SEPARATOR_STR)) {
+        // Malformed env variable (e.g.: ':<PATH>') can result in split returning empty string.
+        if (path.empty()) {
+            continue;
+        }
         result.emplace(path);
     }
     return result;
@@ -285,7 +289,7 @@ static bool pubkey_from_privkey(std::string* out, const std::string& path) {
 }
 
 bssl::UniquePtr<EVP_PKEY> adb_auth_get_user_privkey() {
-    std::string path = get_user_key_path();
+    std::string path = adb_auth_get_userkey_path();
     if (path.empty()) {
         PLOG(ERROR) << "Error getting user key filename";
         return nullptr;
@@ -307,7 +311,7 @@ bssl::UniquePtr<EVP_PKEY> adb_auth_get_user_privkey() {
 }
 
 std::string adb_auth_get_userkey() {
-    std::string path = get_user_key_path();
+    std::string path = adb_auth_get_userkey_path();
     if (path.empty()) {
         PLOG(ERROR) << "Error getting user key filename";
         return "";
diff --git a/client/bugreport.cpp b/client/bugreport.cpp
index 23ecb552..15b13cad 100644
--- a/client/bugreport.cpp
+++ b/client/bugreport.cpp
@@ -54,7 +54,7 @@ class BugreportStandardStreamsCallback : public StandardStreamsCallbackInterface
         SetLineMessage("generating");
     }
 
-    bool OnStdout(const char* buffer, size_t length) {
+    bool OnStdoutReceived(const char* buffer, size_t length) override {
         for (size_t i = 0; i < length; i++) {
             char c = buffer[i];
             if (c == '\n') {
@@ -67,8 +67,8 @@ class BugreportStandardStreamsCallback : public StandardStreamsCallbackInterface
         return true;
     }
 
-    bool OnStderr(const char* buffer, size_t length) {
-      return OnStream(nullptr, stderr, buffer, length, false);
+    bool OnStderrReceived(const char* buffer, size_t length) override {
+        return SendTo(nullptr, stderr, buffer, length, false);
     }
 
     int Done(int unused_) {
diff --git a/client/commandline.cpp b/client/commandline.cpp
index d7a517fd..024c2e08 100644
--- a/client/commandline.cpp
+++ b/client/commandline.cpp
@@ -36,6 +36,7 @@
 #include <string>
 #include <thread>
 #include <vector>
+using namespace std::string_literals;
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
@@ -43,6 +44,8 @@
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
+#include "client/host_services.h"
+
 #if defined(_WIN32)
 #define _POSIX
 #include <signal.h>
@@ -51,8 +54,6 @@
 #include <termios.h>
 #endif
 
-#include <google/protobuf/text_format.h>
-
 #include "adb.h"
 #include "adb_auth.h"
 #include "adb_client.h"
@@ -304,15 +305,15 @@ int read_and_dump_protocol(borrowed_fd fd, StandardStreamsCallbackInterface* cal
     }
     while (protocol->Read()) {
       if (protocol->id() == ShellProtocol::kIdStdout) {
-        if (!callback->OnStdout(protocol->data(), protocol->data_length())) {
-          exit_code = SIGPIPE + 128;
-          break;
-        }
+          if (!callback->OnStdoutReceived(protocol->data(), protocol->data_length())) {
+              exit_code = SIGPIPE + 128;
+              break;
+          }
       } else if (protocol->id() == ShellProtocol::kIdStderr) {
-        if (!callback->OnStderr(protocol->data(), protocol->data_length())) {
-          exit_code = SIGPIPE + 128;
-          break;
-        }
+          if (!callback->OnStderrReceived(protocol->data(), protocol->data_length())) {
+              exit_code = SIGPIPE + 128;
+              break;
+          }
       } else if (protocol->id() == ShellProtocol::kIdExit) {
         // data() returns a char* which doesn't have defined signedness.
         // Cast to uint8_t to prevent 255 from being sign extended to INT_MIN,
@@ -340,8 +341,8 @@ int read_and_dump(borrowed_fd fd, bool use_shell_protocol,
         if (length <= 0) {
           break;
         }
-        if (!callback->OnStdout(buffer_ptr, length)) {
-          break;
+        if (!callback->OnStdoutReceived(buffer_ptr, length)) {
+            break;
         }
       }
     }
@@ -1379,13 +1380,13 @@ class AdbServerStateStreamsCallback : public DefaultStandardStreamsCallback {
   public:
     AdbServerStateStreamsCallback() : DefaultStandardStreamsCallback(nullptr, nullptr) {}
 
-    bool OnStdout(const char* buffer, size_t length) override {
-        return OnStream(&output_, nullptr, buffer, length, false);
+    bool OnStdoutReceived(const char* buffer, size_t length) override {
+        return SendTo(&output_, nullptr, buffer, length, false);
     }
 
     int Done(int status) {
         if (output_.size() < 4) {
-            return OnStream(nullptr, stdout, output_.data(), output_.length(), false);
+            return SendTo(nullptr, stdout, output_.data(), output_.length(), false);
         }
 
         // Skip the 4-hex prefix
@@ -1397,7 +1398,7 @@ class AdbServerStateStreamsCallback : public DefaultStandardStreamsCallback {
         std::string string_proto;
         google::protobuf::TextFormat::PrintToString(binary_proto, &string_proto);
 
-        return OnStream(nullptr, stdout, string_proto.data(), string_proto.length(), false);
+        return SendTo(nullptr, stdout, string_proto.data(), string_proto.length(), false);
     }
 
   private:
@@ -1405,35 +1406,6 @@ class AdbServerStateStreamsCallback : public DefaultStandardStreamsCallback {
     DISALLOW_COPY_AND_ASSIGN(AdbServerStateStreamsCallback);
 };
 
-// A class that prints out human readable form of the protobuf message for "track-app" service
-// (received in binary format).
-class TrackAppStreamsCallback : public DefaultStandardStreamsCallback {
-  public:
-    TrackAppStreamsCallback() : DefaultStandardStreamsCallback(nullptr, nullptr) {}
-
-    // Assume the buffer contains at least 4 bytes of valid data.
-    bool OnStdout(const char* buffer, size_t length) override {
-        if (length < 4) return true;  // Unexpected length received. Do nothing.
-
-        adb::proto::AppProcesses binary_proto;
-        // The first 4 bytes are the length of remaining content in hexadecimal format.
-        binary_proto.ParseFromString(std::string(buffer + 4, length - 4));
-        char summary[24];  // The following string includes digits and 16 fixed characters.
-        int written = snprintf(summary, sizeof(summary), "Process count: %d\n",
-                               binary_proto.process_size());
-        if (!OnStream(nullptr, stdout, summary, written, false)) {
-          return false;
-        }
-
-        std::string string_proto;
-        google::protobuf::TextFormat::PrintToString(binary_proto, &string_proto);
-        return OnStream(nullptr, stdout, string_proto.data(), string_proto.length(), false);
-    }
-
-  private:
-    DISALLOW_COPY_AND_ASSIGN(TrackAppStreamsCallback);
-};
-
 static int adb_connect_command_bidirectional(const std::string& command) {
     std::string error;
     unique_fd fd(adb_connect(command, &error));
@@ -1975,19 +1947,34 @@ int adb_commandline(int argc, const char** argv) {
             error_exit("failed to check server version: %s", error.c_str());
         }
 
-        std::string query = "host:mdns:";
         if (!strcmp(argv[0], "check")) {
-            if (argc != 1) error_exit("mdns %s doesn't take any arguments", argv[0]);
-            query += "check";
+            if (argc != 1) {
+                error_exit("mdns %s doesn't take any arguments", argv[0]);
+            }
+            return adb_query_command("host:mdns:check");
         } else if (!strcmp(argv[0], "services")) {
-            if (argc != 1) error_exit("mdns %s doesn't take any arguments", argv[0]);
-            query += "services";
+            if (argc != 1) {
+                error_exit("mdns %s doesn't take any arguments", argv[0]);
+            }
             printf("List of discovered mdns services\n");
+            return adb_query_command("host:mdns:services");
+        } else if (!strcmp(argv[0], "track-services")) {
+            if (argc != 2) {
+                error_exit("mdns %s take two arguments", argv[0]);
+            }
+
+            std::string service = "host:"s + HostServices::kTrackMdnsServices;
+            if (!strcmp(argv[1], "--proto-binary")) {
+                return adb_connect_command(service);
+            } else if (!strcmp(argv[1], "--proto-text")) {
+                ProtoBinaryToText<adb::proto::MdnsServices> callback("\nServices:\n");
+                return adb_connect_command(service, nullptr, &callback);
+            } else {
+                error_exit("unknown mdns command [%s] flag '%s'", argv[0], argv[1]);
+            }
         } else {
             error_exit("unknown mdns command [%s]", argv[0]);
         }
-
-        return adb_query_command(query);
     }
     /* do_sync_*() commands */
     else if (!strcmp(argv[0], "ls")) {
@@ -2127,7 +2114,7 @@ int adb_commandline(int argc, const char** argv) {
         if (!CanUseFeature(*features, kFeatureTrackApp)) {
             error_exit("track-app is not supported by the device");
         }
-        TrackAppStreamsCallback callback;
+        ProtoBinaryToText<adb::proto::AppProcesses> callback("\nProcesses:\n");
         if (argc == 1) {
             return adb_connect_command("track-app", nullptr, &callback);
         } else if (argc == 2) {
diff --git a/client/commandline.h b/client/commandline.h
index 96eeb836..5b3e97b1 100644
--- a/client/commandline.h
+++ b/client/commandline.h
@@ -18,7 +18,9 @@
 #define COMMANDLINE_H
 
 #include <android-base/strings.h>
+#include <google/protobuf/text_format.h>
 
+#include <stdlib.h>
 #include <optional>
 
 #include "adb.h"
@@ -36,11 +38,11 @@ class StandardStreamsCallbackInterface {
     }
     // Handles the stdout output from devices supporting the Shell protocol.
     // Returns true on success and false on failure.
-    virtual bool OnStdout(const char* buffer, size_t length) = 0;
+    virtual bool OnStdoutReceived(const char* buffer, size_t length) = 0;
 
     // Handles the stderr output from devices supporting the Shell protocol.
     // Returns true on success and false on failure.
-    virtual bool OnStderr(const char* buffer, size_t length) = 0;
+    virtual bool OnStderrReceived(const char* buffer, size_t length) = 0;
 
     // Indicates the communication is finished and returns the appropriate error
     // code.
@@ -50,8 +52,8 @@ class StandardStreamsCallbackInterface {
     virtual int Done(int status) = 0;
 
   protected:
-    static bool OnStream(std::string* string, FILE* stream, const char* buffer, size_t length,
-                         bool returnErrors) {
+    static bool SendTo(std::string* string, FILE* stream, const char* buffer, size_t length,
+                       bool returnErrors) {
         if (string != nullptr) {
             string->append(buffer, length);
             return true;
@@ -70,8 +72,8 @@ class StandardStreamsCallbackInterface {
 // stream or to a string passed to the constructor.
 class DefaultStandardStreamsCallback : public StandardStreamsCallbackInterface {
   public:
-    // If |stdout_str| is non-null, OnStdout will append to it.
-    // If |stderr_str| is non-null, OnStderr will append to it.
+    // If |stdout_str| is non-null, OnStdoutReceived will append to it.
+    // If |stderr_str| is non-null, OnStderrReceived will append to it.
     DefaultStandardStreamsCallback(std::string* stdout_str, std::string* stderr_str)
         : stdout_str_(stdout_str), stderr_str_(stderr_str), returnErrors_(false) {
     }
@@ -80,12 +82,24 @@ class DefaultStandardStreamsCallback : public StandardStreamsCallbackInterface {
         : stdout_str_(stdout_str), stderr_str_(stderr_str), returnErrors_(returnErrors) {
     }
 
-    bool OnStdout(const char* buffer, size_t length) {
-        return OnStream(stdout_str_, stdout, buffer, length, returnErrors_);
+    // Called when receiving from the device standard input stream
+    bool OnStdoutReceived(const char* buffer, size_t length) override {
+        return SendToOut(buffer, length);
     }
 
-    bool OnStderr(const char* buffer, size_t length) {
-        return OnStream(stderr_str_, stderr, buffer, length, returnErrors_);
+    // Called when receiving from the device error input stream
+    bool OnStderrReceived(const char* buffer, size_t length) override {
+        return SendToErr(buffer, length);
+    }
+
+    // Send to local standard input stream (or stdout_str if one was provided).
+    bool SendToOut(const char* buffer, size_t length) {
+        return SendTo(stdout_str_, stdout, buffer, length, returnErrors_);
+    }
+
+    // Send to local standard error stream (or stderr_str if one was provided).
+    bool SendToErr(const char* buffer, size_t length) {
+        return SendTo(stderr_str_, stderr, buffer, length, returnErrors_);
     }
 
     int Done(int status) {
@@ -107,14 +121,70 @@ class DefaultStandardStreamsCallback : public StandardStreamsCallbackInterface {
 class SilentStandardStreamsCallbackInterface : public StandardStreamsCallbackInterface {
   public:
     SilentStandardStreamsCallbackInterface() = default;
-    bool OnStdout(const char*, size_t) override final { return true; }
-    bool OnStderr(const char*, size_t) override final { return true; }
-    int Done(int status) override final { return status; }
+    bool OnStdoutReceived(const char*, size_t) final { return true; }
+    bool OnStderrReceived(const char*, size_t) final { return true; }
+    int Done(int status) final { return status; }
 };
 
 // Singleton.
 extern DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK;
 
+// Prints out human-readable form of the protobuf message received in binary format.
+// Expected input is a stream of (<hex4>, [binary protobuf]).
+template <typename T>
+class ProtoBinaryToText : public DefaultStandardStreamsCallback {
+  public:
+    explicit ProtoBinaryToText(const std::string& m, std::string* std_out = nullptr,
+                               std::string* std_err = nullptr)
+        : DefaultStandardStreamsCallback(std_out, std_err), message(m) {}
+    bool OnStdoutReceived(const char* b, size_t l) override {
+        constexpr size_t kHeader_size = 4;
+
+        // Add the incoming bytes to our internal buffer.
+        std::copy_n(b, l, std::back_inserter(buffer_));
+
+        // Do we have at least the header?
+        if (buffer_.size() < kHeader_size) {
+            return true;
+        }
+
+        // We have a header. Convert <hex4> to size_t and check if we have received all
+        // the payload.
+        const std::string expected_size_hex = std::string(buffer_.data(), kHeader_size);
+        const size_t expected_size = strtoull(expected_size_hex.c_str(), nullptr, 16);
+
+        // Do we have the header + all expected payload?
+        if (buffer_.size() < expected_size + kHeader_size) {
+            return true;
+        }
+
+        // Convert binary to text proto.
+        T binary_proto;
+        binary_proto.ParseFromString(std::string(buffer_.data() + kHeader_size, expected_size));
+        std::string string_proto;
+        google::protobuf::TextFormat::PrintToString(binary_proto, &string_proto);
+
+        // Drop bytes that we just consumed.
+        buffer_.erase(buffer_.begin(), buffer_.begin() + kHeader_size + expected_size);
+
+        SendToOut(message.data(), message.length());
+        SendToOut(string_proto.data(), string_proto.length());
+
+        // Recurse if there is still data in our buffer (there may be more messages).
+        if (!buffer_.empty()) {
+            OnStdoutReceived("", 0);
+        }
+
+        return true;
+    }
+
+  private:
+    DISALLOW_COPY_AND_ASSIGN(ProtoBinaryToText);
+    // We buffer bytes here until we get all the header and payload bytes
+    std::vector<char> buffer_;
+    std::string message;
+};
+
 int adb_commandline(int argc, const char** argv);
 
 // Helper retrieval function.
diff --git a/client/commandline_test.cpp b/client/commandline_test.cpp
new file mode 100644
index 00000000..249a2f34
--- /dev/null
+++ b/client/commandline_test.cpp
@@ -0,0 +1,174 @@
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
+#include <gtest/gtest.h>
+
+#include "app_processes.pb.h"
+#include "client/commandline.h"
+
+std::size_t count_occurrences(const std::string& str, const std::string& substr) {
+    size_t occurrences = 0;
+    std::string::size_type pos = 0;
+    while ((pos = str.find(substr, pos)) != std::string::npos) {
+        occurrences += 1;
+        pos += substr.length();
+    }
+    return occurrences;
+}
+
+std::string proto_to_hex4proto(const std::string& proto) {
+    return android::base::StringPrintf("%04zx", proto.size()) + proto;
+}
+
+TEST(commandline, parse_full_proto) {
+    adb::proto::AppProcesses processes;
+    auto process = processes.add_process();
+    std::string process_name = "foo4089";
+    process->set_process_name(process_name);
+
+    std::string proto;
+    processes.SerializeToString(&proto);
+    std::string hex4_proto = proto_to_hex4proto(proto);
+
+    std::string out;
+    std::string err;
+    std::string message = "Testing123";
+    auto converter = ProtoBinaryToText<adb::proto::AppProcesses>(message, &out, &err);
+    converter.OnStdoutReceived(hex4_proto.data(), hex4_proto.size());
+
+    ASSERT_FALSE(out.empty());
+    ASSERT_TRUE(out.contains(message));
+    ASSERT_EQ(1u, count_occurrences(out, message));
+    ASSERT_EQ(1u, count_occurrences(out, process_name));
+}
+
+TEST(commandline, parse_full_proto_chopped_in_1_bytes) {
+    adb::proto::AppProcesses processes;
+    auto process = processes.add_process();
+    std::string process_name = "foo4089";
+    process->set_process_name(process_name);
+
+    std::string proto;
+    processes.SerializeToString(&proto);
+    std::string hex4_proto = proto_to_hex4proto(proto);
+
+    std::string out;
+    std::string err;
+    std::string message = "Testing123";
+    auto converter = ProtoBinaryToText<adb::proto::AppProcesses>(message, &out, &err);
+    for (auto i = 0u; i < hex4_proto.size(); i++) {
+        converter.OnStdoutReceived(hex4_proto.data() + i, 1);
+    }
+
+    ASSERT_FALSE(out.empty());
+    ASSERT_TRUE(out.contains(message));
+    ASSERT_EQ(1u, count_occurrences(out, message));
+    ASSERT_EQ(1u, count_occurrences(out, process_name));
+}
+
+TEST(commandline, parse_half_proto) {
+    adb::proto::AppProcesses processes;
+    auto process = processes.add_process();
+    process->set_process_name("foo");
+
+    std::string proto;
+    processes.SerializeToString(&proto);
+    std::string hex4_proto = proto_to_hex4proto(proto);
+
+    std::string out;
+    std::string err;
+    std::string message = "Testing 123";
+    auto converter = ProtoBinaryToText<adb::proto::AppProcesses>(message, &out, &err);
+    converter.OnStdoutReceived(hex4_proto.data(), hex4_proto.size() / 2);
+    ASSERT_TRUE(out.empty());
+}
+
+TEST(commandline, parse_two_proto) {
+    adb::proto::AppProcesses processes1;
+    auto process1 = processes1.add_process();
+    std::string process_name1 = "foo4089";
+    process1->set_process_name(process_name1);
+
+    adb::proto::AppProcesses processes2;
+    auto process2 = processes2.add_process();
+    std::string process_name2 = "foo8098";
+    process2->set_process_name(process_name2);
+
+    std::string proto1;
+    processes1.SerializeToString(&proto1);
+    std::string hex4_proto1 = proto_to_hex4proto(proto1);
+
+    std::string proto2;
+    processes2.SerializeToString(&proto2);
+    std::string hex4_proto2 = proto_to_hex4proto(proto2);
+
+    std::string two_messages;
+    two_messages.append(hex4_proto1);
+    two_messages.append(hex4_proto2);
+    std::string out;
+    std::string err;
+    std::string message = "Testing123";
+    auto converter = ProtoBinaryToText<adb::proto::AppProcesses>(message, &out, &err);
+    converter.OnStdoutReceived(two_messages.data(), two_messages.size());
+
+    ASSERT_FALSE(out.empty());
+    ASSERT_EQ(2u, count_occurrences(out, message));
+    ASSERT_EQ(1u, count_occurrences(out, process_name1));
+    ASSERT_EQ(1u, count_occurrences(out, process_name2));
+}
+
+TEST(commandline, parse_one_and_a_half_proto) {
+    adb::proto::AppProcesses processes1;
+    auto process1 = processes1.add_process();
+    std::string process_name1 = "foo4089";
+    process1->set_process_name(process_name1);
+
+    adb::proto::AppProcesses processes2;
+    auto process2 = processes2.add_process();
+    std::string process_name2 = "foo8098";
+    process2->set_process_name(process_name2);
+
+    std::string proto1;
+    processes1.SerializeToString(&proto1);
+    std::string hex4_proto1 = proto_to_hex4proto(proto1);
+
+    std::string proto2;
+    processes2.SerializeToString(&proto2);
+    std::string hex4_proto2 = proto_to_hex4proto(proto2);
+
+    std::string two_messages;
+    two_messages.append(hex4_proto1);
+    two_messages.append(hex4_proto2.substr(0, hex4_proto2.size() / 2));
+    std::string out;
+    std::string err;
+    std::string message = "Testing123";
+    auto converter = ProtoBinaryToText<adb::proto::AppProcesses>(message, &out, &err);
+    converter.OnStdoutReceived(two_messages.data(), two_messages.size());
+
+    ASSERT_FALSE(out.empty());
+    ASSERT_EQ(1u, count_occurrences(out, message));
+    ASSERT_EQ(1u, count_occurrences(out, process_name1));
+    ASSERT_EQ(0u, count_occurrences(out, process_name2));
+
+    // Send the remainder of second proto
+    out.clear();
+    std::string remaining = hex4_proto2.substr(hex4_proto2.size() / 2, hex4_proto2.size());
+    converter.OnStdoutReceived(remaining.data(), remaining.size());
+    ASSERT_FALSE(out.empty());
+    ASSERT_EQ(1u, count_occurrences(out, message));
+    ASSERT_EQ(0u, count_occurrences(out, process_name1));
+    ASSERT_EQ(1u, count_occurrences(out, process_name2));
+}
diff --git a/client/discovered_services.cpp b/client/discovered_services.cpp
new file mode 100644
index 00000000..db87eca6
--- /dev/null
+++ b/client/discovered_services.cpp
@@ -0,0 +1,108 @@
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
+#include "discovered_services.h"
+
+#include "adb_trace.h"
+
+namespace mdns {
+DiscoveredServices discovered_services [[clang::no_destroy]];
+
+static std::string fq_name(const ServiceInfo& si) {
+    return std::format("{}.{}", si.instance, si.service);
+}
+
+void DiscoveredServices::ServiceCreated(const ServiceInfo& service_info) {
+    std::lock_guard lock(services_mutex_);
+    VLOG(MDNS) << "Service created " << service_info;
+    services_[fq_name(service_info)] = service_info;
+}
+
+bool DiscoveredServices::ServiceUpdated(const ServiceInfo& service_info) {
+    std::lock_guard lock(services_mutex_);
+
+    const auto key = fq_name(service_info);
+    if (!services_.contains(key)) {
+        services_[key] = service_info;
+        return true;
+    }
+
+    auto& current_service = services_[key];
+    bool updated = false;
+
+    if (service_info.v4_address.has_value() &&
+        service_info.v4_address != current_service.v4_address) {
+        current_service.v4_address = service_info.v4_address;
+        updated = true;
+    }
+
+    for (auto& new_address : service_info.v6_addresses) {
+        if (!current_service.v6_addresses.contains(new_address)) {
+            updated = true;
+            current_service.v6_addresses.insert(new_address);
+        }
+    }
+
+    if (service_info.port != current_service.port) {
+        current_service.port = service_info.port;
+        updated = true;
+    }
+
+    if (service_info.attributes != current_service.attributes) {
+        current_service.attributes = service_info.attributes;
+        updated = true;
+    }
+
+    if (updated) {
+        VLOG(MDNS) << "Service update " << service_info;
+    }
+
+    return updated;
+}
+
+void DiscoveredServices::ServiceDeleted(const ServiceInfo& service_info) {
+    std::lock_guard lock(services_mutex_);
+    VLOG(MDNS) << "Service deleted " << service_info;
+    services_.erase(fq_name(service_info));
+}
+
+std::optional<ServiceInfo> DiscoveredServices::FindInstance(const std::string& service,
+                                                            const std::string& instance) {
+    std::lock_guard lock(services_mutex_);
+    std::string fully_qualified_name = std::format("{}.{}", instance, service);
+    if (!services_.contains(fully_qualified_name)) {
+        return {};
+    }
+    return services_[fully_qualified_name];
+}
+
+void DiscoveredServices::ForEachServiceNamed(
+        const std::string& service_name, const std::function<void(const ServiceInfo&)>& callback) {
+    std::lock_guard lock(services_mutex_);
+    for (const auto& [_, value] : services_) {
+        if (value.service != service_name) {
+            continue;
+        }
+        callback(value);
+    }
+}
+void DiscoveredServices::ForAllServices(const std::function<void(const ServiceInfo&)>& callback) {
+    std::lock_guard lock(services_mutex_);
+    for (const auto& [_, value] : services_) {
+        callback(value);
+    }
+}
+}  // namespace mdns
diff --git a/client/discovered_services.h b/client/discovered_services.h
new file mode 100644
index 00000000..e56a7524
--- /dev/null
+++ b/client/discovered_services.h
@@ -0,0 +1,46 @@
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
+#include <memory>
+#include <string>
+
+#include "client/openscreen/mdns_service_info.h"
+
+namespace mdns {
+class DiscoveredServices {
+  public:
+    void ServiceCreated(const ServiceInfo& service_info);
+
+    // Return true if the provided service_info resulted in an update
+    // of the internal state of DiscoveredServices
+    bool ServiceUpdated(const ServiceInfo& service_info);
+
+    void ServiceDeleted(const ServiceInfo& service_info);
+    std::optional<ServiceInfo> FindInstance(const std::string& service,
+                                            const std::string& instance);
+    void ForEachServiceNamed(const std::string& service,
+                             const std::function<void(const ServiceInfo&)>& callback);
+    void ForAllServices(const std::function<void(const ServiceInfo&)>& callback);
+
+  private:
+    std::mutex services_mutex_;
+    std::unordered_map<std::string, ServiceInfo> services_ GUARDED_BY(services_mutex_);
+};
+
+extern DiscoveredServices discovered_services;
+}  // namespace mdns
\ No newline at end of file
diff --git a/client/discovered_services_test.cpp b/client/discovered_services_test.cpp
new file mode 100644
index 00000000..eae59049
--- /dev/null
+++ b/client/discovered_services_test.cpp
@@ -0,0 +1,86 @@
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
+#include <gtest/gtest.h>
+
+#include "discovered_services.h"
+#include "openscreen/mdns_service_info.h"
+
+using namespace mdns;
+
+TEST(DiscoveredServicesTest, simpleUpdate) {
+    DiscoveredServices services;
+
+    ServiceInfo service;
+    service.instance = "foo";
+    service.service = "bar";
+
+    services.ServiceCreated(service);
+    auto s = services.FindInstance(service.service, service.instance);
+
+    ASSERT_TRUE(s.has_value());
+    ASSERT_EQ("foo", s.value().instance);
+    ASSERT_EQ("bar", s.value().service);
+
+    service.v4_address = openscreen::IPAddress::kV4LoopbackAddress();
+    auto updated = services.ServiceUpdated(service);
+    ASSERT_TRUE(updated);
+}
+
+TEST(DiscoveredServicesTest, NonUpdateV4) {
+    DiscoveredServices services;
+
+    ServiceInfo service;
+    service.instance = "foo";
+    service.service = "bar";
+    service.v4_address = openscreen::IPAddress::kV4LoopbackAddress();
+
+    services.ServiceCreated(service);
+    auto updated = services.ServiceUpdated(service);
+    ASSERT_FALSE(updated);
+}
+
+TEST(DiscoveredServicesTest, NonUpdateV6) {
+    DiscoveredServices services;
+
+    ServiceInfo service;
+    service.instance = "foo";
+    service.service = "bar";
+    service.v6_addresses = {openscreen::IPAddress::kV6LoopbackAddress()};
+
+    services.ServiceCreated(service);
+    auto updated = services.ServiceUpdated(service);
+    ASSERT_FALSE(updated);
+}
+
+TEST(DiscoveredServicesTest, NonUpdateV6WithDifferentSet) {
+    DiscoveredServices services;
+
+    ServiceInfo service;
+    service.instance = "foo";
+    service.service = "bar";
+    service.v6_addresses = {openscreen::IPAddress::kV6LoopbackAddress()};
+
+    services.ServiceCreated(service);
+    auto updated = services.ServiceUpdated(service);
+    ASSERT_FALSE(updated);
+
+    ServiceInfo service_update;
+    service_update.instance = "foo";
+    service_update.service = "bar";
+    updated = services.ServiceUpdated(service_update);
+    ASSERT_FALSE(updated);
+}
\ No newline at end of file
diff --git a/client/host_services.h b/client/host_services.h
new file mode 100644
index 00000000..84718b1a
--- /dev/null
+++ b/client/host_services.h
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
+#include <string>
+
+namespace HostServices {
+constexpr const char* kTrackMdnsServices = "track-mdns-services";
+}
\ No newline at end of file
diff --git a/client/incremental.cpp b/client/incremental.cpp
index f6cf1b04..2319c2f8 100644
--- a/client/incremental.cpp
+++ b/client/incremental.cpp
@@ -16,134 +16,264 @@
 
 #include "incremental.h"
 
-#include "incremental_utils.h"
-
+#include <cstdio>
+#include <cstring>
+#include <format>
+#include <memory>
+#include <mutex>
+#include <optional>
+#include <string>
+#include <string_view>
+#include <tuple>
+#include <unordered_map>
+#include <utility>
+#include <vector>
+
+#include <android-base/errors.h>
 #include <android-base/file.h>
-#include <android-base/stringprintf.h>
+#include <android-base/logging.h>
+#include <android-base/scopeguard.h>
 #include <openssl/base64.h>
 
-#include "adb_client.h"
-#include "adb_utils.h"
+#include "adb_install.h"
+#include "adb_unique_fd.h"
 #include "commandline.h"
+#include "incremental_utils.h"
 #include "sysdeps.h"
 
 using namespace std::literals;
 
 namespace incremental {
 
-using android::base::StringPrintf;
+// Used to be sent as arguments via install-incremental, to describe the IncrementalServer database.
+class ISDatabaseEntry {
+  public:
+    ISDatabaseEntry(std::string filename, size_t size, int file_id)
+        : filename_(std::move(filename)), size_(size), file_id_(file_id) {}
 
-// Read, verify and return the signature bytes. Keeping fd at the position of start of verity tree.
-static std::pair<unique_fd, std::vector<char>> read_signature(Size file_size,
-                                                              std::string signature_file,
-                                                              bool silent) {
-    signature_file += IDSIG;
+    virtual ~ISDatabaseEntry() = default;
 
-    struct stat st;
-    if (stat(signature_file.c_str(), &st)) {
-        if (!silent) {
-            fprintf(stderr, "Failed to stat signature file %s.\n", signature_file.c_str());
-        }
-        return {};
+    virtual bool is_v4_signed() const = 0;
+    int file_id() const { return file_id_; }
+
+    // Convert the database entry to a string that can be sent to `pm` as a command-line parameter.
+    virtual std::string serialize() const = 0;
+
+  protected:
+    std::string filename_;
+    size_t size_;
+    int file_id_;
+};
+
+// A database entry for an signed file.
+class ISSignedDatabaseEntry : public ISDatabaseEntry {
+  public:
+    ISSignedDatabaseEntry(std::string filename, size_t size, int file_id, std::string signature,
+                          std::string path)
+        : ISDatabaseEntry(std::move(filename), size, file_id),
+          signature_(std::move(signature)),
+          path_(std::move(path)) {}
+
+    bool is_v4_signed() const override { return true; };
+
+    std::string serialize() const override {
+        return std::format("{}:{}:{}:{}:{}", filename_, size_, file_id_, signature_,
+                           kProtocolVersion);
+    }
+
+    std::string path() const { return path_; }
+
+  private:
+    static constexpr int kProtocolVersion = 1;
+
+    std::string signature_;
+    std::string path_;
+};
+
+// A database entry for an unsigned file.
+class ISUnsignedDatabaseEntry : public ISDatabaseEntry {
+  public:
+    ISUnsignedDatabaseEntry(std::string filename, int64_t size, int file_id, unique_fd fd)
+        : ISDatabaseEntry(std::move(filename), size, file_id), fd_(std::move(fd)) {}
+
+    bool is_v4_signed() const override { return false; };
+
+    std::string serialize() const override {
+        return std::format("{}:{}:{}", filename_, size_, file_id_);
     }
 
+    borrowed_fd fd() const { return fd_; }
+
+  private:
+    unique_fd fd_;
+};
+
+static bool requires_v4_signature(const std::string& file) {
+    // Signature has to be present for APKs.
+    return android::base::EndsWithIgnoreCase(file, ".apk") ||
+           android::base::EndsWithIgnoreCase(file, kSdmExtension);
+}
+
+// Read and return the signature bytes and the tree size.
+static std::optional<std::pair<std::vector<char>, int32_t>> read_signature(
+        const std::string& signature_file, std::string* error) {
     unique_fd fd(adb_open(signature_file.c_str(), O_RDONLY));
     if (fd < 0) {
-        if (!silent) {
-            fprintf(stderr, "Failed to open signature file: %s.\n", signature_file.c_str());
+        if (errno == ENOENT) {
+            return std::make_pair(std::vector<char>{}, 0);
         }
+        *error = std::format("Failed to open signature file '{}': {}", signature_file,
+                             strerror(errno));
         return {};
     }
 
-    auto [signature, tree_size] = read_id_sig_headers(fd);
+    return read_id_sig_headers(fd, error);
+}
 
-    std::vector<char> invalid_signature;
-    if (signature.empty()) {
-        if (!silent) {
-            fprintf(stderr, "Invalid signature format. Abort.\n");
-        }
-        return {std::move(fd), std::move(invalid_signature)};
-    }
+static bool validate_signature(const std::vector<char>& signature, int32_t tree_size,
+                               size_t file_size, std::string* error) {
     if (signature.size() > kMaxSignatureSize) {
-        if (!silent) {
-            fprintf(stderr, "Signature is too long: %lld. Max allowed is %d. Abort.\n",
-                    (long long)signature.size(), kMaxSignatureSize);
-        }
-        return {std::move(fd), std::move(invalid_signature)};
+        *error = std::format("Signature is too long: {}. Max allowed is {}", signature.size(),
+                             kMaxSignatureSize);
+        return false;
     }
 
-    if (auto expected = verity_tree_size_for_file(file_size); tree_size != expected) {
-        if (!silent) {
-            fprintf(stderr,
-                    "Verity tree size mismatch in signature file: %s [was %lld, expected %lld].\n",
-                    signature_file.c_str(), (long long)tree_size, (long long)expected);
-        }
-        return {std::move(fd), std::move(invalid_signature)};
+    if (Size expected = verity_tree_size_for_file(file_size); tree_size != expected) {
+        *error =
+                std::format("Verity tree size mismatch [was {}, expected {}]", tree_size, expected);
+        return false;
     }
 
-    return {std::move(fd), std::move(signature)};
+    return true;
 }
 
-// Base64-encode signature bytes. Keeping fd at the position of start of verity tree.
-static std::pair<unique_fd, std::string> read_and_encode_signature(Size file_size,
-                                                                   std::string signature_file,
-                                                                   bool silent) {
+// Base64-encode signature bytes.
+static std::optional<std::string> encode_signature(const std::vector<char>& signature,
+                                                   std::string* error) {
     std::string encoded_signature;
 
-    auto [fd, signature] = read_signature(file_size, std::move(signature_file), silent);
-    if (!fd.ok() || signature.empty()) {
-        return {std::move(fd), std::move(encoded_signature)};
-    }
-
     size_t base64_len = 0;
     if (!EVP_EncodedLength(&base64_len, signature.size())) {
-        if (!silent) {
-            fprintf(stderr, "Fail to estimate base64 encoded length. Abort.\n");
-        }
-        return {std::move(fd), std::move(encoded_signature)};
+        *error = "Fail to estimate base64 encoded length";
+        return {};
     }
 
     encoded_signature.resize(base64_len, '\0');
     encoded_signature.resize(EVP_EncodeBlock((uint8_t*)encoded_signature.data(),
                                              (const uint8_t*)signature.data(), signature.size()));
 
-    return {std::move(fd), std::move(encoded_signature)};
+    return std::move(encoded_signature);
 }
 
-// Send install-incremental to the device along with properly configured file descriptors in
-// streaming format. Once connection established, send all fs-verity tree bytes.
-static unique_fd start_install(const Files& files, const Args& passthrough_args, bool silent) {
-    std::vector<std::string> command_args{"package", "install-incremental"};
-    command_args.insert(command_args.end(), passthrough_args.begin(), passthrough_args.end());
+static std::optional<std::pair<unique_fd, size_t>> open_and_get_size(const std::string& file,
+                                                                     std::string* error) {
+    unique_fd fd(adb_open(file.c_str(), O_RDONLY));
+    if (fd < 0) {
+        *error = std::format("Failed to open input file '{}': {}", file, strerror(errno));
+        return {};
+    }
 
-    for (int i = 0, size = files.size(); i < size; ++i) {
-        const auto& file = files[i];
+    struct stat st;
+    if (fstat(fd.get(), &st)) {
+        *error = std::format("Failed to stat input file '{}': {}", file, strerror(errno));
+        return {};
+    }
 
-        struct stat st;
-        if (stat(file.c_str(), &st)) {
-            if (!silent) {
-                fprintf(stderr, "Failed to stat input file %s. Abort.\n", file.c_str());
-            }
+    return std::make_pair(std::move(fd), st.st_size);
+}
+
+// Returns a list of IncrementalServer database entries.
+// - The caller is expected to send the entries as arguments via install-incremental.
+// - For signed files in the list, the caller is expected to send them via streaming, with file ids
+//   being the indexes in the list.
+// - For unsigned files in the list, the caller is expected to send them through stdin before
+//   streaming the signed ones, in the order specified by the list.
+static std::optional<std::vector<std::unique_ptr<ISDatabaseEntry>>> build_database(
+        const Files& files, std::string* error) {
+    std::unordered_map<std::string, std::pair<std::vector<char>, int32_t>> signatures_by_file;
+
+    for (const std::string& file : files) {
+        auto signature_and_tree_size = read_signature(std::string(file).append(IDSIG), error);
+        if (!signature_and_tree_size.has_value()) {
+            return {};
+        }
+        if (requires_v4_signature(file) && signature_and_tree_size->first.empty()) {
+            *error = std::format("V4 signature missing for '{}'", file);
+            return {};
+        }
+        signatures_by_file[file] = std::move(*signature_and_tree_size);
+    }
+
+    // Constraints:
+    // - Signed files are later passed to IncrementalServer, which assumes the list indexes being
+    //   the file ids, and the file ids for `incremental-install` and IncrementalServer must match.
+    //   Therefore, we assign the leading file ids to the signed files, so their file ids match
+    //   their list indexes and the indexes are unchanged when we discard unsigned files from the
+    //   list.
+    // - Unsigned files are later sent through stdin, while `pm` on the other end assumes the
+    //   inputs being ordered by the file ids incrementally. Therefore, we assign file ids to
+    //   unsigned files in the same order as their list indexes.
+    std::vector<std::unique_ptr<ISDatabaseEntry>> database;
+    int file_id = 0;
+
+    for (const std::string& file : files) {
+        const auto& [signature, tree_size] = signatures_by_file[file];
+        if (signature.empty()) {
+            continue;
+        }
+        // Signed files. Will be sent in streaming mode.
+        auto fd_and_size = open_and_get_size(file, error);
+        if (!fd_and_size.has_value()) {
+            return {};
+        }
+        if (!validate_signature(signature, tree_size, fd_and_size->second, error)) {
+            return {};
+        }
+        std::optional<std::string> encoded_signature = encode_signature(signature, error);
+        if (!encoded_signature.has_value()) {
             return {};
         }
+        database.push_back(std::make_unique<ISSignedDatabaseEntry>(android::base::Basename(file),
+                                                                   fd_and_size->second, file_id++,
+                                                                   *encoded_signature, file));
+    }
 
-        auto [signature_fd, signature] = read_and_encode_signature(st.st_size, file, silent);
-        if (signature_fd.ok() && signature.empty()) {
+    for (const std::string& file : files) {
+        const auto& [signature, _] = signatures_by_file[file];
+        if (!signature.empty()) {
+            continue;
+        }
+        // Unsigned files. Will be sent in stdin mode.
+        // Open the file for reading. We'll return the FD for the caller to send it through stdin.
+        auto fd_and_size = open_and_get_size(file, error);
+        if (!fd_and_size.has_value()) {
             return {};
         }
+        database.push_back(std::make_unique<ISUnsignedDatabaseEntry>(
+                android::base::Basename(file), fd_and_size->second, file_id++,
+                std::move(fd_and_size->first)));
+    }
 
-        auto file_desc = StringPrintf("%s:%lld:%d:%s:1", android::base::Basename(file).c_str(),
-                                      (long long)st.st_size, i, signature.c_str());
-        command_args.push_back(std::move(file_desc));
+    return std::move(database);
+}
+
+// Opens a connection and sends install-incremental to the device along with the database.
+// Returns a socket FD connected to the `abb` deamon on device, where writes to it go to `pm`
+// shell's stdin and reads from it come from `pm` shell's stdout.
+static std::optional<unique_fd> connect_and_send_database(
+        const std::vector<std::unique_ptr<ISDatabaseEntry>>& database, const Args& passthrough_args,
+        std::string* error) {
+    std::vector<std::string> command_args{"package", "install-incremental"};
+    command_args.insert(command_args.end(), passthrough_args.begin(), passthrough_args.end());
+    for (const std::unique_ptr<ISDatabaseEntry>& entry : database) {
+        command_args.push_back(entry->serialize());
     }
 
-    std::string error;
-    auto connection_fd = unique_fd(send_abb_exec_command(command_args, &error));
+    std::string inner_error;
+    auto connection_fd = unique_fd(send_abb_exec_command(command_args, &inner_error));
     if (connection_fd < 0) {
-        if (!silent) {
-            fprintf(stderr, "Failed to run: %s, error: %s\n",
-                    android::base::Join(command_args, " ").c_str(), error.c_str());
-        }
+        *error = std::format("Failed to run '{}': {}", android::base::Join(command_args, " "),
+                             inner_error);
         return {};
     }
 
@@ -157,10 +287,14 @@ bool can_install(const Files& files) {
             return false;
         }
 
-        if (android::base::EndsWithIgnoreCase(file, ".apk")) {
-            // Signature has to be present for APKs.
-            auto [fd, _] = read_signature(st.st_size, file, /*silent=*/true);
-            if (!fd.ok()) {
+        if (requires_v4_signature(file)) {
+            std::string error;
+            auto signature_and_tree_size = read_signature(std::string(file).append(IDSIG), &error);
+            if (!signature_and_tree_size.has_value()) {
+                return false;
+            }
+            if (!validate_signature(signature_and_tree_size->first, signature_and_tree_size->second,
+                                    st.st_size, &error)) {
                 return false;
             }
         }
@@ -168,104 +302,139 @@ bool can_install(const Files& files) {
     return true;
 }
 
-std::optional<Process> install(const Files& files, const Args& passthrough_args, bool silent) {
-    auto connection_fd = start_install(files, passthrough_args, silent);
-    if (connection_fd < 0) {
-        if (!silent) {
-            fprintf(stderr, "adb: failed to initiate installation on device.\n");
+static bool send_unsigned_files(borrowed_fd connection_fd,
+                                const std::vector<std::unique_ptr<ISDatabaseEntry>>& database,
+                                std::string* error) {
+    std::once_flag print_once;
+    for (const std::unique_ptr<ISDatabaseEntry>& entry : database) {
+        if (entry->is_v4_signed()) {
+            continue;
+        }
+        auto unsigned_entry = static_cast<ISUnsignedDatabaseEntry*>(entry.get());
+        std::call_once(print_once, [] { printf("Sending unsigned files...\n"); });
+        if (!copy_to_file(unsigned_entry->fd().get(), connection_fd.get())) {
+            *error = "adb: failed to send unsigned files";
+            return false;
         }
-        return {};
     }
+    return true;
+}
 
-    std::string adb_path = android::base::GetExecutablePath();
-
-    auto osh = cast_handle_to_int(adb_get_os_handle(connection_fd.get()));
-    auto fd_param = std::to_string(osh);
+// Wait until the Package Manager returns either "Success" or "Failure". The streaming
+// may not have finished when this happens but PM received all the blocks is needs
+// to decide if installation was ok.
+static bool wait_for_installation(int read_fd, std::string* error) {
+    static constexpr int kMaxMessageSize = 256;
+    std::string child_stdout;
+    child_stdout.resize(kMaxMessageSize);
+    int bytes_read = adb_read(read_fd, child_stdout.data(), kMaxMessageSize);
+    if (bytes_read < 0) {
+        *error = std::format("Failed to read output: {}", strerror(errno));
+        return false;
+    }
+    child_stdout.resize(bytes_read);
+    // wait till installation either succeeds or fails
+    if (child_stdout.find("Success") != std::string::npos) {
+        return true;
+    }
+    // on failure, wait for full message
+    auto begin_itr = child_stdout.find("Failure [");
+    if (begin_itr != std::string::npos) {
+        auto end_itr = child_stdout.rfind("]");
+        if (end_itr != std::string::npos && end_itr >= begin_itr) {
+            *error = std::format(
+                    "Install failed: {}",
+                    std::string_view(child_stdout).substr(begin_itr, end_itr - begin_itr + 1));
+            return false;
+        }
+    }
+    if (bytes_read == kMaxMessageSize) {
+        *error = std::format("Output too long: {}", child_stdout);
+        return false;
+    }
+    *error = std::format("Failed to parse output: {}", child_stdout);
+    return false;
+}
 
+static std::optional<Process> start_inc_server_and_stream_signed_files(
+        borrowed_fd connection_fd, const std::vector<std::unique_ptr<ISDatabaseEntry>>& database,
+        std::string* error) {
     // pipe for child process to write output
     int print_fds[2];
     if (adb_socketpair(print_fds) != 0) {
-        if (!silent) {
-            fprintf(stderr, "adb: failed to create socket pair for child to print to parent\n");
-        }
+        *error = "adb: failed to create socket pair for child to print to parent";
         return {};
     }
     auto [pipe_read_fd, pipe_write_fd] = print_fds;
-    auto pipe_write_fd_param = std::to_string(cast_handle_to_int(adb_get_os_handle(pipe_write_fd)));
+    auto fd_cleaner = android::base::make_scope_guard([&] {
+        adb_close(pipe_read_fd);
+        adb_close(pipe_write_fd);
+    });
     close_on_exec(pipe_read_fd);
 
     // We spawn an incremental server that will be up until all blocks have been fed to the
     // Package Manager. This could take a long time depending on the size of the files to
     // stream so we use a process able to outlive adb.
-    std::vector<std::string> args(std::move(files));
-    args.insert(args.begin(), {"inc-server", fd_param, pipe_write_fd_param});
-    auto child =
+    std::vector<std::string> args{
+            "inc-server",
+            std::to_string(cast_handle_to_int(adb_get_os_handle(connection_fd.get()))),
+            std::to_string(cast_handle_to_int(adb_get_os_handle(pipe_write_fd)))};
+    int arg_pos = 0;
+    for (const std::unique_ptr<ISDatabaseEntry>& entry : database) {
+        if (!entry->is_v4_signed()) {
+            continue;
+        }
+        // The incremental server assumes the argument position being the file ids.
+        CHECK_EQ(entry->file_id(), arg_pos++);
+        auto signed_entry = static_cast<ISSignedDatabaseEntry*>(entry.get());
+        args.push_back(signed_entry->path());
+    }
+    std::string adb_path = android::base::GetExecutablePath();
+    Process child =
             adb_launch_process(adb_path, std::move(args), {connection_fd.get(), pipe_write_fd});
     if (!child) {
-        if (!silent) {
-            fprintf(stderr, "adb: failed to fork: %s\n", strerror(errno));
-        }
+        *error = "adb: failed to fork";
         return {};
     }
-
-    adb_close(pipe_write_fd);
-
-    auto killOnExit = [](Process* p) { p->kill(); };
-    std::unique_ptr<Process, decltype(killOnExit)> serverKiller(&child, killOnExit);
+    auto server_killer = android::base::make_scope_guard([&] { child.kill(); });
 
     // Block until the Package Manager has received enough blocks to declare the installation
     // successful or failure. Meanwhile, the incremental server is still sending blocks to the
     // device.
-    Result result = wait_for_installation(pipe_read_fd);
-    adb_close(pipe_read_fd);
-
-    if (result != Result::Success) {
-        if (!silent) {
-            fprintf(stderr, "adb: install command failed");
-        }
+    if (!wait_for_installation(pipe_read_fd, error)) {
         return {};
     }
 
     // adb client exits now but inc-server can continue
-    serverKiller.release();
+    server_killer.Disable();
     return child;
 }
 
-// Wait until the Package Manager returns either "Success" or "Failure". The streaming
-// may not have finished when this happens but PM received all the blocks is needs
-// to decide if installation was ok.
-Result wait_for_installation(int read_fd) {
-    static constexpr int maxMessageSize = 256;
-    std::vector<char> child_stdout(CHUNK_SIZE);
-    int bytes_read;
-    int buf_size = 0;
-    // TODO(b/150865433): optimize child's output parsing
-    while ((bytes_read = adb_read(read_fd, child_stdout.data() + buf_size,
-                                  child_stdout.size() - buf_size)) > 0) {
-        // print to parent's stdout
-        fprintf(stdout, "%.*s", bytes_read, child_stdout.data() + buf_size);
-
-        buf_size += bytes_read;
-        const std::string_view stdout_str(child_stdout.data(), buf_size);
-        // wait till installation either succeeds or fails
-        if (stdout_str.find("Success") != std::string::npos) {
-            return Result::Success;
-        }
-        // on failure, wait for full message
-        static constexpr auto failure_msg_head = "Failure ["sv;
-        if (const auto begin_itr = stdout_str.find(failure_msg_head);
-            begin_itr != std::string::npos) {
-            if (buf_size >= maxMessageSize) {
-                return Result::Failure;
-            }
-            const auto end_itr = stdout_str.rfind("]");
-            if (end_itr != std::string::npos && end_itr >= begin_itr + failure_msg_head.size()) {
-                return Result::Failure;
-            }
-        }
-        child_stdout.resize(buf_size + CHUNK_SIZE);
+std::optional<Process> install(const Files& files, const Args& passthrough_args,
+                               std::string* error) {
+    std::optional<std::vector<std::unique_ptr<ISDatabaseEntry>>> database =
+            build_database(files, error);
+    if (!database.has_value()) {
+        return {};
+    }
+    std::optional<unique_fd> connection_fd =
+            connect_and_send_database(*database, passthrough_args, error);
+    if (!connection_fd.has_value()) {
+        return {};
+    }
+    if (!send_unsigned_files(*connection_fd, *database, error)) {
+        return {};
+    }
+    return start_inc_server_and_stream_signed_files(*connection_fd, *database, error);
+}
+
+std::optional<Process> install(const Files& files, const Args& passthrough_args, bool silent) {
+    std::string error;
+    std::optional<Process> res = install(files, passthrough_args, &error);
+    if (!res.has_value() && !silent) {
+        fprintf(stderr, "%s.\n", error.c_str());
     }
-    return Result::None;
+    return res;
 }
 
 }  // namespace incremental
diff --git a/client/incremental.h b/client/incremental.h
index 40e928ae..7861cdce 100644
--- a/client/incremental.h
+++ b/client/incremental.h
@@ -16,10 +16,9 @@
 
 #pragma once
 
-#include "adb_unique_fd.h"
-
 #include <optional>
 #include <string>
+#include <vector>
 
 #include "sysdeps.h"
 
@@ -31,7 +30,4 @@ using Args = std::vector<std::string_view>;
 bool can_install(const Files& files);
 std::optional<Process> install(const Files& files, const Args& passthrough_args, bool silent);
 
-enum class Result { Success, Failure, None };
-Result wait_for_installation(int read_fd);
-
 }  // namespace incremental
diff --git a/client/incremental_server.cpp b/client/incremental_server.cpp
index 156cc47b..6c95d8b3 100644
--- a/client/incremental_server.cpp
+++ b/client/incremental_server.cpp
@@ -18,8 +18,6 @@
 
 #include "incremental_server.h"
 
-#include <android-base/endian.h>
-#include <android-base/strings.h>
 #include <inttypes.h>
 #include <lz4.h>
 #include <stdio.h>
@@ -34,6 +32,9 @@
 #include <type_traits>
 #include <unordered_set>
 
+#include <android-base/endian.h>
+#include <android-base/strings.h>
+
 #include "adb.h"
 #include "adb_client.h"
 #include "adb_io.h"
@@ -680,7 +681,14 @@ static std::pair<unique_fd, int64_t> open_signature(int64_t file_size, const cha
         return {};
     }
 
-    auto [tree_offset, tree_size] = skip_id_sig_headers(fd);
+    std::string error;
+    auto res = skip_id_sig_headers(fd, &error);
+    if (!res.has_value()) {
+        D("Invalid signature file '%s': %s", filepath, error.c_str());
+        return {};
+    }
+
+    auto [tree_offset, tree_size] = std::move(res.value());
     if (auto expected = verity_tree_size_for_file(file_size); tree_size != expected) {
         error_exit("Verity tree size mismatch in signature file: %s [was %lld, expected %lld].\n",
                    signature_file.c_str(), (long long)tree_size, (long long)expected);
diff --git a/client/incremental_utils.cpp b/client/incremental_utils.cpp
index 67f21a13..121e1bd2 100644
--- a/client/incremental_utils.cpp
+++ b/client/incremental_utils.cpp
@@ -18,18 +18,21 @@
 
 #include "incremental_utils.h"
 
+#include <algorithm>
+#include <array>
+#include <cstring>
+#include <format>
+#include <numeric>
+#include <optional>
+#include <unordered_set>
+#include <utility>
+
 #include <android-base/endian.h>
 #include <android-base/mapped_file.h>
 #include <android-base/strings.h>
 #include <ziparchive/zip_archive.h>
 #include <ziparchive/zip_writer.h>
 
-#include <algorithm>
-#include <array>
-#include <cinttypes>
-#include <numeric>
-#include <unordered_set>
-
 #include "adb_io.h"
 #include "adb_trace.h"
 #include "sysdeps.h"
@@ -64,30 +67,44 @@ Size verity_tree_size_for_file(Size fileSize) {
     return verity_tree_blocks_for_file(fileSize) * kBlockSize;
 }
 
-static inline int32_t read_int32(borrowed_fd fd) {
+static inline std::optional<int32_t> read_int32(borrowed_fd fd, std::string* error) {
     int32_t result;
-    return ReadFdExactly(fd, &result, sizeof(result)) ? result : -1;
+    if (!ReadFdExactly(fd, &result, sizeof(result))) {
+        *error =
+                std::format("Failed to read int: {}", errno == 0 ? "End of file" : strerror(errno));
+        return {};
+    }
+    return result;
 }
 
-static inline int32_t skip_int(borrowed_fd fd) {
-    return adb_lseek(fd, 4, SEEK_CUR);
+static inline bool skip_int(borrowed_fd fd, std::string* error) {
+    if (adb_lseek(fd, 4, SEEK_CUR) < 0) {
+        *error = std::format("Failed to seek: {}", strerror(errno));
+        return false;
+    }
+    return true;
 }
 
-static inline void append_int(borrowed_fd fd, std::vector<char>* bytes) {
-    int32_t le_val = read_int32(fd);
+static inline bool append_int(borrowed_fd fd, std::vector<char>* bytes, std::string* error) {
+    std::optional<int32_t> le_val = read_int32(fd, error);
+    if (!le_val.has_value()) {
+        return false;
+    }
     auto old_size = bytes->size();
-    bytes->resize(old_size + sizeof(le_val));
-    memcpy(bytes->data() + old_size, &le_val, sizeof(le_val));
+    bytes->resize(old_size + sizeof(*le_val));
+    memcpy(bytes->data() + old_size, &le_val.value(), sizeof(*le_val));
+    return true;
 }
 
-static inline bool append_bytes_with_size(borrowed_fd fd, std::vector<char>* bytes,
-                                          int* bytes_left) {
-    int32_t le_size = read_int32(fd);
-    if (le_size < 0) {
+static inline bool append_bytes_with_size(borrowed_fd fd, std::vector<char>* bytes, int* bytes_left,
+                                          std::string* error) {
+    std::optional<int32_t> le_size = read_int32(fd, error);
+    if (!le_size.has_value()) {
         return false;
     }
-    int32_t size = int32_t(le32toh(le_size));
+    int32_t size = int32_t(le32toh(*le_size));
     if (size < 0 || size > *bytes_left) {
+        *error = std::format("Invalid size {}", size);
         return false;
     }
     if (size == 0) {
@@ -95,42 +112,75 @@ static inline bool append_bytes_with_size(borrowed_fd fd, std::vector<char>* byt
     }
     *bytes_left -= size;
     auto old_size = bytes->size();
-    bytes->resize(old_size + sizeof(le_size) + size);
-    memcpy(bytes->data() + old_size, &le_size, sizeof(le_size));
-    ReadFdExactly(fd, bytes->data() + old_size + sizeof(le_size), size);
+    bytes->resize(old_size + sizeof(*le_size) + size);
+    memcpy(bytes->data() + old_size, &le_size.value(), sizeof(*le_size));
+    if (!ReadFdExactly(fd, bytes->data() + old_size + sizeof(*le_size), size)) {
+        *error = std::format("Failed to read data: {}",
+                             errno == 0 ? "End of file" : strerror(errno));
+        return false;
+    }
     return true;
 }
 
-static inline int32_t skip_bytes_with_size(borrowed_fd fd) {
-    int32_t le_size = read_int32(fd);
-    if (le_size < 0) {
-        return -1;
+static inline bool skip_bytes_with_size(borrowed_fd fd, std::string* error) {
+    std::optional<int32_t> le_size = read_int32(fd, error);
+    if (!le_size.has_value()) {
+        return false;
     }
-    int32_t size = int32_t(le32toh(le_size));
-    return (int32_t)adb_lseek(fd, size, SEEK_CUR);
+    int32_t size = int32_t(le32toh(*le_size));
+    if (size < 0) {
+        *error = std::format("Invalid size {}", size);
+        return false;
+    }
+    if (adb_lseek(fd, size, SEEK_CUR) < 0) {
+        *error = "Failed to seek";
+        return false;
+    }
+    return true;
 }
 
-std::pair<std::vector<char>, int32_t> read_id_sig_headers(borrowed_fd fd) {
+std::optional<std::pair<std::vector<char>, int32_t>> read_id_sig_headers(borrowed_fd fd,
+                                                                         std::string* error) {
     std::vector<char> signature;
-    append_int(fd, &signature);  // version
+    if (!append_int(fd, &signature, error)) {  // version
+        return {};
+    }
     int max_size = kMaxSignatureSize - sizeof(int32_t);
-    // hashingInfo and signingInfo
-    if (!append_bytes_with_size(fd, &signature, &max_size) ||
-        !append_bytes_with_size(fd, &signature, &max_size)) {
+    if (!append_bytes_with_size(fd, &signature, &max_size, error)) {  // hashingInfo
+        return {};
+    }
+    if (!append_bytes_with_size(fd, &signature, &max_size, error)) {  // signingInfo
+        return {};
+    }
+    std::optional<int32_t> le_tree_size = read_int32(fd, error);
+    if (!le_tree_size.has_value()) {
         return {};
     }
-    auto le_tree_size = read_int32(fd);
-    auto tree_size = int32_t(le32toh(le_tree_size));  // size of the verity tree
-    return {std::move(signature), tree_size};
+    auto tree_size = int32_t(le32toh(*le_tree_size));  // size of the verity tree
+    return std::make_pair(std::move(signature), tree_size);
 }
 
-std::pair<off64_t, ssize_t> skip_id_sig_headers(borrowed_fd fd) {
-    skip_int(fd);                            // version
-    skip_bytes_with_size(fd);                // hashingInfo
-    auto offset = skip_bytes_with_size(fd);  // signingInfo
-    auto le_tree_size = read_int32(fd);
-    auto tree_size = int32_t(le32toh(le_tree_size));  // size of the verity tree
-    return {offset + sizeof(le_tree_size), tree_size};
+std::optional<std::pair<off64_t, ssize_t>> skip_id_sig_headers(borrowed_fd fd, std::string* error) {
+    if (!skip_int(fd, error)) {  // version
+        return {};
+    }
+    if (!skip_bytes_with_size(fd, error)) {  // hashingInfo
+        return {};
+    }
+    if (!skip_bytes_with_size(fd, error)) {  // signingInfo
+        return {};
+    }
+    std::optional<int32_t> le_tree_size = read_int32(fd, error);
+    if (!le_tree_size.has_value()) {
+        return {};
+    }
+    int32_t tree_size = int32_t(le32toh(*le_tree_size));  // size of the verity tree
+    off_t offset = adb_lseek(fd, 0, SEEK_CUR);
+    if (offset < 0) {
+        *error = std::format("Failed to get offset: {}", strerror(errno));
+        return {};
+    }
+    return std::make_pair(offset, tree_size);
 }
 
 template <class T>
diff --git a/client/incremental_utils.h b/client/incremental_utils.h
index 4ad60dd2..731d453e 100644
--- a/client/incremental_utils.h
+++ b/client/incremental_utils.h
@@ -18,6 +18,7 @@
 
 #include "adb_unique_fd.h"
 
+#include <optional>
 #include <string>
 #include <string_view>
 #include <utility>
@@ -43,7 +44,8 @@ std::vector<int32_t> PriorityBlocksForFile(const std::string& filepath, borrowed
 Size verity_tree_blocks_for_file(Size fileSize);
 Size verity_tree_size_for_file(Size fileSize);
 
-std::pair<std::vector<char>, int32_t> read_id_sig_headers(borrowed_fd fd);
-std::pair<off64_t, ssize_t> skip_id_sig_headers(borrowed_fd fd);
+std::optional<std::pair<std::vector<char>, int32_t>> read_id_sig_headers(borrowed_fd fd,
+                                                                         std::string* error);
+std::optional<std::pair<off64_t, ssize_t>> skip_id_sig_headers(borrowed_fd fd, std::string* error);
 
 }  // namespace incremental
diff --git a/client/main.cpp b/client/main.cpp
index 50a60a7b..73397fe2 100644
--- a/client/main.cpp
+++ b/client/main.cpp
@@ -36,7 +36,7 @@
 #include "adb_listeners.h"
 #include "adb_mdns.h"
 #include "adb_utils.h"
-#include "adb_wifi.h"
+#include "client/adb_wifi.h"
 #include "client/mdns_utils.h"
 #include "client/transport_client.h"
 #include "client/usb.h"
@@ -71,11 +71,9 @@ void adb_server_cleanup() {
     //   1. close_smartsockets, so that we don't get any new clients
     //   2. kick_all_transports, to avoid writing only part of a packet to a transport.
     //   3. usb_cleanup, to tear down the USB stack.
-    //   4. mdns_cleanup, to tear down mdns stack.
     close_smartsockets();
     kick_all_transports();
     usb_cleanup();
-    mdns_cleanup();
 }
 
 static void intentionally_leak() {
diff --git a/client/mdns_tracker.cpp b/client/mdns_tracker.cpp
new file mode 100644
index 00000000..9af5ea69
--- /dev/null
+++ b/client/mdns_tracker.cpp
@@ -0,0 +1,151 @@
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
+#include "mdns_tracker.h"
+
+#include <list>
+#include <string>
+
+#include <google/protobuf/text_format.h>
+#include "adb_host.pb.h"
+#include "adb_mdns.h"
+#include "adb_trace.h"
+#include "adb_wifi.h"
+#include "client/discovered_services.h"
+
+struct MdnsTracker {
+    explicit MdnsTracker() {}
+    asocket socket_;
+    bool update_needed_ = true;
+};
+
+// Not synchronized because all calls happen on fdevent thread
+static std::list<MdnsTracker*> mdns_trackers [[clang::no_destroy]];
+
+static std::string list_mdns_services() {
+    adb::proto::MdnsServices services;
+
+    mdns::discovered_services.ForAllServices([&](const mdns::ServiceInfo& service) {
+        adb::proto::MdnsService* s = nullptr;
+
+        if (service.service == ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_SERVICE_TYPE)) {
+            auto* tcp = services.add_tcp();
+            s = tcp->mutable_service();
+        } else if (service.service == ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_PAIRING_TYPE)) {
+            auto* pair = services.add_pair();
+            s = pair->mutable_service();
+        } else if (service.service == ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_CONNECT_TYPE)) {
+            auto* tls = services.add_tls();
+            tls->set_known_device(adb_wifi_is_known_host(service.instance));
+            s = tls->mutable_service();
+        } else {
+            LOG(WARNING) << "Unknown service type: " << service;
+            return;
+        }
+
+        s->set_instance(service.instance);
+        s->set_service(service.service);
+        s->set_port(service.port);
+
+        if (service.v4_address.has_value()) {
+            s->set_ipv4(service.v4_address_string());
+        }
+
+        for (auto& address : service.v6_addresses) {
+            auto ipv6 = s->add_ipv6();
+            ipv6->append(mdns::to_string(address));
+        }
+
+        if (service.attributes.contains("name")) {
+            s->set_product_model(service.attributes.at("name"));
+        }
+        if (service.attributes.contains("api")) {
+            s->set_build_version_sdk_full(service.attributes.at("api"));
+        }
+    });
+
+    std::string proto;
+    services.SerializeToString(&proto);
+    return proto;
+}
+
+static void mdns_tracker_close(asocket* socket) {
+    fdevent_check_looper();
+    auto* tracker = reinterpret_cast<MdnsTracker*>(socket);
+    asocket* peer = socket->peer;
+
+    VLOG(MDNS) << "mdns tracker removed";
+    if (peer) {
+        peer->peer = nullptr;
+        peer->close(peer);
+    }
+    mdns_trackers.remove(tracker);
+    delete tracker;
+}
+
+static int device_tracker_enqueue(asocket* socket, apacket::payload_type) {
+    fdevent_check_looper();
+    /* you can't read from a device tracker, close immediately */
+    mdns_tracker_close(socket);
+    return -1;
+}
+
+static int mdns_tracker_send(const MdnsTracker* tracker, const std::string& string) {
+    fdevent_check_looper();
+    asocket* peer = tracker->socket_.peer;
+
+    apacket::payload_type data;
+    data.resize(4 + string.size());
+    char buf[5];
+    snprintf(buf, sizeof(buf), "%04x", static_cast<int>(string.size()));
+    memcpy(&data[0], buf, 4);
+    memcpy(&data[4], string.data(), string.size());
+    return peer->enqueue(peer, std::move(data));
+}
+
+static void mdns_tracker_ready(asocket* socket) {
+    fdevent_check_looper();
+    auto* tracker = reinterpret_cast<MdnsTracker*>(socket);
+
+    // We want to send the service list when the tracker connects
+    // for the first time, even if no update occurred.
+    if (tracker->update_needed_) {
+        tracker->update_needed_ = false;
+        mdns_tracker_send(tracker, list_mdns_services());
+    }
+}
+
+asocket* create_mdns_tracker() {
+    fdevent_check_looper();
+    auto* tracker = new MdnsTracker();
+    VLOG(MDNS) << "mdns tracker created";
+
+    tracker->socket_.enqueue = device_tracker_enqueue;
+    tracker->socket_.ready = mdns_tracker_ready;
+    tracker->socket_.close = mdns_tracker_close;
+    tracker->update_needed_ = true;
+
+    mdns_trackers.emplace_back(tracker);
+    return &tracker->socket_;
+}
+
+void update_mdns_trackers() {
+    fdevent_run_on_looper([=]() {
+        for (MdnsTracker* tracker : mdns_trackers) {
+            mdns_tracker_send(tracker, list_mdns_services());
+        }
+    });
+}
\ No newline at end of file
diff --git a/client/mdns_tracker.h b/client/mdns_tracker.h
new file mode 100644
index 00000000..2048d7e7
--- /dev/null
+++ b/client/mdns_tracker.h
@@ -0,0 +1,22 @@
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
+#include "socket.h"
+
+asocket* create_mdns_tracker();
+void update_mdns_trackers();
\ No newline at end of file
diff --git a/client/mdns_utils_test.cpp b/client/mdns_utils_test.cpp
index ec715295..a368cf2a 100644
--- a/client/mdns_utils_test.cpp
+++ b/client/mdns_utils_test.cpp
@@ -15,6 +15,7 @@
  */
 
 #include "client/mdns_utils.h"
+#include "client/openscreen/mdns_service_info.h"
 
 #include <gtest/gtest.h>
 
@@ -170,4 +171,44 @@ TEST(mdns_utils, mdns_parse_instance_name) {
     }
 }
 
+TEST(mdns_utils, mdns_split_txt_record_empty) {
+    std::string empty;
+    auto [status, key, value] = ParseTxtKeyValue(empty);
+    EXPECT_FALSE(status);
+}
+
+TEST(mdns_utils, mdns_split_txt_record_just_splitter) {
+    std::string just_splitter = "=";
+    auto [status, key, value] = ParseTxtKeyValue(just_splitter);
+    EXPECT_FALSE(status);
+}
+
+TEST(mdns_utils, mdns_split_txt_record_no_key) {
+    std::string no_key = "=value";
+    auto [status, key, value] = ParseTxtKeyValue(no_key);
+    EXPECT_FALSE(status);
+}
+
+TEST(mdns_utils, mdns_split_txt_record_no_value) {
+    std::string no_value = "key=";
+    auto [status, key, value] = ParseTxtKeyValue(no_value);
+    EXPECT_TRUE(status);
+    EXPECT_TRUE(key == "key");
+    EXPECT_TRUE(value.empty());
+}
+
+TEST(mdns_utils, mdns_split_txt_record_no_split) {
+    std::string no_split = "keyvalue";
+    auto [status, key, value] = ParseTxtKeyValue(no_split);
+    EXPECT_FALSE(status);
+}
+
+TEST(mdns_utils, mdns_split_txt_record_normal) {
+    std::string normal = "key=value";
+    auto [status, key, value] = ParseTxtKeyValue(normal);
+    EXPECT_TRUE(status);
+    EXPECT_TRUE(key == "key");
+    EXPECT_TRUE(value == "value");
+}
+
 }  // namespace mdns
diff --git a/client/mdnsresponder_client.cpp b/client/mdnsresponder_client.cpp
deleted file mode 100644
index dbf2b45c..00000000
--- a/client/mdnsresponder_client.cpp
+++ /dev/null
@@ -1,701 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-#define TRACE_TAG TRANSPORT
-
-#include "transport.h"
-
-#ifdef _WIN32
-#include <winsock2.h>
-#else
-#include <arpa/inet.h>
-#endif
-
-#include <memory>
-#include <thread>
-#include <vector>
-
-#include <android-base/stringprintf.h>
-#include <android-base/strings.h>
-#include <dns_sd.h>
-
-#include "adb_client.h"
-#include "adb_mdns.h"
-#include "adb_trace.h"
-#include "adb_utils.h"
-#include "adb_wifi.h"
-#include "client/mdns_utils.h"
-#include "fdevent/fdevent.h"
-#include "sysdeps.h"
-
-// TODO: Remove this file once openscreen has bonjour client APIs implemented.
-namespace {
-
-DNSServiceRef g_service_refs[kNumADBDNSServices];
-fdevent* g_service_ref_fdes[kNumADBDNSServices];
-
-// Use adb_DNSServiceRefSockFD() instead of calling DNSServiceRefSockFD()
-// directly so that the socket is put through the appropriate compatibility
-// layers to work with the rest of ADB's internal APIs.
-int adb_DNSServiceRefSockFD(DNSServiceRef ref) {
-    return adb_register_socket(DNSServiceRefSockFD(ref));
-}
-#define DNSServiceRefSockFD ___xxx_DNSServiceRefSockFD
-
-void DNSSD_API register_service_ip(DNSServiceRef sdref, DNSServiceFlags flags,
-                                   uint32_t interface_index, DNSServiceErrorType error_code,
-                                   const char* hostname, const sockaddr* address, uint32_t ttl,
-                                   void* context);
-
-void pump_service_ref(int /*fd*/, unsigned ev, void* data) {
-    DNSServiceRef* ref = reinterpret_cast<DNSServiceRef*>(data);
-
-    if (ev & FDE_READ) DNSServiceProcessResult(*ref);
-}
-
-class AsyncServiceRef {
-  public:
-    bool Initialized() const { return initialized_; }
-
-    void DestroyServiceRef() {
-        if (!initialized_) {
-            return;
-        }
-
-        // Order matters here! Must destroy the fdevent first since it has a
-        // reference to |sdref_|.
-        fdevent_destroy(fde_);
-        D("DNSServiceRefDeallocate(sdref=%p)", sdref_);
-        DNSServiceRefDeallocate(sdref_);
-        initialized_ = false;
-    }
-
-    virtual ~AsyncServiceRef() { DestroyServiceRef(); }
-
-  protected:
-    DNSServiceRef sdref_;
-
-    void Initialize() {
-        fde_ = fdevent_create(adb_DNSServiceRefSockFD(sdref_), pump_service_ref, &sdref_);
-        if (fde_ == nullptr) {
-            D("Unable to create fdevent");
-            return;
-        }
-        fdevent_set(fde_, FDE_READ);
-        initialized_ = true;
-    }
-
-  private:
-    bool initialized_ = false;
-    fdevent* fde_;
-};
-
-class ResolvedService : public AsyncServiceRef {
-  public:
-    virtual ~ResolvedService() = default;
-
-    ResolvedService(const std::string& service_name, const std::string& reg_type,
-                    uint32_t interface_index, const std::string& host_target, uint16_t port,
-                    int version)
-        : service_name_(service_name),
-          reg_type_(reg_type),
-          host_target_(host_target),
-          port_(port),
-          sa_family_(0),
-          service_version_(version) {
-        /* TODO: We should be able to get IPv6 support by adding
-         * kDNSServiceProtocol_IPv6 to the flags below. However, when we do
-         * this, we get served link-local addresses that are usually useless to
-         * connect to. What's more, we seem to /only/ get those and nothing else.
-         * If we want IPv6 in the future we'll have to figure out why.
-         */
-        DNSServiceErrorType ret = DNSServiceGetAddrInfo(
-                &sdref_, 0, interface_index, kDNSServiceProtocol_IPv4, host_target_.c_str(),
-                register_service_ip, reinterpret_cast<void*>(this));
-
-        if (ret != kDNSServiceErr_NoError) {
-            D("Got %d from DNSServiceGetAddrInfo.", ret);
-        } else {
-            D("DNSServiceGetAddrInfo(sdref=%p, host_target=%s)", sdref_, host_target_.c_str());
-            Initialize();
-        }
-
-        D("Client version: %d Service version: %d", ADB_SECURE_CLIENT_VERSION, service_version_);
-    }
-
-    bool ConnectSecureWifiDevice() {
-        if (!adb_wifi_is_known_host(service_name_)) {
-            LOG(INFO) << "service_name=" << service_name_ << " not in keystore";
-            return false;
-        }
-
-        std::string response;
-        connect_device(
-                android::base::StringPrintf("%s.%s", service_name_.c_str(), reg_type_.c_str()),
-                &response);
-        D("Secure connect to %s regtype %s (%s:%hu) : %s", service_name_.c_str(), reg_type_.c_str(),
-          ip_addr_.c_str(), port_, response.c_str());
-        return true;
-    }
-
-    bool RegisterIpAddress(const sockaddr* address) {
-        sa_family_ = address->sa_family;
-
-        const void* ip_addr_data;
-        if (sa_family_ == AF_INET) {
-            ip_addr_data = &reinterpret_cast<const sockaddr_in*>(address)->sin_addr;
-            addr_format_ = "%s:%hu";
-        } else if (sa_family_ == AF_INET6) {
-            ip_addr_data = &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
-            addr_format_ = "[%s]:%hu";
-        } else {  // Should be impossible
-            D("mDNS resolved non-IP address.");
-            return false;
-        }
-
-        // Winsock version requires the const cast mingw defines inet_ntop differently from msvc.
-        char ip_addr[INET6_ADDRSTRLEN] = {};
-        if (!inet_ntop(sa_family_, const_cast<void*>(ip_addr_data), ip_addr, sizeof(ip_addr))) {
-            D("Could not convert IP address to string.");
-            return false;
-        }
-        ip_addr_ = ip_addr;
-
-        return true;
-    }
-
-    static void AddToServiceRegistry(std::unique_ptr<ResolvedService> service) {
-        // Add to the service registry before trying to auto-connect, since socket_spec_connect will
-        // check these registries for the ip address when connecting via mdns instance name.
-        auto service_index = service->service_index();
-        if (!service_index) {
-            return;
-        }
-
-        // Remove any services with the same instance name, as it may be a stale registration.
-        RemoveDNSService(service->reg_type(), service->service_name());
-
-        ServiceRegistry* services = nullptr;
-        switch (*service_index) {
-            case kADBTransportServiceRefIndex:
-                services = sAdbTransportServices;
-                break;
-            case kADBSecurePairingServiceRefIndex:
-                services = sAdbSecurePairingServices;
-                break;
-            case kADBSecureConnectServiceRefIndex:
-                services = sAdbSecureConnectServices;
-                break;
-            default:
-                LOG(WARNING) << "No registry available for reg_type=[" << service->reg_type()
-                             << "]";
-                return;
-        }
-
-        services->push_back(std::move(service));
-        const auto& s = services->back();
-
-        auto reg_type = s->reg_type();
-        auto service_name = s->service_name();
-
-        auto ip_addr = s->ip_address();
-        auto port = s->port();
-        if (adb_DNSServiceShouldAutoConnect(reg_type, service_name)) {
-            std::string response;
-            D("Attempting to connect service_name=[%s], regtype=[%s] ip_addr=(%s:%hu)",
-              service_name.c_str(), reg_type.c_str(), ip_addr.c_str(), port);
-
-            if (*service_index == kADBSecureConnectServiceRefIndex) {
-                s->ConnectSecureWifiDevice();
-            } else {
-                connect_device(android::base::StringPrintf("%s.%s", service_name.c_str(),
-                                                           reg_type.c_str()),
-                               &response);
-                D("Connect to %s regtype %s (%s:%hu) : %s", service_name.c_str(), reg_type.c_str(),
-                  ip_addr.c_str(), port, response.c_str());
-            }
-        } else {
-            D("Not immediately connecting to service_name=[%s], regtype=[%s] ip_addr=(%s:%hu)",
-              service_name.c_str(), reg_type.c_str(), ip_addr.c_str(), port);
-        }
-    }
-
-    std::optional<int> service_index() const {
-        return adb_DNSServiceIndexByName(reg_type_.c_str());
-    }
-
-    const std::string& service_name() const { return service_name_; }
-
-    const std::string& reg_type() const { return reg_type_; }
-
-    const std::string& ip_address() const { return ip_addr_; }
-
-    uint16_t port() const { return port_; }
-
-    using ServiceRegistry = std::vector<std::unique_ptr<ResolvedService>>;
-
-    // unencrypted tcp connections
-    static ServiceRegistry* sAdbTransportServices;
-
-    static ServiceRegistry* sAdbSecurePairingServices;
-    static ServiceRegistry* sAdbSecureConnectServices;
-
-    static void InitAdbServiceRegistries();
-
-    static void ForEachService(const ServiceRegistry& services, const std::string& hostname,
-                               adb_secure_foreach_service_callback cb);
-
-    static bool ConnectByServiceName(const ServiceRegistry& services,
-                                     const std::string& service_name);
-
-    static void RemoveDNSService(const std::string& reg_type, const std::string& service_name);
-
-  private:
-    std::string addr_format_;
-    std::string service_name_;
-    std::string reg_type_;
-    std::string host_target_;
-    const uint16_t port_;
-    int sa_family_;
-    std::string ip_addr_;
-    int service_version_;
-};
-
-// static
-ResolvedService::ServiceRegistry* ResolvedService::sAdbTransportServices = NULL;
-
-// static
-ResolvedService::ServiceRegistry* ResolvedService::sAdbSecurePairingServices = NULL;
-
-// static
-ResolvedService::ServiceRegistry* ResolvedService::sAdbSecureConnectServices = NULL;
-
-// static
-void ResolvedService::InitAdbServiceRegistries() {
-    if (!sAdbTransportServices) {
-        sAdbTransportServices = new ServiceRegistry;
-    }
-    if (!sAdbSecurePairingServices) {
-        sAdbSecurePairingServices = new ServiceRegistry;
-    }
-    if (!sAdbSecureConnectServices) {
-        sAdbSecureConnectServices = new ServiceRegistry;
-    }
-}
-
-// static
-void ResolvedService::ForEachService(const ServiceRegistry& services,
-                                     const std::string& wanted_service_name,
-                                     adb_secure_foreach_service_callback cb) {
-    InitAdbServiceRegistries();
-
-    for (const auto& service : services) {
-        const auto ivp4 = openscreen::IPAddress::Parse(service->ip_address()).value();
-        // Bonjour doesn't resolve ipv6 currently so we just use "any" address.
-        const auto ivp6 = openscreen::IPAddress::Parse("::").value();
-        mdns::ServiceInfo si{service->service_name(), service->reg_type(), ivp4, ivp6,
-                             service->port()};
-        if (wanted_service_name.empty()) {
-            cb(si);
-        } else if (service->service_name() == wanted_service_name) {
-            cb(si);
-        }
-    }
-}
-
-// static
-bool ResolvedService::ConnectByServiceName(const ServiceRegistry& services,
-                                           const std::string& service_name) {
-    InitAdbServiceRegistries();
-    for (const auto& service : services) {
-        auto wanted_name = service->service_name();
-        if (wanted_name == service_name) {
-            D("Got service_name match [%s]", wanted_name.c_str());
-            return service->ConnectSecureWifiDevice();
-        }
-    }
-    D("No registered service_names matched [%s]", service_name.c_str());
-    return false;
-}
-
-// static
-void ResolvedService::RemoveDNSService(const std::string& reg_type,
-                                       const std::string& service_name) {
-    D("%s: reg_type=[%s] service_name=[%s]", __func__, reg_type.c_str(), service_name.c_str());
-    auto index = adb_DNSServiceIndexByName(reg_type);
-    if (!index) {
-        return;
-    }
-    ServiceRegistry* services;
-    switch (*index) {
-        case kADBTransportServiceRefIndex:
-            services = sAdbTransportServices;
-            break;
-        case kADBSecurePairingServiceRefIndex:
-            services = sAdbSecurePairingServices;
-            break;
-        case kADBSecureConnectServiceRefIndex:
-            services = sAdbSecureConnectServices;
-            break;
-        default:
-            return;
-    }
-
-    if (services->empty()) {
-        return;
-    }
-
-    services->erase(std::remove_if(services->begin(), services->end(),
-                                   [&service_name](std::unique_ptr<ResolvedService>& service) {
-                                       return (service_name == service->service_name());
-                                   }),
-                    services->end());
-}
-
-void DNSSD_API register_service_ip(DNSServiceRef sdref, DNSServiceFlags flags,
-                                   uint32_t /*interface_index*/, DNSServiceErrorType error_code,
-                                   const char* hostname, const sockaddr* address, uint32_t ttl,
-                                   void* context) {
-    D("%s: sdref=%p flags=0x%08x error_code=%u ttl=%u", __func__, sdref, flags, error_code, ttl);
-    std::unique_ptr<ResolvedService> data(static_cast<ResolvedService*>(context));
-    // Only resolve the address once. If the address or port changes, we'll just get another
-    // registration.
-    data->DestroyServiceRef();
-
-    if (error_code != kDNSServiceErr_NoError) {
-        D("Got error while looking up ip_addr [%u]", error_code);
-        return;
-    }
-
-    if (flags & kDNSServiceFlagsAdd) {
-        if (data->RegisterIpAddress(address)) {
-            D("Resolved IP address for [%s]. Adding to service registry.", hostname);
-            ResolvedService::AddToServiceRegistry(std::move(data));
-        }
-    }
-}
-
-void DNSSD_API register_resolved_mdns_service(DNSServiceRef sdref, DNSServiceFlags flags,
-                                              uint32_t interface_index,
-                                              DNSServiceErrorType error_code, const char* fullname,
-                                              const char* host_target, uint16_t port,
-                                              uint16_t txt_len, const unsigned char* txt_record,
-                                              void* context);
-
-class DiscoveredService : public AsyncServiceRef {
-  public:
-    DiscoveredService(uint32_t interface_index, const char* service_name, const char* regtype,
-                      const char* domain)
-        : service_name_(service_name), reg_type_(regtype) {
-        DNSServiceErrorType ret =
-                DNSServiceResolve(&sdref_, 0, interface_index, service_name, regtype, domain,
-                                  register_resolved_mdns_service, reinterpret_cast<void*>(this));
-
-        D("DNSServiceResolve for "
-          "interface_index %u "
-          "service_name %s "
-          "regtype %s "
-          "domain %s "
-          ": %d",
-          interface_index, service_name, regtype, domain, ret);
-
-        if (ret == kDNSServiceErr_NoError) {
-            Initialize();
-        }
-    }
-
-    const std::string& service_name() { return service_name_; }
-
-    const std::string& reg_type() { return reg_type_; }
-
-  private:
-    std::string service_name_;
-    std::string reg_type_;
-};
-
-// Returns the version the device wanted to advertise,
-// or -1 if parsing fails.
-int ParseVersionFromTxtRecord(uint16_t txt_len, const unsigned char* txt_record) {
-    if (!txt_len) return -1;
-    if (!txt_record) return -1;
-
-    // https://tools.ietf.org/html/rfc6763
-    // """
-    // 6.1.  General Format Rules for DNS TXT Records
-    //
-    // A DNS TXT record can be up to 65535 (0xFFFF) bytes long.  The total
-    // length is indicated by the length given in the resource record header
-    // in the DNS message.  There is no way to tell directly from the data
-    // alone how long it is (e.g., there is no length count at the start, or
-    // terminating NULL byte at the end).
-    //
-    // The format of the data within a DNS TXT record is zero or more strings,
-    // packed together in memory without any intervening gaps or padding bytes
-    // for word alignment. The format of each constituent string within the DNS
-    // TXT record is a single length byte, followed by 0-255 bytes of text data.
-    // """
-
-    // We only parse the first string in the record.
-    // Let's not trust the length byte (txt_record[0]).
-    // Worst case, it wastes 65,535 bytes.
-    std::vector<char> record_str(txt_len + 1, '\0');
-    char* str = record_str.data();
-
-    memcpy(str, txt_record + 1 /* skip the length byte */, txt_len - 1);
-
-    // Check if it's the version key
-    static const char* version_key = "v=";
-    size_t version_key_len = strlen(version_key);
-
-    if (strncmp(version_key, str, version_key_len)) return -1;
-
-    auto value_start = str + version_key_len;
-
-    long parsed_number = strtol(value_start, 0, 10);
-
-    // No valid conversion. Also, 0
-    // is not a valid version.
-    if (!parsed_number) return -1;
-
-    // Outside bounds of int.
-    if (parsed_number < INT_MIN || parsed_number > INT_MAX) return -1;
-
-    // Possibly valid version
-    return static_cast<int>(parsed_number);
-}
-
-void DNSSD_API register_resolved_mdns_service(DNSServiceRef sdref, DNSServiceFlags flags,
-                                              uint32_t interface_index,
-                                              DNSServiceErrorType error_code, const char* fullname,
-                                              const char* host_target, uint16_t port,
-                                              uint16_t txt_len, const unsigned char* txt_record,
-                                              void* context) {
-    D("Resolved a service.");
-    std::unique_ptr<DiscoveredService> discovered(reinterpret_cast<DiscoveredService*>(context));
-
-    if (error_code != kDNSServiceErr_NoError) {
-        D("Got error %d resolving service.", error_code);
-        return;
-    }
-
-    // TODO: Reject certain combinations of invalid or mismatched client and
-    // service versions here before creating anything.
-    // At the moment, there is nothing to reject, so accept everything
-    // as an optimistic default.
-    auto service_version = ParseVersionFromTxtRecord(txt_len, txt_record);
-
-    auto resolved = new ResolvedService(discovered->service_name(), discovered->reg_type(),
-                                        interface_index, host_target, ntohs(port), service_version);
-
-    if (!resolved->Initialized()) {
-        D("Unable to init resolved service");
-        delete resolved;
-    }
-
-    if (flags) { /* Only ever equals MoreComing or 0 */
-        D("releasing discovered service");
-        discovered.release();
-    }
-}
-
-void DNSSD_API on_service_browsed(DNSServiceRef sdref, DNSServiceFlags flags,
-                                  uint32_t interface_index, DNSServiceErrorType error_code,
-                                  const char* service_name, const char* regtype, const char* domain,
-                                  void* /*context*/) {
-    if (error_code != kDNSServiceErr_NoError) {
-        D("Got error %d during mDNS browse.", error_code);
-        DNSServiceRefDeallocate(sdref);
-        auto service_index = adb_DNSServiceIndexByName(regtype);
-        if (service_index) {
-            fdevent_destroy(g_service_ref_fdes[*service_index]);
-        }
-        return;
-    }
-
-    if (flags & kDNSServiceFlagsAdd) {
-        D("%s: Discover found new service_name=[%s] regtype=[%s] domain=[%s]", __func__,
-          service_name, regtype, domain);
-        auto discovered = new DiscoveredService(interface_index, service_name, regtype, domain);
-        if (!discovered->Initialized()) {
-            delete discovered;
-        }
-    } else {
-        D("%s: Discover lost service_name=[%s] regtype=[%s] domain=[%s]", __func__, service_name,
-          regtype, domain);
-        ResolvedService::RemoveDNSService(regtype, service_name);
-    }
-}
-
-void init_mdns_transport_discovery_thread() {
-    int error_codes[kNumADBDNSServices];
-    for (int i = 0; i < kNumADBDNSServices; ++i) {
-        error_codes[i] = DNSServiceBrowse(&g_service_refs[i], 0, 0, kADBDNSServices[i], nullptr,
-                                          on_service_browsed, nullptr);
-
-        if (error_codes[i] != kDNSServiceErr_NoError) {
-            D("Got %d browsing for mDNS service %s.", error_codes[i], kADBDNSServices[i]);
-        } else {
-            fdevent_run_on_looper([i]() {
-                g_service_ref_fdes[i] = fdevent_create(adb_DNSServiceRefSockFD(g_service_refs[i]),
-                                                       pump_service_ref, &g_service_refs[i]);
-                fdevent_set(g_service_ref_fdes[i], FDE_READ);
-            });
-        }
-    }
-}
-
-namespace MdnsResponder {
-
-bool adb_secure_connect_by_service_name(const std::string& instance_name) {
-    return ResolvedService::ConnectByServiceName(*ResolvedService::sAdbSecureConnectServices,
-                                                 instance_name);
-}
-
-std::string mdns_check() {
-    uint32_t daemon_version;
-    uint32_t sz = sizeof(daemon_version);
-
-    auto dnserr = DNSServiceGetProperty(kDNSServiceProperty_DaemonVersion, &daemon_version, &sz);
-    if (dnserr != kDNSServiceErr_NoError) {
-        return "ERROR: mdns daemon unavailable";
-    }
-
-    return android::base::StringPrintf("mdns daemon version [%u]", daemon_version);
-}
-
-std::string mdns_list_discovered_services() {
-    std::string result;
-    auto cb = [&](const mdns::ServiceInfo& si) {
-        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", si.instance_name.c_str(),
-                                              si.service_name.c_str(),
-                                              si.v4_address_string().c_str(), si.port);
-    };
-
-    ResolvedService::ForEachService(*ResolvedService::sAdbTransportServices, "", cb);
-    ResolvedService::ForEachService(*ResolvedService::sAdbSecureConnectServices, "", cb);
-    ResolvedService::ForEachService(*ResolvedService::sAdbSecurePairingServices, "", cb);
-    return result;
-}
-
-std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
-    CHECK(!name.empty());
-
-    // only adb server creates these registries
-    if (!ResolvedService::sAdbTransportServices && !ResolvedService::sAdbSecureConnectServices) {
-        return std::nullopt;
-    }
-    CHECK(ResolvedService::sAdbTransportServices);
-    CHECK(ResolvedService::sAdbSecureConnectServices);
-
-    auto mdns_instance = mdns::mdns_parse_instance_name(name);
-    if (!mdns_instance.has_value()) {
-        D("Failed to parse mDNS name [%s]", name.c_str());
-        return std::nullopt;
-    }
-
-    std::optional<MdnsInfo> info;
-    auto cb = [&](const mdns::ServiceInfo& si) {
-        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
-    };
-
-    std::string reg_type;
-    if (!mdns_instance->service_name.empty()) {
-        reg_type = android::base::StringPrintf("%s.%s", mdns_instance->service_name.c_str(),
-                                               mdns_instance->transport_type.c_str());
-        auto index = adb_DNSServiceIndexByName(reg_type);
-        if (!index) {
-            return std::nullopt;
-        }
-        switch (*index) {
-            case kADBTransportServiceRefIndex:
-                ResolvedService::ForEachService(*ResolvedService::sAdbTransportServices,
-                                                mdns_instance->instance_name, cb);
-                break;
-            case kADBSecureConnectServiceRefIndex:
-                ResolvedService::ForEachService(*ResolvedService::sAdbSecureConnectServices,
-                                                mdns_instance->instance_name, cb);
-                break;
-            default:
-                D("Unknown reg_type [%s]", reg_type.c_str());
-                return std::nullopt;
-        }
-        return info;
-    }
-
-    for (const auto& service :
-         {ResolvedService::sAdbTransportServices, ResolvedService::sAdbSecureConnectServices}) {
-        ResolvedService::ForEachService(*service, name, cb);
-        if (info.has_value()) {
-            return info;
-        }
-    }
-
-    return std::nullopt;
-}
-
-std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name) {
-    CHECK(!name.empty());
-
-    auto mdns_instance = mdns::mdns_parse_instance_name(name);
-    if (!mdns_instance.has_value()) {
-        D("Failed to parse mDNS pairing name [%s]", name.c_str());
-        return std::nullopt;
-    }
-
-    std::optional<MdnsInfo> info;
-    auto cb = [&](const mdns::ServiceInfo& si) {
-        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
-    };
-
-    // Verify it's a pairing service if user explicitly inputs it.
-    if (!mdns_instance->service_name.empty()) {
-        auto reg_type = android::base::StringPrintf("%s.%s", mdns_instance->service_name.c_str(),
-                                                    mdns_instance->transport_type.c_str());
-        auto index = adb_DNSServiceIndexByName(reg_type);
-        if (!index) {
-            return std::nullopt;
-        }
-        switch (*index) {
-            case kADBSecurePairingServiceRefIndex:
-                break;
-            default:
-                D("Not an adb pairing reg_type [%s]", reg_type.c_str());
-                return std::nullopt;
-        }
-    }
-
-    ResolvedService::ForEachService(*ResolvedService::sAdbSecurePairingServices, name, cb);
-    return info;
-}
-
-void mdns_cleanup() {}
-
-}  // namespace MdnsResponder
-}  // namespace
-
-AdbMdnsResponderFuncs StartMdnsResponderDiscovery() {
-    ResolvedService::InitAdbServiceRegistries();
-    std::thread(init_mdns_transport_discovery_thread).detach();
-    AdbMdnsResponderFuncs f = {
-            .mdns_check = MdnsResponder::mdns_check,
-            .mdns_list_discovered_services = MdnsResponder::mdns_list_discovered_services,
-            .mdns_get_connect_service_info = MdnsResponder::mdns_get_connect_service_info,
-            .mdns_get_pairing_service_info = MdnsResponder::mdns_get_pairing_service_info,
-            .mdns_cleanup = MdnsResponder::mdns_cleanup,
-            .adb_secure_connect_by_service_name = MdnsResponder::adb_secure_connect_by_service_name,
-    };
-    return f;
-}
diff --git a/client/openscreen/mdns_service_info.cpp b/client/openscreen/mdns_service_info.cpp
index fb338882..4b318a8c 100644
--- a/client/openscreen/mdns_service_info.cpp
+++ b/client/openscreen/mdns_service_info.cpp
@@ -23,42 +23,76 @@ using namespace openscreen;
 namespace mdns {
 
 std::string ServiceInfo::v4_address_string() const {
+    if (v4_address.has_value()) {
+        std::stringstream ss;
+        ss << v4_address.value();
+        return ss.str();
+    }
     std::stringstream ss;
-    ss << v4_address;
+    ss << IPAddress::kAnyV4();
     return ss.str();
 }
 
-std::string ServiceInfo::v6_address_string() const {
-    std::stringstream ss;
-    ss << v6_address;
-    return ss.str();
+// Parse a key/value from a TXT record. Format expected is "key=value"
+std::tuple<bool, std::string, std::string> ParseTxtKeyValue(const std::string& kv) {
+    auto split_loc = std::ranges::find(kv, static_cast<uint8_t>('='));
+    if (split_loc == kv.end()) {
+        return {false, "", ""};
+    }
+    std::string key;
+    std::string value;
+
+    key.assign(kv.begin(), split_loc);
+    if (split_loc + 1 != kv.end()) {
+        value.assign(split_loc + 1, kv.end());
+    }
+
+    if (key.empty()) {
+        return {false, key, value};
+    }
+    return {true, key, value};
+}
+
+static std::unordered_map<std::string, std::string> ParseTxt(
+        std::vector<std::vector<uint8_t>>& txt) {
+    std::unordered_map<std::string, std::string> kv;
+    for (auto& in_kv : txt) {
+        std::string skv = std::string(in_kv.begin(), in_kv.end());
+        auto [valid, key, value] = ParseTxtKeyValue(skv);
+        if (!valid) {
+            VLOG(MDNS) << "Bad TXT value '" << skv << "'";
+            continue;
+        }
+        kv[key] = value;
+    }
+    return kv;
 }
 
 ErrorOr<ServiceInfo> DnsSdInstanceEndpointToServiceInfo(
         const discovery::DnsSdInstanceEndpoint& endpoint) {
     ServiceInfo service_info;
-    // Check if |endpoint| is a known adb service name
-    for (int i = 0; i < kNumADBDNSServices; ++i) {
-        if (endpoint.service_id() == kADBDNSServices[i]) {
-            service_info.service_name = endpoint.service_id();
-            service_info.instance_name = endpoint.instance_id();
-            break;
-        }
-        if (i == kNumADBDNSServices - 1) {
-            LOG(ERROR) << "Got unknown service name [" << endpoint.service_id() << "]";
-            return Error::Code::kParameterInvalid;
-        }
-    }
 
+    service_info.instance = endpoint.instance_id();
+    service_info.service = endpoint.service_id();
     service_info.port = endpoint.port();
     for (const IPAddress& address : endpoint.addresses()) {
-        if (!service_info.v4_address && address.IsV4()) {
-            service_info.v4_address = address;
-        } else if (!service_info.v6_address && address.IsV6()) {
-            service_info.v6_address = address;
+        switch (address.version()) {
+            case IPAddress::Version::kV4: {
+                if (!service_info.v4_address.has_value()) {
+                    service_info.v4_address = address;
+                }
+                break;
+            }
+            case IPAddress::Version::kV6: {
+                service_info.v6_addresses.insert(address);
+                break;
+            }
         }
     }
-    CHECK(service_info.v4_address || service_info.v6_address);
+
+    auto txt = endpoint.txt().GetData();
+    service_info.attributes = ParseTxt(txt);
+
     return service_info;
 }
 
diff --git a/client/openscreen/mdns_service_info.h b/client/openscreen/mdns_service_info.h
index e6407184..2267ef19 100644
--- a/client/openscreen/mdns_service_info.h
+++ b/client/openscreen/mdns_service_info.h
@@ -17,26 +17,64 @@
 #pragma once
 
 #include <string>
+#include <tuple>
 
 #include <discovery/dnssd/public/dns_sd_instance_endpoint.h>
 #include <platform/base/ip_address.h>
 
+#include <unordered_set>
+
 #include "client/mdns_utils.h"
 
 namespace mdns {
 
+struct IPAddressHasher {
+    size_t operator()(const openscreen::IPAddress& ip_address) const {
+        return std::hash<std::string_view>{}(
+                {reinterpret_cast<const char*>(ip_address.bytes()), 16});
+    }
+};
+
+struct IPAddressEqual {
+    bool operator()(const openscreen::IPAddress& lhs, const openscreen::IPAddress& rhs) const {
+        return lhs == rhs;
+    }
+};
+
 struct ServiceInfo {
-    std::string instance_name;
-    std::string service_name;
-    openscreen::IPAddress v4_address;
-    openscreen::IPAddress v6_address;
+    std::string instance;
+    std::string service;
+    std::optional<openscreen::IPAddress> v4_address;
+    std::unordered_set<openscreen::IPAddress, IPAddressHasher, IPAddressEqual> v6_addresses;
     uint16_t port;
 
     std::string v4_address_string() const;
-    std::string v6_address_string() const;
+
+    // Store keys/values from TXT resource record
+    std::unordered_map<std::string, std::string> attributes;
 };  // ServiceInfo
 
+inline std::string to_string(const openscreen::IPAddress& ip_address) {
+    std::stringstream ss;
+    ss << ip_address;
+    return ss.str();
+}
+
+inline std::ostream& operator<<(std::ostream& os, const ServiceInfo& service_info) {
+    os << "Instance: " << service_info.instance << ", Service: " << service_info.service
+       << ", Port: " << service_info.port;
+    if (service_info.v4_address) {
+        os << ", IPv4: " << service_info.v4_address.value();
+    }
+    for (auto& address : service_info.v6_addresses) {
+        os << ", IPv6: " << address;
+    }
+    return os;
+}
+
 openscreen::ErrorOr<ServiceInfo> DnsSdInstanceEndpointToServiceInfo(
         const openscreen::discovery::DnsSdInstanceEndpoint& endpoint);
 
-}  // namespace mdns
+std::tuple<bool, std::string, std::string> ParseTxtKeyValue(const std::string& kv);
+
+}  // namespace mdns
\ No newline at end of file
diff --git a/client/openscreen/platform/udp_socket.cpp b/client/openscreen/platform/udp_socket.cpp
index a8747492..4ea9fab7 100644
--- a/client/openscreen/platform/udp_socket.cpp
+++ b/client/openscreen/platform/udp_socket.cpp
@@ -167,7 +167,7 @@ class AdbUdpSocket : public UdpSocket {
             return;
         }
         fdevent_set(fde_, FDE_READ);
-        LOG(INFO) << __func__ << " fd=" << fd_.get();
+        VLOG(MDNS) << " fd=" << fd_.get();
     }
 
     ~AdbUdpSocket() override {
@@ -271,7 +271,7 @@ class AdbUdpSocket : public UdpSocket {
         // TODO: remove once osp-discovery calls Bind() after SetMulticastOutboundInterface().
         *mdns_ifindex_ = ifindex;
 
-        LOG(INFO) << "SetMulticastOutboundInterface for index=" << ifindex;
+        VLOG(MDNS) << "SetMulticastOutboundInterface for index=" << ifindex;
         switch (local_endpoint_.address.version()) {
             case UdpSocket::Version::kV4: {
                 struct ip_mreq multicast_properties = {};
@@ -285,7 +285,7 @@ class AdbUdpSocket : public UdpSocket {
                     const auto default_ip =
                             IPAddress(IPAddress::Version::kV4,
                                       reinterpret_cast<const uint8_t*>(&default_addr.s_addr));
-                    LOG(INFO) << "BEFORE IP_MULTICAST_IF: default multicast addr=" << default_ip;
+                    VLOG(MDNS) << "BEFORE IP_MULTICAST_IF: default multicast addr=" << default_ip;
                 }
 #endif  // DEBUG_UDP
                 if (adb_setsockopt(fd_, IPPROTO_IP, IP_MULTICAST_IF, &multicast_properties,
@@ -530,7 +530,7 @@ class AdbUdpSocket : public UdpSocket {
                 if (adb_getsockname(fd_, reinterpret_cast<sockaddr*>(&sa), &sa_len) != -1) {
                     local_endpoint_.address = GetIPAddressFromSockAddr(sa);
                     local_endpoint_.port = GetPortFromFromSockAddr(sa);
-                    LOG(INFO) << "bind endpoint=" << local_endpoint_;
+                    VLOG(MDNS) << "bind endpoint=" << local_endpoint_;
                 }
                 return;
             }
@@ -555,8 +555,8 @@ class AdbUdpSocket : public UdpSocket {
                 if (adb_getsockname(fd_, reinterpret_cast<sockaddr*>(&sa), &sa_len) != -1) {
                     local_endpoint_.address = GetIPAddressFromSockAddr(sa);
                     local_endpoint_.port = GetPortFromFromSockAddr(sa);
-                    LOG(INFO) << "bind endpoint=" << local_endpoint_
-                              << " scope_id=" << sa.sin6_scope_id;
+                    VLOG(MDNS) << "bind endpoint=" << local_endpoint_
+                               << " scope_id=" << sa.sin6_scope_id;
                 }
                 return;
             }
diff --git a/client/transport_emulator.cpp b/client/transport_emulator.cpp
index e9ebaaa6..3b747565 100644
--- a/client/transport_emulator.cpp
+++ b/client/transport_emulator.cpp
@@ -42,6 +42,7 @@
 #include "adb_io.h"
 #include "adb_unique_fd.h"
 #include "adb_utils.h"
+#include "fdevent/fdevent.h"
 #include "socket_spec.h"
 #include "sysdeps/chrono.h"
 
@@ -73,11 +74,13 @@ static std::unordered_map<int, atransport*> emulator_transports
         [[clang::no_destroy]] GUARDED_BY(emulator_transports_lock);
 
 bool connect_emulator(int port) {
+    fdevent_check_not_looper();
     std::string dummy;
     return connect_emulator_arbitrary_ports(port - 1, port, &dummy) == 0;
 }
 
 void connect_device(const std::string& address, std::string* response) {
+    fdevent_check_not_looper();
     if (address.empty()) {
         *response = "empty address";
         return;
diff --git a/client/transport_mdns.cpp b/client/transport_mdns.cpp
index 81fba1a8..e55c98e9 100644
--- a/client/transport_mdns.cpp
+++ b/client/transport_mdns.cpp
@@ -46,9 +46,11 @@
 #include "adb_trace.h"
 #include "adb_utils.h"
 #include "adb_wifi.h"
+#include "client/discovered_services.h"
 #include "client/mdns_utils.h"
 #include "client/openscreen/platform/task_runner.h"
 #include "fdevent/fdevent.h"
+#include "mdns_tracker.h"
 #include "sysdeps.h"
 
 namespace {
@@ -60,16 +62,10 @@ using ServicesUpdatedState = ServiceWatcher::ServicesUpdatedState;
 
 struct DiscoveryState;
 DiscoveryState* g_state = nullptr;
-// TODO: remove once openscreen has bonjour client APIs.
-bool g_using_bonjour = false;
-AdbMdnsResponderFuncs g_adb_mdnsresponder_funcs;
 
 class DiscoveryReportingClient : public discovery::ReportingClient {
   public:
     void OnFatalError(Error error) override {
-        // The multicast port 5353 may fail to bind because of another process already binding
-        // to it (bonjour). So let's fallback to bonjour client APIs.
-        // TODO: Remove this once openscreen implements the bonjour client APIs.
         LOG(ERROR) << "Encountered fatal discovery error: " << error;
         got_fatal_ = true;
     }
@@ -93,45 +89,68 @@ struct DiscoveryState {
     InterfaceInfo interface_info;
 };
 
+static void RequestConnectToDevice(const ServiceInfo& info) {
+    // Connecting to a device does not happen often. We spawn a new thread each time.
+    // Let's re-evaluate if we need a thread-pool or a background thread if this ever becomes
+    // a perf bottleneck.
+    std::thread([=] {
+        VLOG(MDNS) << "Attempting to secure connect to instance '" << info << "'";
+        std::string response;
+        connect_device(std::format("{}.{}", info.instance, info.service), &response);
+        VLOG(MDNS) << std::format("secure connect to {} regtype {} ({}:{}) : {}", info.instance,
+                                  info.service, info.v4_address_string(), info.port, response);
+    }).detach();
+}
+
+void AttemptAutoConnect(const std::reference_wrapper<const ServiceInfo> info) {
+    if (!adb_DNSServiceShouldAutoConnect(info.get().service, info.get().instance)) {
+        return;
+    }
+    if (!info.get().v4_address.has_value()) {
+        return;
+    }
+
+    const auto index = adb_DNSServiceIndexByName(info.get().service);
+    if (!index) {
+        return;
+    }
+
+    // Don't try to auto-connect if not in the keystore.
+    if (*index == kADBSecureConnectServiceRefIndex &&
+        !adb_wifi_is_known_host(info.get().instance)) {
+        VLOG(MDNS) << "instance_name=" << info.get().instance << " not in keystore";
+        return;
+    }
+
+    RequestConnectToDevice(info.get());
+}
+
 // Callback provided to service receiver for updates.
-void OnServiceReceiverResult(std::vector<std::reference_wrapper<const ServiceInfo>> infos,
+void OnServiceReceiverResult(std::vector<std::reference_wrapper<const ServiceInfo>>,
                              std::reference_wrapper<const ServiceInfo> info,
                              ServicesUpdatedState state) {
-    VLOG(MDNS) << "Endpoint state=" << static_cast<int>(state)
-               << " instance_name=" << info.get().instance_name
-               << " service_name=" << info.get().service_name << " addr=" << info.get().v4_address
-               << " addrv6=" << info.get().v6_address << " total_serv=" << infos.size();
-
+    bool updated = true;
     switch (state) {
-        case ServicesUpdatedState::EndpointCreated:
-        case ServicesUpdatedState::EndpointUpdated:
-            if (adb_DNSServiceShouldAutoConnect(info.get().service_name,
-                                                info.get().instance_name) &&
-                info.get().v4_address) {
-                auto index = adb_DNSServiceIndexByName(info.get().service_name);
-                if (!index) {
-                    return;
-                }
-
-                // Don't try to auto-connect if not in the keystore.
-                if (*index == kADBSecureConnectServiceRefIndex &&
-                    !adb_wifi_is_known_host(info.get().instance_name)) {
-                    VLOG(MDNS) << "instance_name=" << info.get().instance_name
-                               << " not in keystore";
-                    return;
-                }
-                std::string response;
-                VLOG(MDNS) << "Attempting to auto-connect to instance=" << info.get().instance_name
-                           << " service=" << info.get().service_name << " addr4=%s"
-                           << info.get().v4_address << ":" << info.get().port;
-                connect_device(
-                        android::base::StringPrintf("%s.%s", info.get().instance_name.c_str(),
-                                                    info.get().service_name.c_str()),
-                        &response);
+        case ServicesUpdatedState::EndpointCreated: {
+            discovered_services.ServiceCreated(info);
+            AttemptAutoConnect(info);
+            break;
+        }
+        case ServicesUpdatedState::EndpointUpdated: {
+            updated = discovered_services.ServiceUpdated(info);
+            if (updated) {
+                AttemptAutoConnect(info);
             }
             break;
-        default:
+        }
+        case ServicesUpdatedState::EndpointDeleted: {
+            discovered_services.ServiceDeleted(info);
             break;
+        }
+    }
+
+    if (updated) {
+        update_mdns_trackers();
     }
 }
 
@@ -145,7 +164,7 @@ std::optional<discovery::Config> GetConfigForAllInterfaces() {
     // to answer over no domain.
     config.enable_publication = false;
 
-    for (const auto interface : interface_infos) {
+    for (const auto& interface : interface_infos) {
         if (interface.GetIpAddressV4() || interface.GetIpAddressV6()) {
             config.network_info.push_back({interface});
             VLOG(MDNS) << "Listening on interface [" << interface << "]";
@@ -192,45 +211,19 @@ void StartDiscovery() {
                         w->StopDiscovery();
                     }
                 }
-                g_using_bonjour = true;
                 break;
             }
         }
-
-        if (g_using_bonjour) {
-            VLOG(MDNS) << "Fallback to MdnsResponder client for discovery";
-            g_adb_mdnsresponder_funcs = StartMdnsResponderDiscovery();
-        }
     });
 }
 
-void ForEachService(const std::unique_ptr<ServiceWatcher>& receiver,
-                    std::string_view wanted_instance_name, adb_secure_foreach_service_callback cb) {
-    if (!receiver->is_running()) {
-        return;
-    }
-    auto services = receiver->GetServices();
-    for (const auto& s : services) {
-        if (wanted_instance_name.empty() || s.get().instance_name == wanted_instance_name) {
-            std::stringstream ss;
-            ss << s.get().v4_address;
-            cb(s.get());
-        }
-    }
-}
-
-bool ConnectAdbSecureDevice(const MdnsInfo& info) {
-    if (!adb_wifi_is_known_host(info.service_name)) {
-        VLOG(MDNS) << "serviceName=" << info.service_name << " not in keystore";
+bool ConnectAdbSecureDevice(const ServiceInfo& info) {
+    if (!adb_wifi_is_known_host(info.instance)) {
+        VLOG(MDNS) << "serviceName=" << info.instance << " not in keystore";
         return false;
     }
 
-    std::string response;
-    connect_device(android::base::StringPrintf("%s.%s", info.service_name.c_str(),
-                                               info.service_type.c_str()),
-                   &response);
-    D("Secure connect to %s regtype %s (%s:%hu) : %s", info.service_name.c_str(),
-      info.service_type.c_str(), info.addr.c_str(), info.port, response.c_str());
+    RequestConnectToDevice(info);
     return true;
 }
 
@@ -238,21 +231,10 @@ bool ConnectAdbSecureDevice(const MdnsInfo& info) {
 
 /////////////////////////////////////////////////////////////////////////////////
 
-bool using_bonjour(void) {
-    return g_using_bonjour;
-}
-
-void mdns_cleanup() {
-    if (g_using_bonjour) {
-        return g_adb_mdnsresponder_funcs.mdns_cleanup();
-    }
-}
-
 void init_mdns_transport_discovery() {
     const char* mdns_osp = getenv("ADB_MDNS_OPENSCREEN");
     if (mdns_osp && strcmp(mdns_osp, "0") == 0) {
-        g_using_bonjour = true;
-        g_adb_mdnsresponder_funcs = StartMdnsResponderDiscovery();
+        LOG(WARNING) << "Environment variable ADB_MDNS_OPENSCREEN disregarded";
     } else {
         VLOG(MDNS) << "Openscreen mdns discovery enabled";
         StartDiscovery();
@@ -260,20 +242,12 @@ void init_mdns_transport_discovery() {
 }
 
 bool adb_secure_connect_by_service_name(const std::string& instance_name) {
-    if (g_using_bonjour) {
-        return g_adb_mdnsresponder_funcs.adb_secure_connect_by_service_name(instance_name);
-    }
-
     if (!g_state || g_state->watchers.empty()) {
         VLOG(MDNS) << "Mdns not enabled";
         return false;
     }
 
-    std::optional<MdnsInfo> info;
-    auto cb = [&](const mdns::ServiceInfo& si) {
-        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
-    };
-    ForEachService(g_state->watchers[kADBSecureConnectServiceRefIndex], instance_name, cb);
+    auto info = discovered_services.FindInstance(ADB_SERVICE_TLS, instance_name);
     if (info.has_value()) {
         return ConnectAdbSecureDevice(*info);
     }
@@ -281,134 +255,49 @@ bool adb_secure_connect_by_service_name(const std::string& instance_name) {
 }
 
 std::string mdns_check() {
-    if (!g_state && !g_using_bonjour) {
+    if (!g_state) {
         return "ERROR: mdns discovery disabled";
     }
 
-    if (g_using_bonjour) {
-        return g_adb_mdnsresponder_funcs.mdns_check();
-    }
-
     return "mdns daemon version [Openscreen discovery 0.0.0]";
 }
 
 std::string mdns_list_discovered_services() {
-    if (g_using_bonjour) {
-        return g_adb_mdnsresponder_funcs.mdns_list_discovered_services();
-    }
-
     if (!g_state || g_state->watchers.empty()) {
         return "";
     }
 
     std::string result;
     auto cb = [&](const mdns::ServiceInfo& si) {
-        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", si.instance_name.data(),
-                                              si.service_name.data(), si.v4_address_string().data(),
-                                              si.port);
+        result += std::format("{}\t{}\t{}:{}\n", si.instance, si.service, si.v4_address_string(),
+                              si.port);
     };
-
-    for (const auto& receiver : g_state->watchers) {
-        ForEachService(receiver, "", cb);
-    }
+    discovered_services.ForAllServices(cb);
     return result;
 }
 
-std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
+std::optional<ServiceInfo> mdns_get_connect_service_info(const std::string& name) {
     CHECK(!name.empty());
 
-    if (g_using_bonjour) {
-        return g_adb_mdnsresponder_funcs.mdns_get_connect_service_info(name);
-    }
-
-    if (!g_state || g_state->watchers.empty()) {
-        return std::nullopt;
-    }
-
     auto mdns_instance = mdns::mdns_parse_instance_name(name);
     if (!mdns_instance.has_value()) {
         D("Failed to parse mDNS name [%s]", name.data());
         return std::nullopt;
     }
 
-    std::optional<MdnsInfo> info;
-    auto cb = [&](const ServiceInfo& si) {
-        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
-    };
-
-    std::string reg_type;
-    // Service name was provided.
-    if (!mdns_instance->service_name.empty()) {
-        reg_type = android::base::StringPrintf("%s.%s", mdns_instance->service_name.data(),
-                                               mdns_instance->transport_type.data());
-        const auto index = adb_DNSServiceIndexByName(reg_type);
-        if (!index) {
-            return std::nullopt;
-        }
-        switch (*index) {
-            case kADBTransportServiceRefIndex:
-            case kADBSecureConnectServiceRefIndex:
-                ForEachService(g_state->watchers[*index], mdns_instance->instance_name, cb);
-                break;
-            default:
-                D("Not a connectable service name [%s]", reg_type.data());
-                return std::nullopt;
-        }
-        return info;
-    }
-
-    // No mdns service name provided. Just search for the instance name in all adb connect services.
-    // Prefer the secured connect service over the other.
-    ForEachService(g_state->watchers[kADBSecureConnectServiceRefIndex], name, cb);
-    if (!info.has_value()) {
-        ForEachService(g_state->watchers[kADBTransportServiceRefIndex], name, cb);
-    }
-
-    return info;
+    std::string fq_service =
+            std::format("{}.{}", mdns_instance->service_name, mdns_instance->transport_type);
+    return discovered_services.FindInstance(fq_service, mdns_instance->instance_name);
 }
 
-std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name) {
+std::optional<ServiceInfo> mdns_get_pairing_service_info(const std::string& name) {
     CHECK(!name.empty());
 
-    if (g_using_bonjour) {
-        return g_adb_mdnsresponder_funcs.mdns_get_pairing_service_info(name);
-    }
-
-    if (!g_state || g_state->watchers.empty()) {
-        return std::nullopt;
-    }
-
     auto mdns_instance = mdns::mdns_parse_instance_name(name);
     if (!mdns_instance.has_value()) {
         D("Failed to parse mDNS name [%s]", name.data());
-        return std::nullopt;
+        return {};
     }
 
-    std::optional<MdnsInfo> info;
-    auto cb = [&](const ServiceInfo& si) {
-        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
-    };
-
-    std::string reg_type;
-    // Verify it's a pairing service if user explicitly inputs it.
-    if (!mdns_instance->service_name.empty()) {
-        reg_type = android::base::StringPrintf("%s.%s", mdns_instance->service_name.data(),
-                                               mdns_instance->transport_type.data());
-        const auto index = adb_DNSServiceIndexByName(reg_type);
-        if (!index) {
-            return std::nullopt;
-        }
-        switch (*index) {
-            case kADBSecurePairingServiceRefIndex:
-                break;
-            default:
-                D("Not an adb pairing reg_type [%s]", reg_type.data());
-                return std::nullopt;
-        }
-        return info;
-    }
-
-    ForEachService(g_state->watchers[kADBSecurePairingServiceRefIndex], name, cb);
-
-    return info;
+    return discovered_services.FindInstance(ADB_SERVICE_PAIR, mdns_instance->instance_name);
 }
diff --git a/client/usb_libusb.cpp b/client/usb_libusb.cpp
index 085276eb..27499e0d 100644
--- a/client/usb_libusb.cpp
+++ b/client/usb_libusb.cpp
@@ -42,6 +42,12 @@ LibUsbConnection::~LibUsbConnection() {
 
 void LibUsbConnection::OnError(const std::string& reason) {
     std::call_once(this->error_flag_, [this, reason]() {
+        // Clears halt condition for endpoints when an error is encountered. This logic was moved
+        // here from LibUsbDevice::ClaimInterface() where calling it as part of the open device
+        // flow would cause some devices to enter a state where communication was broken. See issue
+        // https://issuetracker.google.com/issues/404741058
+        device_->ClearEndpoints();
+
         // When a Windows machine goes to sleep it powers off all its USB host controllers to save
         // energy. When the machine awakens, it powers them up which causes all the endpoints
         // to be closed (which generates a read/write failure leading to us Close()ing the device).
@@ -87,28 +93,14 @@ bool LibUsbConnection::Start() {
 
 void LibUsbConnection::StartReadThread() {
     read_thread_ = std::thread([this]() {
-        LOG(INFO) << Serial() << ": read thread spawning";
+        VLOG(USB) << Serial() << ": read thread spawning";
         while (true) {
             auto packet = std::make_unique<apacket>();
             if (!device_->Read(packet.get())) {
                 PLOG(INFO) << Serial() << ": read failed";
                 break;
             }
-
-            bool got_stls_cmd = false;
-            if (packet->msg.command == A_STLS) {
-                got_stls_cmd = true;
-            }
-
             transport_->HandleRead(std::move(packet));
-
-            // If we received the STLS packet, we are about to perform the TLS
-            // handshake. So this read thread must stop and resume after the
-            // handshake completes otherwise this will interfere in the process.
-            if (got_stls_cmd) {
-                LOG(INFO) << Serial() << ": Received STLS packet. Stopping read thread.";
-                break;
-            }
         }
         HandleStop("read thread stopped");
     });
@@ -116,7 +108,7 @@ void LibUsbConnection::StartReadThread() {
 
 void LibUsbConnection::StartWriteThread() {
     write_thread_ = std::thread([this]() {
-        LOG(INFO) << Serial() << ": write thread spawning";
+        VLOG(USB) << Serial() << ": write thread spawning";
         while (true) {
             std::unique_lock<std::mutex> lock(mutex_);
             ScopedLockAssertion assume_locked(mutex_);
@@ -141,7 +133,7 @@ void LibUsbConnection::StartWriteThread() {
 }
 
 bool LibUsbConnection::DoTlsHandshake(RSA* key, std::string* auth_key) {
-    LOG(WARNING) << "TlsHandshake is not supported by libusb backen";
+    LOG(WARNING) << "TlsHandshake is not supported by libusb backend";
     return false;
 }
 
diff --git a/client/usb_libusb_device.cpp b/client/usb_libusb_device.cpp
index 2bd71ab5..49ca829d 100644
--- a/client/usb_libusb_device.cpp
+++ b/client/usb_libusb_device.cpp
@@ -330,6 +330,27 @@ bool LibUsbDevice::RetrieveSerial() {
     return true;
 }
 
+// Clear halt condition for endpoints
+void LibUsbDevice::ClearEndpoints() {
+    if (device_handle_ == nullptr) {
+        VLOG(USB) << "cannot clear device endpoints, invalid device handle";
+        return;
+    }
+
+    if (!interface_claimed_) {
+        VLOG(USB) << "cannot clear device endpoints, adb interface not claimed";
+        return;
+    }
+
+    for (uint8_t endpoint : {read_endpoint_, write_endpoint_}) {
+        int rc = libusb_clear_halt(device_handle_, endpoint);
+        if (rc != 0) {
+            VLOG(USB) << "failed to clear halt on device " << serial_ << " endpoint "
+                      << StringPrintf("%#x", endpoint) << ": " << libusb_error_name(rc);
+        }
+    }
+}
+
 // libusb gives us an int which is a value from 'enum libusb_speed'
 static uint64_t ToConnectionSpeed(int speed) {
     switch (speed) {
@@ -467,16 +488,6 @@ bool LibUsbDevice::ClaimInterface() {
         return false;
     }
 
-    for (uint8_t endpoint : {read_endpoint_, write_endpoint_}) {
-        rc = libusb_clear_halt(device_handle_, endpoint);
-        if (rc != 0) {
-            VLOG(USB) << "failed to clear halt on device " << serial_ << " endpoint" << endpoint
-                      << ": " << libusb_error_name(rc);
-            libusb_release_interface(device_handle_, interface_num_);
-            return false;
-        }
-    }
-
     VLOG(USB) << "Claimed interface for " << GetSerial() << ", "
               << StringPrintf("bulk_in = %#x, bulk_out = %#x", read_endpoint_, write_endpoint_);
     interface_claimed_ = true;
diff --git a/client/usb_libusb_device.h b/client/usb_libusb_device.h
index 0cff8c78..bab3af48 100644
--- a/client/usb_libusb_device.h
+++ b/client/usb_libusb_device.h
@@ -85,6 +85,9 @@ struct LibUsbDevice {
 
     static USBSessionID GenerateSessionId(libusb_device* device);
 
+    // Clears halt condition for endpoints
+    void ClearEndpoints();
+
   private:
     // Make sure device is and Android device, retrieve OS address, retrieve Android serial.
     void Init();
diff --git a/daemon/adb_wifi.cpp b/daemon/adb_wifi.cpp
index a62db3a0..24fcbdf4 100644
--- a/daemon/adb_wifi.cpp
+++ b/daemon/adb_wifi.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include "adb_wifi.h"
+#include "adbd_wifi.h"
 
 #include <unistd.h>
 #include <optional>
@@ -23,6 +23,7 @@
 #include <android-base/properties.h>
 
 #include "adb.h"
+#include "adbd_wifi.h"
 #include "daemon/mdns.h"
 #include "sysdeps.h"
 #include "transport.h"
@@ -42,10 +43,6 @@ static void adb_disconnected(void* unused, atransport* t) {
     adbd_auth_tls_device_disconnected(auth_ctx, kAdbTransportTypeWifi, t->auth_id.value());
 }
 
-// TODO(b/31559095): need bionic host so that we can use 'prop_info' returned
-// from WaitForProperty
-#if defined(__ANDROID__)
-
 class TlsServer {
   public:
     explicit TlsServer(int port);
@@ -146,11 +143,42 @@ void TlsServer::OnFdEvent(int fd, unsigned ev) {
 }
 
 TlsServer* sTlsServer = nullptr;
-const char kWifiPortProp[] = "service.adb.tls.port";
 
 const char kWifiEnabledProp[] = "persist.adb.tls_server.enable";
 
-static void enable_wifi_debugging() {
+// TODO(b/31559095): need bionic host so that we can use 'prop_info' returned
+// from WaitForProperty
+#if defined(__ANDROID__)
+// Pre API 37 control ADB Wifi TLSServer by toggling kWifiEnabledProp property
+static void start_wifi_enabled_observer() {
+    std::thread([]() {
+        bool wifi_enabled = false;
+        while (true) {
+            std::string toggled_val = wifi_enabled ? "0" : "1";
+            LOG(INFO) << "Waiting for " << kWifiEnabledProp << "=" << toggled_val;
+
+            if (WaitForProperty(kWifiEnabledProp, toggled_val)) {
+                wifi_enabled = !wifi_enabled;
+                LOG(INFO) << kWifiEnabledProp << " changed to " << toggled_val;
+                if (wifi_enabled) {
+                    enable_wifi_debugging();
+                } else {
+                    disable_wifi_debugging();
+                }
+            }
+        }
+    }).detach();
+}
+#endif  //__ANDROID__
+
+}  // namespace
+
+static void adbd_send_tls_server_port(uint16_t port) {
+    LOG(INFO) << "Sending TLS port to framework via system property '" << port << "'";
+    SetProperty("service.adb.tls.port", std::to_string(port));
+}
+
+void enable_wifi_debugging() {
     start_mdnsd();
 
     if (sTlsServer != nullptr) {
@@ -167,10 +195,10 @@ static void enable_wifi_debugging() {
     // Start mdns connect service for discovery
     register_adb_secure_connect_service(sTlsServer->port());
     LOG(INFO) << "adb wifi started on port " << sTlsServer->port();
-    SetProperty(kWifiPortProp, std::to_string(sTlsServer->port()));
+    adbd_send_tls_server_port(sTlsServer->port());
 }
 
-static void disable_wifi_debugging() {
+void disable_wifi_debugging() {
     if (sTlsServer != nullptr) {
         delete sTlsServer;
         sTlsServer = nullptr;
@@ -180,32 +208,8 @@ static void disable_wifi_debugging() {
     }
     kick_all_tcp_tls_transports();
     LOG(INFO) << "adb wifi stopped";
-    SetProperty(kWifiPortProp, "");
-}
-
-// Watches for the #kWifiEnabledProp property to toggle the TlsServer
-static void start_wifi_enabled_observer() {
-    std::thread([]() {
-        bool wifi_enabled = false;
-        while (true) {
-            std::string toggled_val = wifi_enabled ? "0" : "1";
-            LOG(INFO) << "Waiting for " << kWifiEnabledProp << "=" << toggled_val;
-
-            if (WaitForProperty(kWifiEnabledProp, toggled_val)) {
-                wifi_enabled = !wifi_enabled;
-                LOG(INFO) << kWifiEnabledProp << " changed to " << toggled_val;
-                if (wifi_enabled) {
-                    enable_wifi_debugging();
-                } else {
-                    disable_wifi_debugging();
-                }
-            }
-        }
-    }).detach();
+    adbd_send_tls_server_port(0);
 }
-#endif  //__ANDROID__
-
-}  // namespace
 
 void adbd_wifi_init(AdbdAuthContext* ctx) {
     auth_ctx = ctx;
@@ -221,4 +225,4 @@ void adbd_wifi_secure_connect(atransport* t) {
     LOG(INFO) << __func__ << ": connected " << t->serial;
     t->auth_id = adbd_auth_tls_device_connected(auth_ctx, kAdbTransportTypeWifi, t->auth_key.data(),
                                                 t->auth_key.size());
-}
+}
\ No newline at end of file
diff --git a/daemon/adbd_wifi.h b/daemon/adbd_wifi.h
new file mode 100644
index 00000000..4be0ed57
--- /dev/null
+++ b/daemon/adbd_wifi.h
@@ -0,0 +1,28 @@
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
+#include "adb_auth.h"
+#include "transport.h"
+
+void enable_wifi_debugging();
+void disable_wifi_debugging();
+
+struct AdbdAuthContext;
+
+void adbd_wifi_init(AdbdAuthContext* ctx);
+void adbd_wifi_secure_connect(atransport* t);
diff --git a/daemon/auth.cpp b/daemon/auth.cpp
index 495df66d..c59d0445 100644
--- a/daemon/auth.cpp
+++ b/daemon/auth.cpp
@@ -44,7 +44,7 @@
 #include "adb.h"
 #include "adb_auth.h"
 #include "adb_io.h"
-#include "adb_wifi.h"
+#include "daemon/adbd_wifi.h"
 #include "fdevent/fdevent.h"
 #include "transport.h"
 #include "types.h"
@@ -241,17 +241,43 @@ static void adbd_key_removed(const char* public_key, size_t len) {
 }
 
 void adbd_auth_init() {
-    AdbdAuthCallbacksV1 cb;
-    cb.version = 1;
-    cb.key_authorized = adbd_auth_key_authorized;
-    cb.key_removed = adbd_key_removed;
-    auth_ctx = adbd_auth_new(&cb);
-    adbd_wifi_init(auth_ctx);
+    // TODO: We have reached the point where we need to refactor this.
+    // Create a Framework class to abstract all this. Pass that object to each
+    // auth and wifi component so they can assign their own callbacks without having
+    // to expose their internals.
+    auto version = adbd_auth_get_max_version();
+    switch (version) {
+        case 1: {
+            AdbdAuthCallbacksV1 cb;
+            cb.version = 1;
+            cb.key_authorized = adbd_auth_key_authorized;
+            cb.key_removed = adbd_key_removed;
+            auth_ctx = adbd_auth_new(&cb);
+            break;
+        }
+        case 2: {
+            AdbdAuthCallbacksV2 cb;
+            cb.version = 2;
+            cb.key_authorized = adbd_auth_key_authorized;
+            cb.key_removed = adbd_key_removed;
+            cb.start_adbd_wifi = enable_wifi_debugging;
+            cb.stop_adbd_wifi = disable_wifi_debugging;
+            auth_ctx = adbd_auth_new(&cb);
+            break;
+        }
+        default: {
+            LOG(WARNING) << "Unknown libadbd_auth version";
+            break;
+        }
+    }
+
     std::thread([]() {
         adb_thread_setname("adbd auth");
         adbd_auth_run(auth_ctx);
         LOG(FATAL) << "auth thread terminated";
     }).detach();
+
+    adbd_wifi_init(auth_ctx);
 }
 
 void send_auth_request(atransport* t) {
diff --git a/daemon/main.cpp b/daemon/main.cpp
index 931b1702..14c10c3d 100644
--- a/daemon/main.cpp
+++ b/daemon/main.cpp
@@ -49,11 +49,11 @@
 #include "adb_auth.h"
 #include "adb_listeners.h"
 #include "adb_utils.h"
-#include "adb_wifi.h"
 #include "socket_spec.h"
 #include "tradeinmode.h"
 #include "transport.h"
 
+#include "daemon/adbd_wifi.h"
 #include "daemon/jdwp_service.h"
 #include "daemon/mdns.h"
 #include "daemon/transport_daemon.h"
diff --git a/daemon/mdns.cpp b/daemon/mdns.cpp
index 7a4839b4..df04b998 100644
--- a/daemon/mdns.cpp
+++ b/daemon/mdns.cpp
@@ -44,6 +44,7 @@ static DNSServiceRef mdns_refs[kNumADBDNSServices] GUARDED_BY(mdns_lock);
 static bool mdns_registered[kNumADBDNSServices] GUARDED_BY(mdns_lock);
 
 void start_mdnsd() {
+#if defined(__ANDROID__)
     if (android::base::GetProperty("init.svc.mdnsd", "") == "running") {
         return;
     }
@@ -53,6 +54,7 @@ void start_mdnsd() {
     if (! android::base::WaitForProperty("init.svc.mdnsd", "running", 5s)) {
         LOG(ERROR) << "Could not start mdnsd.";
     }
+#endif
 }
 
 static void mdns_callback(DNSServiceRef /*ref*/,
@@ -72,7 +74,7 @@ static std::vector<char> buildTxtRecord() {
     std::map<std::string, std::string> attributes;
     attributes["v"] = std::to_string(ADB_SECURE_SERVICE_VERSION);
     attributes["name"] = android::base::GetProperty("ro.product.model", "");
-    attributes["api"] = android::base::GetProperty("ro.build.version.sdk", "");
+    attributes["api"] = android::base::GetProperty("ro.build.version.sdk_full", "");
 
     // See https://tools.ietf.org/html/rfc6763 for the format of DNS TXT record.
     std::vector<char> record;
diff --git a/daemon/transport_socket_server.cpp b/daemon/transport_socket_server.cpp
index 38ba7ea2..950bb9dc 100644
--- a/daemon/transport_socket_server.cpp
+++ b/daemon/transport_socket_server.cpp
@@ -20,9 +20,12 @@
 #include "transport.h"
 
 #include <errno.h>
+#include <linux/vm_sockets.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+#include <sys/ioctl.h>
+#include <sys/socket.h>
 #include <sys/types.h>
 
 #include <condition_variable>
@@ -40,6 +43,10 @@
 
 #include <android-base/properties.h>
 
+#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
+#include <com_android_adbd_flags.h>
+#endif
+
 #include "adb.h"
 #include "adb_io.h"
 #include "adb_unique_fd.h"
@@ -47,6 +54,56 @@
 #include "socket_spec.h"
 #include "sysdeps/chrono.h"
 
+static bool should_check_vsock_cid() {
+#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
+    return com_android_adbd_flags_adbd_restrict_vsock_local_cid();
+#endif
+    return true;
+}
+
+static bool is_local_vsock_connection(const sockaddr_vm& server_addr,
+                                      const sockaddr_vm& client_addr) {
+    // In vsock address, CID is an identifier for detecting whether it's either a virtual machine or
+    // the host of virtual machines. When the connection is from the local process, the address of
+    // the server or the client contains VMADDR_CID_LOCAL or the machine's CID respectively. The
+    // equality checks here is for restricting all possible 4 cases.
+    return server_addr.svm_cid == VMADDR_CID_LOCAL || client_addr.svm_cid == VMADDR_CID_LOCAL ||
+           server_addr.svm_cid == client_addr.svm_cid;
+}
+
+static unique_fd adb_vsock_accept(borrowed_fd serverfd) {
+    sockaddr_vm server_addr, client_addr;
+    socklen_t server_addr_len = sizeof(server_addr);
+    socklen_t client_addr_len = sizeof(client_addr);
+
+    unique_fd fd(adb_socket_accept(serverfd, reinterpret_cast<struct sockaddr*>(&client_addr),
+                                   &client_addr_len));
+    if (fd < 0) {
+        VLOG(TRANSPORT) << "server: failed to adb_socket_accept";
+        return {};
+    }
+
+    if (getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&server_addr), &server_addr_len) <
+        0) {
+        VLOG(TRANSPORT) << "server: failed to retrieve socket address of accept fd";
+        return {};
+    }
+
+    if (server_addr.svm_family != AF_VSOCK || client_addr.svm_family != AF_VSOCK) {
+        VLOG(TRANSPORT) << "server: invalid vsock address";
+        return {};
+    }
+
+    // Adbd rejects local connection over vsock, to prevent connection establishment by any
+    // arbitrary apps or processes unrelated to virtual machine.
+    if (is_local_vsock_connection(server_addr, client_addr)) {
+        VLOG(TRANSPORT) << "server: adbd restricts vsock connection from local";
+        return {};
+    }
+
+    return fd;
+}
+
 void server_socket_thread(std::string_view addr) {
     adb_thread_setname("server_socket");
 
@@ -70,7 +127,12 @@ void server_socket_thread(std::string_view addr) {
 
     while (true) {
         D("server: trying to get new connection from fd %d", serverfd.get());
-        unique_fd fd(adb_socket_accept(serverfd, nullptr, nullptr));
+        unique_fd fd;
+        if (addr.starts_with("vsock:") && should_check_vsock_cid()) {
+            fd = adb_vsock_accept(serverfd);
+        } else {
+            fd = unique_fd{adb_socket_accept(serverfd, nullptr, nullptr)};
+        }
         if (fd >= 0) {
             D("server: new connection on fd %d", fd.get());
             close_on_exec(fd.get());
diff --git a/docs/dev/incremental-install.md b/docs/dev/incremental-install.md
index f47be751..75fb0489 100644
--- a/docs/dev/incremental-install.md
+++ b/docs/dev/incremental-install.md
@@ -68,11 +68,12 @@ This problem is solved with V4 signing which does not discard the merkle tree
 but embed it in the signed file and also outputs the top merkle node hash in
 a .idsig file.
 
-Upon installation the whole merkel tree from V4 is given to `pm` which forwards
+Upon installation the whole merkle tree from V4 is given to `pm` which forwards
 it to the Android kernel. The kernel is in charge of verifying the integrity
 of each block when they are received from the `IS` via the merkle tree.
 
 For more details about v4 signing, refer to [APK signature scheme v4](https://source.android.com/docs/security/features/apksigning/v4) page.
+
 ## How ADB performs incremental-install
 
 To perform incremental-install, ADB needs to do two things.
@@ -81,20 +82,20 @@ To perform incremental-install, ADB needs to do two things.
 - Start a `IS`.
 
 ```
-  ┌───┐                              ┌────┐      
-  │adb│                              │ppm │      
-  └─┬─┘                              └─┬──┘      
-    │       pm install-incremental     │         
-    ├─────────────────────────────────►│         
-    │    ┌────┐                        │         
-    ├───►│ IS │                        │         
-    │    └─┬──┘                        │         
-    X      │                           │         
-           ├──────────────────────────►│         
-           ├──────────────────────────►│         
-           │◄──────────────────────────┤         
-           ├──────────────────────────►│         
-           │                           │         
+  ┌───┐                              ┌────┐
+  │adb│                              │ppm │
+  └─┬─┘                              └─┬──┘
+    │       pm install-incremental     │
+    ├─────────────────────────────────►│
+    │    ┌────┐                        │
+    ├───►│ IS │                        │
+    │    └─┬──┘                        │
+    X      │                           │
+           ├──────────────────────────►│
+           ├──────────────────────────►│
+           │◄──────────────────────────┤
+           ├──────────────────────────►│
+           │                           │
 ```
 
 ### Local database
@@ -112,7 +113,16 @@ where
 - `file_id` is the identified that will be used by the kernel for block
 requests. There is one arg for each file to be streamed.
 - `signature` is the top merkle hash.
-- `[:protocol_version]` is optional.
+- `[:protocol_version]` is optional. (default: 0)
+
+#### Protocol version
+
+If `protocol_version` is 0, the merkle tree of the file is not sent via the `IS`
+but instead sent on stdin, before the `IS` is started.
+
+If `protocol_version` is 1, the merkle tree of the file is sent via the `IS`.
+
+The current implementation of ADB only uses version 1.
 
 ### Unsigned files
 
@@ -120,30 +130,30 @@ There could be unsigned files to be installed. In this case, `pm` has to be made
 aware of them via a special arg format.
 
 ```
-filename::file_size:file_id
+filename:file_size:file_id
 ```
 
 These files are not sent via the `IS` but instead sent on stdin, before
 the `IS` is started.
 
 ```
-  ┌───┐                              ┌────┐      
-  │adb│                              │ppm │      
-  └─┬─┘                              └─┬──┘      
-    │       pm install-incremental     │         
-    ├─────────────────────────────────►│         
-    │                                  │         
-    │       (stdin) write(unsigned)    │         
-    ├─────────────────────────────────►│         
-    │    ┌────┐                        │         
-    ├───►│ IS │                        │         
-    │    └─┬──┘                        │         
-    X      │                           │         
-           ├──────────────────────────►│         
-           ├──────────────────────────►│         
-           │◄──────────────────────────┤         
-           ├──────────────────────────►│         
-           │                           │         
+  ┌───┐                              ┌────┐
+  │adb│                              │ppm │
+  └─┬─┘                              └─┬──┘
+    │       pm install-incremental     │
+    ├─────────────────────────────────►│
+    │                                  │
+    │       (stdin) write(unsigned)    │
+    ├─────────────────────────────────►│
+    │    ┌────┐                        │
+    ├───►│ IS │                        │
+    │    └─┬──┘                        │
+    X      │                           │
+           ├──────────────────────────►│
+           ├──────────────────────────►│
+           │◄──────────────────────────┤
+           ├──────────────────────────►│
+           │                           │
 ```
 
 ## Learn more
@@ -152,4 +162,4 @@ There is more documentation about this topic which is unfortunately internal onl
 
 - [go/incremental-adb](go/incremental-adb)
 - [go/apk-v4-signature-format](go/apk-v4-signature-format)
-- [go/instamatic-design-signature](go/instamatic-design-signature)
\ No newline at end of file
+- [go/instamatic-design-signature](go/instamatic-design-signature)
diff --git a/docs/dev/services.md b/docs/dev/services.md
index d1457c93..8de7f4d2 100644
--- a/docs/dev/services.md
+++ b/docs/dev/services.md
@@ -147,6 +147,16 @@ host:server-status
 
     Used to implement 'adb forward --list'.
 
+<host-prefix>:mdns:check
+    Verify a mdns stack is enable and return which one as text.
+    Example: `mdns daemon version [Openscreen discovery 0.0.0]`
+
+<host-prefix>:track-mdns-services
+    Availability: If "track_mdns" is in the list of supported features.
+    Stream discovered mdns services as follows.
+        <hex4>: The length of the protobuffer message
+        <payload>: An MdnsServices binary protobuffer
+
 LOCAL SERVICES:
 
 All the queries below assumed that you already switched the transport
diff --git a/docs/user/adb.1.md b/docs/user/adb.1.md
index bc8ed4d8..668e3408 100644
--- a/docs/user/adb.1.md
+++ b/docs/user/adb.1.md
@@ -128,6 +128,8 @@ mdns **check** | **services**
 **services**
 &nbsp;&nbsp;&nbsp;&nbsp;List all discovered services.
 
+**track-services**
+&nbsp;&nbsp;&nbsp;&nbsp;Stream discovered services. Supports flags "--proto-text" and "proto-binary".
 
 # FILE TRANSFER:
 
diff --git a/fdevent/fdevent.cpp b/fdevent/fdevent.cpp
index bc0074d9..a5eb20cc 100644
--- a/fdevent/fdevent.cpp
+++ b/fdevent/fdevent.cpp
@@ -186,6 +186,12 @@ void fdevent_context::CheckLooperThread() const {
     }
 }
 
+void fdevent_context::CheckNotLooperThread() const {
+    if (looper_thread_id_) {
+        CHECK_NE(*looper_thread_id_, android::base::GetThreadId());
+    }
+}
+
 void fdevent_context::Run(std::function<void()> fn) {
     {
         std::lock_guard<std::mutex> lock(run_queue_mutex_);
@@ -263,6 +269,10 @@ void fdevent_check_looper() {
     fdevent_get_ambient()->CheckLooperThread();
 }
 
+void fdevent_check_not_looper() {
+    fdevent_get_ambient()->CheckNotLooperThread();
+}
+
 void fdevent_terminate_loop() {
     fdevent_get_ambient()->TerminateLoop();
 }
diff --git a/fdevent/fdevent.h b/fdevent/fdevent.h
index 770e192d..cb5e0102 100644
--- a/fdevent/fdevent.h
+++ b/fdevent/fdevent.h
@@ -113,6 +113,10 @@ struct fdevent_context {
     // thread that invoked Loop().
     void CheckLooperThread() const;
 
+    // Assert that the caller is NOT executing in the context of the execution
+    // thread that invoked Loop().
+    void CheckNotLooperThread() const;
+
     // Queue an operation to be run on the looper thread.
     void Run(std::function<void()> fn);
 
@@ -154,6 +158,7 @@ void fdevent_loop();
 // of Loop() so that fdevent_context requests can be serially processed
 // by the global instance robustly.
 void fdevent_check_looper();
+void fdevent_check_not_looper();
 
 // Queue an operation to run on the looper event thread.
 void fdevent_run_on_looper(std::function<void()> fn);
diff --git a/proto/adb_host.proto b/proto/adb_host.proto
index f5022a66..f2c907ec 100644
--- a/proto/adb_host.proto
+++ b/proto/adb_host.proto
@@ -88,5 +88,53 @@ message AdbServerStatus {
      optional string trace_level = 10;
      optional bool burst_mode = 11;
      optional bool mdns_enabled = 12;
+     optional string keystore_path = 13;
+     optional string known_hosts_path = 14;
 }
 
+message MdnsServices {
+    repeated ServiceAdbTcp tcp = 1;
+    repeated ServiceAdbTls tls = 2;
+    repeated ServiceAdbPairing pair = 3;
+}
+
+message ServiceAdbTcp {
+    MdnsService service = 1;
+}
+
+message ServiceAdbTls {
+    MdnsService service = 1 ;
+    // If this device has previously been paired, it is considered a known device.
+    bool known_device = 2;
+}
+
+message ServiceAdbPairing {
+    MdnsService service = 1;
+}
+
+message MdnsService {
+    // For explanation about the meaning of instance, service, and domain
+    // refer to RFC 6763 (mdns-sd).
+
+    // e.g.: "adb-43081FDAS000ST-GIVKML"
+    string instance = 1;
+
+    // e.g.: _adb-tls-connect._tcp
+    string service = 2;
+
+    // e.g.: local
+    string domain = 3;
+
+    optional string ipv4 = 4;
+    repeated string ipv6 = 5;
+    uint32 port = 6;
+
+    // Comes from device property "ro.product.model"
+    optional string product_model = 7;
+
+    // Comes from device property "ro.build.version.sdk_full"
+    optional string build_version_sdk_full = 8;
+}
+
+
+
diff --git a/services.cpp b/services.cpp
index 1c9ed70d..87c8dcf8 100644
--- a/services.cpp
+++ b/services.cpp
@@ -35,12 +35,19 @@
 #include "adb_io.h"
 #include "adb_unique_fd.h"
 #include "adb_utils.h"
-#include "adb_wifi.h"
+#if ADB_HOST
+#include "client/adb_wifi.h"
+#endif
 #include "services.h"
 #include "socket_spec.h"
 #include "sysdeps.h"
 #include "transport.h"
 
+#if ADB_HOST
+#include "client/host_services.h"
+#include "client/mdns_tracker.h"
+#endif
+
 namespace {
 
 void service_bootstrap_func(std::string service_name, std::function<void(unique_fd)> func,
@@ -149,6 +156,7 @@ static void connect_service(unique_fd fd, std::string host) {
 static void pair_service(unique_fd fd, std::string host, std::string password) {
     std::string response;
     adb_wifi_pair_device(host, password, response);
+    VLOG(MDNS) << "Pairing response: '" << response << "'";
     if (android::base::StartsWith(response, "Successful")) {
         SendProtocolString(fd.get(), response);
     } else {
@@ -278,6 +286,8 @@ asocket* host_service_to_socket(std::string_view name, std::string_view serial,
         unique_fd fd = create_service_thread(
                 "pair", std::bind(pair_service, std::placeholders::_1, host, password));
         return create_local_socket(std::move(fd));
+    } else if (android::base::ConsumePrefix(&name, HostServices::kTrackMdnsServices)) {
+        return create_mdns_tracker();
     }
     return nullptr;
 }
diff --git a/socket_spec.cpp b/socket_spec.cpp
index 5f0cb3f0..eb72ed55 100644
--- a/socket_spec.cpp
+++ b/socket_spec.cpp
@@ -208,16 +208,15 @@ bool socket_spec_connect(unique_fd* fd, std::string_view address, int* port, std
             // Check if the address is an mdns service we can connect to.
             if (auto mdns_info = mdns_get_connect_service_info(std::string(address.substr(4)));
                 mdns_info != std::nullopt) {
-                fd->reset(network_connect(mdns_info->addr, mdns_info->port, SOCK_STREAM, 0, error));
+                fd->reset(network_connect(mdns_info->v4_address_string(), mdns_info->port,
+                                          SOCK_STREAM, 0, error));
                 if (fd->get() != -1) {
                     // TODO(joshuaduong): We still show the ip address for the serial. Change it to
                     // use the mdns instance name, so we can adjust to address changes on
                     // reconnects.
                     port_value = mdns_info->port;
                     if (serial) {
-                        *serial = android::base::StringPrintf("%s.%s",
-                                                              mdns_info->service_name.c_str(),
-                                                              mdns_info->service_type.c_str());
+                        *serial = std::format("{}.{}", mdns_info->instance, mdns_info->service);
                     }
                 }
             } else {
diff --git a/sockets.cpp b/sockets.cpp
index 9a24ff08..acb3de1c 100644
--- a/sockets.cpp
+++ b/sockets.cpp
@@ -470,7 +470,7 @@ asocket* create_local_service_socket(std::string_view name, atransport* transpor
     int fd_value = fd.get();
     asocket* s = create_local_socket(std::move(fd));
     s->transport = transport;
-    VLOG(SERVICES) << "LS(" << s->id << "): bound to '" << name << "' via " << fd_value;
+    VLOG(SOCKETS) << "LS(" << s->id << "): bound to '" << name << "' via " << fd_value;
 
 #if !ADB_HOST
     if ((name.starts_with("root:") && getuid() != 0 && __android_log_is_debuggable()) ||
@@ -567,7 +567,7 @@ void connect_to_remote(asocket* s, std::string_view destination) {
     D("Connect_to_remote call RS(%d) fd=%d", s->id, s->fd);
     apacket* p = get_apacket();
 
-    LOG(VERBOSE) << "LS(" << s->id << ": connect(" << destination << ")";
+    VLOG(ADB) << "LS(" << s->id << ": connect(" << destination << ")";
     p->msg.command = A_OPEN;
     p->msg.arg0 = s->id;
 
@@ -859,7 +859,7 @@ static int smart_socket_enqueue(asocket* s, apacket::payload_type data) {
 
         switch (host_request_result) {
             case HostRequestResult::Handled:
-                LOG(VERBOSE) << "SS(" << s->id << "): handled host service '" << service << "'";
+                VLOG(SERVICES) << "SS(" << s->id << "): handled host service '" << service << "'";
                 goto fail;
 
             case HostRequestResult::SwitchedTransport:
@@ -878,7 +878,8 @@ static int smart_socket_enqueue(asocket* s, apacket::payload_type data) {
         // TODO: Convert to string_view.
         s2 = host_service_to_socket(service, serial, transport_id);
         if (s2 == nullptr) {
-            LOG(VERBOSE) << "SS(" << s->id << "): couldn't create host service '" << service << "'";
+            VLOG(SERVICES) << "SS(" << s->id << "): couldn't create host service '" << service
+                           << "'";
             std::string msg = std::string("unknown host service '") + std::string(service) + "'";
             SendFail(s->peer->fd, msg);
             goto fail;
diff --git a/test_device.py b/test_device.py
index 87b5a032..0b3e7050 100755
--- a/test_device.py
+++ b/test_device.py
@@ -1856,6 +1856,22 @@ class DevicesListing(DeviceTest):
 
             proc.terminate()
 
+class MdnsTracking(DeviceTest):
+    def test_track_mdns_proto_binary(self):
+        with subprocess.Popen(['adb', 'mdns' ,'track-services', '--proto-binary'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
+            output_size = int(proc.stdout.read(4).decode("utf-8"), 16)
+            self.assertTrue(output_size == 0)
+            #TODO Use a mdns client to publish fake services and detect them here
+            proc.kill()
+
+    def test_track_mdns_proto_text(self):
+        with subprocess.Popen(['adb', 'mdns' ,'track-services', '--proto-text'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
+            with io.TextIOWrapper(proc.stdout, encoding='utf8') as reader:
+               out = reader.read(9)
+               #TODO Use a mdns client to publish fake services and detect them here
+               self.assertTrue("Services" in out)
+               proc.kill()
+
 def invoke(*args):
     print(args)
     try:
diff --git a/transport.cpp b/transport.cpp
index 3c27f0dd..312db556 100644
--- a/transport.cpp
+++ b/transport.cpp
@@ -103,6 +103,7 @@ const char* const kFeatureDeviceTrackerProtoFormat = "devicetracker_proto_format
 const char* const kFeatureDevRaw = "devraw";
 const char* const kFeatureAppInfo = "app_info";  // Add information to track-app (package name, ...)
 const char* const kFeatureServerStatus = "server_status";  // Ability to output server status
+const char* const kFeatureTrackMdns = "track_mdns";        // Track and stream mdns services.
 
 namespace {
 
@@ -299,7 +300,7 @@ BlockingConnectionAdapter::BlockingConnectionAdapter(std::unique_ptr<BlockingCon
     : underlying_(std::move(connection)) {}
 
 BlockingConnectionAdapter::~BlockingConnectionAdapter() {
-    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): destructing";
+    VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): destructing";
     Stop();
 }
 
@@ -312,7 +313,7 @@ bool BlockingConnectionAdapter::Start() {
     StartReadThread();
 
     write_thread_ = std::thread([this]() {
-        LOG(INFO) << Serial() << ": write thread spawning";
+        VLOG(ADB) << Serial() << ": write thread spawning";
         while (true) {
             std::unique_lock<std::mutex> lock(mutex_);
             ScopedLockAssertion assume_locked(mutex_);
@@ -341,11 +342,11 @@ bool BlockingConnectionAdapter::Start() {
 
 void BlockingConnectionAdapter::StartReadThread() {
     read_thread_ = std::thread([this]() {
-        LOG(INFO) << Serial() << ": read thread spawning";
+        VLOG(ADB) << Serial() << ": read thread spawning";
         while (true) {
             auto packet = std::make_unique<apacket>();
             if (!underlying_->Read(packet.get())) {
-                PLOG(INFO) << Serial() << ": read failed";
+                VLOG(ADB) << Serial() << ": read failed";
                 break;
             }
 
@@ -360,7 +361,7 @@ void BlockingConnectionAdapter::StartReadThread() {
             // handshake. So this read thread must stop and resume after the
             // handshake completes otherwise this will interfere in the process.
             if (got_stls_cmd) {
-                LOG(INFO) << Serial() << ": Received STLS packet. Stopping read thread.";
+                VLOG(ADB) << Serial() << ": Received STLS packet. Stopping read thread.";
                 return;
             }
         }
@@ -382,17 +383,17 @@ void BlockingConnectionAdapter::Reset() {
     {
         std::lock_guard<std::mutex> lock(mutex_);
         if (!started_) {
-            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): not started";
+            VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): not started";
             return;
         }
 
         if (stopped_) {
-            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): already stopped";
+            VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): already stopped";
             return;
         }
     }
 
-    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): resetting";
+    VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): resetting";
     this->underlying_->Reset();
     Stop();
 }
@@ -401,19 +402,19 @@ void BlockingConnectionAdapter::Stop() {
     {
         std::lock_guard<std::mutex> lock(mutex_);
         if (!started_) {
-            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): not started";
+            VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): not started";
             return;
         }
 
         if (stopped_) {
-            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): already stopped";
+            VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): already stopped";
             return;
         }
 
         stopped_ = true;
     }
 
-    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): stopping";
+    VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): stopping";
 
     this->underlying_->Close();
     this->cv_.notify_one();
@@ -431,7 +432,7 @@ void BlockingConnectionAdapter::Stop() {
     read_thread.join();
     write_thread.join();
 
-    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): stopped";
+    VLOG(ADB) << "BlockingConnectionAdapter(" << Serial() << "): stopped";
     std::call_once(this->error_flag_, [this]() { transport_->HandleError("requested stop"); });
 }
 
@@ -562,6 +563,10 @@ void FdConnection::Close() {
 }
 
 void send_packet(apacket* p, atransport* t) {
+    VLOG(PACKETS) << std::format("packet --> {}{}{}{}", ((char*)(&(p->msg.command)))[0],
+                                 ((char*)(&(p->msg.command)))[1], ((char*)(&(p->msg.command)))[2],
+                                 ((char*)(&(p->msg.command)))[3]);
+
     p->msg.magic = p->msg.command ^ 0xffffffff;
     // compute a checksum for connection/auth packets for compatibility reasons
     if (t->get_protocol_version() >= A_VERSION_SKIP_CHECKSUM) {
@@ -740,6 +745,7 @@ static void fdevent_unregister_transport(atransport* t) {
         pending_list.remove(t);
     }
 
+    t->connection()->SetTransport(nullptr);
     delete t;
 
     update_transports();
@@ -1224,6 +1230,7 @@ const FeatureSet& supported_features() {
             kFeatureDevRaw,
             kFeatureAppInfo,
             kFeatureServerStatus,
+            kFeatureTrackMdns,
         };
         // clang-format on
 
@@ -1502,6 +1509,12 @@ bool validate_transport_list(const std::list<atransport*>& list, const std::stri
 
 bool register_socket_transport(unique_fd s, std::string serial, int port, bool is_emulator,
                                atransport::ReconnectCallback reconnect, bool use_tls, int* error) {
+#if ADB_HOST
+    // Below in this method, we block up to 10s on the waitable. This should never run on the
+    // fdevent thread.
+    fdevent_check_not_looper();
+#endif
+
     atransport* t = new atransport(kTransportLocal, std::move(reconnect), kCsOffline);
     t->use_tls = use_tls;
     t->serial = std::move(serial);
@@ -1717,7 +1730,7 @@ std::shared_ptr<RSA> atransport::Key() {
 
 std::shared_ptr<RSA> atransport::NextKey() {
     if (keys_.empty()) {
-        LOG(INFO) << "fetching keys for transport " << this->serial_name();
+        VLOG(ADB) << "fetching keys for transport " << this->serial_name();
         keys_ = adb_auth_get_private_keys();
 
         // We should have gotten at least one key: the one that's automatically generated.
diff --git a/transport.h b/transport.h
index ed22da7b..08f034cd 100644
--- a/transport.h
+++ b/transport.h
@@ -488,8 +488,6 @@ void init_mdns_transport_discovery();
 atransport* find_transport(const char* serial);
 
 void kick_all_tcp_devices();
-
-bool using_bonjour(void);
 #endif
 
 void kick_all_transports();
```

