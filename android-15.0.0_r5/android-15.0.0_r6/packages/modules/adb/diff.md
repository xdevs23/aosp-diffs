```diff
diff --git a/Android.bp b/Android.bp
index 967bcfd7..6a62c34d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -306,6 +306,7 @@ cc_library_host_static {
 
     static_libs: [
         "libadb_crypto",
+        "libadb_host_protos",
         "libadb_pairing_connection",
         "libadb_protos",
         "libadb_tls_connection",
@@ -314,7 +315,6 @@ cc_library_host_static {
         "libcrypto_utils",
         "libcutils",
         "libdiagnose_usb",
-        "libdevices_protos",
         "liblog",
         "libmdnssd",
         "libopenscreen-discovery",
@@ -375,6 +375,7 @@ cc_test_host {
     static_libs: [
         "libadb_crypto_static",
         "libadb_host",
+        "libadb_host_protos",
         "libadb_pairing_auth_static",
         "libadb_pairing_connection_static",
         "libadb_protos_static",
@@ -384,7 +385,6 @@ cc_test_host {
         "libcrypto",
         "libcrypto_utils",
         "libcutils",
-        "libdevices_protos",
         "libdiagnose_usb",
         "liblog",
         "libmdnssd",
@@ -409,8 +409,8 @@ cc_test_host {
     },
 }
 
-cc_binary_host {
-    name: "adb",
+cc_defaults {
+    name: "adb_binary_host_defaults",
 
     stl: "libc++_static",
     defaults: ["adb_defaults"],
@@ -440,6 +440,7 @@ cc_binary_host {
     static_libs: [
         "libadb_crypto",
         "libadb_host",
+        "libadb_host_protos",
         "libadb_pairing_auth",
         "libadb_pairing_connection",
         "libadb_protos",
@@ -453,7 +454,6 @@ cc_binary_host {
         "libcrypto_utils",
         "libcutils",
         "libdiagnose_usb",
-        "libdevices_protos",
         "libfastdeploy_host",
         "liblog",
         "liblog",
@@ -503,6 +503,38 @@ cc_binary_host {
     },
 }
 
+cc_binary_host {
+    name: "adb",
+    defaults: ["adb_binary_host_defaults"],
+}
+
+cc_binary_host {
+    name: "adb_asan",
+    defaults: ["adb_binary_host_defaults"],
+    target: {
+        darwin: {
+            sanitize: {
+                address: true,
+            },
+            strip: {
+                none: true,
+            },
+        },
+        linux: {
+            sanitize: {
+                address: true,
+            },
+            strip: {
+                none: true,
+            },
+        },
+        // Not supported on Windows yet...
+        windows: {
+            enabled: false,
+        },
+    },
+}
+
 // libadbd_core contains the common sources to build libadbd and libadbd_services.
 cc_library_static {
     name: "libadbd_core",
@@ -917,7 +949,7 @@ python_test_host {
     main: "test_device.py",
     srcs: [
         "proto/app_processes.proto",
-        "proto/devices.proto",
+        ":adb_host_proto",
         "test_device.py",
     ],
     proto: {
@@ -1001,6 +1033,7 @@ cc_test_host {
     static_libs: [
         "libadb_crypto_static",
         "libadb_host",
+        "libadb_host_protos",
         "libadb_pairing_auth_static",
         "libadb_pairing_connection_static",
         "libadb_protos_static",
@@ -1011,7 +1044,6 @@ cc_test_host {
         "libcrypto",
         "libcrypto_utils",
         "libcutils",
-        "libdevices_protos",
         "libdiagnose_usb",
         "libfastdeploy_host",
         "liblog",
diff --git a/README.md b/README.md
index 394fc4cb..9153ea14 100644
--- a/README.md
+++ b/README.md
@@ -1,108 +1,9 @@
-# ADB Internals
+# ADB (Android Debug Bridge) repository
 
-If you are new to adb source code, you should start by reading [OVERVIEW.TXT](OVERVIEW.TXT) which describes the three components of adb pipeline.
+The Android Debug Bridge connects Android devices to to computers running other OSes (Linux, MacOS, and Windows) over USB or TCP.
 
-This document is here to boost what can be achieved within a "window of naive interest". You will not find function or class documentation here but rather the "big picture" which should allow you to build a mental map to help navigate the code.
+## User documentation
+[man page](docs/user/adb.1.md)
 
-## Three components of adb pipeline
-
-As outlined in the overview, this codebase generates three components (Client, Server (a.k.a Host), and Daemon (a.k.a adbd)). The central part is the Server which runs on the Host computer. On one side the Server exposes a "Smart Socket" to Clients such as adb or DDMLIB. On the other side, the Server continuously monitors for connecting Daemons (as USB devices or TCP emulator). Communication with a device is done with a Transport.
-
-```
-+----------+              +------------------------+
-|   ADB    +----------+   |      ADB SERVER        |                   +----------+
-|  CLIENT  |          |   |                        |              (USB)|   ADBD   |
-+----------+          |   |                     Transport+-------------+ (DEVICE) |
-                      |   |                        |                   +----------+
-+-----------          |   |                        |
-|   ADB    |          v   +                        |                   +----------+
-|  CLIENT  +--------->SmartSocket                  |              (USB)|   ADBD   |
-+----------+          ^   | (TCP/IP)            Transport+-------------+ (DEVICE) |
-                      |   |                        |                   +----------+
-+----------+          |   |                        |
-|  DDMLIB  |          |   |                     Transport+--+          +----------+
-|  CLIENT  +----------+   |                        |        |  (TCP/IP)|   ADBD   |
-+----------+              +------------------------+        +----------|(EMULATOR)|
-                                                                       +----------+
-```
-
-The Client and the Server are contained in the same executable and both run on the Host machine. Code sections specific to the Host is enclosed within `ADB_HOST` guard. adbd runs on the Android Device. Daemon specific code is enclosed in `!ADB_HOST` but also sometimes with-in `__ANDROID__` guard.
-
-
-## "SMART SOCKET" and TRANSPORT
-
-A smart socket is a simple TCP socket with a smart protocol built on top of it. This is what Clients connect onto from the Host side. The Client must always initiate communication via a human readable request but the response format varies. The smart protocol is documented in [SERVICES.TXT](SERVICES.TXT).
-
-On the other side, the Server communicates with a device via a Transport. adb initially targeted devices connecting over USB, which is restricted to a fixed number of data streams. Therefore, adb multiplexes multiple byte streams over a single pipe via Transport. When devices connecting over other mechanisms (e.g. emulators over TCP) were introduced, the existing transport protocol was maintained.
-
-## THREADING MODEL and FDEVENT system
-
-At the heart of both the Server and Daemon is a main thread running an fdevent loop, which is a platform-independent abstraction over poll/epoll/WSAPoll monitoring file descriptors events. Requests and services are usually served from the main thread but some service requests result in new threads being spawned.
-
-To allow for operations to run on the Main thread, fdevent features a RunQueue combined with an interrupt fd to force polling to return.
-
-```
-+------------+    +-------------------------^
-|  RUNQUEUE  |    |                         |
-+------------+    |  POLLING (Main thread)  |
-| Function<> |    |                         |
-+------------+    |                         |
-| Function<> |    ^-^-------^-------^------^^
-+------------+      |       |       |       |
-|    ...     |      |       |       |       |
-+------------+      |       |       |       |
-|            |      |       |       |       |
-|============|      |       |       |       |
-|Interrupt fd+------+  +----+  +----+  +----+
-+------------+         fd      Socket  Pipe
-```
-
-## ASOCKET, APACKET, and AMESSAGE
-
-The asocket, apacket, and amessage constructs exist only to wrap data while it transits on a Transport. An asocket handles a stream of apackets. An apacket consists in a amessage header featuring a command (`A_SYNC`, `A_OPEN`, `A_CLSE`, `A_WRTE`, `A_OKAY`, ...) followed by a payload (find more documentation in [protocol.txt](protocol.txt). There is no `A_READ` command because an asocket is unidirectional. To model a bi-directional stream, asocket have a peer which go in the opposite direction.
-
-An asocket features a buffer where the elemental unit is an apacket. If traffic is inbound, the buffer stores the apacket until it is consumed. If the traffic is oubound, the buffer stores apackets until they are sent down the wire (with `A_WRTE` commands).
-
-```
-+---------------------ASocket------------------------+
- |                                                   |
- | +----------------APacket Queue------------------+ |
- | |                                               | |
- | |            APacket     APacket     APacket    | |
- | |          +--------+  +--------+  +--------+   | |
- | |          |AMessage|  |AMessage|  |AMessage|   | |
- | |          +--------+  +--------+  +--------+   | |
- | |          |        |  |        |  |        |   | |
- | |  .....   |        |  |        |  |        |   | |
- | |          |  Data  |  |  Data  |  |  Data  |   | |
- | |          |        |  |        |  |        |   | |
- | |          |        |  |        |  |        |   | |
- | |          +--------+  +--------+  +--------+   | |
- | |                                               | |
- | +-----------------------------------------------+ |
- +---------------------------------------------------+
-```
-
-This system allows to multiplex data streams on an unique byte stream.  Without entering too much into details, the amessage fields arg1 and arg2 are used alike in the TCP protocol where local and remote ports identify an unique stream. Note that unlike TCP which feature an "unacknowledged-send window", an apacket is sent only after the previous one has been confirmed to be received.
-
-The two types of asocket (Remote and Local) differentiate between outbound and inbound traffic.
-
-## adbd <-> APPPLICATION communication
-
-This pipeline is detailed in [daemon/jdwp_service.cpp](daemon/jdwp_service.cpp) with ASCII drawings! The JDWP extension implemented by Dalvik/ART are documented in:
-- platform/dalvik/+/main/docs/debugmon.html
-- platform/dalvik/+/main/docs/debugger.html
-
-### Sync protocol
-
-To transfer files and directories, ADB places a smart-socket in SYNC mode and then issues SYNC commands. The SYNC protocol is documented in [SYNC.TXT](SYNC.TXT).
-
-### Benchmark sample run for Pixel 8,USB
-
-```
-$ ./benchmark_device.py
-sink 100MiB: 10 runs: median 27.00 MiB/s, mean 26.39 MiB/s, stddev: 1.11 MiB/s
-source 100MiB: 10 runs: median 36.97 MiB/s, mean 37.05 MiB/s, stddev: 0.46 MiB/s
-push 100MiB: 10 runs: median 331.96 MiB/s, mean 329.81 MiB/s, stddev: 14.67 MiB/s
-pull 100MiB: 10 runs: median 34.55 MiB/s, mean 33.57 MiB/s, stddev: 2.54 MiB/s
-```
+## Developer documentation
+[main page](docs/dev/README.md)
diff --git a/adb.cpp b/adb.cpp
index f2cf8fc7..95fd303e 100644
--- a/adb.cpp
+++ b/adb.cpp
@@ -73,6 +73,7 @@ using namespace std::chrono_literals;
 #endif
 
 #if ADB_HOST
+#include "adb_host.pb.h"
 #include "client/usb.h"
 #endif
 
@@ -139,12 +140,14 @@ std::string to_string(ConnectionState state) {
             return "authorizing";
         case kCsConnecting:
             return "connecting";
+        case kCsDetached:
+            return "detached";
         default:
             return "unknown";
     }
 }
 
-apacket* get_apacket(void) {
+apacket* get_apacket() {
     apacket* p = new apacket();
     if (p == nullptr) {
         LOG(FATAL) << "failed to allocate an apacket";
@@ -1324,6 +1327,34 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
         }
     }
 
+    if (service == "server-status") {
+        adb::proto::AdbServerStatus status;
+        if (is_libusb_enabled()) {
+            status.set_usb_backend(adb::proto::AdbServerStatus::LIBUSB);
+        } else {
+            status.set_usb_backend(adb::proto::AdbServerStatus::NATIVE);
+        }
+        status.set_usb_backend_forced(getenv("ADB_LIBUSB") != nullptr);
+
+        if (using_bonjour()) {
+            status.set_mdns_backend(adb::proto::AdbServerStatus::BONJOUR);
+        } else {
+            status.set_mdns_backend(adb::proto::AdbServerStatus::OPENSCREEN);
+        }
+        status.set_mdns_backend_forced(getenv("ADB_MDNS_OPENSCREEN") != nullptr);
+
+        status.set_version(std::string(PLATFORM_TOOLS_VERSION));
+        status.set_build(android::build::GetBuildNumber());
+        status.set_executable_absolute_path(android::base::GetExecutablePath());
+        status.set_log_absolute_path(GetLogFilePath());
+        status.set_os(GetOSVersion());
+
+        std::string server_status_string;
+        status.SerializeToString(&server_status_string);
+        SendOkay(reply_fd, server_status_string);
+        return HostRequestResult::Handled;
+    }
+
     // return a list of all connected devices
     if (service == "devices" || service == "devices-l") {
         TrackerOutputType output_type;
@@ -1371,7 +1402,7 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
     if (service == "host-features") {
         FeatureSet features = supported_features();
         // Abuse features to report libusb status.
-        if (should_use_libusb()) {
+        if (is_libusb_enabled()) {
             features.emplace_back(kFeatureLibusb);
         }
         features.emplace_back(kFeaturePushSync);
diff --git a/adb.h b/adb.h
index da546f68..3a00559c 100644
--- a/adb.h
+++ b/adb.h
@@ -32,7 +32,6 @@
 
 constexpr size_t MAX_PAYLOAD_V1 = 4 * 1024;
 constexpr size_t MAX_PAYLOAD = 1024 * 1024;
-constexpr size_t MAX_FRAMEWORK_PAYLOAD = 64 * 1024;
 
 // When delayed acks are supported, the initial number of unacknowledged bytes we're willing to
 // receive on a socket before the other side should block.
@@ -180,7 +179,7 @@ bool handle_forward_request(const char* service,
                             int reply_fd);
 
 /* packet allocator */
-apacket* get_apacket(void);
+apacket* get_apacket();
 void put_apacket(apacket* p);
 
 // Define it if you want to dump packets.
diff --git a/adb_auth.h b/adb_auth.h
index 1a1ab111..38312211 100644
--- a/adb_auth.h
+++ b/adb_auth.h
@@ -51,7 +51,7 @@ void adb_auth_tls_handshake(atransport* t);
 extern bool auth_required;
 extern bool socket_access_allowed;
 
-void adbd_auth_init(void);
+void adbd_auth_init();
 void adbd_auth_verified(atransport *t);
 
 void adbd_cloexec_auth_socket();
diff --git a/adb_integration_test_device.xml b/adb_integration_test_device.xml
index b8923773..74781336 100644
--- a/adb_integration_test_device.xml
+++ b/adb_integration_test_device.xml
@@ -15,7 +15,7 @@
 -->
 <configuration description="Config to run adb integration tests for device">
     <option name="test-suite-tag" value="adb_tests" />
-    <option name="test-suite-tag" value="adb_integration_device" />
+    <option name="test-suite-tag" value="adb_integration" />
     <target_preparer class="com.android.tradefed.targetprep.SemaphoreTokenTargetPreparer">
         <option name="disable" value="false" />
     </target_preparer>
diff --git a/adb_listeners.h b/adb_listeners.h
index 7fd46f02..ceaef119 100644
--- a/adb_listeners.h
+++ b/adb_listeners.h
@@ -43,7 +43,7 @@ InstallStatus install_listener(const std::string& local_name, const char* connec
 std::string format_listeners();
 
 InstallStatus remove_listener(const char* local_name, atransport* transport);
-void remove_all_listeners(void);
+void remove_all_listeners();
 
 #if ADB_HOST
 void enable_server_sockets();
diff --git a/adb_mdns.cpp b/adb_mdns.cpp
index 73230ea6..bd5ff5d6 100644
--- a/adb_mdns.cpp
+++ b/adb_mdns.cpp
@@ -123,7 +123,7 @@ bool adb_DNSServiceShouldAutoConnect(std::string_view reg_type, std::string_view
         (index != kADBTransportServiceRefIndex && index != kADBSecureConnectServiceRefIndex)) {
         return false;
     }
-    if (g_autoconn_allowedlist.find(*index) == g_autoconn_allowedlist.end()) {
+    if (!g_autoconn_allowedlist.contains(*index)) {
         D("Auto-connect for reg_type '%s' disabled", reg_type.data());
         return false;
     }
diff --git a/adb_mdns.h b/adb_mdns.h
index a015f534..14fdc536 100644
--- a/adb_mdns.h
+++ b/adb_mdns.h
@@ -65,7 +65,7 @@ std::optional<int> adb_DNSServiceIndexByName(std::string_view reg_type);
 // See ADB_MDNS_AUTO_CONNECT environment variable for more info.
 bool adb_DNSServiceShouldAutoConnect(std::string_view service_name, std::string_view instance_name);
 
-void mdns_cleanup(void);
+void mdns_cleanup();
 std::string mdns_check();
 std::string mdns_list_discovered_services();
 
@@ -84,11 +84,11 @@ std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name);
 
 // TODO: Remove once openscreen has support for bonjour client APIs.
 struct AdbMdnsResponderFuncs {
-    std::string (*_Nonnull mdns_check)(void);
-    std::string (*_Nonnull mdns_list_discovered_services)(void);
+    std::string (*_Nonnull mdns_check)();
+    std::string (*_Nonnull mdns_list_discovered_services)();
     std::optional<MdnsInfo> (*_Nonnull mdns_get_connect_service_info)(const std::string&);
     std::optional<MdnsInfo> (*_Nonnull mdns_get_pairing_service_info)(const std::string&);
-    void (*_Nonnull mdns_cleanup)(void);
+    void (*_Nonnull mdns_cleanup)();
     bool (*_Nonnull adb_secure_connect_by_service_name)(const std::string&);
 };  // AdbBonjourCallbacks
 
diff --git a/adb_trace.cpp b/adb_trace.cpp
index b9da7a40..cb83b832 100644
--- a/adb_trace.cpp
+++ b/adb_trace.cpp
@@ -73,7 +73,7 @@ static std::string get_log_file_name() {
                                        getpid());
 }
 
-void start_device_log(void) {
+void start_device_log() {
     int fd = unix_open(get_log_file_name(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
     if (fd == -1) {
         return;
@@ -113,22 +113,33 @@ static void setup_trace_mask() {
         return;
     }
 
-    std::unordered_map<std::string, int> trace_flags = {{"1", -1},
-                                                        {"all", -1},
-                                                        {"adb", ADB},
-                                                        {"sockets", SOCKETS},
-                                                        {"packets", PACKETS},
-                                                        {"rwx", RWX},
-                                                        {"usb", USB},
-                                                        {"sync", SYNC},
-                                                        {"sysdeps", SYSDEPS},
-                                                        {"transport", TRANSPORT},
-                                                        {"jdwp", JDWP},
-                                                        {"services", SERVICES},
-                                                        {"auth", AUTH},
-                                                        {"fdevent", FDEVENT},
-                                                        {"shell", SHELL},
-                                                        {"incremental", INCREMENTAL}};
+    std::unordered_map<std::string, int> trace_flags = {
+            {"1", -1},
+            {"all", -1},
+            {"adb", ADB},
+            {"sockets", SOCKETS},
+            {"packets", PACKETS},
+            {"rwx", RWX},
+            {"usb", USB},
+            {"sync", SYNC},
+            {"sysdeps", SYSDEPS},
+            {"transport", TRANSPORT},
+            {"jdwp", JDWP},
+            {"services", SERVICES},
+            {"auth", AUTH},
+            {"fdevent", FDEVENT},
+            {"shell", SHELL},
+            {"incremental", INCREMENTAL},
+            {"mdns", MDNS},
+    };
+
+    // Make sure we check for ALL enum in AdbTrace.
+    size_t num_flags = trace_flags.size() - 2;
+    size_t num_traces = AdbTrace::NUM_TRACES;
+    if (num_flags != num_traces) {
+        LOG(FATAL) << "Mismatched #AdbTrace=" << num_traces
+                   << " and trace_flags.size=" << num_flags;
+    }
 
     std::vector<std::string> elements = android::base::Split(trace_setting, ", ");
     for (const auto& elem : elements) {
diff --git a/adb_trace.h b/adb_trace.h
index 3421a029..d5a10d99 100644
--- a/adb_trace.h
+++ b/adb_trace.h
@@ -22,7 +22,7 @@
 
 /* IMPORTANT: if you change the following list, don't
  * forget to update the corresponding 'tags' table in
- * the adb_trace_init() function implemented in adb_trace.cpp.
+ * the setup_trace_mask() function implemented in adb_trace.cpp.
  */
 enum AdbTrace {
     ADB = 0, /* 0x001 */
@@ -39,6 +39,8 @@ enum AdbTrace {
     FDEVENT,
     SHELL,
     INCREMENTAL,
+    MDNS,
+    NUM_TRACES,
 };
 
 #define VLOG_IS_ON(TAG) \
diff --git a/adb_utils.cpp b/adb_utils.cpp
index d1910f1c..7f65ed88 100644
--- a/adb_utils.cpp
+++ b/adb_utils.cpp
@@ -348,33 +348,3 @@ std::string GetLogFilePath() {
     return android::base::StringPrintf("%s/adb.%u.log", tmp_dir, getuid());
 #endif
 }
-
-[[noreturn]] static void error_exit_va(int error, const char* fmt, va_list va) {
-    fflush(stdout);
-    fprintf(stderr, "%s: ", android::base::Basename(android::base::GetExecutablePath()).c_str());
-
-    vfprintf(stderr, fmt, va);
-
-    if (error != 0) {
-        fprintf(stderr, ": %s", strerror(error));
-    }
-
-    putc('\n', stderr);
-    fflush(stderr);
-
-    exit(EXIT_FAILURE);
-}
-
-void error_exit(const char* fmt, ...) {
-    va_list va;
-    va_start(va, fmt);
-    error_exit_va(0, fmt, va);
-    va_end(va);
-}
-
-void perror_exit(const char* fmt, ...) {
-    va_list va;
-    va_start(va, fmt);
-    error_exit_va(errno, fmt, va);
-    va_end(va);
-}
diff --git a/adb_utils.h b/adb_utils.h
index e72d8b6f..7d8ba01c 100644
--- a/adb_utils.h
+++ b/adb_utils.h
@@ -50,9 +50,6 @@ std::string dump_packet(const char* name, const char* func, const apacket* p);
 
 std::string perror_str(const char* msg);
 
-[[noreturn]] void error_exit(const char* fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
-[[noreturn]] void perror_exit(const char* fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
-
 bool set_file_block_mode(borrowed_fd fd, bool block);
 
 // Given forward/reverse targets, returns true if they look valid. If an error is found, fills
diff --git a/benchmark_device.py b/benchmark_device.py
index 4a543480..4927998f 100755
--- a/benchmark_device.py
+++ b/benchmark_device.py
@@ -22,6 +22,9 @@ import sys
 import tempfile
 import time
 
+transfer_size_mib = 100
+num_runs = 10
+
 # Make sure environment is setup, otherwise "adb" module is not available.
 if os.getenv("ANDROID_BUILD_TOP") is None:
     print("Run source/lunch before running " + sys.argv[0])
@@ -64,7 +67,7 @@ def analyze(name, speeds):
     msg = "%s: %d runs: median %.2f MiB/s, mean %.2f MiB/s, stddev: %.2f MiB/s"
     print(msg % (name, len(speeds), median, mean, stddev))
 
-def benchmark_sink(device=None, size_mb=100):
+def benchmark_sink(device=None, size_mb=transfer_size_mib):
     if device == None:
         device = adb.get_device()
 
@@ -74,16 +77,16 @@ def benchmark_sink(device=None, size_mb=100):
     with tempfile.TemporaryFile() as tmpfile:
         tmpfile.truncate(size_mb * 1024 * 1024)
 
-        for _ in range(0, 10):
+        for _ in range(0, num_runs):
             tmpfile.seek(0)
             begin = time.time()
             subprocess.check_call(cmd, stdin=tmpfile)
             end = time.time()
             speeds.append(size_mb / float(end - begin))
 
-    analyze("sink %dMiB" % size_mb, speeds)
+    analyze("sink   %dMiB (write RAM)  " % size_mb, speeds)
 
-def benchmark_source(device=None, size_mb=100):
+def benchmark_source(device=None, size_mb=transfer_size_mib):
     if device == None:
         device = adb.get_device()
 
@@ -91,72 +94,75 @@ def benchmark_source(device=None, size_mb=100):
     cmd = device.adb_cmd + ["raw", "source:%d" % (size_mb * 1024 * 1024)]
 
     with open(os.devnull, 'w') as devnull:
-        for _ in range(0, 10):
+        for _ in range(0, num_runs):
             begin = time.time()
             subprocess.check_call(cmd, stdout=devnull)
             end = time.time()
             speeds.append(size_mb / float(end - begin))
 
-    analyze("source %dMiB" % size_mb, speeds)
+    analyze("source %dMiB (read RAM)   " % size_mb, speeds)
 
-def benchmark_push(device=None, file_size_mb=100):
+def benchmark_push(device=None, file_size_mb=transfer_size_mib):
     if device == None:
         device = adb.get_device()
 
-    remote_path = "/dev/null"
+    remote_path = "/data/local/tmp/adb_benchmark_push_tmp"
     local_path = "/tmp/adb_benchmark_temp"
 
     with open(local_path, "wb") as f:
         f.truncate(file_size_mb * 1024 * 1024)
 
     speeds = list()
-    for _ in range(0, 10):
+    for _ in range(0, num_runs):
         begin = time.time()
-        device.push(local=local_path, remote=remote_path)
+        parameters = ['-Z'] # Disable compression since our file is full of 0s
+        device.push(local=local_path, remote=remote_path, parameters=parameters)
         end = time.time()
         speeds.append(file_size_mb / float(end - begin))
 
-    analyze("push %dMiB" % file_size_mb, speeds)
+    analyze("push   %dMiB (write flash)" % file_size_mb, speeds)
 
-def benchmark_pull(device=None, file_size_mb=100):
+def benchmark_pull(device=None, file_size_mb=transfer_size_mib):
     if device == None:
         device = adb.get_device()
 
-    remote_path = "/data/local/tmp/adb_benchmark_temp"
+    remote_path = "/data/local/tmp/adb_benchmark_pull_temp"
     local_path = "/tmp/adb_benchmark_temp"
 
     device.shell(["dd", "if=/dev/zero", "of=" + remote_path, "bs=1m",
                   "count=" + str(file_size_mb)])
     speeds = list()
-    for _ in range(0, 10):
+    for _ in range(0, num_runs):
         begin = time.time()
         device.pull(remote=remote_path, local=local_path)
         end = time.time()
         speeds.append(file_size_mb / float(end - begin))
 
-    analyze("pull %dMiB" % file_size_mb, speeds)
+    analyze("pull   %dMiB (read flash) " % file_size_mb, speeds)
 
-def benchmark_shell(device=None, file_size_mb=100):
+def benchmark_device_dd(device=None, file_size_mb=transfer_size_mib):
     if device == None:
         device = adb.get_device()
 
     speeds = list()
-    for _ in range(0, 10):
+    for _ in range(0, num_runs):
         begin = time.time()
         device.shell(["dd", "if=/dev/zero", "bs=1m",
                       "count=" + str(file_size_mb)])
         end = time.time()
         speeds.append(file_size_mb / float(end - begin))
 
-    analyze("shell %dMiB" % file_size_mb, speeds)
+    analyze("dd     %dMiB (write flash)" % file_size_mb, speeds)
 
 def main():
     device = adb.get_device()
     unlock(device)
+
     benchmark_sink(device)
     benchmark_source(device)
     benchmark_push(device)
     benchmark_pull(device)
+    benchmark_device_dd(device)
 
 if __name__ == "__main__":
     main()
diff --git a/client/adb_client.cpp b/client/adb_client.cpp
index 13389ee9..6b201516 100644
--- a/client/adb_client.cpp
+++ b/client/adb_client.cpp
@@ -431,7 +431,7 @@ std::string format_host_command(const char* command) {
 
 const std::optional<FeatureSet>& adb_get_feature_set(std::string* error) {
     static std::mutex feature_mutex [[clang::no_destroy]];
-    static std::optional<FeatureSet> features [[clang::no_destroy]] GUARDED_BY(feature_mutex);
+    static std::optional<FeatureSet> features [[clang::no_destroy]];
     std::lock_guard<std::mutex> lock(feature_mutex);
     if (!features) {
         std::string result;
@@ -446,3 +446,33 @@ const std::optional<FeatureSet>& adb_get_feature_set(std::string* error) {
     }
     return features;
 }
+
+[[noreturn]] static void error_exit_va(int error, const char* fmt, va_list va) {
+    fflush(stdout);
+    fprintf(stderr, "%s: ", android::base::Basename(android::base::GetExecutablePath()).c_str());
+
+    vfprintf(stderr, fmt, va);
+
+    if (error != 0) {
+        fprintf(stderr, ": %s", strerror(error));
+    }
+
+    putc('\n', stderr);
+    fflush(stderr);
+
+    exit(EXIT_FAILURE);
+}
+
+void error_exit(const char* fmt, ...) {
+    va_list va;
+    va_start(va, fmt);
+    error_exit_va(0, fmt, va);
+    va_end(va);
+}
+
+void perror_exit(const char* fmt, ...) {
+    va_list va;
+    va_start(va, fmt);
+    error_exit_va(errno, fmt, va);
+    va_end(va);
+}
diff --git a/client/adb_client.h b/client/adb_client.h
index 8262d18c..e095506d 100644
--- a/client/adb_client.h
+++ b/client/adb_client.h
@@ -88,6 +88,9 @@ const std::optional<FeatureSet>& adb_get_feature_set(std::string* _Nullable erro
 std::optional<std::string> adb_get_server_executable_path();
 #endif
 
+[[noreturn]] void error_exit(const char* _Nonnull fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
+[[noreturn]] void perror_exit(const char* _Nonnull fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
+
 // Globally acccesible argv/envp, for the purpose of re-execing adb.
 extern const char* _Nullable * _Nullable __adb_argv;
 extern const char* _Nullable * _Nullable __adb_envp;
diff --git a/client/adb_install.cpp b/client/adb_install.cpp
index 5a1e1b09..abfcd4ef 100644
--- a/client/adb_install.cpp
+++ b/client/adb_install.cpp
@@ -391,7 +391,7 @@ static std::pair<InstallMode, std::optional<InstallMode>> calculate_install_mode
         // still ok: let's see if the device allows using incremental by default
         // it starts feeling like we're looking for an excuse to not to use incremental...
         std::string error;
-        std::vector<std::string> args = {"settings", "get",
+        std::vector<std::string> args = {"settings", "get", "global",
                                          "enable_adb_incremental_install_default"};
         auto fd = send_abb_exec_command(args, &error);
         if (!fd.ok()) {
diff --git a/client/auth.cpp b/client/auth.cpp
index f90c334b..f87ee85a 100644
--- a/client/auth.cpp
+++ b/client/auth.cpp
@@ -145,7 +145,7 @@ static bool load_key(const std::string& file) {
 
     std::lock_guard<std::mutex> lock(g_keys_mutex);
     std::string fingerprint = hash_key(key.get());
-    bool already_loaded = (g_keys.find(fingerprint) != g_keys.end());
+    bool already_loaded = g_keys.contains(fingerprint);
     if (!already_loaded) {
         g_keys[fingerprint] = std::move(key);
     }
diff --git a/client/bugreport.cpp b/client/bugreport.cpp
index 626dfbb2..23ecb552 100644
--- a/client/bugreport.cpp
+++ b/client/bugreport.cpp
@@ -26,6 +26,7 @@
 #include <android-base/file.h>
 #include <android-base/strings.h>
 
+#include "adb_client.h"
 #include "adb_utils.h"
 #include "client/file_sync_client.h"
 
diff --git a/client/commandline.cpp b/client/commandline.cpp
index b203cd6f..6620836f 100644
--- a/client/commandline.cpp
+++ b/client/commandline.cpp
@@ -56,6 +56,7 @@
 #include "adb.h"
 #include "adb_auth.h"
 #include "adb_client.h"
+#include "adb_host.pb.h"
 #include "adb_install.h"
 #include "adb_io.h"
 #include "adb_unique_fd.h"
@@ -1371,6 +1372,37 @@ static int adb_connect_command(const std::string& command, TransportId* transpor
     return adb_connect_command(command, transport, &DEFAULT_STANDARD_STREAMS_CALLBACK);
 }
 
+// A class to convert server status binary protobuf to text protobuf.
+class AdbServerStateStreamsCallback : public DefaultStandardStreamsCallback {
+  public:
+    AdbServerStateStreamsCallback() : DefaultStandardStreamsCallback(nullptr, nullptr) {}
+
+    bool OnStdout(const char* buffer, size_t length) override {
+        return OnStream(&output_, nullptr, buffer, length, false);
+    }
+
+    int Done(int status) {
+        if (output_.size() < 4) {
+            return OnStream(nullptr, stdout, output_.data(), output_.length(), false);
+        }
+
+        // Skip the 4-hex prefix
+        std::string binary_proto_bytes{output_.substr(4)};
+
+        ::adb::proto::AdbServerStatus binary_proto;
+        binary_proto.ParseFromString(binary_proto_bytes);
+
+        std::string string_proto;
+        google::protobuf::TextFormat::PrintToString(binary_proto, &string_proto);
+
+        return OnStream(nullptr, stdout, string_proto.data(), string_proto.length(), false);
+    }
+
+  private:
+    std::string output_;
+    DISALLOW_COPY_AND_ASSIGN(AdbServerStateStreamsCallback);
+};
+
 // A class that prints out human readable form of the protobuf message for "track-app" service
 // (received in binary format).
 class TrackAppStreamsCallback : public DefaultStandardStreamsCallback {
@@ -2195,6 +2227,9 @@ int adb_commandline(int argc, const char** argv) {
         }
         printf("%s\n", result.c_str());
         return 0;
+    } else if (!strcmp(argv[0], "server-status")) {
+        AdbServerStateStreamsCallback callback;
+        return adb_connect_command("host:server-status", nullptr, &callback);
     }
 
     error_exit("unknown command %s", argv[0]);
diff --git a/client/commandline.h b/client/commandline.h
index a0bba06f..96eeb836 100644
--- a/client/commandline.h
+++ b/client/commandline.h
@@ -118,7 +118,7 @@ extern DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK;
 int adb_commandline(int argc, const char** argv);
 
 // Helper retrieval function.
-const std::optional<FeatureSet>& adb_get_feature_set_or_die(void);
+const std::optional<FeatureSet>& adb_get_feature_set_or_die();
 
 bool copy_to_file(int inFd, int outFd);
 
diff --git a/client/fastdeploy.cpp b/client/fastdeploy.cpp
index 0fb4f133..ee042a17 100644
--- a/client/fastdeploy.cpp
+++ b/client/fastdeploy.cpp
@@ -35,6 +35,7 @@
 #include "fastdeploycallbacks.h"
 #include "sysdeps.h"
 
+#include "adb_client.h"
 #include "adb_utils.h"
 
 static constexpr long kRequiredAgentVersion = 0x00000003;
diff --git a/client/file_sync_client.cpp b/client/file_sync_client.cpp
index 410f4128..11dde9c5 100644
--- a/client/file_sync_client.cpp
+++ b/client/file_sync_client.cpp
@@ -836,7 +836,7 @@ class SyncConnection {
                     const ssize_t bytes_left = amount - buf.size();
                     ssize_t rc = adb_read(fd, buf.end(), bytes_left);
                     if (rc <= 0) {
-                        Error("failed to read copy response");
+                        Error("failed to read copy response: %s", rc < 0 ? strerror(errno) : "EOF");
                         return ReadStatus::Failure;
                     }
                     buf.resize(buf.size() + rc);
diff --git a/client/incremental_server.cpp b/client/incremental_server.cpp
index 0654a11b..156cc47b 100644
--- a/client/incremental_server.cpp
+++ b/client/incremental_server.cpp
@@ -1,4 +1,4 @@
-﻿/*
+/*
  * Copyright (C) 2020 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
@@ -35,6 +35,7 @@
 #include <unordered_set>
 
 #include "adb.h"
+#include "adb_client.h"
 #include "adb_io.h"
 #include "adb_trace.h"
 #include "adb_unique_fd.h"
diff --git a/client/main.cpp b/client/main.cpp
index 818d305a..15308287 100644
--- a/client/main.cpp
+++ b/client/main.cpp
@@ -137,7 +137,7 @@ int adb_server_main(int is_daemon, const std::string& socket_spec, const char* o
     }
 
     if (!getenv("ADB_USB") || strcmp(getenv("ADB_USB"), "0") != 0) {
-        if (should_use_libusb()) {
+        if (is_libusb_enabled()) {
             libusb::usb_init();
         } else {
             usb_init();
diff --git a/client/mdnsresponder_client.cpp b/client/mdnsresponder_client.cpp
index 9e238954..3b262504 100644
--- a/client/mdnsresponder_client.cpp
+++ b/client/mdnsresponder_client.cpp
@@ -539,7 +539,7 @@ void DNSSD_API on_service_browsed(DNSServiceRef sdref, DNSServiceFlags flags,
     }
 }
 
-void init_mdns_transport_discovery_thread(void) {
+void init_mdns_transport_discovery_thread() {
     int error_codes[kNumADBDNSServices];
     for (int i = 0; i < kNumADBDNSServices; ++i) {
         error_codes[i] = DNSServiceBrowse(&g_service_refs[i], 0, 0, kADBDNSServices[i], nullptr,
diff --git a/client/openscreen/platform/logging.cpp b/client/openscreen/platform/logging.cpp
index 9611e495..90e99f71 100644
--- a/client/openscreen/platform/logging.cpp
+++ b/client/openscreen/platform/logging.cpp
@@ -24,24 +24,26 @@ bool IsLoggingOn(LogLevel level, const char* file) {
     return true;
 }
 
-void LogWithLevel(LogLevel level, const char* file, int line, std::stringstream message) {
+void LogWithLevel(LogLevel level, const char* file, int line, std::stringstream desc) {
+    android::base::LogSeverity severity;
     switch (level) {
         case LogLevel::kInfo:
-            LOG(INFO) << message.str();
+            severity = android::base::LogSeverity::INFO;
             break;
         case LogLevel::kWarning:
-            LOG(WARNING) << message.str();
+            severity = android::base::LogSeverity::WARNING;
             break;
         case LogLevel::kError:
-            LOG(ERROR) << message.str();
+            severity = android::base::LogSeverity::ERROR;
             break;
         case LogLevel::kFatal:
-            LOG(FATAL) << message.str();
+            severity = android::base::LogSeverity::FATAL;
             break;
         default:
-            LOG(VERBOSE) << message.str();
+            severity = android::base::LogSeverity::DEBUG;
             break;
     }
+    LOG(severity) << std::string("(") + file + ":" + std::to_string(line) + ") " + desc.str();
 }
 
 [[noreturn]] void Break() {
diff --git a/client/openscreen/platform/udp_socket.cpp b/client/openscreen/platform/udp_socket.cpp
index 9b9e4998..d85661c2 100644
--- a/client/openscreen/platform/udp_socket.cpp
+++ b/client/openscreen/platform/udp_socket.cpp
@@ -399,7 +399,7 @@ class AdbUdpSocket : public UdpSocket {
             return;
         }
 
-        LOG(INFO) << "SendMessage ip=" << dest.ToString();
+        VLOG(MDNS) << "SendMessage ip=" << dest.ToString() << ", size=" << length;
         adb_iovec iov;
         iov.iov_len = length;
         iov.iov_base = const_cast<void*>(data);
@@ -578,6 +578,7 @@ class AdbUdpSocket : public UdpSocket {
             client_->OnRead(this, ChooseError(errno, Error::Code::kSocketReadFailure));
             return;
         }
+        VLOG(MDNS) << "mDNS received bytes=" << *bytes_available;
 
         UdpPacket packet(*bytes_available);
         packet.set_socket(this);
@@ -666,7 +667,7 @@ ErrorOr<std::unique_ptr<UdpSocket>> UdpSocket::Create(TaskRunner* task_runner,
         return Error::Code::kInitializationFailure;
     }
 
-    LOG(INFO) << "UDP socket created for " << local_endpoint;
+    VLOG(MDNS) << "UDP socket created for " << local_endpoint;
     std::unique_ptr<UdpSocket> udp_socket(new AdbUdpSocket(client, local_endpoint, std::move(fd)));
     return udp_socket;
 }
diff --git a/client/transport_mdns.cpp b/client/transport_mdns.cpp
index 1b969b56..d4118e51 100644
--- a/client/transport_mdns.cpp
+++ b/client/transport_mdns.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define TRACE_TAG TRANSPORT
+#define TRACE_TAG MDNS
 
 #include "transport.h"
 
@@ -84,6 +84,7 @@ class DiscoveryReportingClient : public discovery::ReportingClient {
 };
 
 struct DiscoveryState {
+    std::optional<discovery::Config> config;
     SerialDeletePtr<discovery::DnsSdService> service;
     std::unique_ptr<DiscoveryReportingClient> reporting_client;
     std::unique_ptr<AdbOspTaskRunner> task_runner;
@@ -95,10 +96,10 @@ struct DiscoveryState {
 void OnServiceReceiverResult(std::vector<std::reference_wrapper<const ServiceInfo>> infos,
                              std::reference_wrapper<const ServiceInfo> info,
                              ServicesUpdatedState state) {
-    LOG(INFO) << "Endpoint state=" << static_cast<int>(state)
-              << " instance_name=" << info.get().instance_name
-              << " service_name=" << info.get().service_name << " addr=" << info.get().v4_address
-              << " addrv6=" << info.get().v6_address << " total_serv=" << infos.size();
+    VLOG(MDNS) << "Endpoint state=" << static_cast<int>(state)
+               << " instance_name=" << info.get().instance_name
+               << " service_name=" << info.get().service_name << " addr=" << info.get().v4_address
+               << " addrv6=" << info.get().v6_address << " total_serv=" << infos.size();
 
     switch (state) {
         case ServicesUpdatedState::EndpointCreated:
@@ -114,13 +115,14 @@ void OnServiceReceiverResult(std::vector<std::reference_wrapper<const ServiceInf
                 // Don't try to auto-connect if not in the keystore.
                 if (*index == kADBSecureConnectServiceRefIndex &&
                     !adb_wifi_is_known_host(info.get().instance_name)) {
-                    LOG(INFO) << "instance_name=" << info.get().instance_name << " not in keystore";
+                    VLOG(MDNS) << "instance_name=" << info.get().instance_name
+                               << " not in keystore";
                     return;
                 }
                 std::string response;
-                LOG(INFO) << "Attempting to auto-connect to instance=" << info.get().instance_name
-                          << " service=" << info.get().service_name << " addr4=%s"
-                          << info.get().v4_address << ":" << info.get().port;
+                VLOG(MDNS) << "Attempting to auto-connect to instance=" << info.get().instance_name
+                           << " service=" << info.get().service_name << " addr4=%s"
+                           << info.get().v4_address << ":" << info.get().port;
                 connect_device(
                         android::base::StringPrintf("%s.%s", info.get().instance_name.c_str(),
                                                     info.get().service_name.c_str()),
@@ -136,15 +138,21 @@ std::optional<discovery::Config> GetConfigForAllInterfaces() {
     auto interface_infos = GetNetworkInterfaces();
 
     discovery::Config config;
+
+    // The host only consumes mDNS traffic. It doesn't publish anything.
+    // Avoid creating an mDNSResponder that will listen with authority
+    // to answer over no domain.
+    config.enable_publication = false;
+
     for (const auto interface : interface_infos) {
         if (interface.GetIpAddressV4() || interface.GetIpAddressV6()) {
             config.network_info.push_back({interface});
-            LOG(VERBOSE) << "Listening on interface [" << interface << "]";
+            VLOG(MDNS) << "Listening on interface [" << interface << "]";
         }
     }
 
     if (config.network_info.empty()) {
-        LOG(INFO) << "No available network interfaces for mDNS discovery";
+        VLOG(MDNS) << "No available network interfaces for mDNS discovery";
         return std::nullopt;
     }
 
@@ -158,13 +166,17 @@ void StartDiscovery() {
     g_state->reporting_client = std::make_unique<DiscoveryReportingClient>();
 
     g_state->task_runner->PostTask([]() {
-        auto config = GetConfigForAllInterfaces();
-        if (!config) {
+        g_state->config = GetConfigForAllInterfaces();
+        if (!g_state->config) {
+            VLOG(MDNS) << "No mDNS config. Aborting StartDiscovery()";
             return;
         }
 
-        g_state->service = discovery::CreateDnsSdService(g_state->task_runner.get(),
-                                                         g_state->reporting_client.get(), *config);
+        VLOG(MDNS) << "Starting discovery on " << (*g_state->config).network_info.size()
+                   << " interfaces";
+
+        g_state->service = discovery::CreateDnsSdService(
+                g_state->task_runner.get(), g_state->reporting_client.get(), *g_state->config);
         // Register a receiver for each service type
         for (int i = 0; i < kNumADBDNSServices; ++i) {
             auto receiver = std::make_unique<ServiceReceiver>(
@@ -184,7 +196,7 @@ void StartDiscovery() {
         }
 
         if (g_using_bonjour) {
-            LOG(INFO) << "Fallback to MdnsResponder client for discovery";
+            VLOG(MDNS) << "Fallback to MdnsResponder client for discovery";
             g_adb_mdnsresponder_funcs = StartMdnsResponderDiscovery();
         }
     });
@@ -208,7 +220,7 @@ void ForEachService(const std::unique_ptr<ServiceReceiver>& receiver,
 
 bool ConnectAdbSecureDevice(const MdnsInfo& info) {
     if (!adb_wifi_is_known_host(info.service_name)) {
-        LOG(INFO) << "serviceName=" << info.service_name << " not in keystore";
+        VLOG(MDNS) << "serviceName=" << info.service_name << " not in keystore";
         return false;
     }
 
@@ -224,22 +236,25 @@ bool ConnectAdbSecureDevice(const MdnsInfo& info) {
 }  // namespace
 
 /////////////////////////////////////////////////////////////////////////////////
+
+bool using_bonjour(void) {
+    return g_using_bonjour;
+}
+
 void mdns_cleanup() {
     if (g_using_bonjour) {
         return g_adb_mdnsresponder_funcs.mdns_cleanup();
     }
 }
 
-void init_mdns_transport_discovery(void) {
-    // TODO(joshuaduong): Use openscreen discovery by default for all platforms.
+void init_mdns_transport_discovery() {
     const char* mdns_osp = getenv("ADB_MDNS_OPENSCREEN");
-    if (mdns_osp && strcmp(mdns_osp, "1") == 0) {
-        LOG(INFO) << "Openscreen mdns discovery enabled";
-        StartDiscovery();
-    } else {
-        // Original behavior is to use Bonjour client.
+    if (mdns_osp && strcmp(mdns_osp, "0") == 0) {
         g_using_bonjour = true;
         g_adb_mdnsresponder_funcs = StartMdnsResponderDiscovery();
+    } else {
+        VLOG(MDNS) << "Openscreen mdns discovery enabled";
+        StartDiscovery();
     }
 }
 
@@ -249,7 +264,7 @@ bool adb_secure_connect_by_service_name(const std::string& instance_name) {
     }
 
     if (!g_state || g_state->receivers.empty()) {
-        LOG(INFO) << "Mdns not enabled";
+        VLOG(MDNS) << "Mdns not enabled";
         return false;
     }
 
diff --git a/client/transport_usb.cpp b/client/transport_usb.cpp
index 998f73c9..58d50252 100644
--- a/client/transport_usb.cpp
+++ b/client/transport_usb.cpp
@@ -177,7 +177,7 @@ bool is_adb_interface(int usb_class, int usb_subclass, int usb_protocol) {
         return false;
 }
 
-bool should_use_libusb() {
+bool is_libusb_enabled() {
     bool enable = true;
 #if defined(_WIN32)
     enable = false;
diff --git a/client/usb.h b/client/usb.h
index 0ccc0576..b12e7c6b 100644
--- a/client/usb.h
+++ b/client/usb.h
@@ -37,7 +37,7 @@ size_t usb_get_max_packet_size(usb_handle*);
 // USB device detection.
 bool is_adb_interface(int usb_class, int usb_subclass, int usb_protocol);
 
-bool should_use_libusb();
+bool is_libusb_enabled();
 
 namespace libusb {
 void usb_init();
diff --git a/client/usb_linux.cpp b/client/usb_linux.cpp
index 59c23ea7..96d7a8a3 100644
--- a/client/usb_linux.cpp
+++ b/client/usb_linux.cpp
@@ -642,4 +642,9 @@ void usb_init() {
     std::thread(device_poll_thread).detach();
 }
 
-void usb_cleanup() {}
+void usb_cleanup() {
+    if (is_libusb_enabled()) {
+        VLOG(USB) << "Linux libusb cleanup";
+        close_usb_devices();
+    }
+}
diff --git a/client/usb_osx.cpp b/client/usb_osx.cpp
index 358056c1..ce3f5df9 100644
--- a/client/usb_osx.cpp
+++ b/client/usb_osx.cpp
@@ -492,7 +492,7 @@ static void RunLoopThread() {
 }
 
 void usb_cleanup() NO_THREAD_SAFETY_ANALYSIS {
-    VLOG(USB) << "usb_cleanup";
+    VLOG(USB) << "Macos usb_cleanup";
     // Wait until usb operations in RunLoopThread finish, and prevent further operations.
     operate_device_lock.lock();
     close_usb_devices();
diff --git a/client/usb_windows.cpp b/client/usb_windows.cpp
index 65819289..b17c4806 100644
--- a/client/usb_windows.cpp
+++ b/client/usb_windows.cpp
@@ -253,7 +253,14 @@ void usb_init() {
     std::thread(_power_notification_thread).detach();
 }
 
-void usb_cleanup() {}
+void usb_cleanup() {
+    // On Windows, shutting down the server without releasing USB interfaces makes claiming
+    // them again unstable upon next startup.
+    if (is_libusb_enabled()) {
+        VLOG(USB) << "Windows libusb cleanup";
+        close_usb_devices();
+    }
+}
 
 usb_handle* do_usb_open(const wchar_t* interface_name) {
     unsigned long name_len = 0;
diff --git a/daemon/auth.cpp b/daemon/auth.cpp
index d2f6d6bb..b65f4745 100644
--- a/daemon/auth.cpp
+++ b/daemon/auth.cpp
@@ -240,7 +240,7 @@ static void adbd_key_removed(const char* public_key, size_t len) {
     kick_all_transports_by_auth_key(auth_key);
 }
 
-void adbd_auth_init(void) {
+void adbd_auth_init() {
     AdbdAuthCallbacksV1 cb;
     cb.version = 1;
     cb.key_authorized = adbd_auth_key_authorized;
diff --git a/daemon/framebuffer_service.cpp b/daemon/framebuffer_service.cpp
index 676f8e9d..117cc0d3 100644
--- a/daemon/framebuffer_service.cpp
+++ b/daemon/framebuffer_service.cpp
@@ -78,7 +78,8 @@ void framebuffer_service(unique_fd fd) {
         const char* command = "screencap";
         const char *args[2] = {command, nullptr};
         execvp(command, (char**)args);
-        perror_exit("exec screencap failed");
+        perror("exec screencap failed");
+        _exit(127);
     }
 
     adb_close(fds[1]);
diff --git a/daemon/jdwp_service.cpp b/daemon/jdwp_service.cpp
index 3aeade05..6e0c89ef 100644
--- a/daemon/jdwp_service.cpp
+++ b/daemon/jdwp_service.cpp
@@ -139,8 +139,8 @@ enum class TrackerKind {
 };
 
 static void jdwp_process_event(int socket, unsigned events, void* _proc);
-static void jdwp_process_list_updated(void);
-static void app_process_list_updated(void);
+static void jdwp_process_list_updated();
+static void app_process_list_updated();
 
 struct JdwpProcess;
 static auto& _jdwp_list = *new std::list<std::unique_ptr<JdwpProcess>>();
@@ -218,7 +218,7 @@ static size_t app_process_list(char* buffer, size_t bufferlen) {
     for (auto& proc : _jdwp_list) {
         if (!proc->process.debuggable && !proc->process.profileable) continue;
         auto* entry = temp.add_process();
-        *entry = std::move(proc->process.toProtobuf());
+        *entry = proc->process.toProtobuf();
         temp.SerializeToString(&serialized_message);
         if (serialized_message.size() > bufferlen) {
             D("truncating app process list (max len = %zu)", bufferlen);
@@ -377,7 +377,7 @@ static void jdwp_socket_ready(asocket* s) {
     }
 }
 
-asocket* create_jdwp_service_socket(void) {
+asocket* create_jdwp_service_socket() {
     JdwpSocket* s = new JdwpSocket();
 
     if (!s) {
@@ -429,11 +429,11 @@ static void process_list_updated(TrackerKind kind) {
     }
 }
 
-static void jdwp_process_list_updated(void) {
+static void jdwp_process_list_updated() {
     process_list_updated(TrackerKind::kJdwp);
 }
 
-static void app_process_list_updated(void) {
+static void app_process_list_updated() {
     process_list_updated(TrackerKind::kApp);
 }
 
@@ -507,7 +507,7 @@ asocket* create_app_tracker_service_socket() {
     return create_process_tracker_service_socket(TrackerKind::kApp);
 }
 
-int init_jdwp(void) {
+int init_jdwp() {
     std::thread([]() {
         adb_thread_setname("jdwp control");
         adbconnection_listen([](int fd, ProcessInfo process) {
@@ -530,7 +530,7 @@ int init_jdwp(void) {
 #else  // !defined(__ANDROID_RECOVERY)
 #include "adb.h"
 
-asocket* create_jdwp_service_socket(void) {
+asocket* create_jdwp_service_socket() {
     return nullptr;
 }
 
diff --git a/daemon/jdwp_service.h b/daemon/jdwp_service.h
index 1daa0f9d..71a8e64b 100644
--- a/daemon/jdwp_service.h
+++ b/daemon/jdwp_service.h
@@ -17,7 +17,7 @@
 #include "adb_unique_fd.h"
 #include "socket.h"
 
-int init_jdwp(void);
+int init_jdwp();
 asocket* create_jdwp_service_socket();
 asocket* create_jdwp_tracker_service_socket();
 asocket* create_app_tracker_service_socket();
diff --git a/docs/dev/README.md b/docs/dev/README.md
new file mode 100644
index 00000000..eabe3fee
--- /dev/null
+++ b/docs/dev/README.md
@@ -0,0 +1,149 @@
+# ADB Internals
+
+If you are new to adb source code, you should start by reading [overview.md](overview.md) which describes the three components of adb pipeline.
+
+This document gives the "big picture" which should allow you to build a mental map to help navigate the code.
+
+## Three components of adb pipeline
+
+As described in the [overview](overview.md), this codebase generates three components (Client, Server (a.k.a Host), and Daemon (a.k.a adbd)).
+
+The central part is the Server which runs on the Host computer. On one side the Server exposes a connection to Clients such as adb or DDMLIB.
+
+On the other side, the Server continuously monitors for connecting Daemons (such as USB devices or TCP emulator). Communication with a device is done with a Transport.
+
+```
++----------+              +------------------------+
+|   ADB    +----------+   |      ADB SERVER        |                   +----------+
+|  CLIENT  |          |   |                        |              (USB)|   ADBD   |
++----------+          |   |                     Transport+-------------+ (DEVICE) |
+                      |   |                        |                   +----------+
++-----------          |   |                        |
+|   ADB    |          v   +                        |                   +----------+
+|  CLIENT  +--------->SmartSocket                  |              (USB)|   ADBD   |
++----------+          ^   | (TCP/IP)            Transport+-------------+ (DEVICE) |
+                      |   |                        |                   +----------+
++----------+          |   |                        |
+|  DDMLIB  |          |   |                     Transport+--+          +----------+
+|  CLIENT  +----------+   |                        |        |  (TCP/IP)|   ADBD   |
++----------+              +------------------------+        +----------|(EMULATOR)|
+                                                                       +----------+
+```
+
+The Client and the Server are contained in the same executable and both run on the Host machine. Code sections specific to the Host are enclosed within `ADB_HOST` guard. adbd runs on the Android Device. Daemon specific code is enclosed in `!ADB_HOST` but also sometimes within `__ANDROID__` guards.
+
+
+## "SMART SOCKET" and TRANSPORT
+
+A smart socket is a simple TCP socket with a smart protocol built on top of it which allows to target a device **after** the connection is initalized (see [services.md](services.md) families of `host:transport-` services for more information). This is what Clients connect onto from the Host side. The Client must always initiate communication via a human readable request but the response format varies. The smart protocol is documented in [services.md](services.md).
+
+On the other side, the Server communicates with a device via a Transport. adb initially targeted devices connecting over USB, which is restricted to a fixed number of data streams. Therefore, adb multiplexes multiple byte streams over a single pipe via Transport. When devices connecting over other mechanisms (e.g. emulators over TCP) were introduced, the existing transport protocol was maintained.
+
+## THREADING MODEL and FDEVENT system
+
+At the heart of both the Server and Daemon is a main thread running an fdevent loop, which is a platform-independent abstraction over poll/epoll/WSAPoll monitoring file descriptors events. Requests and services are usually served from the main thread but some service requests result in new threads being spawned.
+
+To allow for operations to run on the Main thread, fdevent features a RunQueue combined with an interrupt fd to force polling to return.
+
+```
++------------+    +-------------------------^
+|  RUNQUEUE  |    |                         |
++------------+    |  POLLING (Main thread)  |
+| Function<> |    |                         |
++------------+    |                         |
+| Function<> |    ^-^-------^-------^------^^
++------------+      |       |       |       |
+|    ...     |      |       |       |       |
++------------+      |       |       |       |
+|            |      |       |       |       |
+|============|      |       |       |       |
+|Interrupt fd+------+  +----+  +----+  +----+
++------------+         fd      Socket  Pipe
+```
+
+## ASOCKET, APACKET, and AMESSAGE
+
+The asocket, apacket, and amessage constructs exist only to wrap data while it transits on a Transport. An asocket handles a stream of apackets. An apacket consists of an amessage header featuring a command (`A_SYNC`, `A_OPEN`, `A_CLSE`, `A_WRTE`, `A_OKAY`, ...) followed by a payload (find more documentation in [protocol.md](protocol.md). There is no `A_READ` command because an asocket is unidirectional. To model a bi-directional stream, asocket have peers which go in the opposite direction.
+
+An asocket features a buffer containing apackets. If traffic is inbound, the buffer stores the apacket until it is consumed. If the traffic is oubound, the buffer stores apackets until they are sent down the wire (with `A_WRTE` commands).
+
+```
++---------------------ASocket------------------------+
+ |                                                   |
+ | +----------------APacket Queue------------------+ |
+ | |                                               | |
+ | |            APacket     APacket     APacket    | |
+ | |          +--------+  +--------+  +--------+   | |
+ | |          |AMessage|  |AMessage|  |AMessage|   | |
+ | |          +--------+  +--------+  +--------+   | |
+ | |          |        |  |        |  |        |   | |
+ | |  .....   |        |  |        |  |        |   | |
+ | |          |  Data  |  |  Data  |  |  Data  |   | |
+ | |          |        |  |        |  |        |   | |
+ | |          |        |  |        |  |        |   | |
+ | |          +--------+  +--------+  +--------+   | |
+ | |                                               | |
+ | +-----------------------------------------------+ |
+ +---------------------------------------------------+
+```
+
+This system allows adb to multiplex data streams on an unique byte stream. Without going into too much detail, the amessage arg1 and arg2 fields are similar to the TCP local and remote ports, where the combination uniquely identifies a particular stream. Note that unlike TCP which features an [unacknowledged-send window](https://en.wikipedia.org/wiki/TCP_congestion_control), an apacket is sent only after the previous one has been confirmed to be received.
+This is more of an historical accident than a design decision.
+
+The two types of asocket (Remote and Local) differentiate between outbound and inbound traffic.
+
+## adbd <-> APPPLICATION communication
+
+This pipeline is detailed in [daemon/jdwp_service.cpp](../../daemon/jdwp_service.cpp) with ASCII drawings! The JDWP extension implemented by Dalvik/ART are documented in:
+- platform/dalvik/+/main/docs/debugmon.html
+- platform/dalvik/+/main/docs/debugger.html
+
+### Sync protocol
+
+To transfer files and directories, ADB places a smart-socket in SYNC mode and then issues SYNC commands. The SYNC protocol is documented in [sync.md](sync.md).
+Despite its name the `sync` protocol is also what powers operations such as `pull` and `push`.
+
+### ADB Wifi architecture
+
+[here](adb_wifi.md)
+
+### Benchmark sample run for Pixel 8,USB
+
+```
+$ ./benchmark_device.py 
+sink   100MiB (write RAM)  : 10 runs: median 128.07 MiB/s, mean 126.90 MiB/s, stddev: 19.37 MiB/s
+source 100MiB (read RAM)   : 10 runs: median 233.73 MiB/s, mean 250.81 MiB/s, stddev: 47.45 MiB/s
+push   100MiB (write flash): 10 runs: median 142.82 MiB/s, mean 145.49 MiB/s, stddev: 16.57 MiB/s
+pull   100MiB (read flash) : 10 runs: median 190.37 MiB/s, mean 189.08 MiB/s, stddev: 51.24 MiB/s
+dd     100MiB (write flash): 10 runs: median 121.57 MiB/s, mean 125.60 MiB/s, stddev: 15.81 MiB/s
+```
+
+### Tests
+
+#### Integration Tests
+Run integration tests as follows.
+
+```
+$ atest adb_integration_test_device
+$ atest adb_integration_test_adb
+```
+
+You can use a filter to run only a class of test.
+
+```
+atest adb_integration_test_device --test-filter=FileOperationsTest
+```
+
+You can also use the filter to run a single test in a class.
+
+```
+atest adb_integration_test_device --test-filter=FileOperationsTest#test_push_sync
+```
+
+#### Unit tests
+
+The list of all the units tests can be found in [TEST_MAPPING](../../TEST_MAPPING)
+
+
+### More Legacy documentation
+[socket-activation.md](socket-activation.md): ADB socket control protocol.
\ No newline at end of file
diff --git a/docs/dev/adb_wifi.md b/docs/dev/adb_wifi.md
new file mode 100644
index 00000000..647b19e7
--- /dev/null
+++ b/docs/dev/adb_wifi.md
@@ -0,0 +1,200 @@
+# Architecture of *ADB Wifi*
+
+ADB has always had the capability to communicate with a device over TCP. However
+the process involved is convoluted and results in an insecure channel.
+The steps are as follows.
+
+1. Connect device via USB cable.
+2. Accept host's public key in the device UI dialog (pairing).
+3. Request adbd to open a TCP server socket
+```
+$ adb tcpip 5555
+```
+4. Retrieve device's Wi-Fi IP address
+```
+IP=`adb shell ip route | awk '{print $9}'`
+```
+5. Finally, connect over TCP
+```
+$ adb connect $IP:5555
+```
+
+After all these steps, adb server is communicating
+with adbd over TCP unencrypted.
+This means all traffic can be eavesdropped and open to MITM attacks.
+
+## The two problems *ADB Wifi* solves
+
+*ADB Wifi* allows a user to pair a device and a host in a single step, without
+requiring prior USB connection.
+
+Moreover, *ADB Wifi* uses TLS which allows for secure authentication and
+a secure connection after authentication.
+
+## How *ADB Wifi* works
+
+*ADB Wifi* revolves around four capabilities.
+
+- Pair without the user having to click "Allow debugging".
+- Encrypt ADB traffic.
+- Advertise services over the network.
+- Auto-connect to paired devices.
+
+### Pairing
+
+A host and a device are considered *paired* if the host's public key
+is in the device's `/data/misc/adb/adb_keys` or `/adb_keys` files (keystore). After pairing, the
+host can be trusted by the device because the host
+can use its private key to answer the challenges from the device (and the device can verify
+answer using keys from the keystore until a matching public key is found).
+
+To pair, *ADB Wifi* uses a Pairing Server running on the device.
+The Pairing Server communicates using RSA 2048-bit encryption (in a x509 certificate).
+Trust is bootstrapped using a shared secret, seeded either by a six-digit number (pairing code)
+or a 10-digit number (QR code pairing).
+
+### Encrypted traffic
+
+After pairing, and if the user has enabled "Wireless debugging", adbd listens on
+a TCP server socket (port picked at random). This is not the same as the legacy `tcpip` socket. The
+legacy socket greets all communication attempts with an A_AUTH packet whereas
+this socket opens communication with A_STLS which means all traffic will be
+TLS encrypted (and [authentication](../../protocol.txt) is different as well).
+
+All this traffic is handled by the TLSServer which is forwarded to adbd's fdevent.
+When users toggle "Wireless Debugging", they start and stop the TLSServer.
+
+### Network Advertising (mDNS)
+
+All of the elements previously mentioned advertise their presence on the network
+via mDNS. Three service types are used.
+
+- `_adb._tcp`: This is the legacy TCP service started via `adb tcpip <PORT>`.
+- `_adb-tls-pairing._tcp`: The service advertised when the device pairing server is active.
+- `_adb-tls-connect._tcp`: The service advertised when the device TLSServer is active.
+
+Note that all services' instances are published by the device (adb server is merely a consumer
+of mDNS packets). Both `_adb._tcp` and `_adb-tls-connect._tcp` are published directly
+by adbd while `_adb-tls-pairing._tcp` is published via NsdServiceInfo.
+
+#### mDNS Service Instance names
+
+An instance name prefix is usually `adb-` followed by the value of the property `ro.serialno` plus a random suffix added
+by the mdns backend.
+
+The Pairing Server is special. Its service instance name changes whether it is intended
+to be used with a pairing code or a QR code.
+
+- Pairing code: `adb-`<`prop(persist.adb.wifi.guid)`>
+- QR code: `studio-`< RANDOM-10> (e.g: `studio-58m*7E2fq4`)
+
+### Auto-connect
+
+When the host starts, it also starts mDNS service discovery for all three service types.
+Any service instance of type `_adb-tls-connect` being published by the device results in a connection attempt
+by the host (if the device's GUID is known to the host from pairing). If the device was previously paired,
+TLS authentication will automatically succeed and the device is made available to the host.
+
+There is one exception. When the pairing client finishes on the host, it also attempts to connect to the device
+it just paired with. This is because `_adb-tls-connect` was already published before pairing even began, which
+means the host cannot rely on the mDNS `_adb-tls-connect` "Create" event being published.
+
+### Device components communication
+
+On the device, three components must communicate. There is adbd, Framework (AdbDebuggingManager)
+and the mDNS daemon.
+
+The Pairing Server and the TLS server are part of the adbd apex API.
+These two libraries are linked into system_server (AdbDebuggingManager).
+The rest of the communication works via system properties.
+
+- `persist.adb.tls_server.enable`: Set when the Developer Settings UI checkbox "Use wireless debugging" is changed.
+adbd listens for these changes and manages the TLSServer lifecycle accordingly.
+-  `service.adb.tls.port`: Set by adbd. Retrieved by Framework so it can publish `_adb-tls-connect`.
+- `ctl.start`: Set to `mdnsd` by adbd to make sure the mDNS daemon is up and running.
+- `persist.adb.wifi.guid`: Where the device GUID (used to build service instance name) comes from. Both adbd
+and Framework retrieve this property to build  `_adb-tls-connect` and `_adb-tls-pairing` service instance
+names.
+
+# CLI tools
+
+*ADB Wifi* can be set up and monitored with the command line.
+
+### mdns check
+`$ adb mdns check` tells the user the name of adb's mDNS stack and its version.
+
+```
+$ adb mdns check
+mdns daemon version [Openscreen discovery 0.0.0]
+```
+
+### mdns services
+`$ adb mdns services` lists all supported mdns services' instances discovered and still active,
+followed by their service type and their resolved IPv4 address/port.
+```
+$ adb mdns services
+List of discovered mdns services
+adb-14141FDF600081         _adb._tcp	          192.168.86.38:5555
+adb-14141FDF600081-QXjCrW  _adb-tls-pairing._tcp  192.168.86.38:33861
+adb-14141FDF600081-TnSdi9  _adb-tls-connect._tcp  192.168.86.38:33015
+studio-g@<xeYnap/          _adb-tls-pairing._tcp  192.168.86.39:55861
+```
+
+Note: At the moment, IPv6 addresses are resolved but not output by the command.
+
+### pair
+
+If a user starts a Pairing Server on the device (via
+`Settings > System > Developer options > Wireless debugging > Pair device with pairing code`), they
+are presented with both a pairing code and the IPv4:port of the Wi-fi interface. In this case
+the vector to exchange the TLS secret is the user who reads it on the device then types the pairing code on the host.
+
+![](adb_wifi_assets/pairing_dialog.png)
+
+With the Pairing Server active, *ADB Wifi* is entirely configurable from the command-line, as follows.
+
+```
+$ adb pair 192.168.86.38:43811
+Enter pairing code: 515109
+$ adb connect 192.168.86.34:44643
+$ adb devices
+List of devices attached
+adb-43081FDAS000VS-QXjCrW._adb-tls-connect._tcp	device
+```
+
+# Android Studio
+
+## Pair with code
+Android Studio automates pairing with a pairing code thanks to its GUI.
+The advantage compared to the CLI method
+is that it relies on mDNS to detect devices with an active Pairing Server.
+To this effect, Studio polls adb server for service instances of type `_adb-tls-pairing`.
+
+## Pair with QR code
+Studio also introduces a QR code system which is just an easy way to share
+the pairing code between the host and the device.
+
+When a user clicks on "Pair device Using Wi-Fi", they are shown a QR code.
+
+![](adb_wifi_assets/qrcode.png)
+
+In the example code above Studio generated a QR code containing the string `WIFI:T:ADB;S:studio-g@<xeYnap/;P:(Aq+v9>Cx>!/;;`.
+The QR code piggyback on [WPA3 Specification](https://www.wi-fi.org/system/files/WPA3%20Specification%20v3.2.pdf#page=25)
+which specifies the format as follows.
+
+```
+“WIFI:” [type “;”] [trdisable “;”] ssid “;” [hidden “;”] [id “;”] [password “;”] [publickey “;”] “;”
+```
+
+Tokens are `;` separated. The QR Code contains three tokens
+
+1. Type (marked by `T:` prefix) indicates this is an `ADB` special string.
+
+1. The `ssid` field (marked by `S:` prefix) is repurposed to request a specific service instance name for `_adb-tls-pairing._tcp`.
+The device has a special Camera QR code handler which when it sees
+type `T:ADB` starts a Pairing Server with the requested instance name. Note that the part after `studio-` is randomized.
+This is done so Studio can tell which phone just scanned the QR code (here the instance name requested is `studio-g@<xeYnap/`).
+
+3. The password (marked by `P:` prefix) to use with the Pairing Server (here: `(Aq+v9>Cx>!/`).
+This is the second shared secret vector we mentioned earlier. Here the code is generated
+by Studio and read by the device's camera.
diff --git a/docs/dev/adb_wifi_assets/pairing_dialog.png b/docs/dev/adb_wifi_assets/pairing_dialog.png
new file mode 100644
index 00000000..301be790
Binary files /dev/null and b/docs/dev/adb_wifi_assets/pairing_dialog.png differ
diff --git a/docs/dev/adb_wifi_assets/qrcode.png b/docs/dev/adb_wifi_assets/qrcode.png
new file mode 100644
index 00000000..e8f7a5f5
Binary files /dev/null and b/docs/dev/adb_wifi_assets/qrcode.png differ
diff --git a/OVERVIEW.TXT b/docs/dev/overview.md
similarity index 99%
rename from OVERVIEW.TXT
rename to docs/dev/overview.md
index 3e200372..e0ff8337 100644
--- a/OVERVIEW.TXT
+++ b/docs/dev/overview.md
@@ -1,3 +1,4 @@
+```
 Implementation notes regarding ADB.
 
 I. General Overview:
@@ -133,3 +134,4 @@ II. Protocol details:
     and the device/emulator they point to. The ADB server must handle
     unexpected transport disconnections (e.g. when a device is physically
     unplugged) properly.
+```
\ No newline at end of file
diff --git a/protocol.txt b/docs/dev/protocol.md
similarity index 99%
rename from protocol.txt
rename to docs/dev/protocol.md
index 6ed38678..24414f95 100644
--- a/protocol.txt
+++ b/docs/dev/protocol.md
@@ -1,4 +1,4 @@
-
+```
 --- a replacement for aproto -------------------------------------------
 
 When it comes down to it, aproto's primary purpose is to forward
@@ -296,4 +296,4 @@ server: "OKAY"
 
 client: <hex4> <service-name>
 server: "FAIL" <hex4> <reason>
-
+```
diff --git a/SERVICES.TXT b/docs/dev/services.md
similarity index 98%
rename from SERVICES.TXT
rename to docs/dev/services.md
index fa853b37..d1457c93 100644
--- a/SERVICES.TXT
+++ b/docs/dev/services.md
@@ -1,3 +1,4 @@
+```
 This file tries to document all requests a client can make
 to the ADB server of an adbd daemon. See the OVERVIEW.TXT document
 to understand what's going on here.
@@ -81,6 +82,10 @@ host:<request>
     interpreted as 'any single device or emulator connected to/running on
     the host'.
 
+host:server-status
+    Return adb server status (version, build, usb backend, mdns backend, ...).
+    See adb_host.proto AdbServerStatus for more details.
+
 <host-prefix>:get-serialno
     Returns the serial number of the corresponding device/emulator.
     Note that emulator serial numbers are of the form "emulator-5554"
@@ -301,3 +306,4 @@ reverse:<forward-command>
 
     The output of reverse:list-forward is the same as host:list-forward
     except that <serial> will be just 'host'.
+```
\ No newline at end of file
diff --git a/SOCKET-ACTIVATION.txt b/docs/dev/socket-activation.md
similarity index 99%
rename from SOCKET-ACTIVATION.txt
rename to docs/dev/socket-activation.md
index 4ef62ac9..fbea073f 100644
--- a/SOCKET-ACTIVATION.txt
+++ b/docs/dev/socket-activation.md
@@ -1,3 +1,4 @@
+```
 adb can be configured to work with systemd-style socket activation,
 allowing the daemon to start automatically when the adb control port
 is forwarded across a network. You need two files, placed in the usual
@@ -40,3 +41,4 @@ accept(2) connections and that's already bound to the desired address
 and listening. inetd-style pre-accepted sockets do _not_ work in this
 configuration: the file descriptor passed to acceptfd must be the
 serve socket, not the accepted connection socket.
+```
\ No newline at end of file
diff --git a/SYNC.TXT b/docs/dev/sync.md
similarity index 99%
rename from SYNC.TXT
rename to docs/dev/sync.md
index 1bc5d99d..6bd7508e 100644
--- a/SYNC.TXT
+++ b/docs/dev/sync.md
@@ -1,3 +1,4 @@
+```
 This file tries to document file-related requests a client can make
 to the ADB server of an adbd daemon. See the OVERVIEW.TXT document
 to understand what's going on here. See the SERVICES.TXT to learn more
@@ -78,3 +79,4 @@ until the file is transferred. Each chunk will not be larger than 64k.
 
 When the file is transferred a sync response "DONE" is retrieved where the
 length can be ignored.
+```
\ No newline at end of file
diff --git a/docs/user/adb.1.md b/docs/user/adb.1.md
index bf443852..bc8ed4d8 100644
--- a/docs/user/adb.1.md
+++ b/docs/user/adb.1.md
@@ -270,6 +270,7 @@ jdwp
 logcat
 &nbsp;&nbsp;&nbsp;&nbsp;Show device log (logcat --help for more).
 
+server-status Display server configuration (USB backend, mDNS backend, log location, binary path. See [adb_host.proto](../../proto/adb_host.proto) (AdbServerStatus) for details.
 
 # SECURITY:
 
@@ -369,7 +370,7 @@ features
 # ENVIRONMENT VARIABLES
 
 $ADB_TRACE
-&nbsp;&nbsp;&nbsp;&nbsp;Comma (or space) separated list of debug info to log: all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp,services,auth,fdevent,shell,incremental.
+&nbsp;&nbsp;&nbsp;&nbsp;Comma (or space) separated list of debug info to log: all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp,services,auth,fdevent,shell,incremental, mdns.
 
 $ADB_VENDOR_KEYS
 &nbsp;&nbsp;&nbsp;&nbsp;Colon-separated list of keys (files or directories).
diff --git a/fastdeploy/Android.bp b/fastdeploy/Android.bp
index 309c6d1a..86e1fdf2 100644
--- a/fastdeploy/Android.bp
+++ b/fastdeploy/Android.bp
@@ -65,9 +65,9 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     data: [
diff --git a/fastdeploy/deploypatchgenerator/deploy_patch_generator.cpp b/fastdeploy/deploypatchgenerator/deploy_patch_generator.cpp
index 8aa7da72..81287eee 100644
--- a/fastdeploy/deploypatchgenerator/deploy_patch_generator.cpp
+++ b/fastdeploy/deploypatchgenerator/deploy_patch_generator.cpp
@@ -164,7 +164,7 @@ void DeployPatchGenerator::GeneratePatch(const std::vector<SimpleEntry>& entries
     if (realSizeOut != currentSizeOut) {
         fprintf(stderr, "Size mismatch current %lld vs real %lld\n",
                 static_cast<long long>(currentSizeOut), static_cast<long long>(realSizeOut));
-        error_exit("Aborting");
+        exit(1);
     }
 
     if (newApkSize > currentSizeOut) {
diff --git a/fastdeploy/deploypatchgenerator/patch_utils.cpp b/fastdeploy/deploypatchgenerator/patch_utils.cpp
index 2b00c801..0cc3e3e1 100644
--- a/fastdeploy/deploypatchgenerator/patch_utils.cpp
+++ b/fastdeploy/deploypatchgenerator/patch_utils.cpp
@@ -60,7 +60,7 @@ APKMetaData PatchUtils::GetHostAPKMetaData(const char* apkPath) {
     auto dump = archive.ExtractMetadata();
     if (dump.cd().empty()) {
         fprintf(stderr, "adb: Could not extract Central Directory from %s\n", apkPath);
-        error_exit("Aborting");
+        exit(1);
     }
 
     auto apkMetaData = GetDeviceAPKMetaData(dump);
@@ -70,7 +70,8 @@ APKMetaData PatchUtils::GetHostAPKMetaData(const char* apkPath) {
         auto dataSize =
                 archive.CalculateLocalFileEntrySize(apkEntry.dataoffset(), apkEntry.datasize());
         if (dataSize == 0) {
-            error_exit("Aborting");
+            fprintf(stderr, "adb: empty local file entry in %s\n", apkPath);
+            exit(1);
         }
         apkEntry.set_datasize(dataSize);
     }
@@ -101,7 +102,7 @@ void PatchUtils::Pipe(borrowed_fd input, borrowed_fd output, size_t amount) {
         auto readAmount = adb_read(input, buffer, chunkAmount);
         if (readAmount < 0) {
             fprintf(stderr, "adb: failed to read from input: %s\n", strerror(errno));
-            error_exit("Aborting");
+            exit(1);
         }
         WriteFdExactly(output, buffer, readAmount);
         transferAmount += readAmount;
diff --git a/fdevent/fdevent.cpp b/fdevent/fdevent.cpp
index e20a2953..46d8cbf7 100644
--- a/fdevent/fdevent.cpp
+++ b/fdevent/fdevent.cpp
@@ -155,7 +155,7 @@ void fdevent_context::HandleEvents(const std::vector<fdevent_event>& events) {
     for (const auto& event : events) {
         // Verify the fde is still installed before invoking it.  It could have been unregistered
         // and destroyed inside an earlier event handler.
-        if (this->fdevent_set_.find(event.fde) != this->fdevent_set_.end()) {
+        if (this->fdevent_set_.contains(event.fde)) {
             invoke_fde(event.fde, event.events);
             break;
         }
diff --git a/proto/Android.bp b/proto/Android.bp
index 383e4a70..edb8059c 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -145,7 +145,7 @@ cc_library_host_static {
 }
 
 cc_defaults {
-    name: "libdevices_protos_defaults",
+    name: "adb_host_protos_defaults",
     cflags: [
         "-Wall",
         "-Wextra",
@@ -156,7 +156,7 @@ cc_defaults {
     compile_multilib: "both",
 
     srcs: [
-        "devices.proto",
+        ":adb_host_proto",
     ],
     target: {
         windows: {
@@ -178,8 +178,11 @@ cc_defaults {
 }
 
 cc_library_host_static {
-    name: "libdevices_protos",
-    defaults: ["libdevices_protos_defaults"],
+    name: "libadb_host_protos",
+    defaults: ["adb_host_protos_defaults"],
+    static_libs: [
+        "libprotobuf-cpp-full",
+    ],
 
     proto: {
         export_proto_headers: true,
@@ -187,3 +190,13 @@ cc_library_host_static {
     },
 }
 
+filegroup {
+    name: "adb_host_proto",
+    srcs: [
+        "adb_host.proto",
+    ],
+    visibility: [
+        "//packages/modules/adb:__subpackages__",
+        "//tools/asuite",
+    ],
+}
diff --git a/proto/devices.proto b/proto/adb_host.proto
similarity index 74%
rename from proto/devices.proto
rename to proto/adb_host.proto
index 6f65babb..fb2a0793 100644
--- a/proto/devices.proto
+++ b/proto/adb_host.proto
@@ -60,3 +60,30 @@ message Device {
 message Devices {
     repeated Device device = 1;
 }
+
+message AdbServerStatus {
+    enum UsbBackend {
+        UNKNOWN_USB = 0;
+        NATIVE = 1;
+        LIBUSB = 2;
+    }
+
+    enum MdnsBackend {
+        UNKNOWN_MDNS = 0;
+        BONJOUR = 1;
+        OPENSCREEN = 2;
+     }
+
+     UsbBackend usb_backend = 1;
+     bool usb_backend_forced = 2;
+
+     MdnsBackend mdns_backend = 3;
+     bool mdns_backend_forced = 4;
+
+     string version = 5;
+     string build = 6;
+     string executable_absolute_path = 7;
+     string log_absolute_path = 8;
+     string os = 9;
+}
+
diff --git a/socket.h b/socket.h
index 6937b9f3..a6f7d4ff 100644
--- a/socket.h
+++ b/socket.h
@@ -65,7 +65,6 @@ struct asocket {
 
     /* flag: set when the socket's peer has closed
      * but packets are still queued for delivery
-     * TODO: This should be a boolean.
      */
     bool closing = false;
 
diff --git a/sockets.cpp b/sockets.cpp
index a33157b8..f766f7e9 100644
--- a/sockets.cpp
+++ b/sockets.cpp
@@ -958,7 +958,7 @@ static void smart_socket_close(asocket* s) {
     delete s;
 }
 
-static asocket* create_smart_socket(void) {
+static asocket* create_smart_socket() {
     D("Creating smart socket");
     asocket* s = new asocket();
     s->enqueue = smart_socket_enqueue;
diff --git a/sysdeps.h b/sysdeps.h
index a06b9394..99f6b74f 100644
--- a/sysdeps.h
+++ b/sysdeps.h
@@ -33,6 +33,7 @@
 
 // Include this before open/close/isatty/unlink are defined as macros below.
 #include <android-base/errors.h>
+#include <android-base/logging.h>
 #include <android-base/macros.h>
 #include <android-base/off64_t.h>
 #include <android-base/unique_fd.h>
@@ -52,6 +53,8 @@ static inline void* mempcpy(void* dst, const void* src, size_t n) {
 }
 #endif
 
+std::optional<ssize_t> network_peek(borrowed_fd fd);
+
 #ifdef _WIN32
 
 #include <ctype.h>
@@ -185,8 +188,6 @@ inline int network_local_server(const char* name, int namespace_id, int type, st
 int network_connect(const std::string& host, int port, int type, int timeout,
                     std::string* error);
 
-std::optional<ssize_t> network_peek(borrowed_fd fd);
-
 extern int adb_socket_accept(borrowed_fd serverfd, struct sockaddr* addr, socklen_t* addrlen);
 
 #undef   accept
@@ -607,11 +608,6 @@ inline int network_local_server(const char* name, int namespace_id, int type, st
 
 int network_connect(const std::string& host, int port, int type, int timeout, std::string* error);
 
-inline std::optional<ssize_t> network_peek(borrowed_fd fd) {
-    ssize_t ret = recv(fd.get(), nullptr, 0, MSG_PEEK | MSG_TRUNC);
-    return ret == -1 ? std::nullopt : std::make_optional(ret);
-}
-
 static inline int adb_socket_accept(borrowed_fd serverfd, struct sockaddr* addr,
                                     socklen_t* addrlen) {
     int fd;
@@ -699,7 +695,11 @@ inline ssize_t adb_sendmsg(borrowed_fd fd, const adb_msghdr* msg, int flags) {
 }
 
 inline ssize_t adb_recvmsg(borrowed_fd fd, adb_msghdr* msg, int flags) {
-    return recvmsg(fd.get(), msg, flags);
+    ssize_t ret = recvmsg(fd.get(), msg, flags);
+    if (ret == -1) {
+        PLOG(ERROR) << "adb_recmsg error";
+    }
+    return ret;
 }
 
 using adb_cmsghdr = cmsghdr;
@@ -789,7 +789,7 @@ static inline void disable_tcp_nagle(borrowed_fd fd) {
 bool set_tcp_keepalive(borrowed_fd fd, int interval_sec);
 
 // Returns a human-readable OS version string.
-extern std::string GetOSVersion(void);
+extern std::string GetOSVersion();
 
 #if defined(_WIN32)
 // Win32 defines ERROR, which we don't need, but which conflicts with google3 logging.
diff --git a/sysdeps_unix.cpp b/sysdeps_unix.cpp
index 66757cd9..db7c368b 100644
--- a/sysdeps_unix.cpp
+++ b/sysdeps_unix.cpp
@@ -18,6 +18,7 @@
 
 #include <sys/utsname.h>
 
+#include <android-base/logging.h>
 #include <android-base/stringprintf.h>
 
 bool set_tcp_keepalive(borrowed_fd fd, int interval_sec) {
@@ -107,3 +108,21 @@ std::string GetOSVersion(void) {
 
     return android::base::StringPrintf("%s %s (%s)", name.sysname, name.release, name.machine);
 }
+
+std::optional<ssize_t> network_peek(borrowed_fd fd) {
+    ssize_t upper_bound_bytes;
+#if defined(__APPLE__)
+    // Can't use recv(MSG_TRUNC) (not supported).
+    // Can't use ioctl(FIONREAD) (returns size in socket queue instead next message size).
+    socklen_t optlen = sizeof(upper_bound_bytes);
+    if (getsockopt(fd.get(), SOL_SOCKET, SO_NREAD, &upper_bound_bytes, &optlen) == -1) {
+        upper_bound_bytes = -1;
+    }
+#else
+    upper_bound_bytes = recv(fd.get(), nullptr, 0, MSG_PEEK | MSG_TRUNC);
+#endif
+    if (upper_bound_bytes == -1) {
+        PLOG(ERROR) << "network_peek error";
+    }
+    return upper_bound_bytes == -1 ? std::nullopt : std::make_optional(upper_bound_bytes);
+}
\ No newline at end of file
diff --git a/test_device.py b/test_device.py
index 46a55452..cc5e2f05 100755
--- a/test_device.py
+++ b/test_device.py
@@ -36,8 +36,7 @@ import threading
 import time
 import unittest
 
-import proto.devices_pb2 as proto_devices
-import proto.app_processes_pb2 as proto_track_app
+import adb_host_pb2 as adb_host_proto
 
 from datetime import datetime
 
@@ -1830,7 +1829,7 @@ class DevicesListing(DeviceTest):
             output_size = int(proc.stdout.read(4).decode("utf-8"), 16)
             proto = proc.stdout.read(output_size)
 
-            devices = proto_devices.Devices()
+            devices = adb_host_proto.Devices()
             devices.ParseFromString(proto)
 
             device = devices.device[0]
@@ -1882,6 +1881,17 @@ class DevicesListing(DeviceTest):
             self.assertTrue(foundAdbAppOwnProc)
             proc.terminate()
 
+class ServerStatus(unittest.TestCase):
+    def test_server_status(self):
+        with subprocess.Popen(['adb', 'server-status'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
+            lines = list(map(lambda b: b.decode("utf-8"), proc.stdout.readlines()))
+            self.assertTrue("usb_backend" in lines[0])
+            self.assertTrue("mdns_backend" in lines[1])
+            self.assertTrue("version" in lines[2])
+            self.assertTrue("build" in lines[3])
+            self.assertTrue("executable_absolute_path" in lines[4])
+            self.assertTrue("log_absolute_path" in lines[5])
+
 if __name__ == '__main__':
     random.seed(0)
     unittest.main()
diff --git a/transport.cpp b/transport.cpp
index dd644f25..b99e8bcf 100644
--- a/transport.cpp
+++ b/transport.cpp
@@ -57,8 +57,8 @@
 
 #if ADB_HOST
 #include <google/protobuf/text_format.h>
+#include "adb_host.pb.h"
 #include "client/usb.h"
-#include "devices.pb.h"
 #endif
 
 using namespace adb::crypto;
@@ -100,6 +100,7 @@ const char* const kFeatureOpenscreenMdns = "openscreen_mdns";
 const char* const kFeatureDeviceTrackerProtoFormat = "devicetracker_proto_format";
 const char* const kFeatureDevRaw = "devraw";
 const char* const kFeatureAppInfo = "app_info";  // Add information to track-app (package name, ...)
+const char* const kFeatureServerStatus = "server_status";  // Ability to output server status
 
 namespace {
 
@@ -731,7 +732,7 @@ void update_transports() {
 static bool usb_devices_start_detached() {
     static const char* env = getenv("ADB_LIBUSB_START_DETACHED");
     static bool result = env && strcmp("1", env) == 0;
-    return should_use_libusb() && result;
+    return is_libusb_enabled() && result;
 }
 #endif
 
@@ -781,7 +782,7 @@ static void fdevent_register_transport(atransport* t) {
 }
 
 #if ADB_HOST
-void init_reconnect_handler(void) {
+void init_reconnect_handler() {
     reconnect_handler.Start();
 }
 #endif
@@ -1076,7 +1077,7 @@ bool atransport::Attach(std::string* error) {
     D("%s: attach", serial.c_str());
     fdevent_check_looper();
 
-    if (!should_use_libusb()) {
+    if (!is_libusb_enabled()) {
         *error = "attach/detach only implemented for libusb backend";
         return false;
     }
@@ -1103,7 +1104,7 @@ bool atransport::Detach(std::string* error) {
     D("%s: detach", serial.c_str());
     fdevent_check_looper();
 
-    if (!should_use_libusb()) {
+    if (!is_libusb_enabled()) {
         *error = "attach/detach only implemented for libusb backend";
         return false;
     }
@@ -1210,6 +1211,7 @@ const FeatureSet& supported_features() {
             kFeatureDeviceTrackerProtoFormat,
             kFeatureDevRaw,
             kFeatureAppInfo,
+            kFeatureServerStatus,
         };
         // clang-format on
 
@@ -1640,7 +1642,7 @@ void atransport::UpdateReverseConfig(std::string_view service_addr) {
         }
         std::string remote(service_addr.substr(0, it));
 
-        if (norebind && reverse_forwards_.find(remote) != reverse_forwards_.end()) {
+        if (norebind && reverse_forwards_.contains(remote)) {
             // This will fail, don't update the map.
             LOG(DEBUG) << "ignoring reverse forward that will fail due to norebind";
             return;
diff --git a/transport.h b/transport.h
index 27ddea61..71decb21 100644
--- a/transport.h
+++ b/transport.h
@@ -471,19 +471,21 @@ atransport* acquire_one_transport(TransportType type, const char* serial, Transp
                                   bool* is_ambiguous, std::string* error_out,
                                   bool accept_any_state = false);
 void kick_transport(atransport* t, bool reset = false);
-void update_transports(void);
+void update_transports();
 
 // Iterates across all of the current and pending transports.
 // Stops iteration and returns false if fn returns false, otherwise returns true.
 bool iterate_transports(std::function<bool(const atransport*)> fn);
 
-void init_reconnect_handler(void);
-void init_mdns_transport_discovery(void);
+void init_reconnect_handler();
+void init_mdns_transport_discovery();
 
 #if ADB_HOST
 atransport* find_transport(const char* serial);
 
 void kick_all_tcp_devices();
+
+bool using_bonjour(void);
 #endif
 
 void kick_all_transports();
```

