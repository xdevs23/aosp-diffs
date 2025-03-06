```diff
diff --git a/Android.bp b/Android.bp
index 6a62c34d..076cfe9f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -217,6 +217,7 @@ libadb_srcs = [
     "adb_trace.cpp",
     "adb_unique_fd.cpp",
     "adb_utils.cpp",
+    "apacket_reader.cpp",
     "fdevent/fdevent.cpp",
     "services.cpp",
     "sockets.cpp",
@@ -275,7 +276,7 @@ cc_library_host_static {
         "client/auth.cpp",
         "client/adb_wifi.cpp",
         "client/usb_libusb.cpp",
-        "client/transport_local.cpp",
+        "client/transport_emulator.cpp",
         "client/mdnsresponder_client.cpp",
         "client/mdns_utils.cpp",
         "client/transport_mdns.cpp",
@@ -401,6 +402,24 @@ cc_test_host {
             ldflags: ["-municode"],
             shared_libs: ["AdbWinApi"],
         },
+        // TODO: Create an asan_default rule and use it for adb_asan target
+        // and ALL unit tests.
+        linux: {
+            sanitize: {
+                address: true,
+            },
+            strip: {
+                none: true,
+            },
+        },
+        darwin: {
+            sanitize: {
+                address: true,
+            },
+            strip: {
+                none: true,
+            },
+        },
     },
 
     test_options: {
@@ -432,7 +451,7 @@ cc_defaults {
         "shell_service_protocol.cpp",
     ],
 
-    generated_headers: [
+    device_first_generated_headers: [
         "bin2c_fastdeployagent",
         "bin2c_fastdeployagentscript",
     ],
@@ -552,7 +571,7 @@ cc_library_static {
         "daemon/auth.cpp",
         "daemon/jdwp_service.cpp",
         "daemon/logging.cpp",
-        "daemon/transport_local.cpp",
+        "daemon/transport_socket_server.cpp",
     ],
 
     generated_headers: ["platform_tools_version"],
@@ -628,6 +647,7 @@ cc_library {
         "daemon/file_sync_service.cpp",
         "daemon/services.cpp",
         "daemon/shell_service.cpp",
+        "daemon/tradeinmode.cpp",
         "shell_service_protocol.cpp",
     ],
 
@@ -676,6 +696,9 @@ cc_library {
                 "libmdnssd",
                 "libselinux",
             ],
+            static_libs: [
+                "android_trade_in_mode_flags_cc_lib",
+            ],
         },
         recovery: {
             exclude_srcs: [
@@ -685,6 +708,9 @@ cc_library {
                 "libadb_pairing_auth",
                 "libadb_pairing_connection",
             ],
+            exclude_static_libs: [
+                "android_trade_in_mode_flags_cc_lib",
+            ],
         },
     },
 
@@ -760,14 +786,12 @@ cc_library {
     ],
 }
 
-cc_binary {
-    name: "adbd",
+cc_defaults {
+    name: "adbd_binary_defaults",
     defaults: [
         "adbd_defaults",
-        "host_adbd_supported",
         "libadbd_binary_dependencies",
     ],
-    recovery_available: true,
     min_sdk_version: "30",
     apex_available: ["com.android.adbd"],
 
@@ -798,17 +822,32 @@ cc_binary {
     shared_libs: [
         "libadbd_auth",
     ],
+}
 
+cc_binary {
+    name: "adbd",
+    defaults: [
+        "host_adbd_supported",
+        "adbd_binary_defaults",
+    ],
     target: {
-        recovery: {
-            exclude_shared_libs: [
-                "libadb_pairing_auth",
-                "libadb_pairing_connection",
+        android: {
+            static_libs: [
+                "android_trade_in_mode_flags_cc_lib",
             ],
         },
     },
 }
 
+cc_binary {
+    name: "adbd.recovery",
+    defaults: [
+        "adbd_binary_defaults",
+    ],
+    recovery: true,
+    stem: "adbd",
+}
+
 phony {
     // Interface between adbd in a module and the system.
     name: "adbd_system_api",
@@ -893,6 +932,8 @@ cc_test {
         "daemon/services.cpp",
         "daemon/shell_service.cpp",
         "daemon/shell_service_test.cpp",
+        "daemon/tradeinmode.cpp",
+        "daemon/tradeinmode_test.cpp",
         "test_utils/test_utils.cpp",
         "shell_service_protocol_test.cpp",
         "mdns_test.cpp",
@@ -905,6 +946,9 @@ cc_test {
             srcs: [
                 "daemon/property_monitor_test.cpp",
             ],
+            static_libs: [
+                "android_trade_in_mode_flags_cc_lib",
+            ],
         },
     },
 
@@ -964,7 +1008,7 @@ python_test_host {
     test_options: {
         unit_test: false,
     },
-    data: [
+    device_common_data: [
         ":adb_test_app1",
         ":adb_test_app2",
     ],
diff --git a/NOTICE b/NOTICE
index 9ffcc081..32a74b92 100644
--- a/NOTICE
+++ b/NOTICE
@@ -1,6 +1,5 @@
 
    Copyright (c) 2006-2009, The Android Open Source Project
-   Copyright 2006, Brian Swetland <swetland@frotz.net>
 
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
diff --git a/README.md b/README.md
index 9153ea14..62741148 100644
--- a/README.md
+++ b/README.md
@@ -6,4 +6,4 @@ The Android Debug Bridge connects Android devices to to computers running other
 [man page](docs/user/adb.1.md)
 
 ## Developer documentation
-[main page](docs/dev/README.md)
+[main page](docs/dev/internals.md)
diff --git a/adb.cpp b/adb.cpp
index 95fd303e..66d5785e 100644
--- a/adb.cpp
+++ b/adb.cpp
@@ -116,6 +116,29 @@ uint32_t calculate_apacket_checksum(const apacket* p) {
     return sum;
 }
 
+std::string command_to_string(uint32_t cmd) {
+    switch (cmd) {
+        case A_SYNC:
+            return "A_SYNC";
+        case A_CNXN:
+            return "A_CNXN";
+        case A_OPEN:
+            return "A_OPEN";
+        case A_OKAY:
+            return "A_OKAY";
+        case A_CLSE:
+            return "A_CLSE";
+        case A_WRTE:
+            return "A_WRTE";
+        case A_AUTH:
+            return "A_AUTH";
+        case A_STLS:
+            return "A_STLS";
+        default:
+            return "UNKNOWN (" + std::to_string(cmd) + ")";
+    }
+}
+
 std::string to_string(ConnectionState state) {
     switch (state) {
         case kCsOffline:
@@ -142,8 +165,8 @@ std::string to_string(ConnectionState state) {
             return "connecting";
         case kCsDetached:
             return "detached";
-        default:
-            return "unknown";
+        case kCsAny:
+            return "any";
     }
 }
 
@@ -550,7 +573,6 @@ void handle_packet(apacket *p, atransport *t)
                     s->peer->peer = s;
 
                     local_socket_ack(s, acked_bytes);
-                    s->ready(s);
                 } else if (s->peer->id == p->msg.arg0) {
                     /* Other READY messages must use the same local-id */
                     local_socket_ack(s, acked_bytes);
@@ -1498,7 +1520,7 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
         if (!ParseUint(&port, service)) {
           LOG(ERROR) << "received invalid port for emulator: " << service;
         } else {
-          local_connect(port);
+            connect_emulator(port);
         }
 
         /* we don't even need to send a reply */
diff --git a/adb.h b/adb.h
index 3a00559c..4516d3cb 100644
--- a/adb.h
+++ b/adb.h
@@ -47,6 +47,7 @@ constexpr size_t LINUX_MAX_SOCKET_SIZE = 4194304;
 #define A_WRTE 0x45545257
 #define A_AUTH 0x48545541
 #define A_STLS 0x534C5453
+std::string command_to_string(uint32_t cmd);
 
 // ADB protocol version.
 // Version revision:
@@ -108,8 +109,8 @@ enum ConnectionState {
     kCsAuthorizing,     // Authorizing with keys from ADB_VENDOR_KEYS.
     kCsUnauthorized,    // ADB_VENDOR_KEYS exhausted, fell back to user prompt.
     kCsNoPerm,          // Insufficient permissions to communicate with the device.
-    kCsDetached,        // USB device that's detached from the adb server.
-    kCsOffline,
+    kCsDetached,        // USB device detached from the adb server (known but not opened/claimed).
+    kCsOffline,         // A peer has been detected (device/host) but no comm has started yet.
 
     // After CNXN packet, the ConnectionState describes not a state but the type of service
     // on the other end of the transport.
@@ -146,9 +147,6 @@ int launch_server(const std::string& socket_spec, const char* one_device);
 int adb_server_main(int is_daemon, const std::string& socket_spec, const char* one_device,
                     int ack_reply_fd);
 
-/* initialize a transport object's func pointers and state */
-int init_socket_transport(atransport* t, unique_fd s, int port, int local);
-
 std::string getEmulatorSerialString(int console_port);
 #if ADB_HOST
 atransport* find_emulator_transport_by_adb_port(int adb_port);
@@ -191,8 +189,6 @@ void put_apacket(apacket* p);
     } while (0)
 #endif
 
-#define DEFAULT_ADB_PORT 5037
-
 #define DEFAULT_ADB_LOCAL_TRANSPORT_PORT 5555
 
 #define ADB_CLASS 0xff
@@ -202,9 +198,8 @@ void put_apacket(apacket* p);
 #define ADB_DBC_CLASS 0xDC
 #define ADB_DBC_SUBCLASS 0x2
 
-void local_init(const std::string& addr);
-bool local_connect(int port);
-int local_connect_arbitrary_ports(int console_port, int adb_port, std::string* error);
+bool connect_emulator(int port);
+int connect_emulator_arbitrary_ports(int console_port, int adb_port, std::string* error);
 
 extern const char* adb_device_banner;
 
diff --git a/adb_listeners_test.cpp b/adb_listeners_test.cpp
index a7e2deaf..2b53c3d0 100644
--- a/adb_listeners_test.cpp
+++ b/adb_listeners_test.cpp
@@ -61,7 +61,7 @@ class AdbListenersTest : public ::testing::Test {
     }
 
   protected:
-    atransport transport_;
+    atransport transport_{kTransportLocal};
 };
 
 TEST_F(AdbListenersTest, test_install_listener) {
diff --git a/apacket_reader.cpp b/apacket_reader.cpp
new file mode 100644
index 00000000..f777dd43
--- /dev/null
+++ b/apacket_reader.cpp
@@ -0,0 +1,125 @@
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
+#include "apacket_reader.h"
+
+#include "adb.h"
+#include "adb_trace.h"
+
+APacketReader::APacketReader() {
+    prepare_for_next_packet();
+}
+
+void APacketReader::add_packet(std::unique_ptr<apacket> packet) {
+    VLOG(USB) << "Got packet " << command_to_string(packet->msg.command)
+              << ", size=" << packet->msg.data_length;
+    packets_.emplace_back(std::move(packet));
+    prepare_for_next_packet();
+}
+
+APacketReader::AddResult APacketReader::add_bytes(Block&& block) noexcept {
+    if (block.remaining() == 0) {
+        return OK;
+    }
+
+    VLOG(USB) << "Received " << block.remaining() << " bytes";
+
+    header_.fillFrom(block);
+    if (!header_.is_full()) {
+        // We don't have a full header. Nothing much we can do here, except wait for the next block.
+        return OK;
+    }
+
+    // From here, we have a full header and we can peek to see how much payload is expected.
+    auto m = reinterpret_cast<amessage*>(header_.data());
+
+    // Is the packet buggy?
+    if (m->data_length > MAX_PAYLOAD) {
+        VLOG(USB) << "Payload > " << MAX_PAYLOAD;
+        prepare_for_next_packet();
+        return ERROR;
+    }
+
+    // Is it a packet without payload? If it is, we have an apacket.
+    if (m->data_length == 0) {
+        packet_ = std::make_unique<apacket>();
+        packet_->msg = *reinterpret_cast<amessage*>(header_.data());
+        packet_->payload = Block{0};
+        add_packet(std::move(packet_));
+        return add_bytes(std::move(block));
+    }
+
+    // In most cases (when the USB layer works as intended) this should be where we have the header
+    // but no payload. The odds of using a fast (std::move) are good but we don't know yet. If
+    // there is nothing remaining, wait until payload packet shows up.
+    if (block.remaining() == 0) {
+        VLOG(USB) << "Packet " << command_to_string(m->command) << " needs " << m->data_length
+                  << " bytes.";
+        return OK;
+    }
+
+    // We just received the first block for the packet payload. We may be able to use
+    // std::move (fast). If we can't std::move it, we allocate to store the payload as a fallback
+    // mechanism (slow).
+    if (!packet_) {
+        packet_ = std::make_unique<apacket>();
+        packet_->msg = *reinterpret_cast<amessage*>(header_.data());
+
+        if (block.position() == 0 && block.remaining() == packet_->msg.data_length) {
+            // The block is exactly the expected size and nothing was read from it.
+            // Move it and we are done.
+            VLOG(USB) << "Zero-copy";
+            packet_->payload = std::move(block);
+            add_packet(std::move(packet_));
+            return OK;
+        } else {
+            VLOG(USB) << "Falling back: Allocating block " << packet_->msg.data_length;
+            packet_->payload.resize(packet_->msg.data_length);
+        }
+    }
+
+    // Fallback (we could not std::move). Fill the payload with incoming block.
+    packet_->payload.fillFrom(block);
+
+    // If we have all the bytes we needed for the payload, we have a packet. Add it to the list.
+    if (packet_->payload.is_full()) {
+        packet_->payload.rewind();
+        add_packet(std::move(packet_));
+    } else {
+        VLOG(USB) << "Need " << packet_->payload.remaining() << " bytes to full packet";
+    }
+
+    // If we still have more data, start parsing the next packet via recursion.
+    if (block.remaining() > 0) {
+        VLOG(USB) << "Detected block with merged payload-header (remaining=" << block.remaining()
+                  << " bytes)";
+        return add_bytes(std::move(block));
+    }
+
+    return OK;
+}
+
+std::vector<std::unique_ptr<apacket>> APacketReader::get_packets() noexcept {
+    auto ret = std::move(packets_);
+    // We moved the vector so it is in undefined state. clear() sets it back into a known state
+    packets_.clear();
+    return ret;
+}
+
+void APacketReader::prepare_for_next_packet() {
+    header_.rewind();
+    packet_ = std::unique_ptr<apacket>(nullptr);
+}
diff --git a/apacket_reader.h b/apacket_reader.h
new file mode 100644
index 00000000..8f8b1918
--- /dev/null
+++ b/apacket_reader.h
@@ -0,0 +1,50 @@
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
+#pragma once
+
+#include <memory>
+#include <vector>
+
+#include "types.h"
+
+// Historically, adb expects apackets to be transferred over USB with two transfers. One for the
+// header and one for the payload. This usually translates into two Blocks. Buggy drivers and
+// "bridges" / IO libs can lead to merged transfers (e.g.: a header and a payload, or a payload
+// and the next header).
+// This class is able to read inbound Blocks containing apackets chopped/merged on any boundaries.
+class APacketReader {
+  public:
+    APacketReader();
+    ~APacketReader() = default;
+
+    enum AddResult { OK, ERROR };
+    AddResult add_bytes(Block&& block) noexcept;
+
+    // Returns all packets parsed so far. Upon return, the internal apacket vector is emptied.
+    std::vector<std::unique_ptr<apacket>> get_packets() noexcept;
+
+    // Clear blocks so we can start parsing the next packet.
+    void prepare_for_next_packet();
+
+  private:
+    void add_packet(std::unique_ptr<apacket> packet);
+    Block header_{sizeof(amessage)};
+    std::unique_ptr<apacket> packet_;
+
+    // We keep packets in this internal vector. It is empty after a `get_packets` call.
+    std::vector<std::unique_ptr<apacket>> packets_;
+};
\ No newline at end of file
diff --git a/apex/adbd.rc b/apex/adbd.rc
index 0fb6f69d..09ceff8a 100644
--- a/apex/adbd.rc
+++ b/apex/adbd.rc
@@ -1,4 +1,4 @@
-service adbd /apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0
+service adbd /apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0 --tim_seclabel=u:r:adbd_tradeinmode:s0
     class core
     socket adbd seqpacket 660 system system
     disabled
diff --git a/client/adb_install.cpp b/client/adb_install.cpp
index abfcd4ef..451b96d5 100644
--- a/client/adb_install.cpp
+++ b/client/adb_install.cpp
@@ -150,6 +150,7 @@ static void read_status_line(int fd, char* buf, size_t count) {
 }
 
 static unique_fd send_command(const std::vector<std::string>& cmd_args, std::string* error) {
+    VLOG(ADB) << "pm command: '" << android::base::Join(cmd_args, " ") << "'";
     if (is_abb_exec_supported()) {
         return send_abb_exec_command(cmd_args, error);
     } else {
@@ -192,14 +193,12 @@ static int install_app_streamed(int argc, const char** argv, bool use_fastdeploy
 
     struct stat sb;
     if (stat(file, &sb) == -1) {
-        fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
-        return 1;
+        perror_exit("failed to stat %s", file);
     }
 
     unique_fd local_fd(adb_open(file, O_RDONLY | O_CLOEXEC));
     if (local_fd < 0) {
-        fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
-        return 1;
+        perror_exit("failed to open %s", file);
     }
 
 #ifdef __linux__
@@ -231,20 +230,17 @@ static int install_app_streamed(int argc, const char** argv, bool use_fastdeploy
 
     unique_fd remote_fd = send_command(cmd_args, &error);
     if (remote_fd < 0) {
-        fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
-        return 1;
+        error_exit("connect error for write: %s", error.c_str());
     }
 
     if (!copy_to_file(local_fd.get(), remote_fd.get())) {
-        fprintf(stderr, "adb: failed to install: copy_to_file: %s: %s", file, strerror(errno));
-        return 1;
+        perror_exit("failed to install: copy_to_file: %s", file);
     }
 
     char buf[BUFSIZ];
     read_status_line(remote_fd.get(), buf, sizeof(buf));
     if (strncmp("Success", buf, 7) != 0) {
-        fprintf(stderr, "adb: failed to install %s: %s", file, buf);
-        return 1;
+        error_exit("failed to install %s: %s", file, buf);
     }
 
     fputs(buf, stdout);
@@ -395,7 +391,7 @@ static std::pair<InstallMode, std::optional<InstallMode>> calculate_install_mode
                                          "enable_adb_incremental_install_default"};
         auto fd = send_abb_exec_command(args, &error);
         if (!fd.ok()) {
-            fprintf(stderr, "adb: retrieving the default device installation mode failed: %s",
+            fprintf(stderr, "adb: retrieving the default device installation mode failed: %s\n",
                     error.c_str());
         } else {
             char buf[BUFSIZ] = {};
@@ -543,7 +539,8 @@ static int install_multiple_app_streamed(int argc, const char** argv) {
 
         if (android::base::EndsWithIgnoreCase(file, ".apk") ||
             android::base::EndsWithIgnoreCase(file, ".dm") ||
-            android::base::EndsWithIgnoreCase(file, ".fsv_sig")) {
+            android::base::EndsWithIgnoreCase(file, ".fsv_sig") ||
+            android::base::EndsWithIgnoreCase(file, ".idsig")) {  // v4 external signature.
             struct stat sb;
             if (stat(file, &sb) == -1) perror_exit("failed to stat \"%s\"", file);
             total_size += sb.st_size;
@@ -577,8 +574,7 @@ static int install_multiple_app_streamed(int argc, const char** argv) {
     {
         unique_fd fd = send_command(cmd_args, &error);
         if (fd < 0) {
-            fprintf(stderr, "adb: connect error for create: %s\n", error.c_str());
-            return EXIT_FAILURE;
+            perror_exit("connect error for create: %s", error.c_str());
         }
         read_status_line(fd.get(), buf, sizeof(buf));
     }
diff --git a/client/auth.cpp b/client/auth.cpp
index f87ee85a..5b837526 100644
--- a/client/auth.cpp
+++ b/client/auth.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define TRACE_TAG AUTH
-
 #include <dirent.h>
 #include <stdio.h>
 #include <stdlib.h>
@@ -61,7 +59,7 @@ using namespace adb::crypto;
 using namespace adb::tls;
 
 static bool generate_key(const std::string& file) {
-    LOG(INFO) << "generate_key(" << file << ")...";
+    VLOG(AUTH) << "generate_key(" << file << ")...";
 
     auto rsa_2048 = CreateRSA2048Key();
     if (!rsa_2048) {
@@ -149,13 +147,13 @@ static bool load_key(const std::string& file) {
     if (!already_loaded) {
         g_keys[fingerprint] = std::move(key);
     }
-    LOG(INFO) << (already_loaded ? "ignored already-loaded" : "loaded new") << " key from '" << file
-              << "' with fingerprint " << SHA256BitsToHexString(fingerprint);
+    VLOG(AUTH) << (already_loaded ? "ignored already-loaded" : "loaded new") << " key from '"
+               << file << "' with fingerprint " << SHA256BitsToHexString(fingerprint);
     return true;
 }
 
 static bool load_keys(const std::string& path, bool allow_dir = true) {
-    LOG(INFO) << "load_keys '" << path << "'...";
+    VLOG(AUTH) << "load_keys '" << path << "'...";
 
     struct stat st;
     if (stat(path.c_str(), &st) != 0) {
@@ -191,7 +189,7 @@ static bool load_keys(const std::string& path, bool allow_dir = true) {
             }
 
             if (!android::base::EndsWith(name, ".adb_key")) {
-                LOG(INFO) << "skipped non-adb_key '" << path << "/" << name << "'";
+                VLOG(AUTH) << "skipped non-adb_key '" << path << "/" << name << "'";
                 continue;
             }
 
@@ -217,7 +215,7 @@ static bool load_userkey() {
 
     struct stat buf;
     if (stat(path.c_str(), &buf) == -1) {
-        LOG(INFO) << "User key '" << path << "' does not exist...";
+        VLOG(AUTH) << "User key '" << path << "' does not exist...";
         if (!generate_key(path)) {
             LOG(ERROR) << "Failed to generate new key";
             return false;
@@ -259,7 +257,7 @@ std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys() {
 
 static std::string adb_auth_sign(RSA* key, const char* token, size_t token_size) {
     if (token_size != TOKEN_SIZE) {
-        D("Unexpected token size %zd", token_size);
+        LOG(WARNING) << "Unexpected token size=" << token_size;
         return std::string();
     }
 
@@ -274,7 +272,7 @@ static std::string adb_auth_sign(RSA* key, const char* token, size_t token_size)
 
     result.resize(len);
 
-    D("adb_auth_sign len=%d", len);
+    VLOG(AUTH) << "adb_auth_sign len=" << len;
     return result;
 }
 
@@ -337,7 +335,7 @@ int adb_auth_pubkey(const char* filename) {
 
 #if defined(__linux__)
 static void adb_auth_inotify_update(int fd, unsigned fd_event, void*) {
-    LOG(INFO) << "adb_auth_inotify_update called";
+    VLOG(AUTH) << "adb_auth_inotify_update called";
     if (!(fd_event & FDE_READ)) {
         return;
     }
@@ -347,7 +345,7 @@ static void adb_auth_inotify_update(int fd, unsigned fd_event, void*) {
         ssize_t rc = TEMP_FAILURE_RETRY(unix_read(fd, buf, sizeof(buf)));
         if (rc == -1) {
             if (errno == EAGAIN) {
-                LOG(INFO) << "done reading inotify fd";
+                VLOG(AUTH) << "done reading inotify fd";
                 break;
             }
             PLOG(FATAL) << "read of inotify event failed";
@@ -372,9 +370,9 @@ static void adb_auth_inotify_update(int fd, unsigned fd_event, void*) {
 
             if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                 if (event->mask & IN_ISDIR) {
-                    LOG(INFO) << "ignoring new directory at '" << path << "'";
+                    VLOG(AUTH) << "ignoring new directory at '" << path << "'";
                 } else {
-                    LOG(INFO) << "observed new file at '" << path << "'";
+                    VLOG(AUTH) << "observed new file at '" << path << "'";
                     load_keys(path, false);
                 }
             } else {
@@ -388,7 +386,7 @@ static void adb_auth_inotify_update(int fd, unsigned fd_event, void*) {
 }
 
 static void adb_auth_inotify_init(const std::set<std::string>& paths) {
-    LOG(INFO) << "adb_auth_inotify_init...";
+    VLOG(AUTH) << "adb_auth_inotify_init...";
 
     int infd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
     if (infd < 0) {
@@ -404,7 +402,7 @@ static void adb_auth_inotify_init(const std::set<std::string>& paths) {
         }
 
         g_monitored_paths[wd] = path;
-        LOG(INFO) << "watch descriptor " << wd << " registered for '" << path << "'";
+        VLOG(AUTH) << "watch descriptor " << wd << " registered for '" << path << "'";
     }
 
     fdevent* event = fdevent_create(infd, adb_auth_inotify_update, nullptr);
@@ -413,7 +411,7 @@ static void adb_auth_inotify_init(const std::set<std::string>& paths) {
 #endif
 
 void adb_auth_init() {
-    LOG(INFO) << "adb_auth_init...";
+    VLOG(AUTH) << "adb_auth_init...";
 
     if (!load_userkey()) {
         LOG(ERROR) << "Failed to load (or generate) user key";
@@ -432,16 +430,16 @@ void adb_auth_init() {
 }
 
 static void send_auth_publickey(atransport* t) {
-    LOG(INFO) << "Calling send_auth_publickey";
+    VLOG(AUTH) << "Calling send_auth_publickey";
 
     std::string key = adb_auth_get_userkey();
     if (key.empty()) {
-        D("Failed to get user public key");
+        LOG(WARNING) << "Failed to get user public key";
         return;
     }
 
     if (key.size() >= MAX_PAYLOAD_V1) {
-        D("User public key too large (%zu B)", key.size());
+        LOG(WARNING) << "User public key too large " << key.size() << " bytes";
         return;
     }
 
@@ -465,12 +463,12 @@ void send_auth_response(const char* token, size_t token_size, atransport* t) {
         return;
     }
 
-    LOG(INFO) << "Calling send_auth_response";
+    VLOG(AUTH) << "Calling send_auth_response";
     apacket* p = get_apacket();
 
     std::string result = adb_auth_sign(key.get(), token, token_size);
     if (result.empty()) {
-        D("Error signing the token");
+        LOG(WARNING) << "Error signing the token";
         put_apacket(p);
         return;
     }
@@ -487,17 +485,17 @@ void adb_auth_tls_handshake(atransport* t) {
         std::shared_ptr<RSA> key = t->Key();
         if (key == nullptr) {
             // Can happen if !auth_required
-            LOG(INFO) << "t->auth_key not set before handshake";
+            VLOG(AUTH) << "t->auth_key not set before handshake";
             key = t->NextKey();
             CHECK(key);
         }
 
-        LOG(INFO) << "Attempting to TLS handshake";
+        VLOG(AUTH) << "Attempting to TLS handshake";
         bool success = t->connection()->DoTlsHandshake(key.get());
         if (success) {
-            LOG(INFO) << "Handshake succeeded. Waiting for CNXN packet...";
+            VLOG(AUTH) << "Handshake succeeded. Waiting for CNXN packet...";
         } else {
-            LOG(INFO) << "Handshake failed. Kicking transport";
+            VLOG(AUTH) << "Handshake failed. Kicking transport";
             t->Kick();
         }
     }).detach();
@@ -510,13 +508,13 @@ void adb_auth_tls_handshake(atransport* t) {
 // See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_set_cert_cb
 // for more details.
 int adb_tls_set_certificate(SSL* ssl) {
-    LOG(INFO) << __func__;
+    VLOG(AUTH) << __func__;
 
     const STACK_OF(X509_NAME)* ca_list = SSL_get_client_CA_list(ssl);
     if (ca_list == nullptr) {
         // Either the device doesn't know any keys, or !auth_required.
         // So let's just try with the default certificate and see what happens.
-        LOG(INFO) << "No client CA list. Trying with default certificate.";
+        VLOG(AUTH) << "No client CA list. Trying with default certificate.";
         return 1;
     }
 
@@ -530,7 +528,7 @@ int adb_tls_set_certificate(SSL* ssl) {
             continue;
         }
 
-        LOG(INFO) << "Checking for fingerprint match [" << *adbFingerprint << "]";
+        VLOG(AUTH) << "Checking for fingerprint match [" << *adbFingerprint << "]";
         auto encoded_key = SHA256HexStringToBits(*adbFingerprint);
         if (!encoded_key.has_value()) {
             continue;
@@ -539,7 +537,7 @@ int adb_tls_set_certificate(SSL* ssl) {
         std::lock_guard<std::mutex> lock(g_keys_mutex);
         auto rsa_priv_key = g_keys.find(*encoded_key);
         if (rsa_priv_key != g_keys.end()) {
-            LOG(INFO) << "Got SHA256 match on a key";
+            VLOG(AUTH) << "Got SHA256 match on a key";
             bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
             CHECK(EVP_PKEY_set1_RSA(evp_pkey.get(), rsa_priv_key->second.get()));
             auto x509 = GenerateX509Certificate(evp_pkey.get());
@@ -548,7 +546,7 @@ int adb_tls_set_certificate(SSL* ssl) {
             TlsConnection::SetCertAndKey(ssl, x509_str, evp_str);
             return 1;
         } else {
-            LOG(INFO) << "No match for [" << *adbFingerprint << "]";
+            VLOG(AUTH) << "No match for [" << *adbFingerprint << "]";
         }
     }
 
diff --git a/client/commandline.cpp b/client/commandline.cpp
index 6620836f..876d13e9 100644
--- a/client/commandline.cpp
+++ b/client/commandline.cpp
@@ -82,6 +82,8 @@ static std::string product_file(const std::string& file) {
     return std::string{ANDROID_PRODUCT_OUT} + OS_PATH_SEPARATOR_STR + file;
 }
 
+static constexpr int kDefaultServerPort = 5037;
+
 static void help() {
     fprintf(stdout, "%s\n", adb_version().c_str());
     // clang-format off
@@ -1150,7 +1152,7 @@ static int logcat(int argc, const char** argv) {
     char* log_tags = getenv("ANDROID_LOG_TAGS");
     std::string quoted = escape_arg(log_tags == nullptr ? "" : log_tags);
 
-    std::string cmd = "export ANDROID_LOG_TAGS=\"" + quoted + "\"; exec logcat";
+    std::string cmd = "export ANDROID_LOG_TAGS=" + quoted + "; exec logcat";
 
     if (!strcmp(argv[0], "longcat")) {
         cmd += " -v long";
@@ -1671,7 +1673,7 @@ int adb_commandline(int argc, const char** argv) {
         // tcp:1234 and tcp:localhost:1234 are different with -a, so don't default to localhost
         server_host_str = server_host_str ? server_host_str : getenv("ANDROID_ADB_SERVER_ADDRESS");
 
-        int server_port = DEFAULT_ADB_PORT;
+        int server_port = kDefaultServerPort;
         server_port_str = server_port_str ? server_port_str : getenv("ANDROID_ADB_SERVER_PORT");
         if (server_port_str && strlen(server_port_str) > 0) {
             if (!android::base::ParseInt(server_port_str, &server_port, 1, 65535)) {
diff --git a/client/main.cpp b/client/main.cpp
index 15308287..59d8403e 100644
--- a/client/main.cpp
+++ b/client/main.cpp
@@ -37,6 +37,7 @@
 #include "adb_mdns.h"
 #include "adb_utils.h"
 #include "adb_wifi.h"
+#include "client/transport_client.h"
 #include "client/usb.h"
 #include "commandline.h"
 #include "sysdeps/chrono.h"
@@ -147,7 +148,8 @@ int adb_server_main(int is_daemon, const std::string& socket_spec, const char* o
     }
 
     if (!getenv("ADB_EMU") || strcmp(getenv("ADB_EMU"), "0") != 0) {
-        local_init(android::base::StringPrintf("tcp:%d", DEFAULT_ADB_LOCAL_TRANSPORT_PORT));
+        init_emulator_scanner(
+                android::base::StringPrintf("tcp:%d", DEFAULT_ADB_LOCAL_TRANSPORT_PORT));
     }
 
     std::string error;
diff --git a/client/transport_client.h b/client/transport_client.h
new file mode 100644
index 00000000..58b7c7a0
--- /dev/null
+++ b/client/transport_client.h
@@ -0,0 +1,22 @@
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
+#pragma once
+
+#include <string>
+
+// Start scanning for emulator on localhost interface
+void init_emulator_scanner(const std::string& addr);
diff --git a/client/transport_local.cpp b/client/transport_emulator.cpp
similarity index 85%
rename from client/transport_local.cpp
rename to client/transport_emulator.cpp
index 15a07246..e9ebaaa6 100644
--- a/client/transport_local.cpp
+++ b/client/transport_emulator.cpp
@@ -51,8 +51,6 @@
 // Once emulators self-(re-)register, they'll have to avoid 5601 in their own way.
 static int adb_local_transport_max_port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT + 16 * 2 - 1;
 
-static std::mutex& local_transports_lock = *new std::mutex();
-
 static void adb_local_transport_max_port_env_override() {
     const char* env_max_s = getenv("ADB_LOCAL_TRANSPORT_MAX_PORT");
     if (env_max_s != nullptr) {
@@ -68,14 +66,15 @@ static void adb_local_transport_max_port_env_override() {
     }
 }
 
+static std::mutex& emulator_transports_lock = *new std::mutex();
 // We keep a map from emulator port to transport.
 // TODO: weak_ptr?
-static std::unordered_map<int, atransport*> local_transports
-        [[clang::no_destroy]] GUARDED_BY(local_transports_lock);
+static std::unordered_map<int, atransport*> emulator_transports
+        [[clang::no_destroy]] GUARDED_BY(emulator_transports_lock);
 
-bool local_connect(int port) {
+bool connect_emulator(int port) {
     std::string dummy;
-    return local_connect_arbitrary_ports(port - 1, port, &dummy) == 0;
+    return connect_emulator_arbitrary_ports(port - 1, port, &dummy) == 0;
 }
 
 void connect_device(const std::string& address, std::string* response) {
@@ -114,12 +113,12 @@ void connect_device(const std::string& address, std::string* response) {
         // invoked if the atransport* has already been setup. This eventually
         // calls atransport->SetConnection() with a newly created Connection*
         // that will in turn send the CNXN packet.
-        return init_socket_transport(t, std::move(fd), port, 0) >= 0 ? ReconnectResult::Success
-                                                                     : ReconnectResult::Retry;
+        return init_socket_transport(t, std::move(fd), port, false) >= 0 ? ReconnectResult::Success
+                                                                         : ReconnectResult::Retry;
     };
 
     int error;
-    if (!register_socket_transport(std::move(fd), serial, port, 0, std::move(reconnect), false,
+    if (!register_socket_transport(std::move(fd), serial, port, false, std::move(reconnect), false,
                                    &error)) {
         if (error == EALREADY) {
             *response = android::base::StringPrintf("already connected to %s", serial.c_str());
@@ -133,7 +132,7 @@ void connect_device(const std::string& address, std::string* response) {
     }
 }
 
-int local_connect_arbitrary_ports(int console_port, int adb_port, std::string* error) {
+int connect_emulator_arbitrary_ports(int console_port, int adb_port, std::string* error) {
     unique_fd fd;
 
     if (find_emulator_transport_by_adb_port(adb_port) != nullptr ||
@@ -156,7 +155,7 @@ int local_connect_arbitrary_ports(int console_port, int adb_port, std::string* e
         disable_tcp_nagle(fd.get());
         std::string serial = getEmulatorSerialString(console_port);
         if (register_socket_transport(
-                    std::move(fd), std::move(serial), adb_port, 1,
+                    std::move(fd), std::move(serial), adb_port, true,
                     [](atransport*) { return ReconnectResult::Abort; }, false)) {
             return 0;
         }
@@ -168,7 +167,7 @@ static void PollAllLocalPortsForEmulator() {
     // Try to connect to any number of running emulator instances.
     for (int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT; port <= adb_local_transport_max_port;
          port += 2) {
-        local_connect(port);  // Note, uses port and port-1, so '=max_port' is OK.
+        connect_emulator(port);  // Note, uses port and port-1, so '=max_port' is OK.
     }
 }
 
@@ -187,8 +186,7 @@ std::mutex& retry_ports_lock = *new std::mutex;
 std::condition_variable& retry_ports_cond = *new std::condition_variable;
 
 static void client_socket_thread(std::string_view) {
-    adb_thread_setname("client_socket_thread");
-    D("transport: client_socket_thread() starting");
+    adb_thread_setname("emulator_scanner");
     PollAllLocalPortsForEmulator();
     while (true) {
         std::vector<RetryPort> ports;
@@ -210,7 +208,7 @@ static void client_socket_thread(std::string_view) {
         for (auto& port : ports) {
             VLOG(TRANSPORT) << "retry port " << port.port << ", last retry_count "
                             << port.retry_count;
-            if (local_connect(port.port)) {
+            if (connect_emulator(port.port)) {
                 VLOG(TRANSPORT) << "retry port " << port.port << " successfully";
                 continue;
             }
@@ -229,8 +227,8 @@ static void client_socket_thread(std::string_view) {
     }
 }
 
-void local_init(const std::string& addr) {
-    D("transport: local client init");
+void init_emulator_scanner(const std::string& addr) {
+    VLOG(TRANSPORT) << "Starting emulator scanner on '" << addr << "'";
     std::thread(client_socket_thread, addr).detach();
     adb_local_transport_max_port_env_override();
 }
@@ -250,26 +248,26 @@ struct EmulatorConnection : public FdConnection {
     }
 
     void Close() override {
-        std::lock_guard<std::mutex> lock(local_transports_lock);
-        local_transports.erase(local_port_);
+        std::lock_guard<std::mutex> lock(emulator_transports_lock);
+        emulator_transports.erase(local_port_);
         FdConnection::Close();
     }
 
     int local_port_;
 };
 
-/* Only call this function if you already hold local_transports_lock. */
+/* Only call this function if you already hold emulator_transports_lock. */
 static atransport* find_emulator_transport_by_adb_port_locked(int adb_port)
-        REQUIRES(local_transports_lock) {
-    auto it = local_transports.find(adb_port);
-    if (it == local_transports.end()) {
+        REQUIRES(emulator_transports_lock) {
+    auto it = emulator_transports.find(adb_port);
+    if (it == emulator_transports.end()) {
         return nullptr;
     }
     return it->second;
 }
 
 atransport* find_emulator_transport_by_adb_port(int adb_port) {
-    std::lock_guard<std::mutex> lock(local_transports_lock);
+    std::lock_guard<std::mutex> lock(emulator_transports_lock);
     return find_emulator_transport_by_adb_port_locked(adb_port);
 }
 
@@ -281,23 +279,21 @@ std::string getEmulatorSerialString(int console_port) {
     return android::base::StringPrintf("emulator-%d", console_port);
 }
 
-int init_socket_transport(atransport* t, unique_fd fd, int adb_port, int local) {
+int init_socket_transport(atransport* t, unique_fd fd, int adb_port, bool is_emulator) {
     int fail = 0;
 
-    t->type = kTransportLocal;
-
-    // Emulator connection.
-    if (local) {
+    if (is_emulator) {
         auto emulator_connection = std::make_unique<EmulatorConnection>(std::move(fd), adb_port);
         t->SetConnection(
                 std::make_unique<BlockingConnectionAdapter>(std::move(emulator_connection)));
-        std::lock_guard<std::mutex> lock(local_transports_lock);
+        std::lock_guard<std::mutex> lock(emulator_transports_lock);
         atransport* existing_transport = find_emulator_transport_by_adb_port_locked(adb_port);
         if (existing_transport != nullptr) {
-            D("local transport for port %d already registered (%p)?", adb_port, existing_transport);
+            D("is_emulator transport for port %d already registered (%p)?", adb_port,
+              existing_transport);
             fail = -1;
         } else {
-            local_transports[adb_port] = t;
+            emulator_transports[adb_port] = t;
         }
 
         return fail;
diff --git a/client/transport_usb.cpp b/client/transport_usb.cpp
index 58d50252..3b0b4906 100644
--- a/client/transport_usb.cpp
+++ b/client/transport_usb.cpp
@@ -164,7 +164,6 @@ void init_usb_transport(atransport* t, usb_handle* h) {
     D("transport: usb");
     auto connection = std::make_unique<UsbConnection>(h);
     t->SetConnection(std::make_unique<BlockingConnectionAdapter>(std::move(connection)));
-    t->type = kTransportUsb;
     t->SetUsbHandle(h);
 }
 
diff --git a/client/usb_libusb.cpp b/client/usb_libusb.cpp
index 46d8464b..8ada3303 100644
--- a/client/usb_libusb.cpp
+++ b/client/usb_libusb.cpp
@@ -173,7 +173,8 @@ struct LibusbConnection : public Connection {
         }
 
         if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
-            std::string msg = StringPrintf("usb read failed: status = %d", transfer->status);
+            std::string msg =
+                    StringPrintf("usb read failed: '%s'", libusb_error_name(transfer->status));
             LOG(ERROR) << msg;
             if (!self->detached_) {
                 self->OnError(msg);
@@ -222,7 +223,8 @@ struct LibusbConnection : public Connection {
         }
 
         if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
-            std::string msg = StringPrintf("usb read failed: status = %d", transfer->status);
+            std::string msg =
+                    StringPrintf("usb read failed: '%s'", libusb_error_name(transfer->status));
             LOG(ERROR) << msg;
             if (!self->detached_) {
                 self->OnError(msg);
@@ -722,7 +724,6 @@ struct LibusbConnection : public Connection {
             });
 
             incoming_header_.reset();
-            incoming_payload_.clear();
         }
 
         if (device_handle_) {
@@ -796,11 +797,13 @@ struct LibusbConnection : public Connection {
         }
     }
 
-    virtual void Start() override final {
+    virtual bool Start() override final {
         std::string error;
         if (!Attach(&error)) {
             OnError(error);
+            return false;
         }
+        return true;
     }
 
     virtual void Stop() override final {
@@ -876,7 +879,6 @@ struct LibusbConnection : public Connection {
     ReadBlock header_read_ GUARDED_BY(read_mutex_);
     ReadBlock payload_read_ GUARDED_BY(read_mutex_);
     std::optional<amessage> incoming_header_ GUARDED_BY(read_mutex_);
-    IOVector incoming_payload_ GUARDED_BY(read_mutex_);
 
     std::mutex write_mutex_;
     std::unordered_map<TransferId, std::unique_ptr<WriteBlock>> writes_ GUARDED_BY(write_mutex_);
@@ -918,7 +920,8 @@ static void process_device(libusb_device* device_raw) {
     VLOG(USB) << "constructed LibusbConnection for device " << connection->serial_ << " ("
               << device_address << ")";
 
-    register_usb_transport(connection, connection->serial_.c_str(), device_address.c_str(), true);
+    register_libusb_transport(connection, connection->serial_.c_str(), device_address.c_str(),
+                              true);
 }
 
 static void device_connected(libusb_device* device) {
diff --git a/client/usb_osx.cpp b/client/usb_osx.cpp
index ce3f5df9..0e5af487 100644
--- a/client/usb_osx.cpp
+++ b/client/usb_osx.cpp
@@ -350,6 +350,66 @@ static bool ClearPipeStallBothEnds(IOUSBInterfaceInterface550** interface, UInt8
     return true;
 }
 
+static std::string darwinErrorToString(IOReturn result) {
+    switch (result) {
+        case kIOReturnSuccess:
+            return "no error";
+        case kIOReturnNotOpen:
+            return "device not opened for exclusive access";
+        case kIOReturnNoDevice:
+            return "no connection to an IOService";
+        case kIOUSBNoAsyncPortErr:
+            return "no async port has been opened for interface";
+        case kIOReturnExclusiveAccess:
+            return "another process has device opened for exclusive access";
+        case kIOUSBPipeStalled:
+#if defined(kUSBHostReturnPipeStalled)
+        case kUSBHostReturnPipeStalled:
+#endif
+            return "pipe is stalled";
+        case kIOReturnError:
+            return "could not establish a connection to the Darwin kernel";
+        case kIOUSBTransactionTimeout:
+            return "transaction timed out";
+        case kIOReturnBadArgument:
+            return "invalid argument";
+        case kIOReturnAborted:
+            return "transaction aborted";
+        case kIOReturnNotResponding:
+            return "device not responding";
+        case kIOReturnOverrun:
+            return "data overrun";
+        case kIOReturnCannotWire:
+            return "physical memory can not be wired down";
+        case kIOReturnNoResources:
+            return "out of resources";
+        case kIOUSBHighSpeedSplitError:
+            return "high speed split error";
+        case kIOUSBUnknownPipeErr:
+            return "pipe ref not recognized";
+        default:
+            return std::format("unknown error ({:#x})", result);
+    }
+}
+
+static void dumpEndpointProperties(const std::string& label,
+                                   const IOUSBEndpointProperties& properties) {
+    VLOG(USB) << std::endl << label;
+    VLOG(USB) << "    wMaxPacketSize=" << properties.wMaxPacketSize;
+    VLOG(USB) << "    bTransferType=" << static_cast<unsigned>(properties.bTransferType);
+    VLOG(USB) << "    bDirection=" << static_cast<unsigned>(properties.bDirection);
+    VLOG(USB) << "    bAlternateSetting=" << static_cast<unsigned>(properties.bAlternateSetting);
+    VLOG(USB) << "    bMult=" << static_cast<unsigned>(properties.bMult);
+    VLOG(USB) << "    bMaxBurst=" << static_cast<unsigned>(properties.bMaxBurst);
+    VLOG(USB) << "    bEndpointNumber=" << static_cast<unsigned>(properties.bEndpointNumber);
+    VLOG(USB) << "    bInterval=" << static_cast<unsigned>(properties.bInterval);
+    VLOG(USB) << "    bMaxStreams=" << static_cast<unsigned>(properties.bMaxStreams);
+    VLOG(USB) << "    bSyncType=" << static_cast<unsigned>(properties.bSyncType);
+    VLOG(USB) << "    bUsageType=" << static_cast<unsigned>(properties.bUsageType);
+    VLOG(USB) << "    bVersion=" << static_cast<unsigned>(properties.bVersion);
+    VLOG(USB) << "    wBytesPerInterval=" << static_cast<unsigned>(properties.wBytesPerInterval);
+}
+
 //* TODO: simplify this further since we only register to get ADB interface
 //* subclass+protocol events
 static std::unique_ptr<usb_handle> CheckInterface(IOUSBInterfaceInterface550** interface,
@@ -396,43 +456,34 @@ static std::unique_ptr<usb_handle> CheckInterface(IOUSBInterfaceInterface550** i
     //* Iterate over the endpoints for this interface and find the first
     //* bulk in/out pipes available.  These will be our read/write pipes.
     for (endpoint = 1; endpoint <= interfaceNumEndpoints; ++endpoint) {
-        UInt8   transferType;
-        UInt16  endPointMaxPacketSize = 0;
-        UInt8   interval;
-
-        // Attempt to retrieve the 'true' packet-size from supported interface.
-        kr = (*interface)
-                 ->GetEndpointProperties(interface, 0, endpoint,
-                    kUSBOut,
-                    &transferType,
-                    &endPointMaxPacketSize, &interval);
-        if (kr == kIOReturnSuccess) {
-            CHECK_NE(0, endPointMaxPacketSize);
+        VLOG(USB) << std::endl << "Inspecting endpoint " << static_cast<unsigned>(endpoint);
+        IOUSBEndpointProperties properties = {.bVersion = kUSBEndpointPropertiesVersion3};
+
+        // We only call GetPipePropertiesV3 so it populates the IOUSBEndpointProperties field
+        // needed for GetEndpointPropertiesV3. We don't use wMaxPacketSize returned here
+        // because it is the FULL maxPacketSize which includes burst and mul.
+        kr = (*interface)->GetPipePropertiesV3(interface, endpoint, &properties);
+        if (kr != kIOReturnSuccess) {
+            LOG(ERROR) << "GetPipePropertiesV3 error : " << darwinErrorToString(kr);
+            goto err_get_pipe_props;
         }
+        dumpEndpointProperties("GetPipePropertiesV3 values", properties);
 
-        UInt16  pipePropMaxPacketSize;
-        UInt8   number;
-        UInt8   direction;
-        UInt8 maxBurst;
-        UInt8 mult;
-        UInt16 bytesPerInterval;
-
-        // Proceed with extracting the transfer direction, so we can fill in the
-        // appropriate fields (bulkIn or bulkOut).
-        kr = (*interface)->GetPipePropertiesV2(interface, endpoint,
-                                       &direction, &number, &transferType,
-                                       &pipePropMaxPacketSize, &interval,
-                                       &maxBurst, &mult,
-                                       &bytesPerInterval);
+        // GetEndpointPropertiesV3 needs IOUSBEndpointProperties fields bVersion, bAlternateSetting,
+        // bDirection, and bEndPointNumber to be set before calling. This was done by
+        // GetPipePropertiesV3.
+        kr = (*interface)->GetEndpointPropertiesV3(interface, &properties);
         if (kr != kIOReturnSuccess) {
-            LOG(ERROR) << "FindDeviceInterface - could not get pipe properties: "
-                       << std::hex << kr;
+            LOG(ERROR) << "GetEndpointPropertiesV3 error : " << darwinErrorToString(kr);
             goto err_get_pipe_props;
         }
+        dumpEndpointProperties("GetEndpointPropertiesV3 values", properties);
 
-        if (kUSBBulk != transferType) continue;
+        if (properties.bTransferType != kUSBBulk) {
+            continue;
+        }
 
-        if (kUSBIn == direction) {
+        if (properties.bDirection == kUSBIn) {
             handle->bulkIn = endpoint;
 
             if (!ClearPipeStallBothEnds(interface, handle->bulkIn)) {
@@ -440,25 +491,15 @@ static std::unique_ptr<usb_handle> CheckInterface(IOUSBInterfaceInterface550** i
             }
         }
 
-        if (kUSBOut == direction) {
+        if (properties.bDirection == kUSBOut) {
             handle->bulkOut = endpoint;
+            handle->zero_mask = properties.wMaxPacketSize - 1;
+            handle->max_packet_size = properties.wMaxPacketSize;
 
             if (!ClearPipeStallBothEnds(interface, handle->bulkOut)) {
                 goto err_get_pipe_props;
             }
         }
-
-        // Compute the packet-size, in case the system did not return the correct value.
-        if (endPointMaxPacketSize == 0 && maxBurst != 0) {
-            // bMaxBurst is the number of additional packets in the burst.
-            endPointMaxPacketSize = pipePropMaxPacketSize / (maxBurst + 1);
-        }
-
-        // mult is only relevant for isochronous endpoints.
-        CHECK_EQ(0, mult);
-
-        handle->zero_mask = endPointMaxPacketSize - 1;
-        handle->max_packet_size = endPointMaxPacketSize;
     }
 
     handle->interface = interface;
diff --git a/daemon/adb_wifi.cpp b/daemon/adb_wifi.cpp
index 8c93aebb..a62db3a0 100644
--- a/daemon/adb_wifi.cpp
+++ b/daemon/adb_wifi.cpp
@@ -140,7 +140,7 @@ void TlsServer::OnFdEvent(int fd, unsigned ev) {
         disable_tcp_nagle(new_fd.get());
         std::string serial = android::base::StringPrintf("host-%d", new_fd.get());
         register_socket_transport(
-                std::move(new_fd), std::move(serial), port_, 1,
+                std::move(new_fd), std::move(serial), port_, false,
                 [](atransport*) { return ReconnectResult::Abort; }, true);
     }
 }
diff --git a/daemon/main.cpp b/daemon/main.cpp
index 77e535af..931b1702 100644
--- a/daemon/main.cpp
+++ b/daemon/main.cpp
@@ -51,14 +51,17 @@
 #include "adb_utils.h"
 #include "adb_wifi.h"
 #include "socket_spec.h"
+#include "tradeinmode.h"
 #include "transport.h"
 
 #include "daemon/jdwp_service.h"
 #include "daemon/mdns.h"
+#include "daemon/transport_daemon.h"
 #include "daemon/watchdog.h"
 
 #if defined(__ANDROID__)
 static const char* root_seclabel = nullptr;
+static const char* tim_seclabel = nullptr;
 
 static bool should_drop_privileges() {
     // The properties that affect `adb root` and `adb unroot` are ro.secure and
@@ -92,7 +95,7 @@ static bool should_drop_privileges() {
     return drop;
 }
 
-static void drop_privileges(int server_port) {
+static void drop_privileges() {
     ScopedMinijail jail(minijail_new());
 
     // Add extra groups:
@@ -115,7 +118,6 @@ static void drop_privileges(int server_port) {
                       AID_EXT_OBB_RW,   AID_READTRACEFS};
     minijail_set_supplementary_gids(jail.get(), arraysize(groups), groups);
 
-    // Don't listen on a port (default 5037) if running in secure mode.
     // Don't run as root if running in secure mode.
     if (should_drop_privileges()) {
         const bool should_drop_caps = !__android_log_is_debuggable();
@@ -161,7 +163,12 @@ static void drop_privileges(int server_port) {
             PLOG(FATAL) << "cap_set_proc() failed";
         }
 
-        D("Local port disabled");
+        if (should_enter_tradeinmode()) {
+            enter_tradeinmode(tim_seclabel);
+            auth_required = false;
+        } else if (is_in_tradein_evaluation_mode()) {
+            auth_required = false;
+        }
     } else {
         // minijail_enter() will abort if any priv-dropping step fails.
         minijail_enter(jail.get());
@@ -197,11 +204,11 @@ static void setup_adb(const std::vector<std::string>& addrs) {
 #endif
     for (const auto& addr : addrs) {
         LOG(INFO) << "adbd listening on " << addr;
-        local_init(addr);
+        init_transport_socket_server(addr);
     }
 }
 
-int adbd_main(int server_port) {
+int adbd_main() {
     umask(0);
 
     signal(SIGPIPE, SIG_IGN);
@@ -237,7 +244,7 @@ int adbd_main(int server_port) {
     }
 
 #if defined(__ANDROID__)
-    drop_privileges(server_port);
+    drop_privileges();
 #endif
 
 #if defined(__ANDROID__)
@@ -317,6 +324,7 @@ int main(int argc, char** argv) {
     while (true) {
         static struct option opts[] = {
                 {"root_seclabel", required_argument, nullptr, 's'},
+                {"tim_seclabel", required_argument, nullptr, 't'},
                 {"device_banner", required_argument, nullptr, 'b'},
                 {"version", no_argument, nullptr, 'v'},
                 {"logpostfsdata", no_argument, nullptr, 'l'},
@@ -334,6 +342,9 @@ int main(int argc, char** argv) {
             case 's':
                 root_seclabel = optarg;
                 break;
+            case 't':
+                tim_seclabel = optarg;
+                break;
 #endif
             case 'b':
                 adb_device_banner = optarg;
@@ -356,5 +367,5 @@ int main(int argc, char** argv) {
     adb_trace_init(argv);
 
     D("Handling main()");
-    return adbd_main(DEFAULT_ADB_PORT);
+    return adbd_main();
 }
diff --git a/daemon/services.cpp b/daemon/services.cpp
index 50904410..152603cb 100644
--- a/daemon/services.cpp
+++ b/daemon/services.cpp
@@ -51,6 +51,7 @@
 #include "services.h"
 #include "socket_spec.h"
 #include "sysdeps.h"
+#include "tradeinmode.h"
 #include "transport.h"
 
 #include "daemon/file_sync_service.h"
@@ -275,6 +276,10 @@ asocket* daemon_service_to_socket(std::string_view name, atransport* transport)
 unique_fd daemon_service_to_fd(std::string_view name, atransport* transport) {
     ADB_LOG(Service) << "transport " << transport->serial_name() << " opening service " << name;
 
+    if (is_in_tradeinmode() && !allow_tradeinmode_command(name)) {
+        return unique_fd{};
+    }
+
 #if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
     if (name.starts_with("abb:") || name.starts_with("abb_exec:")) {
         return execute_abb_command(name);
diff --git a/daemon/tradeinmode.cpp b/daemon/tradeinmode.cpp
new file mode 100644
index 00000000..2b27e50d
--- /dev/null
+++ b/daemon/tradeinmode.cpp
@@ -0,0 +1,88 @@
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
+#include <unistd.h>
+
+#include <regex>
+
+#include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+
+#if defined(__ANDROID__)
+#include <log/log_properties.h>
+#include "selinux/android.h"
+#endif
+
+#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
+#include <com_android_tradeinmode_flags.h>
+#endif
+
+static bool in_tradeinmode = false;
+static constexpr char kTradeInModeProp[] = "persist.adb.tradeinmode";
+
+static constexpr int TIM_DISABLED = -1;
+static constexpr int TIM_UNSET = 0;
+static constexpr int TIM_FOYER = 1;
+static constexpr int TIM_EVALUATION_MODE = 2;
+
+bool should_enter_tradeinmode() {
+#if defined(__ANDROID__) && !defined(__ANDROID_RECOVERY__)
+    if (!com_android_tradeinmode_flags_enable_trade_in_mode()) {
+        return false;
+    }
+    return android::base::GetIntProperty(kTradeInModeProp, TIM_UNSET) == TIM_FOYER;
+#else
+    return false;
+#endif
+}
+
+void enter_tradeinmode(const char* seclabel) {
+#if defined(__ANDROID__)
+    if (selinux_android_setcon(seclabel) < 0) {
+        PLOG(ERROR) << "Could not set SELinux context";
+
+        // Flag TIM as failed so we don't enter a restart loop.
+        android::base::SetProperty(kTradeInModeProp, std::to_string(TIM_DISABLED));
+
+        _exit(1);
+    }
+
+    // Keep a separate global flag for TIM in case the property changes (for
+    // example, if it's set while as root for testing).
+    in_tradeinmode = true;
+#endif
+}
+
+bool is_in_tradeinmode() {
+    return in_tradeinmode;
+}
+
+bool is_in_tradein_evaluation_mode() {
+    return android::base::GetIntProperty(kTradeInModeProp, TIM_UNSET) == TIM_EVALUATION_MODE;
+}
+
+bool allow_tradeinmode_command(std::string_view name) {
+#if defined(__ANDROID__)
+    // Allow "adb root" from trade-in-mode so that automated testing is possible.
+    if (__android_log_is_debuggable() && android::base::ConsumePrefix(&name, "root:")) {
+        return true;
+    }
+#endif
+
+    // Allow "shell tradeinmode" with only simple arguments.
+    std::regex tim_pattern("shell[^:]*:tradeinmode(\\s*|\\s[A-Za-z0-9_\\-\\s]*)");
+    return std::regex_match(std::string(name), tim_pattern);
+}
diff --git a/daemon/tradeinmode.h b/daemon/tradeinmode.h
new file mode 100644
index 00000000..2982728f
--- /dev/null
+++ b/daemon/tradeinmode.h
@@ -0,0 +1,36 @@
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
+#pragma once
+
+#include <string_view>
+
+// Return true if adbd should transition to trade-in mode.
+bool should_enter_tradeinmode();
+
+// Transition adbd to the given trade-in mode secontext.
+void enter_tradeinmode(const char* seclabel);
+
+// Returns whether the given command string is allowed while in trade-in mode.
+bool allow_tradeinmode_command(std::string_view name);
+
+// Returns whether adbd is currently in trade-in mode (eg enter_tradeinmode was called).
+bool is_in_tradeinmode();
+
+// Returns whether the "tradeinmode enter" command was used. This command places the device in
+// "trade-in evaluation" mode, granting normal adb shell without authorization. In this mode, a
+// factory reset is guaranteed on reboot.
+bool is_in_tradein_evaluation_mode();
diff --git a/daemon/tradeinmode_test.cpp b/daemon/tradeinmode_test.cpp
new file mode 100644
index 00000000..8e0f75da
--- /dev/null
+++ b/daemon/tradeinmode_test.cpp
@@ -0,0 +1,29 @@
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
+#include "tradeinmode.h"
+
+#include <gtest/gtest.h>
+
+TEST(TradeInModeTest, ValidateCommand) {
+    EXPECT_FALSE(allow_tradeinmode_command("shell:blah"));
+    EXPECT_TRUE(allow_tradeinmode_command("shell,-x:tradeinmode"));
+    EXPECT_TRUE(allow_tradeinmode_command("shell:tradeinmode"));
+    EXPECT_FALSE(allow_tradeinmode_command("shell:tradeinmodebad"));
+    EXPECT_TRUE(allow_tradeinmode_command("shell:tradeinmode getstatus"));
+    EXPECT_TRUE(allow_tradeinmode_command("shell:tradeinmode getstatus -c 1234"));
+    EXPECT_TRUE(allow_tradeinmode_command("shell:tradeinmode enter"));
+    EXPECT_FALSE(allow_tradeinmode_command("shell:tradeinmode && ls"));
+}
diff --git a/daemon/transport_daemon.h b/daemon/transport_daemon.h
new file mode 100644
index 00000000..d7b2777b
--- /dev/null
+++ b/daemon/transport_daemon.h
@@ -0,0 +1,22 @@
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
+#pragma once
+
+#include <string>
+
+// Start the TCP server, to allow commands like `adb connect IP:PORT"
+void init_transport_socket_server(const std::string& addr);
diff --git a/daemon/transport_local.cpp b/daemon/transport_socket_server.cpp
similarity index 80%
rename from daemon/transport_local.cpp
rename to daemon/transport_socket_server.cpp
index 1b459e4e..9f1d0949 100644
--- a/daemon/transport_local.cpp
+++ b/daemon/transport_socket_server.cpp
@@ -38,9 +38,7 @@
 #include <android-base/thread_annotations.h>
 #include <cutils/sockets.h>
 
-#if !ADB_HOST
 #include <android-base/properties.h>
-#endif
 
 #include "adb.h"
 #include "adb_io.h"
@@ -49,16 +47,15 @@
 #include "socket_spec.h"
 #include "sysdeps/chrono.h"
 
-void server_socket_thread(std::function<unique_fd(std::string_view, std::string*)> listen_func,
-                          std::string_view addr) {
-    adb_thread_setname("server socket");
+void server_socket_thread(std::string_view addr) {
+    adb_thread_setname("server_socket");
 
     unique_fd serverfd;
     std::string error;
 
     while (serverfd == -1) {
         errno = 0;
-        serverfd = listen_func(addr, &error);
+        serverfd = unique_fd{socket_spec_listen(addr, &error, nullptr)};
         if (errno == EAFNOSUPPORT || errno == EINVAL || errno == EPROTONOSUPPORT) {
             D("unrecoverable error: '%s'", error.c_str());
             return;
@@ -81,25 +78,21 @@ void server_socket_thread(std::function<unique_fd(std::string_view, std::string*
             // We don't care about port value in "register_socket_transport" as it is used
             // only from ADB_HOST. "server_socket_thread" is never called from ADB_HOST.
             register_socket_transport(
-                    std::move(fd), std::move(serial), 0, 1,
+                    std::move(fd), std::move(serial), 0, false,
                     [](atransport*) { return ReconnectResult::Abort; }, false);
         }
     }
     D("transport: server_socket_thread() exiting");
 }
 
-unique_fd adb_listen(std::string_view addr, std::string* error) {
-    return unique_fd{socket_spec_listen(addr, error, nullptr)};
+void init_transport_socket_server(const std::string& addr) {
+    VLOG(TRANSPORT) << "Starting tcp server on '" << addr << "'";
+    std::thread(server_socket_thread, addr).detach();
 }
 
-void local_init(const std::string& addr) {
-    D("transport: local server init");
-    std::thread(server_socket_thread, adb_listen, addr).detach();
-}
-
-int init_socket_transport(atransport* t, unique_fd fd, int adb_port, int local) {
+int init_socket_transport(atransport* t, unique_fd fd, int, bool) {
     t->type = kTransportLocal;
     auto fd_connection = std::make_unique<FdConnection>(std::move(fd));
     t->SetConnection(std::make_unique<BlockingConnectionAdapter>(std::move(fd_connection)));
     return 0;
-}
+}
\ No newline at end of file
diff --git a/daemon/usb.cpp b/daemon/usb.cpp
index f9e085fb..bd881c7d 100644
--- a/daemon/usb.cpp
+++ b/daemon/usb.cpp
@@ -48,6 +48,7 @@
 
 #include "adb_unique_fd.h"
 #include "adb_utils.h"
+#include "apacket_reader.h"
 #include "daemon/property_monitor.h"
 #include "daemon/usb_ffs.h"
 #include "sysdeps/chrono.h"
@@ -213,7 +214,10 @@ struct UsbFfsConnection : public Connection {
         return true;
     }
 
-    virtual void Start() override final { StartMonitor(); }
+    virtual bool Start() override final {
+        StartMonitor();
+        return true;
+    }
 
     virtual void Stop() override final {
         if (stopped_.exchange(true)) {
@@ -420,7 +424,7 @@ struct UsbFfsConnection : public Connection {
                     LOG(FATAL) << "hit EOF on eventfd";
                 }
 
-                ReadEvents();
+                HandleEvents();
 
                 std::lock_guard<std::mutex> lock(write_mutex_);
                 SubmitWrites();
@@ -481,7 +485,7 @@ struct UsbFfsConnection : public Connection {
         return block;
     }
 
-    void ReadEvents() {
+    void HandleEvents() {
         static constexpr size_t kMaxEvents = kUsbReadQueueDepth + kUsbWriteQueueDepth;
         struct io_event events[kMaxEvents];
         struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
@@ -532,6 +536,7 @@ struct UsbFfsConnection : public Connection {
         uint64_t read_idx = id.id % kUsbReadQueueDepth;
         IoReadBlock* block = &read_requests_[read_idx];
         block->pending = false;
+        VLOG(USB) << "HandleRead, resizing from " << block->payload.size() << " to " << size;
         block->payload.resize(size);
 
         // Notification for completed reads can be received out of order.
@@ -558,43 +563,20 @@ struct UsbFfsConnection : public Connection {
 
     bool ProcessRead(IoReadBlock* block) {
         if (!block->payload.empty()) {
-            if (!incoming_header_.has_value()) {
-                if (block->payload.size() != sizeof(amessage)) {
-                    HandleError("received packet of unexpected length while reading header");
-                    return false;
-                }
-                amessage& msg = incoming_header_.emplace();
-                memcpy(&msg, block->payload.data(), sizeof(msg));
-                LOG(DEBUG) << "USB read:" << dump_header(&msg);
-                incoming_header_ = msg;
+            if (packet_reader_.add_bytes(std::move(block->payload)) != APacketReader::OK) {
+                HandleError("Error while reading USB block");
+                return false;
+            }
 
-                if (msg.command == A_CNXN) {
+            auto packets = packet_reader_.get_packets();
+            for (auto& p : packets) {
+                if (p->msg.command == A_CNXN) {
                     CancelWrites();
                 }
-            } else {
-                size_t bytes_left = incoming_header_->data_length - incoming_payload_.size();
-                if (block->payload.size() > bytes_left) {
-                    HandleError("received too many bytes while waiting for payload");
-                    return false;
-                }
-                incoming_payload_.append(std::move(block->payload));
+                transport_->HandleRead(std::move(p));
             }
 
-            if (incoming_header_->data_length == incoming_payload_.size()) {
-                auto packet = std::make_unique<apacket>();
-                packet->msg = *incoming_header_;
-
-                // TODO: Make apacket contain an IOVector so we don't have to coalesce.
-                packet->payload = std::move(incoming_payload_).coalesce();
-                transport_->HandleRead(std::move(packet));
-
-                incoming_header_.reset();
-                // reuse the capacity of the incoming payload while we can.
-                auto free_block = incoming_payload_.clear();
-                if (block->payload.capacity() == 0) {
-                    block->payload = std::move(free_block);
-                }
-            }
+            block->payload.clear();
         }
 
         PrepareReadBlock(block, block->id().id + kUsbReadQueueDepth);
@@ -721,8 +703,7 @@ struct UsbFfsConnection : public Connection {
     unique_fd write_fd_;
 
     bool connection_started_ = false;
-    std::optional<amessage> incoming_header_;
-    IOVector incoming_payload_;
+    APacketReader packet_reader_;
 
     std::array<IoReadBlock, kUsbReadQueueDepth> read_requests_;
     IOVector read_data_;
@@ -773,7 +754,7 @@ static void usb_ffs_open_thread() {
             LOG(INFO) << "resuming USB";
         }
 
-        atransport* transport = new atransport();
+        atransport* transport = new atransport(kTransportUsb);
         transport->serial = "UsbFfs";
         std::promise<void> destruction_notifier;
         std::future<void> future = destruction_notifier.get_future();
diff --git a/docs/dev/README.md b/docs/dev/README.md
index eabe3fee..9bdc1a5d 100644
--- a/docs/dev/README.md
+++ b/docs/dev/README.md
@@ -1,149 +1,8 @@
-# ADB Internals
-
-If you are new to adb source code, you should start by reading [overview.md](overview.md) which describes the three components of adb pipeline.
-
-This document gives the "big picture" which should allow you to build a mental map to help navigate the code.
-
-## Three components of adb pipeline
-
-As described in the [overview](overview.md), this codebase generates three components (Client, Server (a.k.a Host), and Daemon (a.k.a adbd)).
-
-The central part is the Server which runs on the Host computer. On one side the Server exposes a connection to Clients such as adb or DDMLIB.
-
-On the other side, the Server continuously monitors for connecting Daemons (such as USB devices or TCP emulator). Communication with a device is done with a Transport.
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
-The Client and the Server are contained in the same executable and both run on the Host machine. Code sections specific to the Host are enclosed within `ADB_HOST` guard. adbd runs on the Android Device. Daemon specific code is enclosed in `!ADB_HOST` but also sometimes within `__ANDROID__` guards.
-
-
-## "SMART SOCKET" and TRANSPORT
-
-A smart socket is a simple TCP socket with a smart protocol built on top of it which allows to target a device **after** the connection is initalized (see [services.md](services.md) families of `host:transport-` services for more information). This is what Clients connect onto from the Host side. The Client must always initiate communication via a human readable request but the response format varies. The smart protocol is documented in [services.md](services.md).
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
-The asocket, apacket, and amessage constructs exist only to wrap data while it transits on a Transport. An asocket handles a stream of apackets. An apacket consists of an amessage header featuring a command (`A_SYNC`, `A_OPEN`, `A_CLSE`, `A_WRTE`, `A_OKAY`, ...) followed by a payload (find more documentation in [protocol.md](protocol.md). There is no `A_READ` command because an asocket is unidirectional. To model a bi-directional stream, asocket have peers which go in the opposite direction.
-
-An asocket features a buffer containing apackets. If traffic is inbound, the buffer stores the apacket until it is consumed. If the traffic is oubound, the buffer stores apackets until they are sent down the wire (with `A_WRTE` commands).
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
-This system allows adb to multiplex data streams on an unique byte stream. Without going into too much detail, the amessage arg1 and arg2 fields are similar to the TCP local and remote ports, where the combination uniquely identifies a particular stream. Note that unlike TCP which features an [unacknowledged-send window](https://en.wikipedia.org/wiki/TCP_congestion_control), an apacket is sent only after the previous one has been confirmed to be received.
-This is more of an historical accident than a design decision.
-
-The two types of asocket (Remote and Local) differentiate between outbound and inbound traffic.
-
-## adbd <-> APPPLICATION communication
-
-This pipeline is detailed in [daemon/jdwp_service.cpp](../../daemon/jdwp_service.cpp) with ASCII drawings! The JDWP extension implemented by Dalvik/ART are documented in:
-- platform/dalvik/+/main/docs/debugmon.html
-- platform/dalvik/+/main/docs/debugger.html
-
-### Sync protocol
-
-To transfer files and directories, ADB places a smart-socket in SYNC mode and then issues SYNC commands. The SYNC protocol is documented in [sync.md](sync.md).
-Despite its name the `sync` protocol is also what powers operations such as `pull` and `push`.
-
-### ADB Wifi architecture
-
-[here](adb_wifi.md)
-
-### Benchmark sample run for Pixel 8,USB
-
-```
-$ ./benchmark_device.py 
-sink   100MiB (write RAM)  : 10 runs: median 128.07 MiB/s, mean 126.90 MiB/s, stddev: 19.37 MiB/s
-source 100MiB (read RAM)   : 10 runs: median 233.73 MiB/s, mean 250.81 MiB/s, stddev: 47.45 MiB/s
-push   100MiB (write flash): 10 runs: median 142.82 MiB/s, mean 145.49 MiB/s, stddev: 16.57 MiB/s
-pull   100MiB (read flash) : 10 runs: median 190.37 MiB/s, mean 189.08 MiB/s, stddev: 51.24 MiB/s
-dd     100MiB (write flash): 10 runs: median 121.57 MiB/s, mean 125.60 MiB/s, stddev: 15.81 MiB/s
-```
-
-### Tests
-
-#### Integration Tests
-Run integration tests as follows.
-
-```
-$ atest adb_integration_test_device
-$ atest adb_integration_test_adb
-```
-
-You can use a filter to run only a class of test.
-
-```
-atest adb_integration_test_device --test-filter=FileOperationsTest
-```
-
-You can also use the filter to run a single test in a class.
-
-```
-atest adb_integration_test_device --test-filter=FileOperationsTest#test_push_sync
-```
-
-#### Unit tests
-
-The list of all the units tests can be found in [TEST_MAPPING](../../TEST_MAPPING)
-
-
-### More Legacy documentation
-[socket-activation.md](socket-activation.md): ADB socket control protocol.
\ No newline at end of file
+# ADB Developer documentation
+
+- [Architecture](internals.md)
+- [Debugging](debugging.md)
+- [How root/unroot works](root.md)
+- [Understanding asocket](asocket.md)
+- [Trade-In Mode](adb_tradeinmode.md)
+- [How ADB uses USB Zero-length packets](zero_length_packet.md)
\ No newline at end of file
diff --git a/docs/dev/adb_tradeinmode.md b/docs/dev/adb_tradeinmode.md
new file mode 100644
index 00000000..7604b6ec
--- /dev/null
+++ b/docs/dev/adb_tradeinmode.md
@@ -0,0 +1,70 @@
+# Architecture of *ADB Trade-In Mode*
+
+ADB can run in a specialized "trade-in mode" (TIM). This is a highly restricted ADB designed to
+faciliate automated diagnostics. It is only activated during the SetUp Wizard (SUW) on user builds.
+
+## Activation flow
+
+The DeviceDiagnostics apk has a `BOOT_COMPLETE` broadcast receiver, which it uses to call into the
+tradeinmode service (`ITradeInMode.start`). The service activates trade-in mode if the following
+conditions are true:
+
+1. ADB is disabled.
+2. `ro.debuggable` is 0 (to avoid breaking userdebug testing).
+3. The `USER_SETUP_COMPLETE` setting is 0.
+4. The `DEVICE_PROVISIONED` setting is 0.
+5. There is no active wifi connection.
+
+If all of these conditions hold, `persist.adb.tradeinmode` is set to `1` and the `ADB_ENABLED`
+setting is set to `1`.
+
+When adbd subsequentily starts, it sees `persist.adb.tradeinmode` is set and lowers its SELinux
+context to a highly restricted policy (`adb_tradeinmode`).  This policy restricts adbd to
+effectively one command: `adb shell tradeinmode`. It also disables authorization.
+
+`ITradeInMode` monitors conditions 3, 4, and 5 above and turns off ADB as soon as any become true.
+
+If the device is rebooted, the persist property ensures that ADB will stay in trade-in mode.
+
+## userdebug testing
+
+On userdebug builds, TIM is not enabled by default since adb is already available. This means the
+authorization dialog is still present. However, TIM can still be manually tested with the following
+command sequence:
+1. `adb root`
+2. `adb shell setprop service.adb.tradeinmode 1`
+3. `adb unroot`
+
+Unlike user builds, if entering TIM fails, then userdebug adbd will simply restart without TIM
+enabled.
+
+## Trade-In Mode commands
+
+When ADB is in trade-in mode (the default in SUW when ro.debuggable is 0), the only allowed command
+is `adb shell tradeinmode` plus arguments. On userdebug or eng builds, `adb root` is also allowed.
+
+The tradeinmode shell command has two arguments:
+ - `getstatus [-challenge CHALLENGE]`: Returns diagnostic information about the device, optionally
+   with an attestation challenge.
+ - `evaluate`: Bypasses setup and enters Android in an evaluation mode. A factory reset is forced
+   on next boot.
+
+## Evaluation mode
+
+Evaluation mode is entered via `adb shell tradeinmode evaluate`. This changes
+`persist.adb.tradeinmode` to `2` and restarts adbd. adbd then starts normally, without trade-in
+mode restrictions. However, authorization is disabled. The device is factory reset on next boot.
+This mode allows further diagnostics via normal adb commands (such as adb install).
+
+## Factory reset
+
+The factory reset is guaranteed by `ITradeInModeService.enterEvaluationMode` which writes a marker
+to `/metadata/tradeinmode/wipe`. If first-stage init sees this file, it immediately reboots into
+recovery to issue an unprompted wipe.
+
+## persist.adb.tradeinmode values
+ - `-1`: Failed to start TIM.
+ - `0`: TIM is not enabled.
+ - `1`: TIM is enabled.
+ - `2`: "adb shell tradeinmode evaluate" was used, which enables adbd past SUW but
+        also guarantees a factory reset on reboot.
diff --git a/docs/dev/asocket.md b/docs/dev/asocket.md
new file mode 100644
index 00000000..d6efb64b
--- /dev/null
+++ b/docs/dev/asocket.md
@@ -0,0 +1,244 @@
+# Understanding asockets
+
+The data structure of asocket, with their queue, amessage, and apackets are described
+in [internals.md](internals.md). But understanding asocket, how they are used, and how they are
+paired is non-trivial. This document hopefully explains how bytes flow through them.
+
+## Why ADB needs asocket
+
+The concept of `asocket` was created to achieve two things.
+
+- Carry multiple streams over a single pipe (originally that meant USB only).
+- Manage congestion (propagate back-pressure).
+
+With the introduction of TCP support, an abstraction layer (transport) was created
+but TCP multiplexing was not leveraged. Even when using TCP, a transport still uses `asocket`
+to multiplex streams.
+
+## Data direction and asocket peers
+
+- A asocket is uni-directional. It only allows data to be `enqueue`d.
+- A asocket is paired with a peer asocket which handles traffic in the opposite direction.
+
+## Types of asocket
+
+There are several types of `asocket`. Some are easy to understand because they
+extend `asocket`.
+
+- JdwpSocket
+- JdwpTracker
+- SinkSocket
+- SourceSocket
+
+However there are "undeclared" types, whose behavior differs only via the `asocket`
+function pointers.
+
+- Local Socket (LS)
+- Remote Socket (RS)
+- Smart Socket (SS)
+- Local Service Socket (LSS)
+
+
+## Local socket (abbreviated LS)
+
+A LS interfaces with a file descriptor to forward a stream of bytes
+without altering it (as opposed to a LSS).
+To perform its task, a LS leverages fdevent to request FDE_READ/FDE_WRITE notification.
+
+```
+                                  LOCAL SOCKET                                TRANSPORT
+                   ┌────────────────────────────────────────────────┐           ┌──┐
+     ┌──┐ write(3) │  ┌─────┐                                   enqueue()       │  │
+     │  │◄─────────┼──┤Queue├─────────────◄──────────────◄──────────┼─────────(A_WRTE)◄──
+     │fd│          │  └─────┘                                       │           │  │
+     │  ├──────────►─────────────────┐                              │           │  │
+     └──┘ read(3)  └─────────────────┼──────────────────────────────┘           │  │
+                                     ▼                                          └──┘
+                                 peer.enqueue()
+```
+
+A_WRTE apackets are forwarded directly to the LS by the transport. The transport
+is able to route the apacket to the local asocket by using `apacket.msg1` which
+points to the target local asocket `id`.
+
+### Write to fd and Back-pressure
+
+When a payload is enqueued, an LS tries to write as much as possible to its `fd`.
+After the write attempt, the LS stores in its queue what could not be written.
+Based on the volume of data in the queue, it sets `FDE_WRITE` and allows/forbids
+more data to come.
+
+- If there is data in the queue, the LS always requests `FDE_WRITE` events so it
+can write the outstanding data.
+- If there is less than `MAX_PAYLOAD` in the queue, LS calls ready on its peer (a RS),
+so an A_OKAY apacket is sent (which trigger another A_WRTE packet to be send).
+- If there is more than `MAX_PAYLOAD` in the queue, back-pressure is propagated by not
+calling `peer->ready`. This will trigger the other side to not send more A_WRTE until
+the volume of data in the queue has decreased.
+
+### Read from fd and Back-pressure
+
+When it is created, a LS requests FDE_READ from fdevent. When it triggers, it reads
+as much as possible from the `fd` (within MAX_PAYLOAD to make sure transport will take it).
+The data is then enqueueed on the peer.
+
+If `peer.enqueue` indicates that the peer cannot take more updates, the LS deletes
+the FDE_READ request.
+It is re-installed when A_OKAY is received by transport.
+
+## Remote socket (abbreviated RS)
+
+A RS handles outbound traffic and interfaces with a transport. It is simple
+compared to a LS since it merely translates function calls into transport packets.
+
+- enqueue -> A_WRTE
+- ready   -> A_OKAY
+- close   -> A_CLSE on RS and peer.
+- shutdown-> A_CLSE
+
+A RS is often paired with a LS  or a LSS.
+```
+                                    LOCAL SOCKET (THIS)                      TRANSPORT    
+                   ┌────────────────────────────────────────────────┐           ┌──┐      
+     ┌──┐ write(3) │  ┌─────┐                      enqueue()        │           │  │      
+     │  │◄─────────┼──┤Queue├─────────────◄──────────────◄──────────┼─────────(A_WRTE)◄── 
+     │fd│          │  └─────┘                                       │           │  │      
+     │  ├──────────►─────────────────┐                              │        ─  │  │      
+     └──┘ read(3)  └─────────────────┼──────────────────────────────┘           │  │      
+                                     │                                          │  │      
+                   ┌─────────────────▼─────────────────▲────────────┐           │  │      
+                   │                 │                              │           │  │      
+                   │                 │                              │           │  │      
+                   │                 └─────────────────────►──────────────────(A_WRTE)───►
+                   │                enqueue()                       │           │  │      
+                   └────────────────────────────────────────────────┘           └──┘      
+                                    REMOTE SOCKET (PEER)                                  
+```
+
+### RS creation
+
+A RS is always created by the transport layer (on A_OKAY or A_OPEN) and paired with a LS or LSS. 
+
+- Upon A_OPEN: The transport creates a LSS to handle inbound traffic and peers it with
+a RS to handle outbound traffic.
+
+- Upon A_OKAY: When receiving this packet, the transport always checks if there is a 
+LS with the id matching `msg1`. If there is and it does not have a peer yet, a RS is
+created, which completes a bi-directional chain.
+
+## Local Service Socket (LSS)
+
+A LSS is a wrapper around a `fd` (which is used to build a LS). The purpose is to process
+inbound and outbound traffic when it needs modification. e.g.: The "framebuffer" service
+involves invoking executable `screencap` and generating a header describing the payload
+before forwarding the color payload. This could not be done with a "simple" LS.
+
+The `fd` created by the LSS is often a pipe backed by a thread. 
+
+## Smart Socket (abbreviated SS)
+
+These Smart sockets are only created on the host by adb server on accept(3) by the listener
+service. They interface with a TCP socket.
+
+Upon creation, a SS enqueue does not forward anything until the [smart protocol](services.md) 
+has provided a target device and a service to invoke. 
+
+When these two conditions are met, the SS selects a transport and A_OPEN the service
+on the device. It gives the TCP socket fd to a LS and creates a RS to build a data flow
+similar to what was described in the Local Socket section.
+
+## Examples of dataflow
+
+### Package Manager (Device service)
+
+Let's take the example of the command `adb install -S <SIZE> -`. There are several install
+strategies but for the sake of simplicity, let's focus on the one resulting in invoking
+`pm install -S <SIZE> -` on the device and then streaming the content of the APK.
+
+In the beginning there is only a listener service, waiting for `connect(3)` on the server.
+
+```
+      ADB Client                   ADB Server       TRANSPORT        ADBd
+┌──────────────────────┐      ┌─────────────────┐      │     ┌─────────────────┐
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                     tcp * ───►* alistener     │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+└──────────────────────┘      └─────────────────┘      │     └─────────────────┘
+                                                                               
+┌──────────┐   ┌───────┐
+│    APK   │   │Console│
+└──────────┘   └───────┘
+```
+
+Upon `accept(3)`, the listener service creates a SS and gives it the socket `fd`.
+Then the client starts writing to the socket `|host:transport:XXXXXXX| |exec:pm pm install -S <SIZE> ->|`.
+
+```
+      ADB Client                   ADB Server       TRANSPORT        ADBd        
+┌──────────────────────┐      ┌─────────────────┐      │     ┌─────────────────┐
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                     tcp * ───►* SS            │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+└──────────────────────┘      └─────────────────┘      │     └─────────────────┘
+                                                                               
+┌──────────┐   ┌───────┐
+│    APK   │   │Console│
+└──────────┘   └───────┘
+```
+
+The SS buffers the smart protocol requests until it has everything it needs from
+the client.
+The first part, `host:transport:XXXXXXX` lets the SS know which transport to use (it
+contains the device identified `XXXXXXX`). The second part is the service to execute
+`exec:pm pm install -S <SIZE> -`.
+
+When it has both, the SS creates a LS to handle the TCP `fd`, and creates a RS to let
+the LS talk to the transport. The last thing the SS does before replacing itself with a
+LS (and giving it its socket fd) is sending an A_OPEN apacket.
+
+```
+      ADB Client                   ADB Server       TRANSPORT        ADBd
+┌──────────────────────┐      ┌─────────────────┐      │     ┌─────────────────┐
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                      │      │                 │      │     │                 │
+│                  tcp * ◄───►* LS              │      │     │                 │
+│                      │      │  │              │      │     │                 │
+│                      │      │  └─────────► RS─┼──────┼─►───┼──────►A_OPEN    │
+└──────────────────────┘      └─────────────────┘      │     └─────────────────┘
+                                                                               
+┌──────────┐   ┌───────┐                                       
+│   APK    │   │Console│                                      
+└──────────┘   └───────┘
+```
+So far only one side of the pipeline has been set up.
+
+Upon reception of the A_OPEN on the device side, `pm` is invoked via `fork/exec`.
+A socket pair end is given to a LS. A RS is also created to handle bytes generated by `pm`.
+Now we have a full pipeline able to handle bidirectional streams.
+ 
+```
+      ADB Client                   ADB Server       TRANSPORT        ADBd
+┌──────────────────────┐      ┌─────────────────┐      │     ┌─────────────────┐
+│                      │      │                 │      │     │                 │
+│                      │      │  ┌──────────────┼──◄───┼─────┼─RS ◄───┐        │
+│                      │      │  ▼              │      │     │        │        │
+│     ┌───────────►tcp * ◄───►* LS              │      │     │        │        │
+│     │             │  │      │  │              │      │     │        │        │
+│     │             │  │      │  └─────────► RS─┼──────┼─►───┼──────►LS        │
+└─────┼─────────────┼──┘      └─────────────────┘      │     └────────▲────────┘
+      │             │                                                 │         
+┌─────┴────┐   ┌────▼──┐                                        ┌─────▼────┐    
+│    APK   │   │Console│                                        │    PM    │    
+└──────────┘   └───────┘                                        └──────────┘    
+```
+
+At this point the client can `write(3)` the content of the apk to feed it to `pm`.
+It is also able to `read(3)` to show the output of `pm` in the console.
+
diff --git a/docs/dev/debugging.md b/docs/dev/debugging.md
new file mode 100644
index 00000000..f6acbfac
--- /dev/null
+++ b/docs/dev/debugging.md
@@ -0,0 +1,46 @@
+# ADB Debugging page
+
+## Address sanitizer
+
+### Host
+
+When you build you not only get an `adb` executable, you also get an `adb_asan`
+which is built with clang's address sanitizer.
+
+### Device
+
+Use HWASan (Hardware-assisted AddressSanitizer). This is done via `lunch`
+with an `hwasan` suffixed <product> (e.g.: `lunch aosp_panther_hwasan-trunk_staging-userdebug`)
+(for reminder, the lunch format is <product>-<release>-<variant>).
+
+## Logs
+
+### Host
+
+Enable logs and cycle the server.
+
+```
+$ export ADB_TRACE=all
+$ adb server nodaemon
+```
+
+The environment variable `ADB_TRACE` is also checked by the adb client.
+
+### Host libusb
+Libusb log level can be increased via environment variable `LIBUSB_DEBUG=4` (and restarting the server).
+See libusb documentation for available [log levels](https://libusb.sourceforge.io/api-1.0/group__libusb__lib.html#ga2d6144203f0fc6d373677f6e2e89d2d2).
+
+### Device
+
+On the device, `adbd` does not read `ADB_TRACE` env variable. Instead it checks property `persist.adb.trace_mask`.
+Set it and then cycle `adbd`.
+
+```
+$ adb shell su 0 setprop persist.adb.trace_mask 1
+$ adb shell su 0 pkill adbd
+```
+
+`adbd` will write logs in `/data/adb`. The filename depends on what time `adbd` started (e.g.:`adb-2024-10-08-17-06-21-4611`).
+
+
+
diff --git a/docs/dev/delayed_ack.md b/docs/dev/delayed_ack.md
new file mode 100644
index 00000000..251bb291
--- /dev/null
+++ b/docs/dev/delayed_ack.md
@@ -0,0 +1,83 @@
+# Delayed ACK
+
+Historically, ADB transport protocol transfer speed was affected by two factors.
+
+1. Each `A_WRTE` apacket was CRCed upon write and the CRC was checked upon read on the other end.
+2. There could be only one `A_WRTE` apacket in-flight on an asocket. A local asocket
+would not schedule more data to be sent out until it had received an `A_OKAY` apacket response from
+its peer.
+
+The first issue was solved in [aosp/568123](https://android-review.googlesource.com/q/568123).
+In that CL, the protocol was updated to remove the requirement for CRC generation and verification.
+This does not affect the reliability of a transport since both USB and TCP have packet checksums of their own.
+
+The second issue is solved by "delayed ACK" ([aosp/1953877](https://android-review.googlesource.com/q/1953877)),
+an experimental feature controlled by the environment variable `ADB_DELAYED_ACK`.
+
+# How delayed ACK works
+
+The idea is to introduce the concept of a per-asocket "available send bytes" (ASB) integer.
+This integer represent how many bytes we are willing to send without having received any
+`A_OKAY` for them.
+
+While the ASB is positive, the asocket does not wait for an `A_OKAY` before sending
+more `A_WRTE` apackets. A remote asocket can be written to up until the ASB is exhausted.
+
+The ASB capability is first negotiated on `A_OPEN`/`A_OKAY` exchange. After
+that, the ASB is maintained via decrement upon `A_WRTE` and increment
+upon `A_OKAY`.
+
+This approach allows to "burst" `A_WRTE` packet but also "burst" `A_OKAY` packets
+to allow several `A_WRTE` packets to be in-flight on an asocket. This greatly
+increases data transfer throughput.
+
+# Implementation
+
+## Packet update
+1. `A_OPEN` unused field (`arg1`) is repurposed to declare the wish to use delayed ACK features.
+If not supported, the receiving end of the `A_OPEN` will `A_CLSE` the connection.
+2. `A_OKAY` now has a payload (a int32_t) which acknowledge how much payload was
+received in the last received `A_WRTE` apacket.
+
+## Trace
+
+Here are two traces showing the timing of three A_WRTE.
+
+### Before
+```
+Host                > A_OPEN                  > Device
+Host                > A_WRTE                  > Device
+The LS removes itself from the fdevent EPOLLIN and nothing is sent.
+Host                < A_OKAY                  < Device
+The LS requests fdevent EPOLLIN for its fd to start reading and send more A_WRTE.
+Host                > A_WRTE                  > Device
+The LS removes itself from the fdevent EPOLLIN and nothing is sent.
+Host                < A_OKAY                  < Device
+The LS requests fdevent EPOLLIN for its fd to start reading and send more A_WRTE.
+Host                > A_WRTE                  > Device
+The LS removes itself from the fdevent EPOLLIN and nothing is sent.
+Host                < A_OKAY                  < Device
+The LS requests fdevent EPOLLIN for its fd to start reading and send more A_WRTE.
+```
+
+
+## After
+
+With ASB, see how `A_WRTE` and `A_OKAY` are burst instead of being paired.
+
+```
+Host(ASB=0)         > A_OPEN(arg1=1MiB)       > Device
+Host(ASB=X)         < A_OKAY(<ASB=X>)         < Device
+Host<ASB=X-a)       > A_WRTE(payload size=a)  > Device
+Host<ASB=Y-a-b)     > A_WRTE(payload size=b)  > Device
+Host<ASB=Z-a-b-c)   > A_WRTE(payload size=c)  > Device
+ASB is < 0. The LS removes itself from the fdevent EPOLLIN and nothing is sent.
+...
+Host(ASB=X-b-c)     < A_OKAY(<a>)             < Device
+ASB is > 0. The LS requests fdevent EPOLLIN for its fd to start reading and send more A_WRTE.
+...
+Host(ASB=X-c)       < A_OKAY(<b>)             < Device
+Host(ASB=X)         < A_OKAY(<c>)             < Device
+```
+
+
diff --git a/docs/dev/internals.md b/docs/dev/internals.md
new file mode 100644
index 00000000..68d3831d
--- /dev/null
+++ b/docs/dev/internals.md
@@ -0,0 +1,153 @@
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
+### ADB Trade-In Mode
+
+[here](adb_tradeinmode.md)
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
diff --git a/docs/dev/root.md b/docs/dev/root.md
new file mode 100644
index 00000000..cbb19981
--- /dev/null
+++ b/docs/dev/root.md
@@ -0,0 +1,37 @@
+# How does ADB root/unroot work?
+
+Every couple of months the question is asked to the OWNERS: "How does adb root/unroot work?". Every time, we have to
+dig out the code to remember. Here is a doc to hopefully solve this problem.
+
+## shell uid vs root uid
+
+`adbd` always starts running as user `root`.  One of the first things the daemon does is to check
+if it should drop its privileges to run as `shell` user. There are a few read-only properties involved in the decision.
+
+```
+ro.secure
+ro.debuggable
+```
+
+On a `user` debug, these properties will never allow `adbd` to remain `root`. However, on `eng` and `userdebug` builds
+they will.
+
+## From CLI to restart
+
+If adbd can remain `root`, it doesn't mean that it should. There is a second level decision dictated by the property
+`service.adb.root`. If set to `1`, adbd remains `root`. Otherwise, it drops to `shell`.
+
+The command `adb root` and `adb unroot` triggers adbd to write `service.adb.root` and restart.
+
+The one catch is that `adbd` cannot call `exit(3)` right away since it must make sure the "success" message makes
+it back to the caller on the host.
+
+The trick is done by tagging any asocket associated with a `root`/`unroot` command to call `exit(3)` when the
+asocket they run upon is closed (see `exit_on_close`).
+
+
+## How adb restarts upon root/unroot
+
+If `adbd` calls `exit(3)`, how does it restart itself? Since it is a critical process, `initd` notices that it is
+gone and restarts it.
+
diff --git a/docs/dev/zero_length_packet.md b/docs/dev/zero_length_packet.md
new file mode 100644
index 00000000..0d7df3a3
--- /dev/null
+++ b/docs/dev/zero_length_packet.md
@@ -0,0 +1,279 @@
+# How ADB uses USB Zero-Length Packets (ZLP)
+
+## TLDR;
+There is no USB mechanism that lets a sender announce the size of a `Transfer`. This is not
+a problem when the host side receives packet since is leverage the aprotocol to know what size
+of transfer to expect. However, traffic towards the device must include zero length packets to
+mark the boundaries since the device does not leverage the aprotocol.
+
+## Introduction
+
+There is an asymmetry in how ADB communicates over USB. While all USB backends on the host side (Linux,
+Windows, Mac, and libusb) send ZLPs, the device side never does. Why is that? This document explains
+what ZLPs are, how ADB uses them, and why things are designed this way.
+
+## USB Transfer 101
+
+In the context of ADB, USB can be thought of as two unidirectional pipes per device.
+One pipe takes care of upload while the other takes care of the download. On the pipe
+transit payloads. The maximum size of a payload is set by the pipe buffers located
+on the device. These buffers are called the `Endpoint`.
+
+```
+  ┌──────────┐                         ┌──────────┐
+  │ USB Host │                         │USB Device│
+  ├──────────┤                         ├──────────┤
+  │          │                         │          │
+  │  Pipe ◄──┼─────────────────────────┼ Endpoint │
+  │          │        USB              │          │
+  │  Pipe ───┼─────────────────────────► Endpoint │
+  └──────────┘                         └──────────┘
+```
+
+In USB parlance, sending a buffer of data on a pipe and receiving it on the other end is called a `Transfer`.
+On the sender side, the USB Controller is presented with a [buffer,size] pair called IRP. On the receiver
+side, a similar IRP is provided to the USB controller.
+
+```
+       ┌────────┐                             ┌──────────┐
+       │ Sender │                             │ Receiver │
+       └────┬───┘                             └─────┬────┘
+            │                                       │
+         ┌──▼───┐                                ┌──▼───┐
+         │ IRP  │                                │  IRP │
+         └──┬───┘                                └──▲───┘
+     ┌──────▼───────┐                        ┌──────┴───────┐
+     │USB Controller│                        │USB Controller│
+     │              │                        │              │
+     │             ─┼───►─DP──►─DP ─►──DP──►─┼─►            │
+     └──────────────┘                        └──────────────┘
+```
+
+Because of the endpoint buffer size (`wMaxPacketSize`), an IRP is broken down in
+several data payloads called `Data Packets` (DP).
+
+Note: On the device, ADB uses `functionfs` which is not based on IRP. However, the logic is the same since received DP
+must be re-assembled on the device to rebuild the original IRP. To simplify this document we use the name "IRP"
+everywhere in this doc to mean "[buffer,size] pair provided to the USB Controller".
+
+## When does a USB Transfer ends?
+
+If an IRP is broken down in DPs by the sender, how does the receiver reassemble
+the DPs into an IRP on the other side?
+
+The key concept to get out of this whole document is that there is no mechanism
+in USB for the sender to announce the size of a `Transfer`. Instead, the receiving
+end uses the following rules. A `Transfer` is considered done when either of the following condition
+is met.
+
+- An error occurred (device disconnected, ...).
+- The IRP is full.
+- The size of the packet is less than `wMaxPacketSize` (this is a Short-Packet). This is
+a different behavior from the usual UNIX `read(3)` which is allowed to return less than required
+without meaning that the stream is over.
+- Too much data is received. The IRP overflows (this is also an error).
+
+See USB 2 specifications (5.8.3 Bulk Transfer Packet Size Constraints) for additional information.
+```
+An endpoint must always transmit data payloads with a data field less than or equal to the endpoint’s
+reported wMaxPacketSize value. When a bulk IRP involves more data than can fit in one maximum-sized
+data payload, all data payloads are required to be maximum size except for the last data payload, which will
+contain the remaining data. A bulk transfer is complete when the endpoint does one of the following:
+
+• Has transferred exactly the amount of data expected
+• Transfers a packet with a payload size less than wMaxPacketSize or transfers a zero-length packet
+```
+
+### Example 1: The IRP is full
+
+For a USB3 bulk pipe, the `wMaxPacketSize` is 1024. The sender "S" wishes
+to send 2048 bytes. It creates a IRP, fills it with the 2048 bytes, and gives the IRP
+to the USB controller. On the
+received side "R", the USB controller is provided with a IRP of side 2048.
+
+```
+Traffic:
+S -> 1024 -> R
+S -> 1024 -> R IRP full, Transfer OK!
+```
+
+At this point R's IRP is full. R USB controller declares the `Transfer` over
+and calls whatever callback the client provided the IRP.
+
+### Example 2: Short-Packet
+
+Same USB3 bulk as Example 1. The `wMaxPacketSize` is 1024. The sender wishes
+to send 2148 bytes. It creates a IRP of size 2148 bytes and fills it with data.
+On the received side, the USB controller is provided with a IRP of size 4096.
+
+```
+Traffic:
+S -> 1024 -> R
+S -> 1024 -> R
+S ->  100 -> R Short-Packet, Transfer OK!
+```
+
+The receiver end detects a short packet. Even though it was provided with a 4906
+byte IRP, it declares the `Transfer` completed (and records the actual size
+of the `Transfer` in the IRP).
+
+### Example 3: Overflow
+
+Same USB3 bulk as Example 1. The `wMaxPacketSize` is 1024. The sender wishes
+to send 4096 bytes. It creates a IRP, fills it with the 4096 bytes. On the
+receiver side, the USB controller is provided with an IRP of size 2148.
+
+```
+Traffic:
+S -> 1024 -> R
+S -> 1024 -> R
+S -> 1024 -> R ERROR, Transfer failed!
+```
+
+On the third packet, the receiver runs out of space in the IRP (it only had 100
+bytes available). Without a way to fully store this packet,
+it discards everything and returns an error stating that the `Transfer` was not successful.
+
+## Preventing overflow and the need for Zero-Length Packets
+
+There are two techniques to avoid overflows.
+
+### Using a protocol
+One technique is to create a protocol on top of `Transfers`.
+ADB does that with its "aprotocol" ([protocol.md](protocol.md)).
+
+In aprotocol, the sender creates a `Transfer` containing a header which is
+always 24 bytes. Then it sends a separate `Transfer` containing the payload.
+The size of the payload is in the header. This way the receiver always knows
+what size of IRP to provide to the USB controller: it first requests a 24 byte IRP
+read, extracts the size of the payload, then issues a second IRP read request
+with the extracted size of the payload.
+
+### Using a multiple of `wMaxPacketSize`
+
+The other technique to avoid overflows is for the receiver to always use a IRP with
+a size which is a multiple of the `wMaxPacketSize`. This way a `Transfer` always ends properly.
+* A max size packet will exactly finish to fill the IRP, ending the `Transfer`.
+* A short packet will end the `Transfer`.
+
+This technique comes with an edge case. Take the example of a USB3 pipe where
+`wMaxPacketSize` is 1024. The sender wishes to send 3072 byte. It creates a IRP
+of that size, fills in the data and gives it to the USB controller which breaks
+it into Packets. The receiver decides to read with a IRP of size 4096.
+
+```
+Traffic:
+S -> 1024 -> R
+S -> 1024 -> R
+S -> 1024 -> R
+.
+.
+.
+Stalled!
+```
+
+After the USB controller on the sender side has sent all the data in the IRP, it won't send anything else.
+But none of the ending conditions of a `Transfer` have been reached on the receiving end. No overflow, no short-packet, and the IRP is not
+full (there is still 1024 bytes unused). As is, the USB controller on the receiving end will never declare the `Transfer`
+either successful or failed. This is a stall (at least until another Packet is sent, if ever).
+
+This condition is entered when the size of a IRP to send is a multiple of `wMaxPacketSize`
+but less than the size of the IRP provided by the receiving end. To fix this condition,
+the sender MUST issue a Zero-Length Packet. Technically, this is a short packet (it is less
+than `wMaxPacketSize`). Upon receiving the ZLP, the receiver declares the `Transfer`
+finished.
+
+```
+Traffic:
+S -> 1024 -> R
+S -> 1024 -> R
+S -> 1024 -> R
+S ->    0 -> R Short-Packet, Transfer is over!
+```
+
+## Implementation choices
+
+By now, it should be clear that whether a sender needs to send a ZLP depends on the way
+the receiver end works.
+
+### ADB Device to Host pipe communication design
+
+The receiver on the host leverages ADB aprotocol ([protocol.md](protocol.md)). It
+first creates a IRP of size 24 bytes to receive the header. Then it creates a IRP
+`Transfer`
+of the size of the payload. Because the IRPs are always exactly the size of the `Transfer`
+the device sends, there is no need for LZP. The USB Controller on the host side will always be able
+to declare a `Transfer` complete when the IRP is full and there will never be any overflow.
+
+The drawback of this technique is that it can consume a lot of RAM because multiple
+IRPs can be in flight at a time. With the maximum size of
+a apacket payload being MAX_PAYLOAD (1MiB), things can quickly add up.
+
+
+### ADB Host to Device pipe communication design
+
+On the device side, the receiver does not leverage the ADB aprotocol ([protocol.md](protocol.md)).
+I suspect this was done to reduce memory consumption (the first Android device had a total RAM size of 192MiB).
+
+The UsbFS connection always requests the same
+`Transfer` size. To prevent overflows, the size is picked to be a multiple of the `wMaxPacketSize` (1x would be
+valid but the overhead would kill performances). Currently, the value is kUsbReadSize (16384). USB endpoints
+have a well known `wMaxPacketSize` so 16384 works for all of them (this list is for bulk transfers only which
+ADB exclusively uses).
+
+* Full Speed: 8, 16, 32, or 64 bytes.
+* High Speed: 512 bytes.
+* Super Speed: 1024 bytes.
+
+When the apacket payload size is a multiple
+of the `wMaxPacketSize`, the sender on the host side MUST send a ZLP to avoid stalling
+on the receiver end.
+
+
+## What happens if the host sender has a bug and ZLPs are not sent?
+
+If there is a bug on the host and ZLPs are not sent, several things can happen.
+You can observe normal behavior, stalled communication, or even device disconnection.
+
+Because there are many buffers before the USB controller layer
+is hit, the issue won't be deterministic. However my experience showed that attempting to
+push 10GiB  rarely
+fails to bring up instabilities.
+
+```
+$ dd if=/dev/urandom of=r.bin bs=1G count=10 iflag=fullblock`
+$ adb push -Z r.bin /datal/local/tmp
+```
+
+### 1. Nothing breaks
+
+You could be unlucky and not trigger the fault.
+
+### 2. Stall
+
+A payload of a size that's a multiple of `wMaxPacketSize` but of size less than kUsbReadSize (16384) is sent.
+This is a stall as previously described.
+
+### 3. Disconnection (due to merged packets)
+
+In real-life usage, there is rarely a single thing happening on ADB. Users often also run logcat, Studio
+monitors metrics, or perhaps the user has a shell opened. What happens if a connection goes stalls
+but then something else sends an apacket?
+
+The first `Transfer` of the apacket will be an apacket header which is 24 bytes. This will be considered
+a short-packet. The previous stalled `Transfer` will be completed with the header appended. This will
+confuse UsbFS since the payload will be 24 bytes more than it should be. In this condition, the connection
+is closed. The log message is
+
+```
+received too many bytes while waiting for payload
+```
+
+or
+
+```
+received packet of unexpected length while reading header
+```
+
+A summary inspection of logs may make it look like a payload `Transfer`
+was merged with the next header `Transfer`.
\ No newline at end of file
diff --git a/fdevent/fdevent.cpp b/fdevent/fdevent.cpp
index 46d8cbf7..bc0074d9 100644
--- a/fdevent/fdevent.cpp
+++ b/fdevent/fdevent.cpp
@@ -1,5 +1,5 @@
 /*
- * Copyright 2006, Brian Swetland <swetland@frotz.net>
+ * Copyright (C) 2006 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
diff --git a/services.cpp b/services.cpp
index 2e9499f4..1c9ed70d 100644
--- a/services.cpp
+++ b/services.cpp
@@ -113,7 +113,7 @@ void connect_emulator(const std::string& port_spec, std::string* response) {
     // Check if the emulator is already known.
     // Note: There's a small but harmless race condition here: An emulator not
     // present just yet could be registered by another invocation right
-    // after doing this check here. However, local_connect protects
+    // after doing this check here. However, connect_emulator protects
     // against double-registration too. From here, a better error message
     // can be produced. In the case of the race condition, the very specific
     // error message won't be shown, but the data doesn't get corrupted.
@@ -125,7 +125,7 @@ void connect_emulator(const std::string& port_spec, std::string* response) {
 
     // Preconditions met, try to connect to the emulator.
     std::string error;
-    if (!local_connect_arbitrary_ports(console_port, adb_port, &error)) {
+    if (!connect_emulator_arbitrary_ports(console_port, adb_port, &error)) {
         *response = android::base::StringPrintf("Connected to emulator on ports %d,%d",
                                                 console_port, adb_port);
     } else {
diff --git a/socket.h b/socket.h
index a6f7d4ff..5e3dd0db 100644
--- a/socket.h
+++ b/socket.h
@@ -32,28 +32,28 @@ class atransport;
 
 /* An asocket represents one half of a connection between a local and
    remote entity.  A local asocket is bound to a file descriptor.  A
-   remote asocket is bound to the protocol engine.
-
-   Example (two local_sockets) :
-
-                                   ASOCKET(THIS)
-              ┌────────────────────────────────────────────────┐
-┌──┐ write(3) │  ┌─────┐                      enqueue()        │
-│  │◄─────────┼──┤Queue├─────────────◄────────────┐            │
-│fd│          │  └─────┘                          ▲            │
-│  ├──────────►─────────────────┐                 │            │
-└──┘ read(3)  └─────────────────┼─────────────────┼────────────┘
-                       outgoing │                 │ incoming
-              ┌─────────────────▼─────────────────▲────────────┐  read(3)  ┌──┐
-              │                 │                 └────────────┼─────────◄─┤  │
-              │                 │                      ┌─────┐ │           │fd│
-              │                 └─────────────────────►│Queue├─┼─────────►─┤  │
-              │                enqueue()               └─────┘ │  write(3) └──┘
-              └────────────────────────────────────────────────┘
-                                 ASOCKET(PEER)
-
-    Note that sockets can be peered regardless of their kind. A remote socket can be peered with
-    a smart socket, a local socket can be peered with a remote socket and so on.
+   remote asocket is bound to the protocol engine (transport).
+
+   Example of a Local Socket (LS) with undetermined peer:
+
+                                  LOCAL SOCKET (THIS)                         TRANSPORT
+                   ┌────────────────────────────────────────────────┐           ┌──┐
+     ┌──┐ write(3) │  ┌─────┐                                   enqueue()       │  │
+     │  │◄─────────┼──┤Queue├─────────────◄──────────────◄──────────┼─────────(A_WRTE)◄──
+     │fd│          │  └─────┘                                       │           │  │
+     │  ├──────────►─────────────────┐                              │        ─  │  │
+     └──┘ read(3)  └─────────────────┼──────────────────────────────┘           │  │
+                                     │                                          │  │
+                   ┌─────────────────▼─────────────────▲────────────┐           │  │
+                   │                 │                              │           │  │
+                   │                 │                              │           │  │
+                   │                 └─────────────────────►──────────────────(A_WRTE)───►
+                   │                enqueue()                       │           │  │
+                   └────────────────────────────────────────────────┘           └──┘
+                                  REMOTE SOCKET (PEER)
+
+    Note that sockets can be peered regardless of their kind. A Remote Socket (RS) can be peered
+   with a Local Socket (LS) or a Local Service Socket (LSS).
  */
 struct asocket {
     /* the unique identifier for this asocket
diff --git a/test_device.py b/test_device.py
index cc5e2f05..3ccbe5cd 100755
--- a/test_device.py
+++ b/test_device.py
@@ -1846,13 +1846,9 @@ class DevicesListing(DeviceTest):
 
 class DevicesListing(DeviceTest):
 
-    serial = subprocess.check_output(['adb', 'get-serialno']).strip().decode("utf-8")
-
     def test_track_app_appinfo(self):
-        return # Disabled until b/301491148 is fixed.
-        # (Exported FeatureFlags cannot be read-only)
-        subprocess.check_output(['adb', 'install', '-t', 'adb1.apk']).strip().decode("utf-8")
-        subprocess.check_output(['adb', 'install', '-t', 'adb2.apk']).strip().decode("utf-8")
+        subprocess.check_output(['adb', 'install', '-r', '-t', 'adb_test_app1.apk']).strip().decode("utf-8")
+        subprocess.check_output(['adb', 'install', '-r', '-t', 'adb_test_app2.apk']).strip().decode("utf-8")
         subprocess.check_output(['adb', 'shell', 'am', 'start', '-W', 'adb.test.app1/.MainActivity']).strip().decode("utf-8")
         subprocess.check_output(['adb', 'shell', 'am', 'start', '-W', 'adb.test.app2/.MainActivity']).strip().decode("utf-8")
         subprocess.check_output(['adb', 'shell', 'am', 'start', '-W', 'adb.test.app1/.OwnProcessActivity']).strip().decode("utf-8")
@@ -1892,6 +1888,26 @@ class ServerStatus(unittest.TestCase):
             self.assertTrue("executable_absolute_path" in lines[4])
             self.assertTrue("log_absolute_path" in lines[5])
 
+def invoke(*args):
+    return subprocess.check_output(args).strip().decode("utf-8")
+
+class OneDevice(unittest.TestCase):
+
+    serial = invoke("adb", "get-serialno")
+    owner_server_port = "14424"
+
+    def test_one_device(self):
+        invoke("adb", "kill-server")
+        invoke("adb", "--one-device", self.serial, "-P", self.owner_server_port, "start-server")
+        devices = invoke("adb", "devices")
+        owned_devices = invoke("adb",  "-P", "14424", "devices")
+        self.assertTrue(self.serial in owned_devices)
+        self.assertFalse(self.serial in devices)
+
+    def tearDown(self):
+        invoke("adb",  "-P", self.owner_server_port, "kill-server")
+        invoke("adb",  "kill-server")
+
 if __name__ == '__main__':
     random.seed(0)
     unittest.main()
diff --git a/transport.cpp b/transport.cpp
index b99e8bcf..0c51ede6 100644
--- a/transport.cpp
+++ b/transport.cpp
@@ -70,11 +70,12 @@ using TlsError = TlsConnection::TlsError;
 static void remove_transport(atransport* transport);
 static void transport_destroy(atransport* transport);
 
+static auto& transport_lock = *new std::recursive_mutex();
+// When a tranport is created, it is not started yet (and in the case of the host side, it has
+// not yet sent CNXN). These transports are staged in the pending list.
+static auto& pending_list = *new std::list<atransport*>();
 // TODO: unordered_map<TransportId, atransport*>
 static auto& transport_list = *new std::list<atransport*>();
-static auto& pending_list = *new std::list<atransport*>();
-
-static auto& transport_lock = *new std::recursive_mutex();
 
 const char* const kFeatureShell2 = "shell_v2";
 const char* const kFeatureCmd = "cmd";
@@ -301,7 +302,7 @@ BlockingConnectionAdapter::~BlockingConnectionAdapter() {
     Stop();
 }
 
-void BlockingConnectionAdapter::Start() {
+bool BlockingConnectionAdapter::Start() {
     std::lock_guard<std::mutex> lock(mutex_);
     if (started_) {
         LOG(FATAL) << "BlockingConnectionAdapter(" << Serial() << "): started multiple times";
@@ -334,6 +335,7 @@ void BlockingConnectionAdapter::Start() {
     });
 
     started_ = true;
+    return true;
 }
 
 void BlockingConnectionAdapter::StartReadThread() {
@@ -737,11 +739,12 @@ static bool usb_devices_start_detached() {
 #endif
 
 static void fdevent_unregister_transport(atransport* t) {
-    D("transport: %s deleting", t->serial.c_str());
+    VLOG(TRANSPORT) << "unregistering transport: " << t->serial;
 
     {
         std::lock_guard<std::recursive_mutex> lock(transport_lock);
         transport_list.remove(t);
+        pending_list.remove(t);
     }
 
     delete t;
@@ -750,23 +753,34 @@ static void fdevent_unregister_transport(atransport* t) {
 }
 
 static void fdevent_register_transport(atransport* t) {
+    auto state = to_string(t->GetConnectionState());
+    VLOG(TRANSPORT) << "registering: " << t->serial.c_str() << " state=" << state
+                    << " type=" << t->type;
+
     /* don't create transport threads for inaccessible devices */
     if (t->GetConnectionState() != kCsNoPerm) {
         t->connection()->SetTransport(t);
 
-        if (t->type == kTransportUsb
 #if ADB_HOST
-            && usb_devices_start_detached()  // -d setting propagated from the
-                                             // host device, hence n/a on-device.
-#endif
-        ) {
+        if (t->type == kTransportUsb && usb_devices_start_detached()) {
+            VLOG(TRANSPORT) << "Force-detaching transport:" << t->serial;
             t->SetConnectionState(kCsDetached);
-        } else {
-            t->connection()->Start();
-#if ADB_HOST
-            send_connect(t);
-#endif
         }
+
+        VLOG(TRANSPORT) << "transport:" << t->serial << "(" << state << ")";
+        if (t->GetConnectionState() != kCsDetached) {
+            VLOG(TRANSPORT) << "Starting transport:" << t->serial;
+            if (t->connection()->Start()) {
+                send_connect(t);
+            } else {
+                VLOG(TRANSPORT) << "transport:" << t->serial << " failed to start.";
+                return;
+            }
+        }
+#else
+        VLOG(TRANSPORT) << "Starting transport:" << t->serial;
+        t->connection()->Start();
+#endif
     }
 
     {
@@ -819,12 +833,10 @@ void kick_all_transports_by_auth_key(std::string_view auth_key) {
 #endif
 
 void register_transport(atransport* transport) {
-    D("transport: %s registered", transport->serial.c_str());
     fdevent_run_on_looper([=]() { fdevent_register_transport(transport); });
 }
 
 static void remove_transport(atransport* transport) {
-    D("transport: %s removed", transport->serial.c_str());
     fdevent_run_on_looper([=]() { fdevent_unregister_transport(transport); });
 }
 
@@ -833,7 +845,7 @@ static void transport_destroy(atransport* t) {
     CHECK(t != nullptr);
 
     std::lock_guard<std::recursive_mutex> lock(transport_lock);
-    LOG(INFO) << "destroying transport " << t->serial_name();
+    VLOG(TRANSPORT) << "destroying transport " << t->serial_name();
     t->connection()->Stop();
 #if ADB_HOST
     if (t->IsTcpDevice() && !t->kicked()) {
@@ -1488,14 +1500,14 @@ bool validate_transport_list(const std::list<atransport*>& list, const std::stri
     return true;
 }
 
-bool register_socket_transport(unique_fd s, std::string serial, int port, int local,
+bool register_socket_transport(unique_fd s, std::string serial, int port, bool is_emulator,
                                atransport::ReconnectCallback reconnect, bool use_tls, int* error) {
-    atransport* t = new atransport(std::move(reconnect), kCsOffline);
+    atransport* t = new atransport(kTransportLocal, std::move(reconnect), kCsOffline);
     t->use_tls = use_tls;
     t->serial = std::move(serial);
 
     D("transport: %s init'ing for socket %d, on port %d", t->serial.c_str(), s.get(), port);
-    if (init_socket_transport(t, std::move(s), port, local) < 0) {
+    if (init_socket_transport(t, std::move(s), port, is_emulator) < 0) {
         delete t;
         if (error) *error = errno;
         return false;
@@ -1519,8 +1531,7 @@ bool register_socket_transport(unique_fd s, std::string serial, int port, int lo
 #endif
     register_transport(t);
 
-    if (local == 1) {
-        // Do not wait for emulator transports.
+    if (is_emulator) {
         return true;
     }
 
@@ -1569,9 +1580,9 @@ void kick_all_tcp_devices() {
 }
 
 #if ADB_HOST
-void register_usb_transport(std::shared_ptr<Connection> connection, const char* serial,
-                            const char* devpath, unsigned writeable) {
-    atransport* t = new atransport(writeable ? kCsOffline : kCsNoPerm);
+void register_libusb_transport(std::shared_ptr<Connection> connection, const char* serial,
+                               const char* devpath, unsigned writeable) {
+    atransport* t = new atransport(kTransportUsb, writeable ? kCsOffline : kCsNoPerm);
     if (serial) {
         t->serial = serial;
     }
@@ -1580,7 +1591,6 @@ void register_usb_transport(std::shared_ptr<Connection> connection, const char*
     }
 
     t->SetConnection(std::move(connection));
-    t->type = kTransportUsb;
 
     {
         std::lock_guard<std::recursive_mutex> lock(transport_lock);
@@ -1592,7 +1602,7 @@ void register_usb_transport(std::shared_ptr<Connection> connection, const char*
 
 void register_usb_transport(usb_handle* usb, const char* serial, const char* devpath,
                             unsigned writeable) {
-    atransport* t = new atransport(writeable ? kCsOffline : kCsNoPerm);
+    atransport* t = new atransport(kTransportUsb, writeable ? kCsOffline : kCsNoPerm);
 
     D("transport: %p init'ing for usb_handle %p (sn='%s')", t, usb, serial ? serial : "");
     init_usb_transport(t, usb);
diff --git a/transport.h b/transport.h
index 71decb21..cb4a6209 100644
--- a/transport.h
+++ b/transport.h
@@ -115,7 +115,8 @@ struct Connection {
 
     virtual bool Write(std::unique_ptr<apacket> packet) = 0;
 
-    virtual void Start() = 0;
+    // Return true if the transport successfully started.
+    virtual bool Start() = 0;
     virtual void Stop() = 0;
 
     virtual bool DoTlsHandshake(RSA* key, std::string* auth_key = nullptr) = 0;
@@ -175,7 +176,7 @@ struct BlockingConnectionAdapter : public Connection {
 
     virtual bool Write(std::unique_ptr<apacket> packet) override final;
 
-    virtual void Start() override final;
+    virtual bool Start() override final;
     virtual void Stop() override final;
     virtual bool DoTlsHandshake(RSA* key, std::string* auth_key) override final;
 
@@ -264,8 +265,9 @@ class atransport : public enable_weak_from_this<atransport> {
 
     using ReconnectCallback = std::function<ReconnectResult(atransport*)>;
 
-    atransport(ReconnectCallback reconnect, ConnectionState state)
+    atransport(TransportType t, ReconnectCallback reconnect, ConnectionState state)
         : id(NextTransportId()),
+          type(t),
           kicked_(false),
           connection_state_(state),
           connection_(nullptr),
@@ -279,8 +281,8 @@ class atransport : public enable_weak_from_this<atransport> {
         protocol_version = A_VERSION_MIN;
         max_payload = MAX_PAYLOAD;
     }
-    atransport(ConnectionState state = kCsOffline)
-        : atransport([](atransport*) { return ReconnectResult::Abort; }, state) {}
+    atransport(TransportType t, ConnectionState state = kCsOffline)
+        : atransport(t, [](atransport*) { return ReconnectResult::Abort; }, state) {}
     ~atransport();
 
     int Write(apacket* p);
@@ -501,8 +503,9 @@ void register_transport(atransport* transport);
 #if ADB_HOST
 void init_usb_transport(atransport* t, usb_handle* usb);
 
-void register_usb_transport(std::shared_ptr<Connection> connection, const char* serial,
-                            const char* devpath, unsigned writeable);
+void register_libusb_transport(std::shared_ptr<Connection> connection, const char* serial,
+                               const char* devpath, unsigned writable);
+
 void register_usb_transport(usb_handle* h, const char* serial, const char* devpath,
                             unsigned writeable);
 
@@ -513,8 +516,11 @@ void unregister_usb_transport(usb_handle* usb);
 /* Connect to a network address and register it as a device */
 void connect_device(const std::string& address, std::string* response);
 
+/* initialize a transport object's func pointers and state */
+int init_socket_transport(atransport* t, unique_fd s, int port, bool is_emulator);
+
 /* cause new transports to be init'd and added to the list */
-bool register_socket_transport(unique_fd s, std::string serial, int port, int local,
+bool register_socket_transport(unique_fd s, std::string serial, int port, bool is_emulator,
                                atransport::ReconnectCallback reconnect, bool use_tls,
                                int* error = nullptr);
 
@@ -531,10 +537,4 @@ asocket* create_device_tracker(TrackerOutputType type);
 std::string list_transports(TrackerOutputType type);
 #endif
 
-#if !ADB_HOST
-unique_fd adb_listen(std::string_view addr, std::string* error);
-void server_socket_thread(std::function<unique_fd(std::string_view, std::string*)> listen_func,
-                          std::string_view addr);
-#endif
-
 #endif /* __TRANSPORT_H */
diff --git a/transport_fd.cpp b/transport_fd.cpp
index d88d57d3..d26adc53 100644
--- a/transport_fd.cpp
+++ b/transport_fd.cpp
@@ -137,7 +137,7 @@ struct NonblockingFdConnection : public Connection {
         }
     }
 
-    void Start() override final {
+    bool Start() override final {
         if (started_.exchange(true)) {
             LOG(FATAL) << "Connection started multiple times?";
         }
@@ -147,6 +147,7 @@ struct NonblockingFdConnection : public Connection {
             Run(&error);
             transport_->HandleError(error);
         });
+        return true;
     }
 
     void Stop() override final {
diff --git a/transport_test.cpp b/transport_test.cpp
index 1a047aa3..31a875db 100644
--- a/transport_test.cpp
+++ b/transport_test.cpp
@@ -42,7 +42,7 @@ static void DisconnectFunc(void* arg, atransport*) {
 }
 
 TEST_F(TransportTest, RunDisconnects) {
-    atransport t;
+    atransport t{kTransportLocal};
     // RunDisconnects() can be called with an empty atransport.
     t.RunDisconnects();
 
@@ -66,7 +66,7 @@ TEST_F(TransportTest, RunDisconnects) {
 }
 
 TEST_F(TransportTest, SetFeatures) {
-    atransport t;
+    atransport t{kTransportLocal};
     ASSERT_EQ(0U, t.features().size());
 
     t.SetFeatures(FeatureSetToString(FeatureSet{"foo"}));
@@ -94,7 +94,7 @@ TEST_F(TransportTest, SetFeatures) {
 }
 
 TEST_F(TransportTest, parse_banner_no_features) {
-    atransport t;
+    atransport t{kTransportLocal};
 
     parse_banner("host::", &t);
 
@@ -107,7 +107,7 @@ TEST_F(TransportTest, parse_banner_no_features) {
 }
 
 TEST_F(TransportTest, parse_banner_product_features) {
-    atransport t;
+    atransport t{kTransportLocal};
 
     const char banner[] =
         "host::ro.product.name=foo;ro.product.model=bar;ro.product.device=baz;";
@@ -123,7 +123,7 @@ TEST_F(TransportTest, parse_banner_product_features) {
 }
 
 TEST_F(TransportTest, parse_banner_features) {
-    atransport t;
+    atransport t{kTransportLocal};
     const char banner[] =
         "host::ro.product.name=foo;ro.product.model=bar;ro.product.device=baz;"
         "features=woodly,doodly";
@@ -148,7 +148,7 @@ TEST_F(TransportTest, test_matches_target) {
     std::string model = "test_model";
     std::string device = "test_device";
 
-    atransport t;
+    atransport t{kTransportUsb};
     t.serial = &serial[0];
     t.devpath = &devpath[0];
     t.product = &product[0];
@@ -175,7 +175,7 @@ TEST_F(TransportTest, test_matches_target) {
 TEST_F(TransportTest, test_matches_target_local) {
     std::string serial = "100.100.100.100:5555";
 
-    atransport t;
+    atransport t{kTransportLocal};
     t.serial = &serial[0];
 
     // Network address matching should only be used for local transports.
diff --git a/types.h b/types.h
index 18c8e135..6b8bbfdd 100644
--- a/types.h
+++ b/types.h
@@ -20,6 +20,7 @@
 
 #include <algorithm>
 #include <memory>
+#include <string>
 #include <type_traits>
 #include <utility>
 #include <vector>
@@ -30,6 +31,7 @@
 #include "sysdeps/uio.h"
 
 // Essentially std::vector<char>, except without zero initialization or reallocation.
+// Features a position attribute to allow sequential read/writes for copying between Blocks.
 struct Block {
     using iterator = char*;
 
@@ -37,6 +39,8 @@ struct Block {
 
     explicit Block(size_t size) { allocate(size); }
 
+    explicit Block(const std::string& s) : Block(s.begin(), s.end()) {}
+
     template <typename Iterator>
     Block(Iterator begin, Iterator end) : Block(end - begin) {
         std::copy(begin, end, data_.get());
@@ -46,7 +50,8 @@ struct Block {
     Block(Block&& move) noexcept
         : data_(std::exchange(move.data_, nullptr)),
           capacity_(std::exchange(move.capacity_, 0)),
-          size_(std::exchange(move.size_, 0)) {}
+          size_(std::exchange(move.size_, 0)),
+          position_(std::exchange(move.position_, 0)) {}
 
     Block& operator=(const Block& copy) = delete;
     Block& operator=(Block&& move) noexcept {
@@ -54,6 +59,7 @@ struct Block {
         data_ = std::exchange(move.data_, nullptr);
         capacity_ = std::exchange(move.capacity_, 0);
         size_ = std::exchange(move.size_, 0);
+        position_ = std::exchange(move.size_, 0);
         return *this;
     }
 
@@ -79,8 +85,24 @@ struct Block {
         data_.reset();
         capacity_ = 0;
         size_ = 0;
+        position_ = 0;
+    }
+
+    bool is_full() const { return remaining() == 0; }
+
+    size_t remaining() const { return size_ - position_; }
+
+    size_t fillFrom(Block& from) {
+        size_t size = std::min(remaining(), from.remaining());
+        memcpy(&data_[position_], &from.data_[from.position_], size);
+        position_ += size;
+        from.position_ += size;
+        return size;
     }
 
+    void rewind() { position_ = 0; }
+    size_t position() const { return position_; }
+
     size_t capacity() const { return capacity_; }
     size_t size() const { return size_; }
     bool empty() const { return size() == 0; }
@@ -120,6 +142,7 @@ struct Block {
     std::unique_ptr<char[]> data_;
     size_t capacity_ = 0;
     size_t size_ = 0;
+    size_t position_ = 0;
 };
 
 struct amessage {
diff --git a/types_test.cpp b/types_test.cpp
index a6a225a6..707b5005 100644
--- a/types_test.cpp
+++ b/types_test.cpp
@@ -22,6 +22,8 @@
 #include <type_traits>
 #include <utility>
 
+#include "adb.h"
+#include "apacket_reader.h"
 #include "fdevent/fdevent_test.h"
 
 static IOVector::block_type create_block(const std::string& string) {
@@ -216,3 +218,287 @@ TEST_F(weak_ptr_test, smoke) {
 
     TerminateThread();
 }
+
+void ASSERT_APACKET_EQ(const apacket& expected, const std::unique_ptr<apacket>& result) {
+    ASSERT_EQ(expected.msg.data_length, result->msg.data_length);
+    ASSERT_EQ(expected.msg.command, result->msg.command);
+    ASSERT_EQ(expected.msg.arg0, result->msg.arg0);
+    ASSERT_EQ(expected.msg.arg1, result->msg.arg1);
+    ASSERT_EQ(expected.msg.data_check, result->msg.data_check);
+    ASSERT_EQ(expected.msg.magic, result->msg.magic);
+    ASSERT_EQ(size_t(0), expected.payload.position());
+    ASSERT_EQ(size_t(0), result->payload.position());
+
+    ASSERT_EQ(expected.payload.remaining(), result->payload.remaining());
+    ASSERT_EQ(0, memcmp(expected.payload.data(), result->payload.data(),
+                        expected.payload.remaining()));
+}
+
+void ASSERT_APACKETS_EQ(const std::vector<apacket>& expected,
+                        const std::vector<std::unique_ptr<apacket>>& result) {
+    ASSERT_EQ(expected.size(), result.size());
+    for (size_t i = 0; i < expected.size(); i++) {
+        ASSERT_APACKET_EQ(expected[i], result[i]);
+    }
+}
+static Block block_from_header(amessage& header) {
+    Block b{sizeof(amessage)};
+    memcpy(b.data(), reinterpret_cast<char*>(&header), sizeof(amessage));
+    return b;
+}
+
+static apacket make_packet(uint32_t cmd, const std::string payload = "") {
+    apacket p;
+    p.msg.command = cmd;
+    p.msg.data_length = payload.size();
+    p.payload.resize(payload.size());
+    memcpy(p.payload.data(), payload.data(), payload.size());
+    return p;
+}
+
+static std::vector<Block> packets_to_blocks(const std::vector<apacket>& packets) {
+    std::vector<Block> blocks;
+    for (auto& p : packets) {
+        // Create the header
+        Block header{sizeof(amessage)};
+        memcpy(header.data(), reinterpret_cast<const char*>(&p.msg), sizeof(amessage));
+        blocks.emplace_back(std::move(header));
+
+        // Create the payload
+        if (p.msg.data_length != 0) {
+            Block payload{p.msg.data_length};
+            memcpy(payload.data(), p.payload.data(), p.msg.data_length);
+            blocks.push_back(std::move(payload));
+        }
+    }
+    return blocks;
+}
+
+TEST(APacketReader, initial_state) {
+    APacketReader reader;
+    auto packets = reader.get_packets();
+    ASSERT_EQ(packets.size(), (size_t)0);
+}
+
+void runAndVerifyAPacketTest(std::vector<Block>& traffic, const std::vector<apacket>& expected) {
+    adb_trace_enable(USB);
+    // Feed the blocks to the reader (on the receiver end)
+    APacketReader reader;
+    for (auto& b : traffic) {
+        auto res = reader.add_bytes(std::move(b));
+        ASSERT_EQ(res, APacketReader::AddResult::OK);
+    }
+
+    // Make sure the input and the output match
+    ASSERT_APACKETS_EQ(expected, reader.get_packets());
+}
+
+TEST(APacketReader, one_packet_two_blocks) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, "12345"));
+
+    auto blocks = packets_to_blocks(input);
+    ASSERT_EQ(size_t(2), blocks.size());
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, one_packet_empty_blocks) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, "12345"));
+
+    auto blocks = packets_to_blocks(input);
+    blocks.emplace(blocks.begin(), Block{0});
+    blocks.emplace_back(Block{0});
+    ASSERT_EQ(size_t(4), blocks.size());
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, no_payload) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY));
+
+    auto blocks = packets_to_blocks(input);
+    // Make sure we have a single block with the header in it.
+    ASSERT_EQ(size_t(1), blocks.size());
+    ASSERT_EQ(sizeof(amessage), blocks[0].size());
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, several_no_payload) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY));
+    input.emplace_back(make_packet(A_WRTE));
+    input.emplace_back(make_packet(A_CLSE));
+    input.emplace_back(make_packet(A_CNXN));
+
+    auto blocks = packets_to_blocks(input);
+    // Make sure we have a single block with the header in it.
+    ASSERT_EQ(size_t(4), blocks.size());
+    for (const auto& block : blocks) {
+        ASSERT_EQ(sizeof(amessage), block.size());
+    }
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, payload_overflow) {
+    std::vector<apacket> input;
+    std::string payload = "0";
+    input.emplace_back(make_packet(A_OKAY, payload));
+
+    // Create a header block but a payload block with too much payload
+    std::vector<Block> blocks;
+    blocks.emplace_back(block_from_header(input[0].msg));
+    blocks.emplace_back(payload + "0");
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, several_packets) {
+    std::vector<apacket> input;
+    for (int i = 0; i < 10; i++) {
+        input.emplace_back(make_packet(i, std::string(i, (char)i)));
+    }
+
+    auto blocks = packets_to_blocks(input);
+    ASSERT_EQ(size_t(19), blocks.size());  // Not 20, because first one has no payload!
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, split_header) {
+    std::string payload = "0123456789";
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, payload));
+
+    // We do some surgery here to split the header into two Blocks
+    std::vector<Block> blocks;
+    // First half of header
+    Block header1(sizeof(amessage) / 2);
+    memcpy(header1.data(), (char*)&input[0].msg, sizeof(amessage) / 2);
+    blocks.emplace_back(std::move(header1));
+
+    // Second half of header
+    Block header2(sizeof(amessage) / 2);
+    memcpy(header2.data(), ((char*)&input[0].msg) + sizeof(amessage) / 2, sizeof(amessage) / 2);
+    blocks.emplace_back(std::move(header2));
+
+    // Payload is not split
+    blocks.emplace_back(Block{payload});
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, payload_and_next_header_merged) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, "12345"));
+    std::string second_payload = "67890";
+    input.emplace_back(make_packet(A_CLSE, second_payload));
+
+    // We do some surgery here to merge the payload of first packet with header of second packet
+    std::vector<Block> blocks;
+    blocks.emplace_back(block_from_header(input[0].msg));
+    Block mergedBlock{input[0].payload.size() + sizeof(amessage)};
+    memcpy(mergedBlock.data(), input[0].payload.data(), input[0].msg.data_length);
+    memcpy(mergedBlock.data() + input[0].msg.data_length, block_from_header(input[1].msg).data(),
+           sizeof(amessage));
+    blocks.emplace_back(std::move(mergedBlock));
+    blocks.emplace_back(Block{second_payload});
+
+    ASSERT_EQ(size_t(3), blocks.size());
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+static Block mergeBlocks(std::vector<Block>& blocks) {
+    size_t total_size = 0;
+    for (Block& b : blocks) {
+        total_size += b.size();
+    }
+    Block block{total_size};
+    size_t rover = 0;
+    for (Block& b : blocks) {
+        memcpy(block.data() + rover, b.data(), b.size());
+        rover += b.size();
+    }
+    return block;
+}
+
+TEST(APacketReader, one_packet_one_block) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, "12345"));
+
+    std::vector<Block> blocks_clean = packets_to_blocks(input);
+    std::vector<Block> blocks;
+    blocks.emplace_back(mergeBlocks(blocks_clean));
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, two_packets_one_block) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, "12345"));
+    input.emplace_back(make_packet(A_WRTE, "67890"));
+
+    std::vector<Block> blocks_clean = packets_to_blocks(input);
+    std::vector<Block> blocks;
+    blocks.emplace_back(mergeBlocks(blocks_clean));
+    ASSERT_EQ(size_t(1), blocks.size());
+
+    runAndVerifyAPacketTest(blocks, input);
+}
+
+TEST(APacketReader, bad_big_payload_header) {
+    std::vector<apacket> input;
+    input.emplace_back(make_packet(A_OKAY, std::string(MAX_PAYLOAD + 1, 'a')));
+    std::vector<Block> blocks = packets_to_blocks(input);
+
+    APacketReader reader;
+    auto res = reader.add_bytes(std::move(blocks[0]));
+    ASSERT_EQ(res, APacketReader::AddResult::ERROR);
+}
+
+std::vector<Block> splitBlock(Block src_block, size_t chop_size) {
+    std::vector<Block> blocks;
+    while (src_block.remaining()) {
+        Block block{std::min(chop_size, src_block.remaining())};
+        block.fillFrom(src_block);
+        block.rewind();
+        blocks.emplace_back(std::move(block));
+    }
+    return blocks;
+}
+
+// Collapse all packets into a single block. Chop it into chop_size Blocks.
+// And feed that to the packet reader.
+void chainSaw(int chop_size) {
+    std::vector<apacket> packets;
+    packets.emplace_back(make_packet(A_CNXN));
+    packets.emplace_back(make_packet(A_OKAY, "12345"));
+    packets.emplace_back(make_packet(A_WRTE, "6890"));
+    packets.emplace_back(make_packet(A_CNXN));
+    packets.emplace_back(make_packet(A_AUTH, "abc"));
+    packets.emplace_back(make_packet(A_WRTE));
+    ASSERT_EQ(size_t(6), packets.size());
+
+    auto all_blocks = packets_to_blocks(packets);
+    ASSERT_EQ(size_t(9), all_blocks.size());
+
+    auto single_block = mergeBlocks(all_blocks);
+    auto single_block_size = single_block.remaining();
+    auto blocks = splitBlock(std::move(single_block), chop_size);
+    auto expected_num_blocks =
+            single_block_size / chop_size + (single_block_size % chop_size == 0 ? 0 : 1);
+    ASSERT_EQ(expected_num_blocks, blocks.size());
+
+    runAndVerifyAPacketTest(blocks, packets);
+}
+
+TEST(APacketReader, chainsaw) {
+    // Try to send packets, chopping in various pieces sizes
+    for (int i = 1; i < 256; i++) {
+        chainSaw(i);
+    }
+}
\ No newline at end of file
```

