```diff
diff --git a/Android.bp b/Android.bp
index 076cfe9f..7a7e4915 100644
--- a/Android.bp
+++ b/Android.bp
@@ -118,6 +118,10 @@ cc_defaults {
         "-UADB_HOST",
         "-DADB_HOST=0",
     ],
+
+    shared_libs: [
+        "libprocessgroup",
+    ],
 }
 
 cc_defaults {
@@ -269,13 +273,16 @@ cc_library_host_static {
 
     srcs: libadb_srcs + [
         "client/openscreen/mdns_service_info.cpp",
-        "client/openscreen/mdns_service_watcher.cpp",
         "client/openscreen/platform/logging.cpp",
         "client/openscreen/platform/task_runner.cpp",
         "client/openscreen/platform/udp_socket.cpp",
         "client/auth.cpp",
         "client/adb_wifi.cpp",
+        "client/detach.cpp",
         "client/usb_libusb.cpp",
+        "client/usb_libusb_device.cpp",
+        "client/usb_libusb_hotplug.cpp",
+        "client/usb_libusb_inhouse_hotplug.cpp",
         "client/transport_emulator.cpp",
         "client/mdnsresponder_client.cpp",
         "client/mdns_utils.cpp",
@@ -359,10 +366,7 @@ cc_library {
         "//packages/modules/adb:__subpackages__",
     ],
 
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 }
 
 cc_test_host {
@@ -444,7 +448,6 @@ cc_defaults {
         "client/adb_install.cpp",
         "client/line_printer.cpp",
         "client/fastdeploy.cpp",
-        "client/fastdeploycallbacks.cpp",
         "client/incremental.cpp",
         "client/incremental_server.cpp",
         "client/incremental_utils.cpp",
diff --git a/README.md b/README.md
index 62741148..17b3d337 100644
--- a/README.md
+++ b/README.md
@@ -1,9 +1,9 @@
 # ADB (Android Debug Bridge) repository
 
-The Android Debug Bridge connects Android devices to to computers running other OSes (Linux, MacOS, and Windows) over USB or TCP.
+The Android Debug Bridge connects Android devices to computers running other OSes (Linux, MacOS, and Windows) over USB or TCP.
 
 ## User documentation
 [man page](docs/user/adb.1.md)
 
 ## Developer documentation
-[main page](docs/dev/internals.md)
+[main page](docs/dev/README.md)
diff --git a/adb.cpp b/adb.cpp
index 66d5785e..a2406761 100644
--- a/adb.cpp
+++ b/adb.cpp
@@ -74,6 +74,8 @@ using namespace std::chrono_literals;
 
 #if ADB_HOST
 #include "adb_host.pb.h"
+#include "client/detach.h"
+#include "client/mdns_utils.h"
 #include "client/usb.h"
 #endif
 
@@ -199,11 +201,11 @@ void handle_online(atransport *t)
 void handle_offline(atransport *t)
 {
     if (t->GetConnectionState() == kCsOffline) {
-        LOG(INFO) << t->serial_name() << ": already offline";
+        VLOG(ADB) << t->serial_name() << ": already offline";
         return;
     }
 
-    LOG(INFO) << t->serial_name() << ": offline";
+    VLOG(ADB) << t->serial_name() << ": offline";
 
 #if !ADB_HOST && defined(__ANDROID__)
     DecrementActiveConnections();
@@ -535,13 +537,13 @@ void handle_packet(apacket *p, atransport *t)
         s->peer->peer = s;
 
         if (t->SupportsDelayedAck()) {
-            LOG(DEBUG) << "delayed ack available: send buffer = " << send_bytes;
+            VLOG(PACKETS) << "delayed ack available: send buffer = " << send_bytes;
             s->available_send_bytes = send_bytes;
 
             // TODO: Make this adjustable at connection time?
             send_ready(s->id, s->peer->id, t, INITIAL_DELAYED_ACK_BYTES);
         } else {
-            LOG(DEBUG) << "delayed ack unavailable";
+            VLOG(PACKETS) << "delayed ack unavailable";
             send_ready(s->id, s->peer->id, t, 0);
         }
 
@@ -1370,6 +1372,9 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
         status.set_executable_absolute_path(android::base::GetExecutablePath());
         status.set_log_absolute_path(GetLogFilePath());
         status.set_os(GetOSVersion());
+        status.set_burst_mode(burst_mode_enabled());
+        status.set_trace_level(get_trace_setting());
+        status.set_mdns_enabled(mdns::is_enabled());
 
         std::string server_status_string;
         status.SerializeToString(&server_status_string);
@@ -1551,6 +1556,7 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
             return HostRequestResult::Handled;
         }
 
+        attached_devices.RegisterAttach(t->serial_name());
         if (t->Attach(&error)) {
             SendOkay(reply_fd,
                      android::base::StringPrintf("%s attached", t->serial_name().c_str()));
@@ -1578,6 +1584,7 @@ HostRequestResult handle_host_request(std::string_view service, TransportType ty
         // function that called us.
         s->transport = nullptr;
 
+        attached_devices.RegisterDetach(t->serial_name());
         if (t->Detach(&error)) {
             SendOkay(reply_fd,
                      android::base::StringPrintf("%s detached", t->serial_name().c_str()));
diff --git a/adb_mdns.cpp b/adb_mdns.cpp
index bd5ff5d6..c5bb9aab 100644
--- a/adb_mdns.cpp
+++ b/adb_mdns.cpp
@@ -26,24 +26,11 @@
 
 #include "adb_trace.h"
 
-#define ADB_SECURE_SERVICE_VERSION_TXT_RECORD(ver) ("v=" #ver)
-
-const char* kADBSecurePairingServiceTxtRecord =
-        ADB_SECURE_SERVICE_VERSION_TXT_RECORD(ADB_SECURE_SERVICE_VERSION);
-const char* kADBSecureConnectServiceTxtRecord =
-        ADB_SECURE_SERVICE_VERSION_TXT_RECORD(ADB_SECURE_SERVICE_VERSION);
-
 #define ADB_FULL_MDNS_SERVICE_TYPE(atype) ("_" atype "._tcp")
 const char* kADBDNSServices[] = {ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_SERVICE_TYPE),
                                  ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_PAIRING_TYPE),
                                  ADB_FULL_MDNS_SERVICE_TYPE(ADB_MDNS_TLS_CONNECT_TYPE)};
 
-const char* kADBDNSServiceTxtRecords[] = {
-        nullptr,
-        kADBSecurePairingServiceTxtRecord,
-        kADBSecureConnectServiceTxtRecord,
-};
-
 #if ADB_HOST
 namespace {
 
diff --git a/adb_mdns.h b/adb_mdns.h
index 14fdc536..e2da4b51 100644
--- a/adb_mdns.h
+++ b/adb_mdns.h
@@ -48,11 +48,10 @@ extern const char* _Nonnull kADBDNSServices[kNumADBDNSServices];
 extern const char* _Nonnull kADBDNSServiceTxtRecords[kNumADBDNSServices];
 
 #if ADB_HOST
+#include "client/openscreen/mdns_service_info.h"
 // ADB Secure DNS service interface. Used to query what ADB Secure DNS services have been
 // resolved, and to run some kind of callback for each one.
-using adb_secure_foreach_service_callback =
-        std::function<void(const std::string& service_name, const std::string& reg_type,
-                           const std::string& ip_address, uint16_t port)>;
+using adb_secure_foreach_service_callback = std::function<void(const mdns::ServiceInfo& si)>;
 
 // Tries to connect to a |service_name| if found. Returns true if found and
 // connected, false otherwise.
diff --git a/adb_trace.cpp b/adb_trace.cpp
index cb83b832..79829d7f 100644
--- a/adb_trace.cpp
+++ b/adb_trace.cpp
@@ -131,6 +131,7 @@ static void setup_trace_mask() {
             {"shell", SHELL},
             {"incremental", INCREMENTAL},
             {"mdns", MDNS},
+            {"mdns-stack", MDNS_STACK},
     };
 
     // Make sure we check for ALL enum in AdbTrace.
diff --git a/adb_trace.h b/adb_trace.h
index d5a10d99..f2f3896d 100644
--- a/adb_trace.h
+++ b/adb_trace.h
@@ -17,6 +17,8 @@
 #ifndef __ADB_TRACE_H
 #define __ADB_TRACE_H
 
+#include <string>
+
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
 
@@ -40,6 +42,7 @@ enum AdbTrace {
     SHELL,
     INCREMENTAL,
     MDNS,
+    MDNS_STACK,
     NUM_TRACES,
 };
 
@@ -60,5 +63,6 @@ enum AdbTrace {
 extern int adb_trace_mask;
 void adb_trace_init(char**);
 void adb_trace_enable(AdbTrace trace_tag);
+std::string get_trace_setting();
 
 #endif /* __ADB_TRACE_H */
diff --git a/apex/Android.bp b/apex/Android.bp
index 05c40e4c..ca99d8c6 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -45,6 +45,7 @@ apex_test {
     defaults: ["com.android.adbd-defaults"],
     manifest: "test_apex_manifest.json",
     file_contexts: ":com.android.adbd-file_contexts",
+    apex_available_name: "com.android.adbd",
     installable: false,
 }
 
diff --git a/client/adb_install.cpp b/client/adb_install.cpp
index 451b96d5..566bdb53 100644
--- a/client/adb_install.cpp
+++ b/client/adb_install.cpp
@@ -538,9 +538,12 @@ static int install_multiple_app_streamed(int argc, const char** argv) {
         }
 
         if (android::base::EndsWithIgnoreCase(file, ".apk") ||
-            android::base::EndsWithIgnoreCase(file, ".dm") ||
+            android::base::EndsWithIgnoreCase(
+                    file, ".dm") ||  // dex metadata, for cloud profile and cloud verification
+            android::base::EndsWithIgnoreCase(
+                    file, ".sdm") ||  // secure dex metadata, for cloud compilation
             android::base::EndsWithIgnoreCase(file, ".fsv_sig") ||
-            android::base::EndsWithIgnoreCase(file, ".idsig")) {  // v4 external signature.
+            android::base::EndsWithIgnoreCase(file, ".idsig")) {  // v4 external signature
             struct stat sb;
             if (stat(file, &sb) == -1) perror_exit("failed to stat \"%s\"", file);
             total_size += sb.st_size;
diff --git a/client/commandline.cpp b/client/commandline.cpp
index 876d13e9..d7a517fd 100644
--- a/client/commandline.cpp
+++ b/client/commandline.cpp
@@ -43,12 +43,12 @@
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
-#if !defined(_WIN32)
-#include <sys/ioctl.h>
-#include <termios.h>
-#else
+#if defined(_WIN32)
 #define _POSIX
 #include <signal.h>
+#else
+#include <sys/ioctl.h>
+#include <termios.h>
 #endif
 
 #include <google/protobuf/text_format.h>
@@ -2078,7 +2078,7 @@ int adb_commandline(int argc, const char** argv) {
                                             "system", "system_ext", "vendor"};
         bool found = false;
         for (const auto& partition : partitions) {
-            if (src == "all" || src == partition) {
+            if (src == "all" || src == partition || (src == "/" + partition)) {
                 std::string src_dir{product_file(partition)};
                 if (!directory_exists(src_dir)) continue;
                 found = true;
diff --git a/client/detach.cpp b/client/detach.cpp
new file mode 100644
index 00000000..88afa7f6
--- /dev/null
+++ b/client/detach.cpp
@@ -0,0 +1,45 @@
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
+#include "detach.h"
+
+#include "usb.h"
+
+AttachedDevices attached_devices [[clang::no_destroy]];
+
+void AttachedDevices::RegisterAttach(const std::string& serial) {
+    std::lock_guard<std::mutex> lock(attached_devices_mutex_);
+    attached_devices_.insert(serial);
+}
+
+void AttachedDevices::RegisterDetach(const std::string& serial) {
+    std::lock_guard<std::mutex> lock(attached_devices_mutex_);
+    attached_devices_.erase(serial);
+}
+
+bool AttachedDevices::IsAttached(const std::string& serial) {
+    std::lock_guard<std::mutex> lock(attached_devices_mutex_);
+    return attached_devices_.contains(serial);
+}
+
+bool AttachedDevices::ShouldStartDetached(const Connection& c) {
+    if (!c.SupportsDetach()) {
+        return false;
+    }
+    static const char* env = getenv("ADB_LIBUSB_START_DETACHED");
+    static bool should_start_detached = env && strcmp("1", env) == 0;
+    return should_start_detached && !IsAttached(c.Serial());
+}
\ No newline at end of file
diff --git a/client/detach.h b/client/detach.h
new file mode 100644
index 00000000..8aa5e0d4
--- /dev/null
+++ b/client/detach.h
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
+#include <unordered_set>
+
+#include "transport.h"
+
+// If an adb server uses ADB_LIBUSB_START_DETACHED, all devices started detached. But we need a way
+// to tell if this setting should be overridden when a device is attached and then intentionally
+// disconnected and then reconnected (which can happen via `adb reboot` or `adb root/unroot`).
+class AttachedDevices {
+  public:
+    void RegisterAttach(const std::string& serial);
+
+    void RegisterDetach(const std::string& serial);
+
+    bool ShouldStartDetached(const Connection& connection);
+
+  private:
+    bool IsAttached(const std::string& serial);
+
+    std::mutex attached_devices_mutex_;
+
+    // Stores serial numbers of all devices which have been attached.
+    // Entries are cleared when a device is detached.
+    std::unordered_set<std::string> attached_devices_ GUARDED_BY(attached_devices_mutex_);
+};
+
+extern AttachedDevices attached_devices;
\ No newline at end of file
diff --git a/client/fastdeploy.cpp b/client/fastdeploy.cpp
index ee042a17..175dd77b 100644
--- a/client/fastdeploy.cpp
+++ b/client/fastdeploy.cpp
@@ -22,6 +22,7 @@
 #include <memory>
 
 #include "android-base/file.h"
+#include "android-base/parseint.h"
 #include "android-base/strings.h"
 #include "androidfw/ResourceTypes.h"
 #include "androidfw/ZipFileRO.h"
@@ -32,14 +33,11 @@
 #include "fastdeploy/deploypatchgenerator/deploy_patch_generator.h"
 #include "fastdeploy/deploypatchgenerator/patch_utils.h"
 #include "fastdeploy/proto/ApkEntry.pb.h"
-#include "fastdeploycallbacks.h"
 #include "sysdeps.h"
 
 #include "adb_client.h"
 #include "adb_utils.h"
 
-static constexpr long kRequiredAgentVersion = 0x00000003;
-
 static constexpr int kPackageMissing = 3;
 static constexpr int kInvalidAgentVersion = 4;
 
@@ -71,31 +69,18 @@ struct TimeReporter {
 };
 #define REPORT_FUNC_TIME() TimeReporter reporter(__func__)
 
-struct FileDeleter {
-    FileDeleter(const char* path) : path_(path) {}
-    ~FileDeleter() { adb_unlink(path_); }
-
-  private:
-    const char* const path_;
-};
-
 }  // namespace
 
 int get_device_api_level() {
     static const int api_level = [] {
         REPORT_FUNC_TIME();
-        std::vector<char> sdk_version_output_buffer;
-        std::vector<char> sdk_version_error_buffer;
-        int api_level = -1;
-
-        int status_code =
-                capture_shell_command("getprop ro.build.version.sdk", &sdk_version_output_buffer,
-                                      &sdk_version_error_buffer);
-        if (status_code == 0 && sdk_version_output_buffer.size() > 0) {
-            api_level = strtol((char*)sdk_version_output_buffer.data(), nullptr, 10);
-        }
 
-        return api_level;
+        std::string getprop_stdout, getprop_stderr;
+        DefaultStandardStreamsCallback cb(&getprop_stdout, &getprop_stderr);
+        int status_code = send_shell_command("getprop ro.build.version.sdk", false, &cb);
+
+        int api_level;
+        return android::base::ParseInt(getprop_stdout, &api_level) ? api_level : -1;
     }();
     return api_level;
 }
@@ -127,9 +112,8 @@ static bool deploy_agent(bool check_time_stamps) {
 
     // on windows the shell script might have lost execute permission
     // so need to set this explicitly
-    const char* kChmodCommandPattern = "chmod 777 %s";
     std::string chmod_command =
-            android::base::StringPrintf(kChmodCommandPattern, kDeviceAgentScript);
+            android::base::StringPrintf("chmod 777 %s", kDeviceAgentScript);
     int ret = send_shell_command(chmod_command);
     if (ret != 0) {
         error_exit("Error executing %s returncode: %d", chmod_command.c_str(), ret);
@@ -216,14 +200,6 @@ static std::string get_package_name_from_apk(const char* apk_path) {
     error_exit("Could not find package name tag in AndroidManifest.xml inside %s", apk_path);
 }
 
-static long parse_agent_version(const std::vector<char>& version_buffer) {
-    long version = -1;
-    if (!version_buffer.empty()) {
-        version = strtol((char*)version_buffer.data(), NULL, 16);
-    }
-    return version;
-}
-
 static void update_agent_if_necessary() {
     switch (g_agent_update_strategy) {
         case FastDeploy_AgentUpdateAlways:
@@ -243,41 +219,33 @@ std::optional<APKMetaData> extract_metadata(const char* apk_path) {
 
     REPORT_FUNC_TIME();
 
-    std::string package_name = get_package_name_from_apk(apk_path);
-
     // Dump apk command checks the required vs current agent version and if they match then returns
     // the APK dump for package. Doing this in a single call saves round-trip and agent launch time.
-    constexpr const char* kAgentDumpCommandPattern = "/data/local/tmp/deployagent dump %ld %s";
+    std::string package_name(escape_arg(get_package_name_from_apk(apk_path)));
     std::string dump_command = android::base::StringPrintf(
-            kAgentDumpCommandPattern, kRequiredAgentVersion, package_name.c_str());
+            "/data/local/tmp/deployagent dump 3 %s", package_name.c_str());
 
-    std::vector<char> dump_out_buffer;
-    std::vector<char> dump_error_buffer;
-    int returnCode =
-            capture_shell_command(dump_command.c_str(), &dump_out_buffer, &dump_error_buffer);
+    std::string dump_out_buffer;
+    std::string dump_error_buffer;
+    DefaultStandardStreamsCallback cb(&dump_out_buffer, &dump_error_buffer);
+    int returnCode = send_shell_command(dump_command, false, &cb);
     if (returnCode >= kInvalidAgentVersion) {
-        // Agent has wrong version or missing.
-        long agent_version = parse_agent_version(dump_out_buffer);
-        if (agent_version < 0) {
+        long agent_version;
+        if (!android::base::ParseInt(dump_out_buffer, &agent_version)) {
             printf("Could not detect agent on device, deploying\n");
         } else {
-            printf("Device agent version is (%ld), (%ld) is required, re-deploying\n",
-                   agent_version, kRequiredAgentVersion);
+            printf("Device agent version is old (%ld), re-deploying\n", agent_version);
         }
         deploy_agent(/*check_time_stamps=*/false);
 
         // Retry with new agent.
         dump_out_buffer.clear();
         dump_error_buffer.clear();
-        returnCode =
-                capture_shell_command(dump_command.c_str(), &dump_out_buffer, &dump_error_buffer);
+        returnCode = send_shell_command(dump_command, false, &cb);
     }
     if (returnCode != 0) {
         if (returnCode == kInvalidAgentVersion) {
-            long agent_version = parse_agent_version(dump_out_buffer);
-            error_exit(
-                    "After update agent version remains incorrect! Expected %ld but version is %ld",
-                    kRequiredAgentVersion, agent_version);
+            error_exit("After update agent version remains old: %s", dump_out_buffer.c_str());
         }
         if (returnCode == kPackageMissing) {
             fprintf(stderr, "Package %s not found, falling back to install\n",
@@ -300,7 +268,6 @@ std::optional<APKMetaData> extract_metadata(const char* apk_path) {
 
 unique_fd install_patch(int argc, const char** argv) {
     REPORT_FUNC_TIME();
-    constexpr char kAgentApplyServicePattern[] = "shell:/data/local/tmp/deployagent apply - -pm %s";
 
     std::vector<unsigned char> apply_output_buffer;
     std::vector<unsigned char> apply_error_buffer;
@@ -320,7 +287,8 @@ unique_fd install_patch(int argc, const char** argv) {
 
     std::string error;
     std::string apply_patch_service_string =
-            android::base::StringPrintf(kAgentApplyServicePattern, argsString.c_str());
+            android::base::StringPrintf("shell:/data/local/tmp/deployagent apply - -pm %s",
+                                        argsString.c_str());
     unique_fd fd{adb_connect(apply_patch_service_string, &error)};
     if (fd < 0) {
         error_exit("Executing %s returned %s", apply_patch_service_string.c_str(), error.c_str());
@@ -330,11 +298,10 @@ unique_fd install_patch(int argc, const char** argv) {
 
 unique_fd apply_patch_on_device(const char* output_path) {
     REPORT_FUNC_TIME();
-    constexpr char kAgentApplyServicePattern[] = "shell:/data/local/tmp/deployagent apply - -o %s";
-
     std::string error;
     std::string apply_patch_service_string =
-            android::base::StringPrintf(kAgentApplyServicePattern, output_path);
+            android::base::StringPrintf("shell:/data/local/tmp/deployagent apply - -o %s",
+                                        output_path);
     unique_fd fd{adb_connect(apply_patch_service_string, &error)};
     if (fd < 0) {
         error_exit("Executing %s returned %s", apply_patch_service_string.c_str(), error.c_str());
diff --git a/client/fastdeploycallbacks.cpp b/client/fastdeploycallbacks.cpp
deleted file mode 100644
index 7cebe0ce..00000000
--- a/client/fastdeploycallbacks.cpp
+++ /dev/null
@@ -1,73 +0,0 @@
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
-#define TRACE_TAG ADB
-
-#include <fcntl.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <sys/stat.h>
-
-#include "client/file_sync_client.h"
-#include "commandline.h"
-#include "sysdeps.h"
-
-#include "fastdeploycallbacks.h"
-
-static void appendBuffer(std::vector<char>* buffer, const char* input, int length) {
-    if (buffer != NULL) {
-        buffer->insert(buffer->end(), input, input + length);
-    }
-}
-
-class DeployAgentBufferCallback : public StandardStreamsCallbackInterface {
-  public:
-    DeployAgentBufferCallback(std::vector<char>* outBuffer, std::vector<char>* errBuffer);
-
-    virtual bool OnStdout(const char* buffer, size_t length);
-    virtual bool OnStderr(const char* buffer, size_t length);
-    virtual int Done(int status);
-
-  private:
-    std::vector<char>* mpOutBuffer;
-    std::vector<char>* mpErrBuffer;
-};
-
-int capture_shell_command(const char* command, std::vector<char>* outBuffer,
-                          std::vector<char>* errBuffer) {
-    DeployAgentBufferCallback cb(outBuffer, errBuffer);
-    return send_shell_command(command, /*disable_shell_protocol=*/false, &cb);
-}
-
-DeployAgentBufferCallback::DeployAgentBufferCallback(std::vector<char>* outBuffer,
-                                                     std::vector<char>* errBuffer) {
-    mpOutBuffer = outBuffer;
-    mpErrBuffer = errBuffer;
-}
-
-bool DeployAgentBufferCallback::OnStdout(const char* buffer, size_t length) {
-    appendBuffer(mpOutBuffer, buffer, length);
-    return true;
-}
-
-bool DeployAgentBufferCallback::OnStderr(const char* buffer, size_t length) {
-    appendBuffer(mpErrBuffer, buffer, length);
-    return true;
-}
-
-int DeployAgentBufferCallback::Done(int status) {
-    return status;
-}
diff --git a/client/incremental.cpp b/client/incremental.cpp
index de93cb75..f6cf1b04 100644
--- a/client/incremental.cpp
+++ b/client/incremental.cpp
@@ -194,6 +194,9 @@ std::optional<Process> install(const Files& files, const Args& passthrough_args,
     auto pipe_write_fd_param = std::to_string(cast_handle_to_int(adb_get_os_handle(pipe_write_fd)));
     close_on_exec(pipe_read_fd);
 
+    // We spawn an incremental server that will be up until all blocks have been fed to the
+    // Package Manager. This could take a long time depending on the size of the files to
+    // stream so we use a process able to outlive adb.
     std::vector<std::string> args(std::move(files));
     args.insert(args.begin(), {"inc-server", fd_param, pipe_write_fd_param});
     auto child =
@@ -210,6 +213,9 @@ std::optional<Process> install(const Files& files, const Args& passthrough_args,
     auto killOnExit = [](Process* p) { p->kill(); };
     std::unique_ptr<Process, decltype(killOnExit)> serverKiller(&child, killOnExit);
 
+    // Block until the Package Manager has received enough blocks to declare the installation
+    // successful or failure. Meanwhile, the incremental server is still sending blocks to the
+    // device.
     Result result = wait_for_installation(pipe_read_fd);
     adb_close(pipe_read_fd);
 
@@ -225,6 +231,9 @@ std::optional<Process> install(const Files& files, const Args& passthrough_args,
     return child;
 }
 
+// Wait until the Package Manager returns either "Success" or "Failure". The streaming
+// may not have finished when this happens but PM received all the blocks is needs
+// to decide if installation was ok.
 Result wait_for_installation(int read_fd) {
     static constexpr int maxMessageSize = 256;
     std::vector<char> child_stdout(CHUNK_SIZE);
diff --git a/client/main.cpp b/client/main.cpp
index 59d8403e..50a60a7b 100644
--- a/client/main.cpp
+++ b/client/main.cpp
@@ -37,8 +37,10 @@
 #include "adb_mdns.h"
 #include "adb_utils.h"
 #include "adb_wifi.h"
+#include "client/mdns_utils.h"
 #include "client/transport_client.h"
 #include "client/usb.h"
+#include "client/usb_libusb_hotplug.h"
 #include "commandline.h"
 #include "sysdeps/chrono.h"
 #include "transport.h"
@@ -133,7 +135,7 @@ int adb_server_main(int is_daemon, const std::string& socket_spec, const char* o
 
     init_reconnect_handler();
 
-    if (!getenv("ADB_MDNS") || strcmp(getenv("ADB_MDNS"), "0") != 0) {
+    if (mdns::is_enabled()) {
         init_mdns_transport_discovery();
     }
 
diff --git a/client/mdns_utils.cpp b/client/mdns_utils.cpp
index 8666b18e..74a90366 100644
--- a/client/mdns_utils.cpp
+++ b/client/mdns_utils.cpp
@@ -74,4 +74,8 @@ std::optional<MdnsInstance> mdns_parse_instance_name(std::string_view name) {
     return std::make_optional<MdnsInstance>(name.substr(0, pos), name.substr(pos + 1), transport);
 }
 
+bool is_enabled() {
+    return !getenv("ADB_MDNS") || strcmp(getenv("ADB_MDNS"), "0") != 0;
+}
+
 }  // namespace mdns
diff --git a/client/mdns_utils.h b/client/mdns_utils.h
index 40d095dd..86b8fe98 100644
--- a/client/mdns_utils.h
+++ b/client/mdns_utils.h
@@ -51,4 +51,6 @@ struct MdnsInstance {
 // otherwise returns std::nullopt.
 std::optional<MdnsInstance> mdns_parse_instance_name(std::string_view name);
 
+// Return true if mdns backend is enabled
+bool is_enabled();
 }  // namespace mdns
diff --git a/client/mdnsresponder_client.cpp b/client/mdnsresponder_client.cpp
index 3b262504..dbf2b45c 100644
--- a/client/mdnsresponder_client.cpp
+++ b/client/mdnsresponder_client.cpp
@@ -303,15 +303,15 @@ void ResolvedService::ForEachService(const ServiceRegistry& services,
     InitAdbServiceRegistries();
 
     for (const auto& service : services) {
-        auto service_name = service->service_name();
-        auto reg_type = service->reg_type();
-        auto ip = service->ip_address();
-        auto port = service->port();
-
+        const auto ivp4 = openscreen::IPAddress::Parse(service->ip_address()).value();
+        // Bonjour doesn't resolve ipv6 currently so we just use "any" address.
+        const auto ivp6 = openscreen::IPAddress::Parse("::").value();
+        mdns::ServiceInfo si{service->service_name(), service->reg_type(), ivp4, ivp6,
+                             service->port()};
         if (wanted_service_name.empty()) {
-            cb(service_name.c_str(), reg_type.c_str(), ip.c_str(), port);
-        } else if (service_name == wanted_service_name) {
-            cb(service_name.c_str(), reg_type.c_str(), ip.c_str(), port);
+            cb(si);
+        } else if (service->service_name() == wanted_service_name) {
+            cb(si);
         }
     }
 }
@@ -578,10 +578,10 @@ std::string mdns_check() {
 
 std::string mdns_list_discovered_services() {
     std::string result;
-    auto cb = [&](const std::string& service_name, const std::string& reg_type,
-                  const std::string& ip_addr, uint16_t port) {
-        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", service_name.c_str(),
-                                              reg_type.c_str(), ip_addr.c_str(), port);
+    auto cb = [&](const mdns::ServiceInfo& si) {
+        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", si.instance_name.c_str(),
+                                              si.service_name.c_str(),
+                                              si.v4_address_string().c_str(), si.port);
     };
 
     ResolvedService::ForEachService(*ResolvedService::sAdbTransportServices, "", cb);
@@ -607,9 +607,9 @@ std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
     }
 
     std::optional<MdnsInfo> info;
-    auto cb = [&](const std::string& service_name, const std::string& reg_type,
-                  const std::string& ip_addr,
-                  uint16_t port) { info.emplace(service_name, reg_type, ip_addr, port); };
+    auto cb = [&](const mdns::ServiceInfo& si) {
+        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
+    };
 
     std::string reg_type;
     if (!mdns_instance->service_name.empty()) {
@@ -656,9 +656,9 @@ std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name) {
     }
 
     std::optional<MdnsInfo> info;
-    auto cb = [&](const std::string& service_name, const std::string& reg_type,
-                  const std::string& ip_addr,
-                  uint16_t port) { info.emplace(service_name, reg_type, ip_addr, port); };
+    auto cb = [&](const mdns::ServiceInfo& si) {
+        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
+    };
 
     // Verify it's a pairing service if user explicitly inputs it.
     if (!mdns_instance->service_name.empty()) {
diff --git a/client/openscreen/mdns_service_info.cpp b/client/openscreen/mdns_service_info.cpp
index 73d06514..fb338882 100644
--- a/client/openscreen/mdns_service_info.cpp
+++ b/client/openscreen/mdns_service_info.cpp
@@ -22,6 +22,18 @@ using namespace openscreen;
 
 namespace mdns {
 
+std::string ServiceInfo::v4_address_string() const {
+    std::stringstream ss;
+    ss << v4_address;
+    return ss.str();
+}
+
+std::string ServiceInfo::v6_address_string() const {
+    std::stringstream ss;
+    ss << v6_address;
+    return ss.str();
+}
+
 ErrorOr<ServiceInfo> DnsSdInstanceEndpointToServiceInfo(
         const discovery::DnsSdInstanceEndpoint& endpoint) {
     ServiceInfo service_info;
diff --git a/client/openscreen/mdns_service_info.h b/client/openscreen/mdns_service_info.h
index 501b20cf..e6407184 100644
--- a/client/openscreen/mdns_service_info.h
+++ b/client/openscreen/mdns_service_info.h
@@ -31,6 +31,9 @@ struct ServiceInfo {
     openscreen::IPAddress v4_address;
     openscreen::IPAddress v6_address;
     uint16_t port;
+
+    std::string v4_address_string() const;
+    std::string v6_address_string() const;
 };  // ServiceInfo
 
 openscreen::ErrorOr<ServiceInfo> DnsSdInstanceEndpointToServiceInfo(
diff --git a/client/openscreen/mdns_service_watcher.cpp b/client/openscreen/mdns_service_watcher.cpp
deleted file mode 100644
index 2791ff75..00000000
--- a/client/openscreen/mdns_service_watcher.cpp
+++ /dev/null
@@ -1,32 +0,0 @@
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
-#include "client/openscreen/mdns_service_watcher.h"
-
-#include "client/openscreen/mdns_service_info.h"
-
-using namespace openscreen;
-
-namespace mdns {
-
-ServiceReceiver::ServiceReceiver(
-        discovery::DnsSdService* service, std::string_view service_name,
-        openscreen::discovery::DnsSdServiceWatcher<ServiceInfo>::ServicesUpdatedCallback cb)
-    : discovery::DnsSdServiceWatcher<ServiceInfo>(
-              service, service_name.data(), DnsSdInstanceEndpointToServiceInfo, std::move(cb)) {
-    LOG(VERBOSE) << "Initializing ServiceReceiver service=" << service_name;
-}
-}  // namespace mdns
diff --git a/client/openscreen/mdns_service_watcher.h b/client/openscreen/mdns_service_watcher.h
deleted file mode 100644
index efea2609..00000000
--- a/client/openscreen/mdns_service_watcher.h
+++ /dev/null
@@ -1,39 +0,0 @@
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
-#pragma once
-
-#include <string_view>
-
-#include "client/openscreen/mdns_service_info.h"
-
-#include <discovery/public/dns_sd_service_watcher.h>
-
-namespace mdns {
-
-class ServiceReceiver : public ::openscreen::discovery::DnsSdServiceWatcher<ServiceInfo> {
-  public:
-    explicit ServiceReceiver(
-            openscreen::discovery::DnsSdService* service, std::string_view service_name,
-            openscreen::discovery::DnsSdServiceWatcher<ServiceInfo>::ServicesUpdatedCallback cb);
-
-    const std::string& service_name() const { return service_name_; }
-
-  private:
-    std::string service_name_;
-};  // ServiceReceiver
-
-}  // namespace mdns
diff --git a/client/openscreen/platform/logging.cpp b/client/openscreen/platform/logging.cpp
index 90e99f71..3b9be16a 100644
--- a/client/openscreen/platform/logging.cpp
+++ b/client/openscreen/platform/logging.cpp
@@ -18,36 +18,44 @@
 
 #include <android-base/logging.h>
 
+#include "adb_trace.h"
+
 namespace openscreen {
 
 bool IsLoggingOn(LogLevel level, const char* file) {
     return true;
 }
 
-void LogWithLevel(LogLevel level, const char* file, int line, std::stringstream desc) {
-    android::base::LogSeverity severity;
+static android::base::LogSeverity OpenScreenLogLevelToAndroid(LogLevel level) {
     switch (level) {
+        case LogLevel::kVerbose:
+            return android::base::VERBOSE;
         case LogLevel::kInfo:
-            severity = android::base::LogSeverity::INFO;
-            break;
+            return android::base::INFO;
         case LogLevel::kWarning:
-            severity = android::base::LogSeverity::WARNING;
-            break;
+            return android::base::WARNING;
         case LogLevel::kError:
-            severity = android::base::LogSeverity::ERROR;
-            break;
+            return android::base::ERROR;
         case LogLevel::kFatal:
-            severity = android::base::LogSeverity::FATAL;
-            break;
-        default:
-            severity = android::base::LogSeverity::DEBUG;
-            break;
+            return android::base::FATAL;
+    }
+}
+
+void LogWithLevel(LogLevel level, const char* file, int line, std::stringstream desc) {
+    auto severity = OpenScreenLogLevelToAndroid(level);
+    std::string msg = std::string("(") + file + ":" + std::to_string(line) + ") " + desc.str();
+
+    // We never ignore a warning or worse (error and fatals).
+    if (severity >= android::base::WARNING) {
+        LOG(severity) << msg;
+    } else {
+        VLOG(MDNS_STACK) << msg;
     }
-    LOG(severity) << std::string("(") + file + ":" + std::to_string(line) + ") " + desc.str();
 }
 
 [[noreturn]] void Break() {
-    std::abort();
+    LOG(FATAL) << "openscreen Break() called";
+    abort(); // LOG(FATAL) isn't [[noreturn]].
 }
 
 }  // namespace openscreen
diff --git a/client/openscreen/platform/udp_socket.cpp b/client/openscreen/platform/udp_socket.cpp
index d85661c2..a8747492 100644
--- a/client/openscreen/platform/udp_socket.cpp
+++ b/client/openscreen/platform/udp_socket.cpp
@@ -399,7 +399,6 @@ class AdbUdpSocket : public UdpSocket {
             return;
         }
 
-        VLOG(MDNS) << "SendMessage ip=" << dest.ToString() << ", size=" << length;
         adb_iovec iov;
         iov.iov_len = length;
         iov.iov_base = const_cast<void*>(data);
@@ -438,13 +437,14 @@ class AdbUdpSocket : public UdpSocket {
             }
         }
 
-        if (num_bytes_sent == -1) {
+        // Some VPN result in "short send" where less than the full datagram is reported sent. We
+        // shield ourselves from these and hypothetical "long send" and plain errors by reporting
+        // any unexpected return value.
+        if (num_bytes_sent != (ssize_t)length) {
+            LOG(WARNING) << "Error: sendmsg datagram size=" << length << " sent=" << num_bytes_sent;
             client_->OnSendError(this, ChooseError(errno, Error::Code::kSocketSendFailure));
             return;
         }
-
-        // Validity-check: UDP datagram sendmsg() is all or nothing.
-        CHECK_EQ(static_cast<size_t>(num_bytes_sent), length);
     }
 
     // Sets the DSCP value to use for all messages sent from this socket.
@@ -578,7 +578,6 @@ class AdbUdpSocket : public UdpSocket {
             client_->OnRead(this, ChooseError(errno, Error::Code::kSocketReadFailure));
             return;
         }
-        VLOG(MDNS) << "mDNS received bytes=" << *bytes_available;
 
         UdpPacket packet(*bytes_available);
         packet.set_socket(this);
diff --git a/client/transport_mdns.cpp b/client/transport_mdns.cpp
index d4118e51..81fba1a8 100644
--- a/client/transport_mdns.cpp
+++ b/client/transport_mdns.cpp
@@ -35,6 +35,7 @@
 #include <discovery/common/config.h>
 #include <discovery/common/reporting_client.h>
 #include <discovery/public/dns_sd_service_factory.h>
+#include <discovery/public/dns_sd_service_watcher.h>
 #include <platform/api/network_interface.h>
 #include <platform/api/serial_delete_ptr.h>
 #include <platform/base/error.h>
@@ -46,7 +47,6 @@
 #include "adb_utils.h"
 #include "adb_wifi.h"
 #include "client/mdns_utils.h"
-#include "client/openscreen/mdns_service_watcher.h"
 #include "client/openscreen/platform/task_runner.h"
 #include "fdevent/fdevent.h"
 #include "sysdeps.h"
@@ -55,7 +55,8 @@ namespace {
 
 using namespace mdns;
 using namespace openscreen;
-using ServicesUpdatedState = mdns::ServiceReceiver::ServicesUpdatedState;
+using ServiceWatcher = discovery::DnsSdServiceWatcher<ServiceInfo>;
+using ServicesUpdatedState = ServiceWatcher::ServicesUpdatedState;
 
 struct DiscoveryState;
 DiscoveryState* g_state = nullptr;
@@ -88,7 +89,7 @@ struct DiscoveryState {
     SerialDeletePtr<discovery::DnsSdService> service;
     std::unique_ptr<DiscoveryReportingClient> reporting_client;
     std::unique_ptr<AdbOspTaskRunner> task_runner;
-    std::vector<std::unique_ptr<ServiceReceiver>> receivers;
+    std::vector<std::unique_ptr<ServiceWatcher>> watchers;
     InterfaceInfo interface_info;
 };
 
@@ -179,15 +180,16 @@ void StartDiscovery() {
                 g_state->task_runner.get(), g_state->reporting_client.get(), *g_state->config);
         // Register a receiver for each service type
         for (int i = 0; i < kNumADBDNSServices; ++i) {
-            auto receiver = std::make_unique<ServiceReceiver>(
-                    g_state->service.get(), kADBDNSServices[i], OnServiceReceiverResult);
-            receiver->StartDiscovery();
-            g_state->receivers.push_back(std::move(receiver));
+            auto watcher = std::make_unique<ServiceWatcher>(
+                    g_state->service.get(), kADBDNSServices[i], DnsSdInstanceEndpointToServiceInfo,
+                    OnServiceReceiverResult);
+            watcher->StartDiscovery();
+            g_state->watchers.push_back(std::move(watcher));
 
             if (g_state->reporting_client->GotFatalError()) {
-                for (auto& r : g_state->receivers) {
-                    if (r->is_running()) {
-                        r->StopDiscovery();
+                for (auto& w : g_state->watchers) {
+                    if (w->is_running()) {
+                        w->StopDiscovery();
                     }
                 }
                 g_using_bonjour = true;
@@ -202,7 +204,7 @@ void StartDiscovery() {
     });
 }
 
-void ForEachService(const std::unique_ptr<ServiceReceiver>& receiver,
+void ForEachService(const std::unique_ptr<ServiceWatcher>& receiver,
                     std::string_view wanted_instance_name, adb_secure_foreach_service_callback cb) {
     if (!receiver->is_running()) {
         return;
@@ -212,8 +214,7 @@ void ForEachService(const std::unique_ptr<ServiceReceiver>& receiver,
         if (wanted_instance_name.empty() || s.get().instance_name == wanted_instance_name) {
             std::stringstream ss;
             ss << s.get().v4_address;
-            cb(s.get().instance_name.c_str(), s.get().service_name.c_str(), ss.str().c_str(),
-               s.get().port);
+            cb(s.get());
         }
     }
 }
@@ -263,16 +264,16 @@ bool adb_secure_connect_by_service_name(const std::string& instance_name) {
         return g_adb_mdnsresponder_funcs.adb_secure_connect_by_service_name(instance_name);
     }
 
-    if (!g_state || g_state->receivers.empty()) {
+    if (!g_state || g_state->watchers.empty()) {
         VLOG(MDNS) << "Mdns not enabled";
         return false;
     }
 
     std::optional<MdnsInfo> info;
-    auto cb = [&](const std::string& instance_name, const std::string& service_name,
-                  const std::string& ip_addr,
-                  uint16_t port) { info.emplace(instance_name, service_name, ip_addr, port); };
-    ForEachService(g_state->receivers[kADBSecureConnectServiceRefIndex], instance_name, cb);
+    auto cb = [&](const mdns::ServiceInfo& si) {
+        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
+    };
+    ForEachService(g_state->watchers[kADBSecureConnectServiceRefIndex], instance_name, cb);
     if (info.has_value()) {
         return ConnectAdbSecureDevice(*info);
     }
@@ -296,18 +297,18 @@ std::string mdns_list_discovered_services() {
         return g_adb_mdnsresponder_funcs.mdns_list_discovered_services();
     }
 
-    if (!g_state || g_state->receivers.empty()) {
+    if (!g_state || g_state->watchers.empty()) {
         return "";
     }
 
     std::string result;
-    auto cb = [&](const std::string& instance_name, const std::string& service_name,
-                  const std::string& ip_addr, uint16_t port) {
-        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", instance_name.data(),
-                                              service_name.data(), ip_addr.data(), port);
+    auto cb = [&](const mdns::ServiceInfo& si) {
+        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", si.instance_name.data(),
+                                              si.service_name.data(), si.v4_address_string().data(),
+                                              si.port);
     };
 
-    for (const auto& receiver : g_state->receivers) {
+    for (const auto& receiver : g_state->watchers) {
         ForEachService(receiver, "", cb);
     }
     return result;
@@ -320,7 +321,7 @@ std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
         return g_adb_mdnsresponder_funcs.mdns_get_connect_service_info(name);
     }
 
-    if (!g_state || g_state->receivers.empty()) {
+    if (!g_state || g_state->watchers.empty()) {
         return std::nullopt;
     }
 
@@ -331,9 +332,9 @@ std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
     }
 
     std::optional<MdnsInfo> info;
-    auto cb = [&](const std::string& instance_name, const std::string& service_name,
-                  const std::string& ip_addr,
-                  uint16_t port) { info.emplace(instance_name, service_name, ip_addr, port); };
+    auto cb = [&](const ServiceInfo& si) {
+        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
+    };
 
     std::string reg_type;
     // Service name was provided.
@@ -347,7 +348,7 @@ std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
         switch (*index) {
             case kADBTransportServiceRefIndex:
             case kADBSecureConnectServiceRefIndex:
-                ForEachService(g_state->receivers[*index], mdns_instance->instance_name, cb);
+                ForEachService(g_state->watchers[*index], mdns_instance->instance_name, cb);
                 break;
             default:
                 D("Not a connectable service name [%s]", reg_type.data());
@@ -358,9 +359,9 @@ std::optional<MdnsInfo> mdns_get_connect_service_info(const std::string& name) {
 
     // No mdns service name provided. Just search for the instance name in all adb connect services.
     // Prefer the secured connect service over the other.
-    ForEachService(g_state->receivers[kADBSecureConnectServiceRefIndex], name, cb);
+    ForEachService(g_state->watchers[kADBSecureConnectServiceRefIndex], name, cb);
     if (!info.has_value()) {
-        ForEachService(g_state->receivers[kADBTransportServiceRefIndex], name, cb);
+        ForEachService(g_state->watchers[kADBTransportServiceRefIndex], name, cb);
     }
 
     return info;
@@ -373,7 +374,7 @@ std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name) {
         return g_adb_mdnsresponder_funcs.mdns_get_pairing_service_info(name);
     }
 
-    if (!g_state || g_state->receivers.empty()) {
+    if (!g_state || g_state->watchers.empty()) {
         return std::nullopt;
     }
 
@@ -384,9 +385,9 @@ std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name) {
     }
 
     std::optional<MdnsInfo> info;
-    auto cb = [&](const std::string& instance_name, const std::string& service_name,
-                  const std::string& ip_addr,
-                  uint16_t port) { info.emplace(instance_name, service_name, ip_addr, port); };
+    auto cb = [&](const ServiceInfo& si) {
+        info.emplace(si.instance_name, si.service_name, si.v4_address_string(), si.port);
+    };
 
     std::string reg_type;
     // Verify it's a pairing service if user explicitly inputs it.
@@ -407,7 +408,7 @@ std::optional<MdnsInfo> mdns_get_pairing_service_info(const std::string& name) {
         return info;
     }
 
-    ForEachService(g_state->receivers[kADBSecurePairingServiceRefIndex], name, cb);
+    ForEachService(g_state->watchers[kADBSecurePairingServiceRefIndex], name, cb);
 
     return info;
 }
diff --git a/client/usb.h b/client/usb.h
index b12e7c6b..5c8a4b7c 100644
--- a/client/usb.h
+++ b/client/usb.h
@@ -39,10 +39,6 @@ bool is_adb_interface(int usb_class, int usb_subclass, int usb_protocol);
 
 bool is_libusb_enabled();
 
-namespace libusb {
-void usb_init();
-}
-
 struct UsbConnection : public BlockingConnection {
     explicit UsbConnection(usb_handle* handle) : handle_(handle) {}
     ~UsbConnection();
diff --git a/client/usb_libusb.cpp b/client/usb_libusb.cpp
index 8ada3303..085276eb 100644
--- a/client/usb_libusb.cpp
+++ b/client/usb_libusb.cpp
@@ -14,1074 +14,238 @@
  * limitations under the License.
  */
 
-#include "sysdeps.h"
+#include "usb_libusb.h"
 
-#include "client/usb.h"
+#include "android-base/logging.h"
 
-#include <stdint.h>
-#include <stdlib.h>
-
-#if defined(__linux__)
-#include <sys/inotify.h>
-#include <unistd.h>
-#endif
-
-#include <atomic>
-#include <chrono>
-#include <condition_variable>
-#include <memory>
-#include <mutex>
-#include <string>
-#include <thread>
-#include <unordered_map>
-#include <vector>
-
-#include <libusb/libusb.h>
-
-#include <android-base/file.h>
-#include <android-base/logging.h>
-#include <android-base/stringprintf.h>
-#include <android-base/strings.h>
-#include <android-base/thread_annotations.h>
-
-#include "adb.h"
-#include "adb_utils.h"
-#include "fdevent/fdevent.h"
-#include "transfer_id.h"
-#include "transport.h"
+#include "adb_trace.h"
+#include "client/detach.h"
+#include "client/usb_libusb_inhouse_hotplug.h"
+#include "usb.h"
 
 using namespace std::chrono_literals;
 
 using android::base::ScopedLockAssertion;
-using android::base::StringPrintf;
-
-#define LOG_ERR(out, fmt, ...)                                               \
-    do {                                                                     \
-        std::string __err = android::base::StringPrintf(fmt, ##__VA_ARGS__); \
-        LOG(ERROR) << __err;                                                 \
-        *out = std::move(__err);                                             \
-    } while (0)
-
-// RAII wrappers for libusb.
-struct ConfigDescriptorDeleter {
-    void operator()(libusb_config_descriptor* desc) { libusb_free_config_descriptor(desc); }
-};
-
-using unique_config_descriptor = std::unique_ptr<libusb_config_descriptor, ConfigDescriptorDeleter>;
-
-struct DeviceDeleter {
-    void operator()(libusb_device* d) { libusb_unref_device(d); }
-};
 
-using unique_device = std::unique_ptr<libusb_device, DeviceDeleter>;
-
-struct DeviceHandleDeleter {
-    void operator()(libusb_device_handle* h) { libusb_close(h); }
-};
-
-using unique_device_handle = std::unique_ptr<libusb_device_handle, DeviceHandleDeleter>;
-
-static void process_device(libusb_device* device_raw);
-
-static std::string get_device_address(libusb_device* device) {
-    uint8_t ports[7];
-    int port_count = libusb_get_port_numbers(device, ports, 7);
-    if (port_count < 0) return "";
-
-    std::string address = StringPrintf("%d-%d", libusb_get_bus_number(device), ports[0]);
-    for (int port = 1; port < port_count; ++port) {
-        address += StringPrintf(".%d", ports[port]);
-    }
-
-    return address;
-}
+LibUsbConnection::LibUsbConnection(std::unique_ptr<LibUsbDevice> device)
+    : device_(std::move(device)) {}
 
-#if defined(__linux__)
-static std::string get_device_serial_path(libusb_device* device) {
-    std::string address = get_device_address(device);
-    std::string path = StringPrintf("/sys/bus/usb/devices/%s/serial", address.c_str());
-    return path;
+void LibUsbConnection::Init() {
+    detached_ = attached_devices.ShouldStartDetached(const_cast<LibUsbConnection&>(*this));
+    VLOG(USB) << "Device " << device_->GetSerial() << " created detached=" << detached_;
 }
-#endif
 
-static bool endpoint_is_output(uint8_t endpoint) {
-    return (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT;
+LibUsbConnection::~LibUsbConnection() {
+    VLOG(USB) << "LibUsbConnection(" << Serial() << "): destructing";
+    Stop();
 }
 
-static bool should_perform_zero_transfer(size_t write_length, uint16_t zero_mask) {
-    return write_length != 0 && zero_mask != 0 && (write_length & zero_mask) == 0;
+void LibUsbConnection::OnError(const std::string& reason) {
+    std::call_once(this->error_flag_, [this, reason]() {
+        // When a Windows machine goes to sleep it powers off all its USB host controllers to save
+        // energy. When the machine awakens, it powers them up which causes all the endpoints
+        // to be closed (which generates a read/write failure leading to us Close()ing the device).
+        // The USB device also briefly goes away and comes back with the exact same properties
+        // (including address). This makes in-house hotplug miss device reconnection upon wakeup. To
+        // solve that we remove ourselves from the set of known devices.
+        libusb_inhouse_hotplug::report_error(*this);
+
+        transport_->HandleError(reason);
+    });
 }
 
-struct LibusbConnection : public Connection {
-    struct ReadBlock {
-        LibusbConnection* self = nullptr;
-        libusb_transfer* transfer = nullptr;
-        Block block;
-        bool active = false;
-    };
-
-    struct WriteBlock {
-        LibusbConnection* self;
-        libusb_transfer* transfer;
-        Block block;
-        TransferId id;
-    };
-
-    explicit LibusbConnection(unique_device device)
-        : device_(std::move(device)), device_address_(get_device_address(device_.get())) {}
-
-    ~LibusbConnection() { Stop(); }
-
-    void HandlePacket(amessage& msg, std::optional<Block> payload) {
-        auto packet = std::make_unique<apacket>();
-        packet->msg = msg;
-        if (payload) {
-            packet->payload = std::move(*payload);
-        }
-        transport_->HandleRead(std::move(packet));
+void LibUsbConnection::HandleStop(const std::string& reason) {
+    // If we are detached, we should not report an error condition to the transport
+    // layer. If a connection is detached it has merely been requested to stop transmitting and
+    // release its resources.
+    if (detached_) {
+        VLOG(USB) << "Not reporting error '" << reason << "' because device " << transport_->serial
+                  << " is detached";
+    } else {
+        OnError(reason);
     }
+}
 
-    void Cleanup(ReadBlock* read_block) REQUIRES(read_mutex_) {
-        libusb_free_transfer(read_block->transfer);
-        read_block->active = false;
-        read_block->transfer = nullptr;
-        if (terminated_) {
-            destruction_cv_.notify_one();
-        }
+bool LibUsbConnection::Start() {
+    VLOG(USB) << "LibUsbConnection::Start()";
+    std::lock_guard<std::mutex> lock(mutex_);
+    if (running_) {
+        VLOG(USB) << "LibUsbConnection(" << Serial() << "): already started";
     }
 
-    bool MaybeCleanup(ReadBlock* read_block) REQUIRES(read_mutex_) {
-        CHECK(read_block);
-        CHECK(read_block->transfer);
-
-        if (terminated_) {
-            Cleanup(read_block);
-            return true;
-        }
-
+    if (!device_->Open()) {
+        VLOG(USB) << "Unable to start " << Serial() << ": Failed to open device";
         return false;
     }
 
-    static void LIBUSB_CALL header_read_cb(libusb_transfer* transfer) {
-        auto read_block = static_cast<ReadBlock*>(transfer->user_data);
-        auto self = read_block->self;
-
-        std::lock_guard<std::mutex> lock(self->read_mutex_);
-        CHECK_EQ(read_block, &self->header_read_);
-        if (self->MaybeCleanup(read_block)) {
-            return;
-        }
+    StartReadThread();
+    StartWriteThread();
 
-        if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
-            std::string msg =
-                    StringPrintf("usb read failed: '%s'", libusb_error_name(transfer->status));
-            LOG(ERROR) << msg;
-            if (!self->detached_) {
-                self->OnError(msg);
-            }
-            self->Cleanup(read_block);
-            return;
-        }
-
-        if (transfer->actual_length != sizeof(amessage)) {
-            std::string msg = StringPrintf("usb read: invalid length for header: %d",
-                                           transfer->actual_length);
-            LOG(ERROR) << msg;
-            self->OnError(msg);
-            self->Cleanup(read_block);
-            return;
-        }
-
-        CHECK(!self->incoming_header_);
-        amessage& amsg = self->incoming_header_.emplace();
-        memcpy(&amsg, transfer->buffer, sizeof(amsg));
-
-        if (amsg.data_length > MAX_PAYLOAD) {
-            std::string msg =
-                    StringPrintf("usb read: payload length too long: %d", amsg.data_length);
-            LOG(ERROR) << msg;
-            self->OnError(msg);
-            self->Cleanup(&self->header_read_);
-            return;
-        } else if (amsg.data_length == 0) {
-            self->HandlePacket(amsg, std::nullopt);
-            self->incoming_header_.reset();
-            self->SubmitRead(read_block, sizeof(amessage));
-        } else {
-            read_block->active = false;
-            self->SubmitRead(&self->payload_read_, amsg.data_length);
-        }
-    }
-
-    static void LIBUSB_CALL payload_read_cb(libusb_transfer* transfer) {
-        auto read_block = static_cast<ReadBlock*>(transfer->user_data);
-        auto self = read_block->self;
-        std::lock_guard<std::mutex> lock(self->read_mutex_);
-
-        if (self->MaybeCleanup(&self->payload_read_)) {
-            return;
-        }
+    running_ = true;
+    return true;
+}
 
-        if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
-            std::string msg =
-                    StringPrintf("usb read failed: '%s'", libusb_error_name(transfer->status));
-            LOG(ERROR) << msg;
-            if (!self->detached_) {
-                self->OnError(msg);
+void LibUsbConnection::StartReadThread() {
+    read_thread_ = std::thread([this]() {
+        LOG(INFO) << Serial() << ": read thread spawning";
+        while (true) {
+            auto packet = std::make_unique<apacket>();
+            if (!device_->Read(packet.get())) {
+                PLOG(INFO) << Serial() << ": read failed";
+                break;
             }
-            self->Cleanup(&self->payload_read_);
-            return;
-        }
 
-        if (transfer->actual_length != transfer->length) {
-            std::string msg =
-                    StringPrintf("usb read: unexpected length for payload: wanted %d, got %d",
-                                 transfer->length, transfer->actual_length);
-            LOG(ERROR) << msg;
-            self->OnError(msg);
-            self->Cleanup(&self->payload_read_);
-            return;
-        }
-
-        CHECK(self->incoming_header_.has_value());
-        self->HandlePacket(*self->incoming_header_, std::move(read_block->block));
-        self->incoming_header_.reset();
-
-        read_block->active = false;
-        self->SubmitRead(&self->header_read_, sizeof(amessage));
-    }
-
-    static void LIBUSB_CALL write_cb(libusb_transfer* transfer) {
-        auto write_block = static_cast<WriteBlock*>(transfer->user_data);
-        auto self = write_block->self;
-
-        bool succeeded = transfer->status == LIBUSB_TRANSFER_COMPLETED;
-
-        {
-            std::lock_guard<std::mutex> lock(self->write_mutex_);
-            libusb_free_transfer(transfer);
-            self->writes_.erase(write_block->id);
-
-            if (self->terminated_ && self->writes_.empty()) {
-                self->destruction_cv_.notify_one();
+            bool got_stls_cmd = false;
+            if (packet->msg.command == A_STLS) {
+                got_stls_cmd = true;
             }
-        }
-
-        if (!succeeded && !self->detached_) {
-            self->OnError("libusb write failed");
-        }
-    }
-
-    bool DoTlsHandshake(RSA*, std::string*) final {
-        LOG(FATAL) << "tls not supported";
-        return false;
-    }
 
-    void CreateRead(ReadBlock* read, bool header) {
-        read->self = this;
-        read->transfer = libusb_alloc_transfer(0);
-        if (!read->transfer) {
-            LOG(FATAL) << "failed to allocate libusb_transfer for read";
-        }
-        libusb_fill_bulk_transfer(read->transfer, device_handle_.get(), read_endpoint_, nullptr, 0,
-                                  header ? header_read_cb : payload_read_cb, read, 0);
-    }
-
-    void SubmitRead(ReadBlock* read, size_t length) {
-        read->block.resize(length);
-        read->transfer->buffer = reinterpret_cast<unsigned char*>(read->block.data());
-        read->transfer->length = length;
-        read->active = true;
-        int rc = libusb_submit_transfer(read->transfer);
-        if (rc != 0) {
-            LOG(ERROR) << "libusb_submit_transfer failed: " << libusb_strerror(rc);
-        }
-    }
-
-    void SubmitWrite(Block&& block) REQUIRES(write_mutex_) {
-        // TODO: Reuse write blocks.
-        auto write = std::make_unique<WriteBlock>();
-
-        write->self = this;
-        write->id = TransferId::write(next_write_id_++);
-        write->block = std::move(block);
-        write->transfer = libusb_alloc_transfer(0);
-        if (!write->transfer) {
-            LOG(FATAL) << "failed to allocate libusb_transfer for write";
-        }
-
-        libusb_fill_bulk_transfer(write->transfer, device_handle_.get(), write_endpoint_,
-                                  reinterpret_cast<unsigned char*>(write->block.data()),
-                                  write->block.size(), &write_cb, write.get(), 0);
-        int rc = libusb_submit_transfer(write->transfer);
-        if (rc == 0) {
-            writes_[write->id] = std::move(write);
-        } else {
-            LOG(ERROR) << "libusb_submit_transfer failed: " << libusb_strerror(rc);
-            libusb_free_transfer(write->transfer);
-        }
-    }
-
-    bool Write(std::unique_ptr<apacket> packet) final {
-        VLOG(USB) << "USB write: " << dump_header(&packet->msg);
-        Block header;
-        header.resize(sizeof(packet->msg));
-        memcpy(header.data(), &packet->msg, sizeof(packet->msg));
-
-        std::lock_guard<std::mutex> lock(write_mutex_);
-        if (terminated_) {
-            return false;
-        }
-
-        if (detached_) {
-            return true;
-        }
-
-        SubmitWrite(std::move(header));
-        if (!packet->payload.empty()) {
-            size_t payload_length = packet->payload.size();
-            SubmitWrite(std::move(packet->payload));
+            transport_->HandleRead(std::move(packet));
 
-            // If the payload is a multiple of the endpoint packet size, we
-            // need an explicit zero-sized transfer.
-            if (should_perform_zero_transfer(payload_length, zero_mask_)) {
-                VLOG(USB) << "submitting zero transfer for payload length " << payload_length;
-                Block empty;
-                SubmitWrite(std::move(empty));
+            // If we received the STLS packet, we are about to perform the TLS
+            // handshake. So this read thread must stop and resume after the
+            // handshake completes otherwise this will interfere in the process.
+            if (got_stls_cmd) {
+                LOG(INFO) << Serial() << ": Received STLS packet. Stopping read thread.";
+                break;
             }
         }
+        HandleStop("read thread stopped");
+    });
+}
 
-        return true;
-    }
-
-    std::optional<libusb_device_descriptor> GetDeviceDescriptor() {
-        libusb_device_descriptor device_desc;
-        int rc = libusb_get_device_descriptor(device_.get(), &device_desc);
-        if (rc != 0) {
-            LOG(WARNING) << "failed to get device descriptor for device at " << device_address_
-                         << ": " << libusb_error_name(rc);
-            return {};
-        }
-        return device_desc;
-    }
-
-    bool FindInterface(libusb_device_descriptor* device_desc) {
-        if (device_desc->bDeviceClass != LIBUSB_CLASS_PER_INTERFACE) {
-            // Assume that all Android devices have the device class set to per interface.
-            // TODO: Is this assumption valid?
-            VLOG(USB) << "skipping device with incorrect class at " << device_address_;
-            return false;
-        }
-
-        libusb_config_descriptor* config_raw;
-        int rc = libusb_get_active_config_descriptor(device_.get(), &config_raw);
-        if (rc != 0) {
-            LOG(WARNING) << "failed to get active config descriptor for device at "
-                         << device_address_ << ": " << libusb_error_name(rc);
-            return false;
-        }
-        const unique_config_descriptor config(config_raw);
-
-        // Use size_t for interface_num so <iostream>s don't mangle it.
-        size_t interface_num;
-        uint16_t zero_mask = 0;
-        uint8_t bulk_in = 0, bulk_out = 0;
-        size_t packet_size = 0;
-        bool found_adb = false;
-
-        for (interface_num = 0; interface_num < config->bNumInterfaces; ++interface_num) {
-            const libusb_interface& interface = config->interface[interface_num];
-
-            if (interface.num_altsetting == 0) {
-                continue;
-            }
-
-            const libusb_interface_descriptor& interface_desc = interface.altsetting[0];
-            if (!is_adb_interface(interface_desc.bInterfaceClass, interface_desc.bInterfaceSubClass,
-                                  interface_desc.bInterfaceProtocol)) {
-                VLOG(USB) << "skipping non-adb interface at " << device_address_ << " (interface "
-                          << interface_num << ")";
-                continue;
-            }
+void LibUsbConnection::StartWriteThread() {
+    write_thread_ = std::thread([this]() {
+        LOG(INFO) << Serial() << ": write thread spawning";
+        while (true) {
+            std::unique_lock<std::mutex> lock(mutex_);
+            ScopedLockAssertion assume_locked(mutex_);
+            cv_write_.wait(lock, [this]() REQUIRES(mutex_) {
+                return !this->running_ || !this->write_queue_.empty();
+            });
 
-            if (interface.num_altsetting != 1) {
-                // Assume that interfaces with alternate settings aren't adb interfaces.
-                // TODO: Is this assumption valid?
-                LOG(WARNING) << "skipping interface with unexpected num_altsetting at "
-                             << device_address_ << " (interface " << interface_num << ")";
-                continue;
+            if (!this->running_) {
+                break;
             }
 
-            VLOG(USB) << "found potential adb interface at " << device_address_ << " (interface "
-                      << interface_num << ")";
-
-            bool found_in = false;
-            bool found_out = false;
-            for (size_t endpoint_num = 0; endpoint_num < interface_desc.bNumEndpoints;
-                 ++endpoint_num) {
-                const auto& endpoint_desc = interface_desc.endpoint[endpoint_num];
-                const uint8_t endpoint_addr = endpoint_desc.bEndpointAddress;
-                const uint8_t endpoint_attr = endpoint_desc.bmAttributes;
+            std::unique_ptr<apacket> packet = std::move(this->write_queue_.front());
+            this->write_queue_.pop_front();
+            lock.unlock();
 
-                const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;
-
-                if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
-                    continue;
-                }
-
-                if (endpoint_is_output(endpoint_addr) && !found_out) {
-                    found_out = true;
-                    bulk_out = endpoint_addr;
-                    zero_mask = endpoint_desc.wMaxPacketSize - 1;
-                } else if (!endpoint_is_output(endpoint_addr) && !found_in) {
-                    found_in = true;
-                    bulk_in = endpoint_addr;
-                }
-
-                size_t endpoint_packet_size = endpoint_desc.wMaxPacketSize;
-                CHECK(endpoint_packet_size != 0);
-                if (packet_size == 0) {
-                    packet_size = endpoint_packet_size;
-                } else {
-                    CHECK(packet_size == endpoint_packet_size);
-                }
-            }
-
-            if (found_in && found_out) {
-                found_adb = true;
+            if (!this->device_->Write(packet.get())) {
                 break;
-            } else {
-                VLOG(USB) << "rejecting potential adb interface at " << device_address_
-                          << "(interface " << interface_num << "): missing bulk endpoints "
-                          << "(found_in = " << found_in << ", found_out = " << found_out << ")";
             }
         }
+        HandleStop("write thread stopped");
+    });
+}
 
-        if (!found_adb) {
-            return false;
-        }
-
-        interface_num_ = interface_num;
-        write_endpoint_ = bulk_out;
-        read_endpoint_ = bulk_in;
-        zero_mask_ = zero_mask;
-        return true;
-    }
-
-    std::string GetUsbDeviceAddress() const { return std::string("usb:") + device_address_; }
-
-    std::string GetSerial() {
-        std::string serial;
-
-        auto device_desc = GetDeviceDescriptor();
-
-        serial.resize(255);
-        int rc = libusb_get_string_descriptor_ascii(
-                device_handle_.get(), device_desc->iSerialNumber,
-                reinterpret_cast<unsigned char*>(&serial[0]), serial.length());
-        if (rc == 0) {
-            LOG(WARNING) << "received empty serial from device at " << device_address_;
-            return {};
-        } else if (rc < 0) {
-            LOG(WARNING) << "failed to get serial from device at " << device_address_
-                         << libusb_error_name(rc);
-            return {};
-        }
-        serial.resize(rc);
-
-        return serial;
-    }
-
-    // libusb gives us an int which is a value from 'enum libusb_speed'
-    static uint64_t ToConnectionSpeed(int speed) {
-        switch (speed) {
-            case LIBUSB_SPEED_LOW:
-                return 1;
-            case LIBUSB_SPEED_FULL:
-                return 12;
-            case LIBUSB_SPEED_HIGH:
-                return 480;
-            case LIBUSB_SPEED_SUPER:
-                return 5000;
-            case LIBUSB_SPEED_SUPER_PLUS:
-                return 10000;
-            case LIBUSB_SPEED_SUPER_PLUS_X2:
-                return 20000;
-            case LIBUSB_SPEED_UNKNOWN:
-            default:
-                return 0;
-        }
-    }
-
-    // libusb gives us a bitfield made of 'enum libusb_supported_speed' values
-    static uint64_t ExtractMaxSuperSpeed(uint16_t wSpeedSupported) {
-        if (wSpeedSupported == 0) {
-            return 0;
-        }
-
-        int msb = 0;
-        while (wSpeedSupported >>= 1) {
-            msb++;
-        }
-
-        switch (1 << msb) {
-            case LIBUSB_LOW_SPEED_OPERATION:
-                return 1;
-            case LIBUSB_FULL_SPEED_OPERATION:
-                return 12;
-            case LIBUSB_HIGH_SPEED_OPERATION:
-                return 480;
-            case LIBUSB_SUPER_SPEED_OPERATION:
-                return 5000;
-            default:
-                return 0;
-        }
-    }
-
-    static uint64_t ExtractMaxSuperSpeedPlus(libusb_ssplus_usb_device_capability_descriptor* cap) {
-        // The exponents is one of {bytes, kB, MB, or GB}. We express speed in MB so we use a 0
-        // multiplier for value which would result in 0MB anyway.
-        static uint64_t exponent[] = {0, 0, 1, 1000};
-        uint64_t max_speed = 0;
-        for (uint8_t i = 0; i < cap->numSublinkSpeedAttributes; i++) {
-            libusb_ssplus_sublink_attribute* attr = &cap->sublinkSpeedAttributes[i];
-            uint64_t speed = attr->mantissa * exponent[attr->exponent];
-            max_speed = std::max(max_speed, speed);
-        }
-        return max_speed;
-    }
-
-    void RetrieveSpeeds() {
-        negotiated_speed_ = ToConnectionSpeed(libusb_get_device_speed(device_.get()));
+bool LibUsbConnection::DoTlsHandshake(RSA* key, std::string* auth_key) {
+    LOG(WARNING) << "TlsHandshake is not supported by libusb backen";
+    return false;
+}
 
-        // To discover the maximum speed supported by an USB device, we walk its capability
-        // descriptors.
-        struct libusb_bos_descriptor* bos = nullptr;
-        if (libusb_get_bos_descriptor(device_handle_.get(), &bos)) {
+void LibUsbConnection::Reset() {
+    {
+        std::lock_guard<std::mutex> lock(mutex_);
+        if (!running_) {
+            LOG(INFO) << "LibUsbConnection(" << Serial() << "): not running";
             return;
         }
-
-        for (int i = 0; i < bos->bNumDeviceCaps; i++) {
-            switch (bos->dev_capability[i]->bDevCapabilityType) {
-                case LIBUSB_BT_SS_USB_DEVICE_CAPABILITY: {
-                    libusb_ss_usb_device_capability_descriptor* cap = nullptr;
-                    if (!libusb_get_ss_usb_device_capability_descriptor(
-                                nullptr, bos->dev_capability[i], &cap)) {
-                        max_speed_ =
-                                std::max(max_speed_, ExtractMaxSuperSpeed(cap->wSpeedSupported));
-                        libusb_free_ss_usb_device_capability_descriptor(cap);
-                    }
-                } break;
-                case LIBUSB_BT_SUPERSPEED_PLUS_CAPABILITY: {
-                    libusb_ssplus_usb_device_capability_descriptor* cap = nullptr;
-                    if (!libusb_get_ssplus_usb_device_capability_descriptor(
-                                nullptr, bos->dev_capability[i], &cap)) {
-                        max_speed_ = std::max(max_speed_, ExtractMaxSuperSpeedPlus(cap));
-                        libusb_free_ssplus_usb_device_capability_descriptor(cap);
-                    }
-                } break;
-                default:
-                    break;
-            }
-        }
-        libusb_free_bos_descriptor(bos);
-    }
-
-    bool OpenDevice(std::string* error) {
-        if (device_handle_) {
-            LOG_ERR(error, "device already open");
-            return false;
-        }
-
-        libusb_device_handle* handle_raw;
-        int rc = libusb_open(device_.get(), &handle_raw);
-        if (rc != 0) {
-            // TODO: Handle no permissions.
-            LOG_ERR(error, "failed to open device: %s", libusb_strerror(rc));
-            return false;
-        }
-
-        unique_device_handle handle(handle_raw);
-        device_handle_ = std::move(handle);
-
-        auto device_desc = GetDeviceDescriptor();
-        if (!device_desc) {
-            LOG_ERR(error, "failed to get device descriptor");
-            device_handle_.reset();
-            return false;
-        }
-
-        if (!FindInterface(&device_desc.value())) {
-            LOG_ERR(error, "failed to find adb interface");
-            device_handle_.reset();
-            return false;
-        }
-
-        serial_ = GetSerial();
-
-        VLOG(USB) << "successfully opened adb device at " << device_address_ << ", "
-                  << StringPrintf("bulk_in = %#x, bulk_out = %#x", read_endpoint_, write_endpoint_);
-
-        // WARNING: this isn't released via RAII.
-        rc = libusb_claim_interface(device_handle_.get(), interface_num_);
-        if (rc != 0) {
-            LOG_ERR(error, "failed to claim adb interface for device '%s': %s", serial_.c_str(),
-                    libusb_error_name(rc));
-            device_handle_.reset();
-            return false;
-        }
-
-        for (uint8_t endpoint : {read_endpoint_, write_endpoint_}) {
-            rc = libusb_clear_halt(device_handle_.get(), endpoint);
-            if (rc != 0) {
-                LOG_ERR(error, "failed to clear halt on device '%s' endpoint %#02x: %s",
-                        serial_.c_str(), endpoint, libusb_error_name(rc));
-                libusb_release_interface(device_handle_.get(), interface_num_);
-                device_handle_.reset();
-                return false;
-            }
-        }
-
-        RetrieveSpeeds();
-        return true;
     }
 
-    void CancelReadTransfer(ReadBlock* read_block) REQUIRES(read_mutex_) {
-        if (!read_block->transfer) {
-            return;
-        }
-
-        if (!read_block->active) {
-            // There is no read_cb pending. Clean it up right now.
-            Cleanup(read_block);
-            return;
-        }
-
-        int rc = libusb_cancel_transfer(read_block->transfer);
-        if (rc != 0) {
-            LOG(WARNING) << "libusb_cancel_transfer failed: " << libusb_error_name(rc);
-            // There is no read_cb pending. Clean it up right now.
-            Cleanup(read_block);
-            return;
-        }
-    }
+    LOG(INFO) << "LibUsbConnection(" << Serial() << "): RESET";
+    this->device_->Reset();
+    Stop();
+}
 
-    void CloseDevice() {
-        // This is rather messy, because of the lifecyle of libusb_transfers.
-        //
-        // We can't call libusb_free_transfer for a submitted transfer, we have to cancel it
-        // and free it in the callback. Complicating things more, it's possible for us to be in
-        // the callback for a transfer as the destructor is being called, at which point cancelling
-        // the transfer won't do anything (and it's possible that we'll submit the transfer again
-        // in the callback).
-        //
-        // Resolve this by setting an atomic flag before we lock to cancel transfers, and take the
-        // lock in the callbacks before checking the flag.
+void LibUsbConnection::Stop() {
+    {
+        std::lock_guard<std::mutex> lock(mutex_);
 
-        if (terminated_) {
+        if (!running_) {
+            LOG(INFO) << "LibUsbConnection(" << Serial() << ") Stop: not running";
             return;
         }
 
-        terminated_ = true;
-
-        {
-            std::unique_lock<std::mutex> lock(write_mutex_);
-            ScopedLockAssertion assumed_locked(write_mutex_);
-
-            std::erase_if(writes_, [](const auto& write_item) {
-                auto const& [id, write_block] = write_item;
-                int rc = libusb_cancel_transfer(write_block->transfer);
-                if (rc != 0) {
-                    // libusb_cancel_transfer failed for some reason. We will
-                    // never get a callback for this transfer. So we need to
-                    // remove it from the list or we will hang below.
-                    LOG(INFO) << "libusb_cancel_transfer failed: " << libusb_error_name(rc);
-                    libusb_free_transfer(write_block->transfer);
-                    return true;
-                }
-                // Wait for the write_cb to fire before removing.
-                return false;
-            });
-
-            // Wait here until the write callbacks have all fired and removed
-            // the remaining writes_.
-            destruction_cv_.wait(lock, [this]() {
-                ScopedLockAssertion assumed_locked(write_mutex_);
-                return writes_.empty();
-            });
-        }
-
-        {
-            std::unique_lock<std::mutex> lock(read_mutex_);
-            ScopedLockAssertion assumed_locked(read_mutex_);
-
-            CancelReadTransfer(&header_read_);
-            CancelReadTransfer(&payload_read_);
-
-            destruction_cv_.wait(lock, [this]() {
-                ScopedLockAssertion assumed_locked(read_mutex_);
-                return !header_read_.active && !payload_read_.active;
-            });
-
-            incoming_header_.reset();
-        }
-
-        if (device_handle_) {
-            int rc = libusb_release_interface(device_handle_.get(), interface_num_);
-            if (rc != 0) {
-                LOG(WARNING) << "libusb_release_interface failed: " << libusb_error_name(rc);
-            }
-            device_handle_.reset();
-        }
-    }
-
-    bool StartImpl(std::string* error) {
-        if (!device_handle_) {
-            *error = "device not opened";
-            return false;
-        }
-
-        VLOG(USB) << "registered new usb device '" << serial_ << "'";
-        std::lock_guard lock(read_mutex_);
-        CreateRead(&header_read_, true);
-        CreateRead(&payload_read_, false);
-        SubmitRead(&header_read_, sizeof(amessage));
-
-        return true;
-    }
-
-    void OnError(const std::string& error) {
-        std::call_once(error_flag_, [this, &error]() {
-            if (transport_) {
-                transport_->HandleError(error);
-            }
-        });
-    }
-
-    virtual bool Attach(std::string* error) override final {
-        terminated_ = false;
-        detached_ = false;
-
-        if (!OpenDevice(error)) {
-            return false;
-        }
-
-        if (!StartImpl(error)) {
-            CloseDevice();
-            return false;
-        }
-
-        return true;
-    }
-
-    virtual bool Detach(std::string* error) override final {
-        detached_ = true;
-        CloseDevice();
-        return true;
-    }
-
-    virtual void Reset() override final {
-        VLOG(USB) << "resetting " << transport_->serial_name();
-        int rc = libusb_reset_device(device_handle_.get());
-        if (rc == 0) {
-            libusb_device* device = libusb_ref_device(device_.get());
-
-            Stop();
-
-            fdevent_run_on_looper([device]() {
-                process_device(device);
-                libusb_unref_device(device);
-            });
-        } else {
-            LOG(ERROR) << "libusb_reset_device failed: " << libusb_error_name(rc);
-        }
-    }
-
-    virtual bool Start() override final {
-        std::string error;
-        if (!Attach(&error)) {
-            OnError(error);
-            return false;
-        }
-        return true;
-    }
-
-    virtual void Stop() override final {
-        CloseDevice();
-        OnError("requested stop");
+        running_ = false;
     }
 
-    static std::optional<std::shared_ptr<LibusbConnection>> Create(unique_device device) {
-        auto connection = std::make_unique<LibusbConnection>(std::move(device));
-        if (!connection) {
-            LOG(FATAL) << "failed to construct LibusbConnection";
-        }
+    LOG(INFO) << "LibUsbConnection(" << Serial() << "): stopping";
 
-        auto device_desc = connection->GetDeviceDescriptor();
-        if (!device_desc) {
-            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress()
-                      << ": not an adb interface. (GetDeviceDescriptor)";
-            return {};
-        }
+    this->device_->Close();
+    this->cv_write_.notify_one();
 
-        if (!connection->FindInterface(&device_desc.value())) {
-            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress()
-                      << ": not an adb interface. (FindInterface)";
-            return {};
-        }
-
-#if defined(__linux__)
-        std::string device_serial;
-        if (android::base::ReadFileToString(get_device_serial_path(connection->device_.get()),
-                                            &device_serial)) {
-            connection->serial_ = android::base::Trim(device_serial);
-        } else {
-            // We don't actually want to treat an unknown serial as an error because
-            // devices aren't able to communicate a serial number in early bringup.
-            // http://b/20883914
-            connection->serial_ = "<unknown>";
-        }
-#else
-        // We need to open the device to get its serial on Windows and OS X.
-        std::string error;
-        if (!connection->OpenDevice(&error)) {
-            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress()
-                      << ": not an adb interface. (OpenDevice)";
-            return {};
-        }
-        connection->serial_ = connection->GetSerial();
-        connection->CloseDevice();
-#endif
-        if (!transport_server_owns_device(connection->GetUsbDeviceAddress(), connection->serial_)) {
-            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress() << " serial "
-                      << connection->serial_ << ": this server owns '" << transport_get_one_device()
-                      << "'";
-            return {};
-        }
+    // Move the threads out into locals with the lock taken, and then unlock to let them exit.
+    std::thread read_thread;
+    std::thread write_thread;
 
-        return connection;
+    {
+        std::lock_guard<std::mutex> lock(mutex_);
+        read_thread = std::move(read_thread_);
+        write_thread = std::move(write_thread_);
     }
 
-    virtual uint64_t MaxSpeedMbps() override final { return max_speed_; }
-
-    virtual uint64_t NegotiatedSpeedMbps() override final { return negotiated_speed_; }
-
-    unique_device device_;
-    unique_device_handle device_handle_;
-    std::string device_address_;
-    std::string serial_ = "<unknown>";
-
-    uint32_t interface_num_;
-    uint8_t write_endpoint_;
-    uint8_t read_endpoint_;
-
-    std::mutex read_mutex_;
-    ReadBlock header_read_ GUARDED_BY(read_mutex_);
-    ReadBlock payload_read_ GUARDED_BY(read_mutex_);
-    std::optional<amessage> incoming_header_ GUARDED_BY(read_mutex_);
-
-    std::mutex write_mutex_;
-    std::unordered_map<TransferId, std::unique_ptr<WriteBlock>> writes_ GUARDED_BY(write_mutex_);
-    std::atomic<size_t> next_write_id_ = 0;
-
-    std::once_flag error_flag_;
-    std::atomic<bool> terminated_ = false;
-    std::atomic<bool> detached_ = false;
-    std::condition_variable destruction_cv_;
-
-    size_t zero_mask_ = 0;
+    read_thread.join();
+    write_thread.join();
 
-    uint64_t negotiated_speed_ = 0;
-    uint64_t max_speed_ = 0;
-};
-
-static std::mutex usb_handles_mutex [[clang::no_destroy]];
-static std::unordered_map<libusb_device*, std::weak_ptr<LibusbConnection>> usb_handles
-        [[clang::no_destroy]] GUARDED_BY(usb_handles_mutex);
-static std::atomic<int> connecting_devices(0);
-
-static void process_device(libusb_device* device_raw) {
-    std::string device_address = "usb:" + get_device_address(device_raw);
-    VLOG(USB) << "device connected: " << device_address;
-
-    unique_device device(libusb_ref_device(device_raw));
-    auto connection_opt = LibusbConnection::Create(std::move(device));
-    if (!connection_opt) {
-        return;
+    HandleStop("stop requested");
+    {
+        std::lock_guard<std::mutex> lock(mutex_);
+        write_queue_.clear();
     }
+}
 
-    auto connection = *connection_opt;
-
+bool LibUsbConnection::Write(std::unique_ptr<apacket> packet) {
     {
-        std::lock_guard<std::mutex> lock(usb_handles_mutex);
-        usb_handles.emplace(libusb_ref_device(device_raw), connection);
+        std::lock_guard<std::mutex> lock(this->mutex_);
+        write_queue_.emplace_back(std::move(packet));
     }
 
-    VLOG(USB) << "constructed LibusbConnection for device " << connection->serial_ << " ("
-              << device_address << ")";
-
-    register_libusb_transport(connection, connection->serial_.c_str(), device_address.c_str(),
-                              true);
+    cv_write_.notify_one();
+    return true;
 }
 
-static void device_connected(libusb_device* device) {
-#if defined(__linux__)
-    // Android's host linux libusb uses netlink instead of udev for device hotplug notification,
-    // which means we can get hotplug notifications before udev has updated ownership/perms on the
-    // device. Since we're not going to be able to link against the system's libudev any time soon,
-    // poll for accessibility changes with inotify until a timeout expires.
-    libusb_ref_device(device);
-    auto thread = std::thread([device]() {
-        std::string bus_path = StringPrintf("/dev/bus/usb/%03d/", libusb_get_bus_number(device));
-        std::string device_path =
-                StringPrintf("%s/%03d", bus_path.c_str(), libusb_get_device_address(device));
-        auto deadline = std::chrono::steady_clock::now() + 1s;
-        unique_fd infd(inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
-        if (infd == -1) {
-            PLOG(FATAL) << "failed to create inotify fd";
-        }
-
-        // Register the watch first, and then check for accessibility, to avoid a race.
-        // We can't watch the device file itself, as that requires us to be able to access it.
-        if (inotify_add_watch(infd.get(), bus_path.c_str(), IN_ATTRIB) == -1) {
-            PLOG(ERROR) << "failed to register inotify watch on '" << bus_path
-                        << "', falling back to sleep";
-            std::this_thread::sleep_for(std::chrono::seconds(1));
-        } else {
-            adb_pollfd pfd = {.fd = infd.get(), .events = POLLIN, .revents = 0};
-
-            while (access(device_path.c_str(), R_OK | W_OK) == -1) {
-                auto timeout = deadline - std::chrono::steady_clock::now();
-                if (timeout < 0s) {
-                    break;
-                }
-
-                uint64_t ms = timeout / 1ms;
-                int rc = adb_poll(&pfd, 1, ms);
-                if (rc == -1) {
-                    if (errno == EINTR) {
-                        continue;
-                    } else {
-                        LOG(WARNING) << "timeout expired while waiting for device accessibility";
-                        break;
-                    }
-                }
-
-                union {
-                    struct inotify_event ev;
-                    char bytes[sizeof(struct inotify_event) + NAME_MAX + 1];
-                } buf;
-
-                rc = adb_read(infd.get(), &buf, sizeof(buf));
-                if (rc == -1) {
-                    break;
-                }
-
-                // We don't actually care about the data: we might get spurious events for
-                // other devices on the bus, but we'll double check in the loop condition.
-                continue;
-            }
-        }
-
-        process_device(device);
-        if (--connecting_devices == 0) {
-            adb_notify_device_scan_complete();
-        }
-        libusb_unref_device(device);
-    });
-    thread.detach();
-#else
-    process_device(device);
-#endif
+uint64_t LibUsbConnection::NegotiatedSpeedMbps() {
+    return device_->NegotiatedSpeedMbps();
 }
 
-static void device_disconnected(libusb_device* device) {
-    usb_handles_mutex.lock();
-    auto it = usb_handles.find(device);
-    if (it != usb_handles.end()) {
-        // We need to ensure that we don't destroy the LibusbConnection on this thread,
-        // as we're in a context with internal libusb mutexes held.
-        libusb_device* device = it->first;
-        std::weak_ptr<LibusbConnection> connection_weak = it->second;
-        usb_handles.erase(it);
-        fdevent_run_on_looper([connection_weak]() {
-            auto connection = connection_weak.lock();
-            if (connection) {
-                connection->Stop();
-                VLOG(USB) << "libusb_hotplug: device disconnected: " << connection->serial_;
-            } else {
-                VLOG(USB) << "libusb_hotplug: device disconnected: (destroyed)";
-            }
-        });
-        libusb_unref_device(device);
-    }
-    usb_handles_mutex.unlock();
+uint64_t LibUsbConnection::MaxSpeedMbps() {
+    return device_->MaxSpeedMbps();
 }
 
-static auto& hotplug_queue = *new BlockingQueue<std::pair<libusb_hotplug_event, libusb_device*>>();
-static void hotplug_thread() {
-    VLOG(USB) << "libusb hotplug thread started";
-    adb_thread_setname("libusb hotplug");
-    while (true) {
-        hotplug_queue.PopAll([](std::pair<libusb_hotplug_event, libusb_device*> pair) {
-            libusb_hotplug_event event = pair.first;
-            libusb_device* device = pair.second;
-            if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
-                VLOG(USB) << "libusb hotplug: device arrived";
-                device_connected(device);
-            } else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
-                VLOG(USB) << "libusb hotplug: device left";
-                device_disconnected(device);
-            } else {
-                LOG(WARNING) << "unknown libusb hotplug event: " << event;
-            }
-        });
-    }
+bool LibUsbConnection::SupportsDetach() const {
+    return true;
 }
 
-static LIBUSB_CALL int hotplug_callback(libusb_context*, libusb_device* device,
-                                        libusb_hotplug_event event, void*) {
-    // We're called with the libusb lock taken. Call these on a separate thread outside of this
-    // function so that the usb_handle mutex is always taken before the libusb mutex.
-    static std::once_flag once;
-    std::call_once(once, []() { std::thread(hotplug_thread).detach(); });
+bool LibUsbConnection::Attach(std::string*) {
+    VLOG(USB) << "LibUsbConnection::Attach";
 
-    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
-        ++connecting_devices;
+    if (!detached_) {
+        VLOG(USB) << "Already attached";
+        return true;
     }
-    hotplug_queue.Push({event, device});
-    return 0;
-}
 
-namespace libusb {
+    detached_ = false;
+    return Start();
+}
 
-void usb_init() {
-    VLOG(USB) << "initializing libusb...";
-    int rc = libusb_init(nullptr);
-    if (rc != 0) {
-        LOG(WARNING) << "failed to initialize libusb: " << libusb_error_name(rc);
-        return;
+bool LibUsbConnection::Detach(std::string*) {
+    VLOG(USB) << "LibUsbConnection::Detach";
+    if (detached_) {
+        VLOG(USB) << "Already detached";
+        return true;
     }
 
-    // Register the hotplug callback.
-    rc = libusb_hotplug_register_callback(
-            nullptr,
-            static_cast<libusb_hotplug_event>(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
-                                              LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
-            LIBUSB_HOTPLUG_ENUMERATE, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
-            LIBUSB_CLASS_PER_INTERFACE, hotplug_callback, nullptr, nullptr);
-
-    if (rc != LIBUSB_SUCCESS) {
-        LOG(FATAL) << "failed to register libusb hotplug callback";
-    }
+    detached_ = true;
+    Stop();
+    return true;
+}
 
-    // Spawn a thread for libusb_handle_events.
-    std::thread([]() {
-        adb_thread_setname("libusb");
-        while (true) {
-            libusb_handle_events(nullptr);
-        }
-    }).detach();
+bool LibUsbConnection::IsDetached() {
+    return detached_;
 }
 
-}  // namespace libusb
+uint64_t LibUsbConnection::GetSessionId() const {
+    return device_->GetSessionId().id;
+}
diff --git a/client/usb_libusb.h b/client/usb_libusb.h
new file mode 100644
index 00000000..938ef799
--- /dev/null
+++ b/client/usb_libusb.h
@@ -0,0 +1,92 @@
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
+#include "sysdeps.h"
+#include "types.h"
+
+#include "usb_libusb_device.h"
+
+struct LibUsbConnection : Connection {
+    explicit LibUsbConnection(std::unique_ptr<LibUsbDevice> device);
+    ~LibUsbConnection() override;
+
+    void Init();
+
+    bool Write(std::unique_ptr<apacket> packet) override;
+
+    // Start transmitting. Start the write thread to consume from the
+    // write queue, Start the read thread to retrieve packets and send
+    // them to the transport layer.
+    bool Start() override;
+
+    // Stop both read and write threads.
+    void Stop() override;
+
+    // Not supported
+    bool DoTlsHandshake(RSA* key, std::string* auth_key) override;
+
+    // Reset the device. This will cause transmission to stop.
+    void Reset() override;
+
+    uint64_t NegotiatedSpeedMbps() override;
+    uint64_t MaxSpeedMbps() override;
+
+    bool SupportsDetach() const override;
+
+    // Stop transmitting and release transmission resources but don't report
+    // an error to the transport layer. Detaching allows another ADB server
+    // running on the same host to take over a device.
+    bool Attach(std::string* error) override;
+
+    // Opposite of Attach, re-acquire transmission resources and start
+    // transmitting.
+    bool Detach(std::string* error) override;
+
+    bool IsDetached();
+
+    // Report an error condition to the upper layer. This will result
+    // in transport calling Stop() and this connection be destroyed
+    // on the fdevent thread.
+    void OnError(const std::string& error);
+
+    uint64_t GetSessionId() const;
+
+  private:
+    std::atomic<bool> detached_ = false;
+
+    void HandleStop(const std::string& reason);
+
+    void StartReadThread() REQUIRES(mutex_);
+    void StartWriteThread() REQUIRES(mutex_);
+    bool running_ GUARDED_BY(mutex_) = false;
+
+    std::unique_ptr<LibUsbDevice> device_;
+    std::thread read_thread_ GUARDED_BY(mutex_);
+    std::thread write_thread_ GUARDED_BY(mutex_);
+
+    // To improve throughput, we store apacket in a queue upon Write. This
+    // queue is consumed by the write thread.
+    std::deque<std::unique_ptr<apacket>> write_queue_ GUARDED_BY(mutex_);
+    std::mutex mutex_;
+
+    // Unlock the Write thread when we need to stop or when there are packets
+    // to Write.
+    std::condition_variable cv_write_;
+
+    std::once_flag error_flag_;
+};
\ No newline at end of file
diff --git a/client/usb_libusb_device.cpp b/client/usb_libusb_device.cpp
new file mode 100644
index 00000000..2bd71ab5
--- /dev/null
+++ b/client/usb_libusb_device.cpp
@@ -0,0 +1,533 @@
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
+#include "usb_libusb_device.h"
+
+#include <stdint.h>
+#include <stdlib.h>
+
+#include <atomic>
+#include <chrono>
+#include <condition_variable>
+#include <format>
+#include <memory>
+#include <mutex>
+#include <thread>
+#include <unordered_map>
+#include <vector>
+
+#include <libusb/libusb.h>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+#include <android-base/thread_annotations.h>
+
+#include "adb.h"
+#include "adb_trace.h"
+#include "adb_utils.h"
+#include "fdevent/fdevent.h"
+#include "transport.h"
+#include "usb.h"
+
+using namespace std::chrono_literals;
+
+using android::base::ScopedLockAssertion;
+using android::base::StringPrintf;
+
+static bool endpoint_is_output(uint8_t endpoint) {
+    return (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT;
+}
+
+LibUsbDevice::LibUsbDevice(libusb_device* device)
+    : device_(device), device_address_(GetDeviceAddress()) {
+    libusb_ref_device(device);
+    Init();
+}
+
+LibUsbDevice::~LibUsbDevice() {
+    ReleaseInterface();
+    CloseDeviceHandle();
+    CloseDevice();
+}
+
+bool LibUsbDevice::IsInitialized() const {
+    return initialized_;
+}
+
+void LibUsbDevice::Init() {
+    initialized_ = OpenDeviceHandle();
+    session_ = GenerateSessionId(device_);
+}
+
+void LibUsbDevice::ReleaseInterface() {
+    if (interface_claimed_) {
+        libusb_release_interface(device_handle_, interface_num_);
+        interface_claimed_ = false;
+    }
+}
+
+void LibUsbDevice::CloseDeviceHandle() {
+    if (device_handle_ != nullptr) {
+        libusb_close(device_handle_);
+        device_handle_ = nullptr;
+    }
+}
+
+void LibUsbDevice::CloseDevice() {
+    if (device_ != nullptr) {
+        libusb_unref_device(device_);
+        device_ = nullptr;
+    }
+}
+
+bool LibUsbDevice::Write(apacket* packet) {
+    VLOG(USB) << "Write " << command_to_string(packet->msg.command)
+              << " payload=" << packet->msg.data_length;
+    int transferred;
+    int data_size = sizeof(packet->msg);
+    auto r = libusb_bulk_transfer(device_handle_, write_endpoint_, (unsigned char*)&packet->msg,
+                                  data_size, &transferred, 0);
+    if ((r != 0) || (transferred != data_size)) {
+        VLOG(USB) << "LibUsbDevice::Write failed at header " << libusb_error_name(r);
+        return false;
+    }
+
+    data_size = packet->payload.size();
+    if (data_size == 0) {
+        return true;
+    }
+    r = libusb_bulk_transfer(device_handle_, write_endpoint_,
+                             (unsigned char*)packet->payload.data(), data_size, &transferred, 0);
+    if ((r != 0) || (transferred != data_size)) {
+        VLOG(USB) << "LibUsbDevice::Write failed at payload " << libusb_error_name(r);
+        return false;
+    }
+
+    if ((data_size & zlp_mask_) == 0) {
+        VLOG(USB) << "Sending zlp (payload_size=" << data_size
+                  << ", endpoint_size=" << out_endpoint_size_
+                  << ", modulo=" << data_size % out_endpoint_size_ << ")";
+        libusb_bulk_transfer(device_handle_, write_endpoint_,
+                             (unsigned char*)packet->payload.data(), 0, &transferred, 0);
+    }
+
+    return true;
+}
+
+bool LibUsbDevice::Read(apacket* packet) {
+    VLOG(USB) << "LibUsbDevice Read()";
+    int transferred;
+    int data_size = sizeof(packet->msg);
+    auto r = libusb_bulk_transfer(device_handle_, read_endpoint_, (unsigned char*)&packet->msg,
+                                  data_size, &transferred, 0);
+    if ((r != 0) || (transferred != data_size)) {
+        VLOG(USB) << "LibUsbDevice::READ failed at header " << libusb_error_name(r);
+        return false;
+    }
+    VLOG(USB) << "Read " << command_to_string(packet->msg.command)
+              << " header, now expecting=" << packet->msg.data_length;
+    if (packet->msg.data_length == 0) {
+        packet->payload.resize(0);
+        return true;
+    }
+
+    packet->payload.resize(packet->msg.data_length);
+    data_size = packet->msg.data_length;
+    r = libusb_bulk_transfer(device_handle_, read_endpoint_, (unsigned char*)packet->payload.data(),
+                             data_size, &transferred, 0);
+    if ((r != 0) || (transferred != data_size)) {
+        VLOG(USB) << "LibUsbDevice::READ failed at payload << " << libusb_error_name(r);
+        return false;
+    }
+    VLOG(USB) << "Read " << command_to_string(packet->msg.command) << " got =" << transferred;
+
+    return true;
+}
+
+void LibUsbDevice::Reset() {
+    if (device_handle_ == nullptr) {
+        return;
+    }
+    int rc = libusb_reset_device(device_handle_);
+    if (rc != 0) {
+        LOG(ERROR) << "libusb_reset_device failed: " << libusb_error_name(rc);
+    }
+}
+
+std::string LibUsbDevice::GetDeviceAddress() {
+    uint8_t ports[7];
+    int port_count = libusb_get_port_numbers(device_, ports, 7);
+    if (port_count < 0) return "";
+
+    std::string address =
+            android::base::StringPrintf("%d-%d", libusb_get_bus_number(device_), ports[0]);
+    for (int port = 1; port < port_count; ++port) {
+        address += android::base::StringPrintf(".%d", ports[port]);
+    }
+
+    return address;
+}
+
+std::optional<libusb_device_descriptor> LibUsbDevice::GetDeviceDescriptor() {
+    libusb_device_descriptor device_desc;
+    int rc = libusb_get_device_descriptor(device_, &device_desc);
+    if (rc != 0) {
+        LOG(WARNING) << "failed to get device descriptor for device :" << libusb_error_name(rc);
+        return {};
+    }
+    return device_desc;
+}
+
+std::string LibUsbDevice::GetSerial() {
+    return serial_;
+}
+
+bool LibUsbDevice::FindAdbInterface() {
+    std::optional<libusb_device_descriptor> device_desc = GetDeviceDescriptor();
+    if (!device_desc.has_value()) {
+        return false;
+    }
+
+    if (device_desc->bDeviceClass != LIBUSB_CLASS_PER_INTERFACE) {
+        // Assume that all Android devices have the device class set to per interface.
+        // TODO: Is this assumption valid?
+        VLOG(USB) << "skipping device with incorrect class at " << device_address_;
+        return false;
+    }
+
+    libusb_config_descriptor* config;
+    int rc = libusb_get_active_config_descriptor(device_, &config);
+    if (rc != 0) {
+        LOG(WARNING) << "failed to get active config descriptor for device at " << device_address_
+                     << ": " << libusb_error_name(rc);
+        return false;
+    }
+
+    // Use size_t for interface_num so <iostream>s don't mangle it.
+    size_t interface_num;
+    uint8_t bulk_in = 0, bulk_out = 0;
+    size_t packet_size = 0;
+    bool found_adb = false;
+
+    for (interface_num = 0; interface_num < config->bNumInterfaces; ++interface_num) {
+        const libusb_interface& interface = config->interface[interface_num];
+
+        if (interface.num_altsetting == 0) {
+            continue;
+        }
+
+        const libusb_interface_descriptor& interface_desc = interface.altsetting[0];
+        if (!is_adb_interface(interface_desc.bInterfaceClass, interface_desc.bInterfaceSubClass,
+                              interface_desc.bInterfaceProtocol)) {
+            VLOG(USB) << "skipping non-adb interface at " << device_address_ << " (interface "
+                      << interface_num << ")";
+            continue;
+        }
+
+        VLOG(USB) << "found potential adb interface at " << device_address_ << " (interface "
+                  << interface_num << ")";
+
+        bool found_in = false;
+        bool found_out = false;
+        for (size_t endpoint_num = 0; endpoint_num < interface_desc.bNumEndpoints; ++endpoint_num) {
+            const auto& endpoint_desc = interface_desc.endpoint[endpoint_num];
+            const uint8_t endpoint_addr = endpoint_desc.bEndpointAddress;
+            const uint8_t endpoint_attr = endpoint_desc.bmAttributes;
+            VLOG(USB) << "Scanning endpoint=" << endpoint_num
+                      << ", addr=" << std::format("{:#02x}", endpoint_addr)
+                      << ", attr=" << std::format("{:#02x}", endpoint_attr);
+
+            const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;
+
+            if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
+                continue;
+            }
+
+            if (endpoint_is_output(endpoint_addr) && !found_out) {
+                found_out = true;
+                out_endpoint_size_ = endpoint_desc.wMaxPacketSize;
+                VLOG(USB) << "Device " << GetSerial()
+                          << " uses wMaxPacketSize=" << out_endpoint_size_;
+                zlp_mask_ = out_endpoint_size_ - 1;
+                bulk_out = endpoint_addr;
+            } else if (!endpoint_is_output(endpoint_addr) && !found_in) {
+                found_in = true;
+                bulk_in = endpoint_addr;
+            }
+
+            size_t endpoint_packet_size = endpoint_desc.wMaxPacketSize;
+            CHECK(endpoint_packet_size != 0);
+            if (packet_size == 0) {
+                packet_size = endpoint_packet_size;
+            } else {
+                CHECK(packet_size == endpoint_packet_size);
+            }
+        }
+
+        if (found_in && found_out) {
+            found_adb = true;
+            break;
+        } else {
+            VLOG(USB) << "rejecting potential adb interface at " << device_address_ << "(interface "
+                      << interface_num << "): missing bulk endpoints "
+                      << "(found_in = " << found_in << ", found_out = " << found_out << ")";
+        }
+    }
+
+    libusb_free_config_descriptor(config);
+
+    if (!found_adb) {
+        VLOG(USB) << "ADB interface missing endpoints: bulk_out=" << bulk_out
+                  << " and bulk_in=" << bulk_in;
+        return false;
+    }
+
+    interface_num_ = interface_num;
+    write_endpoint_ = bulk_out;
+    read_endpoint_ = bulk_in;
+
+    VLOG(USB) << "Found ADB interface=" << interface_num_
+              << " bulk_in=" << std::format("{:#02x}", bulk_in)
+              << " bulk_out=" << std::format("{:#02x}", bulk_out);
+    return true;
+}
+
+std::string LibUsbDevice::GetAddress() const {
+    return std::string("usb:") + device_address_;
+}
+
+bool LibUsbDevice::RetrieveSerial() {
+    auto device_desc = GetDeviceDescriptor();
+
+    serial_.resize(512);
+    int rc = libusb_get_string_descriptor_ascii(device_handle_, device_desc->iSerialNumber,
+                                                reinterpret_cast<unsigned char*>(&serial_[0]),
+                                                serial_.length());
+    if (rc == 0) {
+        LOG(WARNING) << "received empty serial from device at " << device_address_;
+        return false;
+    } else if (rc < 0) {
+        VLOG(USB) << "failed to get serial from device " << device_address_ << " :"
+                  << libusb_error_name(rc);
+        return false;
+    }
+    serial_.resize(rc);
+    return true;
+}
+
+// libusb gives us an int which is a value from 'enum libusb_speed'
+static uint64_t ToConnectionSpeed(int speed) {
+    switch (speed) {
+        case LIBUSB_SPEED_LOW:
+            return 1;
+        case LIBUSB_SPEED_FULL:
+            return 12;
+        case LIBUSB_SPEED_HIGH:
+            return 480;
+        case LIBUSB_SPEED_SUPER:
+            return 5000;
+        case LIBUSB_SPEED_SUPER_PLUS:
+            return 10000;
+        case LIBUSB_SPEED_SUPER_PLUS_X2:
+            return 20000;
+        case LIBUSB_SPEED_UNKNOWN:
+        default:
+            return 0;
+    }
+}
+
+// libusb gives us a bitfield made of 'enum libusb_supported_speed' values
+static uint64_t ExtractMaxSuperSpeed(uint16_t wSpeedSupported) {
+    if (wSpeedSupported == 0) {
+        return 0;
+    }
+
+    int msb = 0;
+    while (wSpeedSupported >>= 1) {
+        msb++;
+    }
+
+    switch (1 << msb) {
+        case LIBUSB_LOW_SPEED_OPERATION:
+            return 1;
+        case LIBUSB_FULL_SPEED_OPERATION:
+            return 12;
+        case LIBUSB_HIGH_SPEED_OPERATION:
+            return 480;
+        case LIBUSB_SUPER_SPEED_OPERATION:
+            return 5000;
+        default:
+            return 0;
+    }
+}
+
+static uint64_t ExtractMaxSuperSpeedPlus(libusb_ssplus_usb_device_capability_descriptor* cap) {
+    // The exponents is one of {bytes, kB, MB, or GB}. We express speed in MB so we use a 0
+    // multiplier for value which would result in 0MB anyway.
+    static uint64_t exponent[] = {0, 0, 1, 1000};
+    uint64_t max_speed = 0;
+    for (uint8_t i = 0; i < cap->numSublinkSpeedAttributes; i++) {
+        libusb_ssplus_sublink_attribute* attr = &cap->sublinkSpeedAttributes[i];
+        uint64_t speed = attr->mantissa * exponent[attr->exponent];
+        max_speed = std::max(max_speed, speed);
+    }
+    return max_speed;
+}
+
+void LibUsbDevice::RetrieveSpeeds() {
+    negotiated_speed_ = ToConnectionSpeed(libusb_get_device_speed(device_));
+
+    // To discover the maximum speed supported by an USB device, we walk its capability
+    // descriptors.
+    struct libusb_bos_descriptor* bos = nullptr;
+    if (libusb_get_bos_descriptor(device_handle_, &bos)) {
+        return;
+    }
+
+    for (int i = 0; i < bos->bNumDeviceCaps; i++) {
+        switch (bos->dev_capability[i]->bDevCapabilityType) {
+            case LIBUSB_BT_SS_USB_DEVICE_CAPABILITY: {
+                libusb_ss_usb_device_capability_descriptor* cap = nullptr;
+                if (!libusb_get_ss_usb_device_capability_descriptor(nullptr, bos->dev_capability[i],
+                                                                    &cap)) {
+                    max_speed_ = std::max(max_speed_, ExtractMaxSuperSpeed(cap->wSpeedSupported));
+                    libusb_free_ss_usb_device_capability_descriptor(cap);
+                }
+            } break;
+            case LIBUSB_BT_SUPERSPEED_PLUS_CAPABILITY: {
+                libusb_ssplus_usb_device_capability_descriptor* cap = nullptr;
+                if (!libusb_get_ssplus_usb_device_capability_descriptor(
+                            nullptr, bos->dev_capability[i], &cap)) {
+                    max_speed_ = std::max(max_speed_, ExtractMaxSuperSpeedPlus(cap));
+                    libusb_free_ssplus_usb_device_capability_descriptor(cap);
+                }
+            } break;
+            default:
+                break;
+        }
+    }
+    libusb_free_bos_descriptor(bos);
+}
+
+bool LibUsbDevice::OpenDeviceHandle() {
+    if (device_handle_) {
+        VLOG(USB) << "device already open";
+        return true;
+    }
+
+    int rc = libusb_open(device_, &device_handle_);
+    if (rc != 0) {
+        VLOG(USB) << "Unable to open device: " << GetSerial() << " :" << libusb_strerror(rc);
+        return false;
+    }
+
+    if (!RetrieveSerial()) {
+        return false;
+    }
+
+    if (!FindAdbInterface()) {
+        return false;
+    }
+
+    RetrieveSpeeds();
+    return true;
+}
+
+bool LibUsbDevice::ClaimInterface() {
+    VLOG(USB) << "ClaimInterface for " << GetSerial();
+    if (interface_claimed_) {
+        VLOG(USB) << "Interface already open";
+        return true;
+    }
+
+    if (!FindAdbInterface()) {
+        VLOG(USB) << "Unable to open interface for " << GetSerial();
+        return false;
+    }
+
+    int rc = libusb_claim_interface(device_handle_, interface_num_);
+    if (rc != 0) {
+        VLOG(USB) << "failed to claim adb interface for device " << serial_.c_str() << ":"
+                  << libusb_error_name(rc);
+        return false;
+    }
+
+    for (uint8_t endpoint : {read_endpoint_, write_endpoint_}) {
+        rc = libusb_clear_halt(device_handle_, endpoint);
+        if (rc != 0) {
+            VLOG(USB) << "failed to clear halt on device " << serial_ << " endpoint" << endpoint
+                      << ": " << libusb_error_name(rc);
+            libusb_release_interface(device_handle_, interface_num_);
+            return false;
+        }
+    }
+
+    VLOG(USB) << "Claimed interface for " << GetSerial() << ", "
+              << StringPrintf("bulk_in = %#x, bulk_out = %#x", read_endpoint_, write_endpoint_);
+    interface_claimed_ = true;
+    return true;
+}
+
+bool LibUsbDevice::Open() {
+    if (!OpenDeviceHandle()) {
+        VLOG(USB) << "Unable to attach, cannot open device";
+        return false;
+    }
+
+    if (!ClaimInterface()) {
+        VLOG(USB) << "failed to claim interface " << GetSerial();
+        return false;
+    }
+
+    VLOG(USB) << "Attached device " << GetSerial();
+    return true;
+}
+
+bool LibUsbDevice::Close() {
+    ReleaseInterface();
+    CloseDeviceHandle();
+    return true;
+}
+
+uint64_t LibUsbDevice::MaxSpeedMbps() {
+    return max_speed_;
+}
+
+uint64_t LibUsbDevice::NegotiatedSpeedMbps() {
+    return negotiated_speed_;
+}
+
+USBSessionID LibUsbDevice::GenerateSessionId(libusb_device* dev) {
+    libusb_device_descriptor desc{};
+    auto result = libusb_get_device_descriptor(dev, &desc);
+    if (result != LIBUSB_SUCCESS) {
+        LOG(WARNING) << "Unable to retrieve device descriptor: " << libusb_error_name(result);
+        return USBSessionID{};
+    }
+
+    USBSessionID session{};
+    session.fields.vendor = desc.idVendor;
+    session.fields.product = desc.idProduct;
+    session.fields.port = libusb_get_port_number(dev);
+    session.fields.address = libusb_get_device_address(dev);
+    return session;
+}
+
+USBSessionID LibUsbDevice::GetSessionId() const {
+    return session_;
+}
diff --git a/client/usb_libusb_device.h b/client/usb_libusb_device.h
new file mode 100644
index 00000000..0cff8c78
--- /dev/null
+++ b/client/usb_libusb_device.h
@@ -0,0 +1,127 @@
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
+#include "sysdeps.h"
+#include "transport.h"
+#include "types.h"
+
+#include <stdint.h>
+#include <optional>
+#include <string>
+
+#include "libusb/libusb.h"
+
+// A session is started when a device is connected to a workstation. It ends upon its
+// disconnection. For in-house hotplug, we generate a unique identifier based on the device
+// invariants vendor, product (adb vs mtp...), the USB port, and the address (the location
+// in the USB chain). On Windows, the address is always incremented, even if the same device
+// is unplugged and plugged immediately.
+union USBSessionID {
+    uint64_t id;
+    struct {
+        uint8_t address;
+        uint8_t port;
+        uint16_t product;
+        uint16_t vendor;
+    } fields;
+};
+
+// Abstraction layer simplifying libusb_device management
+struct LibUsbDevice {
+  public:
+    explicit LibUsbDevice(libusb_device* device);
+    ~LibUsbDevice();
+
+    // Device must have been Opened prior to calling this method.
+    // This method blocks until a packet is available on the USB.
+    // Calling Close will make it return even if not packet was
+    // read.
+    bool Read(apacket* packet);
+
+    // Device must have been Opened prior to calling this method.
+    // This method blocks until the packet has been submitted to
+    // the USB.
+    bool Write(apacket* packet);
+
+    // Reset the device. This will cause the OS to issue a disconnect
+    // and the device will re-connect.
+    void Reset();
+
+    uint64_t NegotiatedSpeedMbps();
+    uint64_t MaxSpeedMbps();
+
+    // Return the Android serial
+    std::string GetSerial();
+
+    // Acquire all resources necessary for USB transfer.
+    bool Open();
+
+    // Release all resources necessary for USB transfer.
+    bool Close();
+
+    // Get the OS address (e.g.: usb:4.0.1)
+    std::string GetAddress() const;
+
+    // Call immediately after creating this object to check that the device can be interacted
+    // with (this also makes sure this is an Android device).
+    bool IsInitialized() const;
+
+    USBSessionID GetSessionId() const;
+
+    static USBSessionID GenerateSessionId(libusb_device* device);
+
+  private:
+    // Make sure device is and Android device, retrieve OS address, retrieve Android serial.
+    void Init();
+
+    std::optional<libusb_device_descriptor> GetDeviceDescriptor();
+
+    bool ClaimInterface();
+    void ReleaseInterface();
+
+    bool OpenDeviceHandle();
+    void CloseDeviceHandle();
+
+    void CloseDevice();
+    std::string GetDeviceAddress();
+    bool RetrieveSerial();
+    void RetrieveSpeeds();
+
+    bool FindAdbInterface();
+
+    libusb_device* device_ = nullptr;
+    libusb_device_handle* device_handle_ = nullptr;
+    std::string device_address_{};
+    std::string serial_{};
+
+    // The mask used to determine if we should send a Zero Length Packet
+    int zlp_mask_{};
+    int out_endpoint_size_{};
+
+    int interface_num_ = 0;
+    unsigned char write_endpoint_{};
+    unsigned char read_endpoint_{};
+    std::atomic<bool> interface_claimed_ = false;
+
+    uint64_t negotiated_speed_{};
+    uint64_t max_speed_{};
+
+    bool initialized_ = false;
+
+    USBSessionID session_;
+};
\ No newline at end of file
diff --git a/client/usb_libusb_hotplug.cpp b/client/usb_libusb_hotplug.cpp
new file mode 100644
index 00000000..9619ea7b
--- /dev/null
+++ b/client/usb_libusb_hotplug.cpp
@@ -0,0 +1,267 @@
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
+#include "usb_libusb_hotplug.h"
+
+#include "adb_trace.h"
+#include "adb_utils.h"
+#include "sysdeps.h"
+#include "usb_libusb.h"
+#include "usb_libusb_inhouse_hotplug.h"
+
+#if defined(__linux__)
+#include <sys/inotify.h>
+#include <unistd.h>
+#endif
+
+#include <chrono>
+#include <mutex>
+#include <optional>
+#include <thread>
+#include <unordered_map>
+
+#include "libusb/libusb.h"
+
+using namespace std::chrono_literals;
+
+// Keep track of connected devices so we can notify the transport system of
+// when we are done scanning USB devices.
+static std::atomic<int> connecting_devices(0);
+
+// We usually detect disconnection when a device Read() operation fails. However, when a device
+// is detached, the Read thread is not running so unplugging does not result in a Read failure.
+// In order to let the transport system know that a detached device is disconnected, we keep track
+// of the connections we created.
+static std::mutex connections_mutex_ [[clang::no_destroy]];
+static std::unordered_map<libusb_device*, std::weak_ptr<LibUsbConnection>> GUARDED_BY(
+        connections_mutex_) connections_ [[clang::no_destroy]];
+
+static void process_device(libusb_device* raw_device) {
+    auto device = std::make_unique<LibUsbDevice>(raw_device);
+    if (!device) {
+        LOG(FATAL) << "Failed to construct LibusbConnection";
+    }
+
+    if (!device->IsInitialized()) {
+        VLOG(USB) << std::format("Can't init address='{}', serial='{}'", device->GetAddress(),
+                                 device->GetSerial());
+        return;
+    }
+
+    if (!transport_server_owns_device(device->GetAddress(), device->GetSerial())) {
+        VLOG(USB) << "ignoring device " << device->GetSerial() << ": this server owns '"
+                  << transport_get_one_device() << "'";
+        return;
+    }
+
+    VLOG(USB) << "constructed LibusbConnection for device " << device->GetSerial();
+
+    auto address = device->GetAddress();
+    auto serial = device->GetSerial();
+    auto connection = std::make_shared<LibUsbConnection>(std::move(device));
+    connection->Init();
+
+    // Keep track of connection so we can call Close on it upon disconnection
+    {
+        std::lock_guard<std::mutex> lock(connections_mutex_);
+        connections_.emplace(libusb_ref_device(raw_device), connection);
+    }
+    register_libusb_transport(connection, serial.c_str(), address.c_str(), true);
+}
+
+static void device_disconnected(libusb_device* dev) {
+    std::lock_guard<std::mutex> lock(connections_mutex_);
+    auto it = connections_.find(dev);
+    if (it != connections_.end()) {
+        // We need to ensure that we don't destroy the LibusbConnection on this thread,
+        // as we're in a context with internal libusb mutexes held.
+        libusb_device* device = it->first;
+        std::weak_ptr<LibUsbConnection> connection_weak = it->second;
+        connections_.erase(it);
+        fdevent_run_on_looper([connection_weak]() {
+            auto connection = connection_weak.lock();
+            if (connection) {
+                connection->Stop();
+                VLOG(USB) << "libusb_hotplug: device disconnected: (Stop requested)";
+                if (connection->IsDetached() && connection->transport_ != nullptr) {
+                    connection->OnError("Detached device has disconnected");
+                }
+            } else {
+                VLOG(USB) << "libusb_hotplug: device disconnected: (Already destroyed)";
+            }
+        });
+        libusb_unref_device(device);
+    }
+}
+
+static void device_connected(libusb_device* device) {
+#if defined(__linux__)
+    // Android's host linux libusb uses netlink instead of udev for device hotplug notification,
+    // which means we can get hotplug notifications before udev has updated ownership/perms on the
+    // device. Since we're not going to be able to link against the system's libudev any time soon,
+    // poll for accessibility changes with inotify until a timeout expires.
+    libusb_ref_device(device);
+    auto thread = std::thread([device]() {
+        std::string bus_path =
+                android::base::StringPrintf("/dev/bus/usb/%03d/", libusb_get_bus_number(device));
+        std::string device_path = android::base::StringPrintf("%s/%03d", bus_path.c_str(),
+                                                              libusb_get_device_address(device));
+        auto deadline = std::chrono::steady_clock::now() + 1s;
+        unique_fd infd(inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
+        if (infd == -1) {
+            PLOG(FATAL) << "failed to create inotify fd";
+        }
+
+        // Register the watch first, and then check for accessibility, to avoid a race.
+        // We can't watch the device file itself, as that requires us to be able to access it.
+        if (inotify_add_watch(infd.get(), bus_path.c_str(), IN_ATTRIB) == -1) {
+            PLOG(ERROR) << "failed to register inotify watch on '" << bus_path
+                        << "', falling back to sleep";
+            std::this_thread::sleep_for(std::chrono::seconds(1));
+        } else {
+            adb_pollfd pfd = {.fd = infd.get(), .events = POLLIN, .revents = 0};
+
+            while (access(device_path.c_str(), R_OK | W_OK) == -1) {
+                auto timeout = deadline - std::chrono::steady_clock::now();
+                if (timeout < 0s) {
+                    break;
+                }
+
+                uint64_t ms = timeout / 1ms;
+                int rc = adb_poll(&pfd, 1, ms);
+                if (rc == -1) {
+                    if (errno == EINTR) {
+                        continue;
+                    } else {
+                        LOG(WARNING) << "timeout expired while waiting for device accessibility";
+                        break;
+                    }
+                }
+
+                union {
+                    struct inotify_event ev;
+                    char bytes[sizeof(struct inotify_event) + NAME_MAX + 1];
+                } buf;
+
+                rc = adb_read(infd.get(), &buf, sizeof(buf));
+                if (rc == -1) {
+                    break;
+                }
+
+                // We don't actually care about the data: we might get spurious events for
+                // other devices on the bus, but we'll double check in the loop condition.
+                continue;
+            }
+        }
+
+        process_device(device);
+        if (--connecting_devices == 0) {
+            adb_notify_device_scan_complete();
+        }
+        libusb_unref_device(device);
+    });
+    thread.detach();
+#else
+    process_device(device);
+#endif
+}
+
+static auto& hotplug_queue = *new BlockingQueue<std::pair<libusb_hotplug_event, libusb_device*>>();
+static void hotplug_thread() {
+    VLOG(USB) << "libusb hotplug thread started";
+    adb_thread_setname("libusb hotplug");
+    while (true) {
+        hotplug_queue.PopAll([](std::pair<libusb_hotplug_event, libusb_device*> pair) {
+            libusb_hotplug_event event = pair.first;
+            libusb_device* device = pair.second;
+            if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
+                VLOG(USB) << "libusb hotplug: device arrived";
+                device_connected(device);
+            } else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
+                VLOG(USB) << "libusb hotplug: device left";
+                device_disconnected(device);
+            } else {
+                LOG(WARNING) << "unknown libusb hotplug event: " << event;
+            }
+        });
+    }
+}
+
+LIBUSB_CALL int hotplug_callback(libusb_context*, libusb_device* device, libusb_hotplug_event event,
+                                 void*) {
+    // We're called with the libusb lock taken. Call these on a separate thread outside of this
+    // function so that the usb_handle mutex is always taken before the libusb mutex.
+    static std::once_flag once;
+    std::call_once(once, []() { std::thread(hotplug_thread).detach(); });
+
+    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
+        ++connecting_devices;
+    }
+    hotplug_queue.Push({event, device});
+    return 0;
+}
+
+namespace libusb {
+
+static void usb_init_libusb_hotplug() {
+    int rc = libusb_hotplug_register_callback(
+            nullptr,
+            static_cast<libusb_hotplug_event>(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
+                                              LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
+            LIBUSB_HOTPLUG_ENUMERATE, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
+            LIBUSB_CLASS_PER_INTERFACE, hotplug_callback, nullptr, nullptr);
+
+    if (rc != LIBUSB_SUCCESS) {
+        LOG(FATAL) << "failed to register libusb hotplug callback";
+    }
+
+    // Spawn a thread for libusb_handle_events.
+    std::thread([]() {
+        adb_thread_setname("libusb");
+        while (true) {
+            libusb_handle_events(nullptr);
+        }
+    }).detach();
+}
+
+static void usb_init_inhouse_hotplug() {
+    // Spawn a thread for handling USB events
+    std::thread([]() {
+        adb_thread_setname("libusb_inhouse_hotplug");
+        struct timeval timeout{(time_t)libusb_inhouse_hotplug::kScan_rate_s.count(), 0};
+        while (true) {
+            VLOG(USB) << "libusb thread iteration";
+            libusb_handle_events_timeout_completed(nullptr, &timeout, nullptr);
+            libusb_inhouse_hotplug::scan();
+        }
+    }).detach();
+}
+
+void usb_init() {
+    VLOG(USB) << "initializing libusb...";
+    int rc = libusb_init(nullptr);
+    if (rc != 0) {
+        LOG(WARNING) << "failed to initialize libusb: " << libusb_error_name(rc);
+        return;
+    }
+
+    if (libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
+        usb_init_libusb_hotplug();
+    } else {
+        usb_init_inhouse_hotplug();
+    }
+}
+}  // namespace libusb
\ No newline at end of file
diff --git a/client/usb_libusb_hotplug.h b/client/usb_libusb_hotplug.h
new file mode 100644
index 00000000..27d3ddf6
--- /dev/null
+++ b/client/usb_libusb_hotplug.h
@@ -0,0 +1,30 @@
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
+#include "usb_libusb.h"
+
+#include <libusb/libusb.h>
+
+namespace libusb {
+
+void usb_init();
+}
+
+// Only visible to allow inhouse hotplug to inject events.
+LIBUSB_CALL int hotplug_callback(libusb_context*, libusb_device* device, libusb_hotplug_event event,
+                                 void*);
diff --git a/client/usb_libusb_inhouse_hotplug.cpp b/client/usb_libusb_inhouse_hotplug.cpp
new file mode 100644
index 00000000..dc42ebaf
--- /dev/null
+++ b/client/usb_libusb_inhouse_hotplug.cpp
@@ -0,0 +1,94 @@
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
+#include "usb_libusb_inhouse_hotplug.h"
+
+#include <chrono>
+#include <thread>
+#include <unordered_map>
+
+#include "adb_trace.h"
+#include "client/usb_libusb_hotplug.h"
+
+#include "libusb/libusb.h"
+
+namespace libusb_inhouse_hotplug {
+
+class ScanRateLimiter {
+  public:
+    ScanRateLimiter(std::chrono::seconds rate) : rate_s_(rate) { Tick(); }
+    bool Exceeded() {
+        auto elapsed_since_last_scan = std::chrono::duration_cast<std::chrono::seconds>(
+                std::chrono::steady_clock::now() - last_tick_);
+        return elapsed_since_last_scan < rate_s_;
+    }
+
+    void Tick() { last_tick_ = std::chrono::steady_clock::now(); }
+
+  private:
+    std::chrono::seconds rate_s_;
+    std::chrono::time_point<std::chrono::steady_clock> last_tick_;
+};
+
+std::chrono::seconds kScan_rate_s = std::chrono::seconds(2);
+static ScanRateLimiter rate_limiter{kScan_rate_s};
+
+// We need to synchronize access to the list of known devices. It can be modified from both the
+// monitoring thread but also LibUsbConnection threads (when they report being closed).
+static std::mutex known_devices_mutex [[clang::no_destroy]];
+static std::unordered_map<uint64_t, libusb_device*> GUARDED_BY(known_devices_mutex) known_devices
+        [[clang::no_destroy]];
+
+void scan() {
+    if (rate_limiter.Exceeded()) {
+        return;
+    }
+    rate_limiter.Tick();
+
+    VLOG(USB) << "inhouse USB scanning";
+    std::lock_guard<std::mutex> lock(known_devices_mutex);
+
+    // First retrieve all connected devices and detect new ones.
+    libusb_device** devs = nullptr;
+    libusb_get_device_list(nullptr, &devs);
+    std::unordered_map<uint64_t, libusb_device*> current_devices;
+    for (size_t i = 0; devs[i] != nullptr; i++) {
+        libusb_device* dev = devs[i];
+        auto session_id = LibUsbDevice::GenerateSessionId(dev).id;
+        if (!known_devices.contains(session_id) && !current_devices.contains(session_id)) {
+            hotplug_callback(nullptr, dev, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED, nullptr);
+        }
+        current_devices[session_id] = dev;
+    }
+
+    // Handle disconnected devices
+    for (const auto& [session_id, dev] : known_devices) {
+        if (!current_devices.contains(session_id)) {
+            hotplug_callback(nullptr, dev, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, nullptr);
+        }
+    }
+    known_devices = std::move(current_devices);
+    libusb_free_device_list(devs, false);
+}
+
+void report_error(const LibUsbConnection& connection) {
+    if (libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
+        return;
+    }
+    std::lock_guard<std::mutex> lock(known_devices_mutex);
+    known_devices.erase(connection.GetSessionId());
+}
+}  // end namespace libusb_inhouse_hotplug
\ No newline at end of file
diff --git a/client/fastdeploycallbacks.h b/client/usb_libusb_inhouse_hotplug.h
similarity index 67%
rename from client/fastdeploycallbacks.h
rename to client/usb_libusb_inhouse_hotplug.h
index 4a6fb991..ee5cc877 100644
--- a/client/fastdeploycallbacks.h
+++ b/client/usb_libusb_inhouse_hotplug.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2018 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -16,7 +16,12 @@
 
 #pragma once
 
-#include <vector>
+#include "usb_libusb.h"
 
-int capture_shell_command(const char* command, std::vector<char>* outBuffer,
-                          std::vector<char>* errBuffer);
+#include <chrono>
+
+namespace libusb_inhouse_hotplug {
+void scan();
+void report_error(const LibUsbConnection& connection);
+extern std::chrono::seconds kScan_rate_s;
+}  // namespace libusb_inhouse_hotplug
\ No newline at end of file
diff --git a/crypto/Android.bp b/crypto/Android.bp
index 96283487..fffda7b0 100644
--- a/crypto/Android.bp
+++ b/crypto/Android.bp
@@ -70,10 +70,7 @@ cc_library {
     defaults: ["libadb_crypto_defaults"],
 
     min_sdk_version: "30",
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 }
 
 // For running atest (b/147158681)
diff --git a/daemon/auth.cpp b/daemon/auth.cpp
index b65f4745..495df66d 100644
--- a/daemon/auth.cpp
+++ b/daemon/auth.cpp
@@ -255,7 +255,7 @@ void adbd_auth_init() {
 }
 
 void send_auth_request(atransport* t) {
-    LOG(INFO) << "Calling send_auth_request...";
+    VLOG(AUTH) << "Calling send_auth_request...";
 
     if (!adbd_auth_generate_token(t->token, sizeof(t->token))) {
         PLOG(ERROR) << "Error generating token";
@@ -271,19 +271,19 @@ void send_auth_request(atransport* t) {
 }
 
 void adbd_auth_verified(atransport* t) {
-    LOG(INFO) << "adb client authorized";
+    VLOG(AUTH) << "adb client authorized";
     handle_online(t);
     send_connect(t);
 }
 
 static void adb_disconnected(void* unused, atransport* t) {
-    LOG(INFO) << "ADB disconnect";
+    VLOG(AUTH) << "ADB disconnect";
     CHECK(t->auth_id.has_value());
     adbd_auth_notify_disconnect(auth_ctx, t->auth_id.value());
 }
 
 void adbd_auth_confirm_key(atransport* t) {
-    LOG(INFO) << "prompting user to authorize key";
+    VLOG(AUTH) << "prompting user to authorize key";
     t->AddDisconnect(&adb_disconnect);
     if (adbd_auth_prompt_user_with_id) {
         t->auth_id = adbd_auth_prompt_user_with_id(auth_ctx, t->auth_key.data(), t->auth_key.size(),
@@ -301,19 +301,19 @@ void adbd_notify_framework_connected_key(atransport* t) {
 int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key) {
     if (!auth_required) {
         // Any key will do.
-        LOG(INFO) << __func__ << ": auth not required";
+        VLOG(AUTH) << __func__ << ": auth not required";
         return 1;
     }
 
     bool authorized = false;
     X509* cert = X509_STORE_CTX_get0_cert(ctx);
     if (cert == nullptr) {
-        LOG(INFO) << "got null x509 certificate";
+        VLOG(AUTH) << "got null x509 certificate";
         return 0;
     }
     bssl::UniquePtr<EVP_PKEY> evp_pkey(X509_get_pubkey(cert));
     if (evp_pkey == nullptr) {
-        LOG(INFO) << "got null evp_pkey from x509 certificate";
+        VLOG(AUTH) << "got null evp_pkey from x509 certificate";
         return 0;
     }
 
@@ -337,10 +337,10 @@ int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key) {
         bssl::UniquePtr<EVP_PKEY> known_evp(EVP_PKEY_new());
         EVP_PKEY_set1_RSA(known_evp.get(), key);
         if (EVP_PKEY_cmp(known_evp.get(), evp_pkey.get())) {
-            LOG(INFO) << "Matched auth_key=" << public_key;
+            VLOG(AUTH) << "Matched auth_key=" << public_key;
             verified = true;
         } else {
-            LOG(INFO) << "auth_key doesn't match [" << public_key << "]";
+            VLOG(AUTH) << "auth_key doesn't match [" << public_key << "]";
         }
         RSA_free(key);
         if (verified) {
@@ -367,7 +367,7 @@ void adbd_auth_tls_handshake(atransport* t) {
     std::thread([t]() {
         std::string auth_key;
         if (t->connection()->DoTlsHandshake(rsa_pkey, &auth_key)) {
-            LOG(INFO) << "auth_key=" << auth_key;
+            VLOG(AUTH) << "auth_key=" << auth_key;
             if (t->IsTcpDevice()) {
                 t->auth_key = auth_key;
                 adbd_wifi_secure_connect(t);
diff --git a/daemon/jdwp_service.cpp b/daemon/jdwp_service.cpp
index 6e0c89ef..8ff07480 100644
--- a/daemon/jdwp_service.cpp
+++ b/daemon/jdwp_service.cpp
@@ -35,7 +35,9 @@
 
 #include <adbconnection/server.h>
 #include <android-base/cmsg.h>
+#include <android-base/file.h>
 #include <android-base/unique_fd.h>
+#include <processgroup/processgroup.h>
 
 #include "adb.h"
 #include "adb_io.h"
@@ -268,6 +270,7 @@ static void jdwp_process_event(int socket, unsigned events, void* _proc) {
             goto CloseProcess;
         }
 
+        VLOG(JDWP) << "Received JDWP Process info for pid=" << process_info->pid;
         proc->process = std::move(*process_info);
         jdwp_process_list_updated();
         app_process_list_updated();
@@ -288,6 +291,7 @@ static void jdwp_process_event(int socket, unsigned events, void* _proc) {
 
         proc->out_fds.pop_back();
         if (proc->out_fds.empty()) {
+            VLOG(JDWP) << "Removing FDE_WRITE";
             fdevent_del(proc->fde, FDE_WRITE);
         }
     }
@@ -295,6 +299,7 @@ static void jdwp_process_event(int socket, unsigned events, void* _proc) {
     return;
 
 CloseProcess:
+    VLOG(JDWP) << "Process " << proc->process.pid << " has disconnected";
     bool debuggable = proc->process.debuggable;
     bool profileable = proc->process.profileable;
     proc->RemoveFromList();
@@ -302,30 +307,75 @@ CloseProcess:
     if (debuggable || profileable) app_process_list_updated();
 }
 
-unique_fd create_jdwp_connection_fd(int pid) {
-    D("looking for pid %d in JDWP process list", pid);
+static bool is_process_in_freezer(const ProcessInfo& info) {
+    // Check "/sys/fs/cgroup/apps/uid_{}/pid_{}/cgroup.freeze". Since "apps" is configurable,
+    // use libprocessgroup to make sure we always have the right path.
+    std::string path;
+    if (!CgroupGetAttributePathForProcess("FreezerState", info.uid, info.pid, path)) {
+        VLOG(JDWP) << std::format("Failed to build frozen path of '{}' (got '{}')", info.pid, path);
+        return false;
+    }
 
-    for (auto& proc : _jdwp_list) {
-        // Don't allow JDWP connection to a non-debuggable process.
-        if (!proc->process.debuggable) continue;
-        if (proc->process.pid == static_cast<uint64_t>(pid)) {
-            int fds[2];
+    std::string content;
+    if (!android::base::ReadFileToString(path, &content)) {
+        VLOG(JDWP) << std::format("Failed to read ({})", path);
+        return false;
+    }
 
-            if (adb_socketpair(fds) < 0) {
-                D("%s: socket pair creation failed: %s", __FUNCTION__, strerror(errno));
-                return unique_fd{};
-            }
-            D("socketpair: (%d,%d)", fds[0], fds[1]);
+    bool is_frozen = content == "1\n";
+    VLOG(JDWP) << std::format("Checking if pid {} is frozen at '{}' = '{}'", info.pid, path,
+                              content);
 
-            proc->out_fds.emplace_back(fds[1]);
-            if (proc->out_fds.size() == 1) {
-                fdevent_add(proc->fde, FDE_WRITE);
-            }
+    if (is_frozen) {
+        LOG(WARNING) << std::format("According to '{}'(='{}'), pid {} is frozen", path, content,
+                                    info.pid);
+    }
+    return is_frozen;
+}
+
+static unique_fd send_socket_to_process(JdwpProcess& proc) {
+    // Process in the cached apps freezer don't get scheduled.
+    // Returning a socket will hang the debugger and leak a fd until the app is taken
+    // out of the freezer. Fail instead.
+    if (is_process_in_freezer(proc.process)) {
+        ProcessInfo& info = proc.process;
+        LOG(WARNING) << std::format("Process {} ({}) is frozen. Denying JDWP connection", info.pid,
+                                    info.process_name);
+        return unique_fd{};
+    }
+
+    int fds[2];
+    if (adb_socketpair(fds) < 0) {
+        LOG(WARNING) << std::format("{}: socket pair creation failed: {}", __FUNCTION__,
+                                    strerror(errno));
+        return unique_fd{};
+    }
 
-            return unique_fd{fds[0]};
+    VLOG(JDWP) << std::format("socketpair: ({},{})", fds[0], fds[1]);
+    proc.out_fds.emplace_back(fds[1]);
+    if (proc.out_fds.size() == 1) {
+        fdevent_add(proc.fde, FDE_WRITE);
+    }
+
+    return unique_fd{fds[0]};
+}
+
+unique_fd create_jdwp_connection_fd(pid_t pid) {
+    VLOG(JDWP) << std::format("looking for pid {} in JDWP process list", pid);
+
+    for (auto& proc : _jdwp_list) {
+        // Don't allow JDWP connection to a non-debuggable process.
+        if (!proc->process.debuggable) {
+            continue;
         }
+
+        if (static_cast<pid_t>(proc->process.pid) != pid) {
+            continue;
+        }
+
+        return send_socket_to_process(*proc);
     }
-    D("search failed !!");
+    LOG(WARNING) << std::format("search for pid {} failed !!", pid);
     return unique_fd{};
 }
 
@@ -534,7 +584,7 @@ asocket* create_jdwp_service_socket() {
     return nullptr;
 }
 
-unique_fd create_jdwp_connection_fd(int pid) {
+unique_fd create_jdwp_connection_fd(pid_t pid) {
     return {};
 }
 
diff --git a/daemon/jdwp_service.h b/daemon/jdwp_service.h
index 71a8e64b..a7af06d4 100644
--- a/daemon/jdwp_service.h
+++ b/daemon/jdwp_service.h
@@ -17,8 +17,13 @@
 #include "adb_unique_fd.h"
 #include "socket.h"
 
+#include <unistd.h>
+
 int init_jdwp();
 asocket* create_jdwp_service_socket();
 asocket* create_jdwp_tracker_service_socket();
 asocket* create_app_tracker_service_socket();
-unique_fd create_jdwp_connection_fd(int jdwp_pid);
\ No newline at end of file
+
+// Create a socket pair. Send one end to the debuggable process `jdwp_pid` and
+// return the other one.
+unique_fd create_jdwp_connection_fd(pid_t jdwp_pid);
\ No newline at end of file
diff --git a/daemon/mdns.cpp b/daemon/mdns.cpp
index 3b3292de..7a4839b4 100644
--- a/daemon/mdns.cpp
+++ b/daemon/mdns.cpp
@@ -15,7 +15,9 @@
  */
 
 #include "mdns.h"
+
 #include "adb_mdns.h"
+#include "adb_trace.h"
 #include "sysdeps.h"
 
 #include <dns_sd.h>
@@ -29,13 +31,17 @@
 
 #include <android-base/logging.h>
 #include <android-base/properties.h>
+#include <android-base/thread_annotations.h>
 
 using namespace std::chrono_literals;
 
 static std::mutex& mdns_lock = *new std::mutex();
-static int port;
-static DNSServiceRef mdns_refs[kNumADBDNSServices];
-static bool mdns_registered[kNumADBDNSServices];
+
+// TCP socket port ADBd is listening for incoming connections
+static int tcp_port;
+
+static DNSServiceRef mdns_refs[kNumADBDNSServices] GUARDED_BY(mdns_lock);
+static bool mdns_registered[kNumADBDNSServices] GUARDED_BY(mdns_lock);
 
 void start_mdnsd() {
     if (android::base::GetProperty("init.svc.mdnsd", "") == "running") {
@@ -62,37 +68,33 @@ static void mdns_callback(DNSServiceRef /*ref*/,
     }
 }
 
-static void register_mdns_service(int index, int port, const std::string service_name) {
-    std::lock_guard<std::mutex> lock(mdns_lock);
-
-
-    // https://tools.ietf.org/html/rfc6763
-    // """
-    // The format of the data within a DNS TXT record is one or more
-    // strings, packed together in memory without any intervening gaps or
-    // padding bytes for word alignment.
-    //
-    // The format of each constituent string within the DNS TXT record is a
-    // single length byte, followed by 0-255 bytes of text data.
-    // """
-    //
-    // Therefore:
-    // 1. Begin with the string length
-    // 2. No null termination
-
-    std::vector<char> txtRecord;
-
-    if (kADBDNSServiceTxtRecords[index]) {
-        size_t txtRecordStringLength = strlen(kADBDNSServiceTxtRecords[index]);
+static std::vector<char> buildTxtRecord() {
+    std::map<std::string, std::string> attributes;
+    attributes["v"] = std::to_string(ADB_SECURE_SERVICE_VERSION);
+    attributes["name"] = android::base::GetProperty("ro.product.model", "");
+    attributes["api"] = android::base::GetProperty("ro.build.version.sdk", "");
+
+    // See https://tools.ietf.org/html/rfc6763 for the format of DNS TXT record.
+    std::vector<char> record;
+    for (auto const& [key, val] : attributes) {
+        size_t length = key.size() + val.size() + 1;
+        if (length > 255) {
+            LOG(INFO) << "DNS TXT Record property " << key << "='" << val << "' is too large.";
+            continue;
+        }
+        record.emplace_back(length);
+        std::copy(key.begin(), key.end(), std::back_inserter(record));
+        record.emplace_back('=');
+        std::copy(val.begin(), val.end(), std::back_inserter(record));
+    }
 
-        txtRecord.resize(1 +                    // length byte
-                         txtRecordStringLength  // string bytes
-        );
+    return record;
+}
 
-        txtRecord[0] = (char)txtRecordStringLength;
-        memcpy(txtRecord.data() + 1, kADBDNSServiceTxtRecords[index], txtRecordStringLength);
-    }
+static void register_mdns_service(int index, int port, const std::string& service_name) {
+    std::lock_guard<std::mutex> lock(mdns_lock);
 
+    auto txtRecord = buildTxtRecord();
     auto error = DNSServiceRegister(
             &mdns_refs[index], 0, 0, service_name.c_str(), kADBDNSServices[index], nullptr, nullptr,
             htobe16((uint16_t)port), (uint16_t)txtRecord.size(),
@@ -105,8 +107,8 @@ static void register_mdns_service(int index, int port, const std::string service
     } else {
         mdns_registered[index] = true;
     }
-    LOG(INFO) << "adbd mDNS service " << kADBDNSServices[index]
-            << " registered: " << mdns_registered[index];
+    VLOG(MDNS) << "adbd mDNS service " << kADBDNSServices[index]
+               << " registered: " << mdns_registered[index];
 }
 
 static void unregister_mdns_service(int index) {
@@ -120,7 +122,7 @@ static void unregister_mdns_service(int index) {
 static void register_base_mdns_transport() {
     std::string hostname = "adb-";
     hostname += android::base::GetProperty("ro.serialno", "unidentified");
-    register_mdns_service(kADBTransportServiceRefIndex, port, hostname);
+    register_mdns_service(kADBTransportServiceRefIndex, tcp_port, hostname);
 }
 
 static void setup_mdns_thread() {
@@ -186,25 +188,25 @@ static std::string ReadDeviceGuid() {
 
 // Public interface/////////////////////////////////////////////////////////////
 
-void setup_mdns(int port_in) {
+void setup_mdns(int tcp_port_in) {
     // Make sure the adb wifi guid is generated.
     std::string guid = ReadDeviceGuid();
     CHECK(!guid.empty());
-    port = port_in;
+    tcp_port = tcp_port_in;
     std::thread(setup_mdns_thread).detach();
 
     // TODO: Make this more robust against a hard kill.
     atexit(teardown_mdns);
 }
 
-void register_adb_secure_connect_service(int port) {
-    std::thread([port]() {
+void register_adb_secure_connect_service(int tls_port) {
+    std::thread([tls_port]() {
         auto service_name = ReadDeviceGuid();
         if (service_name.empty()) {
             return;
         }
-        LOG(INFO) << "Registering secure_connect service (" << service_name << ")";
-        register_mdns_service(kADBSecureConnectServiceRefIndex, port, service_name);
+        VLOG(MDNS) << "Registering secure_connect service (" << service_name << ")";
+        register_mdns_service(kADBSecureConnectServiceRefIndex, tls_port, service_name);
     }).detach();
 }
 
diff --git a/daemon/mdns.h b/daemon/mdns.h
index e7e7a621..aa6c6a34 100644
--- a/daemon/mdns.h
+++ b/daemon/mdns.h
@@ -17,9 +17,11 @@
 #ifndef _DAEMON_MDNS_H_
 #define _DAEMON_MDNS_H_
 
-void setup_mdns(int port);
+// Setup mDNS and declare which TCP port ADBd is currently listening on for non-encrypted traffic.
+void setup_mdns(int tcp_port);
 
-void register_adb_secure_connect_service(int port);
+// mDNS advertise the TLS port ADBd is currently listening on for encrypted traffic.
+void register_adb_secure_connect_service(int tls_port);
 void unregister_adb_secure_connect_service();
 bool is_adb_secure_connect_service_registered();
 
diff --git a/daemon/shell_service.cpp b/daemon/shell_service.cpp
index dbca4adb..0b71b035 100644
--- a/daemon/shell_service.cpp
+++ b/daemon/shell_service.cpp
@@ -509,14 +509,15 @@ bool Subprocess::StartThread(std::unique_ptr<Subprocess> subprocess, std::string
 int Subprocess::OpenPtyChildFd(const char* pts_name, unique_fd* error_sfd) {
     int child_fd = adb_open(pts_name, O_RDWR | O_CLOEXEC);
     if (child_fd == -1) {
+        int saved_errno = errno;
         // Don't use WriteFdFmt; since we're in the fork() child we don't want
         // to allocate any heap memory to avoid race conditions.
-        const char* messages[] = {"child failed to open pseudo-term slave ",
-                                  pts_name, ": ", strerror(errno)};
+        const char* messages[] = {"child failed to open pts ",
+                                  pts_name, ": ", strerror(saved_errno)};
         for (const char* message : messages) {
             WriteFdExactly(*error_sfd, message);
         }
-        abort();
+        LOG(FATAL) << "child failed to open pts " << pts_name << ": " << strerror(saved_errno);
     }
 
     if (make_pty_raw_) {
@@ -525,7 +526,7 @@ int Subprocess::OpenPtyChildFd(const char* pts_name, unique_fd* error_sfd) {
             int saved_errno = errno;
             WriteFdExactly(*error_sfd, "tcgetattr failed: ");
             WriteFdExactly(*error_sfd, strerror(saved_errno));
-            abort();
+            LOG(FATAL) << "tcgetattr() failed: " << strerror(saved_errno);
         }
 
         cfmakeraw(&tattr);
@@ -533,7 +534,7 @@ int Subprocess::OpenPtyChildFd(const char* pts_name, unique_fd* error_sfd) {
             int saved_errno = errno;
             WriteFdExactly(*error_sfd, "tcsetattr failed: ");
             WriteFdExactly(*error_sfd, strerror(saved_errno));
-            abort();
+            LOG(FATAL) << "tcsetattr() failed: " << strerror(saved_errno);
         }
     }
 
diff --git a/daemon/transport_socket_server.cpp b/daemon/transport_socket_server.cpp
index 9f1d0949..38ba7ea2 100644
--- a/daemon/transport_socket_server.cpp
+++ b/daemon/transport_socket_server.cpp
@@ -56,10 +56,11 @@ void server_socket_thread(std::string_view addr) {
     while (serverfd == -1) {
         errno = 0;
         serverfd = unique_fd{socket_spec_listen(addr, &error, nullptr)};
-        if (errno == EAFNOSUPPORT || errno == EINVAL || errno == EPROTONOSUPPORT) {
-            D("unrecoverable error: '%s'", error.c_str());
-            return;
-        } else if (serverfd < 0) {
+        if (serverfd < 0) {
+            if (errno == EAFNOSUPPORT || errno == EINVAL || errno == EPROTONOSUPPORT) {
+                D("unrecoverable error: '%s'", error.c_str());
+                return;
+            }
             D("server: cannot bind socket yet: %s", error.c_str());
             std::this_thread::sleep_for(1s);
             continue;
diff --git a/daemon/usb.cpp b/daemon/usb.cpp
index bd881c7d..f4429610 100644
--- a/daemon/usb.cpp
+++ b/daemon/usb.cpp
@@ -150,7 +150,7 @@ struct UsbFfsConnection : public Connection {
           control_fd_(std::move(control)),
           read_fd_(std::move(read)),
           write_fd_(std::move(write)) {
-        LOG(INFO) << "UsbFfsConnection constructed";
+        VLOG(USB) << "UsbFfsConnection constructed";
         worker_event_fd_.reset(eventfd(0, EFD_CLOEXEC));
         if (worker_event_fd_ == -1) {
             PLOG(FATAL) << "failed to create eventfd";
@@ -165,7 +165,7 @@ struct UsbFfsConnection : public Connection {
     }
 
     ~UsbFfsConnection() {
-        LOG(INFO) << "UsbFfsConnection being destroyed";
+        VLOG(USB) << "UsbFfsConnection being destroyed";
         Stop();
         monitor_thread_.join();
 
@@ -180,7 +180,7 @@ struct UsbFfsConnection : public Connection {
     }
 
     virtual bool Write(std::unique_ptr<apacket> packet) override final {
-        LOG(DEBUG) << "USB write: " << dump_header(&packet->msg);
+        VLOG(USB) << "USB write: " << dump_header(&packet->msg);
         auto header = std::make_shared<Block>(sizeof(packet->msg));
         memcpy(header->data(), &packet->msg, sizeof(packet->msg));
 
@@ -260,7 +260,7 @@ struct UsbFfsConnection : public Connection {
 
         monitor_thread_ = std::thread([this]() {
             adb_thread_setname("UsbFfs-monitor");
-            LOG(INFO) << "UsbFfs-monitor thread spawned";
+            VLOG(USB) << "UsbFfs-monitor thread spawned";
 
             bool bound = false;
             bool enabled = false;
@@ -299,7 +299,7 @@ struct UsbFfsConnection : public Connection {
                                << sizeof(event) << ", got " << rc;
                 }
 
-                LOG(INFO) << "USB event: "
+                VLOG(USB) << "USB event: "
                           << to_string(static_cast<usb_functionfs_event_type>(event.type));
 
                 switch (event.type) {
@@ -363,7 +363,7 @@ struct UsbFfsConnection : public Connection {
                         break;
 
                     case FUNCTIONFS_SETUP: {
-                        LOG(INFO) << "received FUNCTIONFS_SETUP control transfer: bRequestType = "
+                        VLOG(USB) << "received FUNCTIONFS_SETUP control transfer: bRequestType = "
                                   << static_cast<int>(event.u.setup.bRequestType)
                                   << ", bRequest = " << static_cast<int>(event.u.setup.bRequest)
                                   << ", wValue = " << static_cast<int>(event.u.setup.wValue)
@@ -371,7 +371,7 @@ struct UsbFfsConnection : public Connection {
                                   << ", wLength = " << static_cast<int>(event.u.setup.wLength);
 
                         if ((event.u.setup.bRequestType & USB_DIR_IN)) {
-                            LOG(INFO) << "acking device-to-host control transfer";
+                            VLOG(USB) << "acking device-to-host control transfer";
                             ssize_t rc = adb_write(control_fd_.get(), "", 0);
                             if (rc != 0) {
                                 PLOG(ERROR) << "failed to write empty packet to host";
@@ -389,7 +389,7 @@ struct UsbFfsConnection : public Connection {
                                         << event.u.setup.wLength;
                             }
 
-                            LOG(INFO) << "control request contents: " << buf;
+                            VLOG(USB) << "control request contents: " << buf;
                             break;
                         }
                     }
@@ -406,7 +406,7 @@ struct UsbFfsConnection : public Connection {
         worker_started_ = true;
         worker_thread_ = std::thread([this]() {
             adb_thread_setname("UsbFfs-worker");
-            LOG(INFO) << "UsbFfs-worker thread spawned";
+            VLOG(USB) << "UsbFfs-worker thread spawned";
 
             for (size_t i = 0; i < kUsbReadQueueDepth; ++i) {
                 read_requests_[i] = CreateReadBlock(next_read_id_++);
@@ -541,8 +541,8 @@ struct UsbFfsConnection : public Connection {
 
         // Notification for completed reads can be received out of order.
         if (block->id().id != needed_read_id_) {
-            LOG(VERBOSE) << "read " << block->id().id << " completed while waiting for "
-                         << needed_read_id_;
+            VLOG(USB) << "read " << block->id().id << " completed while waiting for "
+                      << needed_read_id_;
             return true;
         }
 
@@ -605,7 +605,7 @@ struct UsbFfsConnection : public Connection {
 
         write_requests_.erase(it);
         size_t outstanding_writes = --writes_submitted_;
-        LOG(DEBUG) << "USB write: reaped, down to " << outstanding_writes;
+        VLOG(USB) << "USB write: reaped, down to " << outstanding_writes;
     }
 
     IoWriteBlock CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
@@ -647,7 +647,7 @@ struct UsbFfsConnection : public Connection {
             CHECK(!write_requests_[writes_submitted_ + i].pending);
             write_requests_[writes_submitted_ + i].pending = true;
             iocbs[i] = &write_requests_[writes_submitted_ + i].control;
-            LOG(VERBOSE) << "submitting write_request " << static_cast<void*>(iocbs[i]);
+            VLOG(USB) << "submitting write_request " << static_cast<void*>(iocbs[i]);
         }
 
         writes_submitted_ += writes_to_submit;
@@ -667,7 +667,7 @@ struct UsbFfsConnection : public Connection {
         for (size_t i = 0; i < writes_submitted_; ++i) {
             struct io_event res;
             if (write_requests_[i].pending == true) {
-                LOG(INFO) << "cancelling pending write# " << i;
+                VLOG(USB) << "cancelling pending write# " << i;
                 io_cancel(aio_context_.get(), &write_requests_[i].control, &res);
             }
         }
@@ -749,9 +749,9 @@ static void usb_ffs_open_thread() {
         }
 
         if (android::base::GetBoolProperty(kPropertyUsbDisabled, false)) {
-            LOG(INFO) << "pausing USB due to " << kPropertyUsbDisabled;
+            VLOG(USB) << "pausing USB due to " << kPropertyUsbDisabled;
             prop_mon.Run();
-            LOG(INFO) << "resuming USB";
+            VLOG(USB) << "resuming USB";
         }
 
         atransport* transport = new atransport(kTransportUsb);
diff --git a/docs/dev/README.md b/docs/dev/README.md
index 9bdc1a5d..684c5811 100644
--- a/docs/dev/README.md
+++ b/docs/dev/README.md
@@ -5,4 +5,9 @@
 - [How root/unroot works](root.md)
 - [Understanding asocket](asocket.md)
 - [Trade-In Mode](adb_tradeinmode.md)
-- [How ADB uses USB Zero-length packets](zero_length_packet.md)
\ No newline at end of file
+- [How ADB uses USB Zero-length packets](zero_length_packet.md)
+- [How adbd starts](how_adbd_starts.md)
+- [How burst mode works](delayed_ack.md)
+- [How adbd and framework communicate](adbd_framework.md)
+- [How ADB Wifi works](adb_wifi.md)
+- [How ADB Incremental install works](incremental-install.md)
diff --git a/docs/dev/adbd_framework.md b/docs/dev/adbd_framework.md
new file mode 100644
index 00000000..33397104
--- /dev/null
+++ b/docs/dev/adbd_framework.md
@@ -0,0 +1,46 @@
+# How ADBd and Framework communicate
+
+## adbd_auth
+
+The recommended way is to use `libadbd_auth` (frameworks/native/libs/adbd_auth).
+It is a bidirectional socket originally used to handle authentication messages (hence the name).
+It has since  evolved to carry other categories of messages.
+
+```
+        ┌────────────┐               ┌─────────────────────┐
+        │ ADBService ◄───────────────► AdbDebuggingManager │
+        └────────────┘               └──────────▲──────────┘
+                                                │
+                                     ┌──────────▼──────────┐
+                                     │  AdbDebuggingThread │
+                                     └──────────▲──────────┘
+                                                │
+   Framework                            ┌───────▼───────┐
+   ─────────────────────────────────────┤ "adbd" socket ├─────────
+   ADBd                                 └───────▲───────┘
+                                                │
+           ┌───────┐                     ┌──────▼─────┐
+           │ ADBd  ◄─────────────────────► adbd_auth  │
+           └───────┘                     └────────────┘
+```
+
+Example of usages (adbd-framework direction, packet header):
+
+- [>> DD] Upon authentication, prompt user with a window to accept/refuse adb server's public key.
+- [<< OK] Upon authentication, tell adbd the user accepted the key.
+- [<< KO] Upon authentication, tell adbd the user refused the key.
+- [>> DC] When a device disconnects.
+- [>> TP] When the TLS Server starts, advertise its TLS port.
+- [>> WE] When a TLS device connects.
+- [>> WF] When a TLS device disconnects.
+
+## System properties
+
+A hacky way which should be avoided as much as possible is to use system property setter + getter. There
+are threads listening on system property changes in both adbd and framework. See examples as follows.
+
+- adbd writes `service.adb.tls.port`, framework uses a thread to monitor it.
+- framework writes `persist.adb.tls_server.enable`, adbd uses a thread to monitor it.
+
+If you are an ADB maintainer or/and have a few spare cycles, it would not be a bad idea to remove
+these in favor of using `adbd_auth`.
diff --git a/docs/dev/debugging.md b/docs/dev/debugging.md
index f6acbfac..73a351d6 100644
--- a/docs/dev/debugging.md
+++ b/docs/dev/debugging.md
@@ -26,12 +26,13 @@ $ adb server nodaemon
 
 The environment variable `ADB_TRACE` is also checked by the adb client.
 
-### Host libusb
+#### libusb
 Libusb log level can be increased via environment variable `LIBUSB_DEBUG=4` (and restarting the server).
 See libusb documentation for available [log levels](https://libusb.sourceforge.io/api-1.0/group__libusb__lib.html#ga2d6144203f0fc6d373677f6e2e89d2d2).
 
 ### Device
 
+#### adbd
 On the device, `adbd` does not read `ADB_TRACE` env variable. Instead it checks property `persist.adb.trace_mask`.
 Set it and then cycle `adbd`.
 
@@ -42,5 +43,36 @@ $ adb shell su 0 pkill adbd
 
 `adbd` will write logs in `/data/adb`. The filename depends on what time `adbd` started (e.g.:`adb-2024-10-08-17-06-21-4611`).
 
+#### Framework
+
+To log components living in Framework, several methods are available depending on how much
+needs to be seen.
+
+The log level of each component can be changed.
+```
+adb shell setprop log.tag.all VERBOSE
+adb shell setprop log.tag.AdbDebuggingManager D
+```
+
+Alternatively, components' log levels can be set directly on `logcat` command-line.
+```
+adb logcat AdbDebuggingManager:D *:S
+```
+
+#### mdnsResponder
+
+mdnsResponder is the lib in charge of mDNS service publishing on the device. Enabling logs
+requires recompiling it with the following changes.
+
+Change `mDNSDebug.c`.
+```
+mDNSexport int mDNS_LoggingEnabled = 1;
+```
+Change `Android.bp`.
+```
+-DMDNS_DEBUGMSGS=2
+```
+
+
 
 
diff --git a/docs/dev/delayed_ack.md b/docs/dev/delayed_ack.md
index 251bb291..c714ff64 100644
--- a/docs/dev/delayed_ack.md
+++ b/docs/dev/delayed_ack.md
@@ -12,7 +12,7 @@ In that CL, the protocol was updated to remove the requirement for CRC generatio
 This does not affect the reliability of a transport since both USB and TCP have packet checksums of their own.
 
 The second issue is solved by "delayed ACK" ([aosp/1953877](https://android-review.googlesource.com/q/1953877)),
-an experimental feature controlled by the environment variable `ADB_DELAYED_ACK`.
+an experimental feature controlled by the environment variable `ADB_BURST_MODE`.
 
 # How delayed ACK works
 
@@ -80,4 +80,29 @@ Host(ASB=X-c)       < A_OKAY(<b>)             < Device
 Host(ASB=X)         < A_OKAY(<c>)             < Device
 ```
 
+# Results
 
+Initial testing show that Burst Mode is nearly 70% faster at pushing files to a device over a USB-3 cable.
+
+## Before
+```
+$ adb kill-server && unset ADB_BURST_MODE && adb start-server
+$ adb push -Z ~/Desktop/10G1 /data/local/tmp
+/usr/local/google/home/sanglardf/Desktop/10G1: 1 file pushed, 0 skipped. 202.0 MB/s (10737418240 bytes in 50.701s)
+$ adb push -Z ~/Desktop/10G1 /data/local/tmp
+/usr/local/google/home/sanglardf/Desktop/10G1: 1 file pushed, 0 skipped. 205.9 MB/s (10737418240 bytes in 49.724s)
+$ adb push -Z ~/Desktop/10G1 /data/local/tmp
+/usr/local/google/home/sanglardf/Desktop/10G1: 1 file pushed, 0 skipped. 197.6 MB/s (10737418240 bytes in 51.828s)
+```
+
+## After
+
+```
+$ adb kill-server && export ADB_BURST_MODE=1 && adb start-server
+$ adb push -Z ~/Desktop/10G1 /data/local/tmp
+/usr/local/google/home/sanglardf/Desktop/10G1: 1 file pushed, 0 skipped. 337.2 MB/s (10737418240 bytes in 30.365s)
+$ adb push -Z ~/Desktop/10G1 /data/local/tmp
+/usr/local/google/home/sanglardf/Desktop/10G1: 1 file pushed, 0 skipped. 342.0 MB/s (10737418240 bytes in 29.945s)
+$ adb push -Z ~/Desktop/10G1 /data/local/tmp
+/usr/local/google/home/sanglardf/Desktop/10G1: 1 file pushed, 0 skipped. 341.3 MB/s (10737418240 bytes in 30.000s)
+```
diff --git a/docs/dev/how_adbd_starts.md b/docs/dev/how_adbd_starts.md
new file mode 100644
index 00000000..6d77c95c
--- /dev/null
+++ b/docs/dev/how_adbd_starts.md
@@ -0,0 +1,90 @@
+# How adbd starts
+
+The `adbd` service life cycle is managed by the [init](../../../../../system/core/init/README.md) process.
+The daemon will be started when the two following conditions are true.
+1. The device is in developer mode.
+2. Adb over USB or adb over Wifi are enabled.
+
+`init` itself doesn't have any special knowledge about adbd. Everything it needs to know comes from the various .rc files
+(telling it what to do when various properties are set) and the processes that set those properties.
+
+There are two main scenarios where init will start `adbd`. When the device boots and when a user runs a device into
+"developer mode".
+
+## When the device boots
+
+The behavior of `init` is controlled by `.rc` files, commands, and system properties.
+
+- The `adbd` service is described [here](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/apex/adbd.rc;drc=a9b3987d2a42a40de0d67fcecb50c9716639ef03).
+- The [rc language](../../../../../system/core/init/README.md) tie together properties, commands, and services.
+
+When a device boots, the script init.usb.rc [checks](https://cs.android.com/android/platform/superproject/main/+/main:system/core/rootdir/init.usb.rc;l=109;drc=e34549af332e4be13a2ffb385455280d4736c1a9)
+if persistent property `persist.sys.usb.config` is set, in which case the values is copied into `sys.usb.config`.
+When this value is written, it [triggers](https://cs.android.com/android/platform/superproject/main/+/main:system/core/rootdir/init.usb.rc;l=47;drc=e34549af332e4be13a2ffb385455280d4736c1a9) `init` to run `start adbd`.
+
+## When the device is already booted
+
+When the device is up and running, it could be in "Developer Mode" but `adbd` service may not be running. It is only
+after the user toggles "Developer options" -> "USB debugging" or "Developer options" -> "Wireless debugging" via the GUI that `adbd` starts.
+
+Note that the previous description is valid for `user` builds. In the case of `userdebug` and `eng`, properties set
+at build-time, such as `ro.adb.secure` or `persist.sys.usb.config`, will automate adbd starting up and disable authentication.
+
+Four layers are involved.
+
+1. GUI USB / GUI Wireless
+2. AdbSettingsObserver
+2. AdbService
+3. init process
+
+
+### GUI (USB)
+
+1. The confirmation dialog is displayed from [AdbPreferenceController.showConfirmationDialog](https://cs.android.com/android/platform/superproject/main/+/main:packages/apps/Settings/src/com/android/settings/development/AdbPreferenceController.java;l=48;drc=1b8c0fdfdb9a36f691402513258b26036c41667f).
+2. Validation is performed in [AdbPreferenceController.writeAdbSettings](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/packages/SettingsLib/src/com/android/settingslib/development/AbstractEnableAdbPreferenceController.java;l=133;drc=aaea2d2266d29b3881f452899b79fb9e71525c3b) once the dialog is validated by user
+3. `Settings.Global.ADB_ENABLED` is set.
+
+```
+Settings.Global.putInt(mContext.getContentResolver(),
+Settings.Global.ADB_ENABLED, enabled ? ADB_SETTING_ON : ADB_SETTING_OFF);
+```
+
+### GUI (Wireless)
+In the case of "Wireless debugging" toggle, the same kind of interaction leads to `ADB_WIFI_ENABLED` being set.
+
+```
+Settings.Global.putInt(mContext.getContentResolver(), Settings.Global.ADB_WIFI_ENABLED , 1);
+```
+### AdbSettingsObserver
+1. Both `ADB_ENABLED` and `ADB_WIFI_ENABLED` are monitored by [AdbSettingsObserver](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/adb/AdbService.java;l=208;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b).
+
+2. When a change is detected, the Observers calls [AdbService::setAdbEnabled](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/adb/AdbService.java;l=213;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b).
+
+### AdbService
+
+1. [AdbService.startAdbd](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/adb/AdbService.java;l=480;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b) is called. This talks to the `init` process by setting `ctl.start` or `ctl.stop` to "adbd".
+This step is equivalent to `.rc` files `start adbd` and `stop adbd`.
+
+### USBDeviceManager (USB only)
+
+If USB is involved (as opposed to ADB Wifi), ([USBDeviceManager.onAdbEnabled](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/usb/java/com/android/server/usb/UsbDeviceManager.java;l=1090;drc=e36f88c420fe00112e11e85634851d047c0b623e)
+) is called to recompose the gadget functions. As a side effect, persistent property `persist.sys.usb.config`
+is set so `init` will automatically start `adbd` service on the next device start.
+
+1. `MSG_ENABLE_ADB` message is sent from [onAdbEnabled](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/usb/java/com/android/server/usb/UsbDeviceManager.java;l=1090;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b).
+
+2. In [UsbDeviceManager.setAdbEnabled](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/usb/java/com/android/server/usb/UsbDeviceManager.java;l=780;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b) property `persist.sys.usb.config` is set.
+
+3. The manager needs to recompose the functions into a gadget.
+    1. [UsbDeviceManager.setEnabledFunctions](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/usb/java/com/android/server/usb/UsbDeviceManager.java;l=2422;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b).
+    2. [UsbDeviceManager.setUsbConfig()](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/usb/java/com/android/server/usb/UsbDeviceManager.java;l=2376;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b).
+
+### init
+
+`init` [monitors](https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/property_service.cpp;l=551;drc=8067bd819f42be5512cdab8aaa3b0e9b4dba2369)
+properties `ctl.start` and `ctl.stop` and interprets changes
+as requests to start/stop a service. See `init` built-in commands (such as `start` and `stop`) [here](https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/builtins.cpp;l=1334;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b).
+
+To let other systems observe services' lifecycle, `init` [sets properties](https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/service.cpp;l=179;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b) with known prefixes.
+- Lifecycle: `init.svc.SERVICE_NAME` (`init.svc.adbd`), which can be set to "running", "stopped", "stopping" (see [Service::NotifyStateChange](https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/service.cpp;l=172;drc=6474abd265cae9ccbe4e5d9ad37959215dcf564b) for all possible values).
+- Bootime: `ro.boottime.SERVICE_NAME` (`ro.boottime.adbd`).
diff --git a/docs/dev/incremental-install.md b/docs/dev/incremental-install.md
new file mode 100644
index 00000000..f47be751
--- /dev/null
+++ b/docs/dev/incremental-install.md
@@ -0,0 +1,155 @@
+# How ADB incremental-install works
+
+The regular way an app is installed on an Android devices is for ADB to open a
+connection to the package manager (`pm`) and write all the bytes. Once received
+by `pm`, the app is verified via v2 signature checking, adb gets an
+installation reply (SUCCESS or FAILURE [..]), and the operation is considered
+over.
+
+Incremental-install is a departure from the idea that all bytes needs to be
+pushed for the installation to be considered over. It even allows an app to
+start before `pm` has received all the bytes.
+
+## The big picture
+
+The big picture of incremental-install revolves around four concepts.
+
+- Blocks
+- Block requests
+- Incremental Server (`IS`)
+- V4 signature
+
+Each file of an app (apk, splits, obb) are viewed as a series of blocks.
+
+In incremental-install mode, `pm` only need to receive a few blocks to validate
+the app and declare installation over (with SUCCESS/FAILURE) which increase
+installation speed tremendously.
+
+In the background, ADB will keep on steaming blocks linearly, even after `pm`
+reported being "done". The background streaming is done in ADB's embedded
+`IS`.
+
+The `IS` sends blocks to the device in order it assumes will be accessed by `pm`.
+And then it sends the remaining block from start to end of file.
+
+`pm` will inevitably need blocks it has not received yet. For example, when the
+app's Central Directory (located at the end of a zip file) must be read to know
+what files are in the apk. This is where block requests enter the picture. The
+Android device can issue requests which will make the `IS` bump the priority of
+a block so it is sent to the device as soon as possible.
+
+### Incremental-install filesystem
+
+The block requests are not issued by Android Frameworks. Framework is completely
+oblivious of the background streaming. Everything is done at the Android kernel
+level where file access is detected. If a read lands on a block that has not been
+received yet, the kernel issues a block request to get it from the streaming
+server immediately.
+
+### App verification
+
+In incremental-install mode, `pm` does minimal verification of app integrity.
+- Checks that there is a v4 signature
+- Check there is a v2 or v3 signature
+- Check that v4 is linked to either v2 or v3
+- Check the v4 header is signed with same certificate as v2/v3
+
+The rest of the app verification is done by the Android kernel for each block level
+when they are received.
+
+With v2 signing, an apps is signed by building a merkle tree, keeping only the
+top node hash, signing it, and embedding it in the apk. On `pm` side, to verify
+the app, the merkle tree is rebuilt, and the top hash is compared against the
+signed hash. V2 can only work if `pm` has all the bytes of an app which is not
+the case here.
+
+#### v4 signing
+This problem is solved with V4 signing which does not discard the merkle tree
+but embed it in the signed file and also outputs the top merkle node hash in
+a .idsig file.
+
+Upon installation the whole merkel tree from V4 is given to `pm` which forwards
+it to the Android kernel. The kernel is in charge of verifying the integrity
+of each block when they are received from the `IS` via the merkle tree.
+
+For more details about v4 signing, refer to [APK signature scheme v4](https://source.android.com/docs/security/features/apksigning/v4) page.
+## How ADB performs incremental-install
+
+To perform incremental-install, ADB needs to do two things.
+
+- Define the block database to `pm`.
+- Start a `IS`.
+
+```
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
+```
+
+### Local database
+
+The call to `pm incremental-install` has arguments describing the `IS` database.
+It allows the kernel to issue block requests. The arg format to describe the `IS`
+database is as follows.
+
+```
+filename:file_size:file_id:signature[:protocol_version]
+```
+
+where
+
+- `file_id` is the identified that will be used by the kernel for block
+requests. There is one arg for each file to be streamed.
+- `signature` is the top merkle hash.
+- `[:protocol_version]` is optional.
+
+### Unsigned files
+
+There could be unsigned files to be installed. In this case, `pm` has to be made
+aware of them via a special arg format.
+
+```
+filename::file_size:file_id
+```
+
+These files are not sent via the `IS` but instead sent on stdin, before
+the `IS` is started.
+
+```
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
+```
+
+## Learn more
+
+There is more documentation about this topic which is unfortunately internal only.
+
+- [go/incremental-adb](go/incremental-adb)
+- [go/apk-v4-signature-format](go/apk-v4-signature-format)
+- [go/instamatic-design-signature](go/instamatic-design-signature)
\ No newline at end of file
diff --git a/fdevent/fdevent_test.cpp b/fdevent/fdevent_test.cpp
index 2422f0b5..8705c8c8 100644
--- a/fdevent/fdevent_test.cpp
+++ b/fdevent/fdevent_test.cpp
@@ -261,12 +261,12 @@ TEST_F(FdeventTest, timeout) {
                 } else if (rc == 1) {
                     event = TimeoutEvent::read;
                 } else {
-                    abort();
+                    FAIL() << "unexpected read() result: " << rc;
                 }
             } else if ((events & FDE_TIMEOUT)) {
                 event = TimeoutEvent::timeout;
             } else {
-                abort();
+                FAIL() << "unexpected events: " << events;
             }
 
             CHECK_EQ(fde, test->fde);
diff --git a/libs/adbconnection/Android.bp b/libs/adbconnection/Android.bp
index 45238ad9..3ae868c9 100644
--- a/libs/adbconnection/Android.bp
+++ b/libs/adbconnection/Android.bp
@@ -69,10 +69,7 @@ cc_library {
         "//packages/modules/adb/apex:__subpackages__",
     ],
     min_sdk_version: "30",
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 
     // libadbconnection_client doesn't need an embedded build number.
     use_version_lib: false,
diff --git a/proto/Android.bp b/proto/Android.bp
index edb8059c..b7281e60 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -66,10 +66,7 @@ cc_library {
     defaults: ["libadb_protos_defaults"],
 
     min_sdk_version: "30",
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 }
 
 // For running atest (b/147158681)
@@ -112,10 +109,7 @@ cc_defaults {
 
     stl: "libc++_static",
 
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 }
 
 cc_library {
@@ -171,10 +165,7 @@ cc_defaults {
 
     stl: "libc++_static",
 
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 }
 
 cc_library_host_static {
diff --git a/proto/adb_host.proto b/proto/adb_host.proto
index fb2a0793..f5022a66 100644
--- a/proto/adb_host.proto
+++ b/proto/adb_host.proto
@@ -85,5 +85,8 @@ message AdbServerStatus {
      string executable_absolute_path = 7;
      string log_absolute_path = 8;
      string os = 9;
+     optional string trace_level = 10;
+     optional bool burst_mode = 11;
+     optional bool mdns_enabled = 12;
 }
 
diff --git a/sockets.cpp b/sockets.cpp
index f766f7e9..9a24ff08 100644
--- a/sockets.cpp
+++ b/sockets.cpp
@@ -301,7 +301,7 @@ static void deferred_close(unique_fd fd) {
                 // There's potentially more data to read.
                 auto duration = std::chrono::steady_clock::now() - socket_info->begin;
                 if (duration > 1s) {
-                    LOG(WARNING) << "timeout expired while flushing socket, closing";
+                    LOG(WARNING) << "timeout expired while reading data after flushing socket, closing";
                 } else {
                     return;
                 }
@@ -470,7 +470,7 @@ asocket* create_local_service_socket(std::string_view name, atransport* transpor
     int fd_value = fd.get();
     asocket* s = create_local_socket(std::move(fd));
     s->transport = transport;
-    LOG(VERBOSE) << "LS(" << s->id << "): bound to '" << name << "' via " << fd_value;
+    VLOG(SERVICES) << "LS(" << s->id << "): bound to '" << name << "' via " << fd_value;
 
 #if !ADB_HOST
     if ((name.starts_with("root:") && getuid() != 0 && __android_log_is_debuggable()) ||
diff --git a/sysdeps.h b/sysdeps.h
index 99f6b74f..e973e0ef 100644
--- a/sysdeps.h
+++ b/sysdeps.h
@@ -24,6 +24,13 @@
 #  undef _WIN32
 #endif
 
+// Include this protobuf header first, because it uses some write() calls
+// that we will redefine later. Not all modules that include sysdeps.h use
+// protobufs, so only include it if it exists.
+#if __has_include("google/protobuf/io/coded_stream.h")
+#include "google/protobuf/io/coded_stream.h"
+#endif
+
 #include <errno.h>
 
 #include <optional>
@@ -178,11 +185,11 @@ int unix_isatty(borrowed_fd fd);
 int network_inaddr_any_server(int port, int type, std::string* error);
 
 inline int network_local_client(const char* name, int namespace_id, int type, std::string* error) {
-    abort();
+    abort(); // Windows-only, and libbase logging conflicts with Win32 ERROR.
 }
 
 inline int network_local_server(const char* name, int namespace_id, int type, std::string* error) {
-    abort();
+    abort(); // Windows-only, and libbase logging conflicts with Win32 ERROR.
 }
 
 int network_connect(const std::string& host, int port, int type, int timeout,
diff --git a/sysdeps_win32.cpp b/sysdeps_win32.cpp
index 2c87dc19..a2f7dab5 100644
--- a/sysdeps_win32.cpp
+++ b/sysdeps_win32.cpp
@@ -2903,12 +2903,16 @@ static std::string ToLower(const std::string& anycase) {
     return str;
 }
 
-extern "C" int main(int argc, char** argv);
+int main(int argc, char** argv);
 
 // Link with -municode to cause this wmain() to be used as the program
 // entrypoint. It will convert the args from UTF-16 to UTF-8 and call the
 // regular main() with UTF-8 args.
-extern "C" int wmain(int argc, wchar_t **argv) {
+//
+// The C++ standard requires that main() be declared without a
+// linkage-specification (not extern "C"). The MSDN docs show that wmain() is
+// also used without extern "C". Neither main() nor wmain() is name-mangled.
+int wmain(int argc, wchar_t** argv) {
     // Convert args from UTF-16 to UTF-8 and pass that to main().
     NarrowArgs narrow_args(argc, argv);
 
diff --git a/test_device.py b/test_device.py
index 3ccbe5cd..87b5a032 100755
--- a/test_device.py
+++ b/test_device.py
@@ -1192,8 +1192,8 @@ class FileOperationsTest:
                 dev_md5, _ = device.shell(['md5sum', device_full_path])[0].split()
                 self.assertEqual(temp_file.checksum, dev_md5)
 
-        def test_sync(self):
-            """Sync a host directory to the data partition."""
+        def do_test_sync(self, partition):
+            """Sync a host directory to the given partition."""
 
             try:
                 base_dir = tempfile.mkdtemp()
@@ -1212,7 +1212,7 @@ class FileOperationsTest:
 
                 old_product_out = os.environ.get('ANDROID_PRODUCT_OUT')
                 os.environ['ANDROID_PRODUCT_OUT'] = base_dir
-                device.sync('data')
+                device.sync(partition)
                 if old_product_out is None:
                     del os.environ['ANDROID_PRODUCT_OUT']
                 else:
@@ -1225,6 +1225,16 @@ class FileOperationsTest:
                 if base_dir is not None:
                     shutil.rmtree(base_dir)
 
+        def test_sync_data(self):
+            """Sync a host directory to the data partition."""
+
+            self.do_test_sync('data')
+
+        def test_sync_slash_data(self):
+            """Sync a host directory to the data partition with a leading slash."""
+
+            self.do_test_sync('/data')
+
         def test_push_sync(self):
             """Sync a host directory to a specific path."""
 
@@ -1839,11 +1849,23 @@ class DevicesListing(DeviceTest):
             self.assertFalse(device.model == "")
             self.assertFalse(device.device == "")
             self.assertTrue(device.negotiated_speed == int(device.negotiated_speed))
+            self.assertTrue(int(device.negotiated_speed) != 0)
             self.assertTrue(device.max_speed == int(device.max_speed))
+            self.assertTrue(int(device.max_speed) != 0)
             self.assertTrue(device.transport_id == int(device.transport_id))
 
             proc.terminate()
 
+def invoke(*args):
+    print(args)
+    try:
+        output = subprocess.check_output(args, stderr=subprocess.STDOUT).strip().decode("utf-8")
+        print(output)
+        return output
+    except subprocess.CalledProcessError as e:
+        return "ErrorCode " + str(e.returncode) + ":" + e.output.decode("utf-8")
+
+
 class DevicesListing(DeviceTest):
 
     def test_track_app_appinfo(self):
@@ -1887,9 +1909,149 @@ class ServerStatus(unittest.TestCase):
             self.assertTrue("build" in lines[3])
             self.assertTrue("executable_absolute_path" in lines[4])
             self.assertTrue("log_absolute_path" in lines[5])
+            self.assertTrue("os" in lines[6])
+            self.assertTrue("trace_level" in lines[7])
+            self.assertTrue("burst_mode" in lines[8])
 
-def invoke(*args):
-    return subprocess.check_output(args).strip().decode("utf-8")
+
+class DetachSingleServer(unittest.TestCase):
+    serial = invoke("adb", "get-serialno")
+
+    def wait_for_device(self):
+        count = 0
+        while True:
+            devices = invoke("adb", "devices")
+            if (self.serial in devices and "attached" in devices):
+                return
+            count = count + 1
+            if count > 10:
+                return
+
+    def test_detach_then_attach(self):
+        # Check device is there with comm working
+        who = invoke("adb", "shell", "whoami")
+        self.assertTrue(who == "shell" or who == "root")
+        devices = invoke("adb", "devices")
+        self.assertFalse("detached" in devices, devices)
+        self.assertTrue(self.serial in devices, devices)
+
+        invoke("adb", "detach")
+
+        # Verify detach did not remove the device from list
+        devices = invoke("adb", "devices")
+        self.assertTrue(self.serial in devices, devices)
+        self.assertTrue("detached" in devices, devices)
+
+        # Verify detach makes device unreachable
+        who = invoke("adb", "shell", "whoami")
+        self.assertFalse(who == "shell" or who == "root", who)
+
+        # Re-attach
+        invoke("adb", "attach")
+        time.sleep(2)
+        self.wait_for_device()
+
+        # Check devices is there
+        devices = invoke("adb", "devices")
+        self.assertTrue(self.serial in devices, devices)
+        self.assertFalse("detached" in devices, devices)
+
+        # Check device comm was started
+        who = invoke("adb", "shell", "whoami")
+        self.assertTrue(who == "shell" or who == "root", who)
+
+    def tearDown(self):
+        invoke("adb", "kill-server")
+
+class DetachMultiServer(unittest.TestCase):
+    server1_port = "5038"
+    server2_port = "5039"
+    env_var_detached = "ADB_LIBUSB_START_DETACHED"
+    serial = invoke("adb", "get-serialno")
+
+    def wait_for_device(self, server_id):
+        count = 0
+        while True:
+            devices = invoke("adb", "-P", server_id, "devices")
+            if (self.serial in devices and "attached" in devices):
+                return
+            count = count + 1
+            if count > 10:
+                return
+
+    def test_device_exchange(self):
+       # Enable once we support invoke with env variable
+       return
+       # Start two "detached" servers with ADB_LIBUSB_START_DETACHED
+       # Attach device to server 1, test it.
+       # Detach device from server 1.
+       # Attach device to server 2. test it.
+
+       # Make sure everything is clean
+       invoke("adb", "-P", self.server1_port, "start-server")
+       invoke("adb", "-P", self.server2_port, "start-server")
+
+       # Make sure server1 sees device as detached
+       devices1= invoke("adb", "-P", self.server1_port, "devices")
+       self.assertTrue("detached" in devices1)
+       self.assertTrue(self.serial in devices1)
+
+       # Make sure server2 sees device as detached
+       devices2= invoke("adb", "-P", self.server2_port, "devices")
+       self.assertTrue("detached" in devices2)
+       self.assertTrue(self.serial in devices2)
+
+       # Attach device to server 1. Verify.
+       invoke("adb", "-P", self.server1_port, "attach")
+       time.sleep(4)
+       self.wait_for_device(self.server1_port)
+
+       devices1= invoke("adb", "-P", self.server1_port, "devices")
+       self.assertFalse("detached" in devices1)
+       self.assertTrue(self.serial in devices1)
+
+       # Make sure server 1 can comm with device
+       who = invoke("adb", "-P", self.server1_port, "shell", "whoami")
+       self.assertTrue(who == "shell" or who == "root")
+
+       # Now detach and make sure device cannot comm
+       invoke("adb", "-P", self.server1_port, "detach")
+       who = invoke("adb", "-P", self.server1_port, "shell", "whoami")
+       self.assertFalse(who == "shell" or who == "root")
+       devices1= invoke("adb", "-P", self.server1_port, "devices")
+       self.assertTrue("detached" in devices1)
+       self.assertTrue(self.serial in devices1)
+
+       # Give device to server2
+       invoke("adb", "-P", self.server2_port, "attach")
+       time.sleep(2)
+       self.wait_for_device(self.server2_port)
+       devices2= invoke("adb", "-P", self.server2_port, "devices")
+       self.assertFalse("detached" in devices2)
+       self.assertTrue(self.serial in devices2)
+
+       # Test that sever2 can comm with device
+       who = invoke("adb", "-P", self.server2_port, "shell", "whoami")
+       self.assertTrue(who == "shell" or who == "root")
+
+       # Detach device from server2. Verify.
+       invoke("adb", "-P", self.server2_port, "detach")
+       devices2= invoke("adb", "-P", self.server2_port, "devices")
+       self.assertTrue("detached" in devices2)
+       self.assertTrue(self.serial in devices2)
+
+       # Verify server2 cannot comm with device
+       who = invoke("adb", "-P", self.server2_port, "shell", "whoami")
+       self.assertFalse(who == "shell" or who == "root")
+
+    def setUp(self):
+       os.environ[self.env_var_detached] = "1"
+       invoke("adb", "kill-server")
+
+    def tearDown(self):
+       invoke("adb", "-P", self.server1_port, "kill-server")
+       invoke("adb", "-P", self.server2_port, "kill-server")
+       del os.environ[self.env_var_detached]
 
 class OneDevice(unittest.TestCase):
 
@@ -1908,6 +2070,63 @@ class OneDevice(unittest.TestCase):
         invoke("adb",  "-P", self.owner_server_port, "kill-server")
         invoke("adb",  "kill-server")
 
+class Debugger(unittest.TestCase):
+
+    PKG_NAME = "adb.test.app1"
+    PROCESS_NAME = "adb.test.process.name"
+    APP_PORT = "8000"
+    HANDSHAKE = "JDWP-Handshake"
+
+    def test_denied_debugger_on_frozen_app(self):
+        # TODO: Enable once we have a test runner that allows to debug tests.
+        # -> JAVA
+
+        # Install app
+        apk = self.PKG_NAME.replace(".", "_") + ".apk"
+        invoke('adb', 'install', '-r', '-t', apk)
+
+        # Start app
+        target = self.PKG_NAME + '/.MainActivity'
+        invoke('adb', 'shell', 'am', 'start', '-W', target)
+
+        # Assert that debugger is allowed
+        pid = invoke("adb", "shell", "pidof", self.PROCESS_NAME)
+        self.assertTrue(pid.isdigit(), pid)
+        invoke("adb", "forward", "tcp:" + self.APP_PORT, "jdwp:" + pid)
+        # Connect to debugger
+        sock = socket.socket()
+        sock.connect(("localhost", int(self.APP_PORT)))
+        sock.send(self.HANDSHAKE.encode('utf-8'))
+        resp = sock.recv(len(self.HANDSHAKE))
+        self.assertTrue(resp.decode("utf-8") == self.HANDSHAKE)
+        sock.close()
+
+        # Freeze app (adb shell am freeze <APK_NAME>)
+        invoke("adb", "shell", "am", "freeze", self.PROCESS_NAME)
+
+        # Asset that debugger is denied
+        connection_refused = False
+        try:
+            sock = socket.socket()
+            sock.connect(("localhost", int(self.APP_PORT)))
+        except socket.error as e:
+            connection_refused = True
+        self.assertTrue(connection_refused, connection_refused)
+
+        # Unfreeze app (adb shell am unfreeze <APK_NAME>)
+        invoke("adb", "shell", "am", "unfreeze", self.PROCESS_NAME)
+
+        # Assert that debugger is allowed
+        sock = socket.socket()
+        sock.connect(("localhost", int(self.APP_PORT)))
+        sock.send(self.HANDSHAKE.encode("utf-8"))
+        resp = sock.recv(len(self.HANDSHAKE)).decode("utf-8")
+        self.assertTrue(resp == self.HANDSHAKE, resp)
+        sock.close()
+
+    def tearDown(self):
+        invoke("adb", "forward", "--remove-all")
+
 if __name__ == '__main__':
     random.seed(0)
     unittest.main()
diff --git a/tls/Android.bp b/tls/Android.bp
index b45fc8d3..0c8bec62 100644
--- a/tls/Android.bp
+++ b/tls/Android.bp
@@ -65,10 +65,7 @@ cc_library {
     defaults: ["libadb_tls_connection_defaults"],
 
     min_sdk_version: "30",
-    apex_available: [
-        "com.android.adbd",
-        "test_com.android.adbd",
-    ],
+    apex_available: ["com.android.adbd"],
 }
 
 // For running atest (b/147158681)
diff --git a/transport.cpp b/transport.cpp
index 0c51ede6..3c27f0dd 100644
--- a/transport.cpp
+++ b/transport.cpp
@@ -58,6 +58,7 @@
 #if ADB_HOST
 #include <google/protobuf/text_format.h>
 #include "adb_host.pb.h"
+#include "client/detach.h"
 #include "client/usb.h"
 #endif
 
@@ -730,14 +731,6 @@ void update_transports() {
 
 #endif  // ADB_HOST
 
-#if ADB_HOST
-static bool usb_devices_start_detached() {
-    static const char* env = getenv("ADB_LIBUSB_START_DETACHED");
-    static bool result = env && strcmp("1", env) == 0;
-    return is_libusb_enabled() && result;
-}
-#endif
-
 static void fdevent_unregister_transport(atransport* t) {
     VLOG(TRANSPORT) << "unregistering transport: " << t->serial;
 
@@ -762,7 +755,8 @@ static void fdevent_register_transport(atransport* t) {
         t->connection()->SetTransport(t);
 
 #if ADB_HOST
-        if (t->type == kTransportUsb && usb_devices_start_detached()) {
+        if (t->type == kTransportUsb &&
+            attached_devices.ShouldStartDetached(*t->connection().get())) {
             VLOG(TRANSPORT) << "Force-detaching transport:" << t->serial;
             t->SetConnectionState(kCsDetached);
         }
@@ -1089,9 +1083,12 @@ bool atransport::Attach(std::string* error) {
     D("%s: attach", serial.c_str());
     fdevent_check_looper();
 
-    if (!is_libusb_enabled()) {
-        *error = "attach/detach only implemented for libusb backend";
-        return false;
+    {
+        std::lock_guard<std::mutex> lock(mutex_);
+        if (!connection_->SupportsDetach()) {
+            *error = "attach/detach not supported";
+            return false;
+        }
     }
 
     if (GetConnectionState() != ConnectionState::kCsDetached) {
@@ -1116,9 +1113,12 @@ bool atransport::Detach(std::string* error) {
     D("%s: detach", serial.c_str());
     fdevent_check_looper();
 
-    if (!is_libusb_enabled()) {
-        *error = "attach/detach only implemented for libusb backend";
-        return false;
+    {
+        std::lock_guard<std::mutex> lock(mutex_);
+        if (!connection_->SupportsDetach()) {
+            *error = "attach/detach not supported!";
+            return false;
+        }
     }
 
     if (GetConnectionState() == ConnectionState::kCsDetached) {
@@ -1187,8 +1187,8 @@ size_t atransport::get_max_payload() const {
 }
 
 #if ADB_HOST
-static bool delayed_ack_enabled() {
-    static const char* env = getenv("ADB_DELAYED_ACK");
+bool burst_mode_enabled() {
+    static const char* env = getenv("ADB_BURST_MODE");
     static bool result = env && strcmp(env, "1") == 0;
     return result;
 }
@@ -1228,7 +1228,7 @@ const FeatureSet& supported_features() {
         // clang-format on
 
 #if ADB_HOST
-        if (delayed_ack_enabled()) {
+        if (burst_mode_enabled()) {
             result.push_back(kFeatureDelayedAck);
         }
 #else
diff --git a/transport.h b/transport.h
index cb4a6209..ed22da7b 100644
--- a/transport.h
+++ b/transport.h
@@ -124,6 +124,8 @@ struct Connection {
     // Stop, and reset the device if it's a USB connection.
     virtual void Reset();
 
+    virtual bool SupportsDetach() const { return false; }
+
     virtual bool Attach(std::string* error) {
         *error = "transport type doesn't support attach";
         return false;
@@ -535,6 +537,7 @@ void send_packet(apacket* p, atransport* t);
 enum TrackerOutputType { SHORT_TEXT, LONG_TEXT, PROTOBUF, TEXT_PROTOBUF };
 asocket* create_device_tracker(TrackerOutputType type);
 std::string list_transports(TrackerOutputType type);
+bool burst_mode_enabled();
 #endif
 
 #endif /* __TRANSPORT_H */
```

