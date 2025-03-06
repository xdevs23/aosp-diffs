```diff
diff --git a/Android.bp b/Android.bp
index 48a5304d..bcc3b809 100644
--- a/Android.bp
+++ b/Android.bp
@@ -152,16 +152,21 @@ cc_defaults {
         // The platform specific rules for selecting infrastructure link do not apply to Android
         "-DOTBR_ENABLE_VENDOR_INFRA_LINK_SELECT=0",
 
-        // Disable 1.4 features, they are not supported on Android yet.
+        "-DOTBR_ENABLE_TREL=1",
+
+        // For the following 1.4 features, the `OTBR_ENABLE_*` macros are set to 0 because they
+        // only guard code which deals with feature flagging or telemetry. Such code is targeting
+        // other Linux platforms but not Android.
         "-DOTBR_ENABLE_NAT64=0",
         "-DOTBR_ENABLE_DNS_UPSTREAM_QUERY=0",
         "-DOTBR_ENABLE_DHCP6_PD=0",
-        "-DOTBR_ENABLE_TREL=0",
         "-DOTBR_ENABLE_EPSKC=0",
     ],
 
     srcs: [
         "src/agent/application.cpp",
+        "src/android/android_rcp_host.cpp",
+        "src/android/common_utils.cpp",
         "src/android/mdns_publisher.cpp",
         "src/android/otdaemon_server.cpp",
         "src/android/otdaemon_telemetry.cpp",
@@ -184,6 +189,7 @@ cc_defaults {
         "src/ncp/thread_host.cpp",
         "src/sdp_proxy/advertising_proxy.cpp",
         "src/sdp_proxy/discovery_proxy.cpp",
+        "src/trel_dnssd/trel_dnssd.cpp",
         "src/utils/crc16.cpp",
         "src/utils/dns_utils.cpp",
         "src/utils/hex.cpp",
diff --git a/CMakeLists.txt b/CMakeLists.txt
index d31b2096..5a1ee70a 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -108,6 +108,8 @@ if(SYSTEMD_FOUND)
     pkg_get_variable(OTBR_SYSTEMD_UNIT_DIR systemd systemdsystemunitdir)
 endif()
 
+set(OPENTHREAD_PROJECT_DIRECTORY ${PROJECT_SOURCE_DIR}/third_party/openthread/repo)
+set(OTBR_PROJECT_DIRECTORY ${PROJECT_SOURCE_DIR})
 
 add_subdirectory(third_party EXCLUDE_FROM_ALL)
 add_subdirectory(src)
diff --git a/src/agent/CMakeLists.txt b/src/agent/CMakeLists.txt
index 0bec807c..a1e91f0f 100644
--- a/src/agent/CMakeLists.txt
+++ b/src/agent/CMakeLists.txt
@@ -40,12 +40,12 @@ target_link_libraries(otbr-agent PRIVATE
     $<$<BOOL:${OTBR_MDNS}>:otbr-mdns>
     $<$<BOOL:${OTBR_OPENWRT}>:otbr-ubus>
     $<$<BOOL:${OTBR_REST}>:otbr-rest>
-    openthread-posix
     openthread-cli-ftd
     openthread-ftd
     openthread-spinel-rcp
     openthread-radio-spinel
     openthread-hdlc
+    openthread-posix
     otbr-sdp-proxy
     otbr-ncp
     otbr-common
diff --git a/src/agent/application.hpp b/src/agent/application.hpp
index a4a6d3eb..92b44ef1 100644
--- a/src/agent/application.hpp
+++ b/src/agent/application.hpp
@@ -83,7 +83,6 @@ class VendorServer;
 
 /**
  * This class implements OTBR application management.
- *
  */
 class Application : private NonCopyable
 {
@@ -97,7 +96,6 @@ public:
      * @param[in] aEnableAutoAttach      Whether or not to automatically attach to the saved network.
      * @param[in] aRestListenAddress     Network address to listen on.
      * @param[in] aRestListenPort        Network port to listen on.
-     *
      */
     explicit Application(const std::string               &aInterfaceName,
                          const std::vector<const char *> &aBackboneInterfaceNames,
@@ -108,13 +106,11 @@ public:
 
     /**
      * This method initializes the Application instance.
-     *
      */
     void Init(void);
 
     /**
      * This method de-initializes the Application instance.
-     *
      */
     void Deinit(void);
 
@@ -123,7 +119,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE  The application exited without any error.
      * @retval OTBR_ERROR_ERRNO The application exited with some system error.
-     *
      */
     otbrError Run(void);
 
@@ -246,7 +241,6 @@ public:
      * This method handles mDNS publisher's state changes.
      *
      * @param[in] aState  The state of mDNS publisher.
-     *
      */
     void HandleMdnsState(Mdns::Publisher::State aState);
 
diff --git a/src/agent/main.cpp b/src/agent/main.cpp
index e47c9643..80aaec6d 100644
--- a/src/agent/main.cpp
+++ b/src/agent/main.cpp
@@ -55,6 +55,7 @@
 #include "ncp/thread_host.hpp"
 
 #ifdef OTBR_ENABLE_PLATFORM_ANDROID
+#include <log/log.h>
 #ifndef __ANDROID__
 #error "OTBR_ENABLE_PLATFORM_ANDROID can be enabled for only Android devices"
 #endif
@@ -163,16 +164,21 @@ static void OnAllocateFailed(void)
 
 static otbrLogLevel GetDefaultLogLevel(void)
 {
-    otbrLogLevel level = OTBR_LOG_INFO;
-
 #if OTBR_ENABLE_PLATFORM_ANDROID
-    char value[PROPERTY_VALUE_MAX];
+    // The log level is set to DEBUG by default, the final output log will be filtered by Android log system.
+    otbrLogLevel level = OTBR_LOG_DEBUG;
+    char         value[PROPERTY_VALUE_MAX];
+
+    // Set the Android log level to INFO by default.
+    __android_log_set_minimum_priority(ANDROID_LOG_INFO);
 
     property_get("ro.build.type", value, "user");
     if (!strcmp(value, "user"))
     {
         level = OTBR_LOG_WARNING;
     }
+#else
+    otbrLogLevel level = OTBR_LOG_INFO;
 #endif
 
     return level;
diff --git a/src/agent/uris.hpp b/src/agent/uris.hpp
index 9fe79c1a..632fc9f2 100644
--- a/src/agent/uris.hpp
+++ b/src/agent/uris.hpp
@@ -38,7 +38,6 @@ namespace otbr {
 
 /**
  * The URI Path for Address Query.
- *
  */
 #define OT_URI_PATH_ADDRESS_QUERY "a/aq"
 
@@ -46,7 +45,6 @@ namespace otbr {
  * @def OT_URI_PATH_ADDRESS_NOTIFY
  *
  * The URI Path for Address Notify.
- *
  */
 #define OT_URI_PATH_ADDRESS_NOTIFY "a/an"
 
@@ -54,7 +52,6 @@ namespace otbr {
  * @def OT_URI_PATH_ADDRESS_ERROR
  *
  * The URI Path for Address Error.
- *
  */
 #define OT_URI_PATH_ADDRESS_ERROR "a/ae"
 
@@ -62,7 +59,6 @@ namespace otbr {
  * @def OT_URI_PATH_ADDRESS_RELEASE
  *
  * The URI Path for Address Release.
- *
  */
 #define OT_URI_PATH_ADDRESS_RELEASE "a/ar"
 
@@ -70,7 +66,6 @@ namespace otbr {
  * @def OT_URI_PATH_ADDRESS_SOLICIT
  *
  * The URI Path for Address Solicit.
- *
  */
 #define OT_URI_PATH_ADDRESS_SOLICIT "a/as"
 
@@ -78,7 +73,6 @@ namespace otbr {
  * @def OT_URI_PATH_ACTIVE_GET
  *
  * The URI Path for MGMT_ACTIVE_GET
- *
  */
 #define OT_URI_PATH_ACTIVE_GET "c/ag"
 
@@ -86,7 +80,6 @@ namespace otbr {
  * @def OT_URI_PATH_ACTIVE_SET
  *
  * The URI Path for MGMT_ACTIVE_SET
- *
  */
 #define OT_URI_PATH_ACTIVE_SET "c/as"
 
@@ -94,7 +87,6 @@ namespace otbr {
  * @def OT_URI_PATH_DATASET_CHANGED
  *
  * The URI Path for MGMT_DATASET_CHANGED
- *
  */
 #define OT_URI_PATH_DATASET_CHANGED "c/dc"
 
@@ -102,7 +94,6 @@ namespace otbr {
  * @def OT_URI_PATH_ENERGY_SCAN
  *
  * The URI Path for Energy Scan
- *
  */
 #define OT_URI_PATH_ENERGY_SCAN "c/es"
 
@@ -110,7 +101,6 @@ namespace otbr {
  * @def OT_URI_PATH_ENERGY_REPORT
  *
  * The URI Path for Energy Report
- *
  */
 #define OT_URI_PATH_ENERGY_REPORT "c/er"
 
@@ -118,7 +108,6 @@ namespace otbr {
  * @def OT_URI_PATH_PENDING_GET
  *
  * The URI Path for MGMT_PENDING_GET
- *
  */
 #define OT_URI_PATH_PENDING_GET "c/pg"
 
@@ -126,7 +115,6 @@ namespace otbr {
  * @def OT_URI_PATH_PENDING_SET
  *
  * The URI Path for MGMT_PENDING_SET
- *
  */
 #define OT_URI_PATH_PENDING_SET "c/ps"
 
@@ -134,7 +122,6 @@ namespace otbr {
  * @def OT_URI_PATH_SERVER_DATA
  *
  * The URI Path for Server Data Registration.
- *
  */
 #define OT_URI_PATH_SERVER_DATA "a/sd"
 
@@ -142,7 +129,6 @@ namespace otbr {
  * @def OT_URI_PATH_ANNOUNCE_BEGIN
  *
  * The URI Path for Announce Begin.
- *
  */
 #define OT_URI_PATH_ANNOUNCE_BEGIN "c/ab"
 
@@ -150,7 +136,6 @@ namespace otbr {
  * @def OT_URI_PATH_RELAY_RX
  *
  * The URI Path for Relay RX.
- *
  */
 #define OT_URI_PATH_RELAY_RX "c/rx"
 
@@ -158,7 +143,6 @@ namespace otbr {
  * @def OT_URI_PATH_RELAY_TX
  *
  * The URI Path for Relay TX.
- *
  */
 #define OT_URI_PATH_RELAY_TX "c/tx"
 
@@ -166,7 +150,6 @@ namespace otbr {
  * @def OT_URI_PATH_JOINER_FINALIZE
  *
  * The URI Path for Joiner Finalize
- *
  */
 #define OT_URI_PATH_JOINER_FINALIZE "c/jf"
 
@@ -174,7 +157,6 @@ namespace otbr {
  * @def OT_URI_PATH_JOINER_ENTRUST
  *
  * The URI Path for Joiner Entrust
- *
  */
 #define OT_URI_PATH_JOINER_ENTRUST "c/je"
 
@@ -182,7 +164,6 @@ namespace otbr {
  * @def OT_URI_PATH_LEADER_PETITION
  *
  * The URI Path for Leader Petition
- *
  */
 #define OT_URI_PATH_LEADER_PETITION "c/lp"
 
@@ -190,7 +171,6 @@ namespace otbr {
  * @def OT_URI_PATH_LEADER_KEEP_ALIVE
  *
  * The URI Path for Leader Keep Alive
- *
  */
 #define OT_URI_PATH_LEADER_KEEP_ALIVE "c/la"
 
@@ -198,7 +178,6 @@ namespace otbr {
  * @def OT_URI_PATH_PANID_CONFLICT
  *
  * The URI Path for PAN ID Conflict
- *
  */
 #define OT_URI_PATH_PANID_CONFLICT "c/pc"
 
@@ -206,7 +185,6 @@ namespace otbr {
  * @def OT_URI_PATH_PANID_QUERY
  *
  * The URI Path for PAN ID Query
- *
  */
 #define OT_URI_PATH_PANID_QUERY "c/pq"
 
@@ -214,7 +192,6 @@ namespace otbr {
  * @def OT_URI_PATH_COMMISSIONER_GET
  *
  * The URI Path for MGMT_COMMISSIONER_GET
- *
  */
 #define OT_URI_PATH_COMMISSIONER_GET "c/cg"
 
@@ -222,7 +199,6 @@ namespace otbr {
  * @def OT_URI_PATH_COMMISSIONER_SET
  *
  * The URI Path for MGMT_COMMISSIONER_SET
- *
  */
 #define OT_URI_PATH_COMMISSIONER_SET "c/cs"
 
@@ -230,7 +206,6 @@ namespace otbr {
  * @def OT_URI_PATH_COMMISSIONER_PETITION
  *
  * The URI Path for Commissioner Petition.
- *
  */
 #define OT_URI_PATH_COMMISSIONER_PETITION "c/cp"
 
@@ -238,7 +213,6 @@ namespace otbr {
  * @def OT_URI_PATH_COMMISSIONER_KEEP_ALIVE
  *
  * The URI Path for Commissioner Keep Alive.
- *
  */
 #define OT_URI_PATH_COMMISSIONER_KEEP_ALIVE "c/ca"
 
@@ -246,7 +220,6 @@ namespace otbr {
  * @def OT_URI_PATH_DIAGNOSTIC_GET_REQUEST
  *
  * The URI Path for Network Diagnostic Get Request.
- *
  */
 #define OT_URI_PATH_DIAGNOSTIC_GET_REQUEST "d/dg"
 
@@ -254,7 +227,6 @@ namespace otbr {
  * @def OT_URI_PATH_DIAGNOSTIC_GET_QUERY
  *
  * The URI Path for Network Diagnostic Get Query.
- *
  */
 #define OT_URI_PATH_DIAGNOSTIC_GET_QUERY "d/dq"
 
@@ -262,7 +234,6 @@ namespace otbr {
  * @def OT_URI_PATH_DIAGNOSTIC_GET_ANSWER
  *
  * The URI Path for Network Diagnostic Get Answer.
- *
  */
 #define OT_URI_PATH_DIAGNOSTIC_GET_ANSWER "d/da"
 
@@ -270,7 +241,6 @@ namespace otbr {
  * @def OT_URI_PATH_DIAG_RST
  *
  * The URI Path for Network Diagnostic Reset.
- *
  */
 #define OT_URI_PATH_DIAGNOSTIC_RESET "d/dr"
 
diff --git a/src/android/aidl/Android.bp b/src/android/aidl/Android.bp
index bf25b72f..bf205e0f 100644
--- a/src/android/aidl/Android.bp
+++ b/src/android/aidl/Android.bp
@@ -61,6 +61,7 @@ aidl_interface {
     },
     visibility: [
         "//external/ot-br-posix:__subpackages__",
+        "//packages/modules/Connectivity/thread:__subpackages__",
         "//packages/modules/ThreadNetwork/service:__subpackages__",
         "//system/tools/aidl:__subpackages__",
     ],
diff --git a/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl b/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl
index 15478a77..c70d8cf1 100644
--- a/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl
@@ -58,6 +58,13 @@ oneway interface IOtDaemon {
     /** Thread radio is being disabled. */
     const int OT_STATE_DISABLING = 2;
 
+    /** The ephemeral key is disabled. */
+    const int OT_EPHEMERAL_KEY_DISABLED = 0;
+    /** The ephemeral key is enabled. */
+    const int OT_EPHEMERAL_KEY_ENABLED = 1;
+    /** The ephemeral key is in use. */
+    const int OT_EPHEMERAL_KEY_IN_USE = 2;
+
     enum ErrorCode {
         // Converts to ThreadNetworkException#ERROR_FAILED_PRECONDITION
         OT_ERROR_FAILED_PRECONDITION = -3,
@@ -87,19 +94,22 @@ oneway interface IOtDaemon {
      *
      * <p>This API MUST be called before all other APIs of this interface.
      *
+     * @param enabled the Thead enabled state from Persistent Settings
+     * @param configuration the Thread configuration from Persistent Settings
      * @param tunFd the Thread tunnel interface FD which can be used to transmit/receive
      *              packets to/from Thread PAN
-     * @param enabled the Thead enabled state from Persistent Settings
      * @param nsdPublisher the INsdPublisher which can be used for mDNS advertisement/discovery
      *                     on AIL by {@link NsdManager}
      * @param meshcopTxts the MeshCoP TXT values set by the system_server to override the default
      *                    ones
-     * @param callback the callback for receiving OtDaemonState changes
      * @param countryCode 2 bytes country code (as defined in ISO 3166) to set
+     * @param trelEnabled the TREL enabled state
+     * @param callback the callback for receiving OtDaemonState changes
      */
-    void initialize(in ParcelFileDescriptor tunFd, in boolean enabled,
-            in INsdPublisher nsdPublisher, in MeshcopTxtAttributes meshcopTxts,
-            in IOtDaemonCallback callback, in String countryCode);
+    void initialize(boolean enabled, in OtDaemonConfiguration configuration,
+            in ParcelFileDescriptor tunFd, in INsdPublisher nsdPublisher,
+            in MeshcopTxtAttributes meshcopTxts, in String countryCode, in boolean trelEnabled,
+            in IOtDaemonCallback callback);
 
     /** Terminates the ot-daemon process. */
     void terminate();
@@ -141,11 +151,12 @@ oneway interface IOtDaemon {
      *    the {@code receiver} will be invoked after the previous request is completed
      * 3. Otherwise, OTBR sends Address Release Notification (i.e. ADDR_REL.ntf) to gracefully
      *    detach from the current network and it takes 1 second to finish
-     * 4. The Operational Dataset will be removed from persistent storage
+     * 4. The Operational Dataset will be removed from persistent storage if {@code eraseDataset}
+     *    is {@code true}
      *
      * @sa android.net.thread.ThreadNetworkController#leave
      */
-    void leave(in IOtStatusReceiver receiver);
+    void leave(boolean eraseDataset, in IOtStatusReceiver receiver);
 
     /**
      * Migrates to the new network specified by {@code pendingOpDatasetTlvs}.
@@ -160,7 +171,7 @@ oneway interface IOtDaemon {
      * @param countryCode 2 bytes country code (as defined in ISO 3166) to set.
      * @param receiver the receiver to receive result of this operation
      */
-    oneway void setCountryCode(in String countryCode, in IOtStatusReceiver receiver);
+    void setCountryCode(in String countryCode, in IOtStatusReceiver receiver);
 
     /**
      * Sets the configuration at ot-daemon.
@@ -169,7 +180,7 @@ oneway interface IOtDaemon {
      * @param receiver the status receiver
      *
      */
-    oneway void setConfiguration(in OtDaemonConfiguration config, in IOtStatusReceiver receiver);
+    void setConfiguration(in OtDaemonConfiguration config, in IOtStatusReceiver receiver);
 
     /**
      * Sets the infrastructure network interface.
@@ -179,7 +190,7 @@ oneway interface IOtDaemon {
      * @param receiver the status receiver
      *
      */
-    oneway void setInfraLinkInterfaceName(in @nullable String interfaceName,
+    void setInfraLinkInterfaceName(in @nullable String interfaceName,
             in ParcelFileDescriptor icmp6Socket, in IOtStatusReceiver receiver);
 
     /**
@@ -189,9 +200,27 @@ oneway interface IOtDaemon {
      * @param receiver the status receiver
      *
      */
-    oneway void setInfraLinkNat64Prefix(
+    void setInfraLinkNat64Prefix(
             in @nullable String nat64Prefix, in IOtStatusReceiver receiver);
 
+    /**
+     * Sets the NAT64 CIDR.
+     *
+     * @param nat64Cidr the NAT64 CIDR
+     * @param receiver the status receiver
+     *
+     */
+    void setNat64Cidr(in @nullable String nat64Cidr, in IOtStatusReceiver receiver);
+
+    /**
+     * Sets the infrastructure link DNS servers.
+     *
+     * @param dnsServers the DNS server IP addresses represented by strings
+     * @param receiver the status receiver
+     *
+     */
+    void setInfraLinkDnsServers(in List<String> dnsServers, in IOtStatusReceiver receiver);
+
     /**
      * Gets the supported and preferred channel masks.
      *
@@ -215,8 +244,26 @@ oneway interface IOtDaemon {
      * @param isInteractive indicates whether to run command in interactive mode
      * @param receiver the callback interface to receive the command's output
      */
-    oneway void runOtCtlCommand(
+    void runOtCtlCommand(
             in String command, in boolean isInteractive, in IOtOutputReceiver receiver);
 
+    /**
+     * Activates the ephemeral key mode.
+     *
+     * @param lifetimeMillis the lifetime of the ephemeral key in milliseconds
+     * @param receiver the status receiver
+     */
+    void activateEphemeralKeyMode(in long lifetimeMillis, in IOtStatusReceiver receiver);
+
+    /**
+     * Deactivates the ephemeral key mode.
+     *
+     * This will always succeed. If there are active secure sessions with the ephemeral key, the
+     * sessions will be terminated.
+     *
+     * @param receiver the status receiver
+     */
+    void deactivateEphemeralKeyMode(in IOtStatusReceiver receiver);
+
     // TODO: add Border Router APIs
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl b/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl
index c3eacd2d..2e81c57e 100644
--- a/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl
@@ -34,4 +34,5 @@ package com.android.server.thread.openthread;
 parcelable InfraLinkState {
     @nullable String interfaceName; // The name of infra network interface.
     @nullable String nat64Prefix; // The NAT64 prefix.
+    List<String> dnsServers; // The DNS server IP addresses represented by strings.
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl b/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
index 67cc6921..24a94917 100644
--- a/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
@@ -28,7 +28,13 @@
 
 package com.android.server.thread.openthread;
 
-/** The ot-daemon configuration. */
+/** An internal mirror of {@link android.net.thread.ThreadConfiguration}. */
 @JavaOnlyImmutable
 @JavaDerive(equals=true, toString=true)
-parcelable OtDaemonConfiguration {}
+parcelable OtDaemonConfiguration {
+    // Follow the default value in {@link android.net.thread.ThreadConfiguration}.
+    boolean borderRouterEnabled = true;
+
+    boolean nat64Enabled;
+    boolean dhcpv6PdEnabled;
+}
diff --git a/src/android/aidl/com/android/server/thread/openthread/OtDaemonState.aidl b/src/android/aidl/com/android/server/thread/openthread/OtDaemonState.aidl
index b96baaa5..0bc67c08 100644
--- a/src/android/aidl/com/android/server/thread/openthread/OtDaemonState.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/OtDaemonState.aidl
@@ -51,4 +51,16 @@ parcelable OtDaemonState {
 
     // The Thread enabled state OT_STATE_DISABLED, OT_STATE_ENABLED and OT_STATE_DISABLING.
     int threadEnabled;
+
+    // The ephemeral key state EPHEMERAL_KEY_DISABLED, EPHEMERAL_KEY_ENABLED, EPHEMERAL_KEY_IN_USE
+    // defined in {@link ThreadNetworkController}.
+    int ephemeralKeyState;
+
+    // The ephemeral key passcode string, valid when ephemeralKeyState is not
+    // EPHEMERAL_KEY_DISABLED.
+    String ephemeralKeyPasscode;
+
+    // The ephemeral key lifetime in milliseconds, or 0 when ephemeralKeyState is
+    // EPHEMERAL_KEY_DISABLED.
+    long ephemeralKeyLifetimeMillis;
 }
diff --git a/src/android/android_rcp_host.cpp b/src/android/android_rcp_host.cpp
new file mode 100644
index 00000000..79326d30
--- /dev/null
+++ b/src/android/android_rcp_host.cpp
@@ -0,0 +1,413 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#define OTBR_LOG_TAG "ARCP_HOST"
+
+#include "android_rcp_host.hpp"
+
+#include <net/if.h>
+#include <vector>
+
+#include <android-base/file.h>
+#include <android-base/stringprintf.h>
+#include <openthread/backbone_router_ftd.h>
+#include <openthread/border_routing.h>
+#include <openthread/dnssd_server.h>
+#include <openthread/ip6.h>
+#include <openthread/nat64.h>
+#include <openthread/openthread-system.h>
+#include <openthread/srp_server.h>
+#include <openthread/thread.h>
+#include <openthread/trel.h>
+#include <openthread/platform/infra_if.h>
+#include <openthread/platform/trel.h>
+
+#include "android/common_utils.hpp"
+#include "common/code_utils.hpp"
+
+namespace otbr {
+namespace Android {
+
+AndroidRcpHost *AndroidRcpHost::sAndroidRcpHost = nullptr;
+
+AndroidRcpHost::AndroidRcpHost(Ncp::RcpHost &aRcpHost)
+    : mRcpHost(aRcpHost)
+    , mConfiguration()
+    , mInfraIcmp6Socket(-1)
+{
+    mInfraLinkState.interfaceName = "";
+
+    sAndroidRcpHost = this;
+}
+
+void AndroidRcpHost::SetConfiguration(const OtDaemonConfiguration              &aConfiguration,
+                                      const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    otError          error = OT_ERROR_NONE;
+    std::string      message;
+    otLinkModeConfig linkModeConfig;
+
+    otbrLogInfo("Set configuration: %s", aConfiguration.toString().c_str());
+
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+    VerifyOrExit(aConfiguration != mConfiguration);
+
+    // TODO: b/343814054 - Support enabling/disabling DHCPv6-PD.
+    VerifyOrExit(!aConfiguration.dhcpv6PdEnabled, error = OT_ERROR_NOT_IMPLEMENTED,
+                 message = "DHCPv6-PD is not supported");
+    otNat64SetEnabled(GetOtInstance(), aConfiguration.nat64Enabled);
+    // DNS upstream query is enabled if and only if NAT64 is enabled.
+    otDnssdUpstreamQuerySetEnabled(GetOtInstance(), aConfiguration.nat64Enabled);
+
+    linkModeConfig = GetLinkModeConfig(aConfiguration.borderRouterEnabled);
+    SuccessOrExit(error = otThreadSetLinkMode(GetOtInstance(), linkModeConfig), message = "Failed to set link mode");
+    if (aConfiguration.borderRouterEnabled)
+    {
+        otSrpServerSetAutoEnableMode(GetOtInstance(), true);
+        SetBorderRouterEnabled(true);
+    }
+    else
+    {
+        // This automatically disables the auto-enable mode which is designed for border router
+        otSrpServerSetEnabled(GetOtInstance(), true);
+
+        SetBorderRouterEnabled(false);
+    }
+
+    mConfiguration = aConfiguration;
+
+exit:
+    PropagateResult(error, message, aReceiver);
+}
+
+void AndroidRcpHost::SetInfraLinkInterfaceName(const std::string                        &aInterfaceName,
+                                               int                                       aIcmp6Socket,
+                                               const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    otError           error = OT_ERROR_NONE;
+    std::string       message;
+    const std::string infraIfName  = aInterfaceName;
+    unsigned int      infraIfIndex = if_nametoindex(infraIfName.c_str());
+
+    otbrLogInfo("Setting infra link state: %s", aInterfaceName.c_str());
+
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+    VerifyOrExit(mConfiguration.borderRouterEnabled, error = OT_ERROR_INVALID_STATE,
+                 message = "Set infra link state when border router is disabled");
+    VerifyOrExit(mInfraLinkState.interfaceName != aInterfaceName || aIcmp6Socket != mInfraIcmp6Socket);
+
+    if (infraIfIndex != 0 && aIcmp6Socket > 0)
+    {
+        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
+                      message = "failed to disable border routing");
+        otSysSetInfraNetif(infraIfName.c_str(), aIcmp6Socket);
+        aIcmp6Socket = -1;
+        SuccessOrExit(error   = otBorderRoutingInit(GetOtInstance(), infraIfIndex, otSysInfraIfIsRunning()),
+                      message = "failed to initialize border routing");
+        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), true /* aEnabled */),
+                      message = "failed to enable border routing");
+        // TODO: b/320836258 - Make BBR independently configurable
+        otBackboneRouterSetEnabled(GetOtInstance(), true /* aEnabled */);
+    }
+    else
+    {
+        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
+                      message = "failed to disable border routing");
+        otBackboneRouterSetEnabled(GetOtInstance(), false /* aEnabled */);
+    }
+
+    mInfraLinkState.interfaceName = aInterfaceName;
+    mInfraIcmp6Socket             = aIcmp6Socket;
+
+    SetTrelEnabled(mTrelEnabled);
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        close(aIcmp6Socket);
+    }
+    PropagateResult(error, message, aReceiver);
+}
+
+void AndroidRcpHost::SetTrelEnabled(bool aEnabled)
+{
+    mTrelEnabled = aEnabled;
+
+    otbrLogInfo("%s TREL", aEnabled ? "Enabling" : "Disabling");
+
+    // Tear down TREL if it's been initialized/enabled already.
+    otTrelSetEnabled(GetOtInstance(), false);
+    otSysTrelDeinit();
+
+    if (mTrelEnabled && mInfraLinkState.interfaceName != "")
+    {
+        otSysTrelInit(mInfraLinkState.interfaceName.value_or("").c_str());
+        otTrelSetEnabled(GetOtInstance(), true);
+    }
+}
+
+void AndroidRcpHost::SetInfraLinkNat64Prefix(const std::string                        &aNat64Prefix,
+                                             const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    otError     error = OT_ERROR_NONE;
+    std::string message;
+
+    otbrLogInfo("Setting infra link NAT64 prefix: %s", aNat64Prefix.c_str());
+
+    VerifyOrExit(mRcpHost.GetInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+
+    mInfraLinkState.nat64Prefix = aNat64Prefix;
+    NotifyNat64PrefixDiscoveryDone();
+
+exit:
+    PropagateResult(error, message, aReceiver);
+}
+
+void AndroidRcpHost::RunOtCtlCommand(const std::string                        &aCommand,
+                                     const bool                                aIsInteractive,
+                                     const std::shared_ptr<IOtOutputReceiver> &aReceiver)
+{
+    otSysCliInitUsingDaemon(GetOtInstance());
+
+    if (!aCommand.empty())
+    {
+        std::string command = aCommand;
+
+        mIsOtCtlInteractiveMode = aIsInteractive;
+        mOtCtlOutputReceiver    = aReceiver;
+
+        otCliInit(GetOtInstance(), AndroidRcpHost::OtCtlCommandCallback, this);
+        otCliInputLine(command.data());
+    }
+}
+
+int AndroidRcpHost::OtCtlCommandCallback(void *aBinderServer, const char *aFormat, va_list aArguments)
+{
+    return static_cast<AndroidRcpHost *>(aBinderServer)->OtCtlCommandCallback(aFormat, aArguments);
+}
+
+int AndroidRcpHost::OtCtlCommandCallback(const char *aFormat, va_list aArguments)
+{
+    static const std::string kPrompt = "> ";
+    std::string              output;
+
+    VerifyOrExit(mOtCtlOutputReceiver != nullptr, otSysCliInitUsingDaemon(GetOtInstance()));
+
+    android::base::StringAppendV(&output, aFormat, aArguments);
+
+    // Ignore CLI prompt
+    VerifyOrExit(output != kPrompt);
+
+    mOtCtlOutputReceiver->onOutput(output);
+
+    // Check if the command has completed (indicated by "Done" or "Error")
+    if (output.starts_with("Done") || output.starts_with("Error"))
+    {
+        mIsOtCtlOutputComplete = true;
+    }
+
+    // The OpenThread CLI consistently outputs "\r\n" as a newline character. Therefore, we use the presence of "\r\n"
+    // following "Done" or "Error" to signal the completion of a command's output.
+    if (mIsOtCtlOutputComplete && output.ends_with("\r\n"))
+    {
+        if (!mIsOtCtlInteractiveMode)
+        {
+            otSysCliInitUsingDaemon(GetOtInstance());
+        }
+        mIsOtCtlOutputComplete = false;
+        mOtCtlOutputReceiver->onComplete();
+    }
+
+exit:
+    return output.length();
+}
+
+static int OutputCallback(void *aContext, const char *aFormat, va_list aArguments)
+{
+    std::string output;
+
+    android::base::StringAppendV(&output, aFormat, aArguments);
+
+    int length = output.length();
+
+    VerifyOrExit(android::base::WriteStringToFd(output, *(static_cast<int *>(aContext))), length = 0);
+
+exit:
+    return length;
+}
+
+inline void DumpCliCommand(std::string aCommand, int aFd)
+{
+    android::base::WriteStringToFd(aCommand + '\n', aFd);
+    otCliInputLine(aCommand.data());
+}
+
+binder_status_t AndroidRcpHost::Dump(int aFd, const char **aArgs, uint32_t aNumArgs)
+{
+    OT_UNUSED_VARIABLE(aArgs);
+    OT_UNUSED_VARIABLE(aNumArgs);
+
+    otCliInit(GetOtInstance(), OutputCallback, &aFd);
+
+    DumpCliCommand("state", aFd);
+    DumpCliCommand("srp server state", aFd);
+    DumpCliCommand("srp server service", aFd);
+    DumpCliCommand("srp server host", aFd);
+    DumpCliCommand("dataset activetimestamp", aFd);
+    DumpCliCommand("dataset channel", aFd);
+    DumpCliCommand("dataset channelmask", aFd);
+    DumpCliCommand("dataset extpanid", aFd);
+    DumpCliCommand("dataset meshlocalprefix", aFd);
+    DumpCliCommand("dataset networkname", aFd);
+    DumpCliCommand("dataset panid", aFd);
+    DumpCliCommand("dataset securitypolicy", aFd);
+    DumpCliCommand("leaderdata", aFd);
+    DumpCliCommand("eidcache", aFd);
+    DumpCliCommand("counters mac", aFd);
+    DumpCliCommand("counters mle", aFd);
+    DumpCliCommand("counters ip", aFd);
+    DumpCliCommand("router table", aFd);
+    DumpCliCommand("neighbor table", aFd);
+    DumpCliCommand("ipaddr -v", aFd);
+    DumpCliCommand("netdata show", aFd);
+
+    fsync(aFd);
+
+    otSysCliInitUsingDaemon(GetOtInstance());
+
+    return STATUS_OK;
+}
+
+std::vector<otIp6Address> ToOtUpstreamDnsServerAddresses(const std::vector<std::string> &aAddresses)
+{
+    std::vector<otIp6Address> addresses;
+
+    // TODO: b/363738575 - support IPv6
+    for (const auto &addressString : aAddresses)
+    {
+        otIp6Address ip6Address;
+        otIp4Address ip4Address;
+
+        if (otIp4AddressFromString(addressString.c_str(), &ip4Address) != OT_ERROR_NONE)
+        {
+            continue;
+        }
+        otIp4ToIp4MappedIp6Address(&ip4Address, &ip6Address);
+        addresses.push_back(ip6Address);
+    }
+
+    return addresses;
+}
+
+void AndroidRcpHost::SetInfraLinkDnsServers(const std::vector<std::string>           &aDnsServers,
+                                            const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    otError     error = OT_ERROR_NONE;
+    std::string message;
+    auto        dnsServers = ToOtUpstreamDnsServerAddresses(aDnsServers);
+
+    otbrLogInfo("Setting infra link DNS servers: %d servers", aDnsServers.size());
+
+    VerifyOrExit(aDnsServers != mInfraLinkState.dnsServers);
+
+    mInfraLinkState.dnsServers = aDnsServers;
+    otSysUpstreamDnsSetServerList(dnsServers.data(), dnsServers.size());
+
+exit:
+    PropagateResult(error, message, aReceiver);
+}
+
+void AndroidRcpHost::NotifyNat64PrefixDiscoveryDone(void)
+{
+    otIp6Prefix nat64Prefix{};
+    uint32_t    infraIfIndex = if_nametoindex(mInfraLinkState.interfaceName.value_or("").c_str());
+
+    otIp6PrefixFromString(mInfraLinkState.nat64Prefix.value_or("").c_str(), &nat64Prefix);
+    otPlatInfraIfDiscoverNat64PrefixDone(GetOtInstance(), infraIfIndex, &nat64Prefix);
+}
+
+otInstance *AndroidRcpHost::GetOtInstance(void)
+{
+    return mRcpHost.GetInstance();
+}
+
+otLinkModeConfig AndroidRcpHost::GetLinkModeConfig(bool aIsRouter)
+{
+    otLinkModeConfig linkModeConfig{};
+
+    if (aIsRouter)
+    {
+        linkModeConfig.mRxOnWhenIdle = true;
+        linkModeConfig.mDeviceType   = true;
+        linkModeConfig.mNetworkData  = true;
+    }
+    else
+    {
+        linkModeConfig.mRxOnWhenIdle = false;
+        linkModeConfig.mDeviceType   = false;
+        linkModeConfig.mNetworkData  = true;
+    }
+
+    return linkModeConfig;
+}
+
+void AndroidRcpHost::SetBorderRouterEnabled(bool aEnabled)
+{
+    otError error;
+
+    error = otBorderRoutingSetEnabled(GetOtInstance(), aEnabled);
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to %s Border Routing: %s", (aEnabled ? "enable" : "disable"),
+                       otThreadErrorToString(error));
+        ExitNow();
+    }
+
+    otBackboneRouterSetEnabled(GetOtInstance(), aEnabled);
+
+exit:
+    return;
+}
+
+extern "C" otError otPlatInfraIfDiscoverNat64Prefix(uint32_t aInfraIfIndex)
+{
+    OT_UNUSED_VARIABLE(aInfraIfIndex);
+
+    AndroidRcpHost *androidRcpHost = AndroidRcpHost::Get();
+    otError         error          = OT_ERROR_NONE;
+
+    VerifyOrExit(androidRcpHost != nullptr, error = OT_ERROR_INVALID_STATE);
+
+    androidRcpHost->NotifyNat64PrefixDiscoveryDone();
+
+exit:
+    return error;
+}
+
+} // namespace Android
+} // namespace otbr
diff --git a/src/android/android_rcp_host.hpp b/src/android/android_rcp_host.hpp
new file mode 100644
index 00000000..39fa12d9
--- /dev/null
+++ b/src/android/android_rcp_host.hpp
@@ -0,0 +1,91 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#ifndef OTBR_ANDROID_RCP_HOST_HPP_
+#define OTBR_ANDROID_RCP_HOST_HPP_
+
+#include "android_thread_host.hpp"
+
+#include <memory>
+
+#include "common_utils.hpp"
+#include "ncp/rcp_host.hpp"
+
+namespace otbr {
+namespace Android {
+
+class AndroidRcpHost : public AndroidThreadHost
+{
+public:
+    AndroidRcpHost(Ncp::RcpHost &aRcpHost);
+    ~AndroidRcpHost(void) = default;
+
+    void                         SetConfiguration(const OtDaemonConfiguration              &aConfiguration,
+                                                  const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    const OtDaemonConfiguration &GetConfiguration(void) override { return mConfiguration; }
+    void                         SetInfraLinkInterfaceName(const std::string                        &aInterfaceName,
+                                                           int                                       aIcmp6Socket,
+                                                           const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void                         SetInfraLinkNat64Prefix(const std::string                        &aNat64Prefix,
+                                                         const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void                         SetInfraLinkDnsServers(const std::vector<std::string>           &aDnsServers,
+                                                        const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void                         SetTrelEnabled(bool aEnabled) override;
+    void                         RunOtCtlCommand(const std::string                        &aCommand,
+                                                 const bool                                aIsInteractive,
+                                                 const std::shared_ptr<IOtOutputReceiver> &aReceiver) override;
+    binder_status_t              Dump(int aFd, const char **aArgs, uint32_t aNumArgs) override;
+
+    void                   NotifyNat64PrefixDiscoveryDone(void);
+    static AndroidRcpHost *Get(void) { return sAndroidRcpHost; }
+
+private:
+    otInstance *GetOtInstance(void);
+
+    static otLinkModeConfig GetLinkModeConfig(bool aBeRouter);
+    void                    SetBorderRouterEnabled(bool aEnabled);
+    static int              OtCtlCommandCallback(void *aBinderServer, const char *aFormat, va_list aArguments);
+    int                     OtCtlCommandCallback(const char *aFormat, va_list aArguments);
+
+    static AndroidRcpHost *sAndroidRcpHost;
+
+    Ncp::RcpHost         &mRcpHost;
+    OtDaemonConfiguration mConfiguration;
+    InfraLinkState        mInfraLinkState;
+    int                   mInfraIcmp6Socket;
+    bool                  mTrelEnabled;
+
+    bool                               mIsOtCtlInteractiveMode;
+    bool                               mIsOtCtlOutputComplete;
+    std::shared_ptr<IOtOutputReceiver> mOtCtlOutputReceiver;
+};
+
+} // namespace Android
+} // namespace otbr
+
+#endif // OTBR_ANDROID_RCP_HOST_HPP_
diff --git a/src/android/android_thread_host.hpp b/src/android/android_thread_host.hpp
new file mode 100644
index 00000000..b08679c4
--- /dev/null
+++ b/src/android/android_thread_host.hpp
@@ -0,0 +1,64 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#ifndef OTBR_ANDROID_THREAD_HOST_HPP_
+#define OTBR_ANDROID_THREAD_HOST_HPP_
+
+#include <memory>
+
+#include "common_utils.hpp"
+
+namespace otbr {
+namespace Android {
+
+class AndroidThreadHost
+{
+public:
+    virtual ~AndroidThreadHost(void) = default;
+
+    virtual void                         SetConfiguration(const OtDaemonConfiguration              &aConfiguration,
+                                                          const std::shared_ptr<IOtStatusReceiver> &aReceiver) = 0;
+    virtual const OtDaemonConfiguration &GetConfiguration(void)                                                = 0;
+    virtual void                         SetInfraLinkInterfaceName(const std::string                        &aInterfaceName,
+                                                                   int                                       aIcmp6Socket,
+                                                                   const std::shared_ptr<IOtStatusReceiver> &aReceiver) = 0;
+    virtual void                         SetInfraLinkNat64Prefix(const std::string                        &aNat64Prefix,
+                                                                 const std::shared_ptr<IOtStatusReceiver> &aReceiver) = 0;
+    virtual void                         SetInfraLinkDnsServers(const std::vector<std::string>           &aDnsServers,
+                                                                const std::shared_ptr<IOtStatusReceiver> &aReceiver) = 0;
+    virtual void                         SetTrelEnabled(bool aEnabled)                                        = 0;
+    virtual void                         RunOtCtlCommand(const std::string                        &aCommand,
+                                                         const bool                                aIsInteractive,
+                                                         const std::shared_ptr<IOtOutputReceiver> &aReceiver) = 0;
+    virtual binder_status_t              Dump(int aFd, const char **aArgs, uint32_t aNumArgs)                 = 0;
+};
+
+} // namespace Android
+} // namespace otbr
+
+#endif // OTBR_ANDROID_THREAD_HOST_HPP_
diff --git a/src/android/common_utils.cpp b/src/android/common_utils.cpp
new file mode 100644
index 00000000..abb2e7a1
--- /dev/null
+++ b/src/android/common_utils.cpp
@@ -0,0 +1,56 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include "android/common_utils.hpp"
+
+#include <memory>
+#include <string>
+
+#include <openthread/error.h>
+
+namespace otbr {
+namespace Android {
+
+void PropagateResult(int aError, const std::string &aMessage, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    if (aReceiver != nullptr)
+    {
+        // If an operation has already been requested or accepted, consider it succeeded
+        if (aError == OT_ERROR_NONE || aError == OT_ERROR_ALREADY)
+        {
+            aReceiver->onSuccess();
+        }
+        else
+        {
+            aReceiver->onError(aError, aMessage);
+        }
+    }
+}
+
+} // namespace Android
+} // namespace otbr
diff --git a/src/android/common_utils.hpp b/src/android/common_utils.hpp
new file mode 100644
index 00000000..c792911a
--- /dev/null
+++ b/src/android/common_utils.hpp
@@ -0,0 +1,64 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#ifndef COMMON_UTILS_HPP_
+#define COMMON_UTILS_HPP_
+
+#include <aidl/com/android/server/thread/openthread/BnOtDaemon.h>
+#include <aidl/com/android/server/thread/openthread/INsdPublisher.h>
+#include <aidl/com/android/server/thread/openthread/IOtDaemon.h>
+#include <aidl/com/android/server/thread/openthread/InfraLinkState.h>
+
+namespace otbr {
+namespace Android {
+
+using BinderDeathRecipient = ::ndk::ScopedAIBinder_DeathRecipient;
+using ScopedFileDescriptor = ::ndk::ScopedFileDescriptor;
+using Status               = ::ndk::ScopedAStatus;
+using aidl::android::net::thread::ChannelMaxPower;
+using aidl::com::android::server::thread::openthread::BackboneRouterState;
+using aidl::com::android::server::thread::openthread::BnOtDaemon;
+using aidl::com::android::server::thread::openthread::IChannelMasksReceiver;
+using aidl::com::android::server::thread::openthread::InfraLinkState;
+using aidl::com::android::server::thread::openthread::INsdPublisher;
+using aidl::com::android::server::thread::openthread::IOtDaemon;
+using aidl::com::android::server::thread::openthread::IOtDaemonCallback;
+using aidl::com::android::server::thread::openthread::IOtOutputReceiver;
+using aidl::com::android::server::thread::openthread::IOtStatusReceiver;
+using aidl::com::android::server::thread::openthread::Ipv6AddressInfo;
+using aidl::com::android::server::thread::openthread::MeshcopTxtAttributes;
+using aidl::com::android::server::thread::openthread::OnMeshPrefixConfig;
+using aidl::com::android::server::thread::openthread::OtDaemonConfiguration;
+using aidl::com::android::server::thread::openthread::OtDaemonState;
+
+void PropagateResult(int aError, const std::string &aMessage, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+
+} // namespace Android
+} // namespace otbr
+
+#endif // COMMON_UTILS_HPP_
diff --git a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
index c87f94ba..4d1ce177 100644
--- a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
+++ b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
@@ -28,6 +28,9 @@
 
 package com.android.server.thread.openthread.testing;
 
+import static com.android.server.thread.openthread.IOtDaemon.ErrorCode.OT_ERROR_NOT_IMPLEMENTED;
+import static com.android.server.thread.openthread.IOtDaemon.OT_EPHEMERAL_KEY_DISABLED;
+import static com.android.server.thread.openthread.IOtDaemon.OT_EPHEMERAL_KEY_ENABLED;
 import static com.android.server.thread.openthread.IOtDaemon.OT_STATE_DISABLED;
 import static com.android.server.thread.openthread.IOtDaemon.OT_STATE_ENABLED;
 
@@ -77,6 +80,7 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     private int mChannelMasksReceiverOtError = OT_ERROR_NONE;
     private int mSupportedChannelMask = 0x07FFF800; // from channel 11 to 26
     private int mPreferredChannelMask = 0;
+    private boolean mTrelEnabled = false;
 
     @Nullable private DeathRecipient mDeathRecipient;
     @Nullable private ParcelFileDescriptor mTunFd;
@@ -85,8 +89,10 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     @Nullable private IOtDaemonCallback mCallback;
     @Nullable private Long mCallbackListenerId;
     @Nullable private RemoteException mJoinException;
+    @Nullable private RemoteException mSetNat64CidrException;
     @Nullable private RemoteException mRunOtCtlCommandException;
     @Nullable private String mCountryCode;
+    @Nullable private OtDaemonConfiguration mConfiguration;
 
     public FakeOtDaemon(Handler handler) {
         mHandler = handler;
@@ -101,9 +107,13 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
         mState.activeDatasetTlvs = new byte[0];
         mState.pendingDatasetTlvs = new byte[0];
         mState.threadEnabled = OT_STATE_DISABLED;
+        mState.ephemeralKeyState = OT_EPHEMERAL_KEY_DISABLED;
+        mState.ephemeralKeyPasscode = "";
+        mState.ephemeralKeyLifetimeMillis = 0;
         mBbrState = new BackboneRouterState();
         mBbrState.multicastForwardingEnabled = false;
         mBbrState.listeningAddresses = new ArrayList<>();
+        mConfiguration = null;
 
         mTunFd = null;
         mNsdPublisher = null;
@@ -144,18 +154,23 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
 
     @Override
     public void initialize(
-            ParcelFileDescriptor tunFd,
             boolean enabled,
+            OtDaemonConfiguration config,
+            ParcelFileDescriptor tunFd,
             INsdPublisher nsdPublisher,
             MeshcopTxtAttributes overriddenMeshcopTxts,
-            IOtDaemonCallback callback,
-            String countryCode)
+            String countryCode,
+            boolean trelEnabled,
+            IOtDaemonCallback callback)
             throws RemoteException {
         mIsInitialized = true;
-        mTunFd = tunFd;
+
         mState.threadEnabled = enabled ? OT_STATE_ENABLED : OT_STATE_DISABLED;
+        setConfiguration(config, null /* receiver */);
+        mTunFd = tunFd;
         mNsdPublisher = nsdPublisher;
         mCountryCode = countryCode;
+        mTrelEnabled = trelEnabled;
 
         mOverriddenMeshcopTxts = new MeshcopTxtAttributes();
         mOverriddenMeshcopTxts.vendorOui = overriddenMeshcopTxts.vendorOui.clone();
@@ -295,6 +310,36 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
                 JOIN_DELAY.toMillis());
     }
 
+    @Override
+    public void activateEphemeralKeyMode(long lifetimeMillis, IOtStatusReceiver receiver) {
+        mHandler.post(
+                () -> {
+                    mState.ephemeralKeyState = OT_EPHEMERAL_KEY_ENABLED;
+                    mState.ephemeralKeyPasscode = "123456789";
+                    mState.ephemeralKeyLifetimeMillis = lifetimeMillis;
+                    try {
+                        receiver.onSuccess();
+                    } catch (RemoteException e) {
+                        throw new AssertionError(e);
+                    }
+                });
+    }
+
+    @Override
+    public void deactivateEphemeralKeyMode(IOtStatusReceiver receiver) {
+        mHandler.post(
+                () -> {
+                    mState.ephemeralKeyState = OT_EPHEMERAL_KEY_DISABLED;
+                    mState.ephemeralKeyPasscode = "";
+                    mState.ephemeralKeyLifetimeMillis = 0;
+                    try {
+                        receiver.onSuccess();
+                    } catch (RemoteException e) {
+                        throw new AssertionError(e);
+                    }
+                });
+    }
+
     private OtDaemonState makeCopy(OtDaemonState state) {
         OtDaemonState copyState = new OtDaemonState();
         copyState.isInterfaceUp = state.isInterfaceUp;
@@ -340,15 +385,22 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     }
 
     @Override
-    public void leave(IOtStatusReceiver receiver) throws RemoteException {
+    public void leave(boolean eraseDataset, IOtStatusReceiver receiver) throws RemoteException {
         throw new UnsupportedOperationException("FakeOtDaemon#leave is not implemented!");
     }
 
     @Override
     public void setConfiguration(OtDaemonConfiguration config, IOtStatusReceiver receiver)
             throws RemoteException {
-        throw new UnsupportedOperationException(
-                "FakeOtDaemon#setConfiguration is not implemented!");
+        mConfiguration = config;
+        // TODO: b/343814054 - Support enabling/disabling DHCPv6-PD.
+        if (mConfiguration.dhcpv6PdEnabled) {
+            receiver.onError(OT_ERROR_NOT_IMPLEMENTED, "DHCPv6-PD is not supported");
+            return;
+        }
+        if (receiver != null) {
+            receiver.onSuccess();
+        }
     }
 
     @Override
@@ -366,6 +418,28 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
                 "FakeOtDaemon#setInfraLinkNat64Prefix is not implemented!");
     }
 
+    /** Sets the {@link RemoteException} which will be thrown from {@link #setNat64Cidr}. */
+    public void setSetNat64CidrException(RemoteException exception) {
+        mSetNat64CidrException = exception;
+    }
+
+    @Override
+    public void setNat64Cidr(String nat64Cidr, IOtStatusReceiver receiver) throws RemoteException {
+        if (mSetNat64CidrException != null) {
+            throw mSetNat64CidrException;
+        }
+        if (receiver != null) {
+            receiver.onSuccess();
+        }
+    }
+
+    @Override
+    public void setInfraLinkDnsServers(List<String> dnsServers, IOtStatusReceiver receiver)
+            throws RemoteException {
+        throw new UnsupportedOperationException(
+                "FakeOtDaemon#setInfraLinkDnsServers is not implemented!");
+    }
+
     @Override
     public void scheduleMigration(byte[] pendingDataset, IOtStatusReceiver receiver)
             throws RemoteException {
@@ -442,4 +516,8 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     public void setRunOtCtlCommandException(RemoteException exception) {
         mRunOtCtlCommandException = exception;
     }
+
+    public boolean isTrelEnabled() {
+        return mTrelEnabled;
+    }
 }
diff --git a/src/android/mdns_publisher.cpp b/src/android/mdns_publisher.cpp
index 3458d783..fe77ecbb 100644
--- a/src/android/mdns_publisher.cpp
+++ b/src/android/mdns_publisher.cpp
@@ -62,9 +62,12 @@ Status MdnsPublisher::NsdDiscoverServiceCallback::onServiceDiscovered(const std:
                                                                       const std::string &aType,
                                                                       bool               aIsFound)
 {
-    VerifyOrExit(aIsFound, mSubscription.mPublisher.OnServiceRemoved(0, aType, aName));
+    std::shared_ptr<ServiceSubscription> subscription = mSubscription.lock();
 
-    mSubscription.Resolve(aName, aType);
+    VerifyOrExit(subscription != nullptr);
+    VerifyOrExit(aIsFound, subscription->mPublisher.OnServiceRemoved(0, aType, aName));
+
+    subscription->Resolve(aName, aType);
 
 exit:
     return Status::ok();
@@ -79,8 +82,11 @@ Status MdnsPublisher::NsdResolveServiceCallback::onServiceResolved(const std::st
                                                                    const std::vector<DnsTxtAttribute> &aTxt,
                                                                    int                                 aTtlSeconds)
 {
-    DiscoveredInstanceInfo info;
-    TxtList                txtList;
+    DiscoveredInstanceInfo               info;
+    TxtList                              txtList;
+    std::shared_ptr<ServiceSubscription> subscription = mSubscription.lock();
+
+    VerifyOrExit(subscription != nullptr);
 
     info.mHostName   = aHostname + ".local.";
     info.mName       = aName;
@@ -90,7 +96,9 @@ Status MdnsPublisher::NsdResolveServiceCallback::onServiceResolved(const std::st
     for (const auto &addressStr : aAddresses)
     {
         Ip6Address address;
-        int        error = Ip6Address::FromString(addressStr.c_str(), address);
+        // addressStr may be in the format of "fe80::1234%eth0"
+        std::string addrStr(addressStr.begin(), std::find(addressStr.begin(), addressStr.end(), '%'));
+        int         error = Ip6Address::FromString(addrStr.c_str(), address);
 
         if (error != OTBR_ERROR_NONE)
         {
@@ -105,15 +113,19 @@ Status MdnsPublisher::NsdResolveServiceCallback::onServiceResolved(const std::st
     }
     EncodeTxtData(txtList, info.mTxtData);
 
-    mSubscription.mPublisher.OnServiceResolved(aType, info);
+    subscription->mPublisher.OnServiceResolved(aType, info);
 
+exit:
     return Status::ok();
 }
 
 Status MdnsPublisher::NsdResolveHostCallback::onHostResolved(const std::string              &aName,
                                                              const std::vector<std::string> &aAddresses)
 {
-    DiscoveredHostInfo info;
+    DiscoveredHostInfo                info;
+    std::shared_ptr<HostSubscription> subscription = mSubscription.lock();
+
+    VerifyOrExit(subscription != nullptr);
 
     info.mTtl = kDefaultResolvedTtl;
     for (const auto &addressStr : aAddresses)
@@ -129,8 +141,9 @@ Status MdnsPublisher::NsdResolveHostCallback::onHostResolved(const std::string
         info.mAddresses.push_back(address);
     }
 
-    mSubscription.mPublisher.OnHostResolved(aName, info);
+    subscription->mPublisher.OnHostResolved(aName, info);
 
+exit:
     return Status::ok();
 }
 
@@ -166,19 +179,19 @@ std::shared_ptr<MdnsPublisher::NsdStatusReceiver> CreateReceiver(Mdns::Publisher
 }
 
 std::shared_ptr<MdnsPublisher::NsdDiscoverServiceCallback> CreateNsdDiscoverServiceCallback(
-    MdnsPublisher::ServiceSubscription &aServiceSubscription)
+    const std::shared_ptr<MdnsPublisher::ServiceSubscription> &aServiceSubscription)
 {
     return ndk::SharedRefBase::make<MdnsPublisher::NsdDiscoverServiceCallback>(aServiceSubscription);
 }
 
 std::shared_ptr<MdnsPublisher::NsdResolveServiceCallback> CreateNsdResolveServiceCallback(
-    MdnsPublisher::ServiceSubscription &aServiceSubscription)
+    const std::shared_ptr<MdnsPublisher::ServiceSubscription> &aServiceSubscription)
 {
     return ndk::SharedRefBase::make<MdnsPublisher::NsdResolveServiceCallback>(aServiceSubscription);
 }
 
 std::shared_ptr<MdnsPublisher::NsdResolveHostCallback> CreateNsdResolveHostCallback(
-    MdnsPublisher::HostSubscription &aHostSubscription)
+    const std::shared_ptr<MdnsPublisher::HostSubscription> &aHostSubscription)
 {
     return ndk::SharedRefBase::make<MdnsPublisher::NsdResolveHostCallback>(aHostSubscription);
 }
@@ -341,7 +354,7 @@ void MdnsPublisher::UnpublishKey(const std::string &aName, ResultCallback &&aCal
 
 void MdnsPublisher::SubscribeService(const std::string &aType, const std::string &aInstanceName)
 {
-    auto service = MakeUnique<ServiceSubscription>(aType, aInstanceName, *this, mNsdPublisher);
+    auto service = std::make_shared<ServiceSubscription>(aType, aInstanceName, *this, mNsdPublisher);
 
     VerifyOrExit(IsStarted(), otbrLogWarning("No platform mDNS implementation registered!"));
 
@@ -369,7 +382,7 @@ void MdnsPublisher::UnsubscribeService(const std::string &aType, const std::stri
     VerifyOrExit(IsStarted());
 
     it = std::find_if(mServiceSubscriptions.begin(), mServiceSubscriptions.end(),
-                      [&aType, &aInstanceName](const std::unique_ptr<ServiceSubscription> &aService) {
+                      [&aType, &aInstanceName](const std::shared_ptr<ServiceSubscription> &aService) {
                           return aService->mType == aType && aService->mName == aInstanceName;
                       });
 
@@ -377,7 +390,7 @@ void MdnsPublisher::UnsubscribeService(const std::string &aType, const std::stri
                  otbrLogWarning("The service %s.%s is already unsubscribed.", aInstanceName.c_str(), aType.c_str()));
 
     {
-        std::unique_ptr<ServiceSubscription> service = std::move(*it);
+        std::shared_ptr<ServiceSubscription> service = std::move(*it);
 
         mServiceSubscriptions.erase(it);
     }
@@ -391,11 +404,11 @@ exit:
 
 void MdnsPublisher::SubscribeHost(const std::string &aHostName)
 {
-    auto host = MakeUnique<HostSubscription>(aHostName, *this, mNsdPublisher, AllocateListenerId());
+    auto host = std::make_shared<HostSubscription>(aHostName, *this, mNsdPublisher, AllocateListenerId());
 
     VerifyOrExit(IsStarted(), otbrLogWarning("No platform mDNS implementation registered!"));
 
-    mNsdPublisher->resolveHost(aHostName, CreateNsdResolveHostCallback(*host), host->mListenerId);
+    mNsdPublisher->resolveHost(aHostName, CreateNsdResolveHostCallback(host), host->mListenerId);
     mHostSubscriptions.push_back(std::move(host));
 
     otbrLogInfo("Subscribe host %s (total %zu)", aHostName.c_str(), mHostSubscriptions.size());
@@ -412,13 +425,13 @@ void MdnsPublisher::UnsubscribeHost(const std::string &aHostName)
 
     it = std::find_if(
         mHostSubscriptions.begin(), mHostSubscriptions.end(),
-        [&aHostName](const std::unique_ptr<HostSubscription> &aHost) { return aHost->mName == aHostName; });
+        [&aHostName](const std::shared_ptr<HostSubscription> &aHost) { return aHost->mName == aHostName; });
 
     VerifyOrExit(it != mHostSubscriptions.end(),
                  otbrLogWarning("The host %s is already unsubscribed.", aHostName.c_str()));
 
     {
-        std::unique_ptr<HostSubscription> host = std::move(*it);
+        std::shared_ptr<HostSubscription> host = std::move(*it);
 
         mHostSubscriptions.erase(it);
     }
@@ -519,7 +532,7 @@ void MdnsPublisher::ServiceSubscription::Browse(void)
 
     otbrLogInfo("Browsing service type %s", mType.c_str());
 
-    mNsdPublisher->discoverService(mType, CreateNsdDiscoverServiceCallback(*this), mBrowseListenerId);
+    mNsdPublisher->discoverService(mType, CreateNsdDiscoverServiceCallback(shared_from_this()), mBrowseListenerId);
 
 exit:
     return;
@@ -534,7 +547,8 @@ void MdnsPublisher::ServiceSubscription::Resolve(const std::string &aName, const
     otbrLogInfo("Resolving service %s.%s", aName.c_str(), aType.c_str());
 
     AddServiceResolver(aName, resolver);
-    mNsdPublisher->resolveService(aName, aType, CreateNsdResolveServiceCallback(*this), resolver->mListenerId);
+    mNsdPublisher->resolveService(aName, aType, CreateNsdResolveServiceCallback(shared_from_this()),
+                                  resolver->mListenerId);
 
 exit:
     return;
diff --git a/src/android/mdns_publisher.hpp b/src/android/mdns_publisher.hpp
index 0930c3d4..07f0c0c4 100644
--- a/src/android/mdns_publisher.hpp
+++ b/src/android/mdns_publisher.hpp
@@ -128,7 +128,7 @@ public:
         std::shared_ptr<INsdPublisher> mNsdPublisher;
     };
 
-    struct ServiceSubscription : private ::NonCopyable
+    struct ServiceSubscription : public std::enable_shared_from_this<ServiceSubscription>, private ::NonCopyable
     {
         explicit ServiceSubscription(std::string                    aType,
                                      std::string                    aName,
@@ -185,22 +185,22 @@ public:
     class NsdDiscoverServiceCallback : public BnNsdDiscoverServiceCallback
     {
     public:
-        explicit NsdDiscoverServiceCallback(ServiceSubscription &aSubscription)
-            : mSubscription(aSubscription)
+        explicit NsdDiscoverServiceCallback(std::weak_ptr<ServiceSubscription> aSubscription)
+            : mSubscription(std::move(aSubscription))
         {
         }
 
         Status onServiceDiscovered(const std::string &aName, const std::string &aType, bool aIsFound);
 
     private:
-        ServiceSubscription &mSubscription;
+        std::weak_ptr<ServiceSubscription> mSubscription;
     };
 
     class NsdResolveServiceCallback : public BnNsdResolveServiceCallback
     {
     public:
-        explicit NsdResolveServiceCallback(ServiceSubscription &aSubscription)
-            : mSubscription(aSubscription)
+        explicit NsdResolveServiceCallback(std::weak_ptr<ServiceSubscription> aSubscription)
+            : mSubscription(std::move(aSubscription))
         {
         }
 
@@ -214,21 +214,21 @@ public:
                                  int                                 aTtlSeconds);
 
     private:
-        ServiceSubscription &mSubscription;
+        std::weak_ptr<ServiceSubscription> mSubscription;
     };
 
     class NsdResolveHostCallback : public BnNsdResolveHostCallback
     {
     public:
-        explicit NsdResolveHostCallback(HostSubscription &aSubscription)
-            : mSubscription(aSubscription)
+        explicit NsdResolveHostCallback(std::weak_ptr<HostSubscription> aSubscription)
+            : mSubscription(std::move(aSubscription))
         {
         }
 
         Status onHostResolved(const std::string &aName, const std::vector<std::string> &aAddresses);
 
     private:
-        HostSubscription &mSubscription;
+        std::weak_ptr<HostSubscription> mSubscription;
     };
 
 protected:
@@ -311,8 +311,8 @@ private:
         std::weak_ptr<INsdPublisher> mNsdPublisher;
     };
 
-    typedef std::vector<std::unique_ptr<ServiceSubscription>> ServiceSubscriptionList;
-    typedef std::vector<std::unique_ptr<HostSubscription>>    HostSubscriptionList;
+    typedef std::vector<std::shared_ptr<ServiceSubscription>> ServiceSubscriptionList;
+    typedef std::vector<std::shared_ptr<HostSubscription>>    HostSubscriptionList;
 
     static constexpr int kDefaultResolvedTtl = 10;
     static constexpr int kMinResolvedTtl     = 1;
diff --git a/src/android/otdaemon_server.cpp b/src/android/otdaemon_server.cpp
index ed26e2b3..acdf7e4b 100644
--- a/src/android/otdaemon_server.cpp
+++ b/src/android/otdaemon_server.cpp
@@ -26,32 +26,37 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
+#include <linux/in.h>
 #define OTBR_LOG_TAG "BINDER"
 
 #include "android/otdaemon_server.hpp"
 
+#include <algorithm>
 #include <net/if.h>
+#include <random>
 #include <string.h>
 
-#include <algorithm>
-
-#include <android-base/file.h>
-#include <android-base/stringprintf.h>
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+#include <openthread/border_agent.h>
 #include <openthread/border_router.h>
 #include <openthread/cli.h>
+#include <openthread/dnssd_server.h>
 #include <openthread/icmp6.h>
 #include <openthread/ip6.h>
 #include <openthread/link.h>
 #include <openthread/nat64.h>
 #include <openthread/openthread-system.h>
+#include <openthread/srp_server.h>
 #include <openthread/platform/infra_if.h>
 #include <openthread/platform/radio.h>
 
 #include "agent/vendor.hpp"
+#include "android/android_rcp_host.hpp"
+#include "android/common_utils.hpp"
 #include "android/otdaemon_telemetry.hpp"
 #include "common/code_utils.hpp"
+#include "ncp/thread_host.hpp"
 
 #define BYTE_ARR_END(arr) ((arr) + sizeof(arr))
 
@@ -76,24 +81,6 @@ namespace Android {
 static const char       OTBR_SERVICE_NAME[] = "ot_daemon";
 static constexpr size_t kMaxIp6Size         = 1280;
 
-static void PropagateResult(int                                       aError,
-                            const std::string                        &aMessage,
-                            const std::shared_ptr<IOtStatusReceiver> &aReceiver)
-{
-    if (aReceiver != nullptr)
-    {
-        // If an operation has already been requested or accepted, consider it succeeded
-        if (aError == OT_ERROR_NONE || aError == OT_ERROR_ALREADY)
-        {
-            aReceiver->onSuccess();
-        }
-        else
-        {
-            aReceiver->onError(aError, aMessage);
-        }
-    }
-}
-
 static const char *ThreadEnabledStateToString(int enabledState)
 {
     switch (enabledState)
@@ -112,19 +99,17 @@ static const char *ThreadEnabledStateToString(int enabledState)
 
 OtDaemonServer *OtDaemonServer::sOtDaemonServer = nullptr;
 
-OtDaemonServer::OtDaemonServer(otbr::Ncp::RcpHost    &rcpHost,
-                               otbr::Mdns::Publisher &mdnsPublisher,
-                               otbr::BorderAgent     &borderAgent)
-    : mHost(rcpHost)
-    , mMdnsPublisher(static_cast<MdnsPublisher &>(mdnsPublisher))
-    , mBorderAgent(borderAgent)
-    , mConfiguration()
+OtDaemonServer::OtDaemonServer(otbr::Ncp::RcpHost    &aRcpHost,
+                               otbr::Mdns::Publisher &aMdnsPublisher,
+                               otbr::BorderAgent     &aBorderAgent)
+    : mHost(aRcpHost)
+    , mAndroidHost(CreateAndroidHost())
+    , mMdnsPublisher(static_cast<MdnsPublisher &>(aMdnsPublisher))
+    , mBorderAgent(aBorderAgent)
 {
     mClientDeathRecipient =
         ::ndk::ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient_new(&OtDaemonServer::BinderDeathCallback));
-    mInfraLinkState.interfaceName = "";
-    mInfraIcmp6Socket             = -1;
-    sOtDaemonServer               = this;
+    sOtDaemonServer = this;
 }
 
 void OtDaemonServer::Init(void)
@@ -142,6 +127,9 @@ void OtDaemonServer::Init(void)
     otIcmp6SetEchoMode(GetOtInstance(), OT_ICMP6_ECHO_HANDLER_DISABLED);
     otIp6SetReceiveFilterEnabled(GetOtInstance(), true);
     otNat64SetReceiveIp4Callback(GetOtInstance(), &OtDaemonServer::ReceiveCallback, this);
+    mBorderAgent.AddEphemeralKeyChangedCallback([this]() { HandleEpskcStateChanged(); });
+    mBorderAgent.SetEphemeralKeyEnabled(true);
+    otSysUpstreamDnsServerSetResolvConfEnabled(false);
 
     mTaskRunner.Post(kTelemetryCheckInterval, [this]() { PushTelemetryIfConditionMatch(); });
 }
@@ -176,7 +164,7 @@ void OtDaemonServer::StateCallback(otChangedFlags aFlags)
         }
         else
         {
-            mCallback->onStateChanged(mState, -1);
+            NotifyStateChanged(/* aListenerId*/ -1);
         }
     }
 
@@ -311,47 +299,6 @@ exit:
     otMessageFree(aMessage);
 }
 
-int OtDaemonServer::OtCtlCommandCallback(void *aBinderServer, const char *aFormat, va_list aArguments)
-{
-    return static_cast<OtDaemonServer *>(aBinderServer)->OtCtlCommandCallback(aFormat, aArguments);
-}
-
-int OtDaemonServer::OtCtlCommandCallback(const char *aFormat, va_list aArguments)
-{
-    static const std::string kPrompt = "> ";
-    std::string              output;
-
-    VerifyOrExit(mOtCtlOutputReceiver != nullptr, otSysCliInitUsingDaemon(GetOtInstance()));
-
-    android::base::StringAppendV(&output, aFormat, aArguments);
-
-    // Ignore CLI prompt
-    VerifyOrExit(output != kPrompt);
-
-    mOtCtlOutputReceiver->onOutput(output);
-
-    // Check if the command has completed (indicated by "Done" or "Error")
-    if (output.starts_with("Done") || output.starts_with("Error"))
-    {
-        mIsOtCtlOutputComplete = true;
-    }
-
-    // The OpenThread CLI consistently outputs "\r\n" as a newline character. Therefore, we use the presence of "\r\n"
-    // following "Done" or "Error" to signal the completion of a command's output.
-    if (mIsOtCtlOutputComplete && output.ends_with("\r\n"))
-    {
-        if (!mIsOtCtlInteractiveMode)
-        {
-            otSysCliInitUsingDaemon(GetOtInstance());
-        }
-        mIsOtCtlOutputComplete = false;
-        mOtCtlOutputReceiver->onComplete();
-    }
-
-exit:
-    return output.length();
-}
-
 static constexpr uint8_t kIpVersion4 = 4;
 static constexpr uint8_t kIpVersion6 = 6;
 
@@ -430,6 +377,60 @@ exit:
     }
 }
 
+void OtDaemonServer::HandleEpskcStateChanged(void *aBinderServer)
+{
+    static_cast<OtDaemonServer *>(aBinderServer)->HandleEpskcStateChanged();
+}
+
+void OtDaemonServer::HandleEpskcStateChanged(void)
+{
+    mState.ephemeralKeyState = GetEphemeralKeyState();
+
+    NotifyStateChanged(/* aListenerId*/ -1);
+}
+
+void OtDaemonServer::NotifyStateChanged(int64_t aListenerId)
+{
+    if (mState.ephemeralKeyState == OT_EPHEMERAL_KEY_DISABLED)
+    {
+        mState.ephemeralKeyLifetimeMillis = 0;
+    }
+    else
+    {
+        mState.ephemeralKeyLifetimeMillis =
+            mEphemeralKeyExpiryMillis -
+            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
+                .count();
+    }
+    if (mCallback != nullptr)
+    {
+        mCallback->onStateChanged(mState, aListenerId);
+    }
+}
+
+int OtDaemonServer::GetEphemeralKeyState(void)
+{
+    int ephemeralKeyState;
+
+    if (otBorderAgentIsEphemeralKeyActive(GetOtInstance()))
+    {
+        if (otBorderAgentGetState(GetOtInstance()) == OT_BORDER_AGENT_STATE_ACTIVE)
+        {
+            ephemeralKeyState = OT_EPHEMERAL_KEY_IN_USE;
+        }
+        else
+        {
+            ephemeralKeyState = OT_EPHEMERAL_KEY_ENABLED;
+        }
+    }
+    else
+    {
+        ephemeralKeyState = OT_EPHEMERAL_KEY_DISABLED;
+    }
+
+    return ephemeralKeyState;
+}
+
 BackboneRouterState OtDaemonServer::GetBackboneRouterState()
 {
     BackboneRouterState                       state;
@@ -513,15 +514,37 @@ void OtDaemonServer::Process(const MainloopContext &aMainloop)
     }
 }
 
-Status OtDaemonServer::initialize(const ScopedFileDescriptor               &aTunFd,
-                                  const bool                                enabled,
+std::unique_ptr<AndroidThreadHost> OtDaemonServer::CreateAndroidHost(void)
+{
+    std::unique_ptr<AndroidThreadHost> host;
+
+    switch (mHost.GetCoprocessorType())
+    {
+    case OT_COPROCESSOR_RCP:
+        host = std::make_unique<AndroidRcpHost>(static_cast<otbr::Ncp::RcpHost &>(mHost));
+        break;
+
+    case OT_COPROCESSOR_NCP:
+    default:
+        DieNow("Unknown coprocessor type!");
+        break;
+    }
+
+    return host;
+}
+
+Status OtDaemonServer::initialize(const bool                                aEnabled,
+                                  const OtDaemonConfiguration              &aConfiguration,
+                                  const ScopedFileDescriptor               &aTunFd,
                                   const std::shared_ptr<INsdPublisher>     &aINsdPublisher,
                                   const MeshcopTxtAttributes               &aMeshcopTxts,
-                                  const std::shared_ptr<IOtDaemonCallback> &aCallback,
-                                  const std::string                        &aCountryCode)
+                                  const std::string                        &aCountryCode,
+                                  const bool                                aTrelEnabled,
+                                  const std::shared_ptr<IOtDaemonCallback> &aCallback)
 {
-    otbrLogInfo("OT daemon is initialized by system server (tunFd=%d, enabled=%s)", aTunFd.get(),
-                enabled ? "true" : "false");
+    otbrLogInfo("OT daemon is initialized by system server (enabled=%s, tunFd=%d)", (aEnabled ? "true" : "false"),
+                aTunFd.get());
+
     // The copy constructor of `ScopedFileDescriptor` is deleted. It is unable to pass the `aTunFd`
     // to the lambda function. The processing method of `aTunFd` doesn't call OpenThread functions,
     // we can process `aTunFd` directly in front of the task.
@@ -530,23 +553,28 @@ Status OtDaemonServer::initialize(const ScopedFileDescriptor               &aTun
     mINsdPublisher = aINsdPublisher;
     mMeshcopTxts   = aMeshcopTxts;
 
-    mTaskRunner.Post([enabled, aINsdPublisher, aMeshcopTxts, aCallback, aCountryCode, this]() {
-        initializeInternal(enabled, mINsdPublisher, mMeshcopTxts, aCallback, aCountryCode);
-    });
+    mTaskRunner.Post(
+        [aEnabled, aConfiguration, aINsdPublisher, aMeshcopTxts, aCallback, aCountryCode, aTrelEnabled, this]() {
+            initializeInternal(aEnabled, aConfiguration, mINsdPublisher, mMeshcopTxts, aCountryCode, aTrelEnabled,
+                               aCallback);
+        });
 
     return Status::ok();
 }
 
-void OtDaemonServer::initializeInternal(const bool                                enabled,
+void OtDaemonServer::initializeInternal(const bool                                aEnabled,
+                                        const OtDaemonConfiguration              &aConfiguration,
                                         const std::shared_ptr<INsdPublisher>     &aINsdPublisher,
                                         const MeshcopTxtAttributes               &aMeshcopTxts,
-                                        const std::shared_ptr<IOtDaemonCallback> &aCallback,
-                                        const std::string                        &aCountryCode)
+                                        const std::string                        &aCountryCode,
+                                        const bool                                aTrelEnabled,
+                                        const std::shared_ptr<IOtDaemonCallback> &aCallback)
 {
     std::string              instanceName = aMeshcopTxts.vendorName + " " + aMeshcopTxts.modelName;
     Mdns::Publisher::TxtList nonStandardTxts;
     otbrError                error;
 
+    mAndroidHost->SetConfiguration(aConfiguration, nullptr /* aReceiver */);
     setCountryCodeInternal(aCountryCode, nullptr /* aReceiver */);
     registerStateCallbackInternal(aCallback, -1 /* listenerId */);
 
@@ -563,9 +591,10 @@ void OtDaemonServer::initializeInternal(const bool
         otbrLogCrit("Failed to set MeshCoP values: %d", static_cast<int>(error));
     }
 
-    mBorderAgent.SetEnabled(enabled);
+    mBorderAgent.SetEnabled(aEnabled && aConfiguration.borderRouterEnabled);
+    mAndroidHost->SetTrelEnabled(aTrelEnabled);
 
-    if (enabled)
+    if (aEnabled)
     {
         EnableThread(nullptr /* aReceiver */);
     }
@@ -597,22 +626,12 @@ void OtDaemonServer::UpdateThreadEnabledState(const int enabled, const std::shar
         aReceiver->onSuccess();
     }
 
-    // Enables the BorderAgent module only when Thread is enabled because it always
-    // publishes the MeshCoP service even when no Thread network is provisioned.
-    switch (enabled)
-    {
-    case OT_STATE_ENABLED:
-        mBorderAgent.SetEnabled(true);
-        break;
-    case OT_STATE_DISABLED:
-        mBorderAgent.SetEnabled(false);
-        break;
-    }
+    // Enables the BorderAgent module only when Thread is enabled and configured a Border Router,
+    // so that it won't publish the MeshCoP mDNS service when unnecessary
+    // TODO: b/376217403 - enables / disables OT Border Agent at runtime
+    mBorderAgent.SetEnabled(enabled == OT_STATE_ENABLED && mAndroidHost->GetConfiguration().borderRouterEnabled);
 
-    if (mCallback != nullptr)
-    {
-        mCallback->onStateChanged(mState, -1);
-    }
+    NotifyStateChanged(/* aListenerId*/ -1);
 
 exit:
     return;
@@ -631,14 +650,14 @@ void OtDaemonServer::EnableThread(const std::shared_ptr<IOtStatusReceiver> &aRec
     UpdateThreadEnabledState(OT_STATE_ENABLED, aReceiver);
 }
 
-Status OtDaemonServer::setThreadEnabled(const bool enabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+Status OtDaemonServer::setThreadEnabled(const bool aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    mTaskRunner.Post([enabled, aReceiver, this]() { setThreadEnabledInternal(enabled, aReceiver); });
+    mTaskRunner.Post([aEnabled, aReceiver, this]() { setThreadEnabledInternal(aEnabled, aReceiver); });
 
     return Status::ok();
 }
 
-void OtDaemonServer::setThreadEnabledInternal(const bool enabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+void OtDaemonServer::setThreadEnabledInternal(const bool aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
     int         error = OT_ERROR_NONE;
     std::string message;
@@ -647,13 +666,13 @@ void OtDaemonServer::setThreadEnabledInternal(const bool enabled, const std::sha
 
     VerifyOrExit(mState.threadEnabled != OT_STATE_DISABLING, error = OT_ERROR_BUSY, message = "Thread is disabling");
 
-    if ((mState.threadEnabled == OT_STATE_ENABLED) == enabled)
+    if ((mState.threadEnabled == OT_STATE_ENABLED) == aEnabled)
     {
         aReceiver->onSuccess();
         ExitNow();
     }
 
-    if (enabled)
+    if (aEnabled)
     {
         EnableThread(aReceiver);
     }
@@ -677,15 +696,87 @@ exit:
     }
 }
 
-Status OtDaemonServer::registerStateCallback(const std::shared_ptr<IOtDaemonCallback> &aCallback, int64_t listenerId)
+Status OtDaemonServer::activateEphemeralKeyMode(const int64_t                             aLifetimeMillis,
+                                                const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    mTaskRunner.Post([aCallback, listenerId, this]() { registerStateCallbackInternal(aCallback, listenerId); });
+    mTaskRunner.Post(
+        [aLifetimeMillis, aReceiver, this]() { activateEphemeralKeyModeInternal(aLifetimeMillis, aReceiver); });
+
+    return Status::ok();
+}
+
+void OtDaemonServer::activateEphemeralKeyModeInternal(const int64_t                             aLifetimeMillis,
+                                                      const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    int         error = OT_ERROR_NONE;
+    std::string message;
+    std::string passcode;
+
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+    VerifyOrExit(isAttached(), error = static_cast<int>(IOtDaemon::ErrorCode::OT_ERROR_FAILED_PRECONDITION),
+                 message = "Cannot activate ephemeral key mode when this device is not attached to Thread network");
+    VerifyOrExit(!otBorderAgentIsEphemeralKeyActive(GetOtInstance()), error = OT_ERROR_BUSY,
+                 message = "ephemeral key mode is already activated");
+
+    otbrLogInfo("Activating ephemeral key mode with %lldms lifetime.", aLifetimeMillis);
+
+    SuccessOrExit(error = mBorderAgent.CreateEphemeralKey(passcode), message = "Failed to create ephemeral key");
+    SuccessOrExit(error   = otBorderAgentSetEphemeralKey(GetOtInstance(), passcode.c_str(),
+                                                         static_cast<uint32_t>(aLifetimeMillis), 0 /* aUdpPort */),
+                  message = "Failed to set ephemeral key");
+
+exit:
+    if (aReceiver != nullptr)
+    {
+        if (error == OT_ERROR_NONE)
+        {
+            mState.ephemeralKeyPasscode = passcode;
+            mEphemeralKeyExpiryMillis   = std::chrono::duration_cast<std::chrono::milliseconds>(
+                                            std::chrono::steady_clock::now().time_since_epoch())
+                                            .count() +
+                                        aLifetimeMillis;
+            aReceiver->onSuccess();
+        }
+        else
+        {
+            aReceiver->onError(error, message);
+        }
+    }
+}
+
+Status OtDaemonServer::deactivateEphemeralKeyMode(const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    mTaskRunner.Post([aReceiver, this]() { deactivateEphemeralKeyModeInternal(aReceiver); });
+
+    return Status::ok();
+}
+
+void OtDaemonServer::deactivateEphemeralKeyModeInternal(const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    int         error = OT_ERROR_NONE;
+    std::string message;
+
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+    otbrLogInfo("Deactivating ephemeral key mode.");
+
+    VerifyOrExit(otBorderAgentIsEphemeralKeyActive(GetOtInstance()), error = OT_ERROR_NONE);
+
+    otBorderAgentDisconnect(GetOtInstance());
+    otBorderAgentClearEphemeralKey(GetOtInstance());
+
+exit:
+    PropagateResult(error, message, aReceiver);
+}
+
+Status OtDaemonServer::registerStateCallback(const std::shared_ptr<IOtDaemonCallback> &aCallback, int64_t aListenerId)
+{
+    mTaskRunner.Post([aCallback, aListenerId, this]() { registerStateCallbackInternal(aCallback, aListenerId); });
 
     return Status::ok();
 }
 
 void OtDaemonServer::registerStateCallbackInternal(const std::shared_ptr<IOtDaemonCallback> &aCallback,
-                                                   int64_t                                   listenerId)
+                                                   int64_t                                   aListenerId)
 {
     VerifyOrExit(GetOtInstance() != nullptr, otbrLogWarning("OT is not initialized"));
 
@@ -698,7 +789,7 @@ void OtDaemonServer::registerStateCallbackInternal(const std::shared_ptr<IOtDaem
     // To ensure that a client app can get the latest correct state immediately when registering a
     // state callback, here needs to invoke the callback
     RefreshOtDaemonState(/* aFlags */ 0xffffffff);
-    mCallback->onStateChanged(mState, listenerId);
+    NotifyStateChanged(aListenerId);
     mCallback->onBackboneRouterStateChanged(GetBackboneRouterState());
 
 exit:
@@ -711,47 +802,37 @@ bool OtDaemonServer::RefreshOtDaemonState(otChangedFlags aFlags)
 
     if (aFlags & OT_CHANGED_THREAD_NETIF_STATE)
     {
-        mState.isInterfaceUp = otIp6IsEnabled(GetOtInstance());
+        mState.isInterfaceUp = mHost.Ip6IsEnabled();
         haveUpdates          = true;
     }
 
     if (aFlags & OT_CHANGED_THREAD_ROLE)
     {
-        mState.deviceRole = otThreadGetDeviceRole(GetOtInstance());
+        mState.deviceRole = mHost.GetDeviceRole();
         haveUpdates       = true;
     }
 
     if (aFlags & OT_CHANGED_THREAD_PARTITION_ID)
     {
-        mState.partitionId = otThreadGetPartitionId(GetOtInstance());
+        mState.partitionId = mHost.GetPartitionId();
         haveUpdates        = true;
     }
 
     if (aFlags & OT_CHANGED_ACTIVE_DATASET)
     {
         otOperationalDatasetTlvs datasetTlvs;
-        if (otDatasetGetActiveTlvs(GetOtInstance(), &datasetTlvs) == OT_ERROR_NONE)
-        {
-            mState.activeDatasetTlvs.assign(datasetTlvs.mTlvs, datasetTlvs.mTlvs + datasetTlvs.mLength);
-        }
-        else
-        {
-            mState.activeDatasetTlvs.clear();
-        }
+        mHost.GetDatasetActiveTlvs(datasetTlvs);
+        mState.activeDatasetTlvs.assign(datasetTlvs.mTlvs, datasetTlvs.mTlvs + datasetTlvs.mLength);
+
         haveUpdates = true;
     }
 
     if (aFlags & OT_CHANGED_PENDING_DATASET)
     {
         otOperationalDatasetTlvs datasetTlvs;
-        if (otDatasetGetPendingTlvs(GetOtInstance(), &datasetTlvs) == OT_ERROR_NONE)
-        {
-            mState.pendingDatasetTlvs.assign(datasetTlvs.mTlvs, datasetTlvs.mTlvs + datasetTlvs.mLength);
-        }
-        else
-        {
-            mState.pendingDatasetTlvs.clear();
-        }
+        mHost.GetDatasetPendingTlvs(datasetTlvs);
+        mState.pendingDatasetTlvs.assign(datasetTlvs.mTlvs, datasetTlvs.mTlvs + datasetTlvs.mLength);
+
         haveUpdates = true;
     }
 
@@ -765,6 +846,33 @@ bool OtDaemonServer::RefreshOtDaemonState(otChangedFlags aFlags)
     return haveUpdates;
 }
 
+/**
+ * Returns `true` if the two TLV lists are representing the same Operational Dataset.
+ *
+ * Note this method works even if TLVs in `aLhs` and `aRhs` are not ordered.
+ */
+static bool areDatasetsEqual(const otOperationalDatasetTlvs &aLhs, const otOperationalDatasetTlvs &aRhs)
+{
+    bool result = false;
+
+    otOperationalDataset     lhsDataset;
+    otOperationalDataset     rhsDataset;
+    otOperationalDatasetTlvs lhsNormalizedTlvs;
+    otOperationalDatasetTlvs rhsNormalizedTlvs;
+
+    // Sort the TLVs in the TLV byte arrays by leveraging the deterministic nature of the two OT APIs
+    SuccessOrExit(otDatasetParseTlvs(&aLhs, &lhsDataset));
+    SuccessOrExit(otDatasetParseTlvs(&aRhs, &rhsDataset));
+    otDatasetConvertToTlvs(&lhsDataset, &lhsNormalizedTlvs);
+    otDatasetConvertToTlvs(&rhsDataset, &rhsNormalizedTlvs);
+
+    result = (lhsNormalizedTlvs.mLength == rhsNormalizedTlvs.mLength) &&
+             (memcmp(lhsNormalizedTlvs.mTlvs, rhsNormalizedTlvs.mTlvs, lhsNormalizedTlvs.mLength) == 0);
+
+exit:
+    return result;
+}
+
 Status OtDaemonServer::join(const std::vector<uint8_t>               &aActiveOpDatasetTlvs,
                             const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
@@ -778,7 +886,8 @@ void OtDaemonServer::joinInternal(const std::vector<uint8_t>               &aAct
 {
     int                      error = OT_ERROR_NONE;
     std::string              message;
-    otOperationalDatasetTlvs datasetTlvs;
+    otOperationalDatasetTlvs newDatasetTlvs;
+    otOperationalDatasetTlvs curDatasetTlvs;
 
     VerifyOrExit(mState.threadEnabled != OT_STATE_DISABLING, error = OT_ERROR_BUSY, message = "Thread is disabling");
 
@@ -790,18 +899,29 @@ void OtDaemonServer::joinInternal(const std::vector<uint8_t>               &aAct
 
     VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
 
+    std::copy(aActiveOpDatasetTlvs.begin(), aActiveOpDatasetTlvs.end(), newDatasetTlvs.mTlvs);
+    newDatasetTlvs.mLength = static_cast<uint8_t>(aActiveOpDatasetTlvs.size());
+
+    error = otDatasetGetActiveTlvs(GetOtInstance(), &curDatasetTlvs);
+    if (error == OT_ERROR_NONE && areDatasetsEqual(newDatasetTlvs, curDatasetTlvs) && isAttached())
+    {
+        // Do not leave and re-join if this device has already joined the same network. This can help elimilate
+        // unnecessary connectivity and topology disruption and save the time for re-joining. It's more useful for use
+        // cases where Thread networks are dynamically brought up and torn down (e.g. Thread on mobile phones).
+        aReceiver->onSuccess();
+        ExitNow();
+    }
+
     if (otThreadGetDeviceRole(GetOtInstance()) != OT_DEVICE_ROLE_DISABLED)
     {
         LeaveGracefully([aActiveOpDatasetTlvs, aReceiver, this]() {
-            FinishLeave(nullptr);
+            FinishLeave(true /* aEraseDataset */, nullptr);
             join(aActiveOpDatasetTlvs, aReceiver);
         });
         ExitNow();
     }
 
-    std::copy(aActiveOpDatasetTlvs.begin(), aActiveOpDatasetTlvs.end(), datasetTlvs.mTlvs);
-    datasetTlvs.mLength = static_cast<uint8_t>(aActiveOpDatasetTlvs.size());
-    SuccessOrExit(error   = otDatasetSetActiveTlvs(GetOtInstance(), &datasetTlvs),
+    SuccessOrExit(error   = otDatasetSetActiveTlvs(GetOtInstance(), &newDatasetTlvs),
                   message = "Failed to set Active Operational Dataset");
 
     // TODO(b/273160198): check how we can implement join as a child
@@ -824,14 +944,14 @@ exit:
     }
 }
 
-Status OtDaemonServer::leave(const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+Status OtDaemonServer::leave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    mTaskRunner.Post([aReceiver, this]() { leaveInternal(aReceiver); });
+    mTaskRunner.Post([aEraseDataset, aReceiver, this]() { leaveInternal(aEraseDataset, aReceiver); });
 
     return Status::ok();
 }
 
-void OtDaemonServer::leaveInternal(const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+void OtDaemonServer::leaveInternal(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
     std::string message;
     int         error = OT_ERROR_NONE;
@@ -842,11 +962,11 @@ void OtDaemonServer::leaveInternal(const std::shared_ptr<IOtStatusReceiver> &aRe
 
     if (mState.threadEnabled == OT_STATE_DISABLED)
     {
-        FinishLeave(aReceiver);
+        FinishLeave(aEraseDataset, aReceiver);
         ExitNow();
     }
 
-    LeaveGracefully([aReceiver, this]() { FinishLeave(aReceiver); });
+    LeaveGracefully([aEraseDataset, aReceiver, this]() { FinishLeave(aEraseDataset, aReceiver); });
 
 exit:
     if (error != OT_ERROR_NONE)
@@ -855,9 +975,12 @@ exit:
     }
 }
 
-void OtDaemonServer::FinishLeave(const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+void OtDaemonServer::FinishLeave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    (void)otInstanceErasePersistentInfo(GetOtInstance());
+    if (aEraseDataset)
+    {
+        (void)otInstanceErasePersistentInfo(GetOtInstance());
+    }
 
     // TODO: b/323301831 - Re-init the Application class.
     if (aReceiver != nullptr)
@@ -989,22 +1112,9 @@ Status OtDaemonServer::setCountryCode(const std::string                        &
 void OtDaemonServer::setCountryCodeInternal(const std::string                        &aCountryCode,
                                             const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    static constexpr int kCountryCodeLength = 2;
-    otError              error              = OT_ERROR_NONE;
-    std::string          message;
-    uint16_t             countryCode;
-
-    VerifyOrExit((aCountryCode.length() == kCountryCodeLength) && isalpha(aCountryCode[0]) && isalpha(aCountryCode[1]),
-                 error = OT_ERROR_INVALID_ARGS, message = "The country code is invalid");
-
-    otbrLogInfo("Set country code: %c%c", aCountryCode[0], aCountryCode[1]);
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
-
-    countryCode = static_cast<uint16_t>((aCountryCode[0] << 8) | aCountryCode[1]);
-    SuccessOrExit(error = otLinkSetRegion(GetOtInstance(), countryCode), message = "Failed to set the country code");
-
-exit:
-    PropagateResult(error, message, aReceiver);
+    mHost.SetCountryCode(aCountryCode, [aReceiver](otError aError, const std::string &aMessage) {
+        PropagateResult(aError, aMessage, aReceiver);
+    });
 }
 
 Status OtDaemonServer::getChannelMasks(const std::shared_ptr<IChannelMasksReceiver> &aReceiver)
@@ -1016,27 +1126,13 @@ Status OtDaemonServer::getChannelMasks(const std::shared_ptr<IChannelMasksReceiv
 
 void OtDaemonServer::getChannelMasksInternal(const std::shared_ptr<IChannelMasksReceiver> &aReceiver)
 {
-    otError  error = OT_ERROR_NONE;
-    uint32_t supportedChannelMask;
-    uint32_t preferredChannelMask;
-
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE);
-
-    supportedChannelMask = otLinkGetSupportedChannelMask(GetOtInstance());
-    preferredChannelMask = otPlatRadioGetPreferredChannelMask(GetOtInstance());
-
-exit:
-    if (aReceiver != nullptr)
-    {
-        if (error == OT_ERROR_NONE)
-        {
-            aReceiver->onSuccess(supportedChannelMask, preferredChannelMask);
-        }
-        else
-        {
-            aReceiver->onError(error, "OT is not initialized");
-        }
-    }
+    auto channelMasksReceiver = [aReceiver](uint32_t aSupportedChannelMask, uint32_t aPreferredChannelMask) {
+        aReceiver->onSuccess(aSupportedChannelMask, aPreferredChannelMask);
+    };
+    auto errorReceiver = [aReceiver](otError aError, const std::string &aMessage) {
+        aReceiver->onError(aError, aMessage);
+    };
+    mHost.GetChannelMasks(channelMasksReceiver, errorReceiver);
 }
 
 Status OtDaemonServer::setChannelMaxPowers(const std::vector<ChannelMaxPower>       &aChannelMaxPowers,
@@ -1051,72 +1147,36 @@ Status OtDaemonServer::setChannelMaxPowers(const std::vector<ChannelMaxPower>
 Status OtDaemonServer::setChannelMaxPowersInternal(const std::vector<ChannelMaxPower>       &aChannelMaxPowers,
                                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    otError     error = OT_ERROR_NONE;
-    std::string message;
-    uint8_t     channel;
-    int16_t     maxPower;
-
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
-
-    for (ChannelMaxPower channelMaxPower : aChannelMaxPowers)
-    {
-        VerifyOrExit((channelMaxPower.channel >= OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MIN) &&
-                         (channelMaxPower.channel <= OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MAX),
-                     error = OT_ERROR_INVALID_ARGS, message = "The channel is invalid");
-    }
-
-    for (ChannelMaxPower channelMaxPower : aChannelMaxPowers)
-    {
-        channel = static_cast<uint8_t>(channelMaxPower.channel);
-
-        // INT_MIN indicates that the corresponding channel is disabled in Thread Android API `setChannelMaxPowers()`
-        if (channelMaxPower.maxPower == INT_MIN)
-        {
-            // INT16_MAX indicates that the corresponding channel is disabled in OpenThread API
-            // `otPlatRadioSetChannelTargetPower()`.
-            maxPower = INT16_MAX;
-        }
-        else
-        {
-            maxPower = std::clamp(channelMaxPower.maxPower, INT16_MIN, INT16_MAX - 1);
-        }
-
-        otbrLogInfo("Set channel max power: channel=%u, maxPower=%d", static_cast<unsigned int>(channel),
-                    static_cast<int>(maxPower));
-        SuccessOrExit(error   = otPlatRadioSetChannelTargetPower(GetOtInstance(), channel, maxPower),
-                      message = "Failed to set channel max power");
-    }
+    // Transform aidl ChannelMaxPower to ThreadHost::ChannelMaxPower
+    std::vector<Ncp::ThreadHost::ChannelMaxPower> channelMaxPowers(aChannelMaxPowers.size());
+    std::transform(aChannelMaxPowers.begin(), aChannelMaxPowers.end(), channelMaxPowers.begin(),
+                   [](const ChannelMaxPower &aChannelMaxPower) {
+                       // INT_MIN indicates that the corresponding channel is disabled in Thread Android API
+                       // `setChannelMaxPowers()` INT16_MAX indicates that the corresponding channel is disabled in
+                       // OpenThread API `otPlatRadioSetChannelTargetPower()`.
+                       return Ncp::ThreadHost::ChannelMaxPower(
+                           aChannelMaxPower.channel,
+                           aChannelMaxPower.maxPower == INT_MIN
+                               ? INT16_MAX
+                               : std::clamp(aChannelMaxPower.maxPower, INT16_MIN, INT16_MAX - 1));
+                   });
+
+    mHost.SetChannelMaxPowers(channelMaxPowers, [aReceiver](otError aError, const std::string &aMessage) {
+        PropagateResult(aError, aMessage, aReceiver);
+    });
 
-exit:
-    PropagateResult(error, message, aReceiver);
     return Status::ok();
 }
 
 Status OtDaemonServer::setConfiguration(const OtDaemonConfiguration              &aConfiguration,
                                         const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    mTaskRunner.Post([aConfiguration, aReceiver, this]() { setConfigurationInternal(aConfiguration, aReceiver); });
+    mTaskRunner.Post(
+        [aConfiguration, aReceiver, this]() { mAndroidHost->SetConfiguration(aConfiguration, aReceiver); });
 
     return Status::ok();
 }
 
-void OtDaemonServer::setConfigurationInternal(const OtDaemonConfiguration              &aConfiguration,
-                                              const std::shared_ptr<IOtStatusReceiver> &aReceiver)
-{
-    otError     error = OT_ERROR_NONE;
-    std::string message;
-
-    otbrLogInfo("Configuring Border Router: %s", aConfiguration.toString().c_str());
-
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
-    VerifyOrExit(aConfiguration != mConfiguration);
-
-    mConfiguration = aConfiguration;
-
-exit:
-    PropagateResult(error, message, aReceiver);
-}
-
 Status OtDaemonServer::setInfraLinkInterfaceName(const std::optional<std::string>         &aInterfaceName,
                                                  const ScopedFileDescriptor               &aIcmp6Socket,
                                                  const std::shared_ptr<IOtStatusReceiver> &aReceiver)
@@ -1124,57 +1184,12 @@ Status OtDaemonServer::setInfraLinkInterfaceName(const std::optional<std::string
     int icmp6Socket = aIcmp6Socket.dup().release();
 
     mTaskRunner.Post([interfaceName = aInterfaceName.value_or(""), icmp6Socket, aReceiver, this]() {
-        setInfraLinkInterfaceNameInternal(interfaceName, icmp6Socket, aReceiver);
+        mAndroidHost->SetInfraLinkInterfaceName(interfaceName, icmp6Socket, aReceiver);
     });
 
     return Status::ok();
 }
 
-void OtDaemonServer::setInfraLinkInterfaceNameInternal(const std::string                        &aInterfaceName,
-                                                       int                                       aIcmp6Socket,
-                                                       const std::shared_ptr<IOtStatusReceiver> &aReceiver)
-{
-    otError           error = OT_ERROR_NONE;
-    std::string       message;
-    const std::string infraIfName  = aInterfaceName;
-    unsigned int      infraIfIndex = if_nametoindex(infraIfName.c_str());
-
-    otbrLogInfo("Setting infra link state: %s", aInterfaceName.c_str());
-
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
-    VerifyOrExit(mInfraLinkState.interfaceName != aInterfaceName || aIcmp6Socket != mInfraIcmp6Socket);
-
-    if (infraIfIndex != 0 && aIcmp6Socket > 0)
-    {
-        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
-                      message = "failed to disable border routing");
-        otSysSetInfraNetif(infraIfName.c_str(), aIcmp6Socket);
-        aIcmp6Socket = -1;
-        SuccessOrExit(error   = otBorderRoutingInit(GetOtInstance(), infraIfIndex, otSysInfraIfIsRunning()),
-                      message = "failed to initialize border routing");
-        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), true /* aEnabled */),
-                      message = "failed to enable border routing");
-        // TODO: b/320836258 - Make BBR independently configurable
-        otBackboneRouterSetEnabled(GetOtInstance(), true /* aEnabled */);
-    }
-    else
-    {
-        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
-                      message = "failed to disable border routing");
-        otBackboneRouterSetEnabled(GetOtInstance(), false /* aEnabled */);
-    }
-
-    mInfraLinkState.interfaceName = aInterfaceName;
-    mInfraIcmp6Socket             = aIcmp6Socket;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        close(aIcmp6Socket);
-    }
-    PropagateResult(error, message, aReceiver);
-}
-
 Status OtDaemonServer::runOtCtlCommand(const std::string                        &aCommand,
                                        const bool                                aIsInteractive,
                                        const std::shared_ptr<IOtOutputReceiver> &aReceiver)
@@ -1190,7 +1205,7 @@ Status OtDaemonServer::setInfraLinkNat64Prefix(const std::optional<std::string>
                                                const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
     mTaskRunner.Post([nat64Prefix = aNat64Prefix.value_or(""), aReceiver, this]() {
-        setInfraLinkNat64PrefixInternal(nat64Prefix, aReceiver);
+        mAndroidHost->SetInfraLinkNat64Prefix(nat64Prefix, aReceiver);
     });
 
     return Status::ok();
@@ -1200,91 +1215,21 @@ void OtDaemonServer::runOtCtlCommandInternal(const std::string
                                              const bool                                aIsInteractive,
                                              const std::shared_ptr<IOtOutputReceiver> &aReceiver)
 {
-    otSysCliInitUsingDaemon(GetOtInstance());
-
-    if (!aCommand.empty())
-    {
-        std::string command = aCommand;
-
-        mIsOtCtlInteractiveMode = aIsInteractive;
-        mOtCtlOutputReceiver    = aReceiver;
-
-        otCliInit(GetOtInstance(), OtDaemonServer::OtCtlCommandCallback, this);
-        otCliInputLine(command.data());
-    }
+    mAndroidHost->RunOtCtlCommand(aCommand, aIsInteractive, aReceiver);
 }
 
-void OtDaemonServer::setInfraLinkNat64PrefixInternal(const std::string                        &aNat64Prefix,
-                                                     const std::shared_ptr<IOtStatusReceiver> &aReceiver)
-{
-    otError     error = OT_ERROR_NONE;
-    std::string message;
-
-    otbrLogInfo("Setting infra link NAT64 prefix: %s", aNat64Prefix.c_str());
-
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
-
-    mInfraLinkState.nat64Prefix = aNat64Prefix;
-    NotifyNat64PrefixDiscoveryDone();
-
-exit:
-    PropagateResult(error, message, aReceiver);
-}
-
-static int OutputCallback(void *aContext, const char *aFormat, va_list aArguments)
+Status OtDaemonServer::setInfraLinkDnsServers(const std::vector<std::string>           &aDnsServers,
+                                              const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    std::string output;
-
-    android::base::StringAppendV(&output, aFormat, aArguments);
-
-    int length = output.length();
-
-    VerifyOrExit(android::base::WriteStringToFd(output, *(static_cast<int *>(aContext))), length = 0);
-
-exit:
-    return length;
-}
+    mTaskRunner.Post(
+        [aDnsServers, aReceiver, this]() { mAndroidHost->SetInfraLinkDnsServers(aDnsServers, aReceiver); });
 
-inline void DumpCliCommand(std::string aCommand, int aFd)
-{
-    android::base::WriteStringToFd(aCommand + '\n', aFd);
-    otCliInputLine(aCommand.data());
+    return Status::ok();
 }
 
 binder_status_t OtDaemonServer::dump(int aFd, const char **aArgs, uint32_t aNumArgs)
 {
-    OT_UNUSED_VARIABLE(aArgs);
-    OT_UNUSED_VARIABLE(aNumArgs);
-
-    otCliInit(GetOtInstance(), OutputCallback, &aFd);
-
-    DumpCliCommand("state", aFd);
-    DumpCliCommand("srp server state", aFd);
-    DumpCliCommand("srp server service", aFd);
-    DumpCliCommand("srp server host", aFd);
-    DumpCliCommand("dataset activetimestamp", aFd);
-    DumpCliCommand("dataset channel", aFd);
-    DumpCliCommand("dataset channelmask", aFd);
-    DumpCliCommand("dataset extpanid", aFd);
-    DumpCliCommand("dataset meshlocalprefix", aFd);
-    DumpCliCommand("dataset networkname", aFd);
-    DumpCliCommand("dataset panid", aFd);
-    DumpCliCommand("dataset securitypolicy", aFd);
-    DumpCliCommand("leaderdata", aFd);
-    DumpCliCommand("eidcache", aFd);
-    DumpCliCommand("counters mac", aFd);
-    DumpCliCommand("counters mle", aFd);
-    DumpCliCommand("counters ip", aFd);
-    DumpCliCommand("router table", aFd);
-    DumpCliCommand("neighbor table", aFd);
-    DumpCliCommand("ipaddr -v", aFd);
-    DumpCliCommand("netdata show", aFd);
-
-    fsync(aFd);
-
-    otSysCliInitUsingDaemon(GetOtInstance());
-
-    return STATUS_OK;
+    return mAndroidHost->Dump(aFd, aArgs, aNumArgs);
 }
 
 void OtDaemonServer::PushTelemetryIfConditionMatch()
@@ -1300,31 +1245,38 @@ exit:
     return;
 }
 
-void OtDaemonServer::NotifyNat64PrefixDiscoveryDone(void)
+Status OtDaemonServer::setNat64Cidr(const std::optional<std::string>         &aCidr,
+                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    otIp6Prefix nat64Prefix{};
-    uint32_t    infraIfIndex = if_nametoindex(mInfraLinkState.interfaceName.value_or("").c_str());
-
-    otIp6PrefixFromString(mInfraLinkState.nat64Prefix.value_or("").c_str(), &nat64Prefix);
-    otPlatInfraIfDiscoverNat64PrefixDone(GetOtInstance(), infraIfIndex, &nat64Prefix);
+    mTaskRunner.Post([aCidr, aReceiver, this]() { setNat64CidrInternal(aCidr, aReceiver); });
 
-exit:
-    return;
+    return Status::ok();
 }
 
-extern "C" otError otPlatInfraIfDiscoverNat64Prefix(uint32_t aInfraIfIndex)
+void OtDaemonServer::setNat64CidrInternal(const std::optional<std::string>         &aCidr,
+                                          const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    OT_UNUSED_VARIABLE(aInfraIfIndex);
+    otError     error = OT_ERROR_NONE;
+    std::string message;
 
-    OtDaemonServer *otDaemonServer = OtDaemonServer::Get();
-    otError         error          = OT_ERROR_NONE;
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
 
-    VerifyOrExit(otDaemonServer != nullptr, error = OT_ERROR_INVALID_STATE);
+    if (aCidr.has_value())
+    {
+        otIp4Cidr nat64Cidr{};
 
-    otDaemonServer->NotifyNat64PrefixDiscoveryDone();
+        otbrLogInfo("Setting NAT64 CIDR: %s", aCidr->c_str());
+        SuccessOrExit(error = otIp4CidrFromString(aCidr->c_str(), &nat64Cidr), message = "Failed to parse NAT64 CIDR");
+        SuccessOrExit(error = otNat64SetIp4Cidr(GetOtInstance(), &nat64Cidr), message = "Failed to set NAT64 CIDR");
+    }
+    else
+    {
+        otbrLogInfo("Clearing NAT64 CIDR");
+        otNat64ClearIp4Cidr(GetOtInstance());
+    }
 
 exit:
-    return error;
+    PropagateResult(error, message, aReceiver);
 }
 
 } // namespace Android
diff --git a/src/android/otdaemon_server.hpp b/src/android/otdaemon_server.hpp
index 7578e86a..4aa7e817 100644
--- a/src/android/otdaemon_server.hpp
+++ b/src/android/otdaemon_server.hpp
@@ -33,14 +33,13 @@
 #include <memory>
 #include <vector>
 
-#include <aidl/com/android/server/thread/openthread/BnOtDaemon.h>
-#include <aidl/com/android/server/thread/openthread/INsdPublisher.h>
-#include <aidl/com/android/server/thread/openthread/IOtDaemon.h>
-#include <aidl/com/android/server/thread/openthread/InfraLinkState.h>
 #include <openthread/instance.h>
 #include <openthread/ip6.h>
 
+#include "common_utils.hpp"
 #include "agent/vendor.hpp"
+#include "android/android_thread_host.hpp"
+#include "android/common_utils.hpp"
 #include "android/mdns_publisher.hpp"
 #include "common/mainloop.hpp"
 #include "common/time.hpp"
@@ -49,29 +48,12 @@
 namespace otbr {
 namespace Android {
 
-using BinderDeathRecipient = ::ndk::ScopedAIBinder_DeathRecipient;
-using ScopedFileDescriptor = ::ndk::ScopedFileDescriptor;
-using Status               = ::ndk::ScopedAStatus;
-using aidl::android::net::thread::ChannelMaxPower;
-using aidl::com::android::server::thread::openthread::BackboneRouterState;
-using aidl::com::android::server::thread::openthread::BnOtDaemon;
-using aidl::com::android::server::thread::openthread::IChannelMasksReceiver;
-using aidl::com::android::server::thread::openthread::InfraLinkState;
-using aidl::com::android::server::thread::openthread::INsdPublisher;
-using aidl::com::android::server::thread::openthread::IOtDaemon;
-using aidl::com::android::server::thread::openthread::IOtDaemonCallback;
-using aidl::com::android::server::thread::openthread::IOtOutputReceiver;
-using aidl::com::android::server::thread::openthread::IOtStatusReceiver;
-using aidl::com::android::server::thread::openthread::Ipv6AddressInfo;
-using aidl::com::android::server::thread::openthread::MeshcopTxtAttributes;
-using aidl::com::android::server::thread::openthread::OnMeshPrefixConfig;
-using aidl::com::android::server::thread::openthread::OtDaemonConfiguration;
-using aidl::com::android::server::thread::openthread::OtDaemonState;
-
 class OtDaemonServer : public BnOtDaemon, public MainloopProcessor, public vendor::VendorServer
 {
 public:
-    OtDaemonServer(otbr::Ncp::RcpHost &rcpHost, otbr::Mdns::Publisher &mdnsPublisher, otbr::BorderAgent &borderAgent);
+    OtDaemonServer(otbr::Ncp::RcpHost    &aRcpHost,
+                   otbr::Mdns::Publisher &aMdnsPublisher,
+                   otbr::BorderAgent     &aBorderAgent);
     virtual ~OtDaemonServer(void) = default;
 
     // Disallow copy and assign.
@@ -83,8 +65,6 @@ public:
 
     static OtDaemonServer *Get(void) { return sOtDaemonServer; }
 
-    void NotifyNat64PrefixDiscoveryDone(void);
-
 private:
     using LeaveCallback = std::function<void()>;
 
@@ -99,31 +79,38 @@ private:
     void Update(MainloopContext &aMainloop) override;
     void Process(const MainloopContext &aMainloop) override;
 
+    // Creates AndroidThreadHost instance
+    std::unique_ptr<AndroidThreadHost> CreateAndroidHost(void);
+
     // Implements IOtDaemon.aidl
 
-    Status initialize(const ScopedFileDescriptor               &aTunFd,
-                      const bool                                enabled,
-                      const std::shared_ptr<INsdPublisher>     &aNsdPublisher,
+    Status initialize(const bool                                aEnabled,
+                      const OtDaemonConfiguration              &aConfiguration,
+                      const ScopedFileDescriptor               &aTunFd,
+                      const std::shared_ptr<INsdPublisher>     &aINsdPublisher,
                       const MeshcopTxtAttributes               &aMeshcopTxts,
-                      const std::shared_ptr<IOtDaemonCallback> &aCallback,
-                      const std::string                        &aCountryCode) override;
-    void   initializeInternal(const bool                                enabled,
+                      const std::string                        &aCountryCode,
+                      const bool                                aTrelEnabled,
+                      const std::shared_ptr<IOtDaemonCallback> &aCallback) override;
+    void   initializeInternal(const bool                                aEnabled,
+                              const OtDaemonConfiguration              &aConfiguration,
                               const std::shared_ptr<INsdPublisher>     &aINsdPublisher,
                               const MeshcopTxtAttributes               &aMeshcopTxts,
-                              const std::shared_ptr<IOtDaemonCallback> &aCallback,
-                              const std::string                        &aCountryCode);
+                              const std::string                        &aCountryCode,
+                              const bool                                aTrelEnabled,
+                              const std::shared_ptr<IOtDaemonCallback> &aCallback);
     Status terminate(void) override;
-    Status setThreadEnabled(const bool enabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
-    void   setThreadEnabledInternal(const bool enabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
-    Status registerStateCallback(const std::shared_ptr<IOtDaemonCallback> &aCallback, int64_t listenerId) override;
-    void   registerStateCallbackInternal(const std::shared_ptr<IOtDaemonCallback> &aCallback, int64_t listenerId);
+    Status setThreadEnabled(const bool aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   setThreadEnabledInternal(const bool aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status registerStateCallback(const std::shared_ptr<IOtDaemonCallback> &aCallback, int64_t aListenerId) override;
+    void   registerStateCallbackInternal(const std::shared_ptr<IOtDaemonCallback> &aCallback, int64_t aListenerId);
     bool   isAttached(void);
     Status join(const std::vector<uint8_t>               &aActiveOpDatasetTlvs,
                 const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
     void   joinInternal(const std::vector<uint8_t>               &aActiveOpDatasetTlvs,
                         const std::shared_ptr<IOtStatusReceiver> &aReceiver);
-    Status leave(const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
-    void   leaveInternal(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status leave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   leaveInternal(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status scheduleMigration(const std::vector<uint8_t>               &aPendingOpDatasetTlvs,
                              const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
     void   scheduleMigrationInternal(const std::vector<uint8_t>               &aPendingOpDatasetTlvs,
@@ -136,18 +123,21 @@ private:
                                        const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status setConfiguration(const OtDaemonConfiguration              &aConfiguration,
                             const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
-    void   setConfigurationInternal(const OtDaemonConfiguration              &aConfiguration,
-                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status setInfraLinkInterfaceName(const std::optional<std::string>         &aInterfaceName,
                                      const ScopedFileDescriptor               &aIcmp6Socket,
                                      const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
-    void   setInfraLinkInterfaceNameInternal(const std::string                        &aInterfaceName,
-                                             int                                       aIcmp6SocketFd,
-                                             const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status setInfraLinkNat64Prefix(const std::optional<std::string>         &aNat64Prefix,
                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
     void   setInfraLinkNat64PrefixInternal(const std::string                        &aNat64Prefix,
                                            const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status setNat64Cidr(const std::optional<std::string>         &aNat64Cidr,
+                        const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   setNat64CidrInternal(const std::optional<std::string>         &aNat64Cidr,
+                                const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status setInfraLinkDnsServers(const std::vector<std::string>           &aDnsServers,
+                                  const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    void   setInfraLinkDnsServersInternal(const std::vector<std::string>           &aDnsServers,
+                                          const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status getChannelMasks(const std::shared_ptr<IChannelMasksReceiver> &aReceiver) override;
     void   getChannelMasksInternal(const std::shared_ptr<IChannelMasksReceiver> &aReceiver);
     Status runOtCtlCommand(const std::string                        &aCommand,
@@ -156,10 +146,16 @@ private:
     void   runOtCtlCommandInternal(const std::string                        &aCommand,
                                    const bool                                aIsInteractive,
                                    const std::shared_ptr<IOtOutputReceiver> &aReceiver);
+    Status activateEphemeralKeyMode(const int64_t                             aLifetimeMillis,
+                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   activateEphemeralKeyModeInternal(const int64_t                             aLifetimeMillis,
+                                            const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status deactivateEphemeralKeyMode(const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   deactivateEphemeralKeyModeInternal(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
 
     bool        RefreshOtDaemonState(otChangedFlags aFlags);
     void        LeaveGracefully(const LeaveCallback &aReceiver);
-    void        FinishLeave(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    void        FinishLeave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     static void DetachGracefullyCallback(void *aBinderServer);
     void        DetachGracefullyCallback(void);
     static void SendMgmtPendingSetCallback(otError aResult, void *aBinderServer);
@@ -169,8 +165,6 @@ private:
     static void         AddressCallback(const otIp6AddressInfo *aAddressInfo, bool aIsAdded, void *aBinderServer);
     static void         ReceiveCallback(otMessage *aMessage, void *aBinderServer);
     void                ReceiveCallback(otMessage *aMessage);
-    static int          OtCtlCommandCallback(void *aBinderServer, const char *aFormat, va_list aArguments);
-    int                 OtCtlCommandCallback(const char *aFormat, va_list aArguments);
     void                TransmitCallback(void);
     BackboneRouterState GetBackboneRouterState(void);
     static void         HandleBackboneMulticastListenerEvent(void                                  *aBinderServer,
@@ -180,12 +174,17 @@ private:
     bool                RefreshOnMeshPrefixes();
     Ipv6AddressInfo     ConvertToAddressInfo(const otNetifAddress &aAddress);
     Ipv6AddressInfo     ConvertToAddressInfo(const otNetifMulticastAddress &aAddress);
-    void UpdateThreadEnabledState(const int aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
-    void EnableThread(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    void        UpdateThreadEnabledState(const int aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    void        EnableThread(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    static void HandleEpskcStateChanged(void *aBinderServer);
+    void        HandleEpskcStateChanged(void);
+    int         GetEphemeralKeyState(void);
+    void        NotifyStateChanged(int64_t aListenerId);
 
     static OtDaemonServer *sOtDaemonServer;
 
     otbr::Ncp::RcpHost                &mHost;
+    std::unique_ptr<AndroidThreadHost> mAndroidHost;
     MdnsPublisher                     &mMdnsPublisher;
     otbr::BorderAgent                 &mBorderAgent;
     std::shared_ptr<INsdPublisher>     mINsdPublisher;
@@ -198,13 +197,8 @@ private:
     std::shared_ptr<IOtStatusReceiver> mJoinReceiver;
     std::shared_ptr<IOtStatusReceiver> mMigrationReceiver;
     std::vector<LeaveCallback>         mLeaveCallbacks;
-    bool                               mIsOtCtlInteractiveMode;
-    bool                               mIsOtCtlOutputComplete;
-    std::shared_ptr<IOtOutputReceiver> mOtCtlOutputReceiver;
-    OtDaemonConfiguration              mConfiguration;
     std::set<OnMeshPrefixConfig>       mOnMeshPrefixes;
-    InfraLinkState                     mInfraLinkState;
-    int                                mInfraIcmp6Socket;
+    int64_t                            mEphemeralKeyExpiryMillis;
 
     static constexpr Seconds kTelemetryCheckInterval           = Seconds(600);          // 600 seconds
     static constexpr Seconds kTelemetryUploadIntervalThreshold = Seconds(60 * 60 * 12); // 12 hours
diff --git a/src/android/otdaemon_telemetry.cpp b/src/android/otdaemon_telemetry.cpp
index 166e2565..99987116 100644
--- a/src/android/otdaemon_telemetry.cpp
+++ b/src/android/otdaemon_telemetry.cpp
@@ -27,10 +27,12 @@
  */
 #include "android/otdaemon_telemetry.hpp"
 
+#include <openthread/border_agent.h>
 #include <openthread/nat64.h>
 #include <openthread/openthread-system.h>
 #include <openthread/thread.h>
 #include <openthread/thread_ftd.h>
+#include <openthread/trel.h>
 #include <openthread/platform/radio.h>
 
 #if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
@@ -225,6 +227,46 @@ void RetrieveNat64Counters(otInstance *aInstance, TelemetryData::BorderRoutingCo
     }
 }
 
+void RetrieveBorderAgentInfo(otInstance *aInstance, TelemetryData::BorderAgentInfo *aBorderAgentInfo)
+{
+    auto baCounters            = aBorderAgentInfo->mutable_border_agent_counters();
+    auto otBorderAgentCounters = *otBorderAgentGetCounters(aInstance);
+
+    baCounters->set_epskc_activations(otBorderAgentCounters.mEpskcActivations);
+    baCounters->set_epskc_deactivation_clears(otBorderAgentCounters.mEpskcDeactivationClears);
+    baCounters->set_epskc_deactivation_timeouts(otBorderAgentCounters.mEpskcDeactivationTimeouts);
+    baCounters->set_epskc_deactivation_max_attempts(otBorderAgentCounters.mEpskcDeactivationMaxAttempts);
+    baCounters->set_epskc_deactivation_disconnects(otBorderAgentCounters.mEpskcDeactivationDisconnects);
+    baCounters->set_epskc_invalid_ba_state_errors(otBorderAgentCounters.mEpskcInvalidBaStateErrors);
+    baCounters->set_epskc_invalid_args_errors(otBorderAgentCounters.mEpskcInvalidArgsErrors);
+    baCounters->set_epskc_start_secure_session_errors(otBorderAgentCounters.mEpskcStartSecureSessionErrors);
+    baCounters->set_epskc_secure_session_successes(otBorderAgentCounters.mEpskcSecureSessionSuccesses);
+    baCounters->set_epskc_secure_session_failures(otBorderAgentCounters.mEpskcSecureSessionFailures);
+    baCounters->set_epskc_commissioner_petitions(otBorderAgentCounters.mEpskcCommissionerPetitions);
+
+    baCounters->set_pskc_secure_session_successes(otBorderAgentCounters.mPskcSecureSessionSuccesses);
+    baCounters->set_pskc_secure_session_failures(otBorderAgentCounters.mPskcSecureSessionFailures);
+    baCounters->set_pskc_commissioner_petitions(otBorderAgentCounters.mPskcCommissionerPetitions);
+
+    baCounters->set_mgmt_active_get_reqs(otBorderAgentCounters.mMgmtActiveGets);
+    baCounters->set_mgmt_pending_get_reqs(otBorderAgentCounters.mMgmtPendingGets);
+}
+
+void RetrieveTrelInfo(otInstance *aInstance, TelemetryData::TrelInfo *aTrelInfo)
+{
+    auto otTrelCounters = otTrelGetCounters(aInstance);
+    auto trelCounters   = aTrelInfo->mutable_counters();
+
+    aTrelInfo->set_is_trel_enabled(otTrelIsEnabled(aInstance));
+    aTrelInfo->set_num_trel_peers(otTrelGetNumberOfPeers(aInstance));
+
+    trelCounters->set_trel_tx_packets(otTrelCounters->mTxPackets);
+    trelCounters->set_trel_tx_bytes(otTrelCounters->mTxBytes);
+    trelCounters->set_trel_tx_packets_failed(otTrelCounters->mTxFailure);
+    trelCounters->set_trel_rx_packets(otTrelCounters->mRxPackets);
+    trelCounters->set_trel_rx_bytes(otTrelCounters->mRxBytes);
+}
+
 otError RetrieveTelemetryAtom(otInstance                         *otInstance,
                               Mdns::Publisher                    *aPublisher,
                               ThreadnetworkTelemetryDataReported &telemetryDataReported,
@@ -607,8 +649,17 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
             dnsServerResponseCounters->set_name_error_count(otDnssdCounters.mNameErrorResponse);
             dnsServerResponseCounters->set_not_implemented_count(otDnssdCounters.mNotImplementedResponse);
             dnsServerResponseCounters->set_other_count(otDnssdCounters.mOtherResponse);
+            // The counters of queries, responses, failures handled by upstream DNS server.
+            dnsServerResponseCounters->set_upstream_dns_queries(otDnssdCounters.mUpstreamDnsCounters.mQueries);
+            dnsServerResponseCounters->set_upstream_dns_responses(otDnssdCounters.mUpstreamDnsCounters.mResponses);
+            dnsServerResponseCounters->set_upstream_dns_failures(otDnssdCounters.mUpstreamDnsCounters.mFailures);
 
             dnsServer->set_resolved_by_local_srp_count(otDnssdCounters.mResolvedBySrp);
+
+            dnsServer->set_upstream_dns_query_state(
+                otDnssdUpstreamQueryIsEnabled(otInstance)
+                    ? ThreadnetworkTelemetryDataReported::UPSTREAMDNS_QUERY_STATE_ENABLED
+                    : ThreadnetworkTelemetryDataReported::UPSTREAMDNS_QUERY_STATE_DISABLED);
         }
         // End of DnsServerInfo section.
 #endif // OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
@@ -703,6 +754,8 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
         // End of CoexMetrics section.
 
         RetrieveNat64State(otInstance, wpanBorderRouter);
+        RetrieveBorderAgentInfo(otInstance, wpanBorderRouter->mutable_border_agent_info());
+        RetrieveTrelInfo(otInstance, wpanBorderRouter->mutable_trel_info());
     }
 
     return error;
diff --git a/src/backbone_router/backbone_agent.hpp b/src/backbone_router/backbone_agent.hpp
index 67cb4a15..9f1d1884 100644
--- a/src/backbone_router/backbone_agent.hpp
+++ b/src/backbone_router/backbone_agent.hpp
@@ -63,7 +63,6 @@ namespace BackboneRouter {
 
 /**
  * This class implements Thread Backbone agent functionality.
- *
  */
 class BackboneAgent : private NonCopyable
 {
@@ -74,13 +73,11 @@ public:
      * This constructor intiializes the `BackboneAgent` instance.
      *
      * @param[in] aHost  The Thread controller instance.
-     *
      */
     BackboneAgent(otbr::Ncp::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName);
 
     /**
      * This method initializes the Backbone agent.
-     *
      */
     void Init(void);
 
diff --git a/src/backbone_router/constants.hpp b/src/backbone_router/constants.hpp
index 363e34c3..245710cd 100644
--- a/src/backbone_router/constants.hpp
+++ b/src/backbone_router/constants.hpp
@@ -50,7 +50,6 @@ namespace BackboneRouter {
 
 /**
  * Backbone configurations.
- *
  */
 enum
 {
diff --git a/src/backbone_router/dua_routing_manager.hpp b/src/backbone_router/dua_routing_manager.hpp
index bb4c929c..54d76998 100644
--- a/src/backbone_router/dua_routing_manager.hpp
+++ b/src/backbone_router/dua_routing_manager.hpp
@@ -60,14 +60,12 @@ namespace BackboneRouter {
 
 /**
  * This class implements the DUA routing manager.
- *
  */
 class DuaRoutingManager : private NonCopyable
 {
 public:
     /**
      * This constructor initializes a DUA routing manager instance.
-     *
      */
     explicit DuaRoutingManager(std::string aInterfaceName, std::string aBackboneInterfaceName)
         : mEnabled(false)
@@ -78,13 +76,11 @@ public:
 
     /**
      * This method enables the DUA routing manager.
-     *
      */
     void Enable(const Ip6Prefix &aDomainPrefix);
 
     /**
      * This method disables the DUA routing manager.
-     *
      */
     void Disable(void);
 
diff --git a/src/backbone_router/nd_proxy.hpp b/src/backbone_router/nd_proxy.hpp
index 92823c75..1a6690cb 100644
--- a/src/backbone_router/nd_proxy.hpp
+++ b/src/backbone_router/nd_proxy.hpp
@@ -71,14 +71,12 @@ namespace BackboneRouter {
 
 /**
  * This class implements ND Proxy manager.
- *
  */
 class NdProxyManager : public MainloopProcessor, private NonCopyable
 {
 public:
     /**
      * This constructor initializes a NdProxyManager instance.
-     *
      */
     explicit NdProxyManager(otbr::Ncp::RcpHost &aHost, std::string aBackboneInterfaceName)
         : mHost(aHost)
@@ -92,7 +90,6 @@ public:
 
     /**
      * This method initializes a ND Proxy manager instance.
-     *
      */
     void Init(void);
 
@@ -100,13 +97,11 @@ public:
      * This method enables the ND Proxy manager.
      *
      * @param[in] aDomainPrefix  The Domain Prefix.
-     *
      */
     void Enable(const Ip6Prefix &aDomainPrefix);
 
     /**
      * This method disables the ND Proxy manager.
-     *
      */
     void Disable(void);
 
@@ -119,7 +114,6 @@ public:
      * @param[in] aEvent  The Backbone Router ND Proxy event type.
      * @param[in] aDua    The Domain Unicast Address of the ND Proxy, or `nullptr` if @p `aEvent` is
      *                    `OT_BACKBONE_ROUTER_NDPROXY_CLEARED`.
-     *
      */
     void HandleBackboneRouterNdProxyEvent(otBackboneRouterNdProxyEvent aEvent, const otIp6Address *aDua);
 
@@ -127,7 +121,6 @@ public:
      * This method returns if the ND Proxy manager is enabled.
      *
      * @returns If the ND Proxy manager is enabled;
-     *
      */
     bool IsEnabled(void) const { return mIcmp6RawSock >= 0; }
 
diff --git a/src/border_agent/border_agent.cpp b/src/border_agent/border_agent.cpp
index d63c6176..47283972 100644
--- a/src/border_agent/border_agent.cpp
+++ b/src/border_agent/border_agent.cpp
@@ -83,7 +83,6 @@ static constexpr int kEpskcRandomGenLen             = 8;
 
 /**
  * Locators
- *
  */
 enum
 {
diff --git a/src/border_agent/border_agent.hpp b/src/border_agent/border_agent.hpp
index 577368af..ed9686f4 100644
--- a/src/border_agent/border_agent.hpp
+++ b/src/border_agent/border_agent.hpp
@@ -74,7 +74,6 @@ namespace otbr {
 
 /**
  * This class implements Thread border agent functionality.
- *
  */
 class BorderAgent : private NonCopyable
 {
@@ -87,7 +86,6 @@ public:
      *
      * @param[in] aHost       A reference to the Thread controller.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
-     *
      */
     BorderAgent(otbr::Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
@@ -121,7 +119,6 @@ public:
      * This method enables/disables the Border Agent.
      *
      * @param[in] aIsEnabled  Whether to enable the Border Agent.
-     *
      */
     void SetEnabled(bool aIsEnabled);
 
@@ -129,13 +126,11 @@ public:
      * This method enables/disables the Border Agent Ephemeral Key feature.
      *
      * @param[in] aIsEnabled  Whether to enable the BA Ephemeral Key feature.
-     *
      */
     void SetEphemeralKeyEnabled(bool aIsEnabled);
 
     /**
      * This method returns the Border Agent Ephemeral Key feature state.
-     *
      */
     bool GetEphemeralKeyEnabled(void) const { return mIsEphemeralKeyEnabled; }
 
@@ -143,7 +138,6 @@ public:
      * This method handles mDNS publisher's state changes.
      *
      * @param[in] aState  The state of mDNS publisher.
-     *
      */
     void HandleMdnsState(Mdns::Publisher::State aState);
 
@@ -162,7 +156,6 @@ public:
      * This method adds a callback for ephemeral key changes.
      *
      * @param[in] aCallback  The callback to receive ephemeral key changed events.
-     *
      */
     void AddEphemeralKeyChangedCallback(EphemeralKeyChangedCallback aCallback);
 
diff --git a/src/common/CMakeLists.txt b/src/common/CMakeLists.txt
index 5badd6f6..01ba2f50 100644
--- a/src/common/CMakeLists.txt
+++ b/src/common/CMakeLists.txt
@@ -49,7 +49,12 @@ add_library(otbr-common
 target_link_libraries(otbr-common
     PUBLIC otbr-config
     openthread-ftd
-    openthread-posix
     $<$<BOOL:${OTBR_FEATURE_FLAGS}>:otbr-proto>
     $<$<BOOL:${OTBR_TELEMETRY_DATA_API}>:otbr-proto>
 )
+
+target_include_directories(otbr-common
+    PUBLIC
+        ${OPENTHREAD_PROJECT_DIRECTORY}/src/posix/platform/include
+        ${OPENTHREAD_PROJECT_DIRECTORY}/src
+)
diff --git a/src/common/api_strings.hpp b/src/common/api_strings.hpp
index 30ec9b80..7093e049 100644
--- a/src/common/api_strings.hpp
+++ b/src/common/api_strings.hpp
@@ -30,7 +30,6 @@
  * @file
  * This file has helper functions to convert internal state representations
  * to string (useful for APIs).
- *
  */
 #ifndef OTBR_COMMON_API_STRINGS_HPP_
 #define OTBR_COMMON_API_STRINGS_HPP_
diff --git a/src/common/callback.hpp b/src/common/callback.hpp
index 7df19e5d..3af21d35 100644
--- a/src/common/callback.hpp
+++ b/src/common/callback.hpp
@@ -51,7 +51,6 @@ template <class T> class OnceCallback;
  *
  * Inspired by Chromium base::OnceCallback
  * (https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/base/callback.h).
- *
  */
 template <typename R, typename... Args> class OnceCallback<R(Args...)>
 {
diff --git a/src/common/code_utils.hpp b/src/common/code_utils.hpp
index ade155c0..f6d2620f 100644
--- a/src/common/code_utils.hpp
+++ b/src/common/code_utils.hpp
@@ -52,7 +52,6 @@
  *  @param[in] aAlignType  The type to align with and convert the pointer to this type.
  *
  *  @returns A pointer to aligned memory.
- *
  */
 #define OTBR_ALIGNED(aMem, aAlignType) \
     reinterpret_cast<aAlignType>(      \
@@ -74,7 +73,6 @@
  *  the status is unsuccessful.
  *
  *  @param[in] aStatus  A scalar status to be evaluated against zero (0).
- *
  */
 #define SuccessOrExit(aStatus, ...) \
     do                              \
@@ -92,7 +90,6 @@
  *
  * @param[in] aStatus   A scalar error status to be evaluated against zero (0).
  * @param[in] aMessage  A message (text string) to print on failure.
- *
  */
 #define SuccessOrDie(aStatus, aMessage)                                                   \
     do                                                                                    \
@@ -112,7 +109,6 @@
  *  @param[in] aCondition  A Boolean expression to be evaluated.
  *  @param[in] ...         An expression or block to execute when the
  *                         assertion fails.
- *
  */
 #define VerifyOrExit(aCondition, ...) \
     do                                \
@@ -130,7 +126,6 @@
  *
  * @param[in] aCondition  The condition to verify
  * @param[in] aMessage    A message (text string) to print on failure.
- *
  */
 #define VerifyOrDie(aCondition, aMessage)                                    \
     do                                                                       \
@@ -146,7 +141,6 @@
  * This macro prints the message and terminates the program.
  *
  * @param[in] aMessage    A message (text string) to print.
- *
  */
 #define DieNow(aMessage)                                                 \
     do                                                                   \
@@ -165,7 +159,6 @@
  *
  *  @param[in] ...  An optional expression or block to execute
  *                  when the assertion fails.
- *
  */
 #define ExitNow(...) \
     do               \
@@ -192,7 +185,6 @@ uint64_t ConvertOpenThreadUint64(const uint8_t *aValue);
 
 /**
  * This class makes any class that derives from it non-copyable. It is intended to be used as a private base class.
- *
  */
 class NonCopyable
 {
diff --git a/src/common/dns_utils.hpp b/src/common/dns_utils.hpp
index 13d8e8c2..4645369c 100644
--- a/src/common/dns_utils.hpp
+++ b/src/common/dns_utils.hpp
@@ -29,7 +29,6 @@
 /**
  * @file
  * This file includes DNS utilities.
- *
  */
 #ifndef OTBR_COMMON_DNS_UTILS_HPP_
 #define OTBR_COMMON_DNS_UTILS_HPP_
@@ -42,7 +41,6 @@
  * This structure represents DNS Name information.
  *
  * @sa SplitFullDnsName
- *
  */
 struct DnsNameInfo
 {
@@ -55,7 +53,6 @@ struct DnsNameInfo
      * This method returns if the DNS name is a service instance.
      *
      * @returns Whether the DNS name is a service instance.
-     *
      */
     bool IsServiceInstance(void) const { return !mInstanceName.empty(); };
 
@@ -63,7 +60,6 @@ struct DnsNameInfo
      * This method returns if the DNS name is a service.
      *
      * @returns Whether the DNS name is a service.
-     *
      */
     bool IsService(void) const { return !mServiceName.empty() && mInstanceName.empty(); }
 
@@ -71,7 +67,6 @@ struct DnsNameInfo
      * This method returns if the DNS name is a host.
      *
      * @returns Whether the DNS name is a host.
-     *
      */
     bool IsHost(void) const { return mServiceName.empty(); }
 };
@@ -84,7 +79,6 @@ struct DnsNameInfo
  * @returns A `DnsNameInfo` structure containing DNS name information.
  *
  * @sa DnsNameInfo
- *
  */
 DnsNameInfo SplitFullDnsName(const std::string &aName);
 
@@ -97,7 +91,6 @@ DnsNameInfo SplitFullDnsName(const std::string &aName);
  *
  * @retval OTBR_ERROR_NONE          Successfully split the full service name.
  * @retval OTBR_ERROR_INVALID_ARGS  If the full service name is not valid.
- *
  */
 otbrError SplitFullServiceName(const std::string &aFullName, std::string &aType, std::string &aDomain);
 
@@ -111,7 +104,6 @@ otbrError SplitFullServiceName(const std::string &aFullName, std::string &aType,
  *
  * @retval OTBR_ERROR_NONE          Successfully split the full service instance name.
  * @retval OTBR_ERROR_INVALID_ARGS  If the full service instance name is not valid.
- *
  */
 otbrError SplitFullServiceInstanceName(const std::string &aFullName,
                                        std::string       &aInstanceName,
@@ -127,7 +119,6 @@ otbrError SplitFullServiceInstanceName(const std::string &aFullName,
  *
  * @retval OTBR_ERROR_NONE          Successfully split the full host name.
  * @retval OTBR_ERROR_INVALID_ARGS  If the full host name is not valid.
- *
  */
 otbrError SplitFullHostName(const std::string &aFullName, std::string &aHostName, std::string &aDomain);
 
diff --git a/src/common/logging.cpp b/src/common/logging.cpp
index c5f70185..00dbac37 100644
--- a/src/common/logging.cpp
+++ b/src/common/logging.cpp
@@ -44,6 +44,10 @@
 #include <sys/time.h>
 #include <syslog.h>
 
+#if OTBR_ENABLE_PLATFORM_ANDROID
+#include <log/log.h>
+#endif
+
 #include <sstream>
 
 #include "common/code_utils.hpp"
@@ -87,20 +91,25 @@ void otbrLogSyslogSetEnabled(bool aEnabled)
 /** Initialize logging */
 void otbrLogInit(const char *aProgramName, otbrLogLevel aLevel, bool aPrintStderr, bool aSyslogDisable)
 {
-    const char *ident;
-
-    assert(aProgramName != nullptr);
     assert(aLevel >= OTBR_LOG_EMERG && aLevel <= OTBR_LOG_DEBUG);
-
-    ident = strrchr(aProgramName, '/');
-    ident = (ident != nullptr) ? ident + 1 : aProgramName;
-
     otbrLogSyslogSetEnabled(!aSyslogDisable);
 
+#if OTBR_ENABLE_PLATFORM_ANDROID
+    OTBR_UNUSED_VARIABLE(aProgramName);
+#else
+    assert(aProgramName != nullptr);
+
     if (!sSyslogDisabled)
     {
+        const char *ident;
+
+        ident = strrchr(aProgramName, '/');
+        ident = (ident != nullptr) ? ident + 1 : aProgramName;
+
         openlog(ident, (LOG_CONS | LOG_PID) | (aPrintStderr ? LOG_PERROR : 0), OTBR_SYSLOG_FACILITY_ID);
     }
+#endif
+
     sLevel        = aLevel;
     sDefaultLevel = sLevel;
 }
@@ -130,6 +139,38 @@ static const char *GetPrefix(const char *aLogTag)
     return prefix;
 }
 
+#if OTBR_ENABLE_PLATFORM_ANDROID
+static android_LogPriority ConvertToAndroidLogPriority(otbrLogLevel aLevel)
+{
+    android_LogPriority priority;
+
+    switch (aLevel)
+    {
+    case OTBR_LOG_EMERG:
+    case OTBR_LOG_ALERT:
+    case OTBR_LOG_CRIT:
+        priority = ANDROID_LOG_FATAL;
+        break;
+    case OTBR_LOG_ERR:
+        priority = ANDROID_LOG_ERROR;
+        break;
+    case OTBR_LOG_WARNING:
+        priority = ANDROID_LOG_WARN;
+        break;
+    case OTBR_LOG_NOTICE:
+    case OTBR_LOG_INFO:
+        priority = ANDROID_LOG_INFO;
+        break;
+    case OTBR_LOG_DEBUG:
+    default:
+        priority = ANDROID_LOG_DEBUG;
+        break;
+    }
+
+    return priority;
+}
+#endif
+
 /** log to the syslog or standard out */
 void otbrLog(otbrLogLevel aLevel, const char *aLogTag, const char *aFormat, ...)
 {
@@ -147,7 +188,12 @@ void otbrLog(otbrLogLevel aLevel, const char *aLogTag, const char *aFormat, ...)
         }
         else
         {
+#if OTBR_ENABLE_PLATFORM_ANDROID
+            __android_log_print(ConvertToAndroidLogPriority(aLevel), LOG_TAG, "%s%s: %s", sLevelString[aLevel],
+                                GetPrefix(aLogTag), buffer);
+#else
             syslog(static_cast<int>(aLevel), "%s%s: %s", sLevelString[aLevel], GetPrefix(aLogTag), buffer);
+#endif
         }
     }
 
@@ -177,7 +223,11 @@ void otbrLogvNoFilter(otbrLogLevel aLevel, const char *aFormat, va_list aArgList
     }
     else
     {
+#if OTBR_ENABLE_PLATFORM_ANDROID
+        __android_log_vprint(ConvertToAndroidLogPriority(aLevel), LOG_TAG, aFormat, aArgList);
+#else
         vsyslog(static_cast<int>(aLevel), aFormat, aArgList);
+#endif
     }
 }
 
@@ -297,3 +347,33 @@ void otbrLogDeinit(void)
 {
     closelog();
 }
+
+otLogLevel ConvertToOtLogLevel(otbrLogLevel aLevel)
+{
+    otLogLevel level;
+
+    switch (aLevel)
+    {
+    case OTBR_LOG_EMERG:
+    case OTBR_LOG_ALERT:
+    case OTBR_LOG_CRIT:
+        level = OT_LOG_LEVEL_CRIT;
+        break;
+    case OTBR_LOG_ERR:
+    case OTBR_LOG_WARNING:
+        level = OT_LOG_LEVEL_WARN;
+        break;
+    case OTBR_LOG_NOTICE:
+        level = OT_LOG_LEVEL_NOTE;
+        break;
+    case OTBR_LOG_INFO:
+        level = OT_LOG_LEVEL_INFO;
+        break;
+    case OTBR_LOG_DEBUG:
+    default:
+        level = OT_LOG_LEVEL_DEBG;
+        break;
+    }
+
+    return level;
+}
diff --git a/src/common/logging.hpp b/src/common/logging.hpp
index ad36d4f5..93f900d2 100644
--- a/src/common/logging.hpp
+++ b/src/common/logging.hpp
@@ -46,7 +46,6 @@
 
 /**
  * Logging level.
- *
  */
 typedef enum
 {
@@ -79,7 +78,6 @@ void otbrLogSetLevel(otbrLogLevel aLevel);
  * Control log to syslog.
  *
  * @param[in] aEnabled  True to enable logging to/via syslog.
- *
  */
 void otbrLogSyslogSetEnabled(bool aEnabled);
 
@@ -90,7 +88,6 @@ void otbrLogSyslogSetEnabled(bool aEnabled);
  * @param[in] aLevel          Log level of the logger.
  * @param[in] aPrintStderr    Whether to log to stderr.
  * @param[in] aSyslogDisable  Whether to disable logging to syslog.
- *
  */
 void otbrLogInit(const char *aProgramName, otbrLogLevel aLevel, bool aPrintStderr, bool aSyslogDisable);
 
@@ -100,7 +97,6 @@ void otbrLogInit(const char *aProgramName, otbrLogLevel aLevel, bool aPrintStder
  * @param[in] aLevel   Log level of the logger.
  * @param[in] aLogTag  Log tag.
  * @param[in] aFormat  Format string as in printf.
- *
  */
 void otbrLog(otbrLogLevel aLevel, const char *aLogTag, const char *aFormat, ...);
 
@@ -110,7 +106,6 @@ void otbrLog(otbrLogLevel aLevel, const char *aLogTag, const char *aFormat, ...)
  * @param[in] aLevel    Log level of the logger.
  * @param[in] aFormat   Format string as in printf.
  * @param[in] aArgList  The variable-length arguments list.
- *
  */
 void otbrLogv(otbrLogLevel aLevel, const char *aFormat, va_list aArgList);
 
@@ -120,7 +115,6 @@ void otbrLogv(otbrLogLevel aLevel, const char *aFormat, va_list aArgList);
  * @param[in] aLevel    Log level of the logger.
  * @param[in] aFormat   Format string as in printf.
  * @param[in] aArgList  The variable-length arguments list.
- *
  */
 void otbrLogvNoFilter(otbrLogLevel aLevel, const char *aFormat, va_list aArgList);
 
@@ -132,7 +126,6 @@ void otbrLogvNoFilter(otbrLogLevel aLevel, const char *aFormat, va_list aArgList
  * @param[in] aPrefix  String before dumping memory.
  * @param[in] aMemory  The pointer to the memory to be dumped.
  * @param[in] aSize    The size of memory in bytes to be dumped.
- *
  */
 void otbrDump(otbrLogLevel aLevel, const char *aLogTag, const char *aPrefix, const void *aMemory, size_t aSize);
 
@@ -142,13 +135,11 @@ void otbrDump(otbrLogLevel aLevel, const char *aLogTag, const char *aPrefix, con
  * @param[in] aError  The error code.
  *
  * @returns The string information of error.
- *
  */
 const char *otbrErrorString(otbrError aError);
 
 /**
  * This function deinitializes the logging service.
- *
  */
 void otbrLogDeinit(void);
 
@@ -161,7 +152,6 @@ void otbrLogDeinit(void);
  * @param[in] aError   The action result.
  * @param[in] aFormat  Format string as in printf.
  * @param[in] ...      Arguments for the format specification.
- *
  */
 #define otbrLogResult(aError, aFormat, ...)                                                               \
     do                                                                                                    \
@@ -177,7 +167,6 @@ void otbrLogDeinit(void);
  * Log at level emergency.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -186,7 +175,6 @@ void otbrLogDeinit(void);
  * Log at level alert.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -195,7 +183,6 @@ void otbrLogDeinit(void);
  * Log at level critical.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -204,7 +191,6 @@ void otbrLogDeinit(void);
  * Log at level error.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -213,7 +199,6 @@ void otbrLogDeinit(void);
  * Log at level warning.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -222,7 +207,6 @@ void otbrLogDeinit(void);
  * Log at level notice.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -231,7 +215,6 @@ void otbrLogDeinit(void);
  * Log at level information.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 
 /**
@@ -240,7 +223,6 @@ void otbrLogDeinit(void);
  * Log at level debug.
  *
  * @param[in] ...  Arguments for the format specification.
- *
  */
 #define otbrLogEmerg(...) otbrLog(OTBR_LOG_EMERG, OTBR_LOG_TAG, __VA_ARGS__)
 #define otbrLogAlert(...) otbrLog(OTBR_LOG_ALERT, OTBR_LOG_TAG, __VA_ARGS__)
@@ -251,4 +233,13 @@ void otbrLogDeinit(void);
 #define otbrLogInfo(...) otbrLog(OTBR_LOG_INFO, OTBR_LOG_TAG, __VA_ARGS__)
 #define otbrLogDebug(...) otbrLog(OTBR_LOG_DEBUG, OTBR_LOG_TAG, __VA_ARGS__)
 
+/**
+ * Convert otbrLogLevel to otLogLevel.
+ *
+ * @param[in] aLevel  The otbrLogLevel to convert.
+ *
+ * @return the corresponding OT log level.
+ */
+otLogLevel ConvertToOtLogLevel(otbrLogLevel aLevel);
+
 #endif // OTBR_COMMON_LOGGING_HPP_
diff --git a/src/common/mainloop.hpp b/src/common/mainloop.hpp
index 57e96026..e887ceaf 100644
--- a/src/common/mainloop.hpp
+++ b/src/common/mainloop.hpp
@@ -42,7 +42,6 @@ namespace otbr {
 
 /**
  * This type defines the context data for running a mainloop.
- *
  */
 class MainloopContext : public otSysMainloopContext
 {
@@ -55,7 +54,6 @@ public:
      * This method adds a fd to the read fd set inside the MainloopContext.
      *
      * @param[in] aFd  The fd to add.
-     *
      */
     void AddFdToReadSet(int aFd);
 
@@ -64,7 +62,6 @@ public:
      *
      * @param[in] aFd          The fd to add.
      * @param[in] aFdSetsMask  A bitmask indicating which fd sets to add.
-     *
      */
     void AddFdToSet(int aFd, uint8_t aFdSetsMask);
 };
@@ -72,7 +69,6 @@ public:
 /**
  * This abstract class defines the interface of a mainloop processor
  * which adds fds to the mainloop context and handles fds events.
- *
  */
 class MainloopProcessor
 {
@@ -85,7 +81,6 @@ public:
      * This method updates the mainloop context.
      *
      * @param[in,out] aMainloop  A reference to the mainloop to be updated.
-     *
      */
     virtual void Update(MainloopContext &aMainloop) = 0;
 
@@ -93,7 +88,6 @@ public:
      * This method processes mainloop events.
      *
      * @param[in] aMainloop  A reference to the mainloop context.
-     *
      */
     virtual void Process(const MainloopContext &aMainloop) = 0;
 };
diff --git a/src/common/mainloop_manager.hpp b/src/common/mainloop_manager.hpp
index 739d9de4..f379e2df 100644
--- a/src/common/mainloop_manager.hpp
+++ b/src/common/mainloop_manager.hpp
@@ -48,20 +48,17 @@ namespace otbr {
 
 /**
  * This class implements the mainloop manager.
- *
  */
 class MainloopManager : private NonCopyable
 {
 public:
     /**
      * The constructor to initialize the mainloop manager.
-     *
      */
     MainloopManager() = default;
 
     /**
      * This method returns the singleton instance of the mainloop manager.
-     *
      */
     static MainloopManager &GetInstance(void)
     {
@@ -73,7 +70,6 @@ public:
      * This method adds a mainloop processors to the mainloop managger.
      *
      * @param[in] aMainloopProcessor  A pointer to the mainloop processor.
-     *
      */
     void AddMainloopProcessor(MainloopProcessor *aMainloopProcessor);
 
@@ -81,7 +77,6 @@ public:
      * This method removes a mainloop processors from the mainloop managger.
      *
      * @param[in] aMainloopProcessor  A pointer to the mainloop processor.
-     *
      */
     void RemoveMainloopProcessor(MainloopProcessor *aMainloopProcessor);
 
@@ -89,7 +84,6 @@ public:
      * This method updates the mainloop context of all mainloop processors.
      *
      * @param[in,out] aMainloop  A reference to the mainloop to be updated.
-     *
      */
     void Update(MainloopContext &aMainloop);
 
@@ -97,7 +91,6 @@ public:
      * This method processes mainloop events of all mainloop processors.
      *
      * @param[in] aMainloop  A reference to the mainloop context.
-     *
      */
     void Process(const MainloopContext &aMainloop);
 
diff --git a/src/common/task_runner.hpp b/src/common/task_runner.hpp
index 1e72e807..f56d613d 100644
--- a/src/common/task_runner.hpp
+++ b/src/common/task_runner.hpp
@@ -52,14 +52,12 @@ namespace otbr {
 /**
  * This class implements the Task Runner that executes
  * tasks on the mainloop.
- *
  */
 class TaskRunner : public MainloopProcessor, private NonCopyable
 {
 public:
     /**
      * This type represents the generic executable task.
-     *
      */
     template <class T> using Task = std::function<T(void)>;
 
@@ -67,19 +65,16 @@ public:
      * This type represents a unique task ID to an delayed task.
      *
      * Note: A valid task ID is never zero.
-     *
      */
     typedef uint64_t TaskId;
 
     /**
      * This constructor initializes the Task Runner instance.
-     *
      */
     TaskRunner(void);
 
     /**
      * This destructor destroys the Task Runner instance.
-     *
      */
     ~TaskRunner(void) override;
 
@@ -90,7 +85,6 @@ public:
      * It is safe to call this method in different threads concurrently.
      *
      * @param[in] aTask  The task to be executed.
-     *
      */
     void Post(Task<void> aTask);
 
@@ -104,7 +98,6 @@ public:
      * @param[in] aTask   The task to be executed.
      *
      * @returns  The unique task ID of the delayed task.
-     *
      */
     TaskId Post(Milliseconds aDelay, Task<void> aTask);
 
@@ -113,7 +106,6 @@ public:
      * It is safe to call this method in different threads concurrently.
      *
      * @param[in] aTaskId  The unique task ID of the delayed task to cancel.
-     *
      */
     void Cancel(TaskId aTaskId);
 
@@ -125,7 +117,6 @@ public:
      * the caller will be blocked forever.
      *
      * @returns The result returned by the task @p aTask.
-     *
      */
     template <class T> T PostAndWait(const Task<T> &aTask)
     {
diff --git a/src/common/tlv.hpp b/src/common/tlv.hpp
index 16bc00ad..ade73b71 100644
--- a/src/common/tlv.hpp
+++ b/src/common/tlv.hpp
@@ -43,7 +43,6 @@ namespace otbr {
 
 /**
  * This class implements TMF Tlv functionality.
- *
  */
 class Tlv
 {
@@ -57,13 +56,11 @@ public:
      * This method returns the Tlv type.
      *
      * @returns The Tlv type.
-     *
      */
     uint8_t GetType(void) const { return mType; }
 
     /**
      * This method sets the Tlv type.
-     *
      */
     void SetType(uint8_t aType) { mType = aType; }
 
@@ -71,7 +68,6 @@ public:
      * This method returns the Tlv length.
      *
      * @returns The Tlv length.
-     *
      */
     uint16_t GetLength(void) const
     {
@@ -99,7 +95,6 @@ public:
      * This method returns a pointer to the value.
      *
      * @returns The Tlv value.
-     *
      */
     const void *GetValue(void) const
     {
@@ -111,7 +106,6 @@ public:
      * This method returns the value as a uint16_t.
      *
      * @returns The uint16_t value.
-     *
      */
     uint16_t GetValueUInt16(void) const
     {
@@ -124,7 +118,6 @@ public:
      * This method returns the value as a uint8_t.
      *
      * @returns The uint8_t value.
-     *
      */
     uint8_t GetValueUInt8(void) const { return *static_cast<const uint8_t *>(GetValue()); }
 
@@ -132,7 +125,6 @@ public:
      * This method sets a uint64_t as the value.
      *
      * @param[in] aValue  The uint64_t value.
-     *
      */
     void SetValue(uint64_t aValue)
     {
@@ -150,7 +142,6 @@ public:
      * This method sets a uint32_t as the value.
      *
      * @param[in] aValue  The uint32_t value.
-     *
      */
     void SetValue(uint32_t aValue)
     {
@@ -168,7 +159,6 @@ public:
      * This method sets uint16_t as the value.
      *
      * @param[in] aValue  The uint16_t value.
-     *
      */
     void SetValue(uint16_t aValue)
     {
@@ -184,7 +174,6 @@ public:
      * This method sets uint8_t as the value.
      *
      * @param[in] aValue  The uint8_t value.
-     *
      */
     void SetValue(uint8_t aValue)
     {
@@ -196,7 +185,6 @@ public:
      * This method sets int8_t as the value.
      *
      * @param[in] aValue  The int8_t value.
-     *
      */
     void SetValue(int8_t aValue)
     {
@@ -217,7 +205,6 @@ public:
      * This method returns the pointer to the next Tlv.
      *
      * @returns A pointer to the next Tlv.
-     *
      */
     const Tlv *GetNext(void) const
     {
@@ -228,7 +215,6 @@ public:
      * This method returns the pointer to the next Tlv.
      *
      * @returns A pointer to the next Tlv.
-     *
      */
     Tlv *GetNext(void) { return reinterpret_cast<Tlv *>(static_cast<uint8_t *>(GetValue()) + GetLength()); }
 
diff --git a/src/common/types.hpp b/src/common/types.hpp
index c9cb2d07..a102a9eb 100644
--- a/src/common/types.hpp
+++ b/src/common/types.hpp
@@ -50,7 +50,6 @@
 #ifndef IN6ADDR_ANY
 /**
  * Any IPv6 address literal.
- *
  */
 #define IN6ADDR_ANY "::"
 #endif
@@ -63,7 +62,6 @@
 
 /**
  * Forward declaration for otIp6Prefix to avoid including <openthread/ip6.h>
- *
  */
 struct otIp6Prefix;
 
@@ -107,14 +105,12 @@ static constexpr char kLinkLocalAllNodesMulticastAddress[] = "ff02::01";
 
 /**
  * This class implements the Ipv6 address functionality.
- *
  */
 class Ip6Address
 {
 public:
     /**
      * Default constructor.
-     *
      */
     Ip6Address(void)
     {
@@ -126,7 +122,6 @@ public:
      * Constructor with an 16-bit Thread locator.
      *
      * @param[in] aLocator  The 16-bit Thread locator, RLOC or ALOC.
-     *
      */
     Ip6Address(uint16_t aLocator)
     {
@@ -141,7 +136,6 @@ public:
      * Constructor with an Ip6 address.
      *
      * @param[in] aAddress  The Ip6 address.
-     *
      */
     Ip6Address(const uint8_t (&aAddress)[16]);
 
@@ -149,7 +143,6 @@ public:
      * Constructor with an otIp6Address.
      *
      * @param[in] aAddress  A const reference to an otIp6Address.
-     *
      */
     explicit Ip6Address(const otIp6Address &aAddress);
 
@@ -157,7 +150,6 @@ public:
      * Constructor with a string.
      *
      * @param[in] aString The string representing the IPv6 address.
-     *
      */
     Ip6Address(const char *aString) { FromString(aString, *this); }
 
@@ -167,7 +159,6 @@ public:
      * @param[in] aOther  The other Ip6 address to compare with.
      *
      * @returns Whether the Ip6 address is smaller than the other address.
-     *
      */
     bool operator<(const Ip6Address &aOther) const { return memcmp(this, &aOther, sizeof(Ip6Address)) < 0; }
 
@@ -177,7 +168,6 @@ public:
      * @param[in] aOther  The other Ip6 address to compare with.
      *
      * @returns Whether the Ip6 address is equal to the other address.
-     *
      */
     bool operator==(const Ip6Address &aOther) const { return m64[0] == aOther.m64[0] && m64[1] == aOther.m64[1]; }
 
@@ -187,7 +177,6 @@ public:
      * @param[in] aOther  The other Ip6 address to compare with.
      *
      * @returns Whether the Ip6 address is NOT equal to the other address.
-     *
      */
     bool operator!=(const Ip6Address &aOther) const { return !(*this == aOther); }
 
@@ -195,7 +184,6 @@ public:
      * Retrieve the 16-bit Thread locator.
      *
      * @returns RLOC16 or ALOC16.
-     *
      */
     uint16_t ToLocator(void) const { return static_cast<uint16_t>(m8[14] << 8 | m8[15]); }
 
@@ -203,7 +191,6 @@ public:
      * This method returns the solicited node multicast address.
      *
      * @returns The solicited node multicast address.
-     *
      */
     Ip6Address ToSolicitedNodeMulticastAddress(void) const;
 
@@ -211,7 +198,6 @@ public:
      * This method returns the string representation for the Ip6 address.
      *
      * @returns The string representation of the Ip6 address.
-     *
      */
     std::string ToString(void) const;
 
@@ -220,7 +206,6 @@ public:
      *
      * @retval TRUE   If the Ip6 address is the Unspecified Address.
      * @retval FALSE  If the Ip6 address is not the Unspecified Address.
-     *
      */
     bool IsUnspecified(void) const { return m64[0] == 0 && m64[1] == 0; }
 
@@ -228,7 +213,6 @@ public:
      * This method returns if the Ip6 address is a multicast address.
      *
      * @returns Whether the Ip6 address is a multicast address.
-     *
      */
     bool IsMulticast(void) const { return m8[0] == 0xff; }
 
@@ -236,7 +220,6 @@ public:
      * This method returns if the Ip6 address is a link-local address.
      *
      * @returns Whether the Ip6 address is a link-local address.
-     *
      */
     bool IsLinkLocal(void) const { return (m16[0] & bswap_16(0xffc0)) == bswap_16(0xfe80); }
 
@@ -245,7 +228,6 @@ public:
      *
      * @retval TRUE   If the Ip6 address is the Loopback Address.
      * @retval FALSE  If the Ip6 address is not the Loopback Address.
-     *
      */
     bool IsLoopback(void) const { return (m32[0] == 0 && m32[1] == 0 && m32[2] == 0 && m32[3] == htobe32(1)); }
 
@@ -253,7 +235,6 @@ public:
      * This function returns the wellknown Link Local All Nodes Multicast Address (ff02::1).
      *
      * @returns The Link Local All Nodes Multicast Address.
-     *
      */
     static const Ip6Address &GetLinkLocalAllNodesMulticastAddress(void)
     {
@@ -266,7 +247,6 @@ public:
      * This function returns the wellknown Solicited Node Multicast Address Prefix (ff02::01:ff00:0).
      *
      * @returns The Solicited Node Multicast Address Prefix.
-     *
      */
     static const Ip6Address &GetSolicitedMulticastAddressPrefix(void)
     {
@@ -283,7 +263,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE          If the Ip6 address was successfully converted.
      * @retval OTBR_ERROR_INVALID_ARGS  If @p `aStr` is not a valid string representing of Ip6 address.
-     *
      */
     static otbrError FromString(const char *aStr, Ip6Address &aAddr);
 
@@ -291,7 +270,6 @@ public:
      * This method copies the Ip6 address to a `sockaddr_in6` structure.
      *
      * @param[out] aSockAddr  The `sockaddr_in6` structure to copy the Ip6 address to.
-     *
      */
     void CopyTo(struct sockaddr_in6 &aSockAddr) const;
 
@@ -299,7 +277,6 @@ public:
      * This method copies the Ip6 address from a `sockaddr_in6` structure.
      *
      * @param[in] aSockAddr  The `sockaddr_in6` structure to copy the Ip6 address from.
-     *
      */
     void CopyFrom(const struct sockaddr_in6 &aSockAddr);
 
@@ -307,7 +284,6 @@ public:
      * This method copies the Ip6 address to a `in6_addr` structure.
      *
      * @param[out] aIn6Addr  The `in6_addr` structure to copy the Ip6 address to.
-     *
      */
     void CopyTo(struct in6_addr &aIn6Addr) const;
 
@@ -315,7 +291,6 @@ public:
      * This method copies the Ip6 address from a `in6_addr` structure.
      *
      * @param[in] aIn6Addr  The `in6_addr` structure to copy the Ip6 address from.
-     *
      */
     void CopyFrom(const struct in6_addr &aIn6Addr);
 
@@ -333,14 +308,12 @@ private:
 
 /**
  * This class represents a Ipv6 prefix.
- *
  */
 class Ip6Prefix
 {
 public:
     /**
      * Default constructor.
-     *
      */
     Ip6Prefix(void) { Clear(); }
 
@@ -349,7 +322,6 @@ public:
      *
      * @param[in] aIp6AddrStr The IPv6 address string.
      * @param[in] aLength     The prefix length.
-     *
      */
     Ip6Prefix(const char *aIp6AddrStr, uint8_t aLength)
         : mPrefix(aIp6AddrStr)
@@ -367,7 +339,6 @@ public:
      * @param[in] aOther The Ip6Prefix object to compare with.
      *
      * @returns True if the two objects are equal, false otherwise.
-     *
      */
     bool operator==(const Ip6Prefix &aOther) const;
 
@@ -377,7 +348,6 @@ public:
      * @param[in] aOther The Ip6Prefix object to compare with.
      *
      * @returns True if the two objects are NOT equal, false otherwise.
-     *
      */
     bool operator!=(const Ip6Prefix &aOther) const;
 
@@ -385,7 +355,6 @@ public:
      * This method sets the Ip6 prefix to an `otIp6Prefix` value.
      *
      * @param[in] aPrefix  The `otIp6Prefix` value to set the Ip6 prefix.
-     *
      */
     void Set(const otIp6Prefix &aPrefix);
 
@@ -393,13 +362,11 @@ public:
      * This method returns the string representation for the Ip6 prefix.
      *
      * @returns The string representation of the Ip6 prefix.
-     *
      */
     std::string ToString(void) const;
 
     /**
      * This method clears the Ip6 prefix to be unspecified.
-     *
      */
     void Clear(void) { memset(reinterpret_cast<void *>(this), 0, sizeof(*this)); }
 
@@ -407,7 +374,6 @@ public:
      * This method returns if the Ip6 prefix is valid.
      *
      * @returns If the Ip6 prefix is valid.
-     *
      */
     bool IsValid(void) const { return mLength > 0 && mLength <= 128; }
 
@@ -415,7 +381,6 @@ public:
      * This method checks if the object is the default route prefix ("::/0")
      *
      * @returns true if the object is the default route prefix, false otherwise.
-     *
      */
     bool IsDefaultRoutePrefix(void) const { return (*this == Ip6Prefix("::", 0)); }
 
@@ -423,7 +388,6 @@ public:
      * This method checks if the object is the ULA prefix ("fc00::/7")
      *
      * @returns true if the object is the ULA prefix, false otherwise.
-     *
      */
     bool IsUlaPrefix(void) const { return (*this == Ip6Prefix("fc00::", 7)); }
 
@@ -433,7 +397,6 @@ public:
 
 /**
  * This class represents a Ipv6 address and its info.
- *
  */
 class Ip6AddressInfo
 {
@@ -472,7 +435,6 @@ class MacAddress
 public:
     /**
      * Default constructor.
-     *
      */
     MacAddress(void)
     {
@@ -485,7 +447,6 @@ public:
      * This method returns the string representation for the MAC address.
      *
      * @returns The string representation of the MAC address.
-     *
      */
     std::string ToString(void) const;
 
@@ -540,7 +501,6 @@ static constexpr size_t kMaxProductNameLength = 24;
  * @param[in]  aError  a otbrError code.
  *
  * @returns  a otError code.
- *
  */
 otError OtbrErrorToOtError(otbrError aError);
 
diff --git a/src/dbus/client/client_error.hpp b/src/dbus/client/client_error.hpp
index 7f499bdc..8a0363d0 100644
--- a/src/dbus/client/client_error.hpp
+++ b/src/dbus/client/client_error.hpp
@@ -52,7 +52,6 @@ namespace DBus {
  *
  * @returns The corresponding otError. OT_ERROR_GENERIC will be returned
  *          if the error name is not defined in OpenThread.
- *
  */
 ClientError ConvertFromDBusErrorName(const std::string &aErrorName);
 
@@ -62,7 +61,6 @@ ClientError ConvertFromDBusErrorName(const std::string &aErrorName);
  * @param[in] aMessage  The dbus reply message.
  *
  * @returns The error code encoded in the message.
- *
  */
 ClientError CheckErrorMessage(DBusMessage *aMessage);
 
diff --git a/src/dbus/client/thread_api_dbus.hpp b/src/dbus/client/thread_api_dbus.hpp
index d881f4e9..e817e525 100644
--- a/src/dbus/client/thread_api_dbus.hpp
+++ b/src/dbus/client/thread_api_dbus.hpp
@@ -64,7 +64,6 @@ public:
      * Will use the default interfacename
      *
      * @param[in] aConnection  The dbus connection.
-     *
      */
     ThreadApiDBus(DBusConnection *aConnection);
 
@@ -73,7 +72,6 @@ public:
      *
      * @param[in] aConnection     The dbus connection.
      * @param[in] aInterfaceName  The network interface name.
-     *
      */
     ThreadApiDBus(DBusConnection *aConnection, const std::string &aInterfaceName);
 
@@ -81,7 +79,6 @@ public:
      * This method adds a callback for device role change.
      *
      * @param[in] aHandler  The device role handler.
-     *
      */
     void AddDeviceRoleHandler(const DeviceRoleHandler &aHandler);
 
@@ -94,7 +91,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError PermitUnsecureJoin(uint16_t aPort, uint32_t aSeconds);
 
@@ -106,7 +102,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError Scan(const ScanHandler &aHandler);
 
@@ -121,7 +116,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError EnergyScan(uint32_t aScanDuration, const EnergyScanHandler &aHandler);
 
@@ -138,7 +132,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError Attach(const std::string          &aNetworkName,
                        uint16_t                    aPanId,
@@ -159,7 +152,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError Attach(const OtResultHandler &aHandler);
 
@@ -169,7 +161,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError Detach(const OtResultHandler &aHandler);
 
@@ -188,7 +179,6 @@ public:
      * @retval OT_ERROR_INVALID_STATE  The device is attaching.
      * @retval OT_ERROR_INVALID_ARGS   Arguments are invalid.
      * @retval OT_ERROR_BUSY           There is an ongoing request.
-     *
      */
     ClientError AttachAllNodesTo(const std::vector<uint8_t> &aDataset);
 
@@ -200,7 +190,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError FactoryReset(const OtResultHandler &aHandler);
 
@@ -210,7 +199,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError Reset(void);
 
@@ -230,7 +218,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError JoinerStart(const std::string     &aPskd,
                             const std::string     &aProvisioningUrl,
@@ -246,7 +233,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError JoinerStop(void);
 
@@ -258,7 +244,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError AddOnMeshPrefix(const OnMeshPrefix &aPrefix);
 
@@ -270,7 +255,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError RemoveOnMeshPrefix(const Ip6Prefix &aPrefix);
 
@@ -282,7 +266,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError AddExternalRoute(const ExternalRoute &aExternalRoute);
 
@@ -294,7 +277,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError RemoveExternalRoute(const Ip6Prefix &aPrefix);
 
@@ -306,7 +288,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetMeshLocalPrefix(const std::array<uint8_t, OTBR_IP6_PREFIX_SIZE> &aPrefix);
 
@@ -318,7 +299,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetActiveDatasetTlvs(const std::vector<uint8_t> &aDataset);
 
@@ -331,7 +311,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetFeatureFlagListData(const std::vector<uint8_t> &aFeatureFlagListData);
 
@@ -343,7 +322,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetLinkMode(const LinkModeConfig &aConfig);
 
@@ -355,7 +333,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetRadioRegion(const std::string &aRadioRegion);
 
@@ -367,7 +344,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetNat64Enabled(bool aEnabled);
 
@@ -379,7 +355,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError SetEphemeralKeyEnabled(bool aEnabled);
 
@@ -391,7 +366,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetEphemeralKeyEnabled(bool &aEnabled);
 
@@ -403,7 +377,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetLinkMode(LinkModeConfig &aConfig);
 
@@ -415,7 +388,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetDeviceRole(DeviceRole &aDeviceRole);
 
@@ -427,7 +399,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNetworkName(std::string &aName);
 
@@ -439,7 +410,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetPanId(uint16_t &aPanId);
 
@@ -451,7 +421,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetExtPanId(uint64_t &aExtPanId);
 
@@ -463,7 +432,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetChannel(uint16_t &aChannel);
 
@@ -475,7 +443,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNetworkKey(std::vector<uint8_t> &aNetworkKey);
 
@@ -487,7 +454,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetCcaFailureRate(uint16_t &aFailureRate);
 
@@ -499,7 +465,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetLinkCounters(MacCounters &aCounters); // For telemetry
 
@@ -511,7 +476,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetIp6Counters(IpCounters &aCounters); // For telemetry
 
@@ -523,7 +487,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetSupportedChannelMask(uint32_t &aChannelMask);
 
@@ -535,7 +498,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetPreferredChannelMask(uint32_t &aChannelMask);
 
@@ -547,7 +509,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetRloc16(uint16_t &aRloc16);
 
@@ -559,7 +520,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetExtendedAddress(uint64_t &aExtendedAddress);
 
@@ -572,7 +532,6 @@ public:
      * @retval ERROR_DBUS              dbus encode/decode error.
      * @retval OT_ERROR_INVALID_STATE  The node is not a router.
      * @retval ...                     OpenThread defined error value otherwise.
-     *
      */
     ClientError GetRouterId(uint8_t &aRouterId);
 
@@ -584,7 +543,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetLeaderData(LeaderData &aLeaderData);
 
@@ -596,7 +554,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNetworkData(std::vector<uint8_t> &aNetworkData);
 
@@ -608,7 +565,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetStableNetworkData(std::vector<uint8_t> &aNetworkData);
 
@@ -620,7 +576,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetLocalLeaderWeight(uint8_t &aWeight);
 
@@ -632,7 +587,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetChannelMonitorSampleCount(uint32_t &aSampleCount);
 
@@ -644,7 +598,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetChannelMonitorAllChannelQualities(std::vector<ChannelQuality> &aChannelQualities);
 
@@ -656,7 +609,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetChildTable(std::vector<ChildInfo> &aChildTable);
 
@@ -668,7 +620,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNeighborTable(std::vector<NeighborInfo> &aNeighborTable);
 
@@ -680,7 +631,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetPartitionId(uint32_t &aPartitionId);
 
@@ -692,7 +642,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetInstantRssi(int8_t &aRssi);
 
@@ -704,7 +653,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetRadioTxPower(int8_t &aTxPower);
 
@@ -716,7 +664,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetExternalRoutes(std::vector<ExternalRoute> &aExternalRoutes);
 
@@ -728,7 +675,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetOnMeshPrefixes(std::vector<OnMeshPrefix> &aOnMeshPrefixes);
 
@@ -740,7 +686,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetActiveDatasetTlvs(std::vector<uint8_t> &aDataset);
 
@@ -752,7 +697,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetPendingDatasetTlvs(std::vector<uint8_t> &aDataset);
 
@@ -765,7 +709,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetFeatureFlagListData(std::vector<uint8_t> &aFeatureFlagListData);
 
@@ -777,7 +720,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetRadioRegion(std::string &aRadioRegion);
 
@@ -789,7 +731,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetSrpServerInfo(SrpServerInfo &aSrpServerInfo);
 
@@ -802,7 +743,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetTrelInfo(TrelInfo &aTrelInfo);
 #endif
@@ -815,7 +755,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetMdnsTelemetryInfo(MdnsTelemetryInfo &aMdnsTelemetryInfo);
 
@@ -828,7 +767,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetDnssdCounters(DnssdCounters &aDnssdCounters);
 #endif
@@ -837,7 +775,6 @@ public:
      * This method returns the network interface name the client is bound to.
      *
      * @returns The network interface name.
-     *
      */
     std::string GetInterfaceName(void);
 
@@ -856,7 +793,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError UpdateVendorMeshCopTxtEntries(std::vector<TxtEntry> &aUpdate);
 
@@ -868,7 +804,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNat64State(Nat64ComponentState &aState);
 
@@ -880,7 +815,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNat64Mappings(std::vector<Nat64AddressMapping> &aMappings);
 
@@ -892,7 +826,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNat64ProtocolCounters(Nat64ProtocolCounters &aCounters);
 
@@ -904,7 +837,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetNat64ErrorCounters(Nat64ErrorCounters &aCounters);
 
@@ -917,7 +849,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetTelemetryData(std::vector<uint8_t> &aTelemetryData);
 
@@ -930,7 +861,6 @@ public:
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
      * @retval ...         OpenThread defined error value otherwise
-     *
      */
     ClientError GetCapabilities(std::vector<uint8_t> &aCapabilities);
 
diff --git a/src/dbus/common/error.hpp b/src/dbus/common/error.hpp
index 8b7a2239..7d853d74 100644
--- a/src/dbus/common/error.hpp
+++ b/src/dbus/common/error.hpp
@@ -46,7 +46,6 @@ namespace otbr {
  * @namespace otbr::DBus
  *
  * @brief This namespace contains OpenThread Border Router DBus API.
- *
  */
 namespace DBus {
 
diff --git a/src/dbus/common/types.hpp b/src/dbus/common/types.hpp
index 94687e05..3c427bf6 100644
--- a/src/dbus/common/types.hpp
+++ b/src/dbus/common/types.hpp
@@ -193,7 +193,6 @@ struct ExternalRoute
 
 /**
  * This structure represents the MAC layer counters.
- *
  */
 struct MacCounters
 {
@@ -220,61 +219,51 @@ struct MacCounters
      *     @p mTxTotal = @p mTxUnicast + @p mTxBroadcast
      *     @p mTxTotal = @p mTxAckRequested + @p mTxNoAckRequested
      *     @p mTxTotal = @p mTxData + @p mTxDataPoll + @p mTxBeacon + @p mTxBeaconRequest + @p mTxOther
-     *
      */
     uint32_t mTxTotal;
 
     /**
      * The total number of unique unicast MAC frame transmission requests.
-     *
      */
     uint32_t mTxUnicast;
 
     /**
      * The total number of unique broadcast MAC frame transmission requests.
-     *
      */
     uint32_t mTxBroadcast;
 
     /**
      * The total number of unique MAC frame transmission requests with requested acknowledgment.
-     *
      */
     uint32_t mTxAckRequested;
 
     /**
      * The total number of unique MAC frame transmission requests that were acked.
-     *
      */
     uint32_t mTxAcked;
 
     /**
      * The total number of unique MAC frame transmission requests without requested acknowledgment.
-     *
      */
     uint32_t mTxNoAckRequested;
 
     /**
      * The total number of unique MAC Data frame transmission requests.
-     *
      */
     uint32_t mTxData;
 
     /**
      * The total number of unique MAC Data Poll frame transmission requests.
-     *
      */
     uint32_t mTxDataPoll;
 
     /**
      * The total number of unique MAC Beacon frame transmission requests.
-     *
      */
     uint32_t mTxBeacon;
 
     /**
      * The total number of unique MAC Beacon Request frame transmission requests.
-     *
      */
     uint32_t mTxBeaconRequest;
 
@@ -282,7 +271,6 @@ struct MacCounters
      * The total number of unique other MAC frame transmission requests.
      *
      * This counter is currently unused.
-     *
      */
     uint32_t mTxOther;
 
@@ -302,19 +290,16 @@ struct MacCounters
      *
      * Currently, this counter is invalid if the platform's radio driver capability includes
      * @sa OT_RADIO_CAPS_TRANSMIT_RETRIES.
-     *
      */
     uint32_t mTxRetry;
 
     /**
      * The total number of unique MAC transmission packets that meet maximal retry limit for direct packets.
-     *
      */
     uint32_t mTxDirectMaxRetryExpiry;
 
     /**
      * The total number of unique MAC transmission packets that meet maximal retry limit for indirect packets.
-     *
      */
     uint32_t mTxIndirectMaxRetryExpiry;
 
@@ -329,19 +314,16 @@ struct MacCounters
      * If @sa OT_RADIO_CAPS_TRANSMIT_RETRIES is enabled, this counter represents the total number of full CSMA/CA
      * failed attempts and it is incremented by one for each individual data frame request (regardless of the amount of
      * retransmissions).
-     *
      */
     uint32_t mTxErrCca;
 
     /**
      * The total number of unique MAC transmission request failures cause by an abort error.
-     *
      */
     uint32_t mTxErrAbort;
 
     /**
      * The total number of unique MAC transmission requests failures caused by a busy channel (a CSMA/CA fail).
-     *
      */
     uint32_t mTxErrBusyChannel;
 
@@ -350,61 +332,51 @@ struct MacCounters
      *
      * This counter counts all frames reported by the platform's radio driver, including frames
      * that were dropped, for example because of an FCS error.
-     *
      */
     uint32_t mRxTotal;
 
     /**
      * The total number of unicast frames received.
-     *
      */
     uint32_t mRxUnicast;
 
     /**
      * The total number of broadcast frames received.
-     *
      */
     uint32_t mRxBroadcast;
 
     /**
      * The total number of MAC Data frames received.
-     *
      */
     uint32_t mRxData;
 
     /**
      * The total number of MAC Data Poll frames received.
-     *
      */
     uint32_t mRxDataPoll;
 
     /**
      * The total number of MAC Beacon frames received.
-     *
      */
     uint32_t mRxBeacon;
 
     /**
      * The total number of MAC Beacon Request frames received.
-     *
      */
     uint32_t mRxBeaconRequest;
 
     /**
      * The total number of other types of frames received.
-     *
      */
     uint32_t mRxOther;
 
     /**
      * The total number of frames dropped by MAC Filter module, for example received from denylisted node.
-     *
      */
     uint32_t mRxAddressFiltered;
 
     /**
      * The total number of frames dropped by destination address check, for example received frame for other node.
-     *
      */
     uint32_t mRxDestAddrFiltered;
 
@@ -413,25 +385,21 @@ struct MacCounters
      *
      * This counter may be incremented, for example when ACK frame generated by the receiver hasn't reached
      * transmitter node which performed retransmission.
-     *
      */
     uint32_t mRxDuplicated;
 
     /**
      * The total number of frames dropped because of missing or malformed content.
-     *
      */
     uint32_t mRxErrNoFrame;
 
     /**
      * The total number of frames dropped due to unknown neighbor.
-     *
      */
     uint32_t mRxErrUnknownNeighbor;
 
     /**
      * The total number of frames dropped due to invalid source address.
-     *
      */
     uint32_t mRxErrInvalidSrcAddr;
 
@@ -440,19 +408,16 @@ struct MacCounters
      *
      * This counter may be incremented, for example when lower than expected Frame Counter is used
      * to encrypt the frame.
-     *
      */
     uint32_t mRxErrSec;
 
     /**
      * The total number of frames dropped due to invalid FCS.
-     *
      */
     uint32_t mRxErrFcs;
 
     /**
      * The total number of frames dropped due to other error.
-     *
      */
     uint32_t mRxErrOther;
 };
diff --git a/src/dbus/server/dbus_agent.hpp b/src/dbus/server/dbus_agent.hpp
index 7825ddc7..cd6793ef 100644
--- a/src/dbus/server/dbus_agent.hpp
+++ b/src/dbus/server/dbus_agent.hpp
@@ -61,13 +61,11 @@ public:
      *
      * @param[in] aHost           A reference to the Thread host.
      * @param[in] aPublisher      A reference to the MDNS publisher.
-     *
      */
     DBusAgent(otbr::Ncp::ThreadHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method initializes the dbus agent.
-     *
      */
     void Init(otbr::BorderAgent &aBorderAgent);
 
@@ -94,7 +92,6 @@ private:
 
     /**
      * This map is used to track DBusWatch-es.
-     *
      */
     std::set<DBusWatch *> mWatches;
 };
diff --git a/src/dbus/server/dbus_object.hpp b/src/dbus/server/dbus_object.hpp
index f1a628bb..d77f0450 100644
--- a/src/dbus/server/dbus_object.hpp
+++ b/src/dbus/server/dbus_object.hpp
@@ -60,7 +60,6 @@ namespace DBus {
 
 /**
  * This class is a base class for implementing a d-bus object.
- *
  */
 class DBusObject : private NonCopyable
 {
@@ -74,7 +73,6 @@ public:
      *
      * @param[in] aConnection  The dbus-connection the object bounds to.
      * @param[in] aObjectPath  The path of the object.
-     *
      */
     DBusObject(DBusConnection *aConnection, const std::string &aObjectPath);
 
@@ -85,7 +83,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE  Successfully registered the object.
      * @retval OTBR_ERROR_DBUS  Failed to ragister an object.
-     *
      */
     virtual otbrError Init(void);
 
@@ -95,7 +92,6 @@ public:
      * @param[in] aInterfaceName  The interface name.
      * @param[in] aMethodName     The method name.
      * @param[in] aHandler        The method handler.
-     *
      */
     void RegisterMethod(const std::string       &aInterfaceName,
                         const std::string       &aMethodName,
@@ -107,7 +103,6 @@ public:
      * @param[in] aInterfaceName  The interface name.
      * @param[in] aPropertyName   The property name.
      * @param[in] aHandler        The method handler.
-     *
      */
     virtual void RegisterGetPropertyHandler(const std::string         &aInterfaceName,
                                             const std::string         &aPropertyName,
@@ -119,7 +114,6 @@ public:
      * @param[in] aInterfaceName  The interface name.
      * @param[in] aPropertyName   The property name.
      * @param[in] aHandler        The method handler.
-     *
      */
     virtual void RegisterSetPropertyHandler(const std::string         &aInterfaceName,
                                             const std::string         &aPropertyName,
@@ -131,7 +125,6 @@ public:
      * @param[in] aInterfaceName  The interface name.
      * @param[in] aPropertyName   The property name.
      * @param[in] aHandler        The method handler.
-     *
      */
     virtual void RegisterAsyncGetPropertyHandler(const std::string              &aInterfaceName,
                                                  const std::string              &aPropertyName,
@@ -146,7 +139,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE  Signal successfully sent.
      * @retval OTBR_ERROR_DBUS  Failed to send the signal.
-     *
      */
     template <typename... FieldTypes>
     otbrError Signal(const std::string               &aInterfaceName,
@@ -174,7 +166,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE  Signal successfully sent.
      * @retval OTBR_ERROR_DBUS  Failed to send the signal.
-     *
      */
     template <typename ValueType>
     otbrError SignalPropertyChanged(const std::string &aInterfaceName,
@@ -222,13 +213,11 @@ public:
 
     /**
      * The destructor of a d-bus object.
-     *
      */
     virtual ~DBusObject(void);
 
     /**
      * Sends all outgoing messages, blocks until the message queue is empty.
-     *
      */
     void Flush(void);
 
diff --git a/src/dbus/server/dbus_request.hpp b/src/dbus/server/dbus_request.hpp
index 2e712865..27a803e6 100644
--- a/src/dbus/server/dbus_request.hpp
+++ b/src/dbus/server/dbus_request.hpp
@@ -53,7 +53,6 @@ namespace DBus {
 
 /**
  * This class represents a incoming call for a d-bus method.
- *
  */
 class DBusRequest
 {
@@ -63,7 +62,6 @@ public:
      *
      * @param[in] aConnection  The dbus connection.
      * @param[in] aMessage     The incoming dbus message.
-     *
      */
     DBusRequest(DBusConnection *aConnection, DBusMessage *aMessage)
         : mConnection(aConnection)
@@ -77,7 +75,6 @@ public:
      * The copy constructor of dbus request.
      *
      * @param[in] aOther  The object to be copied from.
-     *
      */
     DBusRequest(const DBusRequest &aOther)
         : mConnection(nullptr)
@@ -90,7 +87,6 @@ public:
      * The assignment operator of dbus request.
      *
      * @param[in] aOther  The object to be copied from.
-     *
      */
     DBusRequest &operator=(const DBusRequest &aOther)
     {
@@ -102,7 +98,6 @@ public:
      * This method returns the message sent to call the d-bus method.
      *
      * @returns The dbus message.
-     *
      */
     DBusMessage *GetMessage(void) { return mMessage; }
 
@@ -110,7 +105,6 @@ public:
      * This method returns underlying d-bus connection.
      *
      * @returns The dbus connection.
-     *
      */
     DBusConnection *GetConnection(void) { return mConnection; }
 
@@ -118,7 +112,6 @@ public:
      * This method replies to the d-bus method call.
      *
      * @param[in] aReply  The tuple to be sent.
-     *
      */
     template <typename... Args> void Reply(const std::tuple<Args...> &aReply)
     {
@@ -143,7 +136,6 @@ public:
      *
      * @param[in] aError  The error to be sent.
      * @param[in] aResult The return value of the method call, if any.
-     *
      */
     template <typename ResultType = int>
     void ReplyOtResult(otError aError, Optional<ResultType> aResult = Optional<ResultType>())
@@ -186,7 +178,6 @@ public:
 
     /**
      * The destructor of DBusRequest
-     *
      */
     ~DBusRequest(void)
     {
diff --git a/src/dbus/server/dbus_thread_object_ncp.hpp b/src/dbus/server/dbus_thread_object_ncp.hpp
index aa7449ba..542dc260 100644
--- a/src/dbus/server/dbus_thread_object_ncp.hpp
+++ b/src/dbus/server/dbus_thread_object_ncp.hpp
@@ -66,7 +66,6 @@ public:
      * @param[in] aConnection     The dbus connection.
      * @param[in] aInterfaceName  The dbus interface name.
      * @param[in] aHost           The Thread controller.
-     *
      */
     DBusThreadObjectNcp(DBusConnection &aConnection, const std::string &aInterfaceName, otbr::Ncp::NcpHost &aHost);
 
@@ -75,7 +74,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE  The initialization succeeded.
      * @retval OTBR_ERROR_DBUS  The initialization failed due to dbus connection.
-     *
      */
     otbrError Init(void) override;
 
diff --git a/src/dbus/server/dbus_thread_object_rcp.hpp b/src/dbus/server/dbus_thread_object_rcp.hpp
index 15ec6598..7e55907b 100644
--- a/src/dbus/server/dbus_thread_object_rcp.hpp
+++ b/src/dbus/server/dbus_thread_object_rcp.hpp
@@ -68,7 +68,6 @@ public:
      * @param[in] aHost           The Thread controller
      * @param[in] aPublisher      The Mdns::Publisher
      * @param[in] aBorderAgent    The Border Agent
-     *
      */
     DBusThreadObjectRcp(DBusConnection     &aConnection,
                         const std::string  &aInterfaceName,
diff --git a/src/dbus/server/error_helper.hpp b/src/dbus/server/error_helper.hpp
index 6b35ac1d..c8ba7902 100644
--- a/src/dbus/server/error_helper.hpp
+++ b/src/dbus/server/error_helper.hpp
@@ -52,7 +52,6 @@ namespace DBus {
  * @param[in] aError  The otError value.
  *
  * @returns The string representation of an otError.
- *
  */
 const char *ConvertToDBusErrorName(otError aError);
 
diff --git a/src/mdns/mdns.hpp b/src/mdns/mdns.hpp
index ed2dc7c0..45dff98d 100644
--- a/src/mdns/mdns.hpp
+++ b/src/mdns/mdns.hpp
@@ -69,14 +69,12 @@ namespace Mdns {
 
 /**
  * This interface defines the functionality of mDNS publisher.
- *
  */
 class Publisher : private NonCopyable
 {
 public:
     /**
      * This structure represents a key/value pair of the TXT record.
-     *
      */
     struct TxtEntry
     {
@@ -127,7 +125,6 @@ public:
 
     /**
      * This structure represents information of a discovered service instance.
-     *
      */
     struct DiscoveredInstanceInfo
     {
@@ -148,7 +145,6 @@ public:
 
     /**
      * This structure represents information of a discovered host.
-     *
      */
     struct DiscoveredHostInfo
     {
@@ -163,21 +159,18 @@ public:
 
     /**
      * This function is called to notify a discovered service instance.
-     *
      */
     using DiscoveredServiceInstanceCallback =
         std::function<void(const std::string &aType, const DiscoveredInstanceInfo &aInstanceInfo)>;
 
     /**
      * This function is called to notify a discovered host.
-     *
      */
     using DiscoveredHostCallback =
         std::function<void(const std::string &aHostName, const DiscoveredHostInfo &aHostInfo)>;
 
     /**
      * mDNS state values.
-     *
      */
     enum class State
     {
@@ -196,13 +189,11 @@ public:
      *
      * @retval OTBR_ERROR_NONE  Successfully started mDNS publisher;
      * @retval OTBR_ERROR_MDNS  Failed to start mDNS publisher.
-     *
      */
     virtual otbrError Start(void) = 0;
 
     /**
      * This method stops the mDNS publisher.
-     *
      */
     virtual void Stop(void) = 0;
 
@@ -211,7 +202,6 @@ public:
      *
      * @retval true   Already started.
      * @retval false  Not started.
-     *
      */
     virtual bool IsStarted(void) const = 0;
 
@@ -233,7 +223,6 @@ public:
      *                          failure. Specifically, `OTBR_ERROR_DUPLICATED` indicates that the name has
      *                          already been published and the caller can re-publish with a new name if an
      *                          alternative name is available/acceptable.
-     *
      */
     void PublishService(const std::string &aHostName,
                         const std::string &aName,
@@ -249,7 +238,6 @@ public:
      * @param[in] aName      The name of this service.
      * @param[in] aType      The type of this service, e.g., "_srv._udp" (MUST NOT end with dot).
      * @param[in] aCallback  The callback for receiving the publishing result.
-     *
      */
     virtual void UnpublishService(const std::string &aName, const std::string &aType, ResultCallback &&aCallback) = 0;
 
@@ -266,7 +254,6 @@ public:
      *                        failure. Specifically, `OTBR_ERROR_DUPLICATED` indicates that the name has
      *                        already been published and the caller can re-publish with a new name if an
      *                        alternative name is available/acceptable.
-     *
      */
     void PublishHost(const std::string &aName, const AddressList &aAddresses, ResultCallback &&aCallback);
 
@@ -275,7 +262,6 @@ public:
      *
      * @param[in] aName      A host name (MUST not end with dot).
      * @param[in] aCallback  The callback for receiving the publishing result.
-     *
      */
     virtual void UnpublishHost(const std::string &aName, ResultCallback &&aCallback) = 0;
 
@@ -289,7 +275,6 @@ public:
      *                        failure. Specifically, `OTBR_ERROR_DUPLICATED` indicates that the name has
      *                        already been published and the caller can re-publish with a new name if an
      *                        alternative name is available/acceptable.
-     *
      */
     void PublishKey(const std::string &aName, const KeyData &aKeyData, ResultCallback &&aCallback);
 
@@ -298,7 +283,6 @@ public:
      *
      * @param[in] aName      The name associated with key record.
      * @param[in] aCallback  The callback for receiving the publishing result.
-     *
      */
     virtual void UnpublishKey(const std::string &aName, ResultCallback &&aCallback) = 0;
 
@@ -314,7 +298,6 @@ public:
      *
      * @param[in] aType          The service type, e.g., "_srv._udp" (MUST NOT end with dot).
      * @param[in] aInstanceName  The service instance to subscribe, or empty to subscribe the service.
-     *
      */
     virtual void SubscribeService(const std::string &aType, const std::string &aInstanceName) = 0;
 
@@ -328,7 +311,6 @@ public:
      *
      * @param[in] aType          The service type, e.g., "_srv._udp" (MUST NOT end with dot).
      * @param[in] aInstanceName  The service instance to unsubscribe, or empty to unsubscribe the service.
-     *
      */
     virtual void UnsubscribeService(const std::string &aType, const std::string &aInstanceName) = 0;
 
@@ -340,7 +322,6 @@ public:
      * @note Discovery Proxy implementation guarantees no duplicate subscriptions for the same host.
      *
      * @param[in] aHostName  The host name (without domain).
-     *
      */
     virtual void SubscribeHost(const std::string &aHostName) = 0;
 
@@ -350,7 +331,6 @@ public:
      * @note Discovery Proxy implementation guarantees no redundant unsubscription for a host.
      *
      * @param[in] aHostName  The host name (without domain).
-     *
      */
     virtual void UnsubscribeHost(const std::string &aHostName) = 0;
 
@@ -361,7 +341,6 @@ public:
      * @param[in] aHostCallback      The callback function to receive discovered hosts.
      *
      * @returns  The Subscriber ID for the callbacks.
-     *
      */
     uint64_t AddSubscriptionCallbacks(DiscoveredServiceInstanceCallback aInstanceCallback,
                                       DiscoveredHostCallback            aHostCallback);
@@ -370,7 +349,6 @@ public:
      * This method cancels callbacks for subscriptions.
      *
      * @param[in] aSubscriberId  The Subscriber ID previously returned by `AddSubscriptionCallbacks`.
-     *
      */
     void RemoveSubscriptionCallbacks(uint64_t aSubscriberId);
 
@@ -378,7 +356,6 @@ public:
      * This method returns the mDNS statistics information of the publisher.
      *
      * @returns  The MdnsTelemetryInfo of the publisher.
-     *
      */
     const MdnsTelemetryInfo &GetMdnsTelemetryInfo(void) const { return mTelemetryInfo; }
 
@@ -390,7 +367,6 @@ public:
      * @param[in] aCallback  The callback for receiving mDNS publisher state changes.
      *
      * @returns A pointer to the newly created mDNS publisher.
-     *
      */
     static Publisher *Create(StateCallback aCallback);
 
@@ -398,7 +374,6 @@ public:
      * This function destroys the mDNS publisher.
      *
      * @param[in] aPublisher  A pointer to the publisher.
-     *
      */
     static void Destroy(Publisher *aPublisher);
 
@@ -416,7 +391,6 @@ public:
      * @retval OTBR_ERROR_INVALID_ARGS  The @p aTxtList includes invalid TXT entry.
      *
      * @sa DecodeTxtData
-     *
      */
     static otbrError EncodeTxtData(const TxtList &aTxtList, TxtData &aTxtData);
 
@@ -434,7 +408,6 @@ public:
      * @retval OTBR_ERROR_INVALID_ARGS  The @p aTxtdata has invalid TXT format.
      *
      * @sa EncodeTxtData
-     *
      */
     static otbrError DecodeTxtData(TxtList &aTxtList, const uint8_t *aTxtData, uint16_t aTxtLength);
 
diff --git a/src/mdns/mdns_avahi.cpp b/src/mdns/mdns_avahi.cpp
index 2f3984d7..2d9719d6 100644
--- a/src/mdns/mdns_avahi.cpp
+++ b/src/mdns/mdns_avahi.cpp
@@ -81,7 +81,6 @@ struct AvahiWatch
      * @param[in] aCallback  The function to be called when events happened on this file descriptor.
      * @param[in] aContext   A pointer to application-specific context.
      * @param[in] aPoller    The AvahiPoller this watcher belongs to.
-     *
      */
     AvahiWatch(int aFd, AvahiWatchEvent aEvents, AvahiWatchCallback aCallback, void *aContext, AvahiPoller &aPoller)
         : mFd(aFd)
@@ -96,7 +95,6 @@ struct AvahiWatch
 
 /**
  * This structure implements the AvahiTimeout.
- *
  */
 struct AvahiTimeout
 {
@@ -115,7 +113,6 @@ struct AvahiTimeout
      * @param[in] aCallback  The function to be called after timeout.
      * @param[in] aContext   A pointer to application-specific context.
      * @param[in] aPoller    The AvahiPoller this timeout belongs to.
-     *
      */
     AvahiTimeout(const struct timeval *aTimeout, AvahiTimeoutCallback aCallback, void *aContext, AvahiPoller &aPoller)
         : mCallback(aCallback)
diff --git a/src/mdns/mdns_avahi.hpp b/src/mdns/mdns_avahi.hpp
index d42f9a2b..5a76ca24 100644
--- a/src/mdns/mdns_avahi.hpp
+++ b/src/mdns/mdns_avahi.hpp
@@ -68,7 +68,6 @@ class AvahiPoller;
 
 /**
  * This class implements mDNS publisher with avahi.
- *
  */
 class PublisherAvahi : public Publisher
 {
diff --git a/src/mdns/mdns_mdnssd.hpp b/src/mdns/mdns_mdnssd.hpp
index 068d7861..07e641b1 100644
--- a/src/mdns/mdns_mdnssd.hpp
+++ b/src/mdns/mdns_mdnssd.hpp
@@ -56,7 +56,6 @@ namespace Mdns {
 
 /**
  * This class implements mDNS publisher with mDNSResponder.
- *
  */
 class PublisherMDnsSd : public MainloopProcessor, public Publisher
 {
diff --git a/src/ncp/async_task.hpp b/src/ncp/async_task.hpp
index 5421d34b..371f1fa7 100644
--- a/src/ncp/async_task.hpp
+++ b/src/ncp/async_task.hpp
@@ -56,13 +56,11 @@ public:
      * Constructor.
      *
      * @param[in]  The error handler called when the result is not OT_ERROR_NONE;
-     *
      */
     AsyncTask(const ResultHandler &aResultHandler);
 
     /**
      * Destructor.
-     *
      */
     ~AsyncTask(void);
 
@@ -70,7 +68,6 @@ public:
      * Trigger the initial action of the chained async operations.
      *
      * This method should be called to trigger the chained async operations.
-     *
      */
     void Run(void);
 
@@ -81,7 +78,6 @@ public:
      * This method will pass the result to next operation.
      *
      * @param[in] aError  The result for the previous async operation.
-     *
      */
     void SetResult(otError aError, const std::string &aErrorInfo);
 
@@ -91,7 +87,6 @@ public:
      * @param[in] aFirst  A reference to a function object for the initial action.
      *
      * @returns  A shared pointer to a AsyncTask object created in this method.
-     *
      */
     AsyncTaskPtr &First(const ThenHandler &aFirst);
 
@@ -101,7 +96,6 @@ public:
      * @param[in] aThen  A reference to a function object for the next action.
      *
      * @returns A shared pointer to a AsyncTask object created in this method.
-     *
      */
     AsyncTaskPtr &Then(const ThenHandler &aThen);
 
diff --git a/src/ncp/ncp_host.cpp b/src/ncp/ncp_host.cpp
index af988feb..f5ad0f78 100644
--- a/src/ncp/ncp_host.cpp
+++ b/src/ncp/ncp_host.cpp
@@ -49,6 +49,7 @@ namespace Ncp {
 NcpNetworkProperties::NcpNetworkProperties(void)
     : mDeviceRole(OT_DEVICE_ROLE_DISABLED)
 {
+    memset(&mDatasetActiveTlvs, 0, sizeof(mDatasetActiveTlvs));
 }
 
 otDeviceRole NcpNetworkProperties::GetDeviceRole(void) const
@@ -61,6 +62,36 @@ void NcpNetworkProperties::SetDeviceRole(otDeviceRole aRole)
     mDeviceRole = aRole;
 }
 
+bool NcpNetworkProperties::Ip6IsEnabled(void) const
+{
+    // TODO: Implement the method under NCP mode.
+    return false;
+}
+
+uint32_t NcpNetworkProperties::GetPartitionId(void) const
+{
+    // TODO: Implement the method under NCP mode.
+    return 0;
+}
+
+void NcpNetworkProperties::SetDatasetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs)
+{
+    mDatasetActiveTlvs.mLength = aActiveOpDatasetTlvs.mLength;
+    memcpy(mDatasetActiveTlvs.mTlvs, aActiveOpDatasetTlvs.mTlvs, aActiveOpDatasetTlvs.mLength);
+}
+
+void NcpNetworkProperties::GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const
+{
+    aDatasetTlvs.mLength = mDatasetActiveTlvs.mLength;
+    memcpy(aDatasetTlvs.mTlvs, mDatasetActiveTlvs.mTlvs, mDatasetActiveTlvs.mLength);
+}
+
+void NcpNetworkProperties::GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const
+{
+    // TODO: Implement the method under NCP mode.
+    OTBR_UNUSED_VARIABLE(aDatasetTlvs);
+}
+
 // ===================================== NcpHost ======================================
 
 NcpHost::NcpHost(const char *aInterfaceName, bool aDryRun)
@@ -144,6 +175,45 @@ exit:
     }
 }
 
+void NcpHost::SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver)
+{
+    OT_UNUSED_VARIABLE(aEnabled);
+
+    // TODO: Implement SetThreadEnabled under NCP mode.
+    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
+void NcpHost::SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver)
+{
+    OT_UNUSED_VARIABLE(aCountryCode);
+
+    // TODO: Implement SetCountryCode under NCP mode.
+    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
+void NcpHost::GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver)
+{
+    OT_UNUSED_VARIABLE(aReceiver);
+
+    // TODO: Implement GetChannelMasks under NCP mode.
+    mTaskRunner.Post([aErrReceiver](void) { aErrReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
+void NcpHost::SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
+                                  const AsyncResultReceiver          &aReceiver)
+{
+    OT_UNUSED_VARIABLE(aChannelMaxPowers);
+
+    // TODO: Implement SetChannelMaxPowers under NCP mode.
+    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
+void NcpHost::AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback)
+{
+    // TODO: Implement AddThreadStateChangedCallback under NCP mode.
+    OT_UNUSED_VARIABLE(aCallback);
+}
+
 void NcpHost::Process(const MainloopContext &aMainloop)
 {
     mSpinelDriver.Process(&aMainloop);
diff --git a/src/ncp/ncp_host.hpp b/src/ncp/ncp_host.hpp
index 9d74177b..18130d9f 100644
--- a/src/ncp/ncp_host.hpp
+++ b/src/ncp/ncp_host.hpp
@@ -47,25 +47,29 @@ namespace Ncp {
 
 /**
  * This class implements the NetworkProperties under NCP mode.
- *
  */
 class NcpNetworkProperties : virtual public NetworkProperties, public PropsObserver
 {
 public:
     /**
      * Constructor
-     *
      */
     explicit NcpNetworkProperties(void);
 
     // NetworkProperties methods
     otDeviceRole GetDeviceRole(void) const override;
+    bool         Ip6IsEnabled(void) const override;
+    uint32_t     GetPartitionId(void) const override;
+    void         GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    void         GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
 
 private:
     // PropsObserver methods
     void SetDeviceRole(otDeviceRole aRole) override;
+    void SetDatasetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs) override;
 
-    otDeviceRole mDeviceRole;
+    otDeviceRole             mDeviceRole;
+    otOperationalDatasetTlvs mDatasetActiveTlvs;
 };
 
 class NcpHost : public MainloopProcessor, public ThreadHost, public NcpNetworkProperties
@@ -76,13 +80,11 @@ public:
      *
      * @param[in]   aInterfaceName  A string of the NCP interface name.
      * @param[in]   aDryRun         TRUE to indicate dry-run mode. FALSE otherwise.
-     *
      */
     NcpHost(const char *aInterfaceName, bool aDryRun);
 
     /**
      * Destructor.
-     *
      */
     ~NcpHost(void) override = default;
 
@@ -91,6 +93,12 @@ public:
     void Leave(const AsyncResultReceiver &aReceiver) override;
     void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
                            const AsyncResultReceiver       aReceiver) override;
+    void SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver) override;
+    void SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver) override;
+    void GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver) override;
+    void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
+                             const AsyncResultReceiver          &aReceiver) override;
+    void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
     CoprocessorType GetCoprocessorType(void) override { return OT_COPROCESSOR_NCP; }
     const char     *GetCoprocessorVersion(void) override;
     const char     *GetInterfaceName(void) const override { return mConfig.mInterfaceName; }
diff --git a/src/ncp/ncp_spinel.cpp b/src/ncp/ncp_spinel.cpp
index c9a0458d..f3f0078e 100644
--- a/src/ncp/ncp_spinel.cpp
+++ b/src/ncp/ncp_spinel.cpp
@@ -418,6 +418,12 @@ otbrError NcpSpinel::HandleResponseForPropSet(spinel_tid_t      aTid,
     case SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS:
         VerifyOrExit(aKey == SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS, error = OTBR_ERROR_INVALID_STATE);
         CallAndClear(mDatasetSetActiveTask, OT_ERROR_NONE);
+        {
+            otOperationalDatasetTlvs datasetTlvs;
+            VerifyOrExit(ParseOperationalDatasetTlvs(aData, aLength, datasetTlvs) == OT_ERROR_NONE,
+                         error = OTBR_ERROR_PARSE);
+            mPropsObserver->SetDatasetActiveTlvs(datasetTlvs);
+        }
         break;
 
     case SPINEL_PROP_NET_IF_UP:
@@ -587,6 +593,40 @@ exit:
     return error;
 }
 
+otError NcpSpinel::ParseIp6StreamNet(const uint8_t *aBuf, uint8_t aLen, const uint8_t *&aData, uint16_t &aDataLen)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+
+    decoder.Init(aBuf, aLen);
+    error = decoder.ReadDataWithLen(aData, aDataLen);
+
+exit:
+    return error;
+}
+
+otError NcpSpinel::ParseOperationalDatasetTlvs(const uint8_t            *aBuf,
+                                               uint8_t                   aLen,
+                                               otOperationalDatasetTlvs &aDatasetTlvs)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+    const uint8_t      *datasetTlvsData;
+    uint16_t            datasetTlvsLen;
+
+    decoder.Init(aBuf, aLen);
+    SuccessOrExit(error = decoder.ReadData(datasetTlvsData, datasetTlvsLen));
+    VerifyOrExit(datasetTlvsLen <= sizeof(aDatasetTlvs.mTlvs), error = OT_ERROR_PARSE);
+
+    memcpy(aDatasetTlvs.mTlvs, datasetTlvsData, datasetTlvsLen);
+    aDatasetTlvs.mLength = datasetTlvsLen;
+
+exit:
+    return error;
+}
+
 otDeviceRole NcpSpinel::SpinelRoleToDeviceRole(spinel_net_role_t aRole)
 {
     otDeviceRole role = OT_DEVICE_ROLE_DISABLED;
diff --git a/src/ncp/ncp_spinel.hpp b/src/ncp/ncp_spinel.hpp
index f60895db..c489b9a2 100644
--- a/src/ncp/ncp_spinel.hpp
+++ b/src/ncp/ncp_spinel.hpp
@@ -56,7 +56,6 @@ namespace Ncp {
 
 /**
  * This interface is an observer to subscribe the network properties from NCP.
- *
  */
 class PropsObserver
 {
@@ -65,20 +64,24 @@ public:
      * Updates the device role.
      *
      * @param[in] aRole  The device role.
-     *
      */
     virtual void SetDeviceRole(otDeviceRole aRole) = 0;
 
     /**
-     * The destructor.
+     * Updates the active dataset.
      *
+     * @param[in] aActiveOpDatasetTlvs  The active dataset tlvs.
+     */
+    virtual void SetDatasetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs) = 0;
+
+    /**
+     * The destructor.
      */
     virtual ~PropsObserver(void) = default;
 };
 
 /**
  * The class provides methods for controlling the Thread stack on the network co-processor (NCP).
- *
  */
 class NcpSpinel
 {
@@ -89,7 +92,6 @@ public:
 
     /**
      * Constructor.
-     *
      */
     NcpSpinel(void);
 
@@ -98,19 +100,16 @@ public:
      *
      * @param[in]  aSpinelDriver   A reference to the SpinelDriver instance that this object depends.
      * @param[in]  aObserver       A reference to the Network properties observer.
-     *
      */
     void Init(ot::Spinel::SpinelDriver &aSpinelDriver, PropsObserver &aObserver);
 
     /**
      * Do the de-initialization.
-     *
      */
     void Deinit(void);
 
     /**
      * Returns the Co-processor version string.
-     *
      */
     const char *GetCoprocessorVersion(void) { return mSpinelDriver->GetVersion(); }
 
@@ -122,7 +121,6 @@ public:
      *
      * @param[in] aActiveOpDatasetTlvs  A reference to the active operational dataset of the Thread network.
      * @param[in] aAsyncTask            A pointer to an async result to receive the result of this operation.
-     *
      */
     void DatasetSetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, AsyncTaskPtr aAsyncTask);
 
@@ -134,7 +132,6 @@ public:
      *
      * @param[in] aPendingOpDatasetTlvsPtr  A shared pointer to the pending operational dataset of the Thread network.
      * @param[in] aAsyncTask                A pointer to an async result to receive the result of this operation.
-     *
      */
     void DatasetMgmtSetPending(std::shared_ptr<otOperationalDatasetTlvs> aPendingOpDatasetTlvsPtr,
                                AsyncTaskPtr                              aAsyncTask);
@@ -147,7 +144,6 @@ public:
      *
      * @param[in] aEnable     TRUE to enable and FALSE to disable.
      * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
-     *
      */
     void Ip6SetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask);
 
@@ -159,7 +155,6 @@ public:
      * if it's not used immediately (within the callback).
      *
      * @param[in] aCallback  The callback to handle the IP6 address table.
-     *
      */
     void Ip6SetAddressCallback(const Ip6AddressTableCallback &aCallback) { mIp6AddressTableCallback = aCallback; }
 
@@ -171,7 +166,6 @@ public:
      * The callback will be invoked when receiving an IPv6 multicast address table from the NCP.
      * When the callback is invoked, the callback MUST copy the otIp6Address objects and maintain it
      * if it's not used immediately (within the callback).
-     *
      */
     void Ip6SetAddressMulticastCallback(const Ip6MulticastAddressTableCallback &aCallback)
     {
@@ -186,7 +180,6 @@ public:
      *
      * @retval OTBR_ERROR_NONE  The datagram is sent to NCP successfully.
      * @retval OTBR_ERROR_BUSY  NcpSpinel is busy with other requests.
-     *
      */
     otbrError Ip6Send(const uint8_t *aData, uint16_t aLength);
 
@@ -198,7 +191,6 @@ public:
      *
      * @param[in] aEnable     TRUE to enable and FALSE to disable.
      * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
-     *
      */
     void ThreadSetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask);
 
@@ -209,7 +201,6 @@ public:
      * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
      *
      * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
-     *
      */
     void ThreadDetachGracefully(AsyncTaskPtr aAsyncTask);
 
@@ -220,7 +211,6 @@ public:
      * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
      *
      * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
-     *
      */
     void ThreadErasePersistentInfo(AsyncTaskPtr aAsyncTask);
 
@@ -228,7 +218,6 @@ public:
      * This method sets the callback invoked when the network interface state changes.
      *
      * @param[in] aCallback  The callback invoked when the network interface state changes.
-     *
      */
     void NetifSetStateChangedCallback(const NetifStateChangedCallback &aCallback)
     {
@@ -286,6 +275,8 @@ private:
 
     otError ParseIp6AddressTable(const uint8_t *aBuf, uint16_t aLength, std::vector<Ip6AddressInfo> &aAddressTable);
     otError ParseIp6MulticastAddresses(const uint8_t *aBuf, uint8_t aLen, std::vector<Ip6Address> &aAddressList);
+    otError ParseIp6StreamNet(const uint8_t *aBuf, uint8_t aLen, const uint8_t *&aData, uint16_t &aDataLen);
+    otError ParseOperationalDatasetTlvs(const uint8_t *aBuf, uint8_t aLen, otOperationalDatasetTlvs &aDatasetTlvs);
 
     ot::Spinel::SpinelDriver *mSpinelDriver;
     uint16_t                  mCmdTidsInUse; ///< Used transaction ids.
diff --git a/src/ncp/rcp_host.cpp b/src/ncp/rcp_host.cpp
index 97d6c730..edfcc7d4 100644
--- a/src/ncp/rcp_host.cpp
+++ b/src/ncp/rcp_host.cpp
@@ -31,6 +31,7 @@
 #include "ncp/rcp_host.hpp"
 
 #include <assert.h>
+#include <limits.h>
 #include <stdio.h>
 #include <string.h>
 
@@ -78,6 +79,38 @@ otDeviceRole OtNetworkProperties::GetDeviceRole(void) const
     return otThreadGetDeviceRole(mInstance);
 }
 
+bool OtNetworkProperties::Ip6IsEnabled(void) const
+{
+    return otIp6IsEnabled(mInstance);
+}
+
+uint32_t OtNetworkProperties::GetPartitionId(void) const
+{
+    return otThreadGetPartitionId(mInstance);
+}
+
+void OtNetworkProperties::GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const
+{
+    otError error = otDatasetGetActiveTlvs(mInstance, &aDatasetTlvs);
+
+    if (error != OT_ERROR_NONE)
+    {
+        aDatasetTlvs.mLength = 0;
+        memset(aDatasetTlvs.mTlvs, 0, sizeof(aDatasetTlvs.mTlvs));
+    }
+}
+
+void OtNetworkProperties::GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const
+{
+    otError error = otDatasetGetPendingTlvs(mInstance, &aDatasetTlvs);
+
+    if (error != OT_ERROR_NONE)
+    {
+        aDatasetTlvs.mLength = 0;
+        memset(aDatasetTlvs.mTlvs, 0, sizeof(aDatasetTlvs.mTlvs));
+    }
+}
+
 void OtNetworkProperties::SetInstance(otInstance *aInstance)
 {
     mInstance = aInstance;
@@ -295,6 +328,9 @@ void RcpHost::Deinit(void)
     OtNetworkProperties::SetInstance(nullptr);
     mThreadStateChangedCallbacks.clear();
     mResetHandlers.clear();
+
+    mSetThreadEnabledReceiver  = nullptr;
+    mScheduleMigrationReceiver = nullptr;
 }
 
 void RcpHost::HandleStateChanged(otChangedFlags aFlags)
@@ -411,10 +447,172 @@ void RcpHost::Leave(const AsyncResultReceiver &aReceiver)
 void RcpHost::ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
                                 const AsyncResultReceiver       aReceiver)
 {
-    OT_UNUSED_VARIABLE(aPendingOpDatasetTlvs);
+    otError              error = OT_ERROR_NONE;
+    std::string          errorMsg;
+    otOperationalDataset emptyDataset;
 
-    // TODO: Implement ScheduleMigration under RCP mode.
-    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
+    VerifyOrExit(IsAttached(), error = OT_ERROR_FAILED,
+                 errorMsg = "Cannot schedule migration when this device is detached");
+
+    // TODO: check supported channel mask
+
+    SuccessOrExit(error    = otDatasetSendMgmtPendingSet(mInstance, &emptyDataset, aPendingOpDatasetTlvs.mTlvs,
+                                                         static_cast<uint8_t>(aPendingOpDatasetTlvs.mLength),
+                                                         SendMgmtPendingSetCallback, this),
+                  errorMsg = "Failed to send MGMT_PENDING_SET.req");
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post([aReceiver, error, errorMsg](void) { aReceiver(error, errorMsg); });
+    }
+    else
+    {
+        // otDatasetSendMgmtPendingSet() returns OT_ERROR_BUSY if it has already been called before but the
+        // callback hasn't been invoked. So we can guarantee that mMigrationReceiver is always nullptr here
+        assert(mScheduleMigrationReceiver == nullptr);
+        mScheduleMigrationReceiver = aReceiver;
+    }
+}
+
+void RcpHost::SendMgmtPendingSetCallback(otError aError, void *aContext)
+{
+    static_cast<RcpHost *>(aContext)->SendMgmtPendingSetCallback(aError);
+}
+
+void RcpHost::SendMgmtPendingSetCallback(otError aError)
+{
+    SafeInvokeAndClear(mScheduleMigrationReceiver, aError, "");
+}
+
+void RcpHost::SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver)
+{
+    otError error             = OT_ERROR_NONE;
+    bool    receiveResultHere = true;
+
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE);
+    VerifyOrExit(mSetThreadEnabledReceiver == nullptr, error = OT_ERROR_BUSY);
+
+    if (aEnabled)
+    {
+        otOperationalDatasetTlvs datasetTlvs;
+
+        if (otDatasetGetActiveTlvs(mInstance, &datasetTlvs) != OT_ERROR_NOT_FOUND && datasetTlvs.mLength > 0 &&
+            otThreadGetDeviceRole(mInstance) == OT_DEVICE_ROLE_DISABLED)
+        {
+            SuccessOrExit(error = otIp6SetEnabled(mInstance, true));
+            SuccessOrExit(error = otThreadSetEnabled(mInstance, true));
+        }
+    }
+    else
+    {
+        SuccessOrExit(error = otThreadDetachGracefully(mInstance, DisableThreadAfterDetach, this));
+        mSetThreadEnabledReceiver = aReceiver;
+        receiveResultHere         = false;
+    }
+
+exit:
+    if (receiveResultHere)
+    {
+        mTaskRunner.Post([aReceiver, error](void) { aReceiver(error, ""); });
+    }
+}
+
+void RcpHost::GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver)
+{
+    otError  error = OT_ERROR_NONE;
+    uint32_t supportedChannelMask;
+    uint32_t preferredChannelMask;
+
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE);
+
+    supportedChannelMask = otLinkGetSupportedChannelMask(mInstance);
+    preferredChannelMask = otPlatRadioGetPreferredChannelMask(mInstance);
+
+exit:
+    if (error == OT_ERROR_NONE)
+    {
+        mTaskRunner.Post([aReceiver, supportedChannelMask, preferredChannelMask](void) {
+            aReceiver(supportedChannelMask, preferredChannelMask);
+        });
+    }
+    else
+    {
+        mTaskRunner.Post([aErrReceiver, error](void) { aErrReceiver(error, "OT is not initialized"); });
+    }
+}
+
+void RcpHost::SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
+                                  const AsyncResultReceiver          &aReceiver)
+{
+    otError     error = OT_ERROR_NONE;
+    std::string errorMsg;
+
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
+
+    for (ChannelMaxPower channelMaxPower : aChannelMaxPowers)
+    {
+        VerifyOrExit((channelMaxPower.mChannel >= OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MIN) &&
+                         (channelMaxPower.mChannel <= OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MAX),
+                     error = OT_ERROR_INVALID_ARGS, errorMsg = "The channel is invalid");
+    }
+
+    for (ChannelMaxPower channelMaxPower : aChannelMaxPowers)
+    {
+        otbrLogInfo("Set channel max power: channel=%u, maxPower=%u", static_cast<uint32_t>(channelMaxPower.mChannel),
+                    static_cast<uint32_t>(channelMaxPower.mMaxPower));
+        SuccessOrExit(error = otPlatRadioSetChannelTargetPower(
+                          mInstance, static_cast<uint8_t>(channelMaxPower.mChannel), channelMaxPower.mMaxPower),
+                      errorMsg = "Failed to set channel max power");
+    }
+
+exit:
+    mTaskRunner.Post([aReceiver, error, errorMsg](void) { aReceiver(error, errorMsg); });
+}
+
+void RcpHost::DisableThreadAfterDetach(void *aContext)
+{
+    static_cast<RcpHost *>(aContext)->DisableThreadAfterDetach();
+}
+
+void RcpHost::DisableThreadAfterDetach(void)
+{
+    otError     error = OT_ERROR_NONE;
+    std::string errorMsg;
+
+    SuccessOrExit(error = otThreadSetEnabled(mInstance, false), errorMsg = "Failed to disable Thread stack");
+    SuccessOrExit(error = otIp6SetEnabled(mInstance, false), errorMsg = "Failed to disable Thread interface");
+
+exit:
+    SafeInvokeAndClear(mSetThreadEnabledReceiver, error, errorMsg);
+}
+
+void RcpHost::SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver)
+{
+    static constexpr int kCountryCodeLength = 2;
+    otError              error              = OT_ERROR_NONE;
+    std::string          errorMsg;
+    uint16_t             countryCode;
+
+    VerifyOrExit((aCountryCode.length() == kCountryCodeLength) && isalpha(aCountryCode[0]) && isalpha(aCountryCode[1]),
+                 error = OT_ERROR_INVALID_ARGS, errorMsg = "The country code is invalid");
+
+    otbrLogInfo("Set country code: %c%c", aCountryCode[0], aCountryCode[1]);
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
+
+    countryCode = static_cast<uint16_t>((aCountryCode[0] << 8) | aCountryCode[1]);
+    SuccessOrExit(error = otLinkSetRegion(mInstance, countryCode), errorMsg = "Failed to set the country code");
+
+exit:
+    mTaskRunner.Post([aReceiver, error, errorMsg](void) { aReceiver(error, errorMsg); });
+}
+
+bool RcpHost::IsAttached(void)
+{
+    otDeviceRole role = GetDeviceRole();
+
+    return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER || role == OT_DEVICE_ROLE_LEADER;
 }
 
 /*
diff --git a/src/ncp/rcp_host.hpp b/src/ncp/rcp_host.hpp
index a13e70cc..f97a6260 100644
--- a/src/ncp/rcp_host.hpp
+++ b/src/ncp/rcp_host.hpp
@@ -62,19 +62,21 @@ namespace Ncp {
 
 /**
  * This class implements the NetworkProperties for architectures where OT APIs are directly accessible.
- *
  */
 class OtNetworkProperties : virtual public NetworkProperties
 {
 public:
     /**
      * Constructor.
-     *
      */
     explicit OtNetworkProperties(void);
 
     // NetworkProperties methods
     otDeviceRole GetDeviceRole(void) const override;
+    bool         Ip6IsEnabled(void) const override;
+    uint32_t     GetPartitionId(void) const override;
+    void         GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    void         GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
 
     // Set the otInstance
     void SetInstance(otInstance *aInstance);
@@ -85,13 +87,10 @@ private:
 
 /**
  * This interface defines OpenThread Controller under RCP mode.
- *
  */
 class RcpHost : public MainloopProcessor, public ThreadHost, public OtNetworkProperties
 {
 public:
-    using ThreadStateChangedCallback = std::function<void(otChangedFlags aFlags)>;
-
     /**
      * This constructor initializes this object.
      *
@@ -100,7 +99,6 @@ public:
      * @param[in]   aBackboneInterfaceName  The Backbone network interface name.
      * @param[in]   aDryRun                 TRUE to indicate dry-run mode. FALSE otherwise.
      * @param[in]   aEnableAutoAttach       Whether or not to automatically attach to the saved network.
-     *
      */
     RcpHost(const char                      *aInterfaceName,
             const std::vector<const char *> &aRadioUrls,
@@ -110,13 +108,11 @@ public:
 
     /**
      * This method initialize the Thread controller.
-     *
      */
     void Init(void) override;
 
     /**
      * This method deinitialize the Thread controller.
-     *
      */
     void Deinit(void) override;
 
@@ -132,7 +128,6 @@ public:
      * This method gets the thread functionality helper.
      *
      * @retval The pointer to the helper object.
-     *
      */
     otbr::agent::ThreadHelper *GetThreadHelper(void)
     {
@@ -148,7 +143,6 @@ public:
      *
      * @param[in] aDelay  The delay in milliseconds before executing the task.
      * @param[in] aTask   The task function.
-     *
      */
     void PostTimerTask(Milliseconds aDelay, TaskRunner::Task<void> aTask);
 
@@ -156,21 +150,11 @@ public:
      * This method registers a reset handler.
      *
      * @param[in] aHandler  The handler function.
-     *
      */
     void RegisterResetHandler(std::function<void(void)> aHandler);
 
-    /**
-     * This method adds a event listener for Thread state changes.
-     *
-     * @param[in] aCallback  The callback to receive Thread state changed events.
-     *
-     */
-    void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback);
-
     /**
      * This method resets the OpenThread instance.
-     *
      */
     void Reset(void);
 
@@ -178,7 +162,6 @@ public:
      * This method returns the Thread protocol version as a string.
      *
      * @returns A pointer to the Thread version string.
-     *
      */
     static const char *GetThreadVersion(void);
 
@@ -186,7 +169,6 @@ public:
      * This method returns the Thread network interface name.
      *
      * @returns A pointer to the Thread network interface name string.
-     *
      */
     const char *GetInterfaceName(void) const override { return mConfig.mInterfaceName; }
 
@@ -199,7 +181,6 @@ public:
      * @param[in] aFeatureFlagList  The feature flag list to be applied to OpenThread.
      *
      * @returns The error value of underlying OpenThread API calls.
-     *
      */
     otError ApplyFeatureFlagList(const FeatureFlagList &aFeatureFlagList);
 
@@ -207,7 +188,6 @@ public:
      * This method returns the applied FeatureFlagList in ApplyFeatureFlagList call.
      *
      * @returns the applied FeatureFlagList's serialized bytes.
-     *
      */
     const std::string &GetAppliedFeatureFlagListBytes(void)
     {
@@ -222,6 +202,12 @@ public:
     void Leave(const AsyncResultReceiver &aRecevier) override;
     void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
                            const AsyncResultReceiver       aReceiver) override;
+    void SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver) override;
+    void SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver) override;
+    void GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver) override;
+    void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
+                             const AsyncResultReceiver          &aReceiver) override;
+    void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
 
     CoprocessorType GetCoprocessorType(void) override
     {
@@ -234,6 +220,15 @@ public:
     }
 
 private:
+    static void SafeInvokeAndClear(AsyncResultReceiver &aReceiver, otError aError, const std::string &aErrorInfo = "")
+    {
+        if (aReceiver)
+        {
+            aReceiver(aError, aErrorInfo);
+            aReceiver = nullptr;
+        }
+    }
+
     static void HandleStateChanged(otChangedFlags aFlags, void *aContext)
     {
         static_cast<RcpHost *>(aContext)->HandleStateChanged(aFlags);
@@ -253,9 +248,16 @@ private:
     void        HandleBackboneRouterNdProxyEvent(otBackboneRouterNdProxyEvent aEvent, const otIp6Address *aAddress);
 #endif
 
+    static void DisableThreadAfterDetach(void *aContext);
+    void        DisableThreadAfterDetach(void);
+    static void SendMgmtPendingSetCallback(otError aError, void *aContext);
+    void        SendMgmtPendingSetCallback(otError aError);
+
     bool IsAutoAttachEnabled(void);
     void DisableAutoAttach(void);
 
+    bool IsAttached(void);
+
     otError SetOtbrAndOtLogLevel(otbrLogLevel aLevel);
 
     otInstance *mInstance;
@@ -267,6 +269,9 @@ private:
     std::vector<ThreadStateChangedCallback>    mThreadStateChangedCallbacks;
     bool                                       mEnableAutoAttach = false;
 
+    AsyncResultReceiver mSetThreadEnabledReceiver;
+    AsyncResultReceiver mScheduleMigrationReceiver;
+
 #if OTBR_ENABLE_FEATURE_FLAGS
     // The applied FeatureFlagList in ApplyFeatureFlagList call, used for debugging purpose.
     std::string mAppliedFeatureFlagListBytes;
diff --git a/src/ncp/thread_host.cpp b/src/ncp/thread_host.cpp
index 294060a3..b5f1bf25 100644
--- a/src/ncp/thread_host.cpp
+++ b/src/ncp/thread_host.cpp
@@ -82,35 +82,5 @@ std::unique_ptr<ThreadHost> ThreadHost::Create(const char                      *
     return host;
 }
 
-otLogLevel ThreadHost::ConvertToOtLogLevel(otbrLogLevel aLevel)
-{
-    otLogLevel level;
-
-    switch (aLevel)
-    {
-    case OTBR_LOG_EMERG:
-    case OTBR_LOG_ALERT:
-    case OTBR_LOG_CRIT:
-        level = OT_LOG_LEVEL_CRIT;
-        break;
-    case OTBR_LOG_ERR:
-    case OTBR_LOG_WARNING:
-        level = OT_LOG_LEVEL_WARN;
-        break;
-    case OTBR_LOG_NOTICE:
-        level = OT_LOG_LEVEL_NOTE;
-        break;
-    case OTBR_LOG_INFO:
-        level = OT_LOG_LEVEL_INFO;
-        break;
-    case OTBR_LOG_DEBUG:
-    default:
-        level = OT_LOG_LEVEL_DEBG;
-        break;
-    }
-
-    return level;
-}
-
 } // namespace Ncp
 } // namespace otbr
diff --git a/src/ncp/thread_host.hpp b/src/ncp/thread_host.hpp
index 65e06356..5301c3ec 100644
--- a/src/ncp/thread_host.hpp
+++ b/src/ncp/thread_host.hpp
@@ -60,13 +60,40 @@ public:
      * Returns the device role.
      *
      * @returns the device role.
-     *
      */
     virtual otDeviceRole GetDeviceRole(void) const = 0;
 
     /**
-     * The destructor.
+     * Returns whether or not the IPv6 interface is up.
+     *
+     * @retval TRUE   The IPv6 interface is enabled.
+     * @retval FALSE  The IPv6 interface is disabled.
+     */
+    virtual bool Ip6IsEnabled(void) const = 0;
+
+    /**
+     * Returns the Partition ID.
      *
+     * @returns The Partition ID.
+     */
+    virtual uint32_t GetPartitionId(void) const = 0;
+
+    /**
+     * Returns the active operational dataset tlvs.
+     *
+     * @param[out] aDatasetTlvs  A reference to where the Active Operational Dataset will be placed.
+     */
+    virtual void GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const = 0;
+
+    /**
+     * Returns the pending operational dataset tlvs.
+     *
+     * @param[out] aDatasetTlvs  A reference to where the Pending Operational Dataset will be placed.
+     */
+    virtual void GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const = 0;
+
+    /**
+     * The destructor.
      */
     virtual ~NetworkProperties(void) = default;
 };
@@ -76,13 +103,21 @@ public:
  * Thread network.
  *
  * The APIs are unified for both NCP and RCP cases.
- *
  */
 class ThreadHost : virtual public NetworkProperties
 {
 public:
     using AsyncResultReceiver = std::function<void(otError, const std::string &)>;
-    using DeviceRoleHandler   = std::function<void(otError, otDeviceRole)>;
+    using ChannelMasksReceiver =
+        std::function<void(uint32_t /*aSupportedChannelMask*/, uint32_t /*aPreferredChannelMask*/)>;
+    using DeviceRoleHandler          = std::function<void(otError, otDeviceRole)>;
+    using ThreadStateChangedCallback = std::function<void(otChangedFlags aFlags)>;
+
+    struct ChannelMaxPower
+    {
+        uint16_t mChannel;
+        int16_t  mMaxPower; // INT16_MAX indicates that the corresponding channel is disabled.
+    };
 
     /**
      * Create a Thread Controller Instance.
@@ -96,7 +131,6 @@ public:
      * @param[in]   aEnableAutoAttach       Whether or not to automatically attach to the saved network.
      *
      * @returns Non-null OpenThread Controller instance.
-     *
      */
     static std::unique_ptr<ThreadHost> Create(const char                      *aInterfaceName,
                                               const std::vector<const char *> &aRadioUrls,
@@ -112,7 +146,6 @@ public:
      *
      * @param[in] aActiveOpDatasetTlvs  A reference to the active operational dataset of the Thread network.
      * @param[in] aReceiver             A receiver to get the async result of this operation.
-     *
      */
     virtual void Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aRecevier) = 0;
 
@@ -129,7 +162,6 @@ public:
      *    will be passed to @p aReceiver when the error happens.
      *
      * @param[in] aReceiver  A receiver to get the async result of this operation.
-     *
      */
     virtual void Leave(const AsyncResultReceiver &aRecevier) = 0;
 
@@ -138,20 +170,74 @@ public:
      *
      * @param[in] aPendingOpDatasetTlvs  A reference to the pending operational dataset of the Thread network.
      * @param[in] aReceiver              A receiver to get the async result of this operation.
-     *
      */
     virtual void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
                                    const AsyncResultReceiver       aReceiver) = 0;
 
     /**
-     * Returns the co-processor type.
+     * This method enables/disables the Thread network.
+     *
+     * 1. If there is an ongoing 'SetThreadEnabled' operation, no action will be taken and @p aReceiver
+     *    will be invoked with error OT_ERROR_BUSY.
+     * 2. If the host hasn't been initialized, @p aReceiver will be invoked with error OT_ERROR_INVALID_STATE.
+     * 3. When @p aEnabled is false, this method will first trigger a graceful detach and then disable Thread
+     *    network interface and the stack.
      *
+     * @param[in] aEnabled  true to enable and false to disable.
+     * @param[in] aReceiver  A receiver to get the async result of this operation.
+     */
+    virtual void SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver) = 0;
+
+    /**
+     * This method sets the country code.
+     *
+     * The country code refers to the 2-alpha code defined in ISO-3166.
+     *
+     * 1. If @p aCountryCode isn't valid, @p aReceiver will be invoked with error OT_ERROR_INVALID_ARGS.
+     * 2. If the host hasn't been initialized, @p aReceiver will be invoked with error OT_ERROR_INVALID_STATE.
+     *
+     * @param[in] aCountryCode  The country code.
+     */
+    virtual void SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver) = 0;
+
+    /**
+     * Gets the supported and preferred channel masks.
+     *
+     * If the operation succeeded, @p aReceiver will be invoked with the supported and preferred channel masks.
+     * Otherwise, @p aErrReceiver will be invoked with the error and @p aReceiver won't be invoked in this case.
+     *
+     * @param aReceiver     A receiver to get the channel masks.
+     * @param aErrReceiver  A receiver to get the error if the operation fails.
+     */
+    virtual void GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver) = 0;
+
+    /**
+     * Sets the max power of each channel.
+     *
+     * 1. If the host hasn't been initialized, @p aReceiver will be invoked with error OT_ERROR_INVALID_STATE.
+     * 2. If any value in @p aChannelMaxPowers is invalid, @p aReceiver will be invoked with error
+     * OT_ERROR_INVALID_ARGS.
+     *
+     * @param[in] aChannelMaxPowers  A vector of ChannelMaxPower.
+     * @param[in] aReceiver          A receiver to get the async result of this operation.
+     */
+    virtual void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
+                                     const AsyncResultReceiver          &aReceiver) = 0;
+
+    /**
+     * This method adds a event listener for Thread state changes.
+     *
+     * @param[in] aCallback  The callback to receive Thread state changed events.
+     */
+    virtual void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) = 0;
+
+    /**
+     * Returns the co-processor type.
      */
     virtual CoprocessorType GetCoprocessorType(void) = 0;
 
     /**
      * Returns the co-processor version string.
-     *
      */
     virtual const char *GetCoprocessorVersion(void) = 0;
 
@@ -159,30 +245,23 @@ public:
      * This method returns the Thread network interface name.
      *
      * @returns A pointer to the Thread network interface name string.
-     *
      */
     virtual const char *GetInterfaceName(void) const = 0;
 
     /**
      * Initializes the Thread controller.
-     *
      */
     virtual void Init(void) = 0;
 
     /**
      * Deinitializes the Thread controller.
-     *
      */
     virtual void Deinit(void) = 0;
 
     /**
      * The destructor.
-     *
      */
     virtual ~ThreadHost(void) = default;
-
-protected:
-    static otLogLevel ConvertToOtLogLevel(otbrLogLevel aLevel);
 };
 
 } // namespace Ncp
diff --git a/src/openwrt/ubus/otubus.hpp b/src/openwrt/ubus/otubus.hpp
index 8c44255e..f9131c73 100644
--- a/src/openwrt/ubus/otubus.hpp
+++ b/src/openwrt/ubus/otubus.hpp
@@ -68,7 +68,6 @@ namespace ubus {
  *
  * @brief
  *   This namespace contains definitions for ubus related instance.
- *
  */
 
 class UbusServer
@@ -86,13 +85,11 @@ public:
      * This method return the instance of the global UbusServer.
      *
      * @retval The reference of the UbusServer Instance.
-     *
      */
     static UbusServer &GetInstance(void);
 
     /**
      * This method install ubus object onto OpenWRT.
-     *
      */
     void InstallUbusObject(void);
 
@@ -106,7 +103,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusScanHandler(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
@@ -124,7 +120,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusChannelHandler(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
@@ -142,7 +137,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetChannelHandler(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
@@ -160,7 +154,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusNetworknameHandler(struct ubus_context      *aContext,
                                       struct ubus_object       *aObj,
@@ -178,7 +171,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetNetworknameHandler(struct ubus_context      *aContext,
                                          struct ubus_object       *aObj,
@@ -196,7 +188,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusStateHandler(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
@@ -214,7 +205,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMacfilterSetStateHandler(struct ubus_context      *aContext,
                                             struct ubus_object       *aObj,
@@ -232,7 +222,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusPanIdHandler(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
@@ -250,7 +239,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetPanIdHandler(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
@@ -268,7 +256,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusPskcHandler(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
@@ -286,7 +273,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetPskcHandler(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
@@ -304,7 +290,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusNetworkkeyHandler(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
@@ -322,7 +307,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetNetworkkeyHandler(struct ubus_context      *aContext,
                                         struct ubus_object       *aObj,
@@ -340,7 +324,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusRloc16Handler(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
@@ -358,7 +341,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusExtPanIdHandler(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
@@ -376,7 +358,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetExtPanIdHandler(struct ubus_context      *aContext,
                                       struct ubus_object       *aObj,
@@ -394,7 +375,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusModeHandler(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
@@ -412,7 +392,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusSetModeHandler(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
@@ -430,7 +409,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusPartitionIdHandler(struct ubus_context      *aContext,
                                       struct ubus_object       *aObj,
@@ -448,7 +426,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusLeaderdataHandler(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
@@ -466,7 +443,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusNetworkdataHandler(struct ubus_context      *aContext,
                                       struct ubus_object       *aObj,
@@ -484,7 +460,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusParentHandler(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
@@ -502,7 +477,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusNeighborHandler(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
@@ -520,7 +494,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusThreadStartHandler(struct ubus_context      *aContext,
                                       struct ubus_object       *aObj,
@@ -538,7 +511,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusThreadStopHandler(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
@@ -556,7 +528,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusLeaveHandler(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
@@ -574,7 +545,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMacfilterAddrHandler(struct ubus_context      *aContext,
                                         struct ubus_object       *aObj,
@@ -592,7 +562,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMacfilterStateHandler(struct ubus_context      *aContext,
                                          struct ubus_object       *aObj,
@@ -610,7 +579,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMacfilterAddHandler(struct ubus_context      *aContext,
                                        struct ubus_object       *aObj,
@@ -628,7 +596,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMacfilterClearHandler(struct ubus_context      *aContext,
                                          struct ubus_object       *aObj,
@@ -646,7 +613,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMacfilterRemoveHandler(struct ubus_context      *aContext,
                                           struct ubus_object       *aObj,
@@ -664,7 +630,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusCommissionerStartHandler(struct ubus_context      *aContext,
                                             struct ubus_object       *aObj,
@@ -682,7 +647,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusJoinerAddHandler(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
@@ -700,7 +664,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusJoinerRemoveHandler(struct ubus_context      *aContext,
                                        struct ubus_object       *aObj,
@@ -718,7 +681,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusJoinerNumHandler(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
@@ -736,7 +698,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusMgmtsetHandler(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
@@ -754,7 +715,6 @@ public:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     static int UbusInterfaceNameHandler(struct ubus_context      *aContext,
                                         struct ubus_object       *aObj,
@@ -769,7 +729,6 @@ public:
      * @param[in] aMessage      A pointer to the message.
      * @param[in] aMessageInfo  A pointer to the message information.
      * @param[in] aContext      A pointer to the context.
-     *
      */
     static void HandleDiagnosticGetResponse(otError              aError,
                                             otMessage           *aMessage,
@@ -782,7 +741,6 @@ public:
      * @param[in] aError       A error of receiving the diagnostic response.
      * @param[in] aMessage     A pointer to the message.
      * @param[in] aMessageInfo A pointer to the message information.
-     *
      */
     void HandleDiagnosticGetResponse(otError aError, otMessage *aMessage, const otMessageInfo *aMessageInfo);
 
@@ -810,7 +768,6 @@ private:
 
     /**
      * This method start scan.
-     *
      */
     void ProcessScan(void);
 
@@ -824,7 +781,6 @@ private:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusScanHandlerDetail(struct ubus_context      *aContext,
                               struct ubus_object       *aObj,
@@ -837,7 +793,6 @@ private:
      *
      * @param[in] aResult   A pointer to result.
      * @param[in] aContext  A pointer to context.
-     *
      */
     static void HandleActiveScanResult(otActiveScanResult *aResult, void *aContext);
 
@@ -845,7 +800,6 @@ private:
      * This method detailly handler the scan result, called by HandleActiveScanResult.
      *
      * @param[in] aResult  A pointer to result.
-     *
      */
     void HandleActiveScanResultDetail(otActiveScanResult *aResult);
 
@@ -859,7 +813,6 @@ private:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusNeighborHandlerDetail(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
@@ -877,7 +830,6 @@ private:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusParentHandlerDetail(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
@@ -895,7 +847,6 @@ private:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusMgmtset(struct ubus_context      *aContext,
                     struct ubus_object       *aObj,
@@ -913,7 +864,6 @@ private:
      * @param[in] aMsg      A pointer to the ubus message.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusLeaveHandlerDetail(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
@@ -932,7 +882,6 @@ private:
      * @param[in] aAction   A pointer to the action needed.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusThreadHandler(struct ubus_context      *aContext,
                           struct ubus_object       *aObj,
@@ -952,7 +901,6 @@ private:
      * @param[in] aAction   A pointer to the action needed.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusGetInformation(struct ubus_context      *aContext,
                            struct ubus_object       *aObj,
@@ -972,7 +920,6 @@ private:
      * @param[in] aAction   A pointer to the action needed.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusSetInformation(struct ubus_context      *aContext,
                            struct ubus_object       *aObj,
@@ -992,7 +939,6 @@ private:
      * @param[in] aAction   A pointer to the action needed.
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int UbusCommissioner(struct ubus_context      *aContext,
                          struct ubus_object       *aObj,
@@ -1006,7 +952,6 @@ private:
      *
      * @param[in] aState    The state of commissioner.
      * @param[in] aContext  A pointer to the ubus context.
-     *
      */
     static void HandleStateChanged(otCommissionerState aState, void *aContext);
 
@@ -1014,7 +959,6 @@ private:
      * This method handle conmmissione state change.
      *
      * @param[in] aState  The state of commissioner.
-     *
      */
     void HandleStateChanged(otCommissionerState aState);
 
@@ -1025,7 +969,6 @@ private:
      * @param[in] aJoinerInfo  A pointer to the Joiner Info.
      * @param[in] aJoinerId    A pointer to the Joiner ID (if not known, it will be NULL).
      * @param[in] aContext     A pointer to application-specific context.
-     *
      */
     static void HandleJoinerEvent(otCommissionerJoinerEvent aEvent,
                                   const otJoinerInfo       *aJoinerInfo,
@@ -1038,7 +981,6 @@ private:
      * @param[in] aEvent       The joiner event type.
      * @param[in] aJoinerInfo  A pointer to the Joiner Info.
      * @param[in] aJoinerId    A pointer to the Joiner ID (if not known, it will be NULL).
-     *
      */
     void HandleJoinerEvent(otCommissionerJoinerEvent aEvent,
                            const otJoinerInfo       *aJoinerInfo,
@@ -1049,13 +991,11 @@ private:
      *
      * @param[in]  aInstance  A pointer to the instance.
      * @param[out] aState     A pointer to the string address.
-     *
      */
     void GetState(otInstance *aInstance, char *aState);
 
     /**
      * This method add fd of ubus object.
-     *
      */
     void UbusAddFd(void);
 
@@ -1063,7 +1003,6 @@ private:
      * This method set ubus reconnect time.
      *
      * @param[in] aTimeout  A pointer to the timeout.
-     *
      */
     static void UbusReconnTimer(struct uloop_timeout *aTimeout);
 
@@ -1071,7 +1010,6 @@ private:
      * This method detailly handle ubus reconnect time.
      *
      * @param[in] aTimeout  A pointer to the timeout.
-     *
      */
     void UbusReconnTimerDetail(struct uloop_timeout *aTimeout);
 
@@ -1079,7 +1017,6 @@ private:
      * This method handle ubus connection lost.
      *
      * @param[in] aContext  A pointer to the context.
-     *
      */
     static void UbusConnectionLost(struct ubus_context *aContext);
 
@@ -1089,13 +1026,11 @@ private:
      * @param[in] aPath  A pointer to the ubus server path(default is nullptr).
      *
      * @retval 0  Successfully handler the request.
-     *
      */
     int DisplayUbusInit(const char *aPath);
 
     /**
      * This method disconnect and display ubus.
-     *
      */
     void DisplayUbusDone(void);
 
@@ -1107,7 +1042,6 @@ private:
      *
      * @retval OT_ERROR_NONE   Successfully parsed the ASCII string.
      * @retval OT_ERROR_PARSE  Could not parse the ASCII string.
-     *
      */
     otError ParseLong(char *aString, long &aLong);
 
@@ -1128,7 +1062,6 @@ private:
      * @param[in]  aBytes   A pointer to the bytes need to be convert.
      * @param[in]  aLength  The length of the bytes.
      * @param[out] aOutput  A pointer to the char* string.
-     *
      */
     void OutputBytes(const uint8_t *aBytes, uint8_t aLength, char *aOutput);
 
@@ -1138,7 +1071,6 @@ private:
      * @param[in] aError    The error type of the message.
      * @param[in] aContext  A pointer to the context.
      * @param[in] aRequest  A pointer to the request.
-     *
      */
     void AppendResult(otError aError, struct ubus_context *aContext, struct ubus_request_data *aRequest);
 };
@@ -1150,7 +1082,6 @@ public:
      * The constructor to initialize the UBus agent.
      *
      * @param[in] aHost  A reference to the Thread controller.
-     *
      */
     UBusAgent(otbr::Ncp::RcpHost &aHost)
         : mHost(aHost)
@@ -1160,7 +1091,6 @@ public:
 
     /**
      * This method initializes the UBus agent.
-     *
      */
     void Init(void);
 
diff --git a/src/proto/threadnetwork_atoms.proto b/src/proto/threadnetwork_atoms.proto
index e8ca7ea7..29980765 100644
--- a/src/proto/threadnetwork_atoms.proto
+++ b/src/proto/threadnetwork_atoms.proto
@@ -241,6 +241,12 @@ message ThreadnetworkTelemetryDataReported {
     SRP_SERVER_ADDRESS_MODE_STATE_ANYCAST = 2;
   }
 
+  enum UpstreamDnsQueryState {
+    UPSTREAMDNS_QUERY_STATE_UNSPECIFIED = 0;
+    UPSTREAMDNS_QUERY_STATE_ENABLED = 1;
+    UPSTREAMDNS_QUERY_STATE_DISABLED = 2;
+  }
+
   message SrpServerInfo {
     // The state of the SRP server
     optional SrpServerState state = 1;
@@ -278,6 +284,15 @@ message ThreadnetworkTelemetryDataReported {
 
     // The number of other responses
     optional uint32 other_count = 6;
+
+    // The number of queries handled by Upstream DNS server.
+    optional uint32 upstream_dns_queries = 7;
+
+    // The number of responses handled by Upstream DNS server.
+    optional uint32 upstream_dns_responses = 8;
+
+    // The number of upstream DNS failures.
+    optional uint32 upstream_dns_failures = 9;
   }
 
   message DnsServerInfo {
@@ -286,6 +301,9 @@ message ThreadnetworkTelemetryDataReported {
 
     // The number of DNS queries resolved at the local SRP server
     optional uint32 resolved_by_local_srp_count = 2;
+
+    // The state of upstream DNS query
+    optional UpstreamDnsQueryState upstream_dns_query_state = 3;
   }
 
   message MdnsResponseCounters {
@@ -355,6 +373,93 @@ message ThreadnetworkTelemetryDataReported {
     optional Nat64State translator_state = 2;
   }
 
+  message TrelPacketCounters {
+    // The number of packets successfully transmitted through TREL
+    optional uint64 trel_tx_packets = 1;
+
+    // The number of bytes successfully transmitted through TREL
+    optional uint64 trel_tx_bytes = 2;
+
+    // The number of packet transmission failures through TREL
+    optional uint64 trel_tx_packets_failed = 3;
+
+    // The number of packets successfully received through TREL
+    optional uint64 trel_rx_packets = 4;
+
+    // The number of bytes successfully received through TREL
+    optional uint64 trel_rx_bytes = 5;
+  }
+
+  message TrelInfo {
+    // Whether TREL is enabled.
+    optional bool is_trel_enabled = 1;
+
+    // The number of TREL peers.
+    optional uint32 num_trel_peers = 2;
+
+    // TREL packet counters
+    optional TrelPacketCounters counters = 3;
+  }
+
+  message BorderAgentCounters {
+    // The number of ePSKc activations
+    optional uint32 epskc_activations = 1;
+
+    // The number of ePSKc deactivations due to cleared via API
+    optional uint32 epskc_deactivation_clears = 2;
+
+    // The number of ePSKc deactivations due to timeout
+    optional uint32 epskc_deactivation_timeouts = 3;
+
+    // The number of ePSKc deactivations due to max connection attempts reached
+    optional uint32 epskc_deactivation_max_attempts = 4;
+
+    // The number of ePSKc deactivations due to commissioner disconnected
+    optional uint32 epskc_deactivation_disconnects = 5;
+
+    // The number of ePSKc activation failures caused by invalid border agent
+    // state
+    optional uint32 epskc_invalid_ba_state_errors = 6;
+
+    // The number of ePSKc activation failures caused by invalid argument
+    optional uint32 epskc_invalid_args_errors = 7;
+
+    // The number of ePSKc activation failures caused by failed to start secure
+    // session
+    optional uint32 epskc_start_secure_session_errors = 8;
+
+    // The number of successful secure session establishment with ePSKc
+    optional uint32 epskc_secure_session_successes = 9;
+
+    // The number of failed secure session establishement with ePSKc
+    optional uint32 epskc_secure_session_failures = 10;
+
+    // The number of active commissioner petitioned over secure session
+    // establishment with ePSKc
+    optional uint32 epskc_commissioner_petitions = 11;
+
+    // The number of successful secure session establishment with PSKc
+    optional uint32 pskc_secure_session_successes = 12;
+
+    // The number of failed secure session establishement with PSKc
+    optional uint32 pskc_secure_session_failures = 13;
+
+    // The number of active commissioner petitioned over secure session
+    // establishment with PSKc
+    optional uint32 pskc_commissioner_petitions = 14;
+
+    // The number of MGMT_ACTIVE_GET.req received
+    optional uint32 mgmt_active_get_reqs = 15;
+
+    // The number of MGMT_PENDING_GET.req received
+    optional uint32 mgmt_pending_get_reqs = 16;
+  }
+
+  message BorderAgentInfo {
+    // The border agent counters
+    optional BorderAgentCounters border_agent_counters = 1;
+  }
+
   message WpanBorderRouter {
     // Border routing counters
     optional BorderRoutingCounters border_routing_counters = 1;
@@ -370,6 +475,12 @@ message ThreadnetworkTelemetryDataReported {
 
     // Information about the state of components of NAT64
     optional BorderRoutingNat64State nat64_state = 5;
+
+    // Information about TREL.
+    optional TrelInfo trel_info = 6;
+
+    // Information about the Border Agent
+    optional BorderAgentInfo border_agent_info = 7;
   }
 
   message RcpStabilityStatistics {
diff --git a/src/rest/connection.hpp b/src/rest/connection.hpp
index 728c2b7e..9ac30373 100644
--- a/src/rest/connection.hpp
+++ b/src/rest/connection.hpp
@@ -50,7 +50,6 @@ namespace rest {
 
 /**
  * This class implements a Connection class of each socket connection.
- *
  */
 class Connection : public MainloopProcessor
 {
@@ -64,20 +63,16 @@ public:
      *                        state.
      * @param[in] aResource   A pointer to the resource handler.
      * @param[in] aFd         The file descriptor for the connection.
-     *
      */
     Connection(steady_clock::time_point aStartTime, Resource *aResource, int aFd);
 
     /**
      * The desctructor destroys the connection instance.
-     *
      */
     ~Connection(void) override;
 
     /**
      * This method initializes the connection.
-     *
-     *
      */
     void Init(void);
 
@@ -89,7 +84,6 @@ public:
      *
      * @retval TRUE   This connection could be released in next loop.
      * @retval FALSE  This connection still needs to be processed in next loop.
-     *
      */
     bool IsComplete(void) const;
 
diff --git a/src/rest/json.hpp b/src/rest/json.hpp
index 7df74db5..22cc0f94 100644
--- a/src/rest/json.hpp
+++ b/src/rest/json.hpp
@@ -49,7 +49,6 @@ namespace rest {
 /**
  * The functions within this namespace provides a tranformation from an object/string/number to a serialized Json
  * string.
- *
  */
 namespace Json {
 
@@ -59,7 +58,6 @@ namespace Json {
  * @param[in] aNumber  An integer need to be format.
  *
  * @returns A string of serialized Json number.
- *
  */
 std::string Number2JsonString(const uint32_t &aNumber);
 
@@ -69,7 +67,6 @@ std::string Number2JsonString(const uint32_t &aNumber);
  * @param[in] aBytes  A Bytes array representing a hex number.
  *
  * @returns A string of serialized Json string.
- *
  */
 std::string Bytes2HexJsonString(const uint8_t *aBytes, uint8_t aLength);
 
@@ -81,7 +78,6 @@ std::string Bytes2HexJsonString(const uint8_t *aBytes, uint8_t aLength);
  * @param[in] aMaxLength Maximum length to parse (in bytes).
  *
  * @returns Number of bytes effectively parsed.
- *
  */
 int Hex2BytesJsonString(const std::string &aHexString, uint8_t *aBytes, uint8_t aMaxLength);
 
@@ -91,7 +87,6 @@ int Hex2BytesJsonString(const std::string &aHexString, uint8_t *aBytes, uint8_t
  * @param[in] aCString  A char pointer pointing to a C string.
  *
  * @returns A string of serialized Json string.
- *
  */
 std::string CString2JsonString(const char *aCString);
 
@@ -101,7 +96,6 @@ std::string CString2JsonString(const char *aCString);
  * @param[in] aString  A string.
  *
  * @returns A string of serialized Json string.
- *
  */
 std::string String2JsonString(const std::string &aString);
 
@@ -121,7 +115,6 @@ bool JsonString2String(const std::string &aJsonString, std::string &aString);
  * @param[in] aNode  A Node object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string Node2JsonString(const NodeInfo &aNode);
 
@@ -131,7 +124,6 @@ std::string Node2JsonString(const NodeInfo &aNode);
  * @param[in] aDiagSet  A vector of diagnostic objects.
  *
  * @returns A string of serialized Json array.
- *
  */
 std::string Diag2JsonString(const std::vector<std::vector<otNetworkDiagTlv>> &aDiagSet);
 
@@ -141,7 +133,6 @@ std::string Diag2JsonString(const std::vector<std::vector<otNetworkDiagTlv>> &aD
  * @param[in] aAddress  An Ip6Address object.
  *
  * @returns A string of serialized Json string.
- *
  */
 std::string IpAddr2JsonString(const otIp6Address &aAddress);
 
@@ -151,7 +142,6 @@ std::string IpAddr2JsonString(const otIp6Address &aAddress);
  * @param[in] aMode  A LinkModeConfig object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string Mode2JsonString(const otLinkModeConfig &aMode);
 
@@ -161,7 +151,6 @@ std::string Mode2JsonString(const otLinkModeConfig &aMode);
  * @param[in] aConnectivity  A Connectivity object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string Connectivity2JsonString(const otNetworkDiagConnectivity &aConnectivity);
 
@@ -171,7 +160,6 @@ std::string Connectivity2JsonString(const otNetworkDiagConnectivity &aConnectivi
  * @param[in] aRoute  A Route object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string Route2JsonString(const otNetworkDiagRoute &aRoute);
 
@@ -181,7 +169,6 @@ std::string Route2JsonString(const otNetworkDiagRoute &aRoute);
  * @param[in] aRouteData  A RouteData object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string RouteData2JsonString(const otNetworkDiagRouteData &aRouteData);
 
@@ -191,7 +178,6 @@ std::string RouteData2JsonString(const otNetworkDiagRouteData &aRouteData);
  * @param[in] aLeaderData  A LeaderData object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string LeaderData2JsonString(const otLeaderData &aLeaderData);
 
@@ -201,7 +187,6 @@ std::string LeaderData2JsonString(const otLeaderData &aLeaderData);
  * @param[in] aMacCounters  A MacCounters object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string MacCounters2JsonString(const otNetworkDiagMacCounters &aMacCounters);
 
@@ -211,7 +196,6 @@ std::string MacCounters2JsonString(const otNetworkDiagMacCounters &aMacCounters)
  * @param[in] aChildEntry  A ChildEntry object.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string ChildTableEntry2JsonString(const otNetworkDiagChildEntry &aChildEntry);
 
@@ -222,7 +206,6 @@ std::string ChildTableEntry2JsonString(const otNetworkDiagChildEntry &aChildEntr
  * @param[in] aErrorMessage  Error message such as '404 Not Found'.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string Error2JsonString(HttpStatusCode aErrorCode, std::string aErrorMessage);
 
@@ -232,7 +215,6 @@ std::string Error2JsonString(HttpStatusCode aErrorCode, std::string aErrorMessag
  * @param[in] aDataset  A dataset struct.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string ActiveDataset2JsonString(const otOperationalDataset &aDataset);
 
@@ -242,7 +224,6 @@ std::string ActiveDataset2JsonString(const otOperationalDataset &aDataset);
  * @param[in] aDataset  A dataset struct.
  *
  * @returns A string of serialized Json object.
- *
  */
 std::string PendingDataset2JsonString(const otOperationalDataset &aPendingDataset);
 
@@ -255,7 +236,6 @@ std::string PendingDataset2JsonString(const otOperationalDataset &aPendingDatase
  * @param[in] aDataset            The dataset struct to be filled.
  *
  * @returns If the Json string has been successfully parsed.
- *
  */
 bool JsonActiveDatasetString2Dataset(const std::string &aJsonActiveDataset, otOperationalDataset &aDataset);
 
@@ -268,7 +248,6 @@ bool JsonActiveDatasetString2Dataset(const std::string &aJsonActiveDataset, otOp
  * @param[in] aDataset            The dataset struct to be filled.
  *
  * @returns If the Json string has been successfully parsed.
- *
  */
 bool JsonPendingDatasetString2Dataset(const std::string &aJsonPendingDataset, otOperationalDataset &aDataset);
 
diff --git a/src/rest/parser.hpp b/src/rest/parser.hpp
index b79d79a8..f5437878 100644
--- a/src/rest/parser.hpp
+++ b/src/rest/parser.hpp
@@ -51,7 +51,6 @@ namespace rest {
 
 /**
  * This class implements Parser class in OTBR-REST which is used to parse the data from read buffer and form a request.
- *
  */
 class Parser
 {
@@ -60,13 +59,11 @@ public:
      * The constructor of a http request parser instance.
      *
      * @param[in] aRequest  A pointer to a request instance.
-     *
      */
     Parser(Request *aRequest);
 
     /**
      * This method initializea the http-parser.
-     *
      */
     void Init(void);
 
@@ -75,7 +72,6 @@ public:
      *
      * @param[in] aBuf     A pointer pointing to read buffer.
      * @param[in] aLength  An integer indicates how much data is to be processed by parser.
-     *
      */
     void Process(const char *aBuf, size_t aLength);
 
diff --git a/src/rest/request.hpp b/src/rest/request.hpp
index ceb92a5f..ccae84f5 100644
--- a/src/rest/request.hpp
+++ b/src/rest/request.hpp
@@ -47,14 +47,12 @@ namespace rest {
 
 /**
  * This class implements an instance to host services used by border router.
- *
  */
 class Request
 {
 public:
     /**
      * The constructor is to initialize Request instance.
-     *
      */
     Request(void);
 
@@ -63,7 +61,6 @@ public:
      *
      * @param[in] aString  A pointer points to url string.
      * @param[in] aLength  Length of the url string
-     *
      */
     void SetUrl(const char *aString, size_t aLength);
 
@@ -72,7 +69,6 @@ public:
      *
      * @param[in] aString  A pointer points to body string.
      * @param[in] aLength  Length of the body string
-     *
      */
     void SetBody(const char *aString, size_t aLength);
 
@@ -80,7 +76,6 @@ public:
      * This method sets the content-length field of a request.
      *
      * @param[in] aContentLength  An unsigned integer representing content-length.
-     *
      */
     void SetContentLength(size_t aContentLength);
 
@@ -88,7 +83,6 @@ public:
      * This method sets the method of the parsed request.
      *
      * @param[in] aMethod  An integer representing request method.
-     *
      */
     void SetMethod(int32_t aMethod);
 
@@ -97,7 +91,6 @@ public:
      *
      * @param[in] aString  A pointer points to body string.
      * @param[in] aLength  Length of the body string
-     *
      */
     void SetNextHeaderField(const char *aString, size_t aLength);
 
@@ -106,19 +99,16 @@ public:
      *
      * @param[in] aString  A pointer points to body string.
      * @param[in] aLength  Length of the body string
-     *
      */
     void SetHeaderValue(const char *aString, size_t aLength);
 
     /**
      * This method labels the request as complete which means it no longer need to be parsed one more time .
-     *
      */
     void SetReadComplete(void);
 
     /**
      * This method resets the request then it could be set by parser from start.
-     *
      */
     void ResetReadComplete(void);
 
@@ -153,8 +143,6 @@ public:
 
     /**
      * This method indicates whether this request is parsed completely.
-     *
-     *
      */
     bool IsComplete(void) const;
 
diff --git a/src/rest/resource.hpp b/src/rest/resource.hpp
index 0929dbcc..7982843b 100644
--- a/src/rest/resource.hpp
+++ b/src/rest/resource.hpp
@@ -58,7 +58,6 @@ namespace rest {
 
 /**
  * This class implements the Resource handler for OTBR-REST.
- *
  */
 class Resource
 {
@@ -67,14 +66,11 @@ public:
      * The constructor initializes the resource handler instance.
      *
      * @param[in] aHost  A pointer to the Thread controller.
-     *
      */
     Resource(RcpHost *aHost);
 
     /**
      * This method initialize the Resource handler.
-     *
-     *
      */
     void Init(void);
 
@@ -84,7 +80,6 @@ public:
      *
      * @param[in]     aRequest  A request instance referred by the Resource handler.
      * @param[in,out] aResponse  A response instance will be set by the Resource handler.
-     *
      */
     void Handle(Request &aRequest, Response &aResponse) const;
 
@@ -93,7 +88,6 @@ public:
      *
      * @param[in]     aRequest   A request instance referred by the Resource handler.
      * @param[in,out] aResponse  A response instance will be set by the Resource handler.
-     *
      */
     void HandleCallback(Request &aRequest, Response &aResponse);
 
@@ -103,14 +97,12 @@ public:
      *
      * @param[in]     aRequest    A request instance referred by the Resource handler.
      * @param[in,out] aErrorCode  An enum class represents the status code.
-     *
      */
     void ErrorHandler(Response &aResponse, HttpStatusCode aErrorCode) const;
 
 private:
     /**
      * This enumeration represents the Dataset type (active or pending).
-     *
      */
     enum class DatasetType : uint8_t
     {
diff --git a/src/rest/response.hpp b/src/rest/response.hpp
index 2bab14c6..1f544b65 100644
--- a/src/rest/response.hpp
+++ b/src/rest/response.hpp
@@ -53,15 +53,12 @@ namespace rest {
 /**
  * This class implements a response class for OTBR_REST, it could be manipulated by connection instance and resource
  * handler.
- *
  */
 class Response
 {
 public:
     /**
      * The constructor to initialize a response instance.
-     *
-     *
      */
     Response(void);
 
@@ -69,7 +66,6 @@ public:
      * This method set the response body.
      *
      * @param[in] aBody  A string to be set as response body.
-     *
      */
     void SetBody(std::string &aBody);
 
@@ -84,7 +80,6 @@ public:
      * This method set the response code.
      *
      * @param[in] aCode  A string representing response code such as "404 not found".
-     *
      */
     void SetResponsCode(std::string &aCode);
 
@@ -92,14 +87,11 @@ public:
      * This method sets the content type.
      *
      * @param[in] aCode  A string representing response content type such as text/plain.
-     *
      */
     void SetContentType(const std::string &aContentType);
 
     /**
      * This method labels the response as need callback.
-     *
-     *
      */
     void SetCallback(void);
 
@@ -112,7 +104,6 @@ public:
 
     /**
      * This method labels the response as complete which means all fields has been successfully set.
-     *
      */
     void SetComplete();
 
diff --git a/src/rest/rest_web_server.hpp b/src/rest/rest_web_server.hpp
index 20e4a5b6..08074c54 100644
--- a/src/rest/rest_web_server.hpp
+++ b/src/rest/rest_web_server.hpp
@@ -51,7 +51,6 @@ namespace rest {
 
 /**
  * This class implements a REST server.
- *
  */
 class RestWebServer : public MainloopProcessor
 {
@@ -60,19 +59,16 @@ public:
      * The constructor to initialize a REST server.
      *
      * @param[in] aHost  A reference to the Thread controller.
-     *
      */
     RestWebServer(RcpHost &aHost, const std::string &aRestListenAddress, int aRestListenPort);
 
     /**
      * The destructor destroys the server instance.
-     *
      */
     ~RestWebServer(void) override;
 
     /**
      * This method initializes the REST server.
-     *
      */
     void Init(void);
 
diff --git a/src/sdp_proxy/advertising_proxy.hpp b/src/sdp_proxy/advertising_proxy.hpp
index 4b1931d0..2077d350 100644
--- a/src/sdp_proxy/advertising_proxy.hpp
+++ b/src/sdp_proxy/advertising_proxy.hpp
@@ -51,7 +51,6 @@ namespace otbr {
 
 /**
  * This class implements the Advertising Proxy.
- *
  */
 class AdvertisingProxy : private NonCopyable
 {
@@ -61,7 +60,6 @@ public:
      *
      * @param[in] aHost       A reference to the NCP controller.
      * @param[in] aPublisher  A reference to the mDNS publisher.
-     *
      */
     explicit AdvertisingProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
@@ -69,13 +67,11 @@ public:
      * This method enables/disables the Advertising Proxy.
      *
      * @param[in] aIsEnabled  Whether to enable the Advertising Proxy.
-     *
      */
     void SetEnabled(bool aIsEnabled);
 
     /**
      * This method publishes all registered hosts and services.
-     *
      */
     void PublishAllHostsAndServices(void);
 
@@ -83,7 +79,6 @@ public:
      * This method handles mDNS publisher's state changes.
      *
      * @param[in] aState  The state of mDNS publisher.
-     *
      */
     void HandleMdnsState(Mdns::Publisher::State aState);
 
@@ -122,7 +117,6 @@ private:
      *
      * @retval  OTBR_ERROR_NONE  Successfully published the host and its services.
      * @retval  ...              Failed to publish the host and/or its services.
-     *
      */
     otbrError PublishHostAndItsServices(const otSrpServerHost *aHost, OutstandingUpdate *aUpdate);
 
diff --git a/src/sdp_proxy/discovery_proxy.hpp b/src/sdp_proxy/discovery_proxy.hpp
index 188a81bf..9278cf49 100644
--- a/src/sdp_proxy/discovery_proxy.hpp
+++ b/src/sdp_proxy/discovery_proxy.hpp
@@ -55,7 +55,6 @@ namespace Dnssd {
 
 /**
  * This class implements the DNS-SD Discovery Proxy.
- *
  */
 class DiscoveryProxy : private NonCopyable
 {
@@ -65,7 +64,6 @@ public:
      *
      * @param[in] aHost       A reference to the OpenThread Controller instance.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
-     *
      */
     explicit DiscoveryProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
@@ -73,7 +71,6 @@ public:
      * This method enables/disables the Discovery Proxy.
      *
      * @param[in] aIsEnabled  Whether to enable the Discovery Proxy.
-     *
      */
     void SetEnabled(bool aIsEnabled);
 
@@ -81,7 +78,6 @@ public:
      * This method handles mDNS publisher's state changes.
      *
      * @param[in] aState  The state of mDNS publisher.
-     *
      */
     void HandleMdnsState(Mdns::Publisher::State aState)
     {
diff --git a/src/trel_dnssd/trel_dnssd.cpp b/src/trel_dnssd/trel_dnssd.cpp
index 7cf4adc2..a80a2e77 100644
--- a/src/trel_dnssd/trel_dnssd.cpp
+++ b/src/trel_dnssd/trel_dnssd.cpp
@@ -91,6 +91,9 @@ TrelDnssd::TrelDnssd(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
 void TrelDnssd::Initialize(std::string aTrelNetif)
 {
     mTrelNetif = std::move(aTrelNetif);
+    // Reset mTrelNetifIndex to 0 so that when this function is called with a different aTrelNetif
+    // than the current mTrelNetif, CheckTrelNetifReady() will update mTrelNetifIndex accordingly.
+    mTrelNetifIndex = 0;
 
     if (IsInitialized())
     {
@@ -190,7 +193,6 @@ exit:
 
 void TrelDnssd::HandleMdnsState(Mdns::Publisher::State aState)
 {
-    VerifyOrExit(IsInitialized());
     VerifyOrExit(aState == Mdns::Publisher::State::kReady);
 
     otbrLogDebug("mDNS Publisher is Ready");
@@ -202,6 +204,7 @@ void TrelDnssd::HandleMdnsState(Mdns::Publisher::State aState)
         mRegisterInfo.mInstanceName = "";
     }
 
+    VerifyOrExit(IsInitialized());
     OnBecomeReady();
 
 exit:
diff --git a/src/trel_dnssd/trel_dnssd.hpp b/src/trel_dnssd/trel_dnssd.hpp
index 6c8555c9..d6856b1d 100644
--- a/src/trel_dnssd/trel_dnssd.hpp
+++ b/src/trel_dnssd/trel_dnssd.hpp
@@ -68,7 +68,6 @@ public:
      *
      * @param[in] aHost       A reference to the OpenThread Controller instance.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
-     *
      */
     explicit TrelDnssd(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
@@ -76,19 +75,16 @@ public:
      * This method initializes the TrelDnssd instance.
      *
      * @param[in] aTrelNetif  The network interface for discovering TREL peers.
-     *
      */
     void Initialize(std::string aTrelNetif);
 
     /**
      * This method starts browsing for TREL peers.
-     *
      */
     void StartBrowse(void);
 
     /**
      * This method stops browsing for TREL peers.
-     *
      */
     void StopBrowse(void);
 
@@ -98,13 +94,11 @@ public:
      * @param[in] aPort         The UDP port of TREL service.
      * @param[in] aTxtData      The TXT data of TREL service.
      * @param[in] aTxtLength    The TXT length of TREL service.
-     *
      */
     void RegisterService(uint16_t aPort, const uint8_t *aTxtData, uint8_t aTxtLength);
 
     /**
      * This method removes the TREL service from DNS-SD.
-     *
      */
     void UnregisterService(void);
 
@@ -112,7 +106,6 @@ public:
      * This method handles mDNS publisher's state changes.
      *
      * @param[in] aState  The state of mDNS publisher.
-     *
      */
     void HandleMdnsState(Mdns::Publisher::State aState);
 
diff --git a/src/utils/crc16.hpp b/src/utils/crc16.hpp
index 6d2167c0..19ae8c60 100644
--- a/src/utils/crc16.hpp
+++ b/src/utils/crc16.hpp
@@ -42,7 +42,6 @@ namespace otbr {
 
 /**
  * This class implements CRC16 computations.
- *
  */
 class Crc16
 {
@@ -57,13 +56,11 @@ public:
      * This constructor initializes the object.
      *
      * @param[in] aPolynomial  The polynomial value.
-     *
      */
     Crc16(Polynomial aPolynomial);
 
     /**
      * This method initializes the CRC16 computation.
-     *
      */
     void Init(void) { mCrc = 0; }
 
@@ -71,7 +68,6 @@ public:
      * This method feeds a byte value into the CRC16 computation.
      *
      * @param[in] aByte  The byte value.
-     *
      */
     void Update(uint8_t aByte);
 
@@ -79,7 +75,6 @@ public:
      * This method gets the current CRC16 value.
      *
      * @returns The current CRC16 value.
-     *
      */
     uint16_t Get(void) const { return mCrc; }
 
diff --git a/src/utils/dns_utils.hpp b/src/utils/dns_utils.hpp
index 9addf66f..829112bc 100644
--- a/src/utils/dns_utils.hpp
+++ b/src/utils/dns_utils.hpp
@@ -51,7 +51,6 @@ namespace DnsUtils {
  * @param[in] aName  The DNS Service Instance name to unescape.
  *
  * @returns  The unescaped DNS Service Instance name.
- *
  */
 std::string UnescapeInstanceName(const std::string &aName);
 
@@ -62,7 +61,6 @@ std::string UnescapeInstanceName(const std::string &aName);
  *      The host name must ends with dot.
  *
  * @param[in] aHostName  The host name to check.
- *
  */
 void CheckHostnameSanity(const std::string &aHostName);
 
@@ -74,7 +72,6 @@ void CheckHostnameSanity(const std::string &aHostName);
  *      The service name must not end with dot.
  *
  * @param[in] aServiceName  The service name to check.
- *
  */
 void CheckServiceNameSanity(const std::string &aServiceName);
 
diff --git a/src/utils/infra_link_selector.hpp b/src/utils/infra_link_selector.hpp
index f2bcd832..5697fd48 100644
--- a/src/utils/infra_link_selector.hpp
+++ b/src/utils/infra_link_selector.hpp
@@ -56,7 +56,6 @@
  *
  * This function should return the infrastructure link that is selected by platform specific rules.
  * If the function returns nullptr, the generic infrastructure link selections rules will be applied.
- *
  */
 extern "C" const char *otbrVendorInfraLinkSelect(void);
 #endif
@@ -66,7 +65,6 @@ namespace Utils {
 
 /**
  * This class implements Infrastructure Link Selector.
- *
  */
 class InfraLinkSelector : public MainloopProcessor, private NonCopyable
 {
@@ -75,13 +73,11 @@ public:
      * This constructor initializes the InfraLinkSelector instance.
      *
      * @param[in]  aInfraLinkNames  A list of infrastructure link candidates to select from.
-     *
      */
     explicit InfraLinkSelector(std::vector<const char *> aInfraLinkNames);
 
     /**
      * This destructor destroys the InfraLinkSelector instance.
-     *
      */
     ~InfraLinkSelector(void);
 
@@ -98,14 +94,12 @@ public:
      *      The interface has been `up and running` within last 10 seconds
      *
      * @returns  The selected infrastructure link.
-     *
      */
     const char *Select(void);
 
 private:
     /**
      * This enumeration infrastructure link states.
-     *
      */
     enum LinkState : uint8_t
     {
diff --git a/src/utils/pskc.hpp b/src/utils/pskc.hpp
index 3a037e6c..ed26701c 100644
--- a/src/utils/pskc.hpp
+++ b/src/utils/pskc.hpp
@@ -67,7 +67,6 @@ public:
      * @param[in] aPassphrase   A pointer to passphrase.
      *
      * @returns The pointer to PSKc value.
-     *
      */
     const uint8_t *ComputePskc(const uint8_t *aExtPanId, const char *aNetworkName, const char *aPassphrase);
 
diff --git a/src/utils/sha256.hpp b/src/utils/sha256.hpp
index df90a846..24f119eb 100644
--- a/src/utils/sha256.hpp
+++ b/src/utils/sha256.hpp
@@ -45,19 +45,16 @@ namespace otbr {
  * @addtogroup core-security
  *
  * @{
- *
  */
 
 /**
  * This class implements SHA-256 computation.
- *
  */
 class Sha256
 {
 public:
     /**
      * This type represents a SHA-256 hash.
-     *
      */
     class Hash : public otCryptoSha256Hash
     {
@@ -68,26 +65,22 @@ public:
          * This method returns a pointer to a byte array containing the hash value.
          *
          * @returns A pointer to a byte array containing the hash.
-         *
          */
         const uint8_t *GetBytes(void) const { return m8; }
     };
 
     /**
      * Constructor for `Sha256` object.
-     *
      */
     Sha256(void);
 
     /**
      * Destructor for `Sha256` object.
-     *
      */
     ~Sha256(void);
 
     /**
      * This method starts the SHA-256 computation.
-     *
      */
     void Start(void);
 
@@ -96,7 +89,6 @@ public:
      *
      * @param[in]  aBuf        A pointer to the input buffer.
      * @param[in]  aBufLength  The length of @p aBuf in bytes.
-     *
      */
     void Update(const void *aBuf, uint16_t aBufLength);
 
@@ -104,7 +96,6 @@ public:
      * This method finalizes the hash computation.
      *
      * @param[out]  aHash  A reference to a `Hash` to output the calculated hash.
-     *
      */
     void Finish(Hash &aHash);
 
diff --git a/src/utils/socket_utils.hpp b/src/utils/socket_utils.hpp
index 33986d3e..7893ac4e 100644
--- a/src/utils/socket_utils.hpp
+++ b/src/utils/socket_utils.hpp
@@ -54,7 +54,6 @@ enum SocketBlockOption
  *
  * @retval -1   Failed to create socket.
  * @retval ...  The file descriptor of the created socket.
- *
  */
 int SocketWithCloseExec(int aDomain, int aType, int aProtocol, SocketBlockOption aBlockOption);
 
@@ -65,7 +64,6 @@ int SocketWithCloseExec(int aDomain, int aType, int aProtocol, SocketBlockOption
  *
  * @retval  -1  Failed to create the netlink socket.
  * @retval ...  The file descriptor of the created netlink socket.
- *
  */
 int CreateNetLinkRouteSocket(uint32_t aNlGroups);
 
diff --git a/src/utils/steering_data.hpp b/src/utils/steering_data.hpp
index 481b9a4d..1c43840f 100644
--- a/src/utils/steering_data.hpp
+++ b/src/utils/steering_data.hpp
@@ -43,7 +43,6 @@ namespace otbr {
 
 /**
  * This class represents Steering Data
- *
  */
 class SteeringData
 {
@@ -58,19 +57,16 @@ public:
      * This method initializes the bloom filter.
      *
      * @param[in] aLength  The length of the bloom filter in bytes.
-     *
      */
     void Init(uint8_t aLength);
 
     /**
      * This method sets all bits in the bloom filter to zero.
-     *
      */
     void Clear(void) { memset(mBloomFilter, 0, sizeof(mBloomFilter)); }
 
     /**
      * Ths method sets all bits in the bloom filter to one.
-     *
      */
     void Set(void) { memset(mBloomFilter, 0xff, sizeof(mBloomFilter)); }
 
@@ -78,7 +74,6 @@ public:
      * This method sets bit @p aBit.
      *
      * @param[in] aBit  The bit offset.
-     *
      */
     void SetBit(uint8_t aBit) { mBloomFilter[mLength - 1 - (aBit / 8)] |= 1 << (aBit % 8); }
 
@@ -86,7 +81,6 @@ public:
      * This method computes the Bloom Filter.
      *
      * @param[in] aJoinerId  Extended address
-     *
      */
     void ComputeBloomFilter(const uint8_t *aJoinerId);
 
@@ -95,7 +89,6 @@ public:
      *
      * @param[in]  aEui64     A pointer to EUI64.
      * @param[out] aJoinerId  A pointer to receive joiner id. This pointer can be the same as @p aEui64.
-     *
      */
     static void ComputeJoinerId(const uint8_t *aEui64, uint8_t *aJoinerId);
 
@@ -103,13 +96,11 @@ public:
      * This method returns a pointer to the bloom filter.
      *
      * @returns A pointer to the computed bloom filter.
-     *
      */
     const uint8_t *GetBloomFilter(void) const { return mBloomFilter; }
 
     /**
      * This method returns the length of the bloom filter.
-     *
      */
     uint8_t GetLength(void) const { return mLength; }
 
diff --git a/src/utils/string_utils.hpp b/src/utils/string_utils.hpp
index 06255ead..21fb7922 100644
--- a/src/utils/string_utils.hpp
+++ b/src/utils/string_utils.hpp
@@ -50,7 +50,6 @@ namespace StringUtils {
  * @param[in] aString2 The second string.
  *
  * @returns  Whether the two strings are equal in a case-insensitive manner.
- *
  */
 bool EqualCaseInsensitive(const std::string &aString1, const std::string &aString2);
 
@@ -60,7 +59,6 @@ bool EqualCaseInsensitive(const std::string &aString1, const std::string &aStrin
  * @param[in] aString The string to convert.
  *
  * @returns  A copy of @p aString with all letters converted to lowercase.
- *
  */
 std::string ToLowercase(const std::string &aString);
 
diff --git a/src/utils/system_utils.hpp b/src/utils/system_utils.hpp
index 2af1ae2e..dff9938a 100644
--- a/src/utils/system_utils.hpp
+++ b/src/utils/system_utils.hpp
@@ -50,7 +50,6 @@ extern "C" {
  * @param[in] ...      Arguments for the format specification.
  *
  * @returns The command exit code.
- *
  */
 int ExecuteCommand(const char *aFormat, ...);
 
diff --git a/src/utils/thread_helper.cpp b/src/utils/thread_helper.cpp
index b7b62163..7722f1a4 100644
--- a/src/utils/thread_helper.cpp
+++ b/src/utils/thread_helper.cpp
@@ -1726,7 +1726,6 @@ otError ThreadHelper::ProcessDatasetForMigration(otOperationalDatasetTlvs &aData
      *
      * | Type | Value | Timestamp Seconds | Timestamp Ticks | U bit |
      * |  8   |   8   |         48        |         15      |   1   |
-     *
      */
     tlv->SetType(OT_MESHCOP_TLV_PENDINGTIMESTAMP);
     clock_gettime(CLOCK_REALTIME, &currentTime);
diff --git a/src/utils/thread_helper.hpp b/src/utils/thread_helper.hpp
index 162b6b5c..ed55d3a2 100644
--- a/src/utils/thread_helper.hpp
+++ b/src/utils/thread_helper.hpp
@@ -86,7 +86,6 @@ public:
      *
      * @param[in] aInstance  The Thread instance.
      * @param[in] aHost      The Thread controller.
-     *
      */
     ThreadHelper(otInstance *aInstance, otbr::Ncp::RcpHost *aHost);
 
@@ -94,7 +93,6 @@ public:
      * This method adds a callback for device role change.
      *
      * @param[in] aHandler  The device role handler.
-     *
      */
     void AddDeviceRoleHandler(DeviceRoleHandler aHandler);
 
@@ -103,7 +101,6 @@ public:
      * This method adds a callback for DHCPv6 PD state change.
      *
      * @param[in] aCallback  The DHCPv6 PD state change callback.
-     *
      */
     void SetDhcp6PdStateCallback(Dhcp6PdStateCallback aCallback);
 #endif
@@ -122,7 +119,6 @@ public:
      * @param[in] aSeconds  The timeout to close the port, 0 for never close.
      *
      * @returns The error value of underlying OpenThread api calls.
-     *
      */
     otError PermitUnsecureJoin(uint16_t aPort, uint32_t aSeconds);
 
@@ -130,7 +126,6 @@ public:
      * This method performs a Thread network scan.
      *
      * @param[in] aHandler  The scan result handler.
-     *
      */
     void Scan(ScanHandler aHandler);
 
@@ -139,7 +134,6 @@ public:
      *
      * @param[in] aScanDuration  The duration for the scan, in milliseconds.
      * @param[in] aHandler       The scan result handler.
-     *
      */
     void EnergyScan(uint32_t aScanDuration, EnergyScanHandler aHandler);
 
@@ -155,7 +149,6 @@ public:
      * @param[in] aPSKc         The pre-shared commissioner key, empty for random.
      * @param[in] aChannelMask  A bitmask for valid channels, will random select one.
      * @param[in] aHandler      The attach result handler.
-     *
      */
     void Attach(const std::string          &aNetworkName,
                 uint16_t                    aPanId,
@@ -169,7 +162,6 @@ public:
      * This method detaches the device from the Thread network.
      *
      * @returns The error value of underlying OpenThread API calls.
-     *
      */
     otError Detach(void);
 
@@ -180,7 +172,6 @@ public:
      *       network parameter will be set through the active dataset.
      *
      * @param[in] aHandler  The attach result handler.
-     *
      */
     void Attach(AttachHandler aHandler);
 
@@ -189,7 +180,6 @@ public:
      *
      * @param[in] aDatasetTlvs  The dataset TLVs.
      * @param[in] aHandler      The result handler.
-     *
      */
     void AttachAllNodesTo(const std::vector<uint8_t> &aDatasetTlvs, AttachHandler aHandler);
 
@@ -197,7 +187,6 @@ public:
      * This method resets the OpenThread stack.
      *
      * @returns The error value of underlying OpenThread api calls.
-     *
      */
     otError Reset(void);
 
@@ -213,7 +202,6 @@ public:
      * @param[in] aVendorSwVersion  The vendor software version.
      * @param[in] aVendorData       The vendor custom data.
      * @param[in] aHandler          The join result handler.
-     *
      */
     void JoinerStart(const std::string &aPskd,
                      const std::string &aProvisioningUrl,
@@ -227,7 +215,6 @@ public:
      * This method tries to restore the network after reboot
      *
      * @returns The error value of underlying OpenThread api calls.
-     *
      */
     otError TryResumeNetwork(void);
 
@@ -235,7 +222,6 @@ public:
      * This method returns the underlying OpenThread instance.
      *
      * @returns The underlying instance.
-     *
      */
     otInstance *GetInstance(void)
     {
@@ -246,7 +232,6 @@ public:
      * This method handles OpenThread state changed notification.
      *
      * @param[in] aFlags    A bit-field indicating specific state that has changed.  See `OT_CHANGED_*` definitions.
-     *
      */
     void StateChangedCallback(otChangedFlags aFlags);
 
@@ -255,7 +240,6 @@ public:
      * This method sets a callback for calls of UpdateVendorMeshCopTxtEntries D-Bus API.
      *
      * @param[in] aHandler  The handler on MeshCoP TXT changes.
-     *
      */
     void SetUpdateMeshCopTxtHandler(UpdateMeshCopTxtHandler aHandler)
     {
@@ -266,7 +250,6 @@ public:
      * This method handles MeshCoP TXT updates done by UpdateVendorMeshCopTxtEntries D-Bus API.
      *
      * @param[in] aUpdate  The key-value pairs to be updated in the TXT record.
-     *
      */
     void OnUpdateMeshCopTxt(std::map<std::string, std::vector<uint8_t>> aUpdate);
 #endif
@@ -294,7 +277,6 @@ public:
      *
      * @param[in] aAction  The action OpenThread performs.
      * @param[in] aError   The action result.
-     *
      */
     static void LogOpenThreadResult(const char *aAction, otError aError);
 
@@ -313,7 +295,6 @@ public:
      *
      * @retval OT_ERROR_NONE          Dataset is valid to do Thread network migration.
      * @retval OT_ERROR_INVALID_ARGS  Dataset is invalid to do Thread network migration.
-     *
      */
     static otError ProcessDatasetForMigration(otOperationalDatasetTlvs &aDatasetTlvs, uint32_t aDelayMilli);
 
diff --git a/src/web/web-service/ot_client.hpp b/src/web/web-service/ot_client.hpp
index c1ba5b98..103de939 100644
--- a/src/web/web-service/ot_client.hpp
+++ b/src/web/web-service/ot_client.hpp
@@ -62,7 +62,6 @@ struct WpanNetworkInfo
 
 /**
  * This class implements functionality of OpenThread client.
- *
  */
 class OpenThreadClient
 {
@@ -71,13 +70,11 @@ public:
      * This constructor creates an OpenThread client.
      *
      * @param[in] aNetifName  The Thread network interface name.
-     *
      */
     OpenThreadClient(const char *aNetifName);
 
     /**
      * This destructor destories an OpenThread client.
-     *
      */
     ~OpenThreadClient(void);
 
@@ -86,7 +83,6 @@ public:
      *
      * @retval TRUE   Successfully connected to the daemon.
      * @retval FALSE  Failed to connected to the daemon.
-     *
      */
     bool Connect(void);
 
@@ -97,7 +93,6 @@ public:
      * @param[in] ...      C style format arguments.
      *
      * @returns A pointer to the output if succeeded, otherwise nullptr.
-     *
      */
     char *Execute(const char *aFormat, ...);
 
@@ -108,7 +103,6 @@ public:
      * @param[in] aTimeout   Timeout for the read, in ms.
      *
      * @returns A pointer to the output if the expected response is found, otherwise nullptr.
-     *
      */
     char *Read(const char *aResponse, int aTimeout);
 
@@ -119,13 +113,11 @@ public:
      * @param[in]  aLength    Number of entries in @p aNetworks.
      *
      * @returns Number of entries found. 0 if none found.
-     *
      */
     int Scan(WpanNetworkInfo *aNetworks, int aLength);
 
     /**
      * This method performs factory reset.
-     *
      */
     bool FactoryReset(void);
 
diff --git a/src/web/web-service/web_server.hpp b/src/web/web-service/web_server.hpp
index f54761e2..4520e41d 100644
--- a/src/web/web-service/web_server.hpp
+++ b/src/web/web-service/web_server.hpp
@@ -61,20 +61,17 @@ typedef SimpleWeb::Server<SimpleWeb::HTTP> HttpServer;
 
 /**
  * This class implements the http server.
- *
  */
 class WebServer
 {
 public:
     /**
      * This method is constructor to initialize the WebServer.
-     *
      */
     WebServer(void);
 
     /**
      * This method is destructor to free the WebServer.
-     *
      */
     ~WebServer(void);
 
@@ -84,13 +81,11 @@ public:
      * @param[in] aIfName      The pointer to the Thread interface name.
      * @param[in] aListenAddr  The http server listen address, can be nullptr for any address.
      * @param[in] aPort        The port of http server.
-     *
      */
     void StartWebServer(const char *aIfName, const char *aListenAddr, uint16_t aPort);
 
     /**
      * This method stops the Web Server.
-     *
      */
     void StopWebServer(void);
 
diff --git a/src/web/web-service/wpan_service.hpp b/src/web/web-service/wpan_service.hpp
index c27107be..aa9b286a 100644
--- a/src/web/web-service/wpan_service.hpp
+++ b/src/web/web-service/wpan_service.hpp
@@ -52,7 +52,6 @@
 
 /**
  * WPAN parameter constants
- *
  */
 
 #define OT_EXTENDED_PANID_LENGTH 8
@@ -68,7 +67,6 @@ namespace Web {
 
 /**
  * This class provides web service to manage WPAN.
- *
  */
 class WpanService
 {
@@ -77,7 +75,6 @@ public:
      * This method handles http request to get information to generate QR code.
      *
      * @returns The string to the http response of getting QR code.
-     *
      */
     std::string HandleGetQRCodeRequest(void);
 
@@ -87,7 +84,6 @@ public:
      * @param[in]  aJoinRequest  A reference to the http request of joining network.
      *
      * @returns The string to the http response of joining network.
-     *
      */
     std::string HandleJoinNetworkRequest(const std::string &aJoinRequest);
 
@@ -97,7 +93,6 @@ public:
      * @param[in]  aFormRequest  A reference to the http request of forming network.
      *
      * @returns The string to the http response of forming network.
-     *
      */
     std::string HandleFormNetworkRequest(const std::string &aFormRequest);
 
@@ -107,7 +102,6 @@ public:
      * @param[in]  aAddPrefixRequest  A reference to the http request of adding on-mesh prefix.
      *
      * @returns The string to the http response of adding on-mesh prefix.
-     *
      */
     std::string HandleAddPrefixRequest(const std::string &aAddPrefixRequest);
 
@@ -117,7 +111,6 @@ public:
      * @param[in]  aDeleteRequest  A reference to the http request of deleting on-mesh prefix.
      *
      * @returns The string to the http response of deleting on-mesh prefix.
-     *
      */
     std::string HandleDeletePrefixRequest(const std::string &aDeleteRequest);
 
@@ -125,7 +118,6 @@ public:
      * This method handles http request to get netowrk status.
      *
      * @returns The string to the http response of getting status.
-     *
      */
     std::string HandleStatusRequest(void);
 
@@ -133,7 +125,6 @@ public:
      * This method handles http request to get available networks.
      *
      * @returns The string to the http response of getting available networks.
-     *
      */
     std::string HandleAvailableNetworkRequest(void);
 
@@ -141,7 +132,6 @@ public:
      * This method handles http request to commission device
      *
      * @returns The string to the http response of commissioning
-     *
      */
     std::string HandleCommission(const std::string &aCommissionRequest);
 
@@ -149,7 +139,6 @@ public:
      * This method sets the Thread interface name.
      *
      * @param[in] aIfName  The pointer to the Thread interface name.
-     *
      */
     void SetInterfaceName(const char *aIfName)
     {
@@ -166,7 +155,6 @@ public:
      * @retval kWpanStatus_OK       Successfully started the Thread service.
      * @retval kWpanStatus_Offline  Not started the Thread service.
      * @retval kWpanStatus_Down     The Thread service was down.
-     *
      */
     int GetWpanServiceStatus(std::string &aNetworkName, std::string &aExtPanId) const;
 
@@ -177,7 +165,6 @@ public:
      * @param[in] aNetworkPassword  Network password
      *
      * @returns The string to the http response of getting available networks.
-     *
      */
     std::string CommissionDevice(const char *aPskd, const char *aNetworkPassword);
 
diff --git a/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java b/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
index 8e214f43..6bb72cdf 100644
--- a/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
+++ b/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
@@ -29,6 +29,7 @@
 package com.android.server.thread.openthread.testing;
 
 import static com.android.server.thread.openthread.IOtDaemon.ErrorCode.OT_ERROR_INVALID_STATE;
+import static com.android.server.thread.openthread.IOtDaemon.ErrorCode.OT_ERROR_NOT_IMPLEMENTED;
 import static com.android.server.thread.openthread.IOtDaemon.OT_STATE_DISABLED;
 import static com.android.server.thread.openthread.IOtDaemon.OT_STATE_ENABLED;
 import static com.android.server.thread.openthread.testing.FakeOtDaemon.OT_DEVICE_ROLE_DISABLED;
@@ -38,8 +39,13 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyByte;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
@@ -59,6 +65,7 @@ import com.android.server.thread.openthread.INsdPublisher;
 import com.android.server.thread.openthread.IOtDaemonCallback;
 import com.android.server.thread.openthread.IOtStatusReceiver;
 import com.android.server.thread.openthread.MeshcopTxtAttributes;
+import com.android.server.thread.openthread.OtDaemonConfiguration;
 import com.android.server.thread.openthread.OtDaemonState;
 
 import org.junit.Before;
@@ -103,6 +110,7 @@ public final class FakeOtDaemonTest {
     private static final String TEST_VENDOR_NAME = "test vendor";
     private static final String TEST_MODEL_NAME = "test model";
     private static final String TEST_DEFAULT_COUNTRY_CODE = "WW";
+    private static final String TEST_NAT64_CIDR = "192.168.255.0/24";
 
     private FakeOtDaemon mFakeOtDaemon;
     private TestLooper mTestLooper;
@@ -110,6 +118,7 @@ public final class FakeOtDaemonTest {
     @Mock private INsdPublisher mMockNsdPublisher;
     @Mock private IOtDaemonCallback mMockCallback;
     private MeshcopTxtAttributes mOverriddenMeshcopTxts;
+    private OtDaemonConfiguration mConfig;
 
     @Before
     public void setUp() {
@@ -122,6 +131,7 @@ public final class FakeOtDaemonTest {
         mOverriddenMeshcopTxts.vendorOui = TEST_VENDOR_OUI;
         mOverriddenMeshcopTxts.modelName = TEST_MODEL_NAME;
         mOverriddenMeshcopTxts.nonStandardTxtEntries = List.of();
+        mConfig = new OtDaemonConfiguration.Builder().build();
     }
 
     @Test
@@ -133,12 +143,14 @@ public final class FakeOtDaemonTest {
                 List.of(new DnsTxtAttribute("v2", new byte[] {0x02}));
 
         mFakeOtDaemon.initialize(
+                true /* enabled */,
+                mConfig,
                 mMockTunFd,
-                true,
                 mMockNsdPublisher,
                 mOverriddenMeshcopTxts,
-                mMockCallback,
-                TEST_DEFAULT_COUNTRY_CODE);
+                TEST_DEFAULT_COUNTRY_CODE,
+                true /* trelEnabled */,
+                mMockCallback);
         mTestLooper.dispatchAll();
 
         MeshcopTxtAttributes meshcopTxts = mFakeOtDaemon.getOverriddenMeshcopTxtAttributes();
@@ -154,6 +166,7 @@ public final class FakeOtDaemonTest {
         assertThat(mFakeOtDaemon.getStateCallback()).isEqualTo(mMockCallback);
         assertThat(mFakeOtDaemon.getCountryCode()).isEqualTo(TEST_DEFAULT_COUNTRY_CODE);
         assertThat(mFakeOtDaemon.isInitialized()).isTrue();
+        assertThat(mFakeOtDaemon.isTrelEnabled()).isTrue();
         verify(mMockCallback, times(1)).onStateChanged(any(), anyLong());
         verify(mMockCallback, times(1)).onBackboneRouterStateChanged(any());
     }
@@ -161,12 +174,14 @@ public final class FakeOtDaemonTest {
     @Test
     public void registerStateCallback_noStateChange_callbackIsInvoked() throws Exception {
         mFakeOtDaemon.initialize(
+                true /* enabled */,
+                mConfig,
                 mMockTunFd,
-                true,
                 mMockNsdPublisher,
                 mOverriddenMeshcopTxts,
-                mMockCallback,
-                TEST_DEFAULT_COUNTRY_CODE);
+                TEST_DEFAULT_COUNTRY_CODE,
+                true /* trelEnabled */,
+                mMockCallback);
         final AtomicReference<OtDaemonState> stateRef = new AtomicReference<>();
         final AtomicLong listenerIdRef = new AtomicLong();
         final AtomicReference<BackboneRouterState> bbrStateRef = new AtomicReference<>();
@@ -278,6 +293,56 @@ public final class FakeOtDaemonTest {
         assertThat(mFakeOtDaemon.getEnabledState()).isEqualTo(OT_STATE_ENABLED);
     }
 
+    @Test
+    public void setConfiguration_validConfig_onSuccessIsInvoked() throws Exception {
+        IOtStatusReceiver receiver = mock(IOtStatusReceiver.class);
+        mConfig = new OtDaemonConfiguration.Builder().setNat64Enabled(true).build();
+
+        mFakeOtDaemon.setConfiguration(mConfig, receiver);
+        mTestLooper.dispatchAll();
+
+        verify(receiver).onSuccess();
+        verify(receiver, never()).onError(anyByte(), anyString());
+    }
+
+    @Test
+    public void setConfiguration_notSupportedConfig_onErrorIsInvoked() throws Exception {
+        IOtStatusReceiver receiver = mock(IOtStatusReceiver.class);
+        mConfig = new OtDaemonConfiguration.Builder().setDhcpv6PdEnabled(true).build();
+
+        mFakeOtDaemon.setConfiguration(mConfig, receiver);
+        mTestLooper.dispatchAll();
+
+        verify(receiver, never()).onSuccess();
+        verify(receiver).onError(eq((int) OT_ERROR_NOT_IMPLEMENTED), anyString());
+    }
+
+    @Test
+    public void setNat64Cidr_onSuccessIsInvoked() throws Exception {
+        IOtStatusReceiver receiver = mock(IOtStatusReceiver.class);
+
+        mFakeOtDaemon.setNat64Cidr(TEST_NAT64_CIDR, receiver);
+        mTestLooper.dispatchAll();
+
+        verify(receiver, never()).onError(anyInt(), any());
+        verify(receiver, times(1)).onSuccess();
+    }
+
+    @Test
+    public void setSetNat64CidrException_setNat64CidrFailsWithTheGivenException() {
+        final RemoteException setNat64CidrException = new RemoteException("setNat64Cidr() failed");
+
+        mFakeOtDaemon.setSetNat64CidrException(setNat64CidrException);
+
+        RemoteException thrown =
+                assertThrows(
+                        RemoteException.class,
+                        () ->
+                                mFakeOtDaemon.setNat64Cidr(
+                                        TEST_NAT64_CIDR, new IOtStatusReceiver.Default()));
+        assertThat(thrown).isEqualTo(setNat64CidrException);
+    }
+
     @Test
     public void getChannelMasks_succeed_onSuccessIsInvoked() throws Exception {
         final AtomicInteger supportedChannelMaskRef = new AtomicInteger();
@@ -336,12 +401,14 @@ public final class FakeOtDaemonTest {
         DeathRecipient mockDeathRecipient = mock(DeathRecipient.class);
         mFakeOtDaemon.linkToDeath(mockDeathRecipient, 0);
         mFakeOtDaemon.initialize(
+                true /* enabled */,
+                mConfig,
                 mMockTunFd,
-                true,
                 mMockNsdPublisher,
                 mOverriddenMeshcopTxts,
-                mMockCallback,
-                TEST_DEFAULT_COUNTRY_CODE);
+                TEST_DEFAULT_COUNTRY_CODE,
+                true /* trelEnabled */,
+                mMockCallback);
 
         mFakeOtDaemon.terminate();
         mTestLooper.dispatchAll();
@@ -363,4 +430,36 @@ public final class FakeOtDaemonTest {
         assertThat(mFakeOtDaemon.getEnabledState()).isEqualTo(OT_STATE_DISABLED);
         verify(mockDeathRecipient, times(1)).binderDied();
     }
+
+    @Test
+    public void initialize_trelEnabled_trelIsEnabled() throws Exception {
+        mFakeOtDaemon.initialize(
+                true /* enabled */,
+                mConfig,
+                mMockTunFd,
+                mMockNsdPublisher,
+                mOverriddenMeshcopTxts,
+                TEST_DEFAULT_COUNTRY_CODE,
+                true /* trelEnabled */,
+                mMockCallback);
+        mTestLooper.dispatchAll();
+
+        assertThat(mFakeOtDaemon.isTrelEnabled()).isTrue();
+    }
+
+    @Test
+    public void initialize_trelDisabled_trelIsDisabled() throws Exception {
+        mFakeOtDaemon.initialize(
+                true /* enabled */,
+                mConfig,
+                mMockTunFd,
+                mMockNsdPublisher,
+                mOverriddenMeshcopTxts,
+                TEST_DEFAULT_COUNTRY_CODE,
+                false /* trelEnabled */,
+                mMockCallback);
+        mTestLooper.dispatchAll();
+
+        assertThat(mFakeOtDaemon.isTrelEnabled()).isFalse();
+    }
 }
diff --git a/tests/gtest/CMakeLists.txt b/tests/gtest/CMakeLists.txt
index f9674ed6..c0761272 100644
--- a/tests/gtest/CMakeLists.txt
+++ b/tests/gtest/CMakeLists.txt
@@ -82,3 +82,23 @@ target_link_libraries(otbr-posix-gtest-unit
     GTest::gmock_main
 )
 gtest_discover_tests(otbr-posix-gtest-unit PROPERTIES LABELS "sudo")
+
+add_executable(otbr-gtest-host-api
+    ${OTBR_PROJECT_DIRECTORY}/src/ncp/rcp_host.cpp
+    ${OPENTHREAD_PROJECT_DIRECTORY}/tests/gtest/fake_platform.cpp
+    fake_posix_platform.cpp
+    test_rcp_host_api.cpp
+)
+target_include_directories(otbr-gtest-host-api
+    PRIVATE
+        ${OTBR_PROJECT_DIRECTORY}/src
+        ${OPENTHREAD_PROJECT_DIRECTORY}/src/core
+        ${OPENTHREAD_PROJECT_DIRECTORY}/tests/gtest
+)
+target_link_libraries(otbr-gtest-host-api
+    mbedtls
+    otbr-common
+    otbr-utils
+    GTest::gmock_main
+)
+gtest_discover_tests(otbr-gtest-host-api)
diff --git a/tests/gtest/fake_posix_platform.cpp b/tests/gtest/fake_posix_platform.cpp
new file mode 100644
index 00000000..96d38240
--- /dev/null
+++ b/tests/gtest/fake_posix_platform.cpp
@@ -0,0 +1,86 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include "fake_platform.hpp"
+
+#include <assert.h>
+
+#include "openthread/openthread-system.h"
+
+otPlatResetReason        gPlatResetReason = OT_PLAT_RESET_REASON_POWER_ON;
+static ot::FakePlatform *sFakePlatform;
+
+const otRadioSpinelMetrics *otSysGetRadioSpinelMetrics(void)
+{
+    return nullptr;
+}
+const otRcpInterfaceMetrics *otSysGetRcpInterfaceMetrics(void)
+{
+    return nullptr;
+}
+
+uint32_t otSysGetInfraNetifFlags(void)
+{
+    return 0;
+}
+
+void otSysCountInfraNetifAddresses(otSysInfraNetIfAddressCounters *)
+{
+}
+
+const char *otSysGetInfraNetifName(void)
+{
+    return nullptr;
+}
+
+otInstance *otSysInit(otPlatformConfig *aPlatformConfig)
+{
+    OT_UNUSED_VARIABLE(aPlatformConfig);
+
+    assert(sFakePlatform == nullptr);
+    sFakePlatform = new ot::FakePlatform();
+    return sFakePlatform->CurrentInstance();
+}
+
+void otSysDeinit(void)
+{
+    if (sFakePlatform != nullptr)
+    {
+        delete sFakePlatform;
+        sFakePlatform = nullptr;
+    }
+}
+
+void otSysMainloopUpdate(otInstance *, otSysMainloopContext *)
+{
+}
+
+void otSysMainloopProcess(otInstance *, const otSysMainloopContext *)
+{
+    sFakePlatform->Run(/* microseconds */ 1000);
+}
diff --git a/tests/gtest/test_rcp_host_api.cpp b/tests/gtest/test_rcp_host_api.cpp
new file mode 100644
index 00000000..4f49257f
--- /dev/null
+++ b/tests/gtest/test_rcp_host_api.cpp
@@ -0,0 +1,235 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include <sys/time.h>
+
+#include <openthread/dataset.h>
+#include <openthread/dataset_ftd.h>
+
+#include "common/mainloop.hpp"
+#include "common/mainloop_manager.hpp"
+#include "ncp/rcp_host.hpp"
+
+#include "fake_platform.hpp"
+
+static void MainloopProcessUntil(otbr::MainloopContext    &aMainloop,
+                                 uint32_t                  aTimeoutSec,
+                                 std::function<bool(void)> aCondition)
+{
+    timeval startTime;
+    timeval now;
+    gettimeofday(&startTime, nullptr);
+
+    while (!aCondition())
+    {
+        gettimeofday(&now, nullptr);
+        // Simply compare the second. We don't need high precision here.
+        if (now.tv_sec - startTime.tv_sec > aTimeoutSec)
+        {
+            break;
+        }
+
+        otbr::MainloopManager::GetInstance().Update(aMainloop);
+        otbr::MainloopManager::GetInstance().Process(aMainloop);
+    }
+}
+
+TEST(RcpHostApi, DeviceRoleChangesCorrectlyAfterSetThreadEnabled)
+{
+    otError                                    error          = OT_ERROR_FAILED;
+    bool                                       resultReceived = false;
+    otbr::MainloopContext                      mainloop;
+    otbr::Ncp::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
+                                                                                    const std::string &aErrorMsg) {
+        OT_UNUSED_VARIABLE(aErrorMsg);
+        resultReceived = true;
+        error          = aError;
+    };
+    otbr::Ncp::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                            /* aEnableAutoAttach */ false);
+
+    host.Init();
+
+    // 1. Active dataset hasn't been set, should succeed with device role still being disabled.
+    host.SetThreadEnabled(true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DISABLED);
+
+    // 2. Set active dataset and enable it
+    {
+        otOperationalDataset     dataset;
+        otOperationalDatasetTlvs datasetTlvs;
+        OT_UNUSED_VARIABLE(otDatasetCreateNewNetwork(ot::FakePlatform::CurrentInstance(), &dataset));
+        otDatasetConvertToTlvs(&dataset, &datasetTlvs);
+        OT_UNUSED_VARIABLE(otDatasetSetActiveTlvs(ot::FakePlatform::CurrentInstance(), &datasetTlvs));
+    }
+    error          = OT_ERROR_FAILED;
+    resultReceived = false;
+    host.SetThreadEnabled(true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DETACHED);
+
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1,
+                         [&host]() { return host.GetDeviceRole() != OT_DEVICE_ROLE_DETACHED; });
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_LEADER);
+
+    // 3. Disable it
+    error          = OT_ERROR_FAILED;
+    resultReceived = false;
+    host.SetThreadEnabled(false, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DISABLED);
+
+    // 4. Duplicate call, should get OT_ERROR_BUSY
+    error                   = OT_ERROR_FAILED;
+    resultReceived          = false;
+    otError error2          = OT_ERROR_FAILED;
+    bool    resultReceived2 = false;
+    host.SetThreadEnabled(false, receiver);
+    host.SetThreadEnabled(false, [&resultReceived2, &error2](otError aError, const std::string &aErrorMsg) {
+        OT_UNUSED_VARIABLE(aErrorMsg);
+        error2          = aError;
+        resultReceived2 = true;
+    });
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1,
+                         [&resultReceived, &resultReceived2]() { return resultReceived && resultReceived2; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_EQ(error2, OT_ERROR_BUSY);
+
+    host.Deinit();
+}
+
+TEST(RcpHostApi, SetCountryCodeWorkCorrectly)
+{
+    otError                                    error          = OT_ERROR_FAILED;
+    bool                                       resultReceived = false;
+    otbr::MainloopContext                      mainloop;
+    otbr::Ncp::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
+                                                                                    const std::string &aErrorMsg) {
+        OT_UNUSED_VARIABLE(aErrorMsg);
+        resultReceived = true;
+        error          = aError;
+    };
+    otbr::Ncp::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                            /* aEnableAutoAttach */ false);
+
+    // 1. Call SetCountryCode when host hasn't been initialized.
+    otbr::MainloopManager::GetInstance().RemoveMainloopProcessor(
+        &host); // Temporarily remove RcpHost because it's not initialized yet.
+    host.SetCountryCode("AF", receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    otbr::MainloopManager::GetInstance().AddMainloopProcessor(&host);
+
+    host.Init();
+    // 2. Call SetCountryCode with invalid arguments
+    resultReceived = false;
+    error          = OT_ERROR_NONE;
+    host.SetCountryCode("AFA", receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_ARGS);
+
+    resultReceived = false;
+    error          = OT_ERROR_NONE;
+    host.SetCountryCode("A", receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_ARGS);
+
+    resultReceived = false;
+    error          = OT_ERROR_NONE;
+    host.SetCountryCode("12", receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_ARGS);
+
+    // 3. Call SetCountryCode with valid argument
+    resultReceived = false;
+    error          = OT_ERROR_NONE;
+    host.SetCountryCode("AF", receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NOT_IMPLEMENTED); // The current platform weak implmentation returns 'NOT_IMPLEMENTED'.
+
+    host.Deinit();
+}
+
+TEST(RcpHostApi, StateChangesCorrectlyAfterScheduleMigration)
+{
+    otError                                    error          = OT_ERROR_NONE;
+    bool                                       resultReceived = false;
+    otbr::MainloopContext                      mainloop;
+    otbr::Ncp::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
+                                                                                    const std::string &aErrorMsg) {
+        OT_UNUSED_VARIABLE(aErrorMsg);
+        resultReceived = true;
+        error          = aError;
+    };
+    otbr::Ncp::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                            /* aEnableAutoAttach */ false);
+
+    otOperationalDataset     dataset;
+    otOperationalDatasetTlvs datasetTlvs;
+
+    // 1. Call ScheduleMigration when host hasn't been initialized.
+    otbr::MainloopManager::GetInstance().RemoveMainloopProcessor(
+        &host); // Temporarily remove RcpHost because it's not initialized yet.
+    host.ScheduleMigration(datasetTlvs, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    otbr::MainloopManager::GetInstance().AddMainloopProcessor(&host);
+
+    host.Init();
+
+    // 2. Call ScheduleMigration when the device is not attached.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.ScheduleMigration(datasetTlvs, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_FAILED);
+
+    // 3. Schedule migration to another network.
+    OT_UNUSED_VARIABLE(otDatasetCreateNewNetwork(ot::FakePlatform::CurrentInstance(), &dataset));
+    otDatasetConvertToTlvs(&dataset, &datasetTlvs);
+    OT_UNUSED_VARIABLE(otDatasetSetActiveTlvs(ot::FakePlatform::CurrentInstance(), &datasetTlvs));
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.SetThreadEnabled(true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1,
+                         [&host]() { return host.GetDeviceRole() != OT_DEVICE_ROLE_DETACHED; });
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_LEADER);
+
+    host.ScheduleMigration(datasetTlvs, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+
+    host.Deinit();
+}
```

