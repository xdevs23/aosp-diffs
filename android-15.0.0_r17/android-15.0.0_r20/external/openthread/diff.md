```diff
diff --git a/Android.bp b/Android.bp
index bfb8a95a7..b86eb197e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -376,7 +376,6 @@ filegroup {
         "examples/platforms/simulation/entropy.c",
         "examples/platforms/simulation/flash.c",
         "examples/platforms/simulation/infra_if.c",
-        "examples/platforms/simulation/logging.c",
         "examples/platforms/simulation/misc.c",
         "examples/platforms/simulation/radio.c",
         "examples/platforms/simulation/simul_utils.c",
@@ -388,6 +387,7 @@ filegroup {
         "examples/platforms/utils/mac_frame.cpp",
         "examples/platforms/utils/settings_ram.c",
         "examples/platforms/utils/soft_source_match_table.c",
+        "src/android/logging.c",
     ],
 }
 
@@ -445,6 +445,7 @@ filegroup {
 filegroup {
     name: "openthread_platform_posix_srcs",
     srcs: [
+        "src/android/logging.c",
         "src/posix/platform/alarm.cpp",
         "src/posix/platform/backtrace.cpp",
         "src/posix/platform/configuration.cpp",
@@ -454,7 +455,6 @@ filegroup {
         "src/posix/platform/firewall.cpp",
         "src/posix/platform/hdlc_interface.cpp",
         "src/posix/platform/infra_if.cpp",
-        "src/posix/platform/logging.cpp",
         "src/posix/platform/mainloop.cpp",
         "src/posix/platform/memory.cpp",
         "src/posix/platform/misc.cpp",
@@ -688,6 +688,10 @@ cc_library_static {
         "ot_simulation_cflags_defaults",
     ],
 
+    static_libs: [
+        "libutils",
+    ],
+
     srcs: [
         ":openthread_simulation_srcs",
         "src/lib/platform/exit_code.c",
@@ -906,6 +910,10 @@ cc_binary {
         "examples/apps/ncp/ncp.c",
     ],
 
+    shared_libs: [
+        "liblog", // Required by src/android/logging.c
+    ],
+
     static_libs: [
         "libbase",
         "libcutils",
@@ -1003,5 +1011,6 @@ cc_binary {
 
     shared_libs: [
         "libcutils", // Required by src/core/instance_api.cpp
+        "liblog", // Required by src/android/logging.c
     ],
 }
diff --git a/include/openthread/border_agent.h b/include/openthread/border_agent.h
index 38bc1dc9c..0dd94db0f 100644
--- a/include/openthread/border_agent.h
+++ b/include/openthread/border_agent.h
@@ -217,9 +217,10 @@ otError otBorderAgentSetId(otInstance *aInstance, const otBorderAgentId *aId);
  * Setting the ephemeral key again before a previously set key has timed out will replace the previously set key and
  * reset the timeout.
  *
- * While the timeout interval is in effect, the ephemeral key can be used only once by an external commissioner to
- * connect. Once the commissioner disconnects, the ephemeral key is cleared, and the Border Agent reverts to using
- * PSKc.
+ * During the timeout interval, the ephemeral key can be used only once by an external commissioner to establish a
+ * connection. After the commissioner disconnects, the ephemeral key is cleared, and the Border Agent reverts to
+ * using PSKc. If the timeout expires while a commissioner is still connected, the session will be terminated, and the
+ * Border Agent will cease using the ephemeral key and revert to PSKc.
  *
  * @param[in] aInstance    The OpenThread instance.
  * @param[in] aKeyString   The ephemeral key string (used as PSK excluding the trailing null `\0` character).
@@ -252,7 +253,7 @@ otError otBorderAgentSetEphemeralKey(otInstance *aInstance,
  *
  * If a commissioner is connected using the ephemeral key and is currently active, calling this function does not
  * change its state. In this case the `otBorderAgentIsEphemeralKeyActive()` will continue to return `TRUE` until the
- * commissioner disconnects.
+ * commissioner disconnects, or the ephemeral key timeout expires.
  *
  * @param[in] aInstance    The OpenThread instance.
  *
@@ -279,6 +280,9 @@ bool otBorderAgentIsEphemeralKeyActive(otInstance *aInstance);
  *
  * - The Border Agent starts using an ephemeral key.
  * - Any parameter related to the ephemeral key, such as the port number, changes.
+ * - A commissioner candidate successfully establishes a secure session with the Border Agent using the ephemeral key.
+ *   This situation can be identified by `otBorderAgentGetState()` being `OT_BORDER_AGENT_STATE_ACTIVE` (this event
+ *   can be used to stop advertising the mDNS service "_meshcop-e._udp").
  * - The Border Agent stops using the ephemeral key due to:
  *   - A direct call to `otBorderAgentClearEphemeralKey()`.
  *   - The ephemeral key timing out.
@@ -308,6 +312,19 @@ void otBorderAgentSetEphemeralKeyCallback(otInstance                       *aIns
                                           otBorderAgentEphemeralKeyCallback aCallback,
                                           void                             *aContext);
 
+/**
+ * Disconnects the Border Agent from any active secure sessions.
+ *
+ * If Border Agent is connected to a commissioner candidate with ephemeral key, calling this API
+ * will cause the ephemeral key to be cleared after the session is disconnected.
+ *
+ * The Border Agent state may not change immediately upon calling this method. The state will be
+ * updated when the connection update is notified with a delay.
+ *
+ * @param[in] aInstance    The OpenThread instance.
+ */
+void otBorderAgentDisconnect(otInstance *aInstance);
+
 /**
  * @}
  *
diff --git a/include/openthread/instance.h b/include/openthread/instance.h
index 42268ac64..0631adab7 100644
--- a/include/openthread/instance.h
+++ b/include/openthread/instance.h
@@ -53,7 +53,7 @@ extern "C" {
  * @note This number versions both OpenThread platform and user APIs.
  *
  */
-#define OPENTHREAD_API_VERSION (439)
+#define OPENTHREAD_API_VERSION (460)
 
 /**
  * @addtogroup api-instance
diff --git a/include/openthread/nat64.h b/include/openthread/nat64.h
index 61fe1b697..5e46ef3d5 100644
--- a/include/openthread/nat64.h
+++ b/include/openthread/nat64.h
@@ -331,12 +331,25 @@ otMessage *otIp4NewMessage(otInstance *aInstance, const otMessageSettings *aSett
  * @retval  OT_ERROR_INVALID_ARGS   The given CIDR is not a valid IPv4 CIDR for NAT64.
  * @retval  OT_ERROR_NONE           Successfully set the CIDR for NAT64.
  *
- * @sa otBorderRouterSend
- * @sa otBorderRouterSetReceiveCallback
- *
+ * @sa otNat64Send
+ * @sa otNat64SetReceiveIp4Callback
  */
 otError otNat64SetIp4Cidr(otInstance *aInstance, const otIp4Cidr *aCidr);
 
+/**
+ * Clears the CIDR used when setting the source address of the outgoing translated IPv4 packets.
+ *
+ * Is available only when OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE is enabled.
+ *
+ * @note This function can be called at any time, but the NAT64 translator will be reset and all existing sessions
+ * will be expired when clearing the configured CIDR.
+ *
+ * @param[in] aInstance  A pointer to an OpenThread instance.
+ *
+ * @sa otNat64SetIp4Cidr
+ */
+void otNat64ClearIp4Cidr(otInstance *aInstance);
+
 /**
  * Translates an IPv4 datagram to an IPv6 datagram and sends via the Thread interface.
  *
diff --git a/include/openthread/trel.h b/include/openthread/trel.h
index e9a0bf00a..dd186fa59 100644
--- a/include/openthread/trel.h
+++ b/include/openthread/trel.h
@@ -184,6 +184,16 @@ const otTrelCounters *otTrelGetCounters(otInstance *aInstance);
  */
 void otTrelResetCounters(otInstance *aInstance);
 
+/**
+ * Gets the UDP port of the TREL interface.
+ *
+ * @param[in]  aInstance  A pointer to an OpenThread instance.
+ *
+ * @returns UDP port of the TREL interface.
+ *
+ */
+uint16_t otTrelGetUdpPort(otInstance *aInstance);
+
 /**
  * @}
  *
diff --git a/src/android/logging.c b/src/android/logging.c
new file mode 100644
index 000000000..889267aab
--- /dev/null
+++ b/src/android/logging.c
@@ -0,0 +1,88 @@
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
+#include <openthread-core-config.h>
+#include <openthread/config.h>
+
+#include <assert.h>
+#include <stdarg.h>
+#include <stdint.h>
+#include <stdio.h>
+
+#include <openthread/platform/logging.h>
+
+#include <log/log.h>
+
+#if (OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_PLATFORM_DEFINED)
+void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, ...)
+{
+    OT_UNUSED_VARIABLE(aLogRegion);
+
+    va_list             args;
+    android_LogPriority priority;
+
+    switch (aLogLevel)
+    {
+    case OT_LOG_LEVEL_NONE:
+        priority = ANDROID_LOG_SILENT;
+        break;
+    case OT_LOG_LEVEL_CRIT:
+        priority = ANDROID_LOG_FATAL;
+        break;
+    case OT_LOG_LEVEL_WARN:
+        priority = ANDROID_LOG_WARN;
+        break;
+    case OT_LOG_LEVEL_NOTE:
+    case OT_LOG_LEVEL_INFO:
+        priority = ANDROID_LOG_INFO;
+        break;
+    case OT_LOG_LEVEL_DEBG:
+        priority = ANDROID_LOG_DEBUG;
+        break;
+    default:
+        assert(false);
+        priority = ANDROID_LOG_DEBUG;
+        break;
+    }
+
+    va_start(args, aFormat);
+    __android_log_vprint(priority, LOG_TAG, aFormat, args);
+    va_end(args);
+}
+
+void platformLoggingInit(const char *aName)
+{
+    otPlatLog(OT_LOG_LEVEL_INFO, OT_LOG_REGION_PLATFORM, "OpenThread logs");
+    otPlatLog(OT_LOG_LEVEL_INFO, OT_LOG_REGION_PLATFORM, "- Program:  %s", aName);
+}
+#else
+void platformLoggingInit(const char *aName) { OT_UNUSED_VARIABLE(aName); }
+#endif // (OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_PLATFORM_DEFINED)
+
+void platformLoggingSetFileName(const char *aName) { OT_UNUSED_VARIABLE(aName); }
+void platformLoggingDeinit(void) {}
diff --git a/src/android/openthread-android-config.h b/src/android/openthread-android-config.h
index 29babe355..4e9c700e4 100644
--- a/src/android/openthread-android-config.h
+++ b/src/android/openthread-android-config.h
@@ -108,3 +108,9 @@
 
 // Enable for Android platform.
 #define OPENTHREAD_POSIX_CONFIG_ANDROID_ENABLE 1
+
+// Bind the upstream DNS socket to infra network interface.
+#define OPENTHREAD_POSIX_CONFIG_UPSTREAM_DNS_BIND_TO_INFRA_NETIF 1
+
+// Enable TREL to select infra interface
+#define OPENTHREAD_POSIX_CONFIG_TREL_SELECT_INFRA_IF 1
diff --git a/src/android/openthread-core-android-config.h b/src/android/openthread-core-android-config.h
index 56c3cfbf7..174ec5e94 100644
--- a/src/android/openthread-core-android-config.h
+++ b/src/android/openthread-core-android-config.h
@@ -291,6 +291,7 @@ static_assert(OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS * (32 * sizeof(void *)) ==
 #define OPENTHREAD_CONFIG_PING_SENDER_ENABLE 1
 #define OPENTHREAD_CONFIG_SRP_SERVER_ENABLE 1
 #define OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE 1
+#define OPENTHREAD_CONFIG_DNS_UPSTREAM_QUERY_ENABLE 1
 
 // Disables built-in TCP support as TCP can be support on upper layer
 #define OPENTHREAD_CONFIG_TCP_ENABLE 0
@@ -350,8 +351,8 @@ static_assert(OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS * (32 * sizeof(void *)) ==
 // Enable the external heap.
 #define OPENTHREAD_CONFIG_HEAP_EXTERNAL_ENABLE 1
 
-// Disable TREL as it's not yet supported.
-#define OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE 0
+// Enable TREL.
+#define OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE 1
 
 // Enable Link Metrics subject feature for Thread certification test.
 #define OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE 1
@@ -359,4 +360,7 @@ static_assert(OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS * (32 * sizeof(void *)) ==
 // Enable Link Metrics initiator feature for Thread certification test.
 #define OPENTHREAD_CONFIG_MLE_LINK_METRICS_INITIATOR_ENABLE 1
 
+// Sets microseconds ahead should MAC deliver CSL frame to SubMac.
+#define OPENTHREAD_CONFIG_MAC_CSL_REQUEST_AHEAD_US 4000
+
 #endif // OPENTHREAD_CORE_ANDROID_CONFIG_H_
diff --git a/src/cli/README.md b/src/cli/README.md
index 0b7c15f98..4f6c5c91c 100644
--- a/src/cli/README.md
+++ b/src/cli/README.md
@@ -372,6 +372,15 @@ Started
 Done
 ```
 
+### ba disconnect
+
+Disconnects border agent from any active secure sessions.
+
+```bash
+> ba disconnect
+Done
+```
+
 ### ba ephemeralkey
 
 Indicates if an ephemeral key is active.
@@ -407,7 +416,7 @@ The `port` specifies the UDP port to use with the ephemeral key. If UDP port is
 
 Setting the ephemeral key again before a previously set one is timed out, will replace the previous one.
 
-While the timeout interval is in effect, the ephemeral key can be used only once by an external commissioner to connect. Once the commissioner disconnects, the ephemeral key is cleared, and Border Agent reverts to using PSKc.
+During the timeout interval, the ephemeral key can be used only once by an external commissioner to establish a connection. After the commissioner disconnects, the ephemeral key is cleared, and the Border Agent reverts to using PSKc. If the timeout expires while a commissioner is still connected, the session will be terminated, and the Border Agent will cease using the ephemeral key and revert to PSKc.
 
 ```bash
 > ba ephemeralkey set Z10X20g3J15w1000P60m16 5000 1234
@@ -3948,6 +3957,16 @@ Done
 Done
 ```
 
+### trel port
+
+Get the TREL UDP port number.
+
+```bash
+> trel port
+49154
+Done
+```
+
 ### tvcheck enable
 
 Enable thread version check when upgrading to router or leader.
diff --git a/src/cli/cli.cpp b/src/cli/cli.cpp
index be6e144b8..a8ecc5ed4 100644
--- a/src/cli/cli.cpp
+++ b/src/cli/cli.cpp
@@ -411,6 +411,20 @@ template <> otError Interpreter::Process<Cmd("ba")>(Arg aArgs[])
 
         OutputLine("%s", Stringify(otBorderAgentGetState(GetInstancePtr()), kStateStrings));
     }
+    /**
+     * @cli ba disconnect
+     * @code
+     * ba disconnect
+     * Done
+     * @endcode
+     * @par
+     * Disconnects the Border Agent from any active secure sessions
+     * @sa otBorderAgentDisconnect
+     */
+    else if (aArgs[0] == "disconnect")
+    {
+        otBorderAgentDisconnect(GetInstancePtr());
+    }
 #if OPENTHREAD_CONFIG_BORDER_AGENT_ID_ENABLE
     /**
      * @cli ba id (get,set)
@@ -7577,6 +7591,20 @@ template <> otError Interpreter::Process<Cmd("trel")>(Arg aArgs[])
             error = OT_ERROR_INVALID_ARGS;
         }
     }
+    /**
+     * @cli trel port
+     * @code
+     * trel port
+     * 49153
+     * Done
+     * @endcode
+     * @par api_copy
+     * #otTrelGetUdpPort
+     */
+    else if (aArgs[0] == "port")
+    {
+        OutputLine("%hu", otTrelGetUdpPort(GetInstancePtr()));
+    }
     else
     {
         error = OT_ERROR_INVALID_ARGS;
diff --git a/src/core/api/border_agent_api.cpp b/src/core/api/border_agent_api.cpp
index 98a7bb37b..989961cc7 100644
--- a/src/core/api/border_agent_api.cpp
+++ b/src/core/api/border_agent_api.cpp
@@ -115,4 +115,6 @@ const otBorderAgentCounters *otBorderAgentGetCounters(otInstance *aInstance)
     return AsCoreType(aInstance).Get<MeshCoP::BorderAgent>().GetCounters();
 }
 
+void otBorderAgentDisconnect(otInstance *aInstance) { AsCoreType(aInstance).Get<MeshCoP::BorderAgent>().Disconnect(); }
+
 #endif // OPENTHREAD_CONFIG_BORDER_AGENT_ENABLE
diff --git a/src/core/api/nat64_api.cpp b/src/core/api/nat64_api.cpp
index f2130e6bc..32fd62649 100644
--- a/src/core/api/nat64_api.cpp
+++ b/src/core/api/nat64_api.cpp
@@ -58,6 +58,8 @@ otError otNat64SetIp4Cidr(otInstance *aInstance, const otIp4Cidr *aCidr)
     return AsCoreType(aInstance).Get<Nat64::Translator>().SetIp4Cidr(AsCoreType(aCidr));
 }
 
+void otNat64ClearIp4Cidr(otInstance *aInstance) { AsCoreType(aInstance).Get<Nat64::Translator>().ClearIp4Cidr(); }
+
 otMessage *otIp4NewMessage(otInstance *aInstance, const otMessageSettings *aSettings)
 {
     return AsCoreType(aInstance).Get<Nat64::Translator>().NewIp4Message(Message::Settings::From(aSettings));
diff --git a/src/core/api/trel_api.cpp b/src/core/api/trel_api.cpp
index 09344d3d1..94e29a279 100644
--- a/src/core/api/trel_api.cpp
+++ b/src/core/api/trel_api.cpp
@@ -82,4 +82,6 @@ const otTrelCounters *otTrelGetCounters(otInstance *aInstance)
 
 void otTrelResetCounters(otInstance *aInstance) { AsCoreType(aInstance).Get<Trel::Interface>().ResetCounters(); }
 
+uint16_t otTrelGetUdpPort(otInstance *aInstance) { return AsCoreType(aInstance).Get<Trel::Interface>().GetUdpPort(); }
+
 #endif // OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
diff --git a/src/core/meshcop/border_agent.cpp b/src/core/meshcop/border_agent.cpp
index 3a61a0ea9..25039cb2f 100644
--- a/src/core/meshcop/border_agent.cpp
+++ b/src/core/meshcop/border_agent.cpp
@@ -670,6 +670,7 @@ void BorderAgent::HandleConnected(SecureTransport::ConnectEvent aEvent)
         if (mUsingEphemeralKey)
         {
             mCounters.mEpskcSecureSessionSuccesses++;
+            mEphemeralKeyTask.Post();
         }
         else
 #endif
@@ -687,11 +688,12 @@ void BorderAgent::HandleConnected(SecureTransport::ConnectEvent aEvent)
         if (mUsingEphemeralKey)
         {
             RestartAfterRemovingEphemeralKey();
+
             if (aEvent == SecureTransport::kDisconnectedError)
             {
                 mCounters.mEpskcSecureSessionFailures++;
             }
-            if (aEvent == SecureTransport::kDisconnectedPeerClosed)
+            else if (aEvent == SecureTransport::kDisconnectedPeerClosed)
             {
                 mCounters.mEpskcDeactivationDisconnects++;
             }
@@ -701,6 +703,7 @@ void BorderAgent::HandleConnected(SecureTransport::ConnectEvent aEvent)
         {
             mState        = kStateStarted;
             mUdpProxyPort = 0;
+
             if (aEvent == SecureTransport::kDisconnectedError)
             {
                 mCounters.mPskcSecureSessionFailures++;
@@ -788,6 +791,16 @@ exit:
     return;
 }
 
+void BorderAgent::Disconnect(void)
+{
+    VerifyOrExit(mState == kStateConnected || mState == kStateAccepted);
+
+    Get<Tmf::SecureAgent>().Disconnect();
+
+exit:
+    return;
+}
+
 #if OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_ENABLE
 
 Error BorderAgent::SetEphemeralKey(const char *aKeyString, uint32_t aTimeout, uint16_t aUdpPort)
@@ -857,16 +870,7 @@ void BorderAgent::ClearEphemeralKey(void)
 
     LogInfo("Clearing ephemeral key");
 
-    if (mEphemeralKeyTimer.IsRunning())
-    {
-        mCounters.mEpskcDeactivationClears++;
-    }
-    else
-    {
-        mCounters.mEpskcDeactivationTimeouts++;
-    }
-
-    mEphemeralKeyTimer.Stop();
+    mCounters.mEpskcDeactivationClears++;
 
     switch (mState)
     {
@@ -877,9 +881,10 @@ void BorderAgent::ClearEphemeralKey(void)
     case kStateStopped:
     case kStateConnected:
     case kStateAccepted:
-        // If there is an active commissioner connection, we wait till
-        // it gets disconnected before removing ephemeral key and
-        // restarting the agent.
+        // If a commissioner connection is currently active, we'll
+        // wait for it to disconnect or for the ephemeral key timeout
+        // or `kKeepAliveTimeout` to expire before removing the key
+        // and restarting the agent.
         break;
     }
 
@@ -890,7 +895,8 @@ exit:
 void BorderAgent::HandleEphemeralKeyTimeout(void)
 {
     LogInfo("Ephemeral key timed out");
-    ClearEphemeralKey();
+    mCounters.mEpskcDeactivationTimeouts++;
+    RestartAfterRemovingEphemeralKey();
 }
 
 void BorderAgent::InvokeEphemeralKeyCallback(void) { mEphemeralKeyCallback.InvokeIfSet(); }
@@ -911,8 +917,8 @@ void BorderAgent::HandleSecureAgentStopped(void *aContext)
 void BorderAgent::HandleSecureAgentStopped(void)
 {
     LogInfo("Reached max allowed connection attempts with ephemeral key");
-    RestartAfterRemovingEphemeralKey();
     mCounters.mEpskcDeactivationMaxAttempts++;
+    RestartAfterRemovingEphemeralKey();
 }
 
 #endif // OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_ENABLE
diff --git a/src/core/meshcop/border_agent.hpp b/src/core/meshcop/border_agent.hpp
index 8e08c22bf..37dc8a5e5 100644
--- a/src/core/meshcop/border_agent.hpp
+++ b/src/core/meshcop/border_agent.hpp
@@ -169,6 +169,17 @@ public:
      */
     State GetState(void) const { return mState; }
 
+    /**
+     * Disconnects the Border Agent from any active secure sessions.
+     *
+     * If Border Agent is connected to a commissioner candidate with ephemeral key, calling this API
+     * will cause the ephemeral key to be cleared after the session is disconnected.
+     *
+     * The Border Agent state may not change immediately upon calling this method, the state will be
+     * updated when the connection update is notified by `HandleConnected()`.
+     */
+    void Disconnect(void);
+
 #if OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_ENABLE
     /**
      * Sets the ephemeral key for a given timeout duration.
@@ -182,9 +193,10 @@ public:
      * Setting the ephemeral key again before a previously set one is timed out will replace the previous one and will
      * reset the timeout.
      *
-     * While the timeout interval is in effect, the ephemeral key can be used only once by an external commissioner to
-     * connect. Once the commissioner disconnects, the ephemeral key is cleared, and Border Agent reverts to using
-     * PSKc.
+     * During the timeout interval, the ephemeral key can be used only once by an external commissioner to establish a
+     * connection. After the commissioner disconnects, the ephemeral key is cleared, and the Border Agent reverts to
+     * using PSKc. If the timeout expires while a commissioner is still connected, the session will be terminated, and
+     * the Border Agent will cease using the ephemeral key and revert to PSKc.
      *
      * @param[in] aKeyString   The ephemeral key.
      * @param[in] aTimeout     The timeout duration in milliseconds to use the ephemeral key.
@@ -210,8 +222,7 @@ public:
      *
      * If a commissioner is connected using the ephemeral key and is currently active, calling this method does not
      * change its state. In this case the `IsEphemeralKeyActive()` will continue to return `true` until the commissioner
-     * disconnects.
-     *
+     * disconnects, or the ephemeral key timeout expires.
      */
     void ClearEphemeralKey(void);
 
diff --git a/src/core/net/nat64_translator.cpp b/src/core/net/nat64_translator.cpp
index da1e6f870..24b94e936 100644
--- a/src/core/net/nat64_translator.cpp
+++ b/src/core/net/nat64_translator.cpp
@@ -518,6 +518,16 @@ exit:
     return err;
 }
 
+void Translator::ClearIp4Cidr(void)
+{
+    mIp4Cidr.Clear();
+    mAddressMappingPool.FreeAll();
+    mActiveAddressMappings.Clear();
+    mIp4AddressPool.Clear();
+
+    UpdateState();
+}
+
 void Translator::SetNat64Prefix(const Ip6::Prefix &aNat64Prefix)
 {
     if (aNat64Prefix.GetLength() == 0)
diff --git a/src/core/net/nat64_translator.hpp b/src/core/net/nat64_translator.hpp
index 2335e7a9f..4ff4479d1 100644
--- a/src/core/net/nat64_translator.hpp
+++ b/src/core/net/nat64_translator.hpp
@@ -251,6 +251,14 @@ public:
      */
     Error SetIp4Cidr(const Ip4::Cidr &aCidr);
 
+    /**
+     * Clears the CIDR used when setting the source address of the outgoing translated IPv4 datagrams.
+     *
+     * @note The NAT64 translator will be reset and all existing sessions will be expired when clearing the configured
+     * CIDR.
+     */
+    void ClearIp4Cidr(void);
+
     /**
      * Sets the prefix of NAT64-mapped addresses in the thread network. The address mapping table will not be cleared.
      * Equals to `ClearNat64Prefix` when an empty prefix is provided.
diff --git a/src/core/radio/trel_interface.hpp b/src/core/radio/trel_interface.hpp
index 70b4eb0b5..a2e86a35a 100644
--- a/src/core/radio/trel_interface.hpp
+++ b/src/core/radio/trel_interface.hpp
@@ -256,6 +256,14 @@ public:
      */
     void ResetCounters(void);
 
+    /**
+     * Returns the TREL UDP port.
+     *
+     * @returns The TREL UDP port.
+     *
+     */
+    uint16_t GetUdpPort(void) const { return mUdpPort; }
+
 private:
 #if OPENTHREAD_CONFIG_TREL_PEER_TABLE_SIZE != 0
     static constexpr uint16_t kPeerTableSize = OPENTHREAD_CONFIG_TREL_PEER_TABLE_SIZE;
diff --git a/src/posix/platform/include/openthread/openthread-system.h b/src/posix/platform/include/openthread/openthread-system.h
index 8a36fd3d7..ef453377d 100644
--- a/src/posix/platform/include/openthread/openthread-system.h
+++ b/src/posix/platform/include/openthread/openthread-system.h
@@ -330,6 +330,22 @@ void otSysUpstreamDnsServerSetResolvConfEnabled(bool aEnabled);
  */
 void otSysUpstreamDnsSetServerList(const otIp6Address *aUpstreamDnsServers, int aNumServers);
 
+/**
+ * Initializes TREL on the given interface.
+ *
+ * After this call, TREL is ready to be enabled on the interface. Callers need to make sure TREL is disabled prior
+ * to this call.
+ */
+void otSysTrelInit(const char *aInterfaceName);
+
+/**
+ * Deinitializes TREL.
+ *
+ * After this call, TREL is deinitialized. It's ready to be initialized on any given interface. Callers need to
+ * make sure TREL is disabled prior to this call.
+ */
+void otSysTrelDeinit(void);
+
 #ifdef __cplusplus
 } // end of extern "C"
 #endif
diff --git a/src/posix/platform/openthread-posix-config.h b/src/posix/platform/openthread-posix-config.h
index 482582ee2..7ae747e64 100644
--- a/src/posix/platform/openthread-posix-config.h
+++ b/src/posix/platform/openthread-posix-config.h
@@ -439,4 +439,22 @@
 #define OPENTHREAD_POSIX_CONFIG_RCP_CAPS_DIAG_ENABLE OPENTHREAD_CONFIG_DIAG_ENABLE
 #endif
 
+/**
+ * @def OPENTHREAD_POSIX_CONFIG_UPSTREAM_DNS_BIND_TO_INFRA_NETIF
+ *
+ * Define as 1 to let the upstream DNS bind the socket to infra network interface.
+ */
+#ifndef OPENTHREAD_POSIX_CONFIG_UPSTREAM_DNS_BIND_TO_INFRA_NETIF
+#define OPENTHREAD_POSIX_CONFIG_UPSTREAM_DNS_BIND_TO_INFRA_NETIF 1
+#endif
+
+/**
+ * @def OPENTHREAD_POSIX_CONFIG_TREL_SELECT_INFRA_IF
+ *
+ * Define to 1 to let TREL select the infrastructure interface, otherwise use the interface in the TREL URL.
+ */
+#ifndef OPENTHREAD_POSIX_CONFIG_TREL_SELECT_INFRA_IF
+#define OPENTHREAD_POSIX_CONFIG_TREL_SELECT_INFRA_IF 0
+#endif
+
 #endif // OPENTHREAD_PLATFORM_POSIX_CONFIG_H_
diff --git a/src/posix/platform/resolver.cpp b/src/posix/platform/resolver.cpp
index 9aa53196a..0e16e6fab 100644
--- a/src/posix/platform/resolver.cpp
+++ b/src/posix/platform/resolver.cpp
@@ -175,7 +175,7 @@ Resolver::Transaction *Resolver::AllocateTransaction(otPlatDnsUpstreamQuery *aTh
     {
         if (txn.mThreadTxn == nullptr)
         {
-            fdOrError = socket(AF_INET, SOCK_DGRAM, 0);
+            fdOrError = CreateUdpSocket();
             if (fdOrError < 0)
             {
                 LogInfo("Failed to create socket for upstream resolver: %d", fdOrError);
@@ -313,6 +313,27 @@ void Resolver::SetUpstreamDnsServers(const otIp6Address *aUpstreamDnsServers, in
     }
 }
 
+int Resolver::CreateUdpSocket(void)
+{
+    int fd = -1;
+
+    VerifyOrExit(otSysGetInfraNetifName() != nullptr, LogDebg("No infra network interface available"));
+    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
+    VerifyOrExit(fd >= 0, LogDebg("Failed to create the UDP socket: %s", strerror(errno)));
+#if OPENTHREAD_POSIX_CONFIG_UPSTREAM_DNS_BIND_TO_INFRA_NETIF
+    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, otSysGetInfraNetifName(), strlen(otSysGetInfraNetifName())) < 0)
+    {
+        LogDebg("Failed to bind the UDP socket to infra interface %s: %s", otSysGetInfraNetifName(), strerror(errno));
+        close(fd);
+        fd = -1;
+        ExitNow();
+    }
+#endif
+
+exit:
+    return fd;
+}
+
 } // namespace Posix
 } // namespace ot
 
diff --git a/src/posix/platform/resolver.hpp b/src/posix/platform/resolver.hpp
index c7b145ff2..816495d6f 100644
--- a/src/posix/platform/resolver.hpp
+++ b/src/posix/platform/resolver.hpp
@@ -118,6 +118,8 @@ private:
         int                     mUdpFd;
     };
 
+    static int CreateUdpSocket(void);
+
     Transaction *GetTransaction(int aFd);
     Transaction *GetTransaction(otPlatDnsUpstreamQuery *aThreadTxn);
     Transaction *AllocateTransaction(otPlatDnsUpstreamQuery *aThreadTxn);
diff --git a/src/posix/platform/system.cpp b/src/posix/platform/system.cpp
index 176a15fbb..ca859b2a9 100644
--- a/src/posix/platform/system.cpp
+++ b/src/posix/platform/system.cpp
@@ -43,6 +43,7 @@
 #include <openthread/cli.h>
 #include <openthread/heap.h>
 #include <openthread/tasklet.h>
+#include <openthread/trel.h>
 #include <openthread/platform/alarm-milli.h>
 #include <openthread/platform/infra_if.h>
 #include <openthread/platform/logging.h>
@@ -138,7 +139,7 @@ void platformInitRcpMode(otPlatformConfig *aPlatformConfig)
     // For Dry-Run option, only init the co-processor.
     VerifyOrExit(!aPlatformConfig->mDryRun);
 
-#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
+#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE && !OPENTHREAD_POSIX_CONFIG_TREL_SELECT_INFRA_IF
     platformTrelInit(getTrelRadioUrl(aPlatformConfig));
 #endif
     platformRandomInit();
@@ -326,7 +327,8 @@ void platformDeinitRcpMode(void)
 #if OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE
     platformNetifDeinit();
 #endif
-#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
+#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE && !OPENTHREAD_POSIX_CONFIG_TREL_SELECT_INFRA_IF
+    otPlatTrelDisable(/* aInstance */ nullptr);
     platformTrelDeinit();
 #endif
 
diff --git a/src/posix/platform/trel.cpp b/src/posix/platform/trel.cpp
index 6b6e6c086..5103ef4dd 100644
--- a/src/posix/platform/trel.cpp
+++ b/src/posix/platform/trel.cpp
@@ -43,6 +43,7 @@
 #include <unistd.h>
 
 #include <openthread/logging.h>
+#include <openthread/openthread-system.h>
 #include <openthread/platform/trel.h>
 
 #include "logger.hpp"
@@ -193,6 +194,15 @@ static void PrepareSocket(uint16_t &aUdpPort)
         DieNow(OT_EXIT_ERROR_ERRNO);
     }
 
+#ifdef __linux__
+    // Bind to the TREL interface
+    if (setsockopt(sSocket, SOL_SOCKET, SO_BINDTODEVICE, sInterfaceName, strlen(sInterfaceName)) < 0)
+    {
+        LogCrit("Failed to bind socket to the interface %s", sInterfaceName);
+        DieNow(OT_EXIT_ERROR_ERRNO);
+    }
+#endif
+
     sockLen = sizeof(sockAddr);
 
     if (getsockname(sSocket, (struct sockaddr *)&sockAddr, &sockLen) == -1)
@@ -473,9 +483,7 @@ void otPlatTrelEnable(otInstance *aInstance, uint16_t *aUdpPort)
 
     VerifyOrExit(!IsSystemDryRun());
 
-    assert(sInitialized);
-
-    VerifyOrExit(!sEnabled);
+    VerifyOrExit(sInitialized && !sEnabled);
 
     PrepareSocket(*aUdpPort);
     trelDnssdStartBrowse();
@@ -492,8 +500,7 @@ void otPlatTrelDisable(otInstance *aInstance)
 
     VerifyOrExit(!IsSystemDryRun());
 
-    assert(sInitialized);
-    VerifyOrExit(sEnabled);
+    VerifyOrExit(sInitialized && sEnabled);
 
     close(sSocket);
     sSocket = -1;
@@ -540,6 +547,8 @@ void otPlatTrelRegisterService(otInstance *aInstance, uint16_t aPort, const uint
     OT_UNUSED_VARIABLE(aInstance);
     VerifyOrExit(!IsSystemDryRun());
 
+    VerifyOrExit(sEnabled);
+
     trelDnssdRegisterService(aPort, aTxtData, aTxtLength);
 
 exit:
@@ -561,10 +570,7 @@ void otPlatTrelResetCounters(otInstance *aInstance)
     ResetCounters();
 }
 
-//---------------------------------------------------------------------------------------------------------------------
-// platformTrel system
-
-void platformTrelInit(const char *aTrelUrl)
+void otSysTrelInit(const char *aInterfaceName)
 {
     // To silence "unused function" warning.
     (void)LogCrit;
@@ -573,17 +579,12 @@ void platformTrelInit(const char *aTrelUrl)
     (void)LogNote;
     (void)LogDebg;
 
-    LogDebg("platformTrelInit(aTrelUrl:\"%s\")", aTrelUrl != nullptr ? aTrelUrl : "");
+    LogDebg("otSysTrelInit(aInterfaceName:\"%s\")", aInterfaceName != nullptr ? aInterfaceName : "");
 
-    assert(!sInitialized);
+    VerifyOrExit(!sInitialized && !sEnabled && aInterfaceName != nullptr);
 
-    if (aTrelUrl != nullptr)
-    {
-        ot::Posix::RadioUrl url(aTrelUrl);
-
-        strncpy(sInterfaceName, url.GetPath(), sizeof(sInterfaceName) - 1);
-        sInterfaceName[sizeof(sInterfaceName) - 1] = '\0';
-    }
+    strncpy(sInterfaceName, aInterfaceName, sizeof(sInterfaceName) - 1);
+    sInterfaceName[sizeof(sInterfaceName) - 1] = '\0';
 
     trelDnssdInitialize(sInterfaceName);
 
@@ -591,13 +592,32 @@ void platformTrelInit(const char *aTrelUrl)
     sInitialized = true;
 
     ResetCounters();
+
+exit:
+    return;
+}
+
+void otSysTrelDeinit(void) { platformTrelDeinit(); }
+
+//---------------------------------------------------------------------------------------------------------------------
+// platformTrel system
+
+void platformTrelInit(const char *aTrelUrl)
+{
+    LogDebg("platformTrelInit(aTrelUrl:\"%s\")", aTrelUrl != nullptr ? aTrelUrl : "");
+
+    if (aTrelUrl != nullptr)
+    {
+        ot::Posix::RadioUrl url(aTrelUrl);
+
+        otSysTrelInit(url.GetPath());
+    }
 }
 
 void platformTrelDeinit(void)
 {
-    VerifyOrExit(sInitialized);
+    VerifyOrExit(sInitialized && !sEnabled);
 
-    otPlatTrelDisable(nullptr);
     sInterfaceName[0] = '\0';
     sInitialized      = false;
     LogDebg("platformTrelDeinit()");
diff --git a/tests/scripts/expect/cli-misc.exp b/tests/scripts/expect/cli-misc.exp
index 522a0faac..86433b16c 100755
--- a/tests/scripts/expect/cli-misc.exp
+++ b/tests/scripts/expect/cli-misc.exp
@@ -184,6 +184,9 @@ expect "Done"
 send "ba state\n"
 expect "Done"
 
+send "ba disconnect\n"
+expect "Done"
+
 send "prefix meshlocal fd00:dead:beef:cafe::/96\n"
 expect_line "Error 7: InvalidArgs"
 send "prefix meshlocal fd00:dead:beef:cafe::/64\n"
diff --git a/tests/scripts/thread-cert/border_router/nat64/test_upstream_dns.py b/tests/scripts/thread-cert/border_router/nat64/test_upstream_dns.py
index 617ea0f19..6f713ce8f 100755
--- a/tests/scripts/thread-cert/border_router/nat64/test_upstream_dns.py
+++ b/tests/scripts/thread-cert/border_router/nat64/test_upstream_dns.py
@@ -41,14 +41,14 @@ import shlex
 # Topology:
 #    ----------------(eth)--------------------
 #           |                 |
-#          BR (Leader)      HOST
+#          BR (Leader)      DNS SERVER
 #           |
 #        ROUTER
 #
 
 BR = 1
 ROUTER = 2
-HOST = 3
+DNS_SERVER = 3
 
 TEST_DOMAIN = 'test.domain'
 TEST_DOMAIN_IP6_ADDRESSES = {'2001:db8::1'}
@@ -70,17 +70,15 @@ class UpstreamDns(thread_cert.TestCase):
     TOPOLOGY = {
         BR: {
             'name': 'BR',
-            'allowlist': [ROUTER],
             'is_otbr': True,
             'version': '1.3',
         },
         ROUTER: {
             'name': 'Router',
-            'allowlist': [BR],
-            'version': '1.3',
+            'version': '1.4',
         },
-        HOST: {
-            'name': 'Host',
+        DNS_SERVER: {
+            'name': 'DNS Server',
             'is_host': True
         },
     }
@@ -88,27 +86,25 @@ class UpstreamDns(thread_cert.TestCase):
     def test(self):
         br = self.nodes[BR]
         router = self.nodes[ROUTER]
-        host = self.nodes[HOST]
+        dns_server = self.nodes[DNS_SERVER]
+
+        self._start_dns_server(dns_server)
+        dns_server_addr = dns_server.get_ether_addrs(ipv4=True, ipv6=False)[0]
 
-        host.start(start_radvd=False)
-        self.simulator.go(5)
+        # Update BR's /etc/resolv.conf and force BR to reload it
+        br.bash(shlex.join(['echo', 'nameserver ' + dns_server_addr]) + ' >> /etc/resolv.conf')
+        br.stop_otbr_service()
+        br.start_otbr_service()
 
         br.start()
-        # When feature flag is enabled, NAT64 might be disabled by default. So
-        # ensure NAT64 is enabled here.
         self.simulator.go(config.LEADER_STARTUP_DELAY)
         self.assertEqual('leader', br.get_state())
 
+        # When feature flag is enabled, NAT64 might be disabled by default. So
+        # ensure NAT64 is enabled here.
         br.nat64_set_enabled(True)
         br.srp_server_set_enabled(True)
 
-        br.bash('service bind9 stop')
-
-        br.bash(shlex.join(['echo', TEST_DOMAIN_BIND_CONF]) + ' >> /etc/bind/named.conf.local')
-        br.bash(shlex.join(['echo', TEST_DOMAIN_BIND_ZONE]) + ' >> /etc/bind/db.test.domain')
-
-        br.bash('service bind9 start')
-
         router.start()
         self.simulator.go(config.ROUTER_STARTUP_DELAY)
         self.assertEqual('router', router.get_state())
@@ -130,6 +126,15 @@ class UpstreamDns(thread_cert.TestCase):
         for record in resolved_names:
             self.assertIn(ipaddress.IPv6Address(record[0]).compressed, TEST_DOMAIN_IP6_ADDRESSES)
 
+    def _start_dns_server(self, dns_server):
+        dns_server.start(start_radvd=False)
+        dns_server.bash('service bind9 stop')
+
+        dns_server.bash(shlex.join(['echo', TEST_DOMAIN_BIND_CONF]) + ' >> /etc/bind/named.conf.local')
+        dns_server.bash(shlex.join(['echo', TEST_DOMAIN_BIND_ZONE]) + ' >> /etc/bind/db.test.domain')
+
+        dns_server.bash('service bind9 start')
+
 
 if __name__ == '__main__':
     unittest.main()
diff --git a/tests/scripts/thread-cert/border_router/test_trel_connectivity.py b/tests/scripts/thread-cert/border_router/test_trel_connectivity.py
index 20ed03932..42a3a1870 100755
--- a/tests/scripts/thread-cert/border_router/test_trel_connectivity.py
+++ b/tests/scripts/thread-cert/border_router/test_trel_connectivity.py
@@ -160,6 +160,8 @@ class TestTrelConnectivity(thread_cert.TestCase):
         self.assertTrue(counters['Outbound']['bytes'] == 0)
         self.assertTrue(counters['Outbound']['failures'] == 0)
 
+        self.assertGreater(br1.get_trel_port(), 0)
+
     def verify(self, pv: PacketVerifier):
         pkts: PacketFilter = pv.pkts
         BR1_RLOC16 = pv.vars['BR1_RLOC16']
diff --git a/tests/scripts/thread-cert/node.py b/tests/scripts/thread-cert/node.py
index da1d96b1f..0ce57dd83 100755
--- a/tests/scripts/thread-cert/node.py
+++ b/tests/scripts/thread-cert/node.py
@@ -1451,6 +1451,11 @@ class NodeImpl:
         self.send_command(cmd)
         self._expect_done()
 
+    def get_trel_port(self):
+        cmd = 'trel port'
+        self.send_command(cmd)
+        return int(self._expect_command_output()[0])
+
     def set_epskc(self, keystring: str, timeout=120000, port=0):
         cmd = 'ba ephemeralkey set ' + keystring + ' ' + str(timeout) + ' ' + str(port)
         self.send_command(cmd)
@@ -3799,19 +3804,27 @@ class LinuxHost():
 
         self.bash(f'ip link set {self.ETH_DEV} down')
 
-    def get_ether_addrs(self):
-        output = self.bash(f'ip -6 addr list dev {self.ETH_DEV}')
+    def get_ether_addrs(self, ipv4=False, ipv6=True):
+        output = self.bash(f'ip addr list dev {self.ETH_DEV}')
 
         addrs = []
         for line in output:
-            # line example: "inet6 fe80::42:c0ff:fea8:903/64 scope link"
+            # line examples:
+            # "inet6 fe80::42:c0ff:fea8:903/64 scope link"
+            # "inet 192.168.9.1/24 brd 192.168.9.255 scope global eth0"
             line = line.strip().split()
 
-            if line and line[0] == 'inet6':
-                addr = line[1]
-                if '/' in addr:
-                    addr = addr.split('/')[0]
-                addrs.append(addr)
+            if not line or not line[0].startswith('inet'):
+                continue
+            if line[0] == 'inet' and not ipv4:
+                continue
+            if line[0] == 'inet6' and not ipv6:
+                continue
+
+            addr = line[1]
+            if '/' in addr:
+                addr = addr.split('/')[0]
+            addrs.append(addr)
 
         logging.debug('%s: get_ether_addrs: %r', self, addrs)
         return addrs
```

