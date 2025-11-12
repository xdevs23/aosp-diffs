```diff
diff --git a/Android.bp b/Android.bp
index 19000d7e..2b17cf39 100644
--- a/Android.bp
+++ b/Android.bp
@@ -78,6 +78,7 @@ java_sdk_library {
         "com.android.internal.net",
         "android.net.ipsec.ike",
         "android.net.eap",
+        "com.android.ipsec.flags",
     ],
     min_sdk_version: "30",
 }
@@ -115,6 +116,7 @@ java_library {
     ],
     static_libs: [
         "bouncycastle_ike_digests",
+        "ipsec_aconfig_flags_lib",
         "modules-utils-build",
         "modules-utils-statemachine",
         "net-utils-framework-ipsec",
diff --git a/apex/Android.bp b/apex/Android.bp
index 2e63fd4e..6456395b 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -34,6 +34,10 @@ apex {
     name: "com.android.ipsec",
     defaults: ["com.android.ipsec-defaults"],
     manifest: "apex_manifest.json",
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 apex_key {
@@ -97,6 +101,7 @@ bootclasspath_fragment {
             "com.android.internal.net.org",
             "com.android.internal.net.utils",
             "com.android.internal.net.vcn",
+            "com.android.ipsec.flags",
         ],
     },
 }
diff --git a/flags/Android.bp b/flags/Android.bp
index b114061e..25655bc3 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -28,6 +28,7 @@ aconfig_declarations {
 java_aconfig_library {
     name: "ipsec_aconfig_flags_lib",
     aconfig_declarations: "ipsec_aconfig_flags",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
     min_sdk_version: "30",
     apex_available: [
         "com.android.ipsec",
diff --git a/flags/ipsec_flags.aconfig b/flags/ipsec_flags.aconfig
index da278a0c..e328f065 100644
--- a/flags/ipsec_flags.aconfig
+++ b/flags/ipsec_flags.aconfig
@@ -31,4 +31,11 @@ flag {
   namespace: "ipsec"
   description: "Expose API to return enabled IKE options"
   bug: "308513922"
+}
+
+flag {
+    name: "use_cached_addresses"
+    namespace: "ipsec"
+    description: "Feature flag for enabling DNS caching during mobility update"
+    bug: "254140820"
 }
\ No newline at end of file
diff --git a/src/java/com/android/internal/net/ipsec/ike/crypto/AesXCbcImpl.java b/src/java/com/android/internal/net/ipsec/ike/crypto/AesXCbcImpl.java
index e5eeaa0a..8a94e041 100644
--- a/src/java/com/android/internal/net/ipsec/ike/crypto/AesXCbcImpl.java
+++ b/src/java/com/android/internal/net/ipsec/ike/crypto/AesXCbcImpl.java
@@ -16,7 +16,7 @@
 
 package com.android.internal.net.ipsec.ike.crypto;
 
-import com.android.internal.util.HexDump;
+import com.android.net.module.util.HexDump;
 
 import java.nio.ByteBuffer;
 import java.security.GeneralSecurityException;
diff --git a/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java b/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
index 64c381ab..84943188 100644
--- a/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
+++ b/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
@@ -33,7 +33,6 @@ import static android.net.ipsec.ike.IkeSessionParams.IKE_OPTION_FORCE_PORT_4500;
 import static android.net.ipsec.ike.exceptions.IkeException.wrapAsIkeException;
 
 import static com.android.internal.net.ipsec.ike.IkeContext.CONFIG_AUTO_NATT_KEEPALIVES_CELLULAR_TIMEOUT_OVERRIDE_SECONDS;
-import static com.android.internal.net.ipsec.ike.IkeContext.CONFIG_USE_CACHED_ADDRS;
 import static com.android.internal.net.ipsec.ike.utils.IkeAlarm.IkeAlarmConfig;
 import static com.android.internal.net.ipsec.ike.utils.IkeAlarmReceiver.ACTION_KEEPALIVE;
 
@@ -71,6 +70,7 @@ import com.android.internal.net.ipsec.ike.message.IkeHeader;
 import com.android.internal.net.ipsec.ike.shim.ShimUtils;
 import com.android.internal.net.ipsec.ike.utils.IkeAlarm;
 import com.android.internal.net.ipsec.ike.utils.IkeMetrics;
+import com.android.ipsec.flags.Flags;
 
 import java.io.IOException;
 import java.io.PrintWriter;
@@ -1202,9 +1202,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
             return false;
         }
 
-        if (mIkeContext.getDeviceConfigPropertyBoolean(
-                        CONFIG_USE_CACHED_ADDRS, false /* defaultValue */)
-                && remoteIpVersionsCached.containsAll(localIpVersions)) {
+        if (Flags.useCachedAddresses() && remoteIpVersionsCached.containsAll(localIpVersions)) {
             return false;
         }
 
diff --git a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java
index 46729257..624eb5b6 100644
--- a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java
+++ b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java
@@ -25,6 +25,6 @@ public class ShimUtilsMinW extends ShimUtilsU {
 
     @Override
     public boolean suspendOnNetworkLossEnabled() {
-        return true;
+        return false;
     }
 }
diff --git a/src/java/com/android/internal/net/ipsec/ike/utils/IkeContext.java b/src/java/com/android/internal/net/ipsec/ike/utils/IkeContext.java
index 75a5352c..0a64edbd 100644
--- a/src/java/com/android/internal/net/ipsec/ike/utils/IkeContext.java
+++ b/src/java/com/android/internal/net/ipsec/ike/utils/IkeContext.java
@@ -33,7 +33,6 @@ public class IkeContext implements EapAuthenticator.EapContext {
             "config_auto_address_family_selection_cellular_prefer_ipv4";
     public static final String CONFIG_AUTO_NATT_KEEPALIVES_CELLULAR_TIMEOUT_OVERRIDE_SECONDS =
             "config_auto_natt_keepalives_cellular_timeout_override_seconds";
-    public static final String CONFIG_USE_CACHED_ADDRS = "config_use_cached_addrs";
 
     private final @IkeMetrics.IkeCaller int mIkeCaller;
     private final Looper mLooper;
diff --git a/tests/iketests/Android.bp b/tests/iketests/Android.bp
index 0bcb5892..9518909e 100644
--- a/tests/iketests/Android.bp
+++ b/tests/iketests/Android.bp
@@ -35,6 +35,7 @@ android_test {
         // TODO (b/149494912): Do not statically link ike and test against <uses-library>
         "ike_test", // Runs against a test version of the IKE library, not on the system's copy.
         "androidx.test.rules",
+        "flag-junit",
         "frameworks-base-testutils",
         "mockito-target-inline-minus-junit4",
         "modules-utils-build",
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
index 7fd36d22..43fc3ede 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
@@ -40,7 +40,6 @@ import static android.system.OsConstants.AF_INET6;
 import static com.android.internal.net.TestUtils.createMockRandomFactory;
 import static com.android.internal.net.eap.test.EapResult.EapResponse.RESPONSE_FLAG_EAP_AKA_SERVER_AUTHENTICATED;
 import static com.android.internal.net.ipsec.test.ike.AbstractSessionStateMachine.RETRY_INTERVAL_MS;
-import static com.android.internal.net.ipsec.test.ike.IkeContext.CONFIG_USE_CACHED_ADDRS;
 import static com.android.internal.net.ipsec.test.ike.IkeSessionStateMachine.CMD_ALARM_FIRED;
 import static com.android.internal.net.ipsec.test.ike.IkeSessionStateMachine.CMD_FORCE_TRANSITION;
 import static com.android.internal.net.ipsec.test.ike.IkeSessionStateMachine.CMD_RECEIVE_IKE_PACKET;
@@ -986,9 +985,6 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         final IkeAlarmConfig alarmConfig = spy(new IkeAlarmConfig(mSpyContext,
                 "mock", NATT_KEEPALIVE_DELAY * 1_000, null, null));
 
-        doReturn(true)
-                .when(ikeContext)
-                .getDeviceConfigPropertyBoolean(eq(CONFIG_USE_CACHED_ADDRS), anyBoolean());
         mSpyIkeConnectionCtrl =
                 spy(
                         new IkeConnectionController(
@@ -7513,7 +7509,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mIkeSessionStateMachine.onUnderlyingNetworkDied(mMockDefaultNetwork);
         mLooper.dispatchAll();
 
-        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+        // TODO: b/433656233  Suspend Retransmission while MOBIKE design improvement
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.BAKLAVA) {
             verifyRetransmitContinuesAndSessionTerminatedByTimeout(
                     IkeSessionStateMachine.DpdIkeLocalInfo.class);
         } else {
@@ -7536,7 +7533,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
                 CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mDpdIkeLocalInfo);
         mLooper.dispatchAll();
 
-        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+        // TODO: b/433656233  Suspend Retransmission while MOBIKE design improvement
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.BAKLAVA) {
             verifyRetransmitContinuesAndSessionTerminatedByTimeout(
                     IkeSessionStateMachine.DpdIkeLocalInfo.class);
         } else {
@@ -7556,7 +7554,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mIkeSessionStateMachine.onUnderlyingNetworkDied(mMockDefaultNetwork);
         mLooper.dispatchAll();
 
-        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+        // TODO: b/433656233  Suspend Retransmission while MOBIKE design improvement
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.BAKLAVA) {
             // Make sure the retransmit flag is not set to suspended.
             assertFalse(mIkeSessionStateMachine.mIsRetransmitSuspended);
         } else {
@@ -7593,7 +7592,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mIkeSessionStateMachine.onUnderlyingNetworkDied(mMockDefaultNetwork);
         mLooper.dispatchAll();
 
-        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+        // TODO: b/433656233  Suspend Retransmission while MOBIKE design improvement
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.BAKLAVA) {
             // Make sure the retransmit flag is not set to suspended.
             assertFalse(mIkeSessionStateMachine.mIsRetransmitSuspended);
             // Verify that retransmission has started.
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
index 85a95ba1..9d3db776 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
@@ -33,7 +33,6 @@ import static android.net.ipsec.test.ike.IkeSessionParams.IKE_OPTION_FORCE_DNS_R
 import static android.net.ipsec.test.ike.IkeSessionParams.IKE_OPTION_FORCE_PORT_4500;
 
 import static com.android.internal.net.ipsec.test.ike.IkeContext.CONFIG_AUTO_NATT_KEEPALIVES_CELLULAR_TIMEOUT_OVERRIDE_SECONDS;
-import static com.android.internal.net.ipsec.test.ike.IkeContext.CONFIG_USE_CACHED_ADDRS;
 import static com.android.internal.net.ipsec.test.ike.net.IkeConnectionController.AUTO_KEEPALIVE_DELAY_SEC_CELL;
 import static com.android.internal.net.ipsec.test.ike.net.IkeConnectionController.AUTO_KEEPALIVE_DELAY_SEC_WIFI;
 import static com.android.internal.net.ipsec.test.ike.net.IkeConnectionController.NAT_TRAVERSAL_SUPPORT_NOT_CHECKED;
@@ -47,7 +46,6 @@ import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
@@ -79,6 +77,10 @@ import android.net.ipsec.test.ike.exceptions.IkeInternalException;
 import android.os.Build.VERSION_CODES;
 import android.os.Handler;
 import android.os.Looper;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 
 import com.android.internal.net.TestUtils;
 import com.android.internal.net.ipsec.test.ike.IkeContext;
@@ -94,6 +96,7 @@ import com.android.internal.net.ipsec.test.ike.keepalive.IkeNattKeepalive;
 import com.android.internal.net.ipsec.test.ike.utils.IkeAlarm.IkeAlarmConfig;
 import com.android.internal.net.ipsec.test.ike.utils.RandomnessFactory;
 import com.android.internal.net.utils.test.Log;
+import com.android.ipsec.flags.Flags;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.testutils.DevSdkIgnoreRule;
 import com.android.testutils.DevSdkIgnoreRule.IgnoreAfter;
@@ -117,6 +120,9 @@ import java.util.concurrent.TimeUnit;
 public class IkeConnectionControllerTest extends IkeSessionTestBase {
     @Rule public final DevSdkIgnoreRule ignoreRule = new DevSdkIgnoreRule();
 
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
     private static final long IKE_LOCAL_SPI = 11L;
 
     private static final int ESP_IP_VERSION_NONE = -1;
@@ -165,10 +171,6 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
         when(mMockConnectionCtrlDeps.newIkeUdp6WithEncapPortSocket(any(), any(), any()))
                 .thenReturn(mMockIkeUdp6WithEncapPortSocket);
 
-        doReturn(true)
-                .when(mIkeContext)
-                .getDeviceConfigPropertyBoolean(eq(CONFIG_USE_CACHED_ADDRS), anyBoolean());
-
         return new IkeConnectionController(
                 mIkeContext,
                 new IkeConnectionController.Config(
@@ -1549,10 +1551,8 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_USE_CACHED_ADDRESSES)
     public void testIsDnsLookupRequired_NetworkChange_LocalRemoteMatch_FlagOff() throws Exception {
-        doReturn(false)
-                .when(mIkeContext)
-                .getDeviceConfigPropertyBoolean(eq(CONFIG_USE_CACHED_ADDRS), anyBoolean());
         verifyIsDnsLookupRequired(
                 true /* isNetworkChanged */,
                 true /* hasLocalV4 */,
@@ -1563,6 +1563,7 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     }
 
     @Test
+    @RequiresFlagsEnabled(Flags.FLAG_USE_CACHED_ADDRESSES)
     public void testIsDnsLookupRequired_NetworkChange_LocalRemoteMatch_FlagOn() throws Exception {
         verifyIsDnsLookupRequired(
                 true /* isNetworkChanged */,
@@ -1574,10 +1575,8 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_USE_CACHED_ADDRESSES)
     public void testIsDnsLookupRequired_NetworkChange_RemoteV4V6_FlagOff() throws Exception {
-        doReturn(false)
-                .when(mIkeContext)
-                .getDeviceConfigPropertyBoolean(eq(CONFIG_USE_CACHED_ADDRS), anyBoolean());
         verifyIsDnsLookupRequired(
                 true /* isNetworkChanged */,
                 false /* hasLocalV4 */,
@@ -1588,6 +1587,7 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     }
 
     @Test
+    @RequiresFlagsEnabled(Flags.FLAG_USE_CACHED_ADDRESSES)
     public void testIsDnsLookupRequired_NetworkChange_RemoteV4V6_FlagOn() throws Exception {
         verifyIsDnsLookupRequired(
                 true /* isNetworkChanged */,
@@ -1710,10 +1710,8 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_USE_CACHED_ADDRESSES)
     public void testIsDnsLookupRequired_LocalV4_RemoteV4V6_FlagOff() throws Exception {
-        doReturn(false)
-                .when(mIkeContext)
-                .getDeviceConfigPropertyBoolean(eq(CONFIG_USE_CACHED_ADDRS), anyBoolean());
         verifyIsDnsLookupRequired(
                 true /* hasLocalV4 */,
                 false /* hasLocalV6 */,
@@ -1723,6 +1721,7 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     }
 
     @Test
+    @RequiresFlagsEnabled(Flags.FLAG_USE_CACHED_ADDRESSES)
     public void testIsDnsLookupRequired_LocalV4_RemoteV4V6_FlagOn() throws Exception {
         verifyIsDnsLookupRequired(
                 true /* hasLocalV4 */,
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java
index 88930aaa..fdd6a91b 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java
@@ -16,7 +16,7 @@
 
 package com.android.internal.net.ipsec.test.ike.shim;
 
-import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertFalse;
 
 import org.junit.Test;
 
@@ -26,6 +26,6 @@ public class ShimUtilsWTest {
     @Test
     public void testSuspendOnNetworkLossEnabled() {
         boolean enabled = mShim.suspendOnNetworkLossEnabled();
-        assertTrue(enabled);
+        assertFalse(enabled);
     }
 }
```

