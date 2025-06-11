```diff
diff --git a/src/java/android/net/ipsec/ike/IkeSession.java b/src/java/android/net/ipsec/ike/IkeSession.java
index 14facd4e..d45a96ee 100644
--- a/src/java/android/net/ipsec/ike/IkeSession.java
+++ b/src/java/android/net/ipsec/ike/IkeSession.java
@@ -470,10 +470,6 @@ public final class IkeSession implements AutoCloseable {
      */
     @FlaggedApi("com.android.ipsec.flags.dumpsys_api")
     public void dump(@NonNull PrintWriter pw) {
-        // TODO(b/336409878): Add @RequiresPermission annotation.
-        mContext.enforceCallingOrSelfPermission(
-                android.Manifest.permission.DUMP, mContext.getAttributionTag());
-
         // Please make sure that the dump is thread-safe
         // so the client won't get a crash or exception when adding codes to the dump.
         pw.println();
diff --git a/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java b/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
index 847d27b1..64c381ab 100644
--- a/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
+++ b/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
@@ -182,6 +182,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
     //Must only be touched on the IkeSessionStateMachine thread.
     private Network mUnderpinnedNetwork;
 
+    private int mKeepaliveDelaySeconds;
     private IkeNattKeepalive mIkeNattKeepalive;
 
     private static final SparseArray<String> NAT_STATUS_TO_STR;
@@ -213,6 +214,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
         mUseCallerConfiguredNetwork = config.ikeParams.getConfiguredNetwork() != null;
         mIpVersion = config.ikeParams.getIpVersion();
         mEncapType = config.ikeParams.getEncapType();
+        mKeepaliveDelaySeconds = config.ikeParams.getNattKeepAliveDelaySeconds();
         mDscp = config.ikeParams.getDscp();
         mUnderpinnedNetwork = null;
 
@@ -637,6 +639,12 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
         return Collections.unmodifiableSet(mIkeSaRecords);
     }
 
+    /** Returns the keepalive config */
+    @VisibleForTesting
+    public IkeAlarmConfig getKeepaliveAlarmConfig() {
+        return mKeepaliveAlarmConfig;
+    }
+
     /**
      * Updates the underlying network
      *
@@ -691,15 +699,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
 
         mIpVersion = ipVersion;
         mEncapType = encapType;
-
-        if (keepaliveDelaySeconds == IkeSessionParams.NATT_KEEPALIVE_INTERVAL_AUTO) {
-            keepaliveDelaySeconds = getKeepaliveDelaySec(mIkeContext, mIkeParams, mNc);
-        }
-        final long keepaliveDelayMs = TimeUnit.SECONDS.toMillis(keepaliveDelaySeconds);
-        if (keepaliveDelayMs != mKeepaliveAlarmConfig.delayMs) {
-            mKeepaliveAlarmConfig = mKeepaliveAlarmConfig.buildCopyWithDelayMs(keepaliveDelayMs);
-            restartKeepaliveIfRunning();
-        }
+        mKeepaliveDelaySeconds = keepaliveDelaySeconds;
 
         // Switch to monitor a new network. This call is never expected to trigger a callback
         mNetworkCallback.setNetwork(network, linkProperties, networkCapabilities);
@@ -1233,6 +1233,23 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
         mNetwork = network;
         mNc = networkCapabilities;
 
+        try {
+            if (mKeepaliveDelaySeconds == IkeSessionParams.NATT_KEEPALIVE_INTERVAL_AUTO) {
+                mKeepaliveDelaySeconds = getKeepaliveDelaySec(mIkeContext, mIkeParams, mNc);
+            }
+
+            final long keepaliveDelayMs = TimeUnit.SECONDS.toMillis(mKeepaliveDelaySeconds);
+
+            if (keepaliveDelayMs != mKeepaliveAlarmConfig.delayMs) {
+                mKeepaliveAlarmConfig =
+                        mKeepaliveAlarmConfig.buildCopyWithDelayMs(keepaliveDelayMs);
+                restartKeepaliveIfRunning();
+            }
+        } catch (IkeException e) {
+            mCallback.onError(wrapAsIkeException(e));
+            return;
+        }
+
         // If there is no local address on the Network, report a fatal error and return
         if (!hasLocalIpV4Address(linkProperties) && !linkProperties.hasGlobalIpv6Address()) {
             mCallback.onError(
diff --git a/tests/iketests/src/java/com/android/internal/net/TestUtils.java b/tests/iketests/src/java/com/android/internal/net/TestUtils.java
index ae6731a5..7c9684d6 100644
--- a/tests/iketests/src/java/com/android/internal/net/TestUtils.java
+++ b/tests/iketests/src/java/com/android/internal/net/TestUtils.java
@@ -16,8 +16,8 @@
 
 package com.android.internal.net;
 
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
@@ -82,7 +82,7 @@ public class TestUtils {
                     throw (Throwable) invocation.getArguments()[2];
                 })
                 .when(spyLog)
-                .wtf(anyString(), anyString(), anyObject());
+                .wtf(anyString(), anyString(), any());
 
         return spyLog;
     }
@@ -109,7 +109,7 @@ public class TestUtils {
                     return null;
                 })
                 .when(spyLog)
-                .wtf(anyString(), anyString(), anyObject());
+                .wtf(anyString(), anyString(), any());
 
         return spyLog;
     }
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachineTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachineTest.java
index e063e177..6bd7a44d 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachineTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachineTest.java
@@ -52,13 +52,12 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyBoolean;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.argThat;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.argThat;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
@@ -341,7 +340,7 @@ public final class ChildSessionStateMachineTest extends IkeSessionTestBase {
 
     private void setUpSpiResource(InetAddress address, int spiRequested) throws Exception {
         when(mMockIpSecService.allocateSecurityParameterIndex(
-                        eq(address.getHostAddress()), anyInt(), anyObject()))
+                        eq(address.getHostAddress()), anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(spiRequested));
     }
 
@@ -1984,7 +1983,7 @@ public final class ChildSessionStateMachineTest extends IkeSessionTestBase {
 
         // Verify no response sent.
         verify(mMockChildSessionSmCallback, never())
-                .onOutboundPayloadsReady(anyInt(), anyBoolean(), any(List.class), anyObject());
+                .onOutboundPayloadsReady(anyInt(), anyBoolean(), any(List.class), any());
 
         // Verify Child SA has been renewed
         verifyChildSaUpdated(mSpyCurrentChildSaRecord, mSpyRemoteInitNewChildSaRecord);
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeLocalRequestSchedulerTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeLocalRequestSchedulerTest.java
index e7ae658c..60204952 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeLocalRequestSchedulerTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeLocalRequestSchedulerTest.java
@@ -24,7 +24,7 @@ import static com.android.internal.net.ipsec.test.ike.IkeSessionStateMachine.CMD
 import static com.android.internal.net.ipsec.test.ike.IkeSessionStateMachine.CMD_LOCAL_REQUEST_MOBIKE;
 
 import static org.junit.Assert.assertEquals;
-import static org.mockito.Matchers.any;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyInt;
 import static org.mockito.Mockito.anyString;
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
index 7674bddd..7fd36d22 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
@@ -92,14 +92,13 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyBoolean;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyLong;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.argThat;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.argThat;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.atLeast;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.doAnswer;
@@ -1474,8 +1473,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
     private IkeMessage verifyEncryptAndEncodeAndGetMessage(IkeSaRecord ikeSaRecord) {
         verify(mMockIkeMessageHelper)
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         eq(ikeSaRecord),
                         mIkeMessageCaptor.capture(),
                         anyBoolean(),
@@ -1486,8 +1485,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
     private void verifyEncryptAndEncodeNeverCalled(IkeSaRecord ikeSaRecord) {
         verify(mMockIkeMessageHelper, never())
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         eq(ikeSaRecord),
                         any(IkeMessage.class),
                         anyBoolean(),
@@ -1497,8 +1496,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
     private void verifyEncryptAndEncodeNeverCalled() {
         verify(mMockIkeMessageHelper, never())
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         any(IkeSaRecord.class),
                         any(IkeMessage.class),
                         anyBoolean(),
@@ -3286,8 +3285,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
     private void verifyEmptyInformationalSent(int count, boolean expectedResp) {
         verify(mMockIkeMessageHelper, times(count))
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         eq(mSpyCurrentIkeSaRecord),
                         argThat(
                                 msg -> {
@@ -3724,8 +3723,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
 
         verify(mMockIkeMessageHelper, times(2))
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         eq(mSpyCurrentIkeSaRecord),
                         mIkeMessageCaptor.capture(),
                         anyBoolean(),
@@ -4762,7 +4761,7 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mLooper.dispatchAll();
 
         // Verify no request received, or response sent.
-        verify(mMockIkeMessageHelper, never()).decode(anyInt(), anyObject(), anyObject());
+        verify(mMockIkeMessageHelper, never()).decode(anyInt(), any(), any());
         verifyEncryptAndEncodeNeverCalled(mSpyCurrentIkeSaRecord);
 
         // Verify final state has not changed - signal was not sent.
@@ -4786,7 +4785,7 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mLooper.dispatchAll();
 
         // Verify no request received, or response sent.
-        verify(mMockIkeMessageHelper, never()).decode(anyInt(), anyObject(), anyObject());
+        verify(mMockIkeMessageHelper, never()).decode(anyInt(), any(), any());
         verifyEncryptAndEncodeNeverCalled(mSpyCurrentIkeSaRecord);
 
         // Verify final state - Idle, with new SA, and old SA closed.
@@ -7576,8 +7575,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         // Verify that message is EXCHANGE_TYPE_CREATE_CHILD_SA.
         verify(mMockIkeMessageHelper, times(1))
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         eq(mSpyCurrentIkeSaRecord),
                         mIkeMessageCaptor.capture(),
                         anyBoolean(),
@@ -7629,8 +7628,8 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         // Verify that message is EXCHANGE_TYPE_INFORMATIONAL.
         verify(mMockIkeMessageHelper, times(2))
                 .encryptAndEncode(
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
                         eq(mSpyCurrentIkeSaRecord),
                         mIkeMessageCaptor.capture(),
                         anyBoolean(),
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionTestBase.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionTestBase.java
index bcfff000..a7e96025 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionTestBase.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionTestBase.java
@@ -22,9 +22,9 @@ import static com.android.internal.net.ipsec.test.ike.IkeSocket.SERVER_PORT_NON_
 import static com.android.internal.net.ipsec.test.ike.IkeSocket.SERVER_PORT_UDP_ENCAPSULATED;
 
 import static org.mockito.ArgumentMatchers.argThat;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyInt;
 import static org.mockito.Mockito.doAnswer;
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeUdpEncapSocketTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeUdpEncapSocketTest.java
index 62028c9d..b12d91a2 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeUdpEncapSocketTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeUdpEncapSocketTest.java
@@ -20,7 +20,6 @@ import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyInt;
-import static org.mockito.Mockito.anyObject;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
@@ -91,11 +90,11 @@ public final class IkeUdpEncapSocketTest extends IkeSocketTestBase {
         IpSecManager dummyIpSecManager = mockIpSecTestUtils.getIpSecManager();
         IpSecService ipSecService = mockIpSecTestUtils.getIpSecService();
 
-        when(ipSecService.openUdpEncapsulationSocket(anyInt(), anyObject()))
+        when(ipSecService.openUdpEncapsulationSocket(anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecUdpEncapResponse(12345));
         mSpyDummyUdpEncapSocketOne = spy(dummyIpSecManager.openUdpEncapsulationSocket());
 
-        when(ipSecService.openUdpEncapsulationSocket(anyInt(), anyObject()))
+        when(ipSecService.openUdpEncapsulationSocket(anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecUdpEncapResponse(23456));
         mSpyDummyUdpEncapSocketTwo = spy(dummyIpSecManager.openUdpEncapsulationSocket());
 
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java
index 344b53d8..748b9c69 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java
@@ -23,10 +23,10 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.mockito.AdditionalMatchers.aryEq;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
@@ -245,10 +245,10 @@ public final class SaRecordTest {
         Context context = mockIpSecTestUtils.getContext();
 
         when(mockIpSecService.allocateSecurityParameterIndex(
-                        eq(LOCAL_ADDRESS.getHostAddress()), anyInt(), anyObject()))
+                        eq(LOCAL_ADDRESS.getHostAddress()), anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(FIRST_CHILD_INIT_SPI));
         when(mockIpSecService.allocateSecurityParameterIndex(
-                        eq(REMOTE_ADDRESS.getHostAddress()), anyInt(), anyObject()))
+                        eq(REMOTE_ADDRESS.getHostAddress()), anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(FIRST_CHILD_RESP_SPI));
 
         SecurityParameterIndex childInitSpi =
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/keepalive/IkeNattKeepaliveTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/keepalive/IkeNattKeepaliveTest.java
index 4915bd27..eba0cbc8 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/keepalive/IkeNattKeepaliveTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/keepalive/IkeNattKeepaliveTest.java
@@ -24,9 +24,8 @@ import static com.android.internal.net.ipsec.test.ike.utils.IkeAlarm.IkeAlarmCon
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
@@ -122,12 +121,12 @@ public class IkeNattKeepaliveTest {
         doReturn(mMockSocketKeepalive)
                 .when(mMockConnectManager)
                 .createSocketKeepalive(
-                        anyObject(),
-                        anyObject(),
-                        anyObject(),
-                        anyObject(),
-                        anyObject(),
-                        anyObject());
+                        any(),
+                        any(),
+                        any(),
+                        any(),
+                        any(),
+                        any());
     }
 
     private void resetMockDeps(
@@ -135,10 +134,10 @@ public class IkeNattKeepaliveTest {
         reset(mMockDeps);
         doReturn(softwareKeepalive)
                 .when(mMockDeps)
-                .createSoftwareKeepaliveImpl(anyObject(), anyObject(), anyObject(), anyObject());
+                .createSoftwareKeepaliveImpl(any(), any(), any(), any());
         doReturn(hardwareKeepalive)
                 .when(mMockDeps)
-                .createHardwareKeepaliveImpl(anyObject(), anyObject(), anyObject(), anyObject());
+                .createHardwareKeepaliveImpl(any(), any(), any(), any());
     }
 
     private IkeNattKeepalive createIkeNattKeepalive() throws Exception {
@@ -150,7 +149,7 @@ public class IkeNattKeepaliveTest {
         reset(mMockDeps);
         doReturn(mMockSoftwareKeepalive)
                 .when(mMockDeps)
-                .createSoftwareKeepaliveImpl(anyObject(), anyObject(), anyObject(), anyObject());
+                .createSoftwareKeepaliveImpl(any(), any(), any(), any());
         return createIkeNattKeepalive();
     }
 
@@ -218,11 +217,11 @@ public class IkeNattKeepaliveTest {
 
         verify(mockConnectManager)
                 .createSocketKeepalive(
-                        anyObject(),
-                        anyObject(),
-                        anyObject(),
-                        anyObject(),
-                        anyObject(),
+                        any(),
+                        any(),
+                        any(),
+                        any(),
+                        any(),
                         socketKeepaliveCbCaptor.capture());
 
         return socketKeepaliveCbCaptor.getValue();
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayloadTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayloadTest.java
index 21f0f121..0322994a 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayloadTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayloadTest.java
@@ -38,7 +38,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeMessageTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeMessageTest.java
index 1b917c75..bf2bcbf7 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeMessageTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeMessageTest.java
@@ -31,10 +31,10 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyBoolean;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayloadTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayloadTest.java
index 4ddba3fc..9f6d4974 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayloadTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayloadTest.java
@@ -34,10 +34,9 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
@@ -252,12 +251,12 @@ public final class IkeSaPayloadTest {
 
         IpSecService mMockIpSecService = mMockIpSecTestUtils.getIpSecService();
         when(mMockIpSecService.allocateSecurityParameterIndex(
-                        eq(LOCAL_ADDRESS.getHostAddress()), anyInt(), anyObject()))
+                        eq(LOCAL_ADDRESS.getHostAddress()), anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(CHILD_SPI_LOCAL_ONE))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(CHILD_SPI_LOCAL_TWO));
 
         when(mMockIpSecService.allocateSecurityParameterIndex(
-                        eq(REMOTE_ADDRESS.getHostAddress()), anyInt(), anyObject()))
+                        eq(REMOTE_ADDRESS.getHostAddress()), anyInt(), any()))
                 .thenReturn(MockIpSecTestUtils.buildDummyIpSecSpiResponse(CHILD_SPI_REMOTE));
 
         mIkeSpiGenerator = new IkeSpiGenerator(createMockRandomFactory());
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSkfPayloadTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSkfPayloadTest.java
index 5abb6f56..9a759fa8 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSkfPayloadTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeSkfPayloadTest.java
@@ -19,7 +19,7 @@ package com.android.internal.net.ipsec.test.ike.message;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
index 52324fde..85a95ba1 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
@@ -112,6 +112,7 @@ import java.net.Inet4Address;
 import java.net.Inet6Address;
 import java.net.InetAddress;
 import java.util.HashSet;
+import java.util.concurrent.TimeUnit;
 
 public class IkeConnectionControllerTest extends IkeSessionTestBase {
     @Rule public final DevSdkIgnoreRule ignoreRule = new DevSdkIgnoreRule();
@@ -217,7 +218,9 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
 
         mIkeConnectionCtrl = buildIkeConnectionCtrl();
         mIkeConnectionCtrl.setUp();
-        verify(mMockIkeParams).getNattKeepAliveDelaySeconds();
+        // getNattKeepAliveDelaySeconds is called once in IkeConnectionController#setUp() and once
+        // at constructor of IkeConnectionController
+        verify(mMockIkeParams, times(2)).getNattKeepAliveDelaySeconds();
         mIkeConnectionCtrl.registerIkeSaRecord(mMockIkeSaRecord);
     }
 
@@ -1152,10 +1155,14 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
         IkeNetworkCallbackBase callback = enableMobilityAndReturnCb(true /* isDefaultNetwork */);
         onNetworkSetByUserWithDefaultParams(mIkeConnectionCtrl, newNetwork);
 
-        // hasIkeOption and getNattKeepAliveDelaySeconds were already called once by
-        // IkeConnectionController#setUp() so check they were called a second time
-        verify(mMockIkeParams, times(2)).hasIkeOption(IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES);
-        verify(mMockIkeParams, times(2)).getNattKeepAliveDelaySeconds();
+        // hasIkeOption was already called once by IkeConnectionController#setUp() so check it was
+        // called second time
+        verify(mMockIkeParams, times(2)).hasIkeOption(
+                IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES);
+        // getNattKeepAliveDelaySeconds was already called once each by
+        // IkeConnectionController#setUp() and at constructor of IkeConnectionController, so check
+        // it was called third time
+        verify(mMockIkeParams, times(3)).getNattKeepAliveDelaySeconds();
         verifyNetworkAndAddressesAfterMobilityEvent(
                 newNetwork, UPDATED_LOCAL_ADDRESS, REMOTE_ADDRESS, callback);
         verify(mMockConnectionCtrlCb).onUnderlyingNetworkUpdated();
@@ -1782,4 +1789,46 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
         mIkeConnectionCtrl.dump(new PrintWriter(stringWriter), "");
         assertFalse(stringWriter.toString().isEmpty());
     }
+
+    private Network createMockNetwork(int transportType) throws Exception {
+        Network network = mock(Network.class);
+        NetworkCapabilities caps = mock(NetworkCapabilities.class);
+        when(caps.hasTransport(transportType)).thenReturn(true);
+        when(mMockConnectManager.getNetworkCapabilities(network)).thenReturn(caps);
+
+        setupLocalAddressForNetwork(network, LOCAL_ADDRESS);
+        setupRemoteAddressForNetwork(network, REMOTE_ADDRESS);
+
+        return network;
+    }
+
+    @Test
+    public void testKeepaliveDelayUpdatesOnNetworkSwitchWithAutoKeeplive() throws Exception {
+        mIkeConnectionCtrl.enableMobility();
+
+        when(mMockIkeParams.getNattKeepAliveDelaySeconds()).thenReturn(200);
+        doReturn(true).when(mMockIkeParams).hasIkeOption(IKE_OPTION_AUTOMATIC_NATT_KEEPALIVES);
+
+        // Migrate IKE to a mocked Wifi netwpork
+        onNetworkSetByUserWithDefaultParams(mIkeConnectionCtrl, createMockNetwork(TRANSPORT_WIFI));
+
+        // Validate the keep alive time set for wifi
+        assertEquals(
+                TimeUnit.SECONDS.toMillis(AUTO_KEEPALIVE_DELAY_SEC_WIFI),
+                mIkeConnectionCtrl.getKeepaliveAlarmConfig().delayMs);
+
+        final int carrierConfigCellDelaySeconds = 100;
+        doReturn(carrierConfigCellDelaySeconds)
+                .when(mIkeContext)
+                .getDeviceConfigPropertyInt(anyString(), anyInt(), anyInt(), anyInt());
+
+        // Migrate IKE to a mocked cell netwpork
+        onNetworkSetByUserWithDefaultParams(
+                mIkeConnectionCtrl, createMockNetwork(TRANSPORT_CELLULAR));
+
+        // Validate the keep alive time set for celll
+        assertEquals(
+                TimeUnit.SECONDS.toMillis(carrierConfigCellDelaySeconds),
+                mIkeConnectionCtrl.getKeepaliveAlarmConfig().delayMs);
+    }
 }
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeDefaultNetworkCallbackTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeDefaultNetworkCallbackTest.java
index 0bf7d246..22977718 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeDefaultNetworkCallbackTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeDefaultNetworkCallbackTest.java
@@ -16,8 +16,8 @@
 
 package com.android.internal.net.ipsec.test.ike.net;
 
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/testutils/MockIpSecTestUtils.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/testutils/MockIpSecTestUtils.java
index f6fee185..4662bd41 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/testutils/MockIpSecTestUtils.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/testutils/MockIpSecTestUtils.java
@@ -20,9 +20,9 @@ import static android.system.OsConstants.AF_INET;
 import static android.system.OsConstants.IPPROTO_UDP;
 import static android.system.OsConstants.SOCK_DGRAM;
 
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
 
@@ -53,14 +53,14 @@ public final class MockIpSecTestUtils {
         mContext = InstrumentationRegistry.getContext();
         mIpSecManager = new IpSecManager(mContext, mMockIpSecService);
 
-        when(mMockIpSecService.allocateSecurityParameterIndex(anyString(), anyInt(), anyObject()))
+        when(mMockIpSecService.allocateSecurityParameterIndex(anyString(), anyInt(), any()))
                 .thenReturn(
                         new IpSecSpiResponse(
                                 IpSecManager.Status.OK,
                                 DUMMY_CHILD_SPI_RESOURCE_ID,
                                 DUMMY_CHILD_SPI));
 
-        when(mMockIpSecService.openUdpEncapsulationSocket(anyInt(), anyObject()))
+        when(mMockIpSecService.openUdpEncapsulationSocket(anyInt(), any()))
                 .thenReturn(
                         new IpSecUdpEncapResponse(
                                 IpSecManager.Status.OK,
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/utils/RetransmitterTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/utils/RetransmitterTest.java
index 95ced5fb..7a638621 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/utils/RetransmitterTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/utils/RetransmitterTest.java
@@ -21,9 +21,8 @@ import static com.android.internal.net.ipsec.test.ike.IkeSessionStateMachine.CMD
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.times;
@@ -69,7 +68,7 @@ public final class RetransmitterTest {
         mMockHandler = mock(Handler.class);
 
         Message mockMessage = mock(Message.class);
-        doReturn(mockMessage).when(mMockHandler).obtainMessage(eq(CMD_RETRANSMIT), anyObject());
+        doReturn(mockMessage).when(mMockHandler).obtainMessage(eq(CMD_RETRANSMIT), any());
 
         mMockIkeMessage = mock(IkeMessage.class);
         mRetransmitter =
```

