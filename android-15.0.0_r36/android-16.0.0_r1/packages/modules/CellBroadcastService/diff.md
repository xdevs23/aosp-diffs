```diff
diff --git a/src/com/android/cellbroadcastservice/CellBroadcastHandler.java b/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
index 90686b9..e3b2a41 100644
--- a/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
+++ b/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
@@ -855,9 +855,11 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
      * Find the name of the default CBR package. The criteria is that it belongs to CB apex and
      * handles the given intent.
      */
-    static String getDefaultCBRPackageName(Context context, Intent intent) {
+    @VisibleForTesting
+    public static String getDefaultCBRPackageName(Context context, Intent intent) {
         PackageManager packageManager = context.getPackageManager();
-        List<ResolveInfo> cbrPackages = packageManager.queryBroadcastReceivers(intent, 0);
+        List<ResolveInfo> cbrPackages = packageManager.queryBroadcastReceivers(intent,
+                PackageManager.MATCH_SYSTEM_ONLY);
 
         // remove apps that don't live in the CellBroadcast apex
         cbrPackages.removeIf(info ->
diff --git a/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java b/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java
index d945ee7..40cf4df 100644
--- a/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java
+++ b/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java
@@ -580,8 +580,8 @@ public class GsmCellBroadcastHandler extends CellBroadcastHandler {
      * network.
      */
     private @Nullable Pair<Integer, Integer> getLacAndCid(int slotIndex) {
-        TelephonyManager tm = mContext.getSystemService(TelephonyManager.class);
-        tm.createForSubscriptionId(getSubIdForPhone(mContext, slotIndex));
+        TelephonyManager tm = mContext.getSystemService(TelephonyManager.class)
+                .createForSubscriptionId(getSubIdForPhone(mContext, slotIndex));
 
         ServiceState serviceState = tm.getServiceState();
 
@@ -646,9 +646,8 @@ public class GsmCellBroadcastHandler extends CellBroadcastHandler {
             }
 
             if (VDBG) log("header=" + header);
-            TelephonyManager tm =
-                    (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);
-            tm.createForSubscriptionId(getSubIdForPhone(mContext, slotIndex));
+            TelephonyManager tm = mContext.getSystemService(TelephonyManager.class)
+                            .createForSubscriptionId(getSubIdForPhone(mContext, slotIndex));
             String plmn = tm.getNetworkOperator();
             int lac = -1;
             int cid = -1;
diff --git a/tests/Android.bp b/tests/Android.bp
index 95110ea..db68a51 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -6,9 +6,10 @@ package {
 android_test {
     name: "CellBroadcastServiceTests",
     static_libs: [
-        "mockito-target",
-        "compatibility-device-util-axt",
+        "frameworks-base-testutils",
         "androidx.test.rules",
+        "mockito-target-extended-minus-junit4",
+        "modules-utils-build",
         "modules-utils-handlerexecutor",
         "modules-utils-locallog",
         "modules-utils-preconditions",
@@ -27,6 +28,11 @@ android_test {
         "src/**/*.java",
         ":cellbroadcast-shared-srcs",
     ],
+    compile_multilib: "both",
+    jni_libs: [
+        "libdexmakerjvmtiagent",
+        "libstaticjvmtiagent",
+    ],
     platform_apis: true,
     test_suites: [
         "general-tests",
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index 2235eed..212b80c 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -19,7 +19,7 @@
 
     <uses-permission android:name="android.permission.READ_CELL_BROADCASTS" />
 
-    <application>
+    <application android:debuggable="true">
         <uses-library android:name="android.test.runner" />
     </application>
 
diff --git a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
index 3037c62..79648c6 100644
--- a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
+++ b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
@@ -38,6 +38,7 @@ import android.content.ContentValues;
 import android.content.Context;
 import android.content.IIntentSender;
 import android.content.Intent;
+import android.content.pm.PackageManager;
 import android.content.res.Configuration;
 import android.database.Cursor;
 import android.database.MatrixCursor;
@@ -497,6 +498,15 @@ public class CellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
         cellBroadcastHandler.cleanup();
     }
 
+    @Test
+    @SmallTest
+    public void testGetDefaultCBRPackageName() {
+        Intent intent = new Intent(Telephony.Sms.Intents.ACTION_SMS_EMERGENCY_CB_RECEIVED);
+        CellBroadcastHandler.getDefaultCBRPackageName(mMockedContext, intent);
+        verify(mMockedPackageManager, times(1))
+                .queryBroadcastReceivers(intent, PackageManager.MATCH_SYSTEM_ONLY);
+    }
+
     /**
      * Makes injecting a mock factory easy.
      */
diff --git a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastServiceTestBase.java b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastServiceTestBase.java
index 3db1131..4fc8302 100644
--- a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastServiceTestBase.java
+++ b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastServiceTestBase.java
@@ -24,6 +24,7 @@ import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.when;
 
 import android.content.BroadcastReceiver;
 import android.content.Context;
@@ -140,6 +141,10 @@ public class CellBroadcastServiceTestBase extends TestCase {
                 .getSystemServiceName(TelephonyManager.class);
         doReturn(mMockedSubscriptionManager).when(mMockedContext)
                 .getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
+        when(mMockedContext.getSystemService(TelephonyManager.class))
+                .thenReturn(mMockedTelephonyManager);
+        when(mMockedContext.getSystemService(SubscriptionManager.class))
+                .thenReturn(mMockedSubscriptionManager);
         doReturn(Context.TELEPHONY_SUBSCRIPTION_SERVICE).when(mMockedContext).getSystemServiceName(
                 SubscriptionManager.class);
         doReturn(mMockedLocationManager).when(mMockedContext)
diff --git a/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java b/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java
index ee933a7..257388a 100644
--- a/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java
+++ b/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java
@@ -16,6 +16,8 @@
 
 package com.android.cellbroadcastservice.tests;
 
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
+
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
@@ -24,6 +26,7 @@ import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.lenient;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
@@ -76,7 +79,8 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
-import org.mockito.Spy;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
 
 import java.util.HashMap;
 import java.util.List;
@@ -95,9 +99,6 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
     @Mock
     private Map<Integer, Resources> mMockedResourcesCache;
 
-    @Spy
-    private HashMap<GsmCellBroadcastHandler.SmsCbConcatInfo, byte[][]> mMockedSmsCbPageMap;
-
     @Mock
     private SubscriptionInfo mSubInfo;
 
@@ -306,6 +307,8 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
                 any(), any(), anyInt(), any(), any());
     }
 
+    private MockitoSession mMockitoSession;
+
     @Test
     @SmallTest
     public void testSmsCbLocation() {
@@ -345,6 +348,88 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
         assertEquals(fakeCid, location.getCid());
     }
 
+    @Test
+    @SmallTest
+    public void testSmsCbLocationInMultiSim() {
+        try {
+            mMockitoSession =
+                    mockitoSession()
+                            .mockStatic(SubscriptionManager.class)
+                            .strictness(Strictness.LENIENT)
+                            .startMocking();
+            lenient().when(SubscriptionManager.isValidSubscriptionId(anyInt()))
+                    .thenReturn(true);
+            lenient().when(SubscriptionManager.getResourcesForSubId(any(), anyInt()))
+                    .thenReturn(mMockedResources);
+            int slotIndex = 2;
+            int subId = 2;
+            if (SdkLevel.isAtLeastU()) {
+                lenient().when(SubscriptionManager.getSubscriptionId(slotIndex))
+                    .thenReturn(subId);
+            }
+            doReturn(new int[]{subId}).when(mMockedSubscriptionManager)
+                    .getSubscriptionIds(slotIndex);
+
+            final byte[] pdu = hexStringToBytes(
+                    "01111B40110101C366701A093685456924080000000000000000000000000000000000000"
+                            + "0000000000000000000000000000000000000000000000000000000000"
+                            + "000000000000000000000000000000000000000000000000B");
+
+            final String plmnSim1 = "310999";
+            final int tacSim1 = 1234;
+            final int cidSim1 = 5678;
+
+            final String plmnSim2 = "310450";
+            final int tacSim2 = 4321;
+            final int cidSim2 = 8765;
+
+            TelephonyManager tm2 = mock(TelephonyManager.class);
+            doReturn(tm2).when(mMockedTelephonyManager)
+                    .createForSubscriptionId(subId);
+            doReturn(plmnSim1).when(mMockedTelephonyManager).getNetworkOperator();
+            doReturn(plmnSim2).when(tm2).getNetworkOperator();
+            ServiceState ss = mock(ServiceState.class);
+            ServiceState ssSim2 = mock(ServiceState.class);
+            doReturn(ss).when(mMockedTelephonyManager).getServiceState();
+            doReturn(ssSim2).when(tm2).getServiceState();
+            NetworkRegistrationInfo nri = new NetworkRegistrationInfo.Builder()
+                    .setDomain(NetworkRegistrationInfo.DOMAIN_CS)
+                    .setAccessNetworkTechnology(TelephonyManager.NETWORK_TYPE_LTE)
+                    .setTransportType(AccessNetworkConstants.TRANSPORT_TYPE_WWAN)
+                    .setRegistrationState(NetworkRegistrationInfo.REGISTRATION_STATE_HOME)
+                    .setCellIdentity(new CellIdentityLte(0, 0, cidSim1, 0, tacSim1))
+                    .build();
+            NetworkRegistrationInfo nri2 = new NetworkRegistrationInfo.Builder()
+                    .setDomain(NetworkRegistrationInfo.DOMAIN_CS)
+                    .setAccessNetworkTechnology(TelephonyManager.NETWORK_TYPE_LTE)
+                    .setTransportType(AccessNetworkConstants.TRANSPORT_TYPE_WWAN)
+                    .setRegistrationState(NetworkRegistrationInfo.REGISTRATION_STATE_HOME)
+                    .setCellIdentity(new CellIdentityLte(0, 0, cidSim2,
+                            0, tacSim2))
+                    .build();
+            doReturn(nri).when(ss).getNetworkRegistrationInfo(anyInt(), anyInt());
+            doReturn(nri2).when(ssSim2).getNetworkRegistrationInfo(anyInt(), anyInt());
+
+            mGsmCellBroadcastHandler.onGsmCellBroadcastSms(slotIndex, pdu);
+            mTestableLooper.processAllMessages();
+
+            ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
+            verify(mMockedContext).sendOrderedBroadcast(intentCaptor.capture(), any(),
+                    (Bundle) any(), any(), any(), anyInt(), any(), any());
+            Intent intent = intentCaptor.getValue();
+            assertEquals(Telephony.Sms.Intents.ACTION_SMS_EMERGENCY_CB_RECEIVED,
+                    intent.getAction());
+            SmsCbMessage msg = intent.getParcelableExtra("message");
+
+            SmsCbLocation location = msg.getLocation();
+            assertEquals(plmnSim2, location.getPlmn());
+            assertEquals(tacSim2, location.getLac());
+            assertEquals(cidSim2, location.getCid());
+        } finally {
+            mMockitoSession.finishMocking();
+        }
+    }
+
     @Test
     @SmallTest
     public void testGeofencingAmbiguousWithMockCalculator() {
@@ -591,27 +676,29 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
     @Test
     @SmallTest
     public void testConcatMessage() throws Exception {
+        HashMap<GsmCellBroadcastHandler.SmsCbConcatInfo, byte[][]>  mockedSmsCbPageMap =
+                new HashMap<>(4);
         doReturn("111222").when(mMockedTelephonyManager).getNetworkOperator();
         replaceInstance(GsmCellBroadcastHandler.class, "mSmsCbPageMap",
-                mGsmCellBroadcastHandler, mMockedSmsCbPageMap);
+                mGsmCellBroadcastHandler, mockedSmsCbPageMap);
 
         // serial_number : 0x1123, message_id : 0x1112, page1/total2
         final byte[] pdu1 = hexStringToBytes("112311120112C8329BFD06");
         mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu1);
         mTestableLooper.processAllMessages();
-        assertEquals(1, mMockedSmsCbPageMap.size());
+        assertEquals(1, mockedSmsCbPageMap.size());
 
         // serial_number : 0x1123, message_id : 0x1113, page1/total2
         final byte[] pdu2 = hexStringToBytes("112311130112C7F7FBCC2E03");
         mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu2);
         mTestableLooper.processAllMessages();
-        assertEquals(2, mMockedSmsCbPageMap.size());
+        assertEquals(2, mockedSmsCbPageMap.size());
 
         // serial_number : 0x1123, message_id : 0x1112, page2/total2
         final byte[] pdu3 = hexStringToBytes("112311130122C7F7FBCC2E03");
         mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu3);
         mTestableLooper.processAllMessages();
-        assertEquals(1, mMockedSmsCbPageMap.size());
+        assertEquals(1, mockedSmsCbPageMap.size());
 
         mGsmCellBroadcastHandler.sendMessage(/*WakeLockStateMachine.EVENT_BROADCAST_COMPLETE*/ 2);
         mTestableLooper.processAllMessages();
@@ -620,7 +707,7 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
         final byte[] pdu4 = hexStringToBytes("112311120122C8329BFD06");
         mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu4);
         mTestableLooper.processAllMessages();
-        assertEquals(0, mMockedSmsCbPageMap.size());
+        assertEquals(0, mockedSmsCbPageMap.size());
 
         mGsmCellBroadcastHandler.sendMessage(/*WakeLockStateMachine.EVENT_BROADCAST_COMPLETE*/ 2);
         mTestableLooper.processAllMessages();
```

