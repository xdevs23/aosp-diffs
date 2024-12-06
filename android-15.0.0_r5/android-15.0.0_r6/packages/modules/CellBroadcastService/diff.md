```diff
diff --git a/Android.bp b/Android.bp
index 3f609a1..74c39a8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -12,7 +12,7 @@ java_defaults {
     ],
     libs: [
         "framework-annotations-lib",
-        "framework-statsd",
+        "framework-statsd.stubs.module_lib",
         "framework-location.stubs.module_lib",
         "unsupportedappusage",
     ],
diff --git a/cellbroadcast-jarjar-rules.txt b/cellbroadcast-jarjar-rules.txt
index f2a1d50..8fda7c3 100644
--- a/cellbroadcast-jarjar-rules.txt
+++ b/cellbroadcast-jarjar-rules.txt
@@ -1,7 +1,7 @@
 rule android.util.LocalLog* com.android.cellbroadcastservice.LocalLog@1
-rule android.internal.util.IState* com.android.cellbroadcastservice.IState@1
+rule com.android.internal.util.IState* com.android.cellbroadcastservice.IState@1
 rule android.internal.util.Preconditions* com.android.cellbroadcastservice.Preconditions@1
 rule com.android.internal.util.Preconditions* com.android.cellbroadcastservice.internal.Preconditions@1
-rule android.internal.util.State* com.android.cellbroadcastservice.State@1
-rule android.internal.util.StateMachine* com.android.cellbroadcastservice.StateMachine@1
+rule com.android.internal.util.State* com.android.cellbroadcastservice.State@1
+rule com.android.internal.util.StateMachine* com.android.cellbroadcastservice.StateMachine@1
 rule com.android.modules.utils.** com.android.cellbroadcastservice.@1
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 4d58edc..c7e6a13 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -20,5 +20,5 @@
     <string name="etws_primary_default_message_tsunami" msgid="2521384573822842618">"Неадкладна эвакуіруйцеся з прыбярэжных раёнаў у больш бяспечнае месца, напрыклад на ўзвышша."</string>
     <string name="etws_primary_default_message_earthquake_and_tsunami" msgid="7826176257527823396">"Заставайцеся спакойнымі і пашукайце прытулак паблізу."</string>
     <string name="etws_primary_default_message_test" msgid="2739829278266087553">"Праверка экстранных паведамленняў"</string>
-    <string name="etws_primary_default_message_others" msgid="3271611843755121534">"Абвестка выпушчана мясцовымі органамі ўлады. Неўзабаве з\'явіцца дадатковая інфармацыя."</string>
+    <string name="etws_primary_default_message_others" msgid="3271611843755121534">"Абвестка выпушчана мясцовымі органамі ўлады. Неўзабаве з’явіцца дадатковая інфармацыя."</string>
 </resources>
diff --git a/src/com/android/cellbroadcastservice/CellBroadcastHandler.java b/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
index de6b7b0..90686b9 100644
--- a/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
+++ b/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
@@ -563,9 +563,10 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
             // If messages are from different slots, then we only compare the message body.
             if (VDBG) log("Checking the message " + messageToCheck);
             if (crossSimDuplicateDetection
-                    && message.getSubscriptionId() != messageToCheck.getSubscriptionId()) {
+                    && message.getSubscriptionId() != messageToCheck.getSubscriptionId()
+                    && message.getSlotIndex() != messageToCheck.getSlotIndex()) {
                 if (TextUtils.equals(message.getMessageBody(), messageToCheck.getMessageBody())) {
-                    log("Duplicate message detected from different slot. " + message);
+                    log("Duplicate message detected from different slot and subId " + message);
                     return true;
                 }
                 if (VDBG) log("Not from the same slot.");
diff --git a/src/com/android/cellbroadcastservice/CellBroadcastServiceMetrics.java b/src/com/android/cellbroadcastservice/CellBroadcastServiceMetrics.java
index 21599ef..6e417c6 100644
--- a/src/com/android/cellbroadcastservice/CellBroadcastServiceMetrics.java
+++ b/src/com/android/cellbroadcastservice/CellBroadcastServiceMetrics.java
@@ -256,16 +256,15 @@ public class CellBroadcastServiceMetrics {
      *
      * @param type     : radio type
      * @param source   : layer of reported message
-     * @param serialNo : unique identifier of message
+     * @param serialNo : set 0 as deprecated
      * @param msgId    : service_category of message
      */
     public void logMessageReported(Context context, int type, int source, int serialNo, int msgId) {
         if (VDBG) {
-            Log.d(TAG,
-                    "logMessageReported : " + type + " " + source + " " + serialNo + " " + msgId);
+            Log.d(TAG, "logMessageReported : " + type + " " + source + " " + 0 + " " + msgId);
         }
         CellBroadcastModuleStatsLog.write(CellBroadcastModuleStatsLog.CB_MESSAGE_REPORTED, type,
-                source, serialNo, msgId);
+                source, 0, msgId);
     }
 
     /**
@@ -291,11 +290,11 @@ public class CellBroadcastServiceMetrics {
     public void logMessageFiltered(int filterType, SmsCbMessage msg) {
         int ratType = msg.getMessageFormat() == MESSAGE_FORMAT_3GPP ? FILTER_GSM : FILTER_CDMA;
         if (VDBG) {
-            Log.d(TAG, "logMessageFiltered : " + ratType + " " + filterType + " "
-                    + msg.getSerialNumber() + " " + msg.getServiceCategory());
+            Log.d(TAG, "logMessageFiltered : " + ratType + " " + filterType + " " + 0 + " "
+                    + msg.getServiceCategory());
         }
         CellBroadcastModuleStatsLog.write(CellBroadcastModuleStatsLog.CB_MESSAGE_FILTERED,
-                ratType, filterType, msg.getSerialNumber(), msg.getServiceCategory());
+                ratType, filterType, 0, msg.getServiceCategory());
     }
 
     /**
diff --git a/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java b/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java
index 5e0ab21..d945ee7 100644
--- a/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java
+++ b/src/com/android/cellbroadcastservice/GsmCellBroadcastHandler.java
@@ -791,7 +791,9 @@ public class GsmCellBroadcastHandler extends CellBroadcastHandler {
 
         @Override
         public int hashCode() {
-            return (mHeader.getSerialNumber() * 31) + mLocation.hashCode();
+            return Objects.hash(mHeader.getSerialNumber(),
+                    mHeader.getServiceCategory(),
+                    mLocation);
         }
 
         @Override
@@ -803,6 +805,7 @@ public class GsmCellBroadcastHandler extends CellBroadcastHandler {
                 // geographical scope and update number), and both pages belong to the same
                 // location (PLMN, plus LAC and CID if these are part of the geographical scope).
                 return mHeader.getSerialNumber() == other.mHeader.getSerialNumber()
+                        && mHeader.getServiceCategory() == other.mHeader.getServiceCategory()
                         && mLocation.equals(other.mLocation);
             }
 
diff --git a/tests/Android.bp b/tests/Android.bp
index 071091d..95110ea 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -17,10 +17,10 @@ android_test {
         "testables",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "unsupportedappusage",
     ],
     srcs: [
diff --git a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
index 9192f49..3037c62 100644
--- a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
+++ b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
@@ -400,42 +400,56 @@ public class CellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
         assertTrue(mCellBroadcastHandler.isDuplicate(msg4));
     }
 
+    private void verifyCBMessageForCrossSimDuplication(
+            boolean isSameSubId, boolean isSameSlot, boolean isSameSerial, boolean isSameUserdata,
+            boolean duplication) {
+
+        int subId = isSameSubId ? 1 : SubscriptionManager.DEFAULT_SUBSCRIPTION_ID;
+        int slotIndex = isSameSlot ? 0 : 1;
+        int serialnumber = isSameSerial ? 1234 : 5678;
+        String userData = isSameUserdata ? "Test Message" : "Different Message";
+
+        SmsCbMessage cbMessage = new SmsCbMessage(SmsCbMessage.MESSAGE_FORMAT_3GPP,
+                0, serialnumber, new SmsCbLocation("311480", 0, 0),
+                4370, "en", userData, 3,
+                null, null, slotIndex, subId);
+
+        assertEquals(duplication, mCellBroadcastHandler.isDuplicate(cbMessage));
+    }
+
     @Test
     @SmallTest
     public void testCrossSimDuplicateDetection() throws Exception {
-        int differentSlotID = 1;
-        int differentSubID = SubscriptionManager.DEFAULT_SUBSCRIPTION_ID;
-
         // enable cross_sim_duplicate_detection
         putResources(com.android.cellbroadcastservice.R.bool.cross_sim_duplicate_detection, true);
 
-        // The message with different subId will be detected as duplication.
-        SmsCbMessage msg1 = new SmsCbMessage(SmsCbMessage.MESSAGE_FORMAT_3GPP,
-                0, 1234, new SmsCbLocation("311480", 0, 0),
-                4370, "en", "Test Message", 3,
-                null, null, 0, differentSubID);
-        assertTrue(mCellBroadcastHandler.isDuplicate(msg1));
-
-        // The message with different body won't be detected as a duplication.
-        SmsCbMessage msg2 = new SmsCbMessage(SmsCbMessage.MESSAGE_FORMAT_3GPP,
-                0, 1234, new SmsCbLocation("311480", 0, 0),
-                4370, "en", "Different Message", 3,
-                null, null, 0, differentSubID);
-        assertFalse(mCellBroadcastHandler.isDuplicate(msg2));
-
-        // The message with different slotId will be detected as a duplication.
-        SmsCbMessage msg3 = new SmsCbMessage(SmsCbMessage.MESSAGE_FORMAT_3GPP,
-                0, 1234, new SmsCbLocation("311480", 0, 0),
-                4370, "en", "Test Message", 3,
-                null, null, differentSlotID, 1);
-        assertTrue(mCellBroadcastHandler.isDuplicate(msg3));
-
-        // The message with different slotId and body will be detected as a duplication.
-        SmsCbMessage msg4 = new SmsCbMessage(SmsCbMessage.MESSAGE_FORMAT_3GPP,
-                0, 1234, new SmsCbLocation("311480", 0, 0),
-                4370, "en", "Different Message", 3,
-                null, null, differentSlotID, 1);
-        assertTrue(mCellBroadcastHandler.isDuplicate(msg4));
+        List<List<Boolean>> combinations = List.of(
+                List.of(true, true, true, true, true),
+                List.of(true, true, true, false, true),
+                List.of(true, true, false, true, false),
+                List.of(true, true, false, false, false),
+                List.of(true, false, true, true, true),
+                List.of(true, false, true, false, true),
+                List.of(true, false, false, true, false),
+                List.of(true, false, false, false, false),
+                List.of(false, true, true, true, true),
+                List.of(false, true, true, false, true),
+                List.of(false, true, false, true, false),
+                List.of(false, true, false, false, false),
+                List.of(false, false, true, true, true),
+                List.of(false, false, true, false, false),
+                List.of(false, false, false, true, true),
+                List.of(false, false, false, false, false)
+        );
+        for (List<Boolean> combinationCase : combinations) {
+            verifyCBMessageForCrossSimDuplication(
+                    combinationCase.get(0),  // isSameSubId
+                    combinationCase.get(1),  // isSameSlot
+                    combinationCase.get(2),  // isSameSerial
+                    combinationCase.get(3),  // isSameUserdata
+                    combinationCase.get(4)   // duplication
+            );
+        }
     }
 
     @Test
diff --git a/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java b/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java
index 075cb07..ee933a7 100644
--- a/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java
+++ b/tests/src/com/android/cellbroadcastservice/tests/GsmCellBroadcastHandlerTest.java
@@ -76,7 +76,9 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
+import org.mockito.Spy;
 
+import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Random;
@@ -93,6 +95,9 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
     @Mock
     private Map<Integer, Resources> mMockedResourcesCache;
 
+    @Spy
+    private HashMap<GsmCellBroadcastHandler.SmsCbConcatInfo, byte[][]> mMockedSmsCbPageMap;
+
     @Mock
     private SubscriptionInfo mSubInfo;
 
@@ -583,6 +588,44 @@ public class GsmCellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
         verify(mMockedContext, never()).getResources();
     }
 
+    @Test
+    @SmallTest
+    public void testConcatMessage() throws Exception {
+        doReturn("111222").when(mMockedTelephonyManager).getNetworkOperator();
+        replaceInstance(GsmCellBroadcastHandler.class, "mSmsCbPageMap",
+                mGsmCellBroadcastHandler, mMockedSmsCbPageMap);
+
+        // serial_number : 0x1123, message_id : 0x1112, page1/total2
+        final byte[] pdu1 = hexStringToBytes("112311120112C8329BFD06");
+        mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu1);
+        mTestableLooper.processAllMessages();
+        assertEquals(1, mMockedSmsCbPageMap.size());
+
+        // serial_number : 0x1123, message_id : 0x1113, page1/total2
+        final byte[] pdu2 = hexStringToBytes("112311130112C7F7FBCC2E03");
+        mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu2);
+        mTestableLooper.processAllMessages();
+        assertEquals(2, mMockedSmsCbPageMap.size());
+
+        // serial_number : 0x1123, message_id : 0x1112, page2/total2
+        final byte[] pdu3 = hexStringToBytes("112311130122C7F7FBCC2E03");
+        mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu3);
+        mTestableLooper.processAllMessages();
+        assertEquals(1, mMockedSmsCbPageMap.size());
+
+        mGsmCellBroadcastHandler.sendMessage(/*WakeLockStateMachine.EVENT_BROADCAST_COMPLETE*/ 2);
+        mTestableLooper.processAllMessages();
+
+        // serial_number : 0x1123, message_id : 0x1113, page2/total2
+        final byte[] pdu4 = hexStringToBytes("112311120122C8329BFD06");
+        mGsmCellBroadcastHandler.onGsmCellBroadcastSms(0, pdu4);
+        mTestableLooper.processAllMessages();
+        assertEquals(0, mMockedSmsCbPageMap.size());
+
+        mGsmCellBroadcastHandler.sendMessage(/*WakeLockStateMachine.EVENT_BROADCAST_COMPLETE*/ 2);
+        mTestableLooper.processAllMessages();
+    }
+
     @Test
     @SmallTest
     public void testConstructorRegistersReceiverWithExpectedFlag() {
```

