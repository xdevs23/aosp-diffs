```diff
diff --git a/src/com/android/mms/service/MmsRequest.java b/src/com/android/mms/service/MmsRequest.java
index 9ddce57..40dde58 100644
--- a/src/com/android/mms/service/MmsRequest.java
+++ b/src/com/android/mms/service/MmsRequest.java
@@ -84,9 +84,11 @@ public abstract class MmsRequest {
          * Read pdu (up to maxSize bytes) from supplied content uri
          * @param contentUri content uri from which to read
          * @param maxSize maximum number of bytes to read
+         * @param callingUser user id of the calling app
          * @return read pdu (else null in case of error or too big)
          */
-        public byte[] readPduFromContentUri(final Uri contentUri, final int maxSize);
+        public byte[] readPduFromContentUri(final Uri contentUri, final int maxSize,
+                int callingUser);
 
         /**
          * Write pdu to supplied content uri
diff --git a/src/com/android/mms/service/MmsService.java b/src/com/android/mms/service/MmsService.java
index 6213513..6897e40 100644
--- a/src/com/android/mms/service/MmsService.java
+++ b/src/com/android/mms/service/MmsService.java
@@ -214,9 +214,9 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
 
     private IMms.Stub mStub = new IMms.Stub() {
         @Override
-        public void sendMessage(int subId, String callingPkg, Uri contentUri,
-                String locationUrl, Bundle configOverrides, PendingIntent sentIntent,
-                long messageId, String attributionTag) {
+        public void sendMessage(int subId, int callingUser, String callingPkg,
+                Uri contentUri, String locationUrl, Bundle configOverrides,
+                PendingIntent sentIntent, long messageId, String attributionTag) {
             LogUtil.d("sendMessage " + formatCrossStackMessageId(messageId));
             enforceSystemUid();
 
@@ -264,8 +264,8 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
             }
 
             final SendRequest request = new SendRequest(MmsService.this, subId, contentUri,
-                    locationUrl, sentIntent, callingPkg, mmsConfig, MmsService.this,
-                    messageId, mmsStats, getTelephonyManager(subId));
+                    locationUrl, sentIntent, callingUser, callingPkg, mmsConfig,
+                    MmsService.this, messageId, mmsStats, getTelephonyManager(subId));
 
             final String carrierMessagingServicePackage =
                     getCarrierMessagingServicePackageIfExists(subId);
@@ -286,7 +286,7 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
                 // ENABLE_MMS_DATA_REQUEST_REASON_OUTGOING_MMS is set for only SendReq case, since
                 // AcknowledgeInd and NotifyRespInd are parts of downloading sequence.
                 // TODO: Should consider ReadRecInd(Read Report)?
-                sendSettingsIntentForFailedMms(!isRawPduSendReq(contentUri), subId);
+                sendSettingsIntentForFailedMms(!isRawPduSendReq(contentUri, callingUser), subId);
 
                 int resultCode = Flags.mmsDisabledError() ? SmsManager.MMS_ERROR_DATA_DISABLED
                         : SmsManager.MMS_ERROR_NO_DATA_NETWORK;
@@ -298,9 +298,9 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
         }
 
         @Override
-        public void downloadMessage(int subId, String callingPkg, String locationUrl,
-                Uri contentUri, Bundle configOverrides, PendingIntent downloadedIntent,
-                long messageId, String attributionTag) {
+        public void downloadMessage(int subId, int callingUser, String callingPkg,
+                String locationUrl, Uri contentUri, Bundle configOverrides,
+                PendingIntent downloadedIntent, long messageId, String attributionTag) {
             // If the subId is no longer active it could be caused by an MVNO using multiple
             // subIds, so we should try to download anyway.
             // TODO: Fail fast when downloading will fail (i.e. SIM swapped)
@@ -441,11 +441,12 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
         }
 
         @Override
-        public Uri importMultimediaMessage(String callingPkg, Uri contentUri,
-                String messageId, long timestampSecs, boolean seen, boolean read) {
+        public Uri importMultimediaMessage(int callingUser, String callingPkg,
+                Uri contentUri, String messageId, long timestampSecs, boolean seen, boolean read) {
             LogUtil.d("importMultimediaMessage");
             enforceSystemUid();
-            return importMms(contentUri, messageId, timestampSecs, seen, read, callingPkg);
+            return importMms(contentUri, messageId, timestampSecs, seen,
+                read, callingUser, callingPkg);
         }
 
         @Override
@@ -535,11 +536,11 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
         }
 
         @Override
-        public Uri addMultimediaMessageDraft(String callingPkg, Uri contentUri)
-                throws RemoteException {
+        public Uri addMultimediaMessageDraft(int callingUser,
+                String callingPkg, Uri contentUri) throws RemoteException {
             LogUtil.d("addMultimediaMessageDraft");
             enforceSystemUid();
-            return addMmsDraft(contentUri, callingPkg);
+            return addMmsDraft(contentUri, callingUser, callingPkg);
         }
 
         @Override
@@ -588,12 +589,12 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
             }
         }
 
-        private boolean isRawPduSendReq(Uri contentUri) {
+        private boolean isRawPduSendReq(Uri contentUri, int callingUser) {
             // X-Mms-Message-Type is at the beginning of the message headers always. 1st byte is
             // MMS-filed-name and 2nd byte is MMS-value for X-Mms-Message-Type field.
             // See OMA-TS-MMS_ENC-V1_3-20110913-A, 7. Binary Encoding of ProtocolData Units
             byte[] pduData = new byte[2];
-            int bytesRead = readPduBytesFromContentUri(contentUri, pduData);
+            int bytesRead = readPduBytesFromContentUri(contentUri, pduData, callingUser);
 
             // Return true for MESSAGE_TYPE_SEND_REQ only. Otherwise false even wrong PDU case.
             if (bytesRead == 2
@@ -805,8 +806,8 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
     }
 
     private Uri importMms(Uri contentUri, String messageId, long timestampSecs,
-            boolean seen, boolean read, String creator) {
-        byte[] pduData = readPduFromContentUri(contentUri, MAX_MMS_FILE_SIZE);
+            boolean seen, boolean read, int callingUser, String creator) {
+        byte[] pduData = readPduFromContentUri(contentUri, MAX_MMS_FILE_SIZE, callingUser);
         if (pduData == null || pduData.length < 1) {
             LogUtil.e("importMessage: empty PDU");
             return null;
@@ -979,8 +980,8 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
         return null;
     }
 
-    private Uri addMmsDraft(Uri contentUri, String creator) {
-        byte[] pduData = readPduFromContentUri(contentUri, MAX_MMS_FILE_SIZE);
+    private Uri addMmsDraft(Uri contentUri, int callingUser, String creator) {
+        byte[] pduData = readPduFromContentUri(contentUri, MAX_MMS_FILE_SIZE, callingUser);
         if (pduData == null || pduData.length < 1) {
             LogUtil.e("addMmsDraft: empty PDU");
             return null;
@@ -1070,10 +1071,11 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
      * @param maxSize    maximum number of bytes to read.
      * @return pdu bytes if succeeded else null.
      */
-    public byte[] readPduFromContentUri(final Uri contentUri, final int maxSize) {
+    public byte[] readPduFromContentUri(final Uri contentUri, final int maxSize,
+            int callingUser) {
         // Request one extra byte to make sure file not bigger than maxSize
         byte[] pduData = new byte[maxSize + 1];
-        int bytesRead = readPduBytesFromContentUri(contentUri, pduData);
+        int bytesRead = readPduBytesFromContentUri(contentUri, pduData, callingUser);
         if (bytesRead <= 0) {
             return null;
         }
@@ -1091,14 +1093,16 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
      * @param pduData    the buffer into which the data is read.
      * @return the total number of bytes read into the pduData.
      */
-    public int readPduBytesFromContentUri(final Uri contentUri, byte[] pduData) {
+    public int readPduBytesFromContentUri(final Uri contentUri, byte[] pduData,
+            int callingUser) {
         if (contentUri == null) {
             LogUtil.e("Uri is null");
             return 0;
         }
         int contentUriUserID = ContentProvider.getUserIdFromUri(contentUri, UserHandle.myUserId());
-        if (UserHandle.myUserId() != contentUriUserID) {
-            LogUtil.e("Uri is invalid");
+        if (callingUser != contentUriUserID) {
+            LogUtil.e("Uri belongs to a different user. contentUriUserId is: " + contentUriUserID
+                    + "and calling User ID is:" + callingUser);
             return 0;
         }
         Callable<Integer> copyPduToArray = new Callable<Integer>() {
diff --git a/src/com/android/mms/service/SendRequest.java b/src/com/android/mms/service/SendRequest.java
index 98af787..19ddeb8 100644
--- a/src/com/android/mms/service/SendRequest.java
+++ b/src/com/android/mms/service/SendRequest.java
@@ -61,16 +61,19 @@ public class SendRequest extends MmsRequest {
     public byte[] mPduData;
     private final String mLocationUrl;
     private final PendingIntent mSentIntent;
+    private final int mCallingUser;
 
     public SendRequest(RequestManager manager, int subId, Uri contentUri, String locationUrl,
-            PendingIntent sentIntent, String creator, Bundle configOverrides, Context context,
-            long messageId, MmsStats mmsStats, TelephonyManager telephonyManager) {
+            PendingIntent sentIntent, int callingUser, String creator,
+            Bundle configOverrides, Context context, long messageId, MmsStats mmsStats,
+            TelephonyManager telephonyManager) {
         super(manager, subId, creator, configOverrides, context, messageId, mmsStats,
                 telephonyManager);
         mPduUri = contentUri;
         mPduData = null;
         mLocationUrl = locationUrl;
         mSentIntent = sentIntent;
+        mCallingUser = callingUser;
     }
 
     @Override
@@ -368,7 +371,7 @@ public class SendRequest extends MmsRequest {
             return true;
         }
         final int bytesTobeRead = mMmsConfig.getInt(SmsManager.MMS_CONFIG_MAX_MESSAGE_SIZE);
-        mPduData = mRequestManager.readPduFromContentUri(mPduUri, bytesTobeRead);
+        mPduData = mRequestManager.readPduFromContentUri(mPduUri, bytesTobeRead, mCallingUser);
         return (mPduData != null);
     }
 
diff --git a/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java b/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java
index af33435..4430f42 100644
--- a/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java
+++ b/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java
@@ -63,6 +63,7 @@ public class MmsRequestRoboTest {
     private SmsManager mSmsManager;
     private Bundle mCarrierConfigValues;
     private static final int sMaxPduSize = 3 * 1000;
+    private static final int CALLING_USER = 10;
 
     @Before
     public void setUp() {
@@ -98,8 +99,8 @@ public class MmsRequestRoboTest {
     @Test
     public void sendRequest_noSatellite_sendSuccessful() {
         SendRequest request = new SendRequest(mMmsService, mSubId, Uri.parse(sFakeUri),
-                sFakeLocationUri, /* sentIntent= */ null, /* callingPkg= */ null,
-                mCarrierConfigValues, /* context= */ mMmsService,
+                sFakeLocationUri, /* sentIntent= */ null, /* callingUser= */ CALLING_USER,
+                /* callingPkg= */ null, mCarrierConfigValues, /* context= */ mMmsService,
                 sFakeMessageId, mMmsStats, mTelephonyManager);
         request.mPduData = new byte[sMaxPduSize + 100];
 
@@ -117,8 +118,8 @@ public class MmsRequestRoboTest {
         ss.addNetworkRegistrationInfo(nri);
         doReturn(ss).when(mTelephonyManager).getServiceState();
         SendRequest request = new SendRequest(mMmsService, mSubId, Uri.parse(sFakeUri),
-                sFakeLocationUri, /* sentIntent= */ null, /* callingPkg= */ null,
-                mCarrierConfigValues, /* context= */ mMmsService,
+                sFakeLocationUri, /* sentIntent= */ null, /* callingUser= */ CALLING_USER,
+                /* callingPkg= */ null, mCarrierConfigValues, /* context= */ mMmsService,
                 sFakeMessageId, mMmsStats, mTelephonyManager);
         request.mPduData = new byte[sMaxPduSize - 1];
 
@@ -136,8 +137,8 @@ public class MmsRequestRoboTest {
         ss.addNetworkRegistrationInfo(nri);
         doReturn(ss).when(mTelephonyManager).getServiceState();
         SendRequest request = new SendRequest(mMmsService, mSubId, Uri.parse(sFakeUri),
-                sFakeLocationUri, /* sentIntent= */ null, /* callingPkg= */ null,
-                mCarrierConfigValues, /* context= */ mMmsService,
+                sFakeLocationUri, /* sentIntent= */ null, /* callingUser= */ CALLING_USER,
+                /* callingPkg= */ null, mCarrierConfigValues, /* context= */ mMmsService,
                 sFakeMessageId, mMmsStats, mTelephonyManager);
         request.mPduData = new byte[sMaxPduSize + 1];
 
diff --git a/tests/robotests/src/com/android/mms/service/MmsServiceRoboTest.java b/tests/robotests/src/com/android/mms/service/MmsServiceRoboTest.java
index b59e92e..efd4b35 100644
--- a/tests/robotests/src/com/android/mms/service/MmsServiceRoboTest.java
+++ b/tests/robotests/src/com/android/mms/service/MmsServiceRoboTest.java
@@ -37,6 +37,7 @@ import org.robolectric.shadows.ShadowBinder;
 @RunWith(RobolectricTestRunner.class)
 public final class MmsServiceRoboTest {
     private IMms.Stub binder;
+    private static final int CALLING_USER = 10;
 
     @Before
     public void setUp() {
@@ -55,7 +56,8 @@ public final class MmsServiceRoboTest {
     @Test
     public void testSendMessage_DoesNotThrowIfSystemUid() throws RemoteException {
         ShadowBinder.setCallingUid(Process.SYSTEM_UID);
-        binder.sendMessage(/* subId= */ 0, "callingPkg", Uri.parse("contentUri"),
+        binder.sendMessage(/* subId= */ 0, /* callingUser= */ CALLING_USER,
+                "callingPkg", Uri.parse("contentUri"),
                 "locationUrl", /* configOverrides= */ null, /* sentIntent= */ null,
                 /* messageId= */ 0L, /* attributionTag= */ null);
     }
@@ -63,7 +65,8 @@ public final class MmsServiceRoboTest {
     @Test
     public void testSendMessageThrows_IfNotSystemUid() {
         assertThrows(SecurityException.class,
-                () -> binder.sendMessage(/* subId= */ 0, "callingPkg", Uri.parse("contentUri"),
+                () -> binder.sendMessage(/* subId= */ 0, /* callingUser= */ CALLING_USER,
+                        "callingPkg", Uri.parse("contentUri"),
                         "locationUrl", /* configOverrides= */ null, /* sentIntent= */ null,
                         /* messageId= */ 0L, /* attributionTag= */ null));
     }
diff --git a/tests/unittests/Android.bp b/tests/unittests/Android.bp
index add4f69..c327318 100644
--- a/tests/unittests/Android.bp
+++ b/tests/unittests/Android.bp
@@ -16,9 +16,9 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "telephony-common",
     ],
     srcs: [
```

