**build/make**
```diff
diff --git a/core/build_id.mk b/core/build_id.mk
index c0750ae7a6..c68fc2387f 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.

-BUILD_ID=AP3A.241005.015
+BUILD_ID=AP3A.241005.015.A2
```

**frameworks/opt/telephony**

```diff
diff --git a/src/java/com/android/internal/telephony/uicc/euicc/EuiccPort.java b/src/java/com/android/internal/telephony/uicc/euicc/EuiccPort.java
index 7bdec47336..3bd66f8d87 100644
--- a/src/java/com/android/internal/telephony/uicc/euicc/EuiccPort.java
+++ b/src/java/com/android/internal/telephony/uicc/euicc/EuiccPort.java
@@ -133,8 +133,7 @@ public class EuiccPort extends UiccPort {
             UiccCard card, MultipleEnabledProfilesMode supportedMepMode) {
         super(c, ci, ics, phoneId, lock, card);
         // TODO: Set supportExtendedApdu based on ATR.
-        mApduSender = new ApduSender(c, phoneId, ci, ISD_R_AID,
-                              false /* supportExtendedApdu */);
+        mApduSender = new ApduSender(ci, ISD_R_AID, false /* supportExtendedApdu */);
         if (TextUtils.isEmpty(ics.eid)) {
             loge("no eid given in constructor for phone " + phoneId);
         } else {
diff --git a/src/java/com/android/internal/telephony/uicc/euicc/apdu/ApduSender.java b/src/java/com/android/internal/telephony/uicc/euicc/apdu/ApduSender.java
index f42d5a2dda..8e7237e182 100644
--- a/src/java/com/android/internal/telephony/uicc/euicc/apdu/ApduSender.java
+++ b/src/java/com/android/internal/telephony/uicc/euicc/apdu/ApduSender.java
@@ -17,13 +17,9 @@
 package com.android.internal.telephony.uicc.euicc.apdu;

 import android.annotation.Nullable;
-import android.content.Context;
-import android.content.SharedPreferences;
 import android.os.Handler;
 import android.os.Looper;
-import android.preference.PreferenceManager;
 import android.telephony.IccOpenLogicalChannelResponse;
-import android.util.Base64;

 import com.android.internal.telephony.CommandsInterface;
 import com.android.internal.telephony.uicc.IccIoResult;
@@ -34,7 +30,6 @@ import com.android.telephony.Rlog;
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.util.List;
-import java.util.NoSuchElementException;

 /**
  * This class sends a list of APDU commands to an AID on a UICC. A logical channel will be opened
@@ -57,9 +52,6 @@ public class ApduSender {
     private static final int SW1_NO_ERROR = 0x91;

     private static final int WAIT_TIME_MS = 2000;
-    private static final String CHANNEL_ID_PRE = "esim-channel";
-    private static final String ISD_R_AID = "A0000005591010FFFFFFFF8900000100";
-    private static final String CHANNEL_RESPONSE_ID_PRE = "esim-res-id";

     private static void logv(String msg) {
         Rlog.v(LOG_TAG, msg);
@@ -74,9 +66,6 @@ public class ApduSender {
     private final OpenLogicalChannelInvocation mOpenChannel;
     private final CloseLogicalChannelInvocation mCloseChannel;
     private final TransmitApduLogicalChannelInvocation mTransmitApdu;
-    private final Context mContext;
-    private final String mChannelKey;
-    private final String mChannelResponseKey;

     // Lock for accessing mChannelOpened. We only allow to open a single logical channel at any
     // time for an AID.
@@ -86,17 +75,12 @@ public class ApduSender {
     /**
      * @param aid The AID that will be used to open a logical channel to.
      */
-    public ApduSender(Context context, int phoneId, CommandsInterface ci, String aid,
-            boolean supportExtendedApdu) {
+    public ApduSender(CommandsInterface ci, String aid, boolean supportExtendedApdu) {
         mAid = aid;
-        mContext = context;
         mSupportExtendedApdu = supportExtendedApdu;
         mOpenChannel = new OpenLogicalChannelInvocation(ci);
         mCloseChannel = new CloseLogicalChannelInvocation(ci);
         mTransmitApdu = new TransmitApduLogicalChannelInvocation(ci);
-        mChannelKey = CHANNEL_ID_PRE + "_" + phoneId;
-        mChannelResponseKey = CHANNEL_RESPONSE_ID_PRE + "_" + phoneId;
-        closeExistingChannelIfExists();
     }

     /**
@@ -145,20 +129,6 @@ public class ApduSender {
             public void onResult(IccOpenLogicalChannelResponse openChannelResponse) {
                 int channel = openChannelResponse.getChannel();
                 int status = openChannelResponse.getStatus();
-                byte[] selectResponse = openChannelResponse.getSelectResponse();
-                if (mAid.equals(ISD_R_AID)
-                      && status == IccOpenLogicalChannelResponse.STATUS_NO_SUCH_ELEMENT) {
-                    channel = PreferenceManager.getDefaultSharedPreferences(mContext)
-                                .getInt(mChannelKey, IccOpenLogicalChannelResponse.INVALID_CHANNEL);
-                    if (channel != IccOpenLogicalChannelResponse.INVALID_CHANNEL) {
-                        logv("Try to use already opened channel: " + channel);
-                        status = IccOpenLogicalChannelResponse.STATUS_NO_ERROR;
-                        String storedResponse = PreferenceManager
-                                .getDefaultSharedPreferences(mContext)
-                                      .getString(mChannelResponseKey, "");
-                        selectResponse = Base64.decode(storedResponse, Base64.DEFAULT);
-                    }
-                }
                 if (channel == IccOpenLogicalChannelResponse.INVALID_CHANNEL
                         || status != IccOpenLogicalChannelResponse.STATUS_NO_ERROR) {
                     synchronized (mChannelLock) {
@@ -173,15 +143,8 @@ public class ApduSender {

                 RequestBuilder builder = new RequestBuilder(channel, mSupportExtendedApdu);
                 Throwable requestException = null;
-                if (mAid.equals(ISD_R_AID)) {
-                   PreferenceManager.getDefaultSharedPreferences(mContext)
-                         .edit().putInt(mChannelKey, channel).apply();
-                   PreferenceManager.getDefaultSharedPreferences(mContext)
-                        .edit().putString(mChannelResponseKey,
-                           Base64.encodeToString(selectResponse, Base64.DEFAULT)).apply();
-                }
                 try {
-                    requestProvider.buildRequest(selectResponse, builder);
+                    requestProvider.buildRequest(openChannelResponse.getSelectResponse(), builder);
                 } catch (Throwable e) {
                     requestException = e;
                 }
@@ -260,7 +223,7 @@ public class ApduSender {
             AsyncResultCallback<IccIoResult> resultCallback,
             Handler handler) {
         ByteArrayOutputStream resultBuilder =
-            responseBuilder == null ? new ByteArrayOutputStream() : responseBuilder;
+                responseBuilder == null ? new ByteArrayOutputStream() : responseBuilder;
         if (lastResponse.payload != null) {
             try {
                 resultBuilder.write(lastResponse.payload);
@@ -304,12 +267,6 @@ public class ApduSender {
             @Override
             public void onResult(Boolean aBoolean) {
                 synchronized (mChannelLock) {
-                    if (mAid.equals(ISD_R_AID)) {
-                      PreferenceManager.getDefaultSharedPreferences(mContext)
-                             .edit().remove(mChannelKey).apply();
-                      PreferenceManager.getDefaultSharedPreferences(mContext)
-                             .edit().remove(mChannelResponseKey).apply();
-                    }
                     mChannelOpened = false;
                     mChannelLock.notify();
                 }
@@ -322,39 +279,4 @@ public class ApduSender {
             }
         }, handler);
     }
-
-    /**
-     * Cleanup the existing opened channel which was remainined opened earlier due
-     * to failure or crash.
-     */
-    private void closeExistingChannelIfExists() {
-        if (mCloseChannel != null) {
-            int channelId = PreferenceManager.getDefaultSharedPreferences(mContext)
-                .getInt(mChannelKey, IccOpenLogicalChannelResponse.INVALID_CHANNEL);
-            if (channelId != IccOpenLogicalChannelResponse.INVALID_CHANNEL) {
-                logv("Trying to clean up the opened channel : " +  channelId);
-                synchronized (mChannelLock) {
-                    mChannelOpened = true;
-                    mChannelLock.notify();
-                }
-                mCloseChannel.invoke(channelId, new AsyncResultCallback<Boolean>() {
-                    @Override
-                    public void onResult(Boolean isSuccess) {
-                        if (isSuccess) {
-                          logv("Channel closed successfully: " +  channelId);
-                          PreferenceManager.getDefaultSharedPreferences(mContext)
-                                 .edit().remove(mChannelResponseKey).apply();
-                          PreferenceManager.getDefaultSharedPreferences(mContext)
-                                 .edit().remove(mChannelKey).apply();
-                       }
-
-                       synchronized (mChannelLock) {
-                           mChannelOpened = false;
-                           mChannelLock.notify();
-                      }
-                    }
-                }, new Handler());
-            }
-        }
-    }
 }
diff --git a/tests/telephonytests/src/com/android/internal/telephony/uicc/euicc/apdu/ApduSenderTest.java b/tests/telephonytests/src/com/android/internal/telephony/uicc/euicc/apdu/ApduSenderTest.java
index cf3f900c27..b073c6af48 100644
--- a/tests/telephonytests/src/com/android/internal/telephony/uicc/euicc/apdu/ApduSenderTest.java
+++ b/tests/telephonytests/src/com/android/internal/telephony/uicc/euicc/apdu/ApduSenderTest.java
@@ -37,7 +37,6 @@ import com.android.internal.telephony.CommandException;
 import com.android.internal.telephony.CommandsInterface;
 import com.android.internal.telephony.uicc.IccIoResult;
 import com.android.internal.telephony.uicc.IccUtils;
-import androidx.test.InstrumentationRegistry;

 import org.junit.After;
 import org.junit.Before;
@@ -94,8 +93,7 @@ public class ApduSenderTest {
         mResponseCaptor = new ResponseCaptor();
         mSelectResponse = null;

-        mSender = new ApduSender(InstrumentationRegistry.getContext(), 0 /* phoneId= */,
-                            mMockCi, AID, false /* supportExtendedApdu */);
+        mSender = new ApduSender(mMockCi, AID, false /* supportExtendedApdu */);
         mLooper = TestableLooper.get(this);
     }
```

**manifest**
```diff
diff --git a/default.xml b/default.xml
index 478294b8c..de3b2080f 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r2"
+  <default revision="refs/tags/android-15.0.0_r3"
            remote="aosp"
            sync-j="4" />

-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r2"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r3"/>
   <contactinfo bugurl="go/repo-bug" />

   <!-- BEGIN open-source projects -->
