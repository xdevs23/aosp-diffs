```diff
diff --git a/Android.bp b/Android.bp
index ef3c148..65e7c25 100644
--- a/Android.bp
+++ b/Android.bp
@@ -8,6 +8,10 @@ android_app {
     // Only compile source java files in this apk.
     srcs: ["src/**/*.java"],
 
+    static_libs: [
+        "calllogbackup_flags_java_lib",
+    ],
+
     // The Jacoco tool analyzes code coverage when running unit tests on the
     // application. This configuration line selects which packages will be analyzed,
     // leaving out code which is tested by other means (e.g. static libraries) that
@@ -24,3 +28,15 @@ android_app {
     },
 
 }
+
+java_aconfig_library {
+    name: "calllogbackup_flags_java_lib",
+    aconfig_declarations: "calllogbackup_flags",
+}
+
+aconfig_declarations {
+    name: "calllogbackup_flags",
+    container: "system",
+    package: "com.android.calllogbackup",
+    srcs: ["**/calllogbackup_flags.aconfig"],
+}
diff --git a/calllogbackup_flags.aconfig b/calllogbackup_flags.aconfig
new file mode 100644
index 0000000..1545749
--- /dev/null
+++ b/calllogbackup_flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.calllogbackup"
+container: "system"
+
+flag {
+    name: "call_log_restore_deduplication_enabled"
+    namespace: "telecom"
+    description: "Enables deduplication of call log entries during restore operations to prevent duplicate entries."
+    bug: "374931480"
+}
\ No newline at end of file
diff --git a/src/com/android/calllogbackup/CallLogBackupAgent.java b/src/com/android/calllogbackup/CallLogBackupAgent.java
index 1f5d1f7..acc29a4 100644
--- a/src/com/android/calllogbackup/CallLogBackupAgent.java
+++ b/src/com/android/calllogbackup/CallLogBackupAgent.java
@@ -17,6 +17,7 @@
 package com.android.calllogbackup;
 
 import static android.provider.CallLog.Calls.MISSED_REASON_NOT_MISSED;
+import static com.android.calllogbackup.Flags.callLogRestoreDeduplicationEnabled;
 
 import android.app.backup.BackupAgent;
 import android.app.backup.BackupDataInput;
@@ -144,6 +145,10 @@ public class CallLogBackupAgent extends BackupAgent {
     static final String TELEPHONY_PHONE_ACCOUNT_HANDLE_COMPONENT_NAME =
             "com.android.phone/com.android.services.telephony.TelephonyConnectionService";
 
+    @VisibleForTesting
+    static final String SELECTION_CALL_DATE_AND_NUMBER =
+            CallLog.Calls.DATE + " = ? AND " + CallLog.Calls.NUMBER + " = ?";
+
     @VisibleForTesting
     protected Map<Integer, String> mSubscriptionInfoMap;
 
@@ -285,10 +290,12 @@ public class CallLogBackupAgent extends BackupAgent {
         while (data.readNextHeader()) {
             Call call = readCallFromData(data);
             if (call != null && call.type != Calls.VOICEMAIL_TYPE) {
-                writeCallToProvider(call);
-                mBackupRestoreEventLoggerProxy.logItemsRestored(CALLLOGS, /* count */ 1);
-                if (isDebug()) {
-                    Log.d(TAG, "Restored call: " + call);
+                if (!callLogRestoreDeduplicationEnabled() || !isDuplicateCall(call)) {
+                    writeCallToProvider(call);
+                    mBackupRestoreEventLoggerProxy.logItemsRestored(CALLLOGS, /* count */ 1);
+                    if (isDebug()) {
+                        Log.d(TAG, "Restored call: " + call);
+                    }
                 }
             }
         }
@@ -356,7 +363,22 @@ public class CallLogBackupAgent extends BackupAgent {
         return calls;
     }
 
-    private void writeCallToProvider(Call call) {
+    private boolean isDuplicateCall(Call call) {
+        // Build the query selection
+        String[] selectionArgs = new String[]{String.valueOf(call.date), call.number};
+
+        // Query the call log provider. We only need to check for the existence of a call with
+        // the same date and number, so we only select the _ID column.
+        try (Cursor cursor = getContentResolver().query(CallLog.Calls.CONTENT_URI,
+                new String[]{CallLog.Calls._ID}, SELECTION_CALL_DATE_AND_NUMBER,
+                selectionArgs, /* sortOrder */ null)) {
+
+            return cursor != null && cursor.moveToFirst();
+        }
+    }
+
+    @VisibleForTesting
+    void writeCallToProvider(Call call) {
         Long dataUsage = call.dataUsage == 0 ? null : call.dataUsage;
 
         PhoneAccountHandle handle = null;
diff --git a/tests/Android.bp b/tests/Android.bp
index 2cc5d06..8f6727f 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -20,7 +20,10 @@ android_test {
     },
 
     static_libs: [
-        "mockito-target",
         "androidx.test.rules",
+        "flag-junit",
+        "mockito-target",
+        "platform-test-annotations",
+        "calllogbackup_flags_java_lib",
     ],
 }
diff --git a/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java b/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java
index 4be4420..a3fd92b 100644
--- a/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java
+++ b/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java
@@ -16,6 +16,9 @@
 
 package com.android.calllogbackup;
 
+import static com.android.calllogbackup.CallLogBackupAgent.SELECTION_CALL_DATE_AND_NUMBER;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.eq;
@@ -24,24 +27,32 @@ import static org.mockito.Mockito.when;
 
 import android.app.backup.BackupDataInput;
 import android.app.backup.BackupDataOutput;
+import android.content.ContentResolver;
+import android.content.ContentValues;
 import android.content.Context;
 import android.database.Cursor;
+import com.google.common.collect.ImmutableList;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.provider.CallLog;
-import android.test.AndroidTestCase;
 
 import androidx.test.InstrumentationRegistry;
 import androidx.test.filters.SmallTest;
 
 import com.android.calllogbackup.CallLogBackupAgent.Call;
 import com.android.calllogbackup.CallLogBackupAgent.CallLogBackupState;
+import com.android.calllogbackup.Flags;
 
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.Rule;
 import org.mockito.InOrder;
-import org.mockito.Matchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
-import org.mockito.invocation.InvocationOnMock;
-import org.mockito.stubbing.Answer;
 
 import java.io.ByteArrayOutputStream;
 import java.io.DataInput;
@@ -53,13 +64,14 @@ import java.util.HashMap;
 import java.util.LinkedList;
 import java.util.List;
 import java.util.Map;
+import java.util.Objects;
 import java.util.TreeSet;
 
 /**
  * Test cases for {@link com.android.providers.contacts.CallLogBackupAgent}
  */
 @SmallTest
-public class CallLogBackupAgentTest extends AndroidTestCase {
+public class CallLogBackupAgentTest {
     static final String TELEPHONY_COMPONENT
             = "com.android.phone/com.android.services.telephony.TelephonyConnectionService";
     static final String TEST_PHONE_ACCOUNT_HANDLE_SUB_ID = "666";
@@ -74,7 +86,9 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
     @Mock BackupDataOutput mBackupDataOutput;
     @Mock Cursor mCursor;
 
-    private CallLogBackupAgent.BackupRestoreEventLoggerProxy mBackupRestoreEventLoggerProxy =
+    private Context mContext;
+
+    private final CallLogBackupAgent.BackupRestoreEventLoggerProxy mBackupRestoreEventLoggerProxy =
             new CallLogBackupAgent.BackupRestoreEventLoggerProxy() {
         @Override
         public void logItemsBackedUp(String dataType, int count) {
@@ -101,30 +115,32 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
 
     MockitoHelper mMockitoHelper = new MockitoHelper();
 
-    @Override
-    public void setUp() throws Exception {
-        super.setUp();
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
 
+
+    @Before
+    public void setUp() throws Exception {
         mMockitoHelper.setUp(getClass());
+
+        mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
+
         // Since we're testing a system app, AppDataDirGuesser doesn't find our
         // cache dir, so set it explicitly.
-        System.setProperty("dexmaker.dexcache", getContext().getCacheDir().toString());
-        MockitoAnnotations.initMocks(this);
+        System.setProperty("dexmaker.dexcache", mContext.getCacheDir().toString());
 
+        MockitoAnnotations.initMocks(this);
         mCallLogBackupAgent = new CallLogBackupAgent();
         mCallLogBackupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
     }
 
-    @Override
+    @After
     public void tearDown() throws Exception {
         mMockitoHelper.tearDown();
     }
 
-    @Override
-    public Context getTestContext() {
-        return InstrumentationRegistry.getContext();
-    }
-
+    @Test
     public void testReadState_NoCall() throws Exception {
         when(mDataInput.readInt()).thenThrow(new EOFException());
 
@@ -134,6 +150,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(state.callIds.size(), 0);
     }
 
+    @Test
     public void testReadState_OneCall() throws Exception {
         when(mDataInput.readInt()).thenReturn(
                 1 /* version */,
@@ -151,6 +168,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
      * Verifies that attempting to restore from a version newer than what the backup agent defines
      * will result in no restored rows.
      */
+    @Test
     public void testRestoreFromHigherVersion() throws Exception {
         // The backup format is not well structured, and consists of a bunch of persisted bytes, so
         // making the mock data is a bit gross.
@@ -162,13 +180,10 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         byte[] data = byteArrayOutputStream.toByteArray();
         when(backupDataInput.getDataSize()).thenReturn(data.length);
         when(backupDataInput.readEntityData(any(), anyInt(), anyInt())).thenAnswer(
-                new Answer<Object>() {
-                    @Override
-                    public Object answer(InvocationOnMock invocation) throws Throwable {
-                        byte[] bytes = invocation.getArgument(0);
-                        System.arraycopy(data, 0, bytes, 0, data.length);
-                        return null;
-                    }
+                invocation -> {
+                    byte[] bytes = invocation.getArgument(0);
+                    System.arraycopy(data, 0, bytes, 0, data.length);
+                    return null;
                 }
         );
 
@@ -177,12 +192,9 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         // number of items to restore.
         final int[] executionLimit = {1};
         when(backupDataInput.readNextHeader()).thenAnswer(
-                new Answer<Object>() {
-                    @Override
-                    public Object answer(InvocationOnMock invocation) throws Throwable {
-                        executionLimit[0]--;
-                        return executionLimit[0] >= 0;
-                    }
+                invocation -> {
+                    executionLimit[0]--;
+                    return executionLimit[0] >= 0;
                 }
         );
 
@@ -192,6 +204,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(0, backupRestoreLoggerSuccessCount);
     }
 
+    @Test
     public void testReadState_MultipleCalls() throws Exception {
         when(mDataInput.readInt()).thenReturn(
                 1 /* version */,
@@ -207,6 +220,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertTrue(state.callIds.contains(102));
     }
 
+    @Test
     public void testWriteState_NoCalls() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
@@ -219,6 +233,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         inOrder.verify(mDataOutput).writeInt(0 /* size */);
     }
 
+    @Test
     public void testWriteState_OneCall() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
@@ -233,6 +248,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         inOrder.verify(mDataOutput).writeInt(101 /* call-ID */);
     }
 
+    @Test
     public void testWriteState_MultipleCalls() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
@@ -251,7 +267,8 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         inOrder.verify(mDataOutput).writeInt(103 /* call-ID */);
     }
 
-    public void testRunBackup_NoCalls() throws Exception {
+    @Test
+    public void testRunBackup_NoCalls() {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
         state.callIds = new TreeSet<>();
@@ -266,6 +283,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         Mockito.verifyNoMoreInteractions(mBackupDataOutput);
     }
 
+    @Test
     public void testRunBackup_OneNewCall_ErrorAddingCall() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
@@ -283,7 +301,8 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(backupRestoreLoggerFailCount, 1);
     }
 
-    public void testRunBackup_OneNewCall_NullBackupDataOutput() throws Exception {
+    @Test
+    public void testRunBackup_OneNewCall_NullBackupDataOutput() {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
         state.callIds = new TreeSet<>();
@@ -298,6 +317,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(backupRestoreLoggerFailCount, 1);
     }
 
+    @Test
     public void testRunBackup_OneNewCall() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
@@ -310,14 +330,15 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(backupRestoreLoggerSuccessCount, 1);
         assertEquals(backupRestoreLoggerFailCount, 0);
 
-        verify(mBackupDataOutput).writeEntityHeader(eq("101"), Matchers.anyInt());
-        verify(mBackupDataOutput).writeEntityData((byte[]) Matchers.any(), Matchers.anyInt());
+        verify(mBackupDataOutput).writeEntityHeader(eq("101"), anyInt());
+        verify(mBackupDataOutput).writeEntityData(any(byte[].class), anyInt());
     }
 
     /*
         Test PhoneAccountHandle Migration process during back up
      */
-    public void testReadCallFromCursorForPhoneAccountMigrationBackup() throws Exception {
+    @Test
+    public void testReadCallFromCursorForPhoneAccountMigrationBackup() {
         Map<Integer, String> subscriptionInfoMap = new HashMap<>();
         subscriptionInfoMap.put(TEST_PHONE_ACCOUNT_HANDLE_SUB_ID_INT,
                 TEST_PHONE_ACCOUNT_HANDLE_ICC_ID);
@@ -338,43 +359,52 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(0, call.isPhoneAccountMigrationPending);
     }
 
-    public void testReadCallFromCursor_WithNullAccountComponentName() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullAccountComponentName() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.PHONE_ACCOUNT_COMPONENT_NAME);
     }
 
-    public void testReadCallFromCursor_WithNullNumber() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullNumber() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.NUMBER);
     }
 
-    public void testReadCallFromCursor_WithNullPostDialDigits() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullPostDialDigits() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.POST_DIAL_DIGITS);
     }
 
-    public void testReadCallFromCursor_WithNullViaNumber() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullViaNumber() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.VIA_NUMBER);
     }
 
-    public void testReadCallFromCursor_WithNullPhoneAccountId() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullPhoneAccountId() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.PHONE_ACCOUNT_ID);
     }
 
-    public void testReadCallFromCursor_WithNullCallAccountAddress() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullCallAccountAddress() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.PHONE_ACCOUNT_ADDRESS);
     }
 
-    public void testReadCallFromCursor_WithNullCallScreeningAppName() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullCallScreeningAppName() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.CALL_SCREENING_APP_NAME);
     }
 
-    public void testReadCallFromCursor_WithNullCallScreeningComponentName() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullCallScreeningComponentName() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.CALL_SCREENING_COMPONENT_NAME);
     }
 
-    public void testReadCallFromCursor_WithNullMissedReason() throws Exception {
+    @Test
+    public void testReadCallFromCursor_WithNullMissedReason() {
         testReadCallFromCursor_WithNullField(CallLog.Calls.MISSED_REASON);
     }
 
-    private void testReadCallFromCursor_WithNullField(String field) throws Exception {
+    private void testReadCallFromCursor_WithNullField(String field) {
         Map<Integer, String> subscriptionInfoMap = new HashMap<>();
         subscriptionInfoMap.put(TEST_PHONE_ACCOUNT_HANDLE_SUB_ID_INT,
             TEST_PHONE_ACCOUNT_HANDLE_ICC_ID);
@@ -385,6 +415,7 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         Call call = mCallLogBackupAgent.readCallFromCursor(mCursor);
     }
 
+    @Test
     public void testRunBackup_MultipleCall() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
         state.version = CallLogBackupAgent.VERSION;
@@ -400,14 +431,15 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(backupRestoreLoggerFailCount, 0);
 
         InOrder inOrder = Mockito.inOrder(mBackupDataOutput);
-        inOrder.verify(mBackupDataOutput).writeEntityHeader(eq("101"), Matchers.anyInt());
+        inOrder.verify(mBackupDataOutput).writeEntityHeader(eq("101"), anyInt());
         inOrder.verify(mBackupDataOutput).
-                writeEntityData((byte[]) Matchers.any(), Matchers.anyInt());
-        inOrder.verify(mBackupDataOutput).writeEntityHeader(eq("102"), Matchers.anyInt());
+                writeEntityData(any(byte[].class), anyInt());
+        inOrder.verify(mBackupDataOutput).writeEntityHeader(eq("102"), anyInt());
         inOrder.verify(mBackupDataOutput).
-                writeEntityData((byte[]) Matchers.any(), Matchers.anyInt());
+                writeEntityData(any(byte[].class), anyInt());
     }
 
+    @Test
     public void testRunBackup_PartialMultipleCall() throws Exception {
         CallLogBackupState state = new CallLogBackupState();
 
@@ -426,9 +458,145 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         assertEquals(backupRestoreLoggerFailCount, 0);
 
         InOrder inOrder = Mockito.inOrder(mBackupDataOutput);
-        inOrder.verify(mBackupDataOutput).writeEntityHeader(eq("102"), Matchers.anyInt());
+        inOrder.verify(mBackupDataOutput).writeEntityHeader(eq("102"), anyInt());
         inOrder.verify(mBackupDataOutput).
-                writeEntityData((byte[]) Matchers.any(), Matchers.anyInt());
+                writeEntityData(any(byte[].class), anyInt());
+    }
+
+    @Test
+    @RequiresFlagsEnabled({Flags.FLAG_CALL_LOG_RESTORE_DEDUPLICATION_ENABLED})
+    public void testRestore_DuplicateEntry_FlagEnabled_Deduplicates() throws Exception {
+        FakeCallLogBackupAgent backupAgent = new FakeCallLogBackupAgent();
+        backupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
+        backupAgent.attach(mContext);
+
+        // Get the initial count of call log entries
+        ContentResolver contentResolver = backupAgent.getContentResolver();
+        int initialCallLogCount = getCallLogCount(contentResolver);
+
+        // Add an existing entry using FakeCallLogBackupAgent.writeCallToProvider
+        // to simulate a call log that was already in the database.
+        Call existingCall = makeCall(100, 1122334455L, 30, "555-0000");
+        backupAgent.writeCallToProvider(existingCall);
+
+        //  Call log count after adding the existing entry
+        int callLogCountWithExistingEntry = initialCallLogCount + 1;
+
+        // Create a new mock call
+        Call call = makeCall(101, 1234567890L, 60, "555-4321");
+
+        try {
+            // Restore the same call data twice using different BackupDataInput objects
+            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+                    0, /* newState */ null);
+            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+                    0, /* newState */ null);
+
+            // Assert that only one new entry was added
+            assertEquals(callLogCountWithExistingEntry + 1, getCallLogCount(contentResolver));
+
+            // Assert that the entry matches the mock call
+            assertCallCount(contentResolver, call, 1);
+
+            // Assert that the existing entry remains in the database and is unaltered
+            assertCallCount(contentResolver, existingCall, 1);
+        } finally {
+            clearCallLogs(contentResolver, ImmutableList.of(existingCall, call));
+        }
+
+        // Assert that the final count is equal to the initial count
+        assertEquals(initialCallLogCount, getCallLogCount(contentResolver));
+    }
+
+    @Test
+    @RequiresFlagsDisabled({Flags.FLAG_CALL_LOG_RESTORE_DEDUPLICATION_ENABLED})
+    public void testRestore_DuplicateEntry_FlagDisabled_AddsDuplicateEntry() throws Exception {
+        FakeCallLogBackupAgent backupAgent = new FakeCallLogBackupAgent();
+        backupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
+        backupAgent.attach(mContext);
+
+        // Get the initial count of call log entries
+        ContentResolver contentResolver = backupAgent.getContentResolver();
+        int initialCallLogCount = getCallLogCount(contentResolver);
+
+        // Add an existing entry using FakeCallLogBackupAgent.writeCallToProvider
+        // to simulate a call log that was already in the database.
+        Call existingCall = makeCall(100, 1122334455L, 30, "555-0000");
+        backupAgent.writeCallToProvider(existingCall);
+
+        //  Call log count after adding the existing entry
+        int callLogCountWithExistingEntry = initialCallLogCount + 1;
+
+        // Create a new mock call
+        Call call = makeCall(101, 1234567890L, 60, "555-4321");
+
+        try {
+            // Restore the same call data twice using different BackupDataInput objects
+            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+                    0, /* newState */ null);
+            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+                    0, /* newState */ null);
+
+            // Assert that two new entries were added
+            assertEquals(callLogCountWithExistingEntry + 2, getCallLogCount(contentResolver));
+
+            // Assert that two entries exist with the same data
+            assertCallCount(contentResolver, call, 2);
+
+            // Assert that the existing entry remains in the database and is unaltered
+            assertCallCount(contentResolver, existingCall, 1);
+        } finally {
+            clearCallLogs(contentResolver, ImmutableList.of(existingCall, call));
+        }
+
+        // Assert that the final count is equal to the initial count
+        assertEquals(initialCallLogCount, getCallLogCount(contentResolver));
+    }
+
+    @Test
+    public void testRestore_DifferentEntries_AddsEntries() throws Exception {
+        FakeCallLogBackupAgent backupAgent = new FakeCallLogBackupAgent();
+        backupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
+        backupAgent.attach(mContext);
+
+        // Get the initial count of call log entries
+        ContentResolver contentResolver = backupAgent.getContentResolver();
+        int initialCallLogCount = getCallLogCount(contentResolver);
+
+        // Add an existing entry using FakeCallLogBackupAgent.writeCallToProvider
+        // to simulate a call log that was already in the database.
+        Call existingCall = makeCall(100, 1122334455L, 30, "555-0000");
+        backupAgent.writeCallToProvider(existingCall);
+
+        //  Call log count after adding the existing entry
+        int callLogCountWithExistingEntry = initialCallLogCount + 1;
+
+        // Create two new mock calls
+        Call call1 = makeCall(101, 1234567890L, 60, "555-4321");
+        Call call2 = makeCall(102, 9876543210L, 60, "555-1234");
+        BackupDataInput backupDataInput1 = mockBackupDataInputWithCall(call1);
+        BackupDataInput backupDataInput2 = mockBackupDataInputWithCall(call2);
+
+        try {
+            // Restore the calls
+            backupAgent.onRestore(backupDataInput1, /* appVersionCode */ 0, /* newState */ null);
+            backupAgent.onRestore(backupDataInput2, /* appVersionCode */ 0, /* newState */ null);
+
+            // Assert that two new entries were added
+            assertEquals(callLogCountWithExistingEntry + 2, getCallLogCount(contentResolver));
+
+            // Assert that both calls exist in the database
+            assertCallCount(contentResolver, call1, 1);
+            assertCallCount(contentResolver, call2, 1);
+
+            // Assert that the existing entry remains in the database and is unaltered
+            assertCallCount(contentResolver, existingCall, 1);
+        } finally {
+            clearCallLogs(contentResolver, ImmutableList.of(existingCall, call1, call2));
+        }
+
+        // Assert that the final count is equal to the initial count
+        assertEquals(initialCallLogCount, getCallLogCount(contentResolver));
     }
 
     private static void mockCursor(Cursor cursor, boolean isTelephonyComponentName) {
@@ -733,6 +901,56 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
             CALL_IS_PHONE_ACCOUNT_MIGRATION_PENDING);
     }
 
+    /**
+     * Creates a mock {@link BackupDataInput} for simulating the restore of call log data.
+     */
+    private BackupDataInput mockBackupDataInputWithCall(Call call) throws Exception {
+        BackupDataInput backupDataInput = Mockito.mock(BackupDataInput.class);
+        when(backupDataInput.readNextHeader()).thenReturn(true).thenReturn(false);
+        when(backupDataInput.getKey()).thenReturn(String.valueOf(call.id));
+
+        ByteArrayOutputStream baos = new ByteArrayOutputStream();
+        DataOutputStream data = new DataOutputStream(baos);
+        // Intentionally keeping the version low to avoid writing
+        // a lot of data not relevant to the deduplication logic.
+        data.writeInt(1); // Version 1
+        data.writeLong(call.date);
+        data.writeLong(call.duration);
+        writeString(data, call.number);
+        data.writeInt(call.type);
+        data.writeInt(call.numberPresentation);
+        writeString(data, call.accountComponentName);
+        writeString(data, call.accountId);
+        writeString(data, call.accountAddress);
+        data.writeLong(call.dataUsage == null ? 0 : call.dataUsage);
+        data.writeInt(call.features);
+        data.flush();
+
+
+        byte[] callData = baos.toByteArray();
+        when(backupDataInput.getDataSize()).thenReturn(callData.length);
+        when(backupDataInput.readEntityData(any(byte[].class), anyInt(), anyInt()))
+                .thenAnswer(invocation -> {
+                    byte[] buffer = invocation.getArgument(0);
+                    System.arraycopy(callData, 0, buffer, 0, callData.length);
+                    return null;
+                });
+
+        return backupDataInput;
+    }
+
+    /**
+     * Writes a String to a {@link DataOutputStream}, handling null values.
+     */
+    private void writeString(DataOutputStream data, String str) throws IOException {
+        if (str == null) {
+            data.writeBoolean(false);
+        } else {
+            data.writeBoolean(true);
+            data.writeUTF(str);
+        }
+    }
+
     private static Call makeCall(int id, long date, long duration, String number) {
         Call c = new Call();
         c.id = id;
@@ -744,4 +962,48 @@ public class CallLogBackupAgentTest extends AndroidTestCase {
         return c;
     }
 
+    private int getCallLogCount(ContentResolver contentResolver) {
+        try (Cursor cursor = contentResolver.query(CallLog.Calls.CONTENT_URI,
+                null, null, null, null)) {
+            return cursor != null ? cursor.getCount() : 0;
+        }
+    }
+
+    private void assertCallCount(ContentResolver contentResolver, Call call,
+            int expectedCount) {
+        String[] whereArgs = {String.valueOf(call.date), call.number};
+        try (Cursor cursor = contentResolver.query(CallLog.Calls.CONTENT_URI, /* projection */ null,
+                SELECTION_CALL_DATE_AND_NUMBER, whereArgs, /* sortOrder */ null)) {
+            assertEquals(expectedCount, Objects.requireNonNull(cursor).getCount());
+        }
+    }
+
+    /**
+     * Clears call logs that match the given list of {@link Call}s.
+     */
+    private void clearCallLogs(ContentResolver contentResolver, ImmutableList<Call> callsToClear) {
+        for (Call call : callsToClear) {
+            String[] whereArgs = {String.valueOf(call.date), call.number};
+            contentResolver.delete(CallLog.Calls.CONTENT_URI, SELECTION_CALL_DATE_AND_NUMBER,
+                    whereArgs);
+        }
+    }
+
+    /**
+     * A fake CallLogBackupAgent used for testing. This agent simplifies
+     * the insertion of call log entries for testing restore operations.
+     */
+    private static class FakeCallLogBackupAgent extends CallLogBackupAgent {
+        @Override
+        protected void writeCallToProvider(Call call) {
+            ContentValues values = new ContentValues();
+            values.put(CallLog.Calls.NUMBER, call.number);
+            values.put(CallLog.Calls.DATE, call.date);
+            values.put(CallLog.Calls.DURATION, call.duration);
+            values.put(CallLog.Calls.TYPE, call.type);
+
+            ContentResolver resolver = getContentResolver();
+            resolver.insert(CallLog.Calls.CONTENT_URI, values);
+        }
+    }
 }
```

