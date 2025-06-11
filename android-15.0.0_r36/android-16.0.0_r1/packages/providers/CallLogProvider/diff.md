```diff
diff --git a/calllogbackup_flags.aconfig b/calllogbackup_flags.aconfig
index 1545749..120a561 100644
--- a/calllogbackup_flags.aconfig
+++ b/calllogbackup_flags.aconfig
@@ -6,4 +6,11 @@ flag {
     namespace: "telecom"
     description: "Enables deduplication of call log entries during restore operations to prevent duplicate entries."
     bug: "374931480"
+}
+
+flag {
+    name: "batch_deduplication_enabled"
+    namespace: "telecom"
+    description: "Enables batch deduplication of call log entries during restore operations for improved efficiency."
+    bug: "388203097"
 }
\ No newline at end of file
diff --git a/src/com/android/calllogbackup/CallLogBackupAgent.java b/src/com/android/calllogbackup/CallLogBackupAgent.java
index acc29a4..99c3eac 100644
--- a/src/com/android/calllogbackup/CallLogBackupAgent.java
+++ b/src/com/android/calllogbackup/CallLogBackupAgent.java
@@ -18,6 +18,7 @@ package com.android.calllogbackup;
 
 import static android.provider.CallLog.Calls.MISSED_REASON_NOT_MISSED;
 import static com.android.calllogbackup.Flags.callLogRestoreDeduplicationEnabled;
+import static com.android.calllogbackup.Flags.batchDeduplicationEnabled;
 
 import android.app.backup.BackupAgent;
 import android.app.backup.BackupDataInput;
@@ -48,6 +49,7 @@ import java.io.EOFException;
 import java.io.FileInputStream;
 import java.io.FileOutputStream;
 import java.io.IOException;
+import java.util.ArrayList;
 import java.util.LinkedList;
 import java.util.List;
 import java.util.HashMap;
@@ -113,6 +115,8 @@ public class CallLogBackupAgent extends BackupAgent {
 
     private static final String TAG = "CallLogBackupAgent";
 
+    private static final int CALL_LOG_DEDUPLICATION_BATCH_SIZE = 250;
+
     /** Data types and errors used when reporting B&R success rate and errors.  */
     @BackupRestoreEventLogger.BackupRestoreDataType
     @VisibleForTesting
@@ -282,11 +286,38 @@ public class CallLogBackupAgent extends BackupAgent {
     @Override
     public void onRestore(BackupDataInput data, int appVersionCode, ParcelFileDescriptor newState)
             throws IOException {
-
         if (isDebug()) {
             Log.d(TAG, "Performing Restore");
         }
 
+        if (callLogRestoreDeduplicationEnabled() && batchDeduplicationEnabled()) {
+            if (hasExistingCallLogs()) {
+                Map<String, Call> callMap = new HashMap<>();
+
+                while (data.readNextHeader()) {
+                    Call call = readCallFromData(data);
+                    if (call != null && call.type != Calls.VOICEMAIL_TYPE) {
+                        String key = getCallKey(call.date, call.number);
+                        callMap.put(key, call);
+
+                        if (callMap.size() >= getBatchSize()) {
+                            restoreCallBatch(callMap);
+                            // Clear the map for the next batch
+                            callMap.clear();
+                        }
+                    }
+                }
+
+                if (!callMap.isEmpty()) {
+                    restoreCallBatch(callMap);
+                }
+            } else {
+                // No existing call logs, so no need for deduplication
+                performRestoreWithoutDeduplication(data);
+            }
+            return;
+        }
+
         while (data.readNextHeader()) {
             Call call = readCallFromData(data);
             if (call != null && call.type != Calls.VOICEMAIL_TYPE) {
@@ -301,6 +332,103 @@ public class CallLogBackupAgent extends BackupAgent {
         }
     }
 
+    private void restoreCallBatch(Map<String, Call> callMap) {
+        removeDuplicateCalls(callMap);
+
+        for (Call nonDuplicateCall : callMap.values()) {
+            writeAndLogCall(nonDuplicateCall);
+        }
+    }
+
+    private void removeDuplicateCalls(Map<String, Call> callMap) {
+        // Build the selection clause for the query. This clause will look like:
+        // ((date = ? AND number = ?) OR (date = ? AND number = ?) OR ...)
+        // where the placeholders (?) will be replaced with the date and number of each call
+        // in the callMap.
+        StringBuilder selection = new StringBuilder();
+        selection.append(" (");
+
+        String[] selectionArgs = new String[callMap.size() * 2];
+        int argIndex = 0;
+
+        for (Call call : callMap.values()) {
+            if (argIndex > 0) {
+                selection.append(" OR ");
+            }
+            selection.append("(");
+            selection.append(SELECTION_CALL_DATE_AND_NUMBER);
+            selection.append(")");
+            selectionArgs[argIndex++] = String.valueOf(call.date);
+            selectionArgs[argIndex++] = call.number;
+        }
+        selection.append(")");
+
+        // Query the call log and check for duplicates
+        try (Cursor cursor = getContentResolver().query(CallLog.Calls.CONTENT_URI,
+                new String[]{CallLog.Calls.DATE, CallLog.Calls.NUMBER},
+                selection.toString(), selectionArgs, /* sortOrder */ null)) {
+
+            if (cursor != null && cursor.moveToFirst()) {
+                do {
+                    long callLogDate = cursor.getLong(cursor.getColumnIndex(CallLog.Calls.DATE));
+                    String callLogNumber = cursor.getString(
+                            cursor.getColumnIndex(CallLog.Calls.NUMBER));
+                    String key = getCallKey(callLogDate, callLogNumber);
+
+                    callMap.remove(key);
+                } while (cursor.moveToNext());
+            }
+        }
+    }
+
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
+    private void performRestoreWithoutDeduplication(BackupDataInput data) throws IOException {
+        while (data.readNextHeader()) {
+            Call call = readCallFromData(data);
+            if (call != null && call.type != Calls.VOICEMAIL_TYPE) {
+                writeAndLogCall(call);
+            }
+        }
+    }
+
+    private void writeAndLogCall(Call call) {
+        writeCallToProvider(call);
+        mBackupRestoreEventLoggerProxy.logItemsRestored(CALLLOGS, /* count */ 1);
+        if (isDebug()) {
+            Log.d(TAG, "Restored call: " + call);
+        }
+    }
+
+    private boolean hasExistingCallLogs() {
+        try (Cursor cursor = getContentResolver().query(CallLog.Calls.CONTENT_URI,
+                new String[]{CallLog.Calls._ID}, /* selection */ null, /* selectionArgs */
+                null, /* sortOrder */ null)) {
+            return cursor != null && cursor.moveToFirst();
+        }
+    }
+
+    @VisibleForTesting
+    int getBatchSize() {
+        return CALL_LOG_DEDUPLICATION_BATCH_SIZE;
+    }
+
+    private String getCallKey(long date, String number) {
+        return date + "_" + number;
+    }
+
     @VisibleForTesting
     void runBackup(CallLogBackupState state, BackupDataOutput data, Iterable<Call> calls) {
         SortedSet<Integer> callsToRemove = new TreeSet<>(state.callIds);
@@ -363,20 +491,6 @@ public class CallLogBackupAgent extends BackupAgent {
         return calls;
     }
 
-    private boolean isDuplicateCall(Call call) {
-        // Build the query selection
-        String[] selectionArgs = new String[]{String.valueOf(call.date), call.number};
-
-        // Query the call log provider. We only need to check for the existence of a call with
-        // the same date and number, so we only select the _ID column.
-        try (Cursor cursor = getContentResolver().query(CallLog.Calls.CONTENT_URI,
-                new String[]{CallLog.Calls._ID}, SELECTION_CALL_DATE_AND_NUMBER,
-                selectionArgs, /* sortOrder */ null)) {
-
-            return cursor != null && cursor.moveToFirst();
-        }
-    }
-
     @VisibleForTesting
     void writeCallToProvider(Call call) {
         Long dataUsage = call.dataUsage == 0 ? null : call.dataUsage;
diff --git a/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java b/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java
index a3fd92b..a5051d8 100644
--- a/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java
+++ b/tests/src/com/android/calllogbackup/CallLogBackupAgentTest.java
@@ -44,6 +44,7 @@ import androidx.test.filters.SmallTest;
 import com.android.calllogbackup.CallLogBackupAgent.Call;
 import com.android.calllogbackup.CallLogBackupAgent.CallLogBackupState;
 import com.android.calllogbackup.Flags;
+import com.android.internal.annotations.VisibleForTesting;
 
 import org.junit.After;
 import org.junit.Before;
@@ -53,6 +54,7 @@ import org.mockito.InOrder;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
+import org.mockito.stubbing.OngoingStubbing;
 
 import java.io.ByteArrayOutputStream;
 import java.io.DataInput;
@@ -60,6 +62,7 @@ import java.io.DataOutput;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
+import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.LinkedList;
 import java.util.List;
@@ -198,6 +201,7 @@ public class CallLogBackupAgentTest {
                 }
         );
 
+        mCallLogBackupAgent.attach(mContext);
         mCallLogBackupAgent.onRestore(backupDataInput, Integer.MAX_VALUE, null);
 
         assertEquals(1, backupRestoreLoggerFailCount);
@@ -465,7 +469,9 @@ public class CallLogBackupAgentTest {
 
     @Test
     @RequiresFlagsEnabled({Flags.FLAG_CALL_LOG_RESTORE_DEDUPLICATION_ENABLED})
-    public void testRestore_DuplicateEntry_FlagEnabled_Deduplicates() throws Exception {
+    @RequiresFlagsDisabled({Flags.FLAG_BATCH_DEDUPLICATION_ENABLED})
+    public void testRestore_DeduplicationEnabled_BatchDisabled_DuplicateEntry_Deduplicates()
+            throws Exception {
         FakeCallLogBackupAgent backupAgent = new FakeCallLogBackupAgent();
         backupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
         backupAgent.attach(mContext);
@@ -476,20 +482,24 @@ public class CallLogBackupAgentTest {
 
         // Add an existing entry using FakeCallLogBackupAgent.writeCallToProvider
         // to simulate a call log that was already in the database.
-        Call existingCall = makeCall(100, 1122334455L, 30, "555-0000");
+        Call existingCall = makeCall(/* id */ 100, /* date */ 1122334455L, /* duration */
+                30, /* number */ "555-0000");
         backupAgent.writeCallToProvider(existingCall);
 
         //  Call log count after adding the existing entry
         int callLogCountWithExistingEntry = initialCallLogCount + 1;
 
         // Create a new mock call
-        Call call = makeCall(101, 1234567890L, 60, "555-4321");
+        Call call = makeCall(/* id */ 101, /* date */ 1234567890L, /* duration */ 60, /* number */
+                "555-4321");
 
         try {
             // Restore the same call data twice using different BackupDataInput objects
-            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+            backupAgent.onRestore(
+                    mockBackupDataInputWithCalls(ImmutableList.of(call)), /* appVersionCode */
                     0, /* newState */ null);
-            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+            backupAgent.onRestore(
+                    mockBackupDataInputWithCalls(ImmutableList.of(call)), /* appVersionCode */
                     0, /* newState */ null);
 
             // Assert that only one new entry was added
@@ -510,7 +520,8 @@ public class CallLogBackupAgentTest {
 
     @Test
     @RequiresFlagsDisabled({Flags.FLAG_CALL_LOG_RESTORE_DEDUPLICATION_ENABLED})
-    public void testRestore_DuplicateEntry_FlagDisabled_AddsDuplicateEntry() throws Exception {
+    public void testRestore_DuplicateEntry_DeduplicationDisabled_AddsDuplicateEntry()
+            throws Exception {
         FakeCallLogBackupAgent backupAgent = new FakeCallLogBackupAgent();
         backupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
         backupAgent.attach(mContext);
@@ -521,20 +532,24 @@ public class CallLogBackupAgentTest {
 
         // Add an existing entry using FakeCallLogBackupAgent.writeCallToProvider
         // to simulate a call log that was already in the database.
-        Call existingCall = makeCall(100, 1122334455L, 30, "555-0000");
+        Call existingCall = makeCall(/* id */ 100, /* date */ 1122334455L, /* duration */
+                30, /* number */ "555-0000");
         backupAgent.writeCallToProvider(existingCall);
 
         //  Call log count after adding the existing entry
         int callLogCountWithExistingEntry = initialCallLogCount + 1;
 
         // Create a new mock call
-        Call call = makeCall(101, 1234567890L, 60, "555-4321");
+        Call call = makeCall(/* id */ 101, /* date */ 1234567890L, /* duration */ 60, /* number */
+                "555-4321");
 
         try {
             // Restore the same call data twice using different BackupDataInput objects
-            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+            backupAgent.onRestore(
+                    mockBackupDataInputWithCalls(ImmutableList.of(call)), /* appVersionCode */
                     0, /* newState */ null);
-            backupAgent.onRestore(mockBackupDataInputWithCall(call), /* appVersionCode */
+            backupAgent.onRestore(
+                    mockBackupDataInputWithCalls(ImmutableList.of(call)), /* appVersionCode */
                     0, /* newState */ null);
 
             // Assert that two new entries were added
@@ -565,17 +580,20 @@ public class CallLogBackupAgentTest {
 
         // Add an existing entry using FakeCallLogBackupAgent.writeCallToProvider
         // to simulate a call log that was already in the database.
-        Call existingCall = makeCall(100, 1122334455L, 30, "555-0000");
+        Call existingCall = makeCall(/* id */ 100, /* date */ 1122334455L, /* duration */
+                30, /* number */ "555-0000");
         backupAgent.writeCallToProvider(existingCall);
 
         //  Call log count after adding the existing entry
         int callLogCountWithExistingEntry = initialCallLogCount + 1;
 
         // Create two new mock calls
-        Call call1 = makeCall(101, 1234567890L, 60, "555-4321");
-        Call call2 = makeCall(102, 9876543210L, 60, "555-1234");
-        BackupDataInput backupDataInput1 = mockBackupDataInputWithCall(call1);
-        BackupDataInput backupDataInput2 = mockBackupDataInputWithCall(call2);
+        Call call1 = makeCall(/* id */ 101, /* date */ 1234567890L, /* duration */ 60, /* number */
+                "555-4321");
+        Call call2 = makeCall(/* id */ 102, /* date */ 9876543210L, /* duration */ 60, /* number */
+                "555-1234");
+        BackupDataInput backupDataInput1 = mockBackupDataInputWithCalls(ImmutableList.of(call1));
+        BackupDataInput backupDataInput2 = mockBackupDataInputWithCalls(ImmutableList.of(call2));
 
         try {
             // Restore the calls
@@ -599,6 +617,67 @@ public class CallLogBackupAgentTest {
         assertEquals(initialCallLogCount, getCallLogCount(contentResolver));
     }
 
+    @Test
+    @RequiresFlagsEnabled({Flags.FLAG_CALL_LOG_RESTORE_DEDUPLICATION_ENABLED,
+            Flags.FLAG_BATCH_DEDUPLICATION_ENABLED})
+    public void testRestore_DuplicateEntry_BatchDeduplicationEnabled_Deduplicates()
+            throws Exception {
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
+        Call existingCall = makeCall(/* id */ 100, /* date */ 1122334455L, /* duration */
+                30, /* number */ "555-0000");
+        backupAgent.writeCallToProvider(existingCall);
+
+        //  Call log count after adding the existing entry
+        int callLogCountWithExistingEntry = initialCallLogCount + 1;
+
+        int testBatchSize = backupAgent.getBatchSize();
+        // Create multiple new mock calls (more than the batch size)
+        List<Call> calls = new ArrayList<>();
+        for (int i = 0; i < testBatchSize + 2; i++) {
+            calls.add(makeCall(/* id */ 101 + i, /* date */ 1234567890L + i, /* duration */
+                    60 + i, /* number */ "555-4321"));
+        }
+
+        try {
+            // Restore the same call data twice using different BackupDataInput objects
+            backupAgent.onRestore(
+                    mockBackupDataInputWithCalls(ImmutableList.copyOf(calls)), /* appVersionCode */
+                    0, /* newState */ null);
+            backupAgent.onRestore(
+                    mockBackupDataInputWithCalls(ImmutableList.copyOf(calls)), /* appVersionCode */
+                    0, /* newState */ null);
+
+            // Assert that only the expected number of new entries were added
+            assertEquals(callLogCountWithExistingEntry + calls.size(),
+                    getCallLogCount(contentResolver));
+
+            // Assert that each call exists only once
+            for (Call call : calls) {
+                assertCallCount(contentResolver, call, 1);
+            }
+
+            // Assert that the existing entry remains in the database and is unaltered
+            assertCallCount(contentResolver, existingCall, 1);
+        } finally {
+            clearCallLogs(contentResolver, ImmutableList.<Call>builder()
+                    .addAll(calls)
+                    .add(existingCall)
+                    .build());
+        }
+
+        // Assert that the final count is equal to the initial count
+        assertEquals(initialCallLogCount, getCallLogCount(contentResolver));
+    }
+
     private static void mockCursor(Cursor cursor, boolean isTelephonyComponentName) {
         when(cursor.moveToNext()).thenReturn(true).thenReturn(false);
 
@@ -902,39 +981,71 @@ public class CallLogBackupAgentTest {
     }
 
     /**
-     * Creates a mock {@link BackupDataInput} for simulating the restore of call log data.
+     * Creates a mock {@link BackupDataInput} for simulating the restore of multiple call log
+     * entries.
      */
-    private BackupDataInput mockBackupDataInputWithCall(Call call) throws Exception {
+    private BackupDataInput mockBackupDataInputWithCalls(List<Call> calls) throws Exception {
         BackupDataInput backupDataInput = Mockito.mock(BackupDataInput.class);
-        when(backupDataInput.readNextHeader()).thenReturn(true).thenReturn(false);
-        when(backupDataInput.getKey()).thenReturn(String.valueOf(call.id));
-
-        ByteArrayOutputStream baos = new ByteArrayOutputStream();
-        DataOutputStream data = new DataOutputStream(baos);
-        // Intentionally keeping the version low to avoid writing
-        // a lot of data not relevant to the deduplication logic.
-        data.writeInt(1); // Version 1
-        data.writeLong(call.date);
-        data.writeLong(call.duration);
-        writeString(data, call.number);
-        data.writeInt(call.type);
-        data.writeInt(call.numberPresentation);
-        writeString(data, call.accountComponentName);
-        writeString(data, call.accountId);
-        writeString(data, call.accountAddress);
-        data.writeLong(call.dataUsage == null ? 0 : call.dataUsage);
-        data.writeInt(call.features);
-        data.flush();
-
-
-        byte[] callData = baos.toByteArray();
-        when(backupDataInput.getDataSize()).thenReturn(callData.length);
-        when(backupDataInput.readEntityData(any(byte[].class), anyInt(), anyInt()))
-                .thenAnswer(invocation -> {
-                    byte[] buffer = invocation.getArgument(0);
-                    System.arraycopy(callData, 0, buffer, 0, callData.length);
-                    return null;
-                });
+
+        // Array of ByteArrayOutputStream for each call
+        ByteArrayOutputStream[] callByteStreams = new ByteArrayOutputStream[calls.size()];
+
+        // Create ByteArrayOutputStreams for each call
+        for (int i = 0; i < calls.size(); i++) {
+            callByteStreams[i] = new ByteArrayOutputStream();
+            DataOutputStream data = new DataOutputStream(callByteStreams[i]);
+
+            Call call = calls.get(i);
+            // Intentionally keeping the version low to avoid writing
+            // a lot of data not relevant to the deduplication logic.
+            data.writeInt(1); // Version 1
+            data.writeLong(call.date);
+            data.writeLong(call.duration);
+            writeString(data, call.number);
+            data.writeInt(call.type);
+            data.writeInt(call.numberPresentation);
+            writeString(data, call.accountComponentName);
+            writeString(data, call.accountId);
+            writeString(data, call.accountAddress);
+            data.writeLong(call.dataUsage == null ? 0 : call.dataUsage);
+            data.writeInt(call.features);
+            data.flush();
+        }
+
+        // Configure getDataSize
+        OngoingStubbing<Integer> dataSizeStubbing = Mockito.when(backupDataInput.getDataSize());
+        for (int i = 0; i < calls.size(); i++) {
+            final int index = i;
+            dataSizeStubbing = dataSizeStubbing.thenReturn(callByteStreams[index].size());
+        }
+
+        // Configure readEntityData
+        OngoingStubbing<Integer> readStubbing = Mockito.when(
+                backupDataInput.readEntityData(any(byte[].class), anyInt(), anyInt()));
+        for (int i = 0; i < calls.size(); i++) {
+            final int index = i;
+            readStubbing = readStubbing.thenAnswer(invocation -> {
+                byte[] buffer = invocation.getArgument(/* index */ 0);
+                int offset = invocation.getArgument(/* index */ 1);
+                System.arraycopy(callByteStreams[index].toByteArray(), 0, buffer, offset,
+                        callByteStreams[index].size());
+                return callByteStreams[index].size();
+            });
+        }
+
+        // Configure readNextHeader
+        OngoingStubbing<Boolean> hasNextStubbing = Mockito.when(backupDataInput.readNextHeader());
+        for (int i = 0; i < calls.size(); i++) {
+            hasNextStubbing = hasNextStubbing.thenReturn(true); // More calls to read
+        }
+        hasNextStubbing.thenReturn(false); // No more calls
+
+        // Configure getKey
+        OngoingStubbing<String> getKeyStubbing = Mockito.when(backupDataInput.getKey());
+        for (int i = 0; i < calls.size(); i++) {
+            final int index = i;
+            getKeyStubbing = getKeyStubbing.thenReturn(String.valueOf(index));
+        }
 
         return backupDataInput;
     }
@@ -964,7 +1075,8 @@ public class CallLogBackupAgentTest {
 
     private int getCallLogCount(ContentResolver contentResolver) {
         try (Cursor cursor = contentResolver.query(CallLog.Calls.CONTENT_URI,
-                null, null, null, null)) {
+                /* projection */ null, /* selection */ null, /* selectionArgs */
+                null, /* sortOrder */ null)) {
             return cursor != null ? cursor.getCount() : 0;
         }
     }
@@ -994,6 +1106,8 @@ public class CallLogBackupAgentTest {
      * the insertion of call log entries for testing restore operations.
      */
     private static class FakeCallLogBackupAgent extends CallLogBackupAgent {
+        private static final int TEST_BATCH_SIZE = 10;
+
         @Override
         protected void writeCallToProvider(Call call) {
             ContentValues values = new ContentValues();
@@ -1005,5 +1119,11 @@ public class CallLogBackupAgentTest {
             ContentResolver resolver = getContentResolver();
             resolver.insert(CallLog.Calls.CONTENT_URI, values);
         }
+
+        @Override
+        @VisibleForTesting
+        int getBatchSize() {
+            return TEST_BATCH_SIZE;
+        }
     }
 }
```

