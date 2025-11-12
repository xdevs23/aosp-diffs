```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index c6bfa49..a208135 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -31,6 +31,9 @@ pixel-onboarding-eng@ and aob-platform-Op@. Please refer b/317302212 for details
     <!-- gives the permission holder access to the CellBroadcastProvider -->
     <permission android:name="com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY"
             android:protectionLevel="signature" />
+    <!-- the permission for cellbroadcast privilege access that is granted to CBR and CBS  -->
+    <permission android:name="com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS"
+        android:protectionLevel="signature" />
 
     <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
     <uses-permission android:name="android.permission.RECEIVE_SMS" />
@@ -38,9 +41,12 @@ pixel-onboarding-eng@ and aob-platform-Op@. Please refer b/317302212 for details
     <uses-permission android:name="android.permission.READ_CELL_BROADCASTS" />
     <uses-permission android:name="android.permission.MODIFY_PHONE_STATE" />
     <uses-permission android:name="android.permission.WAKE_LOCK" />
+    <uses-permission android:name="android.permission.MANAGE_USERS" />
     <uses-permission android:name="com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY" />
+    <uses-permission android:name="com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS" />
 
     <protected-broadcast android:name="android.telephony.action.AREA_INFO_UPDATED" />
+    <protected-broadcast android:name="com.android.cellbroadcastservice.action.USER_SWITCHED" />
 
     <uses-sdk android:minSdkVersion="30" />
 
diff --git a/AndroidManifest_Platform.xml b/AndroidManifest_Platform.xml
index 3087165..c5a7189 100644
--- a/AndroidManifest_Platform.xml
+++ b/AndroidManifest_Platform.xml
@@ -25,6 +25,9 @@
     <!-- gives the permission holder access to the CellBroadcastProvider -->
     <permission android:name="com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY"
             android:protectionLevel="signature" />
+    <!-- the permission for cellbroadcast privilege access that is granted to CBR and CBS  -->
+    <permission android:name="com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS"
+        android:protectionLevel="signature" />
 
     <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
     <uses-permission android:name="android.permission.RECEIVE_SMS" />
@@ -32,9 +35,12 @@
     <uses-permission android:name="android.permission.READ_CELL_BROADCASTS" />
     <uses-permission android:name="android.permission.MODIFY_PHONE_STATE" />
     <uses-permission android:name="android.permission.WAKE_LOCK" />
+    <uses-permission android:name="android.permission.MANAGE_USERS" />
     <uses-permission android:name="com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY" />
+    <uses-permission android:name="com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS" />
 
     <protected-broadcast android:name="android.telephony.action.AREA_INFO_UPDATED" />
+    <protected-broadcast android:name="com.android.cellbroadcastservice.action.USER_SWITCHED" />
 
     <uses-sdk android:minSdkVersion="29"/>
 
diff --git a/src/com/android/cellbroadcastservice/CellBroadcastHandler.java b/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
index e3b2a41..dc961b7 100644
--- a/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
+++ b/src/com/android/cellbroadcastservice/CellBroadcastHandler.java
@@ -45,6 +45,7 @@ import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.res.Resources;
 import android.database.Cursor;
+import android.database.SQLException;
 import android.location.Location;
 import android.location.LocationListener;
 import android.location.LocationManager;
@@ -358,13 +359,20 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
      * Dispatch a Cell Broadcast message to listeners.
      * @param message the Cell Broadcast to broadcast
      */
-    protected void handleBroadcastSms(SmsCbMessage message) {
+    @VisibleForTesting
+    public void handleBroadcastSms(SmsCbMessage message) {
         int slotIndex = message.getSlotIndex();
 
         // TODO: Database inserting can be time consuming, therefore this should be changed to
         // asynchronous.
         ContentValues cv = message.getContentValues();
-        Uri uri = mContext.getContentResolver().insert(CellBroadcasts.CONTENT_URI, cv);
+        Uri uri = null;
+        try {
+            uri = mContext.getContentResolver().insert(CellBroadcasts.CONTENT_URI, cv);
+        } catch (SQLException e) {
+            loge("handleBroadcastSms", e);
+        }
+        final Uri finalUri = uri;
 
         if (message.needGeoFencingCheck()) {
             int maximumWaitingTime = getMaxLocationWaitingTime(message);
@@ -384,7 +392,7 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
                         logd("onLocationUpdate: location=" + location
                                 + ", acc=" + accuracy + ". "  + getMessageString(message));
                     }
-                    performGeoFencing(message, uri, calculator, location, slotIndex,
+                    performGeoFencing(message, finalUri, calculator, location, slotIndex,
                             accuracy);
                 }
 
@@ -396,7 +404,7 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
                 @Override
                 public void onLocationUnavailable() {
                     CellBroadcastHandler.this.onLocationUnavailable(
-                            calculator, message, uri, slotIndex);
+                            calculator, message, finalUri, slotIndex);
                 }
             }, maximumWaitingTime);
         } else {
@@ -405,7 +413,7 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
                         + " needGeoFencing = " + message.needGeoFencingCheck() + ". "
                         + getMessageString(message));
             }
-            broadcastMessage(message, uri, slotIndex);
+            broadcastMessage(message, finalUri, slotIndex);
         }
     }
 
@@ -635,7 +643,8 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
      * @param slotIndex the index of the slot
      * @param accuracy the accuracy of the coordinate given in meters
      */
-    protected void performGeoFencing(SmsCbMessage message, Uri uri,
+    @VisibleForTesting
+    public void performGeoFencing(SmsCbMessage message, Uri uri,
             CbSendMessageCalculator calculator, LatLng location, int slotIndex, float accuracy) {
 
         logd(calculator.toString() + ", current action="
@@ -651,11 +660,14 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
         if (uri != null) {
             ContentValues cv = new ContentValues();
             cv.put(CellBroadcasts.LOCATION_CHECK_TIME, System.currentTimeMillis());
-            mContext.getContentResolver().update(CellBroadcasts.CONTENT_URI, cv,
-                    CellBroadcasts._ID + "=?", new String[] {uri.getLastPathSegment()});
+            try {
+                mContext.getContentResolver().update(CellBroadcasts.CONTENT_URI, cv,
+                        CellBroadcasts._ID + "=?", new String[]{uri.getLastPathSegment()});
+            } catch (SQLException e) {
+                loge("performGeoFencing", e);
+            }
         }
 
-
         calculator.addCoordinate(location, accuracy);
 
         if (VDBG) {
@@ -766,7 +778,8 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
      */
     // TODO(b/193460475): Remove when tooling supports SystemApi to public API.
     @SuppressLint("NewApi")
-    protected void broadcastMessage(@NonNull SmsCbMessage message, @Nullable Uri messageUri,
+    @VisibleForTesting
+    public void broadcastMessage(@NonNull SmsCbMessage message, @Nullable Uri messageUri,
             int slotIndex) {
         String msg;
         Intent intent;
@@ -836,8 +849,12 @@ public class CellBroadcastHandler extends WakeLockStateMachine {
         if (messageUri != null) {
             ContentValues cv = new ContentValues();
             cv.put(CellBroadcasts.MESSAGE_BROADCASTED, 1);
-            mContext.getContentResolver().update(CellBroadcasts.CONTENT_URI, cv,
-                    CellBroadcasts._ID + "=?", new String[] {messageUri.getLastPathSegment()});
+            try {
+                mContext.getContentResolver().update(CellBroadcasts.CONTENT_URI, cv,
+                        CellBroadcasts._ID + "=?", new String[]{messageUri.getLastPathSegment()});
+            } catch (SQLException e) {
+                loge("broadcastMessage", e);
+            }
         }
 
         CellBroadcastServiceMetrics.getInstance().logFeatureChangedAsNeeded(mContext);
diff --git a/src/com/android/cellbroadcastservice/DefaultCellBroadcastService.java b/src/com/android/cellbroadcastservice/DefaultCellBroadcastService.java
index 96c42f3..1bd82b4 100644
--- a/src/com/android/cellbroadcastservice/DefaultCellBroadcastService.java
+++ b/src/com/android/cellbroadcastservice/DefaultCellBroadcastService.java
@@ -21,9 +21,12 @@ import static com.android.cellbroadcastservice.CellBroadcastMetrics.RPT_CDMA;
 import static com.android.cellbroadcastservice.CellBroadcastMetrics.SRC_CBS;
 
 import android.annotation.NonNull;
+import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
+import android.content.IntentFilter;
 import android.os.Bundle;
+import android.os.UserHandle;
 import android.provider.Telephony;
 import android.telephony.CellBroadcastService;
 import android.telephony.SmsCbLocation;
@@ -34,6 +37,7 @@ import android.telephony.cdma.CdmaSmsCbProgramData;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.modules.utils.build.SdkLevel;
 
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
@@ -55,6 +59,32 @@ public class DefaultCellBroadcastService extends CellBroadcastService {
     private static final char[] HEX_DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7',
             '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
 
+    @VisibleForTesting
+    public static final String ACTION_CELLBROADCAST_USER_SWITCHED =
+            "com.android.cellbroadcastservice.action.USER_SWITCHED";
+
+    @VisibleForTesting
+    public static final String CBR_MODULE_PERMISSION =
+            "com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS";
+
+    private BroadcastReceiver mReceiver = new BroadcastReceiver() {
+        @Override
+        public void onReceive(Context context, Intent intent) {
+            switch (intent.getAction()) {
+                case Intent.ACTION_USER_SWITCHED:
+                    //  If CBR listens this event directly, this can be missed if that event occurs
+                    //  when the app process is not alive. So, CBS forwards this event to CBR
+                    Intent intentForUserSwitch = new Intent(ACTION_CELLBROADCAST_USER_SWITCHED);
+                    context.sendBroadcastAsUser(intentForUserSwitch, UserHandle.CURRENT,
+                            CBR_MODULE_PERMISSION);
+                    Log.d(TAG, "sent broadcast for user switch");
+                    break;
+                default:
+                    Log.d(TAG, "Unhandled broadcast " + intent.getAction());
+            }
+        }
+    };
+
     @Override
     public void onCreate() {
         super.onCreate();
@@ -64,12 +94,21 @@ public class DefaultCellBroadcastService extends CellBroadcastService {
                 CellBroadcastHandler.makeCellBroadcastHandler(getApplicationContext());
         mCdmaScpHandler =
                 CdmaServiceCategoryProgramHandler.makeScpHandler(getApplicationContext());
+        if (SdkLevel.isAtLeastT()) {
+            // ACTION_USER_SWITCHED is not supported on below T
+            IntentFilter intentFilter = new IntentFilter();
+            intentFilter.addAction(Intent.ACTION_USER_SWITCHED);
+            registerReceiver(mReceiver, intentFilter, RECEIVER_EXPORTED);
+        }
     }
 
     @Override
     public void onDestroy() {
         mGsmCellBroadcastHandler.cleanup();
         mCdmaCellBroadcastHandler.cleanup();
+        if (SdkLevel.isAtLeastT()) {
+            unregisterReceiver(mReceiver);
+        }
         super.onDestroy();
     }
 
diff --git a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
index 79648c6..2289dcb 100644
--- a/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
+++ b/tests/src/com/android/cellbroadcastservice/tests/CellBroadcastHandlerTest.java
@@ -42,6 +42,7 @@ import android.content.pm.PackageManager;
 import android.content.res.Configuration;
 import android.database.Cursor;
 import android.database.MatrixCursor;
+import android.database.SQLException;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.IBinder;
@@ -81,6 +82,8 @@ import org.mockito.Mock;
 import java.io.IOException;
 import java.io.OutputStream;
 import java.io.PrintWriter;
+import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 
@@ -112,6 +115,12 @@ public class CellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
 
     @Mock
     private ISub mISub;
+    @Mock
+    private Uri mUri;
+    @Mock
+    private CbGeoUtils.LatLng mLocation;
+    @Mock
+    private CbGeoUtils.Polygon mPolygon;
 
     private Configuration mConfiguration;
 
@@ -176,6 +185,17 @@ public class CellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
         }
     }
 
+    private static class FullStorageProvider extends MockContentProvider {
+        @Override
+        public Uri insert(Uri uri, ContentValues values) {
+            throw new SQLException("SQL exception thrown on insert call due to full storage.");
+        }
+
+        @Override
+        public int update(Uri url, ContentValues values, String where, String[] whereArgs) {
+            throw new SQLException("SQL exception thrown on update call due to full storage.");
+        }
+    }
 
     @Before
     public void setUp() throws Exception {
@@ -507,6 +527,51 @@ public class CellBroadcastHandlerTest extends CellBroadcastServiceTestBase {
                 .queryBroadcastReceivers(intent, PackageManager.MATCH_SYSTEM_ONLY);
     }
 
+    @Test
+    @SmallTest
+    public void testReceiveAlertWhenStorageFull() {
+        MockContentResolver mockContentResolver = new MockContentResolver();
+        mockContentResolver.addProvider(
+                Telephony.CellBroadcasts.CONTENT_URI.getAuthority(), new FullStorageProvider());
+        doReturn(mockContentResolver).when(mMockedContext).getContentResolver();
+
+        putResources(com.android.cellbroadcastservice.R.array
+                .additional_cell_broadcast_receiver_packages, new String[]{});
+        SmsCbMessage cbMessageEmergency = createSmsCbMessage(100, 4370, "test");
+
+        // Verify that an SQL exception is catched well when inserting the DB after the
+        // handleBroadcastSms call.
+        try {
+            mCellBroadcastHandler.handleBroadcastSms(cbMessageEmergency);
+        } catch (SQLException e) {
+            fail("must handle the SQLException that occurs when the database is full.");
+        }
+
+        // Verify that an SQL exception is catched well when updating the DB after the
+        // broadcastMessage call.
+        try {
+            mCellBroadcastHandler.broadcastMessage(cbMessageEmergency, mUri, 0);
+        } catch (SQLException e) {
+            fail("must handle the SQLException that occurs when the database is full.");
+        }
+
+        // Verify that an SQL exception is catched well when updating the DB after the
+        // performGeoFencing call.
+        try {
+            mCellBroadcastHandler.performGeoFencing(cbMessageEmergency, mUri,
+                    createCalculator(100, mPolygon), mLocation, 0, 0);
+        } catch (SQLException e) {
+            fail("must handle the SQLException that occurs when the database is full.");
+        }
+    }
+
+    private CbSendMessageCalculator createCalculator(float threshold,
+            CbGeoUtils.Geometry geo, CbGeoUtils.Geometry... geos) {
+        List<CbGeoUtils.Geometry> list = new ArrayList<>(Arrays.asList(geos));
+        list.add(geo);
+        return new CbSendMessageCalculator(mMockedContext, list, threshold);
+    }
+
     /**
      * Makes injecting a mock factory easy.
      */
diff --git a/tests/src/com/android/cellbroadcastservice/tests/DefaultCellBroadcastServiceTest.java b/tests/src/com/android/cellbroadcastservice/tests/DefaultCellBroadcastServiceTest.java
new file mode 100644
index 0000000..722871a
--- /dev/null
+++ b/tests/src/com/android/cellbroadcastservice/tests/DefaultCellBroadcastServiceTest.java
@@ -0,0 +1,206 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.cellbroadcastservice.tests;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.SharedPreferences;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
+import android.content.res.Configuration;
+import android.content.res.Resources;
+import android.location.LocationManager;
+import android.os.Handler;
+import android.os.IPowerManager;
+import android.os.IThermalService;
+import android.os.PowerManager;
+import android.telephony.SubscriptionManager;
+import android.telephony.TelephonyManager;
+import android.test.ServiceTestCase;
+import android.test.mock.MockContentResolver;
+import android.testing.AndroidTestingRunner;
+import android.testing.TestableLooper;
+
+import com.android.cellbroadcastservice.DefaultCellBroadcastService;
+import com.android.modules.utils.build.SdkLevel;
+
+import com.google.common.collect.ArrayListMultimap;
+import com.google.common.collect.Multimap;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+import org.mockito.stubbing.Answer;
+
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper
+public class DefaultCellBroadcastServiceTest extends ServiceTestCase<DefaultCellBroadcastService> {
+
+    @Mock
+    private Context mMockedContext;
+
+    @Mock
+    private ApplicationInfo mApplicationInfo;
+    @Mock
+    private Resources mMockedResources;
+
+    @Mock
+    private SubscriptionManager mMockedSubscriptionManager;
+
+    @Mock
+    private TelephonyManager mMockedTelephonyManager;
+
+    @Mock
+    private LocationManager mMockedLocationManager;
+
+    @Mock
+    private PackageManager mMockedPackageManager;
+
+    @Mock
+    private SharedPreferences mSharedPreference;
+
+    @Mock
+    private SharedPreferences.Editor mEditor;
+    private final MockContentResolver mMockedContentResolver = new MockContentResolver();
+
+    private final Multimap<String, BroadcastReceiver> mBroadcastReceiversByAction =
+            ArrayListMultimap.create();
+
+    private static final int FAKE_SUBID = 1;
+
+    public DefaultCellBroadcastServiceTest() {
+        super(DefaultCellBroadcastService.class);
+    }
+
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        MockitoAnnotations.initMocks(this);
+        setContext(mMockedContext);
+        doReturn(mApplicationInfo).when(mMockedContext).getApplicationInfo();
+        doReturn(mMockedContext).when(mMockedContext).getApplicationContext();
+        doReturn(mMockedContext).when(mMockedContext).createConfigurationContext(any());
+        doReturn(mMockedContentResolver).when(mMockedContext).getContentResolver();
+        doReturn(mSharedPreference).when(mMockedContext).getSharedPreferences(
+                anyString(), anyInt());
+        doReturn(mEditor).when(mSharedPreference).edit();
+        doReturn(false).when(mSharedPreference).getBoolean(anyString(), anyBoolean());
+        doReturn(mMockedResources).when(mMockedContext).getResources();
+        Configuration config = new Configuration();
+        doReturn(config).when(mMockedResources).getConfiguration();
+
+        // Can't directly mock power manager because it's final.
+        PowerManager powerManager = new PowerManager(mMockedContext, mock(IPowerManager.class),
+                mock(IThermalService.class),
+                new Handler(TestableLooper.get(DefaultCellBroadcastServiceTest.this).getLooper()));
+        doReturn(powerManager).when(mMockedContext).getSystemService(Context.POWER_SERVICE);
+        doReturn(mMockedTelephonyManager).when(mMockedContext)
+                .getSystemService(Context.TELEPHONY_SERVICE);
+        doReturn(Context.TELEPHONY_SERVICE).when(mMockedContext)
+                .getSystemServiceName(TelephonyManager.class);
+        doReturn(mMockedSubscriptionManager).when(mMockedContext)
+                .getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
+        doReturn(Context.TELEPHONY_SUBSCRIPTION_SERVICE).when(mMockedContext).getSystemServiceName(
+                SubscriptionManager.class);
+        doReturn(mMockedLocationManager).when(mMockedContext)
+                .getSystemService(Context.LOCATION_SERVICE);
+        doReturn(true).when(mMockedLocationManager)
+                .isLocationEnabled();
+        doReturn(mMockedPackageManager).when(mMockedContext)
+                .getPackageManager();
+        doReturn(mMockedContext).when(mMockedContext).createContextAsUser(any(), anyInt());
+        doReturn(new int[]{FAKE_SUBID}).when(mMockedSubscriptionManager)
+                .getSubscriptionIds(anyInt());
+        doReturn(mMockedTelephonyManager).when(mMockedTelephonyManager)
+                .createForSubscriptionId(anyInt());
+        Answer<Intent> registerReceiverAnswer = invocation -> {
+            BroadcastReceiver receiver = invocation.getArgument(0);
+            IntentFilter intentFilter = invocation.getArgument(1);
+            for (int i = 0; i < intentFilter.countActions(); i++) {
+                mBroadcastReceiversByAction.put(intentFilter.getAction(i), receiver);
+            }
+            return null;
+        };
+        doAnswer(registerReceiverAnswer).when(mMockedContext).registerReceiver(
+                any(BroadcastReceiver.class), any(IntentFilter.class), any(int.class));
+        doAnswer(registerReceiverAnswer).when(mMockedContext).registerReceiver(
+                any(BroadcastReceiver.class), any(IntentFilter.class),
+                any(), any(), any(int.class));
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    void sendBroadcast(Intent intent) {
+        if (mBroadcastReceiversByAction.containsKey(intent.getAction())) {
+            for (BroadcastReceiver receiver : mBroadcastReceiversByAction.get(intent.getAction())) {
+                receiver.onReceive(mMockedContext, intent);
+            }
+        }
+    }
+
+    @Test
+    public void testUserSwitchEvent() {
+        if (!SdkLevel.isAtLeastT()) {
+            return;
+        }
+        Intent intentStart = new Intent(mMockedContext, DefaultCellBroadcastService.class);
+        startService(intentStart);
+
+        ArgumentCaptor<IntentFilter> captor = ArgumentCaptor.forClass(IntentFilter.class);
+        verify(mMockedContext, times(3)).registerReceiver(
+                any(), captor.capture(), anyInt());
+        assertEquals(Intent.ACTION_USER_SWITCHED, captor.getAllValues().get(2).getAction(0));
+
+        Intent intent = new Intent(Intent.ACTION_USER_SWITCHED);
+        // Send fake user switch event.
+        sendBroadcast(intent);
+        ArgumentCaptor<Intent> captorIntent = ArgumentCaptor.forClass(Intent.class);
+        ArgumentCaptor<String> capturePermission = ArgumentCaptor.forClass(String.class);
+
+        verify(mContext, times(1)).sendBroadcastAsUser(
+                captorIntent.capture(), any(), capturePermission.capture());
+        assertEquals(DefaultCellBroadcastService.ACTION_CELLBROADCAST_USER_SWITCHED,
+                captorIntent.getValue().getAction());
+        assertEquals(DefaultCellBroadcastService.CBR_MODULE_PERMISSION,
+                capturePermission.getValue());
+    }
+
+    @Test
+    @Override
+    public void testServiceTestCaseSetUpProperly() throws Exception {
+        super.testServiceTestCaseSetUpProperly();
+    }
+}
```

