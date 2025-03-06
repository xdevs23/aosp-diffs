```diff
diff --git a/Android.bp b/Android.bp
index be5cdf7..19cb72b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,9 +32,10 @@ android_library {
     name: "mobly-bundled-snippets-lib",
     static_libs: [
         "androidx.test.runner",
-	"androidx.test.uiautomator_uiautomator",
-	"error_prone_annotations",
-	"gson",
+        "androidx.test.uiautomator_uiautomator",
+        "android-support-multidex",
+        "error_prone_annotations",
+        "gson",
         "guava",
         "mobly-snippet-lib",
     ],
@@ -44,4 +45,4 @@ android_library {
     manifest: "src/main/AndroidManifest.xml",
     sdk_version: "current",
     min_sdk_version: "31",
-}
\ No newline at end of file
+}
diff --git a/METADATA b/METADATA
index c09220a..0df0281 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/mobly-bundled-snippets
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "mobly-bundled-snippets"
 description: "Mobly Bundled Snippets is a set of Snippets to allow Mobly tests to control Android devices by exposing a simplified version of the public Android API suitable for testing."
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 4
-    day: 9
+    month: 10
+    day: 24
   }
   homepage: "https://github.com/google/mobly-bundled-snippets"
   identifier {
     type: "Git"
     value: "https://github.com/google/mobly-bundled-snippets"
-    version: "4c30f2e6d835ac95b47e0fdfdfaffe5e9e63e4f6"
+    version: "bb800d7318c5a8b8d20351bb795a8bbacd736fc0"
   }
 }
diff --git a/build.gradle b/build.gradle
index c88f93c..edce9d1 100644
--- a/build.gradle
+++ b/build.gradle
@@ -76,6 +76,7 @@ dependencies {
     implementation 'com.google.code.gson:gson:2.8.6'
     implementation 'com.google.guava:guava:31.0.1-jre'
     implementation 'com.google.errorprone:error_prone_annotations:2.15.0'
+    implementation 'org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.6.10'
 
     testImplementation 'com.google.errorprone:error_prone_annotations:2.15.0'
     testImplementation 'com.google.guava:guava:31.0.1-jre'
diff --git a/src/main/AndroidManifest.xml b/src/main/AndroidManifest.xml
index 211104d..d3703e4 100644
--- a/src/main/AndroidManifest.xml
+++ b/src/main/AndroidManifest.xml
@@ -36,10 +36,13 @@
     <uses-permission android:name="android.permission.READ_SMS" />
     <uses-permission android:name="android.permission.READ_SYNC_SETTINGS"/>
     <uses-permission android:name="android.permission.RECEIVE_SMS" />
+    <uses-permission android:name="android.permission.WRITE_CONTACTS" />
     <uses-permission android:name="android.permission.WRITE_SETTINGS" />
     <uses-permission android:name="android.permission.WRITE_SYNC_SETTINGS" />
     <uses-permission android:name="android.permission.SEND_SMS" />
-    <application>
+    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
+    <application android:allowBackup="false"
+                 android:name="androidx.multidex.MultiDexApplication">
         <meta-data
             android:name="mobly-snippets"
             android:testOnly="true"
@@ -53,6 +56,7 @@
                            com.google.android.mobly.snippet.bundled.bluetooth.profiles.BluetoothHeadsetSnippet,
                            com.google.android.mobly.snippet.bundled.BluetoothLeAdvertiserSnippet,
                            com.google.android.mobly.snippet.bundled.BluetoothLeScannerSnippet,
+                           com.google.android.mobly.snippet.bundled.ContactSnippet,
                            com.google.android.mobly.snippet.bundled.LogSnippet,
                            com.google.android.mobly.snippet.bundled.MediaSnippet,
                            com.google.android.mobly.snippet.bundled.NotificationSnippet,
@@ -60,6 +64,7 @@
                            com.google.android.mobly.snippet.bundled.NetworkingSnippet,
                            com.google.android.mobly.snippet.bundled.FileSnippet,
                            com.google.android.mobly.snippet.bundled.SmsSnippet,
+                           com.google.android.mobly.snippet.bundled.WifiAwareManagerSnippet,
                            com.google.android.mobly.snippet.bundled.WifiManagerSnippet,
                            com.google.android.mobly.snippet.bundled.StorageSnippet" />
     </application>
diff --git a/src/main/java/com/google/android/mobly/snippet/bundled/ContactSnippet.java b/src/main/java/com/google/android/mobly/snippet/bundled/ContactSnippet.java
new file mode 100644
index 0000000..9983adf
--- /dev/null
+++ b/src/main/java/com/google/android/mobly/snippet/bundled/ContactSnippet.java
@@ -0,0 +1,137 @@
+/*
+ * Copyright (C) 2024 Google Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not
+ * use this file except in compliance with the License. You may obtain a copy of
+ * the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+ * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+ * License for the specific language governing permissions and limitations under
+ * the License.
+ */
+
+package com.google.android.mobly.snippet.bundled;
+
+import android.accounts.Account;
+import android.accounts.AccountManager;
+import android.content.ContentProviderOperation;
+import android.content.ContentResolver;
+import android.content.ContentUris;
+import android.content.Context;
+import android.content.OperationApplicationException;
+import android.database.Cursor;
+import android.os.Bundle;
+import android.os.RemoteException;
+import android.provider.ContactsContract;
+import androidx.test.platform.app.InstrumentationRegistry;
+import com.google.android.mobly.snippet.Snippet;
+import com.google.android.mobly.snippet.rpc.Rpc;
+import java.util.ArrayList;
+
+/* Snippet class for operating contacts. */
+public class ContactSnippet implements Snippet {
+
+  public static class ContactSnippetException extends Exception {
+
+    ContactSnippetException(String msg) {
+      super(msg);
+    }
+  }
+
+  private static final String GOOGLE_ACCOUNT_TYPE = "com.google";
+  private final Context context = InstrumentationRegistry.getInstrumentation().getContext();
+  private final AccountManager mAccountManager = AccountManager.get(context);
+
+  @Rpc(description = "Add a contact with a given email address to a Google account on the device.")
+  public void contactAddToGoogleAccountByEmail(String contactEmailAddress,
+      String accountEmailAddress)
+      throws ContactSnippetException, OperationApplicationException, RemoteException {
+    assertAccountExists(accountEmailAddress);
+    ArrayList<ContentProviderOperation> contentProviderOperations = new ArrayList<>();
+
+    // Specify where the new contact should be stored.
+    contentProviderOperations.add(
+        ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
+            .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, GOOGLE_ACCOUNT_TYPE)
+            .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, accountEmailAddress).build());
+
+    // Specify data to associate with the new contact.
+    contentProviderOperations.add(
+        ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
+            .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
+            .withValue(ContactsContract.Data.MIMETYPE,
+                ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE)
+            .withValue(ContactsContract.CommonDataKinds.Email.ADDRESS, contactEmailAddress)
+            .withValue(ContactsContract.CommonDataKinds.Email.TYPE,
+                ContactsContract.CommonDataKinds.Email.TYPE_HOME).build());
+
+    // Apply the operations to the ContentProvider.
+    context.getContentResolver().applyBatch(ContactsContract.AUTHORITY, contentProviderOperations);
+  }
+
+  @Rpc(description = "Remove a contact with a given email address from a Google account on the device")
+  public void contactRemoveFromGoogleAccountByEmail(String contactEmailAddress,
+      String accountEmailAddress)
+      throws ContactSnippetException, OperationApplicationException, RemoteException {
+    assertAccountExists(accountEmailAddress);
+
+    // Specify data to associate with the target contact to remove.
+    long contactId = getContactIdByEmail(contactEmailAddress, accountEmailAddress);
+    ArrayList<ContentProviderOperation> contentProviderOperations = new ArrayList<>();
+    contentProviderOperations.add(ContentProviderOperation.newDelete(
+        ContentUris.withAppendedId(ContactsContract.RawContacts.CONTENT_URI, contactId)).build());
+
+    // Apply the operations to the ContentProvider.
+    context.getContentResolver().applyBatch(ContactsContract.AUTHORITY, contentProviderOperations);
+  }
+
+  @Rpc(description = "Requests an immediate synchronization of contact data for the specified Google account.")
+  public void syncGoogleContacts(String accountEmailAddress) {
+    Bundle settingsBundle = new Bundle();
+    settingsBundle.putBoolean(ContentResolver.SYNC_EXTRAS_MANUAL, true);
+    settingsBundle.putBoolean(ContentResolver.SYNC_EXTRAS_EXPEDITED, true);
+    ContentResolver.requestSync(new Account(accountEmailAddress, GOOGLE_ACCOUNT_TYPE),
+        ContactsContract.AUTHORITY, settingsBundle);
+  }
+
+  private long getContactIdByEmail(String emailAddress, String accountEmailAddress)
+      throws OperationApplicationException {
+    try (Cursor cursor =
+        context
+            .getContentResolver()
+            .query(
+                ContactsContract.CommonDataKinds.Email.CONTENT_URI,
+                null,
+                ContactsContract.CommonDataKinds.Email.ADDRESS + " = ?"
+                    + " AND "
+                    + ContactsContract.RawContacts.ACCOUNT_NAME + " = ?",
+                new String[]{emailAddress, accountEmailAddress},
+                null)) {
+      if (cursor != null && cursor.moveToFirst()) {
+        return cursor.getLong(
+            cursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.CONTACT_ID));
+      }
+      throw new OperationApplicationException(
+          "The contact " + emailAddress + " doesn't appear to be saved on " + accountEmailAddress);
+    }
+  }
+
+  private void assertAccountExists(String emailAddress) throws ContactSnippetException {
+    Account[] accounts = mAccountManager.getAccountsByType(GOOGLE_ACCOUNT_TYPE);
+    for (Account account : accounts) {
+      if (account.name.equals(emailAddress)) {
+        return;
+      }
+    }
+    throw new ContactSnippetException(
+        "The account " + emailAddress + " doesn't appear to be login on the device");
+  }
+
+  @Override
+  public void shutdown() {
+  }
+}
diff --git a/src/main/java/com/google/android/mobly/snippet/bundled/WifiAwareManagerSnippet.java b/src/main/java/com/google/android/mobly/snippet/bundled/WifiAwareManagerSnippet.java
new file mode 100644
index 0000000..07a359c
--- /dev/null
+++ b/src/main/java/com/google/android/mobly/snippet/bundled/WifiAwareManagerSnippet.java
@@ -0,0 +1,59 @@
+/*
+ * Copyright (C) 2024 Google Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not
+ * use this file except in compliance with the License. You may obtain a copy of
+ * the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+ * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+ * License for the specific language governing permissions and limitations under
+ * the License.
+ */
+package com.google.android.mobly.snippet.bundled;
+
+import android.content.Context;
+import android.content.pm.PackageManager;
+import android.net.wifi.aware.WifiAwareManager;
+import androidx.test.platform.app.InstrumentationRegistry;
+import com.google.android.mobly.snippet.Snippet;
+import com.google.android.mobly.snippet.bundled.utils.Utils;
+import com.google.android.mobly.snippet.rpc.Rpc;
+
+/** Snippet class exposing Android APIs in WifiAwareManager. */
+public class WifiAwareManagerSnippet implements Snippet {
+
+    private static class WifiAwareManagerSnippetException extends Exception {
+        private static final long serialVersionUID = 1;
+
+        public WifiAwareManagerSnippetException(String msg) {
+            super(msg);
+        }
+    }
+    private final Context mContext;
+    private boolean mIsAwareSupported;
+    WifiAwareManager mWifiAwareManager;
+
+    public WifiAwareManagerSnippet() throws Throwable {
+        mContext = InstrumentationRegistry.getInstrumentation().getContext();
+        mIsAwareSupported =
+            mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE);
+        if (mIsAwareSupported) {
+            mWifiAwareManager = (WifiAwareManager) mContext.getSystemService(Context.WIFI_AWARE_SERVICE);
+        }
+        Utils.adaptShellPermissionIfRequired(mContext);
+    }
+
+    /** Checks if Aware is available. This could return false if WiFi or location is disabled. */
+    @Rpc(description = "check if Aware is available.")
+    public boolean wifiAwareIsAvailable() throws WifiAwareManagerSnippetException {
+        if (!mIsAwareSupported) {
+            throw new WifiAwareManagerSnippetException(
+                    "WifiAware is not supported in this device");
+        }
+        return mWifiAwareManager.isAvailable();
+    }
+}
diff --git a/src/main/java/com/google/android/mobly/snippet/bundled/WifiManagerSnippet.java b/src/main/java/com/google/android/mobly/snippet/bundled/WifiManagerSnippet.java
index e457dc3..2185762 100644
--- a/src/main/java/com/google/android/mobly/snippet/bundled/WifiManagerSnippet.java
+++ b/src/main/java/com/google/android/mobly/snippet/bundled/WifiManagerSnippet.java
@@ -20,7 +20,12 @@ import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.net.ConnectivityManager;
+import android.net.Network;
+import android.net.NetworkCapabilities;
+import android.net.NetworkRequest;
 import android.net.wifi.ScanResult;
+import android.net.wifi.SupplicantState;
 import android.net.wifi.WifiConfiguration;
 import android.net.wifi.WifiInfo;
 import android.net.wifi.WifiManager;
@@ -37,12 +42,10 @@ import com.google.android.mobly.snippet.rpc.RpcMinSdk;
 import com.google.android.mobly.snippet.util.Log;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.concurrent.atomic.AtomicBoolean;
 import org.json.JSONArray;
 import org.json.JSONException;
 import org.json.JSONObject;
-import android.net.wifi.SupplicantState;
-
-import com.google.android.mobly.snippet.bundled.utils.Utils;
 
 /** Snippet class exposing Android APIs in WifiManager. */
 public class WifiManagerSnippet implements Snippet {
@@ -56,16 +59,57 @@ public class WifiManagerSnippet implements Snippet {
 
     private static final int TIMEOUT_TOGGLE_STATE = 30;
     private final WifiManager mWifiManager;
+    private final ConnectivityManager mConnectivityManager;
     private final Context mContext;
     private final JsonSerializer mJsonSerializer = new JsonSerializer();
     private volatile boolean mIsScanResultAvailable = false;
+    private final AtomicBoolean mIsWifiConnected = new AtomicBoolean(false);
 
     public WifiManagerSnippet() throws Throwable {
         mContext = InstrumentationRegistry.getInstrumentation().getContext();
         mWifiManager =
                 (WifiManager)
                         mContext.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
+        mConnectivityManager =
+                (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
         Utils.adaptShellPermissionIfRequired(mContext);
+        registerNetworkStateCallback();
+    }
+
+    private void registerNetworkStateCallback() {
+        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
+        return;
+        }
+
+        mConnectivityManager.registerNetworkCallback(
+            new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(),
+            new ConnectivityManager.NetworkCallback() {
+                @Override
+                public void onAvailable(Network network) {
+                    mIsWifiConnected.set(true);
+                }
+
+                @Override
+                public void onLost(Network network) {
+                    mIsWifiConnected.set(false);
+                }
+            });
+    }
+
+    @Rpc(description = "Checks if Wi-Fi is connected.")
+    public boolean isWifiConnected() {
+        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
+            return mWifiManager
+                    .getConnectionInfo()
+                    .getSupplicantState()
+                    .equals(SupplicantState.COMPLETED);
+        } else {
+            return mIsWifiConnected.get();
+        }
+    }
+
+    private boolean isWifiConnectedToSsid(String ssid) {
+        return mWifiManager.getConnectionInfo().getSSID().equals(ssid);
     }
 
     @Rpc(
@@ -190,12 +234,12 @@ public class WifiManagerSnippet implements Snippet {
         return wifiGetCachedScanResults();
     }
 
-    @Rpc(
-            description =
-                    "Connects to a Wi-Fi network. This covers the common network types like open and "
-                            + "WPA2.")
-    public void wifiConnectSimple(String ssid, @Nullable String password)
-            throws InterruptedException, JSONException, WifiManagerSnippetException {
+  @Rpc(
+      description =
+          "Connects to a Wi-Fi network. This covers the common network types like open and "
+              + "WPA2.")
+  public void wifiConnectSimple(String ssid, @Nullable String password)
+      throws InterruptedException, JSONException, WifiManagerSnippetException {
         JSONObject config = new JSONObject();
         config.put("SSID", ssid);
         if (password != null) {
@@ -224,6 +268,7 @@ public class WifiManagerSnippet implements Snippet {
         }
         return null;
     }
+
     /**
      * Connect to a Wi-Fi network.
      *
@@ -274,12 +319,8 @@ public class WifiManagerSnippet implements Snippet {
             throw new WifiManagerSnippetException(
                     "Failed to reconnect to Wi-Fi network of ID: " + networkId);
         }
-        if (!Utils.waitUntil(
-            () ->
-                mWifiManager.getConnectionInfo().getSSID().equals(SSID)
-                    && mWifiManager.getConnectionInfo().getNetworkId() != -1 && mWifiManager
-                    .getConnectionInfo().getSupplicantState().equals(SupplicantState.COMPLETED),
-            90)) {
+
+        if (!Utils.waitUntil(() -> isWifiConnected() && isWifiConnectedToSsid(SSID), 90)) {
             throw new WifiManagerSnippetException(
                 String.format(
                     "Failed to connect to '%s', timeout! Current connection: '%s'",
@@ -328,11 +369,11 @@ public class WifiManagerSnippet implements Snippet {
         return mJsonSerializer.toJson(mWifiManager.getConnectionInfo());
     }
 
-    @Rpc(
-            description =
-                    "Get the info from last successful DHCP request, which is a serialized DhcpInfo "
-                            + "object.")
-    public JSONObject wifiGetDhcpInfo() throws JSONException {
+  @Rpc(
+      description =
+          "Get the info from last successful DHCP request, which is a serialized DhcpInfo "
+              + "object.")
+  public JSONObject wifiGetDhcpInfo() throws JSONException {
         return mJsonSerializer.toJson(mWifiManager.getDhcpInfo());
     }
 
@@ -351,6 +392,14 @@ public class WifiManagerSnippet implements Snippet {
         return mWifiManager.is5GHzBandSupported();
     }
 
+    /** Checks if TDLS is supported. */
+    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
+    @RpcMinSdk(Build.VERSION_CODES.LOLLIPOP)
+    @Rpc(description = "check if TDLS is supported).")
+    public boolean wifiIsTdlsSupported() {
+        return mWifiManager.isTdlsSupported();
+    }
+
     /**
      * Enable Wi-Fi Soft AP (hotspot).
      *
diff --git a/src/main/java/com/google/android/mobly/snippet/bundled/bluetooth/BluetoothAdapterSnippet.java b/src/main/java/com/google/android/mobly/snippet/bundled/bluetooth/BluetoothAdapterSnippet.java
index 07f51e2..05ee84d 100644
--- a/src/main/java/com/google/android/mobly/snippet/bundled/bluetooth/BluetoothAdapterSnippet.java
+++ b/src/main/java/com/google/android/mobly/snippet/bundled/bluetooth/BluetoothAdapterSnippet.java
@@ -65,6 +65,8 @@ public class BluetoothAdapterSnippet implements Snippet {
     private static final int BT_MATCHING_STATE_INTERVAL_SEC = 5;
     // Default timeout in seconds.
     private static final int TIMEOUT_TOGGLE_STATE_SEC = 30;
+    // Default timeout in milliseconds for UI update.
+    private static final long TIMEOUT_UI_UPDATE_MS = 2000;
     private final Context mContext;
     private final PackageManager mPackageManager;
     private static final BluetoothAdapter mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
@@ -139,7 +141,7 @@ public class BluetoothAdapterSnippet implements Snippet {
             mContext.startActivity(enableIntent);
             // Clicks the "ALLOW" button.
             BySelector allowButtonSelector = By.text(TEXT_PATTERN_ALLOW).clickable(true);
-            uiDevice.wait(Until.findObject(allowButtonSelector), 10);
+            uiDevice.wait(Until.findObject(allowButtonSelector), TIMEOUT_UI_UPDATE_MS);
             uiDevice.findObject(allowButtonSelector).click();
         } else if (!mBluetoothAdapter.enable()) {
             throw new BluetoothAdapterSnippetException("Failed to start enabling bluetooth.");
@@ -268,12 +270,12 @@ public class BluetoothAdapterSnippet implements Snippet {
             if (mPackageManager.hasSystemFeature(PackageManager.FEATURE_WATCH)) {
                 // Clicks the "OK" button.
                 BySelector okButtonSelector = By.desc(TEXT_PATTERN_OK).clickable(true);
-                uiDevice.wait(Until.findObject(okButtonSelector), 10);
+                uiDevice.wait(Until.findObject(okButtonSelector), TIMEOUT_UI_UPDATE_MS);
                 uiDevice.findObject(okButtonSelector).click();
             } else {
                 // Clicks the "ALLOW" button.
                 BySelector allowButtonSelector = By.text(TEXT_PATTERN_ALLOW).clickable(true);
-                uiDevice.wait(Until.findObject(allowButtonSelector), 10);
+                uiDevice.wait(Until.findObject(allowButtonSelector), TIMEOUT_UI_UPDATE_MS);
                 uiDevice.findObject(allowButtonSelector).click();
             }
         } else if (Build.VERSION.SDK_INT >= 30) {
diff --git a/src/main/java/com/google/android/mobly/snippet/bundled/utils/Utils.java b/src/main/java/com/google/android/mobly/snippet/bundled/utils/Utils.java
index bd9a76f..9681ece 100644
--- a/src/main/java/com/google/android/mobly/snippet/bundled/utils/Utils.java
+++ b/src/main/java/com/google/android/mobly/snippet/bundled/utils/Utils.java
@@ -217,8 +217,7 @@ public final class Utils {
     }
 
    public static void adaptShellPermissionIfRequired(Context context) throws Throwable {
-      if (context.getApplicationContext().getApplicationInfo().targetSdkVersion >= 29
-          && Build.VERSION.SDK_INT >= 29) {
+      if (Build.VERSION.SDK_INT >= 29) {
         Log.d("Elevating permission require to enable support for privileged operation in Android Q+");
         UiAutomation uia = InstrumentationRegistry.getInstrumentation().getUiAutomation();
         uia.adoptShellPermissionIdentity();
```

