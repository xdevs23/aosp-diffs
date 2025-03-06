```diff
diff --git a/libs/WifiTrackerLib/res/values-in/arrays.xml b/libs/WifiTrackerLib/res/values-in/arrays.xml
index c851e6e0d..2412e411a 100644
--- a/libs/WifiTrackerLib/res/values-in/arrays.xml
+++ b/libs/WifiTrackerLib/res/values-in/arrays.xml
@@ -29,7 +29,7 @@
     <item msgid="5450920562291300229">"Terhubung"</item>
     <item msgid="6332116533879646145">"Ditangguhkan"</item>
     <item msgid="294459081501073818">"Memutus koneksi …"</item>
-    <item msgid="1577368920272598676">"Koneksi terputus"</item>
+    <item msgid="1577368920272598676">"Tidak terhubung"</item>
     <item msgid="7655843177582495451">"Gagal"</item>
     <item msgid="8953752690917593623">"Diblokir"</item>
     <item msgid="4400457817750243671">"Menghindari koneksi buruk untuk sementara"</item>
diff --git a/libs/WifiTrackerLib/res/values-in/strings.xml b/libs/WifiTrackerLib/res/values-in/strings.xml
index cc23f615c..09f154c07 100644
--- a/libs/WifiTrackerLib/res/values-in/strings.xml
+++ b/libs/WifiTrackerLib/res/values-in/strings.xml
@@ -33,7 +33,7 @@
     <string name="wifitrackerlib_wifi_mbo_assoc_disallowed_max_num_sta_associated" msgid="4418848919914618807">"Jaringan melebihi kapasitas. Coba lagi nanti."</string>
     <string name="wifitrackerlib_wifi_mbo_assoc_disallowed_cannot_connect" msgid="2692286425448897083">"Tidak dapat terhubung. Coba lagi nanti."</string>
     <string name="wifitrackerlib_wifi_network_not_found" msgid="1308764769892463388">"Tidak dapat terhubung. Coba lagi nanti."</string>
-    <string name="wifitrackerlib_wifi_disconnected" msgid="3320414360982942679">"Koneksi terputus"</string>
+    <string name="wifitrackerlib_wifi_disconnected" msgid="3320414360982942679">"Tidak terhubung"</string>
     <string name="wifitrackerlib_wifi_remembered" msgid="2406091442008343041">"Tersimpan"</string>
     <string name="wifitrackerlib_wifi_metered_label" msgid="8818508951778620385">"Berbayar"</string>
     <string name="wifitrackerlib_wifi_unmetered_label" msgid="1902150402929678469">"Tidak berbayar"</string>
diff --git a/libs/WifiTrackerLib/res/values-iw/strings.xml b/libs/WifiTrackerLib/res/values-iw/strings.xml
index abfa3bb63..e463f5014 100644
--- a/libs/WifiTrackerLib/res/values-iw/strings.xml
+++ b/libs/WifiTrackerLib/res/values-iw/strings.xml
@@ -74,12 +74,12 @@
     <string name="wifitrackerlib_wifi_security_none" msgid="2686062484642847280">"ללא"</string>
     <string name="wifitrackerlib_wifi_security_passpoint" msgid="3980446437188585906">"Passpoint"</string>
     <string name="wifitrackerlib_wifi_passpoint_expired" msgid="7974960573887452566">"התוקף פג"</string>
-    <string name="wifitrackerlib_tap_to_sign_up" msgid="3897017015910817402">"יש להקיש כדי להירשם"</string>
-    <string name="wifitrackerlib_tap_to_renew_subscription_and_connect" msgid="6048420776676138069">"יש להקיש כדי לחדש את המינוי ולהתחבר"</string>
+    <string name="wifitrackerlib_tap_to_sign_up" msgid="3897017015910817402">"יש ללחוץ כדי להירשם"</string>
+    <string name="wifitrackerlib_tap_to_renew_subscription_and_connect" msgid="6048420776676138069">"יש ללחוץ כדי לחדש את המינוי ולהתחבר"</string>
     <string name="wifitrackerlib_osu_opening_provider" msgid="7128677439450712558">"מתבצעת פתיחה של <xliff:g id="PASSPOINTPROVIDER">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_osu_connect_failed" msgid="3872233609000700930">"לא ניתן להתחבר"</string>
     <string name="wifitrackerlib_osu_completing_sign_up" msgid="4359503050543182480">"מתבצעת השלמה של ההרשמה…"</string>
-    <string name="wifitrackerlib_osu_sign_up_failed" msgid="3964140125523395898">"לא ניתן היה להשלים את ההרשמה. יש להקיש כדי לנסות שוב."</string>
+    <string name="wifitrackerlib_osu_sign_up_failed" msgid="3964140125523395898">"לא ניתן היה להשלים את ההרשמה. יש ללחוץ כדי לנסות שוב."</string>
     <string name="wifitrackerlib_osu_sign_up_complete" msgid="3279606633343124580">"תהליך ההרשמה הסתיים. בתהליך התחברות…"</string>
     <string name="wifitrackerlib_imsi_protection_warning" msgid="7202210931586169466">"‏הרשת הזו מקבלת מזהה SIM שיכול לשמש למעקב אחר מיקום של מכשיר. "<annotation id="url">"למידע נוסף"</annotation></string>
     <string name="wifitrackerlib_wifi_wont_autoconnect_for_now" msgid="4923161724964349851">"‏ה-Wi-Fi לא יתחבר באופן אוטומטי בינתיים"</string>
diff --git a/libs/WifiTrackerLib/res/values/strings.xml b/libs/WifiTrackerLib/res/values/strings.xml
index f0d56ccfc..8392f36bf 100644
--- a/libs/WifiTrackerLib/res/values/strings.xml
+++ b/libs/WifiTrackerLib/res/values/strings.xml
@@ -253,7 +253,7 @@
     <string name="wifitrackerlib_wifi_wont_autoconnect_for_now">Wi-Fi won\u2019t auto-connect for now</string>
 
     <!-- [DO NOT TRANSLATE] Comma-separated list of packages whose saved networks should show no attribution annotation. -->
-    <string name="wifitrackerlib_no_attribution_annotation_packages">com.google.android.setupwizard,com.google.android.gms</string>
+    <string name="wifitrackerlib_no_attribution_annotation_packages">com.android.settings,com.google.android.setupwizard,com.google.android.gms</string>
 
     <!-- Summary for the Wi-Fi standard WIFI_STANDARD_UNKNOWN [CHAR LIMIT=50]-->
     <string name="wifitrackerlib_wifi_standard_unknown">Unknown</string>
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/BaseWifiTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/BaseWifiTracker.java
index 31fdab81a..0934159eb 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/BaseWifiTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/BaseWifiTracker.java
@@ -167,6 +167,8 @@ public class BaseWifiTracker {
     protected final long mScanIntervalMillis;
     protected final ScanResultUpdater mScanResultUpdater;
 
+    protected static final long MAX_SCAN_AGE_FOR_FAILED_SCAN_MS = 5 * 60 * 1000;
+
     @Nullable protected SharedConnectivityManager mSharedConnectivityManager = null;
 
     // Network request for listening on changes to Wifi link properties and network capabilities
@@ -344,8 +346,7 @@ public class BaseWifiTracker {
         mListener = listener;
         mTag = tag;
 
-        mScanResultUpdater = new ScanResultUpdater(clock,
-                maxScanAgeMillis + scanIntervalMillis);
+        mScanResultUpdater = new ScanResultUpdater(clock, MAX_SCAN_AGE_FOR_FAILED_SCAN_MS);
         mScanner = new BaseWifiTracker.Scanner(workerHandler.getLooper());
 
         if (lifecycle != null) { // Need to add after constructor completes.
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointNetworkDetailsTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointNetworkDetailsTracker.java
index 63db0051f..fc4e5385e 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointNetworkDetailsTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointNetworkDetailsTracker.java
@@ -261,7 +261,7 @@ public class PasspointNetworkDetailsTracker extends NetworkDetailsTracker {
         } else {
             // Scan failed, increase scan age window to prevent WifiEntry list from
             // clearing prematurely.
-            scanAgeWindow += mScanIntervalMillis;
+            scanAgeWindow = MAX_SCAN_AGE_FOR_FAILED_SCAN_MS;
         }
 
         List<ScanResult> currentScans = mScanResultUpdater.getScanResults(scanAgeWindow);
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/SavedNetworkTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/SavedNetworkTracker.java
index 63b13aaa3..c1ffde0f8 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/SavedNetworkTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/SavedNetworkTracker.java
@@ -442,10 +442,11 @@ public class SavedNetworkTracker extends BaseWifiTracker {
         } else {
             // Scan failed, increase scan age window to prevent WifiEntry list from
             // clearing prematurely.
-            scanAgeWindow += mScanIntervalMillis;
+            scanAgeWindow = MAX_SCAN_AGE_FOR_FAILED_SCAN_MS;
         }
-        updateStandardWifiEntryScans(mScanResultUpdater.getScanResults(scanAgeWindow));
-        updatePasspointWifiEntryScans(mScanResultUpdater.getScanResults(scanAgeWindow));
+        List<ScanResult> currentScans = mScanResultUpdater.getScanResults(scanAgeWindow);
+        updateStandardWifiEntryScans(currentScans);
+        updatePasspointWifiEntryScans(currentScans);
     }
 
     private void updateStandardWifiEntryConfigs(@NonNull List<WifiConfiguration> configs) {
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardNetworkDetailsTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardNetworkDetailsTracker.java
index e21efc464..35997e3e0 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardNetworkDetailsTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardNetworkDetailsTracker.java
@@ -173,7 +173,7 @@ public class StandardNetworkDetailsTracker extends NetworkDetailsTracker {
         } else {
             // Scan failed, increase scan age window to prevent WifiEntry list from
             // clearing prematurely.
-            scanAgeWindow += mScanIntervalMillis;
+            scanAgeWindow = MAX_SCAN_AGE_FOR_FAILED_SCAN_MS;
         }
         mChosenEntry.updateScanResultInfo(mScanResultUpdater.getScanResults(scanAgeWindow).stream()
                 .filter(scan -> new ScanResultKey(scan).equals(mKey.getScanResultKey()))
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java
index bda8289e4..7b8459dca 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java
@@ -876,7 +876,7 @@ public class StandardWifiEntry extends WifiEntry {
 
     @Override
     protected synchronized String getScanResultDescription() {
-        if (mTargetScanResults.size() == 0) {
+        if (mMatchingScanResults.size() == 0) {
             return "";
         }
 
@@ -891,7 +891,9 @@ public class StandardWifiEntry extends WifiEntry {
     }
 
     private synchronized String getScanResultDescription(int minFrequency, int maxFrequency) {
-        final List<ScanResult> scanResults = mTargetScanResults.stream()
+        final List<ScanResult> scanResults = mMatchingScanResults.values().stream()
+                .flatMap(List::stream)
+                .distinct()
                 .filter(scanResult -> scanResult.frequency >= minFrequency
                         && scanResult.frequency <= maxFrequency)
                 .sorted(Comparator.comparingInt(scanResult -> -1 * scanResult.level))
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java
index 431941b32..c32e40de5 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java
@@ -651,11 +651,7 @@ public class Utils {
         if (specifiedTm == null) {
             return null;
         }
-        CharSequence name = specifiedTm.getSimCarrierIdName();
-        if (name == null) {
-            return null;
-        }
-        return name.toString();
+        return specifiedTm.getSimOperatorName();
     }
 
     static boolean isServerCertUsedNetwork(@NonNull WifiConfiguration config) {
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java
index 6751aa54a..e800fdeb6 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java
@@ -1108,7 +1108,7 @@ public class WifiPickerTracker extends BaseWifiTracker {
         } else {
             // Scan failed, increase scan age window to prevent WifiEntry list from
             // clearing prematurely.
-            scanAgeWindow += mScanIntervalMillis;
+            scanAgeWindow = MAX_SCAN_AGE_FOR_FAILED_SCAN_MS;
         }
 
         List<ScanResult> scanResults = mScanResultUpdater.getScanResults(scanAgeWindow);
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java
index 8d83d1875..89b1fda97 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java
@@ -394,13 +394,13 @@ public class UtilsTest {
 
     @Test
     public void testGetCarrierName() {
-        when(mSpecifiedTm.getSimCarrierIdName()).thenReturn(TEST_CARRIER_NAME);
+        when(mSpecifiedTm.getSimOperatorName()).thenReturn(TEST_CARRIER_NAME);
         assertEquals(TEST_CARRIER_NAME, getCarrierNameForSubId(mMockContext, TEST_CARRIER_ID));
     }
 
     @Test
     public void testGetCarrierNameWithInvalidSubId() {
-        when(mSpecifiedTm.getSimCarrierIdName()).thenReturn(TEST_CARRIER_NAME);
+        when(mSpecifiedTm.getSimOperatorName()).thenReturn(TEST_CARRIER_NAME);
         assertNull(getCarrierNameForSubId(mMockContext,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID));
     }
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java
index adb538bb4..87d352d56 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java
@@ -106,6 +106,7 @@ public class WifiPickerTrackerTest {
     private static final long START_MILLIS = 123_456_789;
 
     private static final long MAX_SCAN_AGE_MILLIS = 15_000;
+    private static final long MAX_SCAN_AGE_FOR_FAILED_SCAN_MS = 5 * 60 * 1000;
     private static final long SCAN_INTERVAL_MILLIS = 10_000;
 
     @Mock private WifiTrackerInjector mInjector;
@@ -428,8 +429,7 @@ public class WifiPickerTrackerTest {
         final List<WifiEntry> previousEntries = wifiPickerTracker.getWifiEntries();
 
         // Advance the clock to time out old entries and simulate failed scan
-        when(mMockClock.millis())
-                .thenReturn(START_MILLIS + MAX_SCAN_AGE_MILLIS + SCAN_INTERVAL_MILLIS);
+        when(mMockClock.millis()).thenReturn(START_MILLIS + MAX_SCAN_AGE_FOR_FAILED_SCAN_MS);
         mBroadcastReceiverCaptor.getValue().onReceive(mMockContext,
                 new Intent(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
                         .putExtra(WifiManager.EXTRA_RESULTS_UPDATED, false));
```

