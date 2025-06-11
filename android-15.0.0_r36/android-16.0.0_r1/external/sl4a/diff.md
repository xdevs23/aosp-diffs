```diff
diff --git a/Common/src/com/googlecode/android_scripting/facade/BatteryManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/BatteryManagerFacade.java
index 7f6791ed..19db4706 100644
--- a/Common/src/com/googlecode/android_scripting/facade/BatteryManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/BatteryManagerFacade.java
@@ -135,7 +135,7 @@ public class BatteryManagerFacade extends RpcReceiver {
       IntentFilter filter = new IntentFilter();
       filter.addAction(Intent.ACTION_BATTERY_CHANGED);
       mReceiver = new BatteryStateListener(mEventFacade);
-      mService.registerReceiver(mReceiver, filter);
+      mService.registerReceiver(mReceiver, filter, Context.RECEIVER_EXPORTED);
     }
   }
 
diff --git a/Common/src/com/googlecode/android_scripting/facade/ConnectivityManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/ConnectivityManagerFacade.java
index f9fffb16..c2f7d606 100644
--- a/Common/src/com/googlecode/android_scripting/facade/ConnectivityManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/ConnectivityManagerFacade.java
@@ -428,7 +428,7 @@ public class ConnectivityManagerFacade extends RpcReceiver {
         if (!mTrackingConnectivityStateChange) {
             mTrackingConnectivityStateChange = true;
             mContext.registerReceiver(mConnectivityReceiver,
-                    new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION));
+                    new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION), Context.RECEIVER_EXPORTED);
         }
     }
 
diff --git a/Common/src/com/googlecode/android_scripting/facade/EventFacade.java b/Common/src/com/googlecode/android_scripting/facade/EventFacade.java
index 7a4a77b3..d0958656 100644
--- a/Common/src/com/googlecode/android_scripting/facade/EventFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/EventFacade.java
@@ -104,7 +104,7 @@ public class EventFacade extends RpcReceiver {
 
         BroadcastListener b = new BroadcastListener(this, enqueue.booleanValue());
         IntentFilter c = new IntentFilter(category);
-        mContext.registerReceiver(b, c);
+        mContext.registerReceiver(b, c, Context.RECEIVER_EXPORTED);
         mBroadcastListeners.put(category, b);
 
         return true;
diff --git a/Common/src/com/googlecode/android_scripting/facade/NfcManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/NfcManagerFacade.java
index a87bd4d6..b776eb2f 100644
--- a/Common/src/com/googlecode/android_scripting/facade/NfcManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/NfcManagerFacade.java
@@ -81,7 +81,7 @@ public class NfcManagerFacade extends RpcReceiver {
 
     @Rpc(description = "Start tracking NFC hardware state changes.")
     public void nfcStartTrackingStateChange() {
-        mService.registerReceiver(mNfcStateReceiver, mStateChangeFilter);
+        mService.registerReceiver(mNfcStateReceiver, mStateChangeFilter, Context.RECEIVER_EXPORTED);
         mTrackingStateChange = true;
     }
 
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothA2dpFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothA2dpFacade.java
index 2c200d3e..5586f5e1 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothA2dpFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothA2dpFacade.java
@@ -72,7 +72,7 @@ public class BluetoothA2dpFacade extends RpcReceiver {
                 BluetoothProfile.A2DP);
 
         mService.registerReceiver(mBluetoothA2dpReceiver,
-                          new IntentFilter(BluetoothA2dp.ACTION_CODEC_CONFIG_CHANGED));
+                          new IntentFilter(BluetoothA2dp.ACTION_CODEC_CONFIG_CHANGED), Context.RECEIVER_EXPORTED);
     }
 
     class A2dpServiceListener implements BluetoothProfile.ServiceListener {
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothBroadcastHelper.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothBroadcastHelper.java
index aab5e63b..a41de6e7 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothBroadcastHelper.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothBroadcastHelper.java
@@ -47,7 +47,7 @@ public class BluetoothBroadcastHelper {
         for (String action : mActions) {
             mIntentFilter.addAction(action);
         }
-        mContext.registerReceiver(mReceiver, mIntentFilter);
+        mContext.registerReceiver(mReceiver, mIntentFilter, Context.RECEIVER_EXPORTED);
     }
 
     /**
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothConnectionFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothConnectionFacade.java
index 33a667e3..2cbd5e1f 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothConnectionFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothConnectionFacade.java
@@ -407,15 +407,15 @@ public class BluetoothConnectionFacade extends RpcReceiver {
                     String deviceID) {
         if (!mDeviceMonitorList.contains(deviceID)) {
             ConnectStateChangeReceiver receiver = new ConnectStateChangeReceiver(deviceID);
-            mService.registerReceiver(receiver, mA2dpStateChangeFilter);
-            mService.registerReceiver(receiver, mA2dpSinkStateChangeFilter);
-            mService.registerReceiver(receiver, mHidStateChangeFilter);
-            mService.registerReceiver(receiver, mHspStateChangeFilter);
-            mService.registerReceiver(receiver, mHfpClientStateChangeFilter);
-            mService.registerReceiver(receiver, mPbapClientStateChangeFilter);
-            mService.registerReceiver(receiver, mPanStateChangeFilter);
-            mService.registerReceiver(receiver, mMapClientStateChangeFilter);
-            mService.registerReceiver(receiver, mMapStateChangeFilter);
+            mService.registerReceiver(receiver, mA2dpStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mA2dpSinkStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mHidStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mHspStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mHfpClientStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mPbapClientStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mPanStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mMapClientStateChangeFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(receiver, mMapStateChangeFilter, Context.RECEIVER_EXPORTED);
             listeningDevices.put("StateChangeListener:" + deviceID, receiver);
         }
     }
@@ -427,7 +427,7 @@ public class BluetoothConnectionFacade extends RpcReceiver {
      * @param deviceID Name (String) of the device to connect to
      */
     private void connectProfile(BluetoothDevice device, String deviceID) {
-        mService.registerReceiver(mPairingHelper, mPairingFilter);
+        mService.registerReceiver(mPairingHelper, mPairingFilter, Context.RECEIVER_EXPORTED);
         ParcelUuid[] deviceUuids = device.getUuids();
         Log.d("Device uuid is " + Arrays.toString(deviceUuids));
         if (deviceUuids == null) {
@@ -536,7 +536,7 @@ public class BluetoothConnectionFacade extends RpcReceiver {
         Boolean autoConfirm) {
         Log.d("Staring pairing helper");
         mPairingHelper.setAutoConfirm(autoConfirm);
-        mService.registerReceiver(mPairingHelper, mPairingFilter);
+        mService.registerReceiver(mPairingHelper, mPairingFilter, Context.RECEIVER_EXPORTED);
     }
 
     @Rpc(description = "Return a list of devices connected through bluetooth")
@@ -577,14 +577,14 @@ public class BluetoothConnectionFacade extends RpcReceiver {
     @Rpc(description = "Bluetooth init Bond by Mac Address")
     public boolean bluetoothBond(@RpcParameter(name = "macAddress") String macAddress) {
         mContext.registerReceiver(new BondBroadcastReceiver(),
-                new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED));
+                new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         return mBluetoothAdapter.getRemoteDevice(macAddress).createBond();
     }
 
     @Rpc(description = "Bluetooth init LE Bond by Mac Address")
     public boolean bluetoothLeBond(@RpcParameter(name = "macAddress") String macAddress) {
         mContext.registerReceiver(new BondBroadcastReceiver(),
-                new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED));
+                new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         return mBluetoothAdapter.getRemoteDevice(macAddress).createBond(BluetoothDevice.TRANSPORT_LE);
     }
 
@@ -676,7 +676,7 @@ public class BluetoothConnectionFacade extends RpcReceiver {
                 .setRandomizerHash(hexStringToByteArray(r))
                 .build();
         mContext.registerReceiver(new BondBroadcastReceiver(),
-                new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED));
+                new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         return remoteDevice.createBondOutOfBand(BluetoothDevice.TRANSPORT_LE, p192, p256);
     }
 
@@ -737,7 +737,7 @@ public class BluetoothConnectionFacade extends RpcReceiver {
         }
         DiscoverConnectReceiver receiver = new DiscoverConnectReceiver(deviceID);
         listeningDevices.put("Connect" + deviceID, receiver);
-        mService.registerReceiver(receiver, mDiscoverConnectFilter);
+        mService.registerReceiver(receiver, mDiscoverConnectFilter, Context.RECEIVER_EXPORTED);
         return mBluetoothAdapter.startDiscovery();
     }
 
@@ -762,7 +762,7 @@ public class BluetoothConnectionFacade extends RpcReceiver {
             mService.unregisterReceiver(listeningDevices.remove("Bond" + deviceID));
         }
         listeningDevices.put("Bond" + deviceID, receiver);
-        mService.registerReceiver(receiver, mBondFilter);
+        mService.registerReceiver(receiver, mBondFilter, Context.RECEIVER_EXPORTED);
         Log.d("Start discovery for bonding.");
         return mBluetoothAdapter.startDiscovery();
     }
@@ -778,7 +778,7 @@ public class BluetoothConnectionFacade extends RpcReceiver {
             BluetoothDevice mDevice = BluetoothFacade.getDevice(
                     mBluetoothAdapter.getBondedDevices(), deviceID);
             mContext.registerReceiver(new BondBroadcastReceiver(),
-                    new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED));
+                    new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED), Context.RECEIVER_EXPORTED);
             return mDevice.removeBond();
         } catch (Exception e) {
             Log.d("Failed to find the device by deviceId");
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothDiscoveryHelper.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothDiscoveryHelper.java
index b1b14d23..6959ee83 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothDiscoveryHelper.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothDiscoveryHelper.java
@@ -101,7 +101,7 @@ public class BluetoothDiscoveryHelper {
 
         IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_FOUND);
         filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
-        mContext.registerReceiver(mReceiver, filter);
+        mContext.registerReceiver(mReceiver, filter, Context.RECEIVER_EXPORTED);
 
         if (!bluetoothAdapter.isEnabled()) {
             bluetoothAdapter.enable();
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothFacade.java
index 68600ebc..088b1e51 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothFacade.java
@@ -351,7 +351,7 @@ public class BluetoothFacade extends RpcReceiver {
             @RpcDefault("false")
             Boolean prompt) {
         mService.registerReceiver(mStateReceiver,
-                                  new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED));
+                                  new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         if (enabled == null) {
             enabled = !bluetoothCheckState();
         }
@@ -368,7 +368,7 @@ public class BluetoothFacade extends RpcReceiver {
          returns = "true on success, false on error")
     public Boolean bluetoothStartDiscovery() {
         DiscoveredDevices.clear();
-        mService.registerReceiver(mDiscoveryReceiver, discoveryFilter);
+        mService.registerReceiver(mDiscoveryReceiver, discoveryFilter, Context.RECEIVER_EXPORTED);
         return mBluetoothAdapter.startDiscovery();
     }
 
@@ -502,21 +502,21 @@ public class BluetoothFacade extends RpcReceiver {
     @Rpc(description = "Enables BLE functionalities.")
     public boolean bluetoothEnableBLE() {
         mService.registerReceiver(mBleStateReceiver,
-            new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED));
+            new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         return mBluetoothAdapter.enableBLE();
     }
 
     @Rpc(description = "Disables BLE functionalities.")
     public boolean bluetoothDisableBLE() {
         mService.registerReceiver(mBleStateReceiver,
-            new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED));
+            new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         return mBluetoothAdapter.disableBLE();
     }
 
     @Rpc(description = "Listen for a Bluetooth LE State Change.")
     public boolean bluetoothListenForBleStateChange() {
         mService.registerReceiver(mBleStateReceiver,
-            new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED));
+            new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         return true;
     }
 
@@ -535,7 +535,7 @@ public class BluetoothFacade extends RpcReceiver {
             }
             mMultiStateReceiver = new BluetoothStateReceiver(true);
             mService.registerReceiver(mMultiStateReceiver,
-                    new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED));
+                    new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), Context.RECEIVER_EXPORTED);
         }
         return true;
     }
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHidFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHidFacade.java
index 968e471c..cfb2a711 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHidFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHidFacade.java
@@ -74,7 +74,7 @@ public class BluetoothHidFacade extends RpcReceiver {
         pkgFilter.addAction(BluetoothHidHost.ACTION_REPORT);
         pkgFilter.addAction(BluetoothHidHost.ACTION_VIRTUAL_UNPLUG_STATUS);
         pkgFilter.addAction(BluetoothHidHost.ACTION_IDLE_TIME_CHANGED);
-        mService.registerReceiver(mHidServiceBroadcastReceiver, pkgFilter);
+        mService.registerReceiver(mHidServiceBroadcastReceiver, pkgFilter, Context.RECEIVER_EXPORTED);
         Log.d(HidServiceBroadcastReceiver.TAG + " registered");
         mEventFacade = manager.getReceiver(EventFacade.class);
     }
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHspFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHspFacade.java
index 58be8d7c..0a21bcd5 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHspFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothHspFacade.java
@@ -344,30 +344,6 @@ public class BluetoothHspFacade extends RpcReceiver {
         return sHspProfile.isInbandRingingEnabled();
     }
 
-    /**
-     * Send a CLCC response from Sl4a (experimental).
-     *
-     * @param index the index of the call
-     * @param direction the direction of the call
-     * @param status the status of the call
-     * @param mode the mode
-     * @param mpty the mpty value
-     * @param number the phone number
-     * @param type the type
-     */
-    @Rpc(description = "Send generic clcc response.")
-    public void bluetoothHspClccResponse(
-            @RpcParameter(name = "index", description = "") Integer index,
-            @RpcParameter(name = "direction", description = "") Integer direction,
-            @RpcParameter(name = "status", description = "") Integer status,
-            @RpcParameter(name = "mode", description = "") Integer mode,
-            @RpcParameter(name = "mpty", description = "") Boolean mpty,
-            @RpcParameter(name = "number", description = "") String number,
-            @RpcParameter(name = "type", description = "") Integer type
-                  ) {
-        sHspProfile.clccResponse(index, direction, status, mode, mpty, number, type);
-    }
-
     @Override
     public void shutdown() {
     }
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothLeScanFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothLeScanFacade.java
index 290cacf0..0a3722ee 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothLeScanFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothLeScanFacade.java
@@ -282,7 +282,7 @@ public class BluetoothLeScanFacade extends RpcReceiver {
         }
         Log.d("Registering receiver");
         mService.registerReceiver(new TestBroadcastReceiver(),
-                new IntentFilter(ScanBroadcastReceiver.ACTION_FOUND_SIDESTEP));
+                new IntentFilter(ScanBroadcastReceiver.ACTION_FOUND_SIDESTEP), Context.RECEIVER_EXPORTED);
         Log.d("Starting Scan");
         mScanner.startScan(mScanFilters, mScanSettings, createPendingIntent());
     }
diff --git a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothMapClientFacade.java b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothMapClientFacade.java
index e0e80e04..e037b0f1 100644
--- a/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothMapClientFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/bluetooth/BluetoothMapClientFacade.java
@@ -82,7 +82,7 @@ public class BluetoothMapClientFacade extends RpcReceiver {
                 BluetoothMapClient.ACTION_MESSAGE_SENT_SUCCESSFULLY);
         intentFilter.addAction(
                 BluetoothMapClient.ACTION_MESSAGE_DELIVERED_SUCCESSFULLY);
-        mService.registerReceiver(mNotificationReceiver, intentFilter);
+        mService.registerReceiver(mNotificationReceiver, intentFilter, Context.RECEIVER_EXPORTED);
         Log.d("notification receiver registered");
     }
 
diff --git a/Common/src/com/googlecode/android_scripting/facade/media/MediaScannerFacade.java b/Common/src/com/googlecode/android_scripting/facade/media/MediaScannerFacade.java
index 16fd46f2..b96e2809 100644
--- a/Common/src/com/googlecode/android_scripting/facade/media/MediaScannerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/media/MediaScannerFacade.java
@@ -69,7 +69,7 @@ public class MediaScannerFacade extends RpcReceiver {
         mService.sendBroadcast(new Intent(Intent.ACTION_MEDIA_MOUNTED,
                                Uri.parse("file://" + Environment.getExternalStorageDirectory())));
         mService.registerReceiver(mReceiver,
-                                  new IntentFilter(Intent.ACTION_MEDIA_SCANNER_FINISHED));
+                                  new IntentFilter(Intent.ACTION_MEDIA_SCANNER_FINISHED), Context.RECEIVER_EXPORTED);
     }
 
     @Rpc(description = "Scan for a media file.")
diff --git a/Common/src/com/googlecode/android_scripting/facade/telephony/SmsFacade.java b/Common/src/com/googlecode/android_scripting/facade/telephony/SmsFacade.java
index 1c8724f2..c3215f21 100644
--- a/Common/src/com/googlecode/android_scripting/facade/telephony/SmsFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/telephony/SmsFacade.java
@@ -185,8 +185,8 @@ public class SmsFacade extends RpcReceiver {
         IntentFilter mmsFilter = new IntentFilter(MMS_MESSAGE_SENT_ACTION);
 
         synchronized (lock) {
-            mService.registerReceiver(mSmsSendListener, smsFilter);
-            mService.registerReceiver(mMmsSendListener, mmsFilter);
+            mService.registerReceiver(mSmsSendListener, smsFilter, Context.RECEIVER_EXPORTED);
+            mService.registerReceiver(mMmsSendListener, mmsFilter, Context.RECEIVER_EXPORTED);
             mSentReceiversRegistered = true;
         }
 
@@ -276,7 +276,7 @@ public class SmsFacade extends RpcReceiver {
     @Rpc(description = "Starts tracking incoming SMS.")
     public void smsStartTrackingIncomingSmsMessage() {
         mService.registerReceiver(mSmsIncomingListener,
-                new IntentFilter(Intents.SMS_RECEIVED_ACTION));
+                new IntentFilter(Intents.SMS_RECEIVED_ACTION), Context.RECEIVER_EXPORTED);
         mListeningIncomingSms = true;
     }
 
@@ -304,7 +304,7 @@ public class SmsFacade extends RpcReceiver {
         IntentFilter mmsReceived = new IntentFilter(Intents.MMS_DOWNLOADED_ACTION);
         mmsReceived.addAction(Intents.WAP_PUSH_RECEIVED_ACTION);
         mmsReceived.addAction(Intents.DATA_SMS_RECEIVED_ACTION);
-        mService.registerReceiver(mMmsIncomingListener, mmsReceived);
+        mService.registerReceiver(mMmsIncomingListener, mmsReceived, Context.RECEIVER_EXPORTED);
         mListeningIncomingMms = true;
     }
 
@@ -450,7 +450,7 @@ public class SmsFacade extends RpcReceiver {
 
             mEmergencyCBMessage = new IntentFilter(EMERGENCY_CB_MESSAGE_RECEIVED_ACTION);
             mService.registerReceiver(mGsmEmergencyCBMessageListener,
-                    mEmergencyCBMessage);
+                    mEmergencyCBMessage, Context.RECEIVER_EXPORTED);
             mGsmEmergencyCBListenerRegistered = true;
         }
     }
@@ -480,7 +480,7 @@ public class SmsFacade extends RpcReceiver {
             }
             mEmergencyCBMessage = new IntentFilter(EMERGENCY_CB_MESSAGE_RECEIVED_ACTION);
             mService.registerReceiver(mCdmaEmergencyCBMessageListener,
-                    mEmergencyCBMessage);
+                    mEmergencyCBMessage, Context.RECEIVER_EXPORTED);
             mCdmaEmergencyCBListenerRegistered = true;
         }
     }
diff --git a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiAwareManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiAwareManagerFacade.java
index 85a72a76..e0f627a5 100644
--- a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiAwareManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiAwareManagerFacade.java
@@ -355,7 +355,7 @@ public class WifiAwareManagerFacade extends RpcReceiver {
 
         mStateChangedReceiver = new WifiAwareStateChangedReceiver();
         IntentFilter filter = new IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);
-        mService.registerReceiver(mStateChangedReceiver, filter);
+        mService.registerReceiver(mStateChangedReceiver, filter, Context.RECEIVER_EXPORTED);
     }
 
     @Override
diff --git a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiManagerFacade.java
index 2bc1f228..4a932dbf 100755
--- a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiManagerFacade.java
@@ -1887,7 +1887,7 @@ public class WifiManagerFacade extends RpcReceiver {
 
     @Rpc(description = "Starts a scan for Wifi access points.", returns = "True if the scan was initiated successfully.")
     public Boolean wifiStartScan() {
-        mService.registerReceiver(mScanResultsAvailableReceiver, mScanFilter);
+        mService.registerReceiver(mScanResultsAvailableReceiver, mScanFilter, Context.RECEIVER_EXPORTED);
         return mWifi.startScan();
     }
 
@@ -1910,7 +1910,7 @@ public class WifiManagerFacade extends RpcReceiver {
 
     @Rpc(description = "Start listening for wifi state change related broadcasts.")
     public void wifiStartTrackingStateChange() {
-        mService.registerReceiver(mStateChangeReceiver, mStateChangeFilter);
+        mService.registerReceiver(mStateChangeReceiver, mStateChangeFilter, Context.RECEIVER_EXPORTED);
         mTrackingWifiStateChange = true;
     }
 
@@ -1924,7 +1924,7 @@ public class WifiManagerFacade extends RpcReceiver {
 
     @Rpc(description = "Start listening for tether state change related broadcasts.")
     public void wifiStartTrackingTetherStateChange() {
-        mService.registerReceiver(mTetherStateReceiver, mTetherFilter);
+        mService.registerReceiver(mTetherStateReceiver, mTetherFilter, Context.RECEIVER_EXPORTED);
         mTrackingTetherStateChange = true;
     }
 
@@ -1939,7 +1939,7 @@ public class WifiManagerFacade extends RpcReceiver {
     @Rpc(description = "Start listening for network suggestion change related broadcasts.")
     public void wifiStartTrackingNetworkSuggestionStateChange() {
         mService.registerReceiver(
-                mNetworkSuggestionStateChangeReceiver, mNetworkSuggestionStateChangeFilter);
+                mNetworkSuggestionStateChangeReceiver, mNetworkSuggestionStateChangeFilter, Context.RECEIVER_EXPORTED);
         mTrackingNetworkSuggestionStateChange = true;
     }
 
diff --git a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java
index 0805350f..e06f5ac2 100644
--- a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java
@@ -566,7 +566,7 @@ public class WifiP2pManagerFacade extends RpcReceiver {
 
     @Rpc(description = "Initialize wifi p2p. Must be called before any other p2p functions.")
     public void wifiP2pInitialize() {
-        mService.registerReceiver(mP2pStateChangedReceiver, mStateChangeFilter);
+        mService.registerReceiver(mP2pStateChangedReceiver, mStateChangeFilter, Context.RECEIVER_EXPORTED);
         mChannel = mP2p.initialize(mService, mService.getMainLooper(), null);
     }
 
diff --git a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiRtt2ManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiRtt2ManagerFacade.java
index 7c1cc008..e3877513 100644
--- a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiRtt2ManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiRtt2ManagerFacade.java
@@ -74,7 +74,7 @@ public class WifiRtt2ManagerFacade extends RpcReceiver {
 
         mStateChangedReceiver = new StateChangedReceiver();
         IntentFilter filter = new IntentFilter(WifiRttManager.ACTION_WIFI_RTT_STATE_CHANGED);
-        mService.registerReceiver(mStateChangedReceiver, filter);
+        mService.registerReceiver(mStateChangedReceiver, filter, Context.RECEIVER_EXPORTED);
     }
 
     @Override
diff --git a/Common/src/com/googlecode/android_scripting/interpreter/InterpreterConfiguration.java b/Common/src/com/googlecode/android_scripting/interpreter/InterpreterConfiguration.java
index 5a483abf..97d1ab5b 100644
--- a/Common/src/com/googlecode/android_scripting/interpreter/InterpreterConfiguration.java
+++ b/Common/src/com/googlecode/android_scripting/interpreter/InterpreterConfiguration.java
@@ -222,7 +222,7 @@ public class InterpreterConfiguration {
     filter.addAction(Intent.ACTION_PACKAGE_REPLACED);
     filter.addDataScheme("package");
     mListener = new InterpreterListener(mContext);
-    mContext.registerReceiver(mListener, filter);
+    mContext.registerReceiver(mListener, filter, Context.RECEIVER_EXPORTED);
   }
 
   public void startDiscovering() {
diff --git a/OWNERS b/OWNERS
index daff27be..f6d9a100 100644
--- a/OWNERS
+++ b/OWNERS
@@ -9,3 +9,4 @@ jpawlowski@google.com
 krisr@google.com
 siyuanh@google.com
 xianyuanjia@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

