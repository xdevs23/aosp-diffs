```diff
diff --git a/service/src/com/android/server/bluetooth/BluetoothManagerService.java b/service/src/com/android/server/bluetooth/BluetoothManagerService.java
index d7d7997e9d..cb7076d077 100644
--- a/service/src/com/android/server/bluetooth/BluetoothManagerService.java
+++ b/service/src/com/android/server/bluetooth/BluetoothManagerService.java
@@ -674,11 +674,7 @@ class BluetoothManagerService {
             return Unit.INSTANCE;
         }
         clearBleApps();
-        try {
-            mAdapter.unregAllGattClient(mContext.getAttributionSource());
-        } catch (RemoteException e) {
-            Log.e(TAG, "onBleScanDisabled: unregAllGattClient failed", e);
-        }
+
         if (mState.oneOf(STATE_BLE_ON)) {
             Log.i(TAG, "onBleScanDisabled: Shutting down BLE_ON mode");
             bleOnToOff();
```

