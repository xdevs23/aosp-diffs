```diff
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper.java
index 4a2436e..ae5d24e 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper.java
@@ -16,6 +16,9 @@
 
 package android.telephony.satellite.wrapper;
 
+import android.telephony.CarrierConfigManager;
+import android.telephony.ServiceState;
+
 /** Interface for carrier roaming non-terrestrial network listener. */
 public interface CarrierRoamingNtnModeListenerWrapper {
     /**
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper2.java b/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper2.java
new file mode 100644
index 0000000..c180817
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/CarrierRoamingNtnModeListenerWrapper2.java
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.telephony.satellite.wrapper;
+
+import android.telephony.CarrierConfigManager;
+import android.telephony.ServiceState;
+
+/** Interface for carrier roaming non-terrestrial network listener. */
+public interface CarrierRoamingNtnModeListenerWrapper2 {
+    /**
+     * Callback invoked when carrier roaming non-terrestrial network mode changes.
+     *
+     * @param active {@code true} If the device is connected to carrier roaming
+     *                           non-terrestrial network or was connected within the
+     *                           {CarrierConfigManager
+     *                           #KEY_SATELLITE_CONNECTION_HYSTERESIS_SEC_INT} duration,
+     *                           {code false} otherwise.
+     */
+    void onCarrierRoamingNtnModeChanged(boolean active);
+
+    /**
+     * Callback invoked when eligibility to connect to carrier roaming non-terrestrial network
+     * changes.
+     *
+     * @param eligible {@code true} when the device is eligible for satellite
+     * communication if all the following conditions are met:
+     * <ul>
+     * <li>Any subscription on the device supports P2P satellite messaging which is defined by
+     * {@link CarrierConfigManager#KEY_SATELLITE_ATTACH_SUPPORTED_BOOL} </li>
+     * <li>{@link CarrierConfigManager#KEY_CARRIER_ROAMING_NTN_CONNECT_TYPE_INT} set to
+     * {@link CarrierConfigManager#CARRIER_ROAMING_NTN_CONNECT_MANUAL} </li>
+     * <li>The device is in {@link ServiceState#STATE_OUT_OF_SERVICE}, not connected to Wi-Fi,
+     * and the hysteresis timer defined by {@link CarrierConfigManager
+     * #KEY_CARRIER_SUPPORTED_SATELLITE_NOTIFICATION_HYSTERESIS_SEC_INT} is expired. </li>
+     * </ul>
+     */
+    default void onCarrierRoamingNtnEligibleStateChanged(boolean eligible) {}
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
index aab002a..e4f38f9 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
@@ -48,6 +48,8 @@ import android.telephony.satellite.SatelliteManager;
 import android.telephony.satellite.SatelliteModemStateCallback;
 import android.telephony.satellite.SatelliteProvisionStateCallback;
 import android.telephony.satellite.SatelliteSessionStats;
+import android.telephony.satellite.SatelliteSubscriberInfo;
+import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
 import android.telephony.satellite.SatelliteSupportedStateCallback;
 import android.telephony.satellite.SatelliteTransmissionUpdateCallback;
 
@@ -56,11 +58,13 @@ import com.android.telephony.Rlog;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
+import java.lang.reflect.Method;
 import java.time.Duration;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
+import java.util.Objects;
 import java.util.Set;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.Executor;
@@ -86,10 +90,18 @@ public class SatelliteManagerWrapper {
           SatelliteModemStateCallback> sSatelliteModemStateCallbackWrapperMap =
           new ConcurrentHashMap<>();
 
+  private static final ConcurrentHashMap<SatelliteModemStateCallbackWrapper2,
+          SatelliteModemStateCallback> sSatelliteModemStateCallbackWrapperMap2 =
+          new ConcurrentHashMap<>();
+
   private static final ConcurrentHashMap<
           SatelliteTransmissionUpdateCallbackWrapper, SatelliteTransmissionUpdateCallback>
       sSatelliteTransmissionUpdateCallbackWrapperMap = new ConcurrentHashMap<>();
 
+  private static final ConcurrentHashMap<
+          SatelliteTransmissionUpdateCallbackWrapper2, SatelliteTransmissionUpdateCallback>
+          sSatelliteTransmissionUpdateCallbackWrapperMap2 = new ConcurrentHashMap<>();
+
   private static final ConcurrentHashMap<
           NtnSignalStrengthCallbackWrapper, NtnSignalStrengthCallback>
       sNtnSignalStrengthCallbackWrapperMap = new ConcurrentHashMap<>();
@@ -106,6 +118,10 @@ public class SatelliteManagerWrapper {
           CarrierRoamingNtnModeListener>
           sCarrierRoamingNtnModeListenerWrapperMap = new ConcurrentHashMap<>();
 
+  private static final ConcurrentHashMap<CarrierRoamingNtnModeListenerWrapper2,
+          CarrierRoamingNtnModeListener>
+          sCarrierRoamingNtnModeListenerWrapperMap2 = new ConcurrentHashMap<>();
+
   private static final ConcurrentHashMap<SatelliteCommunicationAllowedStateCallbackWrapper,
           SatelliteCommunicationAllowedStateCallback>
           sSatelliteCommunicationAllowedStateCallbackWrapperMap = new ConcurrentHashMap<>();
@@ -154,6 +170,11 @@ public class SatelliteManagerWrapper {
    * is the last message to emergency service provider indicating no more help is needed.
    */
   public static final int DATAGRAM_TYPE_LAST_SOS_MESSAGE_NO_HELP_NEEDED = 5;
+  /**
+   * Datagram type indicating that the message to be sent or received is of type SMS.
+   */
+  public static final int DATAGRAM_TYPE_SMS = 6;
+
   /** @hide */
   @IntDef(
       prefix = "DATAGRAM_TYPE_",
@@ -163,7 +184,8 @@ public class SatelliteManagerWrapper {
               DATAGRAM_TYPE_LOCATION_SHARING,
               DATAGRAM_TYPE_KEEP_ALIVE,
               DATAGRAM_TYPE_LAST_SOS_MESSAGE_STILL_NEED_HELP,
-              DATAGRAM_TYPE_LAST_SOS_MESSAGE_NO_HELP_NEEDED
+              DATAGRAM_TYPE_LAST_SOS_MESSAGE_NO_HELP_NEEDED,
+              DATAGRAM_TYPE_SMS
       })
   @Retention(RetentionPolicy.SOURCE)
   public @interface DatagramType {}
@@ -393,6 +415,28 @@ public class SatelliteManagerWrapper {
   public static final int SATELLITE_RESULT_MODEM_BUSY = 22;
   /** Telephony process is not currently available or satellite is not supported. */
   public static final int SATELLITE_RESULT_ILLEGAL_STATE = 23;
+  /**
+   * Telephony framework timeout to receive ACK or response from the satellite modem after
+   * sending a request to the modem.
+   */
+  public static final int SATELLITE_RESULT_MODEM_TIMEOUT = 24;
+
+  /**
+   * Telephony framework needs to access the current location of the device to perform the
+   * request. However, location in the settings is disabled by users.
+   */
+  public static final int SATELLITE_RESULT_LOCATION_DISABLED = 25;
+
+  /**
+   * Telephony framework needs to access the current location of the device to perform the
+   * request. However, Telephony fails to fetch the current location from location service.
+   */
+  public static final int SATELLITE_RESULT_LOCATION_NOT_AVAILABLE = 26;
+
+  /**
+   * Emergency call is in progress.
+   */
+  public static final int SATELLITE_RESULT_EMERGENCY_CALL_IN_PROGRESS = 27;
 
   /** @hide */
   @IntDef(
@@ -421,7 +465,11 @@ public class SatelliteManagerWrapper {
         SATELLITE_RESULT_NOT_SUPPORTED,
         SATELLITE_RESULT_REQUEST_IN_PROGRESS,
         SATELLITE_RESULT_MODEM_BUSY,
-        SATELLITE_RESULT_ILLEGAL_STATE
+        SATELLITE_RESULT_ILLEGAL_STATE,
+        SATELLITE_RESULT_MODEM_TIMEOUT,
+        SATELLITE_RESULT_LOCATION_DISABLED,
+        SATELLITE_RESULT_LOCATION_NOT_AVAILABLE,
+        SATELLITE_RESULT_EMERGENCY_CALL_IN_PROGRESS
       })
   @Retention(RetentionPolicy.SOURCE)
   public @interface SatelliteResult {}
@@ -661,6 +709,66 @@ public class SatelliteManagerWrapper {
     mSatelliteManager.startTransmissionUpdates(executor, resultListener, internalCallback);
   }
 
+  /**
+   * Start receiving satellite transmission updates. This can be called by the pointing UI when the
+   * user starts pointing to the satellite. Modem should continue to report the pointing input as
+   * the device or satellite moves. Satellite transmission updates are started only on {@link
+   * #SATELLITE_RESULT_SUCCESS}. All other results indicate that this operation failed.
+   * Once satellite transmission updates begin, position and datagram transfer state updates
+   * will be sent through {@link SatelliteTransmissionUpdateCallback}.
+   */
+  public void startTransmissionUpdates2(
+          @NonNull @CallbackExecutor Executor executor,
+          @SatelliteResult @NonNull Consumer<Integer> resultListener,
+          @NonNull SatelliteTransmissionUpdateCallbackWrapper2 callback) {
+
+    SatelliteTransmissionUpdateCallback internalCallback =
+            new SatelliteTransmissionUpdateCallback() {
+
+              @Override
+              public void onSendDatagramStateChanged(
+                      @SatelliteDatagramTransferState int state,
+                      int sendPendingCount,
+                      @SatelliteResult int errorCode) {
+                callback.onSendDatagramStateChanged(state, sendPendingCount, errorCode);
+              }
+
+              @Override
+              public void onSendDatagramStateChanged(
+                      @SatelliteManager.DatagramType int datagramType,
+                      @SatelliteDatagramTransferState int state,
+                      int sendPendingCount,
+                      @SatelliteResult int errorCode) {
+                callback.onSendDatagramStateChanged(
+                        datagramType, state, sendPendingCount, errorCode);
+              }
+
+              @Override
+              public void onReceiveDatagramStateChanged(
+                      @SatelliteDatagramTransferState int state,
+                      int receivePendingCount,
+                      @SatelliteResult int errorCode) {
+                callback.onReceiveDatagramStateChanged(state, receivePendingCount, errorCode);
+              }
+
+              @Override
+              public void onSatellitePositionChanged(@NonNull PointingInfo pointingInfo) {
+                callback.onSatellitePositionChanged(
+                        new PointingInfoWrapper(
+                                pointingInfo.getSatelliteAzimuthDegrees(),
+                                pointingInfo.getSatelliteElevationDegrees()));
+              }
+
+              @Override
+              public void onSendDatagramRequested(@SatelliteManager.DatagramType int datagramType) {
+                callback.onSendDatagramRequested(datagramType);
+              }
+            };
+    sSatelliteTransmissionUpdateCallbackWrapperMap2.put(callback, internalCallback);
+
+    mSatelliteManager.startTransmissionUpdates(executor, resultListener, internalCallback);
+  }
+
   /**
    * Stop receiving satellite transmission updates. This can be called by the pointing UI when the
    * user stops pointing to the satellite. Satellite transmission updates are stopped and the
@@ -672,13 +780,31 @@ public class SatelliteManagerWrapper {
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
     SatelliteTransmissionUpdateCallback internalCallback =
-        sSatelliteTransmissionUpdateCallbackWrapperMap.get(callback);
+        sSatelliteTransmissionUpdateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.stopTransmissionUpdates(
           internalCallback, executor, resultListener);
     }
   }
 
+  /**
+   * Stop receiving satellite transmission updates. This can be called by the pointing UI when the
+   * user stops pointing to the satellite. Satellite transmission updates are stopped and the
+   * callback is unregistered only on {@link #SATELLITE_RESULT_SUCCESS}. All other results that this
+   * operation failed.
+   */
+  public void stopTransmissionUpdates2(
+          @NonNull SatelliteTransmissionUpdateCallbackWrapper2 callback,
+          @NonNull @CallbackExecutor Executor executor,
+          @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    SatelliteTransmissionUpdateCallback internalCallback =
+            sSatelliteTransmissionUpdateCallbackWrapperMap2.remove(callback);
+    if (internalCallback != null) {
+      mSatelliteManager.stopTransmissionUpdates(
+              internalCallback, executor, resultListener);
+    }
+  }
+
   /**
    * Provision the device with a satellite provider. This is needed if the provider allows dynamic
    * registration.
@@ -717,6 +843,13 @@ public class SatelliteManagerWrapper {
           public void onSatelliteProvisionStateChanged(boolean provisioned) {
             callback.onSatelliteProvisionStateChanged(provisioned);
           }
+
+          @Override
+          public void onSatelliteSubscriptionProvisionStateChanged(@NonNull
+          List<SatelliteSubscriberProvisionStatus> satelliteSubscriberProvisionStatus) {
+            callback.onSatelliteSubscriptionProvisionStateChanged(
+                    transformToWrapperList(satelliteSubscriberProvisionStatus));
+          }
         };
     sSatelliteProvisionStateCallbackWrapperMap.put(callback, internalCallback);
     int result =
@@ -731,7 +864,7 @@ public class SatelliteManagerWrapper {
   public void unregisterForProvisionStateChanged(
       @NonNull SatelliteProvisionStateCallbackWrapper callback) {
     SatelliteProvisionStateCallback internalCallback =
-        sSatelliteProvisionStateCallbackWrapperMap.get(callback);
+        sSatelliteProvisionStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForProvisionStateChanged(internalCallback);
     }
@@ -774,13 +907,52 @@ public class SatelliteManagerWrapper {
     return result;
   }
 
+  /** Registers for modem state changed from satellite modem. */
+  @SatelliteResult
+  public int registerForModemStateChanged(
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull SatelliteModemStateCallbackWrapper2 callback) {
+    SatelliteModemStateCallback internalCallback =
+            new SatelliteModemStateCallback() {
+              public void onSatelliteModemStateChanged(@SatelliteModemState int state) {
+                callback.onSatelliteModemStateChanged(state);
+              }
+
+              public void onEmergencyModeChanged(boolean isEmergency) {
+                callback.onEmergencyModeChanged(isEmergency);
+              }
+
+              public void onRegistrationFailure(int causeCode) {
+                callback.onRegistrationFailure(causeCode);
+              }
+            };
+    sSatelliteModemStateCallbackWrapperMap2.put(callback, internalCallback);
+
+    int result =
+            mSatelliteManager.registerForModemStateChanged(executor, internalCallback);
+    return result;
+  }
+
   /**
    * Unregisters for modem state changed from satellite modem. If callback was not registered
    * before, the request will be ignored.
    */
   public void unregisterForModemStateChanged(
       @NonNull SatelliteModemStateCallbackWrapper callback) {
-    SatelliteModemStateCallback internalCallback = sSatelliteModemStateCallbackWrapperMap.get(
+    SatelliteModemStateCallback internalCallback = sSatelliteModemStateCallbackWrapperMap.remove(
+            callback);
+    if (internalCallback != null) {
+      mSatelliteManager.unregisterForModemStateChanged(internalCallback);
+    }
+  }
+
+  /**
+   * Unregisters for modem state changed from satellite modem. If callback was not registered
+   * before, the request will be ignored.
+   */
+  public void unregisterForModemStateChanged(
+          @NonNull SatelliteModemStateCallbackWrapper2 callback) {
+    SatelliteModemStateCallback internalCallback = sSatelliteModemStateCallbackWrapperMap2.remove(
             callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForModemStateChanged(internalCallback);
@@ -817,7 +989,8 @@ public class SatelliteManagerWrapper {
    * before, the request will be ignored.
    */
   public void unregisterForIncomingDatagram(@NonNull SatelliteDatagramCallbackWrapper callback) {
-    SatelliteDatagramCallback internalCallback = sSatelliteDatagramCallbackWrapperMap.get(callback);
+    SatelliteDatagramCallback internalCallback =
+            sSatelliteDatagramCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForIncomingDatagram(internalCallback);
     }
@@ -827,15 +1000,34 @@ public class SatelliteManagerWrapper {
           implements TelephonyCallback.CarrierRoamingNtnModeListener {
 
     private CarrierRoamingNtnModeListenerWrapper mListenerWrapper;
+    private CarrierRoamingNtnModeListenerWrapper2 mListenerWrapper2;
 
     public CarrierRoamingNtnModeListener(CarrierRoamingNtnModeListenerWrapper listenerWrapper) {
       mListenerWrapper = listenerWrapper;
+      mListenerWrapper2 = null;
+    }
+
+    public CarrierRoamingNtnModeListener(CarrierRoamingNtnModeListenerWrapper2 listenerWrapper) {
+      mListenerWrapper = null;
+      mListenerWrapper2 = listenerWrapper;
     }
 
     @Override
     public void onCarrierRoamingNtnModeChanged(boolean active) {
       logd("onCarrierRoamingNtnModeChanged: active=" + active);
-      mListenerWrapper.onCarrierRoamingNtnModeChanged(active);
+      if (mListenerWrapper2 != null) {
+        mListenerWrapper2.onCarrierRoamingNtnModeChanged(active);
+      } else if (mListenerWrapper != null) {
+        mListenerWrapper.onCarrierRoamingNtnModeChanged(active);
+      }
+    }
+
+    @Override
+    public void onCarrierRoamingNtnEligibleStateChanged(boolean eligible) {
+      logd("onCarrierRoamingNtnEligibleStateChanged: eligible=" + eligible);
+      if (mListenerWrapper2 != null) {
+        mListenerWrapper2.onCarrierRoamingNtnEligibleStateChanged(eligible);
+      }
     }
   }
 
@@ -851,12 +1043,35 @@ public class SatelliteManagerWrapper {
     tm.registerTelephonyCallback(executor, internalListener);
   }
 
+  public void registerForCarrierRoamingNtnModeChanged(int subId,
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull CarrierRoamingNtnModeListenerWrapper2 listener) {
+    logd("registerForCarrierRoamingNtnModeChanged: subId=" + subId);
+    CarrierRoamingNtnModeListener internalListener = new CarrierRoamingNtnModeListener(listener);
+    sCarrierRoamingNtnModeListenerWrapperMap2.put(listener, internalListener);
+
+    TelephonyManager tm = mTelephonyManager.createForSubscriptionId(subId);
+    tm.registerTelephonyCallback(executor, internalListener);
+  }
+
   /** Unregister for carrier roaming non-terrestrial network mode changes. */
   public void unregisterForCarrierRoamingNtnModeChanged(int subId,
           @NonNull CarrierRoamingNtnModeListenerWrapper listener) {
     logd("unregisterForCarrierRoamingNtnModeChanged: subId=" + subId);
     CarrierRoamingNtnModeListener internalListener =
-            sCarrierRoamingNtnModeListenerWrapperMap.get(listener);
+            sCarrierRoamingNtnModeListenerWrapperMap.remove(listener);
+    if (internalListener != null) {
+      TelephonyManager tm = mTelephonyManager.createForSubscriptionId(subId);
+      tm.unregisterTelephonyCallback(internalListener);
+    }
+  }
+
+  /** Unregister for carrier roaming non-terrestrial network mode changes. */
+  public void unregisterForCarrierRoamingNtnModeChanged(int subId,
+          @NonNull CarrierRoamingNtnModeListenerWrapper2 listener) {
+    logd("unregisterForCarrierRoamingNtnModeChanged: subId=" + subId);
+    CarrierRoamingNtnModeListener internalListener =
+            sCarrierRoamingNtnModeListenerWrapperMap.remove(listener);
     if (internalListener != null) {
       TelephonyManager tm = mTelephonyManager.createForSubscriptionId(subId);
       tm.unregisterTelephonyCallback(internalListener);
@@ -1001,7 +1216,8 @@ public class SatelliteManagerWrapper {
   @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public void unregisterForNtnSignalStrengthChanged(
       @NonNull NtnSignalStrengthCallbackWrapper callback) {
-    NtnSignalStrengthCallback internalCallback = sNtnSignalStrengthCallbackWrapperMap.get(callback);
+    NtnSignalStrengthCallback internalCallback =
+            sNtnSignalStrengthCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       try {
         mSatelliteManager.unregisterForNtnSignalStrengthChanged(internalCallback);
@@ -1066,7 +1282,7 @@ public class SatelliteManagerWrapper {
   public void unregisterForCapabilitiesChanged(
           @NonNull SatelliteCapabilitiesCallbackWrapper callback) {
     SatelliteCapabilitiesCallback internalCallback =
-            sSatelliteCapabilitiesCallbackWrapperMap.get(callback);
+            sSatelliteCapabilitiesCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForCapabilitiesChanged(internalCallback);
     }
@@ -1343,7 +1559,7 @@ public class SatelliteManagerWrapper {
   public void unregisterForSupportedStateChanged(
           @NonNull SatelliteSupportedStateCallbackWrapper callback) {
     SatelliteSupportedStateCallback internalCallback =
-            sSatelliteSupportedStateCallbackWrapperMap.get(callback);
+            sSatelliteSupportedStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForSupportedStateChanged(internalCallback);
     }
@@ -1374,12 +1590,133 @@ public class SatelliteManagerWrapper {
   public void unregisterForCommunicationAllowedStateChanged(
           @NonNull SatelliteCommunicationAllowedStateCallbackWrapper callback) {
     SatelliteCommunicationAllowedStateCallback internalCallback =
-            sSatelliteCommunicationAllowedStateCallbackWrapperMap.get(callback);
+            sSatelliteCommunicationAllowedStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForCommunicationAllowedStateChanged(internalCallback);
     }
   }
 
+  /**
+   * Wrapper API to provide a way to check if the subscription is capable for non-terrestrial
+   * networks for the carrier.
+   *
+   * @param subId The unique SubscriptionInfo key in database.
+   * @return {@code true} if it is a non-terrestrial network capable subscription,
+   * {@code false} otherwise.
+   * Note: The method returns {@code false} if the parameter is invalid or any other error occurs.
+   */
+  @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+  public boolean isSatelliteESOSSupportedSubscription(int subId) {
+    if (!mSubscriptionManager.isValidSubscriptionId(subId)) {
+      return false;
+    }
+
+    List<SubscriptionInfo> subInfoList = mSubscriptionManager.getAvailableSubscriptionInfoList();
+    for (SubscriptionInfo subInfo : subInfoList) {
+      if (subInfo.getSubscriptionId() == subId) {
+        logd("found matched subscription info");
+        return subInfo.isSatelliteESOSSupported();
+      }
+    }
+    logd("failed to found matched subscription info");
+    return false;
+  }
+
+  /**
+   * Request to get list of prioritized satellite subscriber ids to be used for provision.
+   *
+   * @param executor, The executor on which the callback will be called.
+   * @param callback, The callback object to which the result will be delivered.
+   * If successful, the callback returns a list of subscriberIds sorted in ascending priority
+   * order index 0 has the highest priority. Otherwise, it returns an error with a
+   * SatelliteException.
+   */
+  @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+  public void requestSatelliteSubscriberProvisionStatus(
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull OutcomeReceiver<List<SatelliteSubscriberProvisionStatusWrapper>,
+                  SatelliteExceptionWrapper> callback) {
+    Objects.requireNonNull(executor);
+    Objects.requireNonNull(callback);
+
+    OutcomeReceiver internalCallback =
+            new OutcomeReceiver<List<SatelliteSubscriberProvisionStatus>, SatelliteException>() {
+              @Override
+              public void onResult(List<SatelliteSubscriberProvisionStatus> result) {
+                callback.onResult(transformToWrapperList(result));
+              }
+
+              @Override
+              public void onError(SatelliteException exception) {
+                callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+              }
+            };
+    mSatelliteManager.requestSatelliteSubscriberProvisionStatus(executor, internalCallback);
+  }
+
+  /**
+   * Deliver the list of provisioned satellite subscriber ids.
+   *
+   * @param list List of SatelliteSubscriberInfo.
+   * @param executor The executor on which the callback will be called.
+   * @param callback The callback object to which the result will be delivered.
+   */
+  @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+  public void provisionSatellite(@NonNull List<SatelliteSubscriberInfoWrapper> list,
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    OutcomeReceiver internalCallback =
+            new OutcomeReceiver<Boolean, SatelliteException>() {
+              @Override
+              public void onResult(Boolean result) {
+                callback.onResult(result);
+              }
+
+              @Override
+              public void onError(SatelliteException exception) {
+                callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+              }
+            };
+    mSatelliteManager.provisionSatellite(list.stream()
+            .map(info -> new SatelliteSubscriberInfo.Builder()
+                    .setSubscriberId(info.getSubscriberId())
+                    .setCarrierId(info.getCarrierId()).setNiddApn(info.getNiddApn())
+                    .setSubId(info.getSubId()).setSubscriberIdType(info.getSubscriberIdType())
+                    .build())
+            .collect(Collectors.toList()), executor, internalCallback);
+  }
+
+  private List<SatelliteSubscriberProvisionStatusWrapper> transformToWrapperList(
+          List<SatelliteSubscriberProvisionStatus> input) {
+    List<SatelliteSubscriberProvisionStatusWrapper> output = new ArrayList<>();
+    if (Flags.carrierRoamingNbIotNtn()) {
+      for (SatelliteSubscriberProvisionStatus status : input) {
+        SatelliteSubscriberInfo info = status.getSatelliteSubscriberInfo();
+        output.add(new SatelliteSubscriberProvisionStatusWrapper.Builder()
+                .setProvisionStatus(status.getProvisionStatus())
+                .setSatelliteSubscriberInfo(
+                        new SatelliteSubscriberInfoWrapper.Builder()
+                                .setSubscriberId(info.getSubscriberId())
+                                .setCarrierId(info.getCarrierId()).setNiddApn(info.getNiddApn())
+                                .setSubId(info.getSubId())
+                                .setSubscriberIdType(info.getSubscriberIdType())
+                                .build()).build());
+      }
+    }
+    return output;
+  }
+
+  public boolean isSatelliteSubscriberIdSupported() {
+    try {
+      final String methodName = "requestSatelliteSubscriberProvisionStatus";
+      Method method = mSatelliteManager.getClass().getMethod(methodName, Executor.class,
+              OutcomeReceiver.class);
+      return method != null;
+    } catch (NoSuchMethodException e) {
+      return false;
+    }
+  }
+
   @Nullable
   private ServiceState getServiceStateForSubscriptionId(int subId) {
     if (!mSubscriptionManager.isValidSubscriptionId(subId)) {
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java
new file mode 100644
index 0000000..054167b
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java
@@ -0,0 +1,43 @@
+  /*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package android.telephony.satellite.wrapper;
+
+/** A callback class for monitoring satellite modem state change events. */
+public interface SatelliteModemStateCallbackWrapper2 {
+
+  /**
+   * Called when satellite modem state changes.
+   *
+   * @param state The new satellite modem state.
+   */
+  void onSatelliteModemStateChanged(@SatelliteManagerWrapper.SatelliteModemState int state);
+
+  /**
+   * Called when the satellite emergency mode has changed.
+   *
+   * @param isEmergency {@code true} enabled for emergency mode, {@code false} otherwise.
+   */
+  default void onEmergencyModeChanged(boolean isEmergency) {};
+
+  /**
+   * Indicates that the satellite registration failed with following failure code
+   *
+   * @param causeCode the primary failure cause code of the procedure.
+   *        For LTE (EMM), cause codes are TS 24.301 Sec 9.9.3.9
+   */
+  default void onRegistrationFailure(int causeCode) {};
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteProvisionStateCallbackWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteProvisionStateCallbackWrapper.java
index 5e69f70..07991cf 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteProvisionStateCallbackWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteProvisionStateCallbackWrapper.java
@@ -16,6 +16,10 @@
 
 package android.telephony.satellite.wrapper;
 
+import android.annotation.NonNull;
+
+import java.util.List;
+
 /** A callback class for monitoring satellite provision state change events. */
 public interface SatelliteProvisionStateCallbackWrapper {
   /**
@@ -25,4 +29,13 @@ public interface SatelliteProvisionStateCallbackWrapper {
    *     false} means satellite is not provisioned.
    */
   void onSatelliteProvisionStateChanged(boolean provisioned);
+
+  /**
+   * Called when the provisioning state of one or more SatelliteSubscriberInfos changes.
+   *
+   * @param satelliteSubscriberProvisionStatus The list contains the latest provisioning states
+   *                                           of the SatelliteSubscriberInfos.
+   */
+  default void onSatelliteSubscriptionProvisionStateChanged(@NonNull
+        List<SatelliteSubscriberProvisionStatusWrapper> satelliteSubscriberProvisionStatus) {}
 }
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java
new file mode 100644
index 0000000..ce0daaa
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java
@@ -0,0 +1,261 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.FlaggedApi;
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import com.android.internal.telephony.flags.Flags;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.Objects;
+
+@FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+public class SatelliteSubscriberInfoWrapper implements Parcelable {
+    @NonNull private final String mSubscriberId;
+    @NonNull private final int mCarrierId;
+    @NonNull private final String mNiddApn;
+    @NonNull private int mSubId;
+
+    /** SubscriberId format is the ICCID. */
+    @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
+    public static final int ICCID = 0;
+    /** SubscriberId format is the 6 digit of IMSI + MSISDN. */
+    @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
+    public static final int IMSI_MSISDN = 1;
+
+    /** Type of subscriber id */
+    @SubscriberIdType
+    @NonNull private int mSubscriberIdType;
+
+    /** @hide */
+    @IntDef(prefix = "SubscriberId_Type_", value = {
+            ICCID,
+            IMSI_MSISDN
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface SubscriberIdType {
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public SatelliteSubscriberInfoWrapper(@NonNull Builder builder) {
+        this.mSubscriberId = builder.mSubscriberId;
+        this.mCarrierId = builder.mCarrierId;
+        this.mNiddApn = builder.mNiddApn;
+        this.mSubId = builder.mSubId;
+        this.mSubscriberIdType = builder.mSubscriberIdType;
+    }
+
+    /**
+     * Builder class for constructing SatelliteSubscriberInfoWrapper objects
+     *
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public static class Builder {
+        @NonNull private String mSubscriberId;
+        @NonNull private int mCarrierId;
+        @NonNull private String mNiddApn;
+        @NonNull private int mSubId;
+        @NonNull @SubscriberIdType private int mSubscriberIdType;
+
+        /**
+         * Set the SubscriberId and returns the Builder class.
+         *
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setSubscriberId(String subscriberId) {
+            mSubscriberId = subscriberId;
+            return this;
+        }
+
+        /**
+         * Set the CarrierId and returns the Builder class.
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setCarrierId(int carrierId) {
+            mCarrierId = carrierId;
+            return this;
+        }
+
+        /**
+         * Set the niddApn and returns the Builder class.
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setNiddApn(String niddApn) {
+            mNiddApn = niddApn;
+            return this;
+        }
+
+        /**
+         * Set the subId and returns the Builder class.
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setSubId(int subId) {
+            mSubId = subId;
+            return this;
+        }
+
+        /**
+         * Set the SubscriberIdType and returns the Builder class.
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setSubscriberIdType(@SubscriberIdType int subscriberIdType) {
+            mSubscriberIdType = subscriberIdType;
+            return this;
+        }
+
+        /**
+         * Returns SatelliteSubscriberInfoWrapper object.
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public SatelliteSubscriberInfoWrapper build() {
+            return new SatelliteSubscriberInfoWrapper(this);
+        }
+    }
+
+    private SatelliteSubscriberInfoWrapper(Parcel in) {
+        mSubscriberId = in.readString();
+        mCarrierId = in.readInt();
+        mNiddApn = in.readString();
+        mSubId = in.readInt();
+        mSubscriberIdType = in.readInt();
+    }
+
+    /**
+     * @hide
+     */
+    @Override
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public void writeToParcel(@NonNull Parcel out, int flags) {
+        out.writeString(mSubscriberId);
+        out.writeInt(mCarrierId);
+        out.writeString(mNiddApn);
+        out.writeInt(mSubId);
+        out.writeInt(mSubscriberIdType);
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public static final @android.annotation.NonNull Creator<SatelliteSubscriberInfoWrapper>
+            CREATOR =
+            new Creator<SatelliteSubscriberInfoWrapper>() {
+                @Override
+                public SatelliteSubscriberInfoWrapper createFromParcel(Parcel in) {
+                    return new SatelliteSubscriberInfoWrapper(in);
+                }
+
+                @Override
+                public SatelliteSubscriberInfoWrapper[] newArray(int size) {
+                    return new SatelliteSubscriberInfoWrapper[size];
+                }
+            };
+
+    /**
+     * @hide
+     */
+    @Override
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public int describeContents() {
+        return 0;
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    @NonNull
+    public String getSubscriberId() {
+        return mSubscriberId;
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    @NonNull
+    public int getCarrierId() {
+        return mCarrierId;
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    @NonNull
+    public String getNiddApn() {
+        return mNiddApn;
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    @NonNull
+    public int getSubId() {
+        return mSubId;
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    @NonNull
+    public @SubscriberIdType int getSubscriberIdType() {
+        return mSubscriberIdType;
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        StringBuilder sb = new StringBuilder();
+        sb.append("SubscriberId:");
+        sb.append(mSubscriberId);
+        sb.append(",");
+
+        sb.append("carrierId:");
+        sb.append(mCarrierId);
+        sb.append(",");
+
+        sb.append("niddApn:");
+        sb.append(mNiddApn);
+        sb.append(",");
+
+        sb.append("SubId:");
+        sb.append(mSubId);
+        sb.append(",");
+
+        sb.append("SubscriberIdType:");
+        sb.append(mSubscriberIdType);
+        return sb.toString();
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof SatelliteSubscriberInfoWrapper)) return false;
+        SatelliteSubscriberInfoWrapper that = (SatelliteSubscriberInfoWrapper) o;
+        return Objects.equals(mSubscriberId, that.mSubscriberId)
+                && mCarrierId == that.mCarrierId && Objects.equals(mNiddApn, that.mNiddApn)
+                && mSubId == that.mSubId && mSubscriberIdType == that.mSubscriberIdType;
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mSubscriberId, mCarrierId, mNiddApn, mSubId, mSubscriberIdType);
+    }
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberProvisionStatusWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberProvisionStatusWrapper.java
new file mode 100644
index 0000000..e89edc3
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberProvisionStatusWrapper.java
@@ -0,0 +1,181 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import com.android.internal.telephony.flags.Flags;
+
+import java.util.Objects;
+
+@FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+public class SatelliteSubscriberProvisionStatusWrapper implements Parcelable {
+    @NonNull
+    private SatelliteSubscriberInfoWrapper mSubscriberInfo;
+    /** {@code true} mean the satellite subscriber is provisioned, {@code false} otherwise. */
+    private boolean mProvisionStatus;
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public SatelliteSubscriberProvisionStatusWrapper(@NonNull Builder builder) {
+        mSubscriberInfo = builder.mSubscriberInfo;
+        mProvisionStatus = builder.mProvisionStatus;
+    }
+
+    private SatelliteSubscriberProvisionStatusWrapper(Parcel in) {
+        readFromParcel(in);
+    }
+
+    /**
+     * Builder class for constructing SatelliteSubscriberProvisionStatusWrapper objects
+     *
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public static class Builder {
+        private SatelliteSubscriberInfoWrapper mSubscriberInfo;
+        private boolean mProvisionStatus;
+
+        /**
+         * Set the SatelliteSubscriberInfo and returns the Builder class.
+         *
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setSatelliteSubscriberInfo(
+                SatelliteSubscriberInfoWrapper satelliteSubscriberInfo) {
+            mSubscriberInfo = satelliteSubscriberInfo;
+            return this;
+        }
+
+        /**
+         * Set the SatelliteSubscriberInfo's provisionStatus and returns the Builder class.
+         *
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public Builder setProvisionStatus(boolean provisionStatus) {
+            mProvisionStatus = provisionStatus;
+            return this;
+        }
+
+        /**
+         * Returns SatelliteSubscriberProvisionStatus object.
+         *
+         * @hide
+         */
+        @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+        @NonNull
+        public SatelliteSubscriberProvisionStatusWrapper build() {
+            return new SatelliteSubscriberProvisionStatusWrapper(this);
+        }
+    }
+
+    /**
+     * @hide
+     */
+    @Override
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public void writeToParcel(@NonNull Parcel out, int flags) {
+        out.writeParcelable(mSubscriberInfo, flags);
+        out.writeBoolean(mProvisionStatus);
+    }
+
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public static final @android.annotation.NonNull
+            Creator<SatelliteSubscriberProvisionStatusWrapper> CREATOR =
+            new Creator<SatelliteSubscriberProvisionStatusWrapper>() {
+                @Override
+                public SatelliteSubscriberProvisionStatusWrapper createFromParcel(Parcel in) {
+                    return new SatelliteSubscriberProvisionStatusWrapper(in);
+                }
+
+                @Override
+                public SatelliteSubscriberProvisionStatusWrapper[] newArray(int size) {
+                    return new SatelliteSubscriberProvisionStatusWrapper[size];
+                }
+            };
+
+    /**
+     * @hide
+     */
+    @Override
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public int describeContents() {
+        return 0;
+    }
+
+    /**
+     * SatelliteSubscriberInfo that has a provisioning state.
+     *
+     * @return SatelliteSubscriberInfo.
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public @NonNull SatelliteSubscriberInfoWrapper getSatelliteSubscriberInfo() {
+        return mSubscriberInfo;
+    }
+
+    /**
+     * SatelliteSubscriberInfo's provisioning state.
+     *
+     * @return {@code true} means provisioning. {@code false} means deprovisioning.
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+    public @NonNull boolean getProvisionStatus() {
+        return mProvisionStatus;
+    }
+
+    @NonNull
+    @Override
+    public String toString() {
+        StringBuilder sb = new StringBuilder();
+
+        sb.append("SatelliteSubscriberInfoWrapper:");
+        sb.append(mSubscriberInfo);
+        sb.append(",");
+
+        sb.append("ProvisionStatus:");
+        sb.append(mProvisionStatus);
+        return sb.toString();
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mSubscriberInfo, mProvisionStatus);
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof SatelliteSubscriberProvisionStatusWrapper)) return false;
+        SatelliteSubscriberProvisionStatusWrapper that =
+                (SatelliteSubscriberProvisionStatusWrapper) o;
+        return Objects.equals(mSubscriberInfo, that.mSubscriberInfo)
+                && mProvisionStatus == that.mProvisionStatus;
+    }
+
+    private void readFromParcel(Parcel in) {
+        mSubscriberInfo = in.readParcelable(SatelliteSubscriberInfoWrapper.class.getClassLoader());
+        mProvisionStatus = in.readBoolean();
+    }
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteTransmissionUpdateCallbackWrapper2.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteTransmissionUpdateCallbackWrapper2.java
new file mode 100644
index 0000000..a02edcb
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteTransmissionUpdateCallbackWrapper2.java
@@ -0,0 +1,77 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.NonNull;
+
+/**
+ * A callback class for monitoring satellite position update and datagram transfer state change
+ * events.
+ */
+public interface SatelliteTransmissionUpdateCallbackWrapper2 {
+  /**
+   * Called when the satellite position changed.
+   *
+   * @param pointingInfo The pointing info containing the satellite location.
+   */
+  default void onSatellitePositionChanged(@NonNull PointingInfoWrapper pointingInfo) {}
+
+  /**
+   * Called when satellite datagram send state changed.
+   *
+   * @param state The new send datagram transfer state.
+   * @param sendPendingCount The number of datagrams that are currently being sent.
+   * @param errorCode If datagram transfer failed, the reason for failure.
+   */
+  default void onSendDatagramStateChanged(
+      @SatelliteManagerWrapper.SatelliteDatagramTransferState int state,
+      int sendPendingCount,
+      @SatelliteManagerWrapper.SatelliteResult int errorCode) {}
+
+  /**
+   * Called when satellite datagram send state changed.
+   *
+   * @param datagramType The datagram type of currently being sent.
+   * @param state The new send datagram transfer state.
+   * @param sendPendingCount The number of datagrams that are currently being sent.
+   * @param errorCode If datagram transfer failed, the reason for failure.
+   *
+   * @hide
+   */
+  default void onSendDatagramStateChanged(@SatelliteManagerWrapper.DatagramType int datagramType,
+          @SatelliteManagerWrapper.SatelliteDatagramTransferState int state, int sendPendingCount,
+          @SatelliteManagerWrapper.SatelliteResult int errorCode) {}
+
+  /**
+   * Called when satellite datagram receive state changed.
+   *
+   * @param state The new receive datagram transfer state.
+   * @param receivePendingCount The number of datagrams that are currently pending to be received.
+   * @param errorCode If datagram transfer failed, the reason for failure.
+   */
+  default void onReceiveDatagramStateChanged(
+      @SatelliteManagerWrapper.SatelliteDatagramTransferState int state,
+      int receivePendingCount,
+      @SatelliteManagerWrapper.SatelliteResult int errorCode) {}
+
+  /**
+   * Called when framework receives a request to send a datagram.
+   *
+   * @param datagramType The type of the requested datagram.
+   */
+  default void onSendDatagramRequested(@SatelliteManagerWrapper.DatagramType int datagramType) {}
+}
```

