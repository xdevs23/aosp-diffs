```diff
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthCallbackWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthCallbackWrapper.java
index 46aef62..4dc1df3 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthCallbackWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthCallbackWrapper.java
@@ -23,12 +23,10 @@ import com.android.internal.telephony.flags.Flags;
 /**
  * Encapsulates the callback class for notifying satellite signal strength change.
  */
-@FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
 public interface NtnSignalStrengthCallbackWrapper {
   /**
    * Called when non-terrestrial network signal strength changes.
    * @param ntnSignalStrength The new non-terrestrial network signal strength.
    */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   void onNtnSignalStrengthChanged(@NonNull NtnSignalStrengthWrapper ntnSignalStrength);
 }
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthWrapper.java
index 5198457..63c093b 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/NtnSignalStrengthWrapper.java
@@ -16,31 +16,24 @@
 
 package android.telephony.satellite.wrapper;
 
-import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.NonNull;
-import com.android.internal.telephony.flags.Flags;
+
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
 
 /** Encapsulates the non-terrestrial network signal strength related information. */
-@FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
 public final class NtnSignalStrengthWrapper {
 
   /** Non-terrestrial network signal strength is not available. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public static final int NTN_SIGNAL_STRENGTH_NONE = 0;
   /** Non-terrestrial network signal strength is poor. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public static final int NTN_SIGNAL_STRENGTH_POOR = 1;
   /** Non-terrestrial network signal strength is moderate. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public static final int NTN_SIGNAL_STRENGTH_MODERATE = 2;
   /** Non-terrestrial network signal strength is good. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public static final int NTN_SIGNAL_STRENGTH_GOOD = 3;
   /** Non-terrestrial network signal strength is great. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public static final int NTN_SIGNAL_STRENGTH_GREAT = 4;
   @NtnSignalStrengthLevel private final int mLevel;
 
@@ -55,12 +48,10 @@ public final class NtnSignalStrengthWrapper {
   @Retention(RetentionPolicy.SOURCE)
   public @interface NtnSignalStrengthLevel {}
 
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public NtnSignalStrengthWrapper(@NonNull @NtnSignalStrengthLevel int level) {
     this.mLevel = level;
   }
 
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   @NtnSignalStrengthLevel public int getLevel() {
     return mLevel;
   }
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCapabilitiesCallbackWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCapabilitiesCallbackWrapper.java
index c538608..110393e 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCapabilitiesCallbackWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCapabilitiesCallbackWrapper.java
@@ -24,12 +24,10 @@ import com.android.internal.telephony.flags.Flags;
 /**
  * A callback class for satellite capabilities change events.
  */
-@FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
 public interface SatelliteCapabilitiesCallbackWrapper {
   /**
    * Called when satellite capability has changed.
    * @param capabilities The new satellite capabilities.
    */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   void onSatelliteCapabilitiesChanged(@NonNull SatelliteCapabilitiesWrapper capabilities);
 }
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
index b4c55d1..9fab193 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
@@ -44,7 +44,7 @@ import android.telephony.satellite.PointingInfo;
 import android.telephony.satellite.SatelliteAccessConfiguration;
 import android.telephony.satellite.SatelliteCapabilities;
 import android.telephony.satellite.SatelliteCapabilitiesCallback;
-import android.telephony.satellite.SatelliteCommunicationAllowedStateCallback;
+import android.telephony.satellite.SatelliteCommunicationAccessStateCallback;
 import android.telephony.satellite.SatelliteDatagram;
 import android.telephony.satellite.SatelliteDatagramCallback;
 import android.telephony.satellite.SatelliteInfo;
@@ -54,7 +54,6 @@ import android.telephony.satellite.SatelliteProvisionStateCallback;
 import android.telephony.satellite.SatelliteSessionStats;
 import android.telephony.satellite.SatelliteSubscriberInfo;
 import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
-import android.telephony.satellite.SatelliteSupportedStateCallback;
 import android.telephony.satellite.SatelliteTransmissionUpdateCallback;
 import android.telephony.satellite.SelectedNbIotSatelliteSubscriptionCallback;
 
@@ -119,7 +118,7 @@ public class SatelliteManagerWrapper {
           sSatelliteCapabilitiesCallbackWrapperMap = new ConcurrentHashMap<>();
 
   private static final ConcurrentHashMap<
-          SatelliteSupportedStateCallbackWrapper, SatelliteSupportedStateCallback>
+          SatelliteSupportedStateCallbackWrapper, Consumer<Boolean>>
           sSatelliteSupportedStateCallbackWrapperMap = new ConcurrentHashMap<>();
 
   private static final ConcurrentHashMap<CarrierRoamingNtnModeListenerWrapper,
@@ -131,11 +130,11 @@ public class SatelliteManagerWrapper {
           sCarrierRoamingNtnModeListenerWrapperMap2 = new ConcurrentHashMap<>();
 
   private static final ConcurrentHashMap<SatelliteCommunicationAllowedStateCallbackWrapper,
-          SatelliteCommunicationAllowedStateCallback>
+          SatelliteCommunicationAccessStateCallback>
           sSatelliteCommunicationAllowedStateCallbackWrapperMap = new ConcurrentHashMap<>();
 
   private static final ConcurrentHashMap<SatelliteCommunicationAllowedStateCallbackWrapper2,
-          SatelliteCommunicationAllowedStateCallback>
+          SatelliteCommunicationAccessStateCallback>
           sSatelliteCommunicationAllowedStateCallbackWrapperMap2 = new ConcurrentHashMap<>();
 
   private static final ConcurrentHashMap<SelectedNbIotSatelliteSubscriptionCallbackWrapper,
@@ -1165,7 +1164,7 @@ public class SatelliteManagerWrapper {
   }
 
   private class CarrierRoamingNtnModeListener extends TelephonyCallback
-          implements TelephonyCallback.CarrierRoamingNtnModeListener {
+          implements TelephonyCallback.CarrierRoamingNtnListener {
 
     private CarrierRoamingNtnModeListenerWrapper mListenerWrapper;
     private CarrierRoamingNtnModeListenerWrapper2 mListenerWrapper2;
@@ -1197,12 +1196,6 @@ public class SatelliteManagerWrapper {
         mListenerWrapper2.onCarrierRoamingNtnEligibleStateChanged(eligible);
       }
     }
-
-    @Override
-    public void onCarrierRoamingNtnAvailableServicesChanged(
-            @NetworkRegistrationInfo.ServiceType int[] availableServices) {
-      logd("onCarrierRoamingNtnAvailableServicesChanged");
-    }
   }
 
   /** Register for carrier roaming non-terrestrial network mode changes. */
@@ -1509,7 +1502,6 @@ public class SatelliteManagerWrapper {
   }
 
   /** Request to get the signal strength of the satellite connection. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   @NonNull
   public void requestNtnSignalStrength(
       @NonNull @CallbackExecutor Executor executor,
@@ -1538,7 +1530,6 @@ public class SatelliteManagerWrapper {
   }
 
   /** Registers for NTN signal strength changed from satellite modem. */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public void registerForNtnSignalStrengthChanged(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull NtnSignalStrengthCallbackWrapper callback) {
@@ -1563,7 +1554,6 @@ public class SatelliteManagerWrapper {
    * Unregisters for NTN signal strength changed from satellite modem.
    * If callback was not registered before, the request will be ignored.
    */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public void unregisterForNtnSignalStrengthChanged(
       @NonNull NtnSignalStrengthCallbackWrapper callback) {
     if (mSatelliteManager == null){
@@ -1591,7 +1581,6 @@ public class SatelliteManagerWrapper {
    * otherwise.
    * Note: The method returns {@code false} if the parameter is invalid or any other error occurs.
    */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public boolean isOnlyNonTerrestrialNetworkSubscription(int subId) {
     List<SubscriptionInfo> subInfoList = mSubscriptionManager.getAvailableSubscriptionInfoList();
 
@@ -1611,7 +1600,6 @@ public class SatelliteManagerWrapper {
    * @param executor The executor on which the callback will be called.
    * @param callback The callback to handle the satellite capabilities changed event.
    */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public int registerForCapabilitiesChanged(
           @NonNull @CallbackExecutor Executor executor,
           @NonNull SatelliteCapabilitiesCallbackWrapper callback) {
@@ -1638,7 +1626,6 @@ public class SatelliteManagerWrapper {
    *
    * @param callback The callback that was passed to.
    */
-  @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public void unregisterForCapabilitiesChanged(
           @NonNull SatelliteCapabilitiesCallbackWrapper callback) {
     if (mSatelliteManager == null) {
@@ -1916,13 +1903,12 @@ public class SatelliteManagerWrapper {
       return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
     }
 
-    SatelliteSupportedStateCallback internalCallback =
-            new SatelliteSupportedStateCallback() {
-              @Override
-              public void onSatelliteSupportedStateChanged(boolean supported) {
-                callback.onSatelliteSupportedStateChanged(supported);
-              }
-            };
+    Consumer<Boolean> internalCallback = new Consumer<Boolean>() {
+      @Override
+      public void accept(Boolean supported) {
+        callback.onSatelliteSupportedStateChanged(supported);
+      }
+    };
     sSatelliteSupportedStateCallbackWrapperMap.put(callback, internalCallback);
     int result =
             mSatelliteManager.registerForSupportedStateChanged(executor, internalCallback);
@@ -2035,7 +2021,7 @@ public class SatelliteManagerWrapper {
       return;
     }
 
-    SatelliteSupportedStateCallback internalCallback =
+    Consumer<Boolean> internalCallback =
             sSatelliteSupportedStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
       mSatelliteManager.unregisterForSupportedStateChanged(internalCallback);
@@ -2052,15 +2038,15 @@ public class SatelliteManagerWrapper {
       return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
     }
 
-    SatelliteCommunicationAllowedStateCallback internalCallback =
-            new SatelliteCommunicationAllowedStateCallback() {
+    SatelliteCommunicationAccessStateCallback internalCallback =
+            new SatelliteCommunicationAccessStateCallback() {
               @Override
-              public void onSatelliteCommunicationAllowedStateChanged(boolean supported) {
+              public void onAccessAllowedStateChanged(boolean supported) {
                 callback.onSatelliteCommunicationAllowedStateChanged(supported);
               }
             };
     sSatelliteCommunicationAllowedStateCallbackWrapperMap.put(callback, internalCallback);
-    int result = mSatelliteManager.registerForCommunicationAllowedStateChanged(executor,
+    int result = mSatelliteManager.registerForCommunicationAccessStateChanged(executor,
             internalCallback);
     return result;
   }
@@ -2100,15 +2086,15 @@ public class SatelliteManagerWrapper {
       return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
     }
 
-    SatelliteCommunicationAllowedStateCallback internalCallback =
-            new SatelliteCommunicationAllowedStateCallback() {
+    SatelliteCommunicationAccessStateCallback internalCallback =
+            new SatelliteCommunicationAccessStateCallback() {
               @Override
-              public void onSatelliteCommunicationAllowedStateChanged(boolean supported) {
+              public void onAccessAllowedStateChanged(boolean supported) {
                 callback.onSatelliteCommunicationAllowedStateChanged(supported);
               }
 
               @Override
-              public void onSatelliteAccessConfigurationChanged(SatelliteAccessConfiguration
+              public void onAccessConfigurationChanged(SatelliteAccessConfiguration
                       config) {
                 if (config != null) {
                   callback.onSatelliteAccessConfigurationChanged(
@@ -2119,7 +2105,7 @@ public class SatelliteManagerWrapper {
               }
             };
     sSatelliteCommunicationAllowedStateCallbackWrapperMap2.put(callback, internalCallback);
-    int result = mSatelliteManager.registerForCommunicationAllowedStateChanged(executor,
+    int result = mSatelliteManager.registerForCommunicationAccessStateChanged(executor,
             internalCallback);
     return result;
   }
@@ -2135,10 +2121,10 @@ public class SatelliteManagerWrapper {
       return;
     }
 
-    SatelliteCommunicationAllowedStateCallback internalCallback =
+    SatelliteCommunicationAccessStateCallback internalCallback =
             sSatelliteCommunicationAllowedStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
-      mSatelliteManager.unregisterForCommunicationAllowedStateChanged(internalCallback);
+      mSatelliteManager.unregisterForCommunicationAccessStateChanged(internalCallback);
     }
   }
 
@@ -2148,10 +2134,10 @@ public class SatelliteManagerWrapper {
    */
   public void unregisterForCommunicationAllowedStateChanged2(
           @NonNull SatelliteCommunicationAllowedStateCallbackWrapper2 callback) {
-    SatelliteCommunicationAllowedStateCallback internalCallback =
+    SatelliteCommunicationAccessStateCallback internalCallback =
             sSatelliteCommunicationAllowedStateCallbackWrapperMap2.remove(callback);
     if (internalCallback != null) {
-      mSatelliteManager.unregisterForCommunicationAllowedStateChanged(internalCallback);
+      mSatelliteManager.unregisterForCommunicationAccessStateChanged(internalCallback);
     }
   }
 
@@ -2241,10 +2227,10 @@ public class SatelliteManagerWrapper {
     }
 
     OutcomeReceiver internalCallback =
-            new OutcomeReceiver<Boolean, SatelliteException>() {
+            new OutcomeReceiver<Void, SatelliteException>() {
               @Override
-              public void onResult(Boolean result) {
-                callback.onResult(result);
+              public void onResult(Void result) {
+                callback.onResult(true);
               }
 
               @Override
@@ -2256,7 +2242,8 @@ public class SatelliteManagerWrapper {
             .map(info -> new SatelliteSubscriberInfo.Builder()
                     .setSubscriberId(info.getSubscriberId())
                     .setCarrierId(info.getCarrierId()).setNiddApn(info.getNiddApn())
-                    .setSubId(info.getSubId()).setSubscriberIdType(info.getSubscriberIdType())
+                    .setSubscriptionId(info.getSubId()).setSubscriberIdType(
+                            info.getSubscriberIdType())
                     .build())
             .collect(Collectors.toList()), executor, internalCallback);
   }
@@ -2273,7 +2260,7 @@ public class SatelliteManagerWrapper {
                         new SatelliteSubscriberInfoWrapper.Builder()
                                 .setSubscriberId(info.getSubscriberId())
                                 .setCarrierId(info.getCarrierId()).setNiddApn(info.getNiddApn())
-                                .setSubId(info.getSubId())
+                                .setSubId(info.getSubscriptionId())
                                 .setSubscriberIdType(info.getSubscriberIdType())
                                 .build()).build());
       }
@@ -2317,10 +2304,10 @@ public class SatelliteManagerWrapper {
     }
 
     OutcomeReceiver internalCallback =
-            new OutcomeReceiver<Boolean, SatelliteException>() {
+            new OutcomeReceiver<Void, SatelliteException>() {
               @Override
-              public void onResult(Boolean result) {
-                callback.onResult(result);
+              public void onResult(Void result) {
+                callback.onResult(true);
               }
 
               @Override
@@ -2332,7 +2319,8 @@ public class SatelliteManagerWrapper {
             .map(info -> new SatelliteSubscriberInfo.Builder()
                     .setSubscriberId(info.getSubscriberId())
                     .setCarrierId(info.getCarrierId()).setNiddApn(info.getNiddApn())
-                    .setSubId(info.getSubId()).setSubscriberIdType(info.getSubscriberIdType())
+                    .setSubscriptionId(info.getSubId()).setSubscriberIdType(
+                            info.getSubscriberIdType())
                     .build())
             .collect(Collectors.toList()), executor, internalCallback);
   }
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java
index ce0daaa..44449d9 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSubscriberInfoWrapper.java
@@ -36,10 +36,8 @@ public class SatelliteSubscriberInfoWrapper implements Parcelable {
     @NonNull private int mSubId;
 
     /** SubscriberId format is the ICCID. */
-    @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
     public static final int ICCID = 0;
     /** SubscriberId format is the 6 digit of IMSI + MSISDN. */
-    @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
     public static final int IMSI_MSISDN = 1;
 
     /** Type of subscriber id */
diff --git a/ts43authentication/src/com/android/libraries/ts43authentication/Ts43AuthenticationLibrary.java b/ts43authentication/src/com/android/libraries/ts43authentication/Ts43AuthenticationLibrary.java
index da45671..d411111 100644
--- a/ts43authentication/src/com/android/libraries/ts43authentication/Ts43AuthenticationLibrary.java
+++ b/ts43authentication/src/com/android/libraries/ts43authentication/Ts43AuthenticationLibrary.java
@@ -124,6 +124,7 @@ public class Ts43AuthenticationLibrary extends Handler {
 
     private static class EapAkaAuthenticationRequest {
         private final String mAppName;
+        @Nullable private final String mAcceptContentType;
         @Nullable private final String mAppVersion;
         private final int mSlotIndex;
         private final URL mEntitlementServerAddress;
@@ -133,11 +134,14 @@ public class Ts43AuthenticationLibrary extends Handler {
         private final AuthenticationOutcomeReceiver<
                 Ts43Authentication.Ts43AuthToken, AuthenticationException> mCallback;
 
-        private EapAkaAuthenticationRequest(String appName, @Nullable String appVersion,
+        private EapAkaAuthenticationRequest(String appName, @Nullable String acceptContentType,
+                @Nullable String appVersion,
                 int slotIndex, URL entitlementServerAddress, @Nullable String entitlementVersion,
-                String appId, Executor executor, AuthenticationOutcomeReceiver<
+                String appId, Executor executor,
+                AuthenticationOutcomeReceiver<
                         Ts43Authentication.Ts43AuthToken, AuthenticationException> callback) {
             mAppName = appName;
+            mAcceptContentType = acceptContentType;
             mAppVersion = appVersion;
             mSlotIndex = slotIndex;
             mEntitlementServerAddress = entitlementServerAddress;
@@ -150,6 +154,7 @@ public class Ts43AuthenticationLibrary extends Handler {
 
     private static class OidcAuthenticationServerRequest {
         private final String mAppName;
+        @Nullable private final String mAcceptContentType;
         @Nullable private final String mAppVersion;
         private final int mSlotIndex;
         private final URL mEntitlementServerAddress;
@@ -158,11 +163,12 @@ public class Ts43AuthenticationLibrary extends Handler {
         private final Executor mExecutor;
         private final AuthenticationOutcomeReceiver<URL, AuthenticationException> mCallback;
 
-        private OidcAuthenticationServerRequest(String appName, @Nullable String appVersion,
-                int slotIndex, URL entitlementServerAddress, @Nullable String entitlementVersion,
-                String appId, Executor executor,
+        private OidcAuthenticationServerRequest(String appName, @Nullable String acceptContentType,
+                @Nullable String appVersion, int slotIndex, URL entitlementServerAddress,
+                @Nullable String entitlementVersion, String appId, Executor executor,
                 AuthenticationOutcomeReceiver<URL, AuthenticationException> callback) {
             mAppName = appName;
+            mAcceptContentType = acceptContentType;
             mAppVersion = appVersion;
             mSlotIndex = slotIndex;
             mEntitlementServerAddress = entitlementServerAddress;
@@ -204,6 +210,8 @@ public class Ts43AuthenticationLibrary extends Handler {
      *        in the HTTP GET request to the entitlement server unless
      *        {@link #KEY_APPEND_SHA_TO_APP_NAME_BOOL} or {@link #KEY_OVERRIDE_APP_NAME_STRING} is
      *        set in the configuration bundle.
+     * @param acceptContentType The accepted content type of the HTTP response, or {@code null} to
+     *        use the default.
      * @param appVersion The optional appVersion of the calling application, passed as the
      *        {@code app_version} in the HTTP GET request to the entitlement server.
      * @param slotIndex The logical SIM slot index involved in ODSA operation.
@@ -224,16 +232,17 @@ public class Ts43AuthenticationLibrary extends Handler {
      *        {@link AuthenticationException} with the failure details.
      */
     public void requestEapAkaAuthentication(PersistableBundle configs, String packageName,
-            @Nullable String appVersion, int slotIndex, URL entitlementServerAddress,
-            @Nullable String entitlementVersion, String appId, Executor executor,
-            AuthenticationOutcomeReceiver<
+            @Nullable String acceptContentType, @Nullable String appVersion, int slotIndex,
+            URL entitlementServerAddress, @Nullable String entitlementVersion, String appId,
+            Executor executor, AuthenticationOutcomeReceiver<
                     Ts43Authentication.Ts43AuthToken, AuthenticationException> callback) {
         String[] allowedPackageInfo = configs.getStringArray(KEY_ALLOWED_CERTIFICATES_STRING_ARRAY);
         String certificate = getMatchingCertificate(allowedPackageInfo, packageName);
         if (isCallingPackageAllowed(allowedPackageInfo, packageName, certificate)) {
             obtainMessage(EVENT_REQUEST_EAP_AKA_AUTHENTICATION, new EapAkaAuthenticationRequest(
-                    getAppName(configs, packageName, certificate), appVersion, slotIndex,
-                    entitlementServerAddress, entitlementVersion, appId, executor, callback))
+                    getAppName(configs, packageName, certificate), acceptContentType, appVersion,
+                    slotIndex, entitlementServerAddress, entitlementVersion, appId, executor,
+                    callback))
                     .sendToTarget();
         } else {
             executor.execute(() -> callback.onError(new AuthenticationException(
@@ -258,6 +267,8 @@ public class Ts43AuthenticationLibrary extends Handler {
      *        in the HTTP GET request to the entitlement server unless
      *        {@link #KEY_APPEND_SHA_TO_APP_NAME_BOOL} or {@link #KEY_OVERRIDE_APP_NAME_STRING} is
      *        set in the configuration bundle.
+     * @param acceptContentType The accepted content type of the HTTP response, or {@code null} to
+     *        use the default.
      * @param appVersion The optional appVersion of the calling application, passed as the
      *        {@code app_version} in the HTTP GET request to the entitlement server.
      * @param slotIndex The logical SIM slot index involved in ODSA operation.
@@ -278,8 +289,8 @@ public class Ts43AuthenticationLibrary extends Handler {
      *        will return an {@link AuthenticationException} with the failure details.
      */
     public void requestOidcAuthenticationServer(PersistableBundle configs,
-            String packageName, @Nullable String appVersion, int slotIndex,
-            URL entitlementServerAddress, @Nullable String entitlementVersion,
+            String packageName, @Nullable String acceptContentType, @Nullable String appVersion,
+            int slotIndex, URL entitlementServerAddress, @Nullable String entitlementVersion,
             String appId, Executor executor,
             AuthenticationOutcomeReceiver<URL, AuthenticationException> callback) {
         String[] allowedPackageInfo = configs.getStringArray(KEY_ALLOWED_CERTIFICATES_STRING_ARRAY);
@@ -287,9 +298,9 @@ public class Ts43AuthenticationLibrary extends Handler {
         if (isCallingPackageAllowed(allowedPackageInfo, packageName, certificate)) {
             obtainMessage(EVENT_REQUEST_OIDC_AUTHENTICATION_SERVER,
                     new OidcAuthenticationServerRequest(
-                            getAppName(configs, packageName, certificate), appVersion, slotIndex,
-                            entitlementServerAddress, entitlementVersion, appId, executor,
-                            callback)).sendToTarget();
+                            getAppName(configs, packageName, certificate), acceptContentType,
+                            appVersion, slotIndex, entitlementServerAddress, entitlementVersion,
+                            appId, executor, callback)).sendToTarget();
         } else {
             executor.execute(() -> callback.onError(new AuthenticationException(
                     AuthenticationException.ERROR_INVALID_APP_NAME,
@@ -531,7 +542,8 @@ public class Ts43AuthenticationLibrary extends Handler {
                 Ts43Authentication authLibrary = new Ts43Authentication(mContext,
                         request.mEntitlementServerAddress, request.mEntitlementVersion);
                 Ts43Authentication.Ts43AuthToken authToken = authLibrary.getAuthToken(
-                        request.mSlotIndex, request.mAppId, request.mAppName, request.mAppVersion);
+                        request.mSlotIndex, request.mAppId, request.mAppName, request.mAppVersion,
+                        request.mAcceptContentType);
                 request.mCallback.onResult(authToken);
             } catch (ServiceEntitlementException exception) {
                 request.mCallback.onError(new AuthenticationException(exception));
@@ -550,7 +562,7 @@ public class Ts43AuthenticationLibrary extends Handler {
                 URL url = authLibrary.getOidcAuthServer(
                         mContext, request.mSlotIndex, request.mEntitlementServerAddress,
                         request.mEntitlementVersion, request.mAppId, request.mAppName,
-                        request.mAppVersion);
+                        request.mAppVersion, request.mAcceptContentType);
                 request.mCallback.onResult(url);
             } catch (ServiceEntitlementException exception) {
                 request.mCallback.onError(new AuthenticationException(exception));
```

