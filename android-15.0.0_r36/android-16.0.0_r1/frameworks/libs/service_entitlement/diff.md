```diff
diff --git a/Android.bp b/Android.bp
index 0c3241b..e95a078 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,6 +27,15 @@ java_defaults {
     plugins: ["auto_value_plugin"],
     sdk_version: "system_current",
     min_sdk_version: "29",
+    errorprone: {
+        extra_check_modules: ["//external/nullaway:nullaway_plugin"],
+        javacflags: [
+            "-XepOpt:NullAway:AnnotatedPackages=com.android.libraries.entitlement",
+            "-Xep:NullAway:ERROR",
+            // Exclude @AutoValue generated code.
+            "-XepExcludedPaths:.*/entitlement/.*AutoValue_.*",
+        ],
+    },
 }
 
 java_library {
diff --git a/README.md b/README.md
index 514d120..b3c8256 100644
--- a/README.md
+++ b/README.md
@@ -5,20 +5,31 @@ spec.
 
 ## How to debug
 
-###  Log TAG to filter:
-* ServiceEntitlement
+This lib produces logcat with log tag `ServiceEntitlement`.
 
+###  Enable logging the raw HTTP request / response / headers
 
-###  Enable logging the PII data:
-Grand the permission:
+Such log is not enabled by default since it contains sensitive device identifiers.
+
+To enable, set the system property below, with **ROOT**:
+
+NOTE This is only supported on devices of userdebug builds.
 
 ```shell
 adb root
+adb shell setprop dbg.se.pii_loggable true
 ```
 
-Enable by system property:
+### EAP-AKA auth test
+
+For testing purpose, it may be helpful to make the device under test return a specified
+response to EAP-AKA challenge.
+
+To do so, set the system property below, with **ROOT**:
+
+NOTE This is only supported on devices of userdebug builds.
 
 ```shell
-adb shell setprop dbg.se.pii_loggable true
+adb root
+adb shell setprop persist.entitlement.fake_eap_aka_response <response>
 ```
-NOTE Debug option only available on devices which is built as userdebug.
\ No newline at end of file
diff --git a/java/com/android/libraries/entitlement/EsimOdsaOperation.java b/java/com/android/libraries/entitlement/EsimOdsaOperation.java
index 63d21bd..bd9e1e1 100644
--- a/java/com/android/libraries/entitlement/EsimOdsaOperation.java
+++ b/java/com/android/libraries/entitlement/EsimOdsaOperation.java
@@ -56,6 +56,9 @@ public abstract class EsimOdsaOperation {
     /** ODSA operation: AcquirePlan */
     public static final String OPERATION_ACQUIRE_PLAN = "AcquirePlan";
 
+    /** ODSA operation: VerifyPhoneNumber */
+    public static final String OPERATION_VERIFY_PHONE_NUMBER = "VerifyPhoneNumber";
+
     @Retention(RetentionPolicy.SOURCE)
     @StringDef({
             OPERATION_UNKNOWN,
@@ -65,7 +68,8 @@ public abstract class EsimOdsaOperation {
             OPERATION_ACQUIRE_CONFIGURATION,
             OPERATION_ACQUIRE_PLAN,
             OPERATION_ACQUIRE_TEMPORARY_TOKEN,
-            OPERATION_GET_PHONE_NUMBER
+            OPERATION_GET_PHONE_NUMBER,
+            OPERATION_VERIFY_PHONE_NUMBER
     })
     public @interface OdsaOperation {
     }
@@ -209,6 +213,24 @@ public abstract class EsimOdsaOperation {
     public @interface MessageButton {
     }
 
+    /** Unknown entitlement protocol. This will not be appended to the request. */
+    public static final String ENTITLEMENT_PROTOCOL_UNKNOWN = "";
+
+    /** Device supports TS.43 entitlement protocol. */
+    public static final String ENTITLEMENT_PROTOCOL_TS43 = "0";
+
+    /** Device does not support TS.43 entitlement protocol. */
+    public static final String ENTITLEMENT_PROTOCOL_OTHER = "1";
+
+    @Retention(RetentionPolicy.SOURCE)
+    @StringDef({
+            ENTITLEMENT_PROTOCOL_UNKNOWN,
+            ENTITLEMENT_PROTOCOL_TS43,
+            ENTITLEMENT_PROTOCOL_OTHER
+    })
+    public @interface EntitlementProtocol {
+    }
+
     /** Returns the ODSA operation. Used by HTTP parameter {@code operation}. */
     public abstract String operation();
 
@@ -327,6 +349,16 @@ public abstract class EsimOdsaOperation {
     @NonNull
     public abstract String targetTerminalModel();
 
+    /**
+     * Returns whether the subscription transfer is for cross-TS.43 platform. Used by HTTP parameter
+     * {@code target_terminal_entitlement_protocol}.
+     *
+     * <p>This is an optional param for cross-platform.
+     */
+    @NonNull
+    @EntitlementProtocol
+    public abstract String targetTerminalEntitlementProtocol();
+
     /**
      * Returns the unique identifier of the old device eSIM, like the IMEI associated with the eSIM.
      * Used by HTTP parameter {@code old_terminal_id}.
@@ -336,6 +368,16 @@ public abstract class EsimOdsaOperation {
     /** Returns the ICCID of old device eSIM. Used by HTTP parameter {@code old_terminal_iccid}. */
     public abstract String oldTerminalIccid();
 
+    /**
+     * Returns whether the subscription transfer is for cross-TS.43 platform. Used by HTTP parameter
+     * {@code old_terminal_entitlement_protocol}.
+     *
+     * <p>This is an optional param for cross-platform.
+     */
+    @NonNull
+    @EntitlementProtocol
+    public abstract String oldTerminalEntitlementProtocol();
+
     /**
      * Returns the user response to the MSG content. Used by HTTP parameter {@code MSG_response}.
      */
@@ -370,8 +412,10 @@ public abstract class EsimOdsaOperation {
                 .setTargetTerminalEid("")
                 .setTargetTerminalSerialNumber("")
                 .setTargetTerminalModel("")
+                .setTargetTerminalEntitlementProtocol(ENTITLEMENT_PROTOCOL_UNKNOWN)
                 .setOldTerminalId("")
                 .setOldTerminalIccid("")
+                .setOldTerminalEntitlementProtocol(ENTITLEMENT_PROTOCOL_UNKNOWN)
                 .setMessageResponse("")
                 .setMessageButton("");
     }
@@ -399,6 +443,7 @@ public abstract class EsimOdsaOperation {
          * @see #OPERATION_ACQUIRE_TEMPORARY_TOKEN
          * @see #OPERATION_GET_PHONE_NUMBER
          * @see #OPERATION_ACQUIRE_PLAN
+         * @see #OPERATION_VERIFY_PHONE_NUMBER
          */
         @NonNull
         public abstract Builder setOperation(@NonNull @OdsaOperation String operation);
@@ -638,6 +683,18 @@ public abstract class EsimOdsaOperation {
         @NonNull
         public abstract Builder setTargetTerminalModel(@NonNull String targetTerminalModel);
 
+        /**
+         * Sets the entitlement protocol of primary device. Used by HTTP parameter
+         * {@code target_terminal_entitlement_protocol}.
+         *
+         * @param targetTerminalEntitlementProtocol The entitlement protocol of primary device.
+         *                                          <p>This is an optional param for cross-platform.
+         * @return The builder.
+         */
+        @NonNull
+        public abstract Builder setTargetTerminalEntitlementProtocol(
+                @NonNull @EntitlementProtocol String targetTerminalEntitlementProtocol);
+
         /**
          * Sets the unique identifier of the old device eSIM, like the IMEI associated with the
          * eSIM.
@@ -662,6 +719,18 @@ public abstract class EsimOdsaOperation {
         @NonNull
         public abstract Builder setOldTerminalIccid(@NonNull String oldTerminalIccid);
 
+        /**
+         * Sets the entitlement protocol of the old device. Used by HTTP parameter
+         * {@code old_terminal_entitlement_protocol}.
+         *
+         * @param oldTerminalEntitlementProtocol The entitlement protocol of the old device.
+         *                                       <p>This is an optional param for cross-platform.
+         * @return The builder.
+         */
+        @NonNull
+        public abstract Builder setOldTerminalEntitlementProtocol(
+                @NonNull @EntitlementProtocol String oldTerminalEntitlementProtocol);
+
         /**
          * Sets the user response to the MSG content. Used by HTTP parameter {@code MSG_response}
          * if set.
diff --git a/java/com/android/libraries/entitlement/ServiceEntitlement.java b/java/com/android/libraries/entitlement/ServiceEntitlement.java
index bf1b4dd..b3e47c9 100644
--- a/java/com/android/libraries/entitlement/ServiceEntitlement.java
+++ b/java/com/android/libraries/entitlement/ServiceEntitlement.java
@@ -19,6 +19,7 @@ package com.android.libraries.entitlement;
 import android.content.Context;
 
 import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.libraries.entitlement.eapaka.EapAkaApi;
@@ -96,6 +97,7 @@ public class ServiceEntitlement {
 
     private final CarrierConfig carrierConfig;
     private final EapAkaApi eapAkaApi;
+    @Nullable
     private ServiceEntitlementRequest mOidcRequest;
     /**
      * Creates an instance for service entitlement configuration query and operation for the
@@ -432,6 +434,10 @@ public class ServiceEntitlement {
     public HttpResponse getEntitlementStatusResponseFromOidc(
             String url, ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
+        if (mOidcRequest == null) {
+            throw new IllegalStateException(
+                    "acquireOidcAuthenticationEndpoint must be called before calling this method.");
+        }
         return eapAkaApi.queryEntitlementStatusFromOidc(
                 url, carrierConfig, mOidcRequest, additionalHeaders);
     }
diff --git a/java/com/android/libraries/entitlement/ServiceEntitlementRequest.java b/java/com/android/libraries/entitlement/ServiceEntitlementRequest.java
index 38206de..e53304b 100644
--- a/java/com/android/libraries/entitlement/ServiceEntitlementRequest.java
+++ b/java/com/android/libraries/entitlement/ServiceEntitlementRequest.java
@@ -119,6 +119,11 @@ public abstract class ServiceEntitlementRequest {
      */
     public abstract String boostType();
 
+    /**
+     * Returns the GID1 (Group ID level 1) of the SIM card. Used by HTTP parameter "gid1".
+     */
+    public abstract String gid1();
+
     /**
      * Returns a new {@link Builder} object.
      */
@@ -137,7 +142,8 @@ public abstract class ServiceEntitlementRequest {
                 .setNotificationToken("")
                 .setNotificationAction(Ts43Constants.NOTIFICATION_ACTION_ENABLE_FCM)
                 .setAcceptContentType(ACCEPT_CONTENT_TYPE_JSON_AND_XML)
-                .setBoostType("");
+                .setBoostType("")
+                .setGid1("");
     }
 
     /**
@@ -260,6 +266,15 @@ public abstract class ServiceEntitlementRequest {
          */
         public abstract Builder setBoostType(String value);
 
+        /**
+         * Sets the GID1 for the SIM Card. Used by HTTP parameter "gid1" for MVNO entitlement
+         * activation.
+         *
+         * <p>Required for TS.43 Versions beginning with v12.0. Will retrieve the value from
+         * {@link android.telephony.TelephonyManager} if not set.
+         */
+        public abstract Builder setGid1(String value);
+
         public abstract ServiceEntitlementRequest build();
     }
 }
diff --git a/java/com/android/libraries/entitlement/Ts43Authentication.java b/java/com/android/libraries/entitlement/Ts43Authentication.java
index a2af936..b0030ab 100644
--- a/java/com/android/libraries/entitlement/Ts43Authentication.java
+++ b/java/com/android/libraries/entitlement/Ts43Authentication.java
@@ -16,6 +16,7 @@
 
 package com.android.libraries.entitlement;
 
+import static com.google.common.base.Preconditions.checkNotNull;
 import static com.google.common.base.Strings.nullToEmpty;
 
 import android.content.Context;
@@ -39,7 +40,6 @@ import com.google.auto.value.AutoValue;
 import com.google.common.collect.ImmutableList;
 
 import java.net.URL;
-import java.util.Objects;
 
 /**
  * The class responsible for TS.43 authentication process.
@@ -113,6 +113,7 @@ public class Ts43Authentication {
      * For test mocking only.
      */
     @VisibleForTesting
+    @Nullable
     private ServiceEntitlement mServiceEntitlement;
 
     /**
@@ -128,11 +129,8 @@ public class Ts43Authentication {
      */
     public Ts43Authentication(@NonNull Context context, @NonNull URL entitlementServerAddress,
             @Nullable String entitlementVersion) {
-        Objects.requireNonNull(context, "context is null");
-        Objects.requireNonNull(entitlementServerAddress, "entitlementServerAddress is null.");
-
-        mContext = context;
-        mEntitlementServerAddress = entitlementServerAddress;
+        mContext = checkNotNull(context);
+        mEntitlementServerAddress = checkNotNull(entitlementServerAddress);
 
         if (entitlementVersion != null) {
             mEntitlementVersion = entitlementVersion;
@@ -155,6 +153,8 @@ public class Ts43Authentication {
      * request in GSMA TS.43 Service Entitlement Configuration section 2.3.
      * @param appVersion The calling client's version. Used for {@code app_version} in HTTP GET
      * request in GSMA TS.43 Service Entitlement Configuration section 2.3.
+     * @param acceptContentType The accepted content type of the HTTP response, or {@code null} to
+     *                          use the default.
      *
      * @return The authentication token.
      *
@@ -167,10 +167,10 @@ public class Ts43Authentication {
      */
     @NonNull
     public Ts43AuthToken getAuthToken(int slotIndex, @NonNull @AppId String appId,
-            @Nullable String appName, @Nullable String appVersion)
+            @Nullable String appName, @Nullable String appVersion,
+            @Nullable String acceptContentType)
             throws ServiceEntitlementException {
-        Objects.requireNonNull(appId, "appId is null");
-
+        checkNotNull(appId);
         if (!Ts43Constants.isValidAppId(appId)) {
             throw new IllegalArgumentException("getAuthToken: invalid app id " + appId);
         }
@@ -186,13 +186,16 @@ public class Ts43Authentication {
 
         // Build the HTTP request. The default params are specified in
         // ServiceEntitlementRequest.builder() already.
-        ServiceEntitlementRequest request =
+        ServiceEntitlementRequest.Builder builder =
                 ServiceEntitlementRequest.builder()
                         .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(imei)
-                        .setAppName(appName)
-                        .setAppVersion(appVersion)
-                        .build();
+                        .setTerminalId(nullToEmpty(imei))
+                        .setAppName(nullToEmpty(appName))
+                        .setAppVersion(nullToEmpty(appVersion));
+        if (acceptContentType != null) {
+            builder.setAcceptContentType(acceptContentType);
+        }
+        ServiceEntitlementRequest request = builder.build();
         CarrierConfig carrierConfig = CarrierConfig.builder()
                 .setServerUrl(mEntitlementServerAddress.toString())
                 .build();
@@ -218,7 +221,7 @@ public class Ts43Authentication {
         try {
             response = mServiceEntitlement.getEntitlementStatusResponse(
                     ImmutableList.of(appId), request);
-            rawXml = response == null ? null : response.body();
+            rawXml = response == null ? "" : response.body();
             Log.d(TAG, "getAuthToken: rawXml=" + rawXml);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "Failed to get authentication token. e=" + e);
@@ -267,6 +270,8 @@ public class Ts43Authentication {
      * request in GSMA TS.43 Service Entitlement Configuration section 2.3.
      * @param appVersion The calling client's version. Used for {@code app_version} in HTTP GET
      * request in GSMA TS.43 Service Entitlement Configuration section 2.3.
+     * @param acceptContentType The accepted content type of the HTTP response, or {@code null} to
+     *                          use the default.
      *
      * @return The URL of OIDC server with all the required parameters for client to launch a
      * user interface for users to interact with the authentication process. The parameters in URL
@@ -279,9 +284,9 @@ public class Ts43Authentication {
     @NonNull
     public URL getOidcAuthServer(@NonNull Context context, int slotIndex,
             @NonNull URL entitlementServerAddress, @Nullable String entitlementVersion,
-            @NonNull @AppId String appId, @Nullable String appName, @Nullable String appVersion)
-            throws ServiceEntitlementException {
-        return null;
+            @NonNull @AppId String appId, @Nullable String appName, @Nullable String appVersion,
+            @Nullable String acceptContentType) throws ServiceEntitlementException {
+        throw new UnsupportedOperationException("Not implemented yet");
     }
 
     /**
@@ -300,6 +305,6 @@ public class Ts43Authentication {
     @NonNull
     public Ts43AuthToken getAuthToken(@NonNull URL aesUrl)
             throws ServiceEntitlementException {
-        return null;
+        throw new UnsupportedOperationException("Not implemented yet");
     }
 }
diff --git a/java/com/android/libraries/entitlement/Ts43Operation.java b/java/com/android/libraries/entitlement/Ts43Operation.java
index b1f8538..ebbf924 100644
--- a/java/com/android/libraries/entitlement/Ts43Operation.java
+++ b/java/com/android/libraries/entitlement/Ts43Operation.java
@@ -16,6 +16,8 @@
 
 package com.android.libraries.entitlement;
 
+import static com.google.common.base.Preconditions.checkNotNull;
+
 import android.content.Context;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
@@ -127,6 +129,10 @@ public class Ts43Operation {
     /** IMEI of the device. */
     private final String mImei;
 
+    /** used to identify the requesting application. Optional */
+    @NonNull
+    private final String mAppName;
+
     /**
      * Constructor of Ts43Operation.
      *
@@ -138,6 +144,8 @@ public class Ts43Operation {
      * @param authToken The authentication token.
      * @param tokenType The token type. Can be {@link #TOKEN_TYPE_NORMAL} or
      *                  {@link #TOKEN_TYPE_TEMPORARY}.
+     * @param appName The name of the device application making the request or empty string
+     *                if unspecified.
      */
     public Ts43Operation(
             @NonNull Context context,
@@ -145,7 +153,8 @@ public class Ts43Operation {
             @NonNull URL entitlementServerAddress,
             @Nullable String entitlementVersion,
             @NonNull String authToken,
-            @TokenType int tokenType) {
+            @TokenType int tokenType,
+            @NonNull String appName) {
         mContext = context;
         mEntitlementServerAddress = entitlementServerAddress;
         if (entitlementVersion != null) {
@@ -179,6 +188,7 @@ public class Ts43Operation {
             imei = telephonyManager.getImei(slotIndex);
         }
         mImei = Strings.nullToEmpty(imei);
+        mAppName = appName;
     }
 
     /**
@@ -199,12 +209,13 @@ public class Ts43Operation {
         ServiceEntitlementRequest.Builder builder =
                 ServiceEntitlementRequest.builder()
                         .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(mImei);
+                        .setTerminalId(mImei)
+                        .setAppName(mAppName);
 
         if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(mAuthToken);
+            builder.setAuthenticationToken(checkNotNull(mAuthToken));
         } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(mTemporaryToken);
+            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
         }
 
         String notificationToken = checkEligibilityRequest.notificationToken();
@@ -362,12 +373,13 @@ public class Ts43Operation {
                 ServiceEntitlementRequest.builder()
                         .setEntitlementVersion(mEntitlementVersion)
                         .setTerminalId(mImei)
+                        .setAppName(mAppName)
                         .setAcceptContentType(ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
 
         if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(mAuthToken);
+            builder.setAuthenticationToken(checkNotNull(mAuthToken));
         } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(mTemporaryToken);
+            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
         }
 
         String notificationToken = manageSubscriptionRequest.notificationToken();
@@ -558,12 +570,13 @@ public class Ts43Operation {
         ServiceEntitlementRequest.Builder builder =
                 ServiceEntitlementRequest.builder()
                         .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(mImei);
+                        .setTerminalId(mImei)
+                        .setAppName(mAppName);
 
         if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(mAuthToken);
+            builder.setAuthenticationToken(checkNotNull(mAuthToken));
         } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(mTemporaryToken);
+            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
         }
 
         ServiceEntitlementRequest request = builder.build();
@@ -640,7 +653,8 @@ public class Ts43Operation {
         ServiceEntitlementRequest.Builder builder = ServiceEntitlementRequest.builder()
                 .setEntitlementVersion(mEntitlementVersion)
                 .setTerminalId(mImei)
-                .setAuthenticationToken(mAuthToken);
+                .setAppName(mAppName)
+                .setAuthenticationToken(checkNotNull(mAuthToken));
 
         String notificationToken = acquireConfigurationRequest.notificationToken();
         if (!TextUtils.isEmpty(notificationToken)) {
@@ -801,7 +815,8 @@ public class Ts43Operation {
                 ServiceEntitlementRequest.builder()
                         .setEntitlementVersion(mEntitlementVersion)
                         .setTerminalId(mImei)
-                        .setAuthenticationToken(mAuthToken)
+                        .setAuthenticationToken(checkNotNull(mAuthToken))
+                        .setAppName(mAppName)
                         .build();
 
         EsimOdsaOperation operation =
@@ -901,12 +916,12 @@ public class Ts43Operation {
         }
 
         if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(mAuthToken);
+            builder.setAuthenticationToken(checkNotNull(mAuthToken));
         } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(mTemporaryToken);
+            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
         }
 
-        ServiceEntitlementRequest request = builder.build();
+        ServiceEntitlementRequest request = builder.setAppName(mAppName).build();
 
         EsimOdsaOperation operation =
                 EsimOdsaOperation.builder()
@@ -1166,4 +1181,4 @@ public class Ts43Operation {
         }
         return EsimOdsaOperation.SERVICE_STATUS_UNKNOWN;
     }
-}
\ No newline at end of file
+}
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java b/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
index f155f4f..d151403 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
@@ -21,6 +21,8 @@ import static com.android.libraries.entitlement.ServiceEntitlementException.ERRO
 import static com.android.libraries.entitlement.ServiceEntitlementException.ERROR_JSON_COMPOSE_FAILURE;
 import static com.android.libraries.entitlement.ServiceEntitlementException.ERROR_MALFORMED_HTTP_RESPONSE;
 
+import static com.google.common.base.Preconditions.checkNotNull;
+
 import android.content.Context;
 import android.content.pm.PackageInfo;
 import android.net.Uri;
@@ -50,6 +52,7 @@ import com.google.common.net.HttpHeaders;
 import org.json.JSONException;
 import org.json.JSONObject;
 
+import java.math.BigDecimal;
 import java.util.List;
 
 public class EapAkaApi {
@@ -74,6 +77,7 @@ public class EapAkaApi {
     private static final String NOTIF_TOKEN = "notif_token";
     private static final String APP_VERSION = "app_version";
     private static final String APP_NAME = "app_name";
+    private static final String GID1 = "gid1";
 
     private static final String OPERATION = "operation";
     private static final String OPERATION_TYPE = "operation_type";
@@ -100,9 +104,13 @@ public class EapAkaApi {
     private static final String TARGET_TERMINAL_SERIAL_NUMBER = "target_terminal_sn";
     // Non-standard params for Korean carriers
     private static final String TARGET_TERMINAL_MODEL = "target_terminal_model";
+    private static final String TARGET_TERMINAL_ENTITLEMENT_PROTOCOL =
+            "target_terminal_entitlement_protocol";
 
     private static final String OLD_TERMINAL_ID = "old_terminal_id";
     private static final String OLD_TERMINAL_ICCID = "old_terminal_iccid";
+    private static final String OLD_TERMINAL_ENTITLEMENT_PROTOCOL =
+            "old_terminal_entitlement_protocol";
 
     private static final String BOOST_TYPE = "boost_type";
 
@@ -190,13 +198,13 @@ public class EapAkaApi {
             Log.d(TAG, "Fast Re-Authentication");
             return carrierConfig.useHttpPost()
                     ? httpPost(
-                            postData,
+                            checkNotNull(postData),
                             carrierConfig,
                             request.acceptContentType(),
                             userAgent,
                             additionalHeaders)
                     : httpGet(
-                            urlBuilder.toString(),
+                            checkNotNull(urlBuilder).toString(),
                             carrierConfig,
                             request.acceptContentType(),
                             userAgent,
@@ -207,13 +215,13 @@ public class EapAkaApi {
             HttpResponse challengeResponse =
                     carrierConfig.useHttpPost()
                             ? httpPost(
-                                    postData,
+                                    checkNotNull(postData),
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
                                     userAgent,
                                     additionalHeaders)
                             : httpGet(
-                                    urlBuilder.toString(),
+                                    checkNotNull(urlBuilder).toString(),
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
                                     userAgent,
@@ -413,13 +421,13 @@ public class EapAkaApi {
             Log.d(TAG, "Fast Re-Authentication");
             return carrierConfig.useHttpPost()
                     ? httpPost(
-                            postData,
+                            checkNotNull(postData),
                             carrierConfig,
                             request.acceptContentType(),
                             userAgent,
                             additionalHeaders)
                     : httpGet(
-                            urlBuilder.toString(),
+                            checkNotNull(urlBuilder).toString(),
                             carrierConfig,
                             request.acceptContentType(),
                             userAgent,
@@ -430,13 +438,13 @@ public class EapAkaApi {
             HttpResponse challengeResponse =
                     carrierConfig.useHttpPost()
                             ? httpPost(
-                                    postData,
+                                    checkNotNull(postData),
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
                                     userAgent,
                                     additionalHeaders)
                             : httpGet(
-                                    urlBuilder.toString(),
+                                    checkNotNull(urlBuilder).toString(),
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
                                     userAgent,
@@ -497,13 +505,13 @@ public class EapAkaApi {
         HttpResponse response =
                 carrierConfig.useHttpPost()
                         ? httpPost(
-                                postData,
+                                checkNotNull(postData),
                                 carrierConfig,
                                 request.acceptContentType(),
                                 userAgent,
                                 additionalHeaders)
                         : httpGet(
-                                urlBuilder.toString(),
+                                checkNotNull(urlBuilder).toString(),
                                 carrierConfig,
                                 request.acceptContentType(),
                                 userAgent,
@@ -611,6 +619,12 @@ public class EapAkaApi {
             urlBuilder.appendQueryParameter(TERMINAL_ID, request.terminalId());
         }
 
+        if (!TextUtils.isEmpty(request.gid1())) {
+            urlBuilder.appendQueryParameter(GID1, request.gid1());
+        } else if ((new BigDecimal(request.entitlementVersion())).intValue() >= 12) {
+            urlBuilder.appendQueryParameter(GID1, mTelephonyManager.getGroupIdLevel1());
+        }
+
         // Optional query parameters, append them if not empty
         appendOptionalQueryParameter(urlBuilder, APP_VERSION, request.appVersion());
         appendOptionalQueryParameter(urlBuilder, APP_NAME, request.appName());
@@ -656,6 +670,12 @@ public class EapAkaApi {
                 postData.put(TERMINAL_ID, request.terminalId());
             }
 
+            if (!TextUtils.isEmpty(request.gid1())) {
+                postData.put(GID1, request.gid1());
+            } else if ((new BigDecimal(request.entitlementVersion())).intValue() >= 12) {
+                postData.put(GID1, mTelephonyManager.getGroupIdLevel1());
+            }
+
             // Optional query parameters, append them if not empty
             appendOptionalQueryParameter(postData, APP_VERSION, request.appVersion());
             appendOptionalQueryParameter(postData, APP_NAME, request.appName());
@@ -740,9 +760,17 @@ public class EapAkaApi {
                 odsaOperation.targetTerminalSerialNumber());
         appendOptionalQueryParameter(
                 urlBuilder, TARGET_TERMINAL_MODEL, odsaOperation.targetTerminalModel());
+        appendOptionalQueryParameter(
+                urlBuilder,
+                TARGET_TERMINAL_ENTITLEMENT_PROTOCOL,
+                odsaOperation.targetTerminalEntitlementProtocol());
         appendOptionalQueryParameter(
                 urlBuilder, OLD_TERMINAL_ICCID, odsaOperation.oldTerminalIccid());
         appendOptionalQueryParameter(urlBuilder, OLD_TERMINAL_ID, odsaOperation.oldTerminalId());
+        appendOptionalQueryParameter(
+                urlBuilder,
+                OLD_TERMINAL_ENTITLEMENT_PROTOCOL,
+                odsaOperation.oldTerminalEntitlementProtocol());
         appendOptionalQueryParameter(urlBuilder, MESSAGE_RESPONSE, odsaOperation.messageResponse());
         appendOptionalQueryParameter(urlBuilder, MESSAGE_BUTTON, odsaOperation.messageButton());
     }
@@ -795,9 +823,17 @@ public class EapAkaApi {
                     odsaOperation.targetTerminalSerialNumber());
             appendOptionalQueryParameter(
                     postData, TARGET_TERMINAL_MODEL, odsaOperation.targetTerminalModel());
+            appendOptionalQueryParameter(
+                    postData,
+                    TARGET_TERMINAL_ENTITLEMENT_PROTOCOL,
+                    odsaOperation.targetTerminalEntitlementProtocol());
             appendOptionalQueryParameter(
                     postData, OLD_TERMINAL_ICCID, odsaOperation.oldTerminalIccid());
             appendOptionalQueryParameter(postData, OLD_TERMINAL_ID, odsaOperation.oldTerminalId());
+            appendOptionalQueryParameter(
+                    postData,
+                    OLD_TERMINAL_ENTITLEMENT_PROTOCOL,
+                    odsaOperation.oldTerminalEntitlementProtocol());
             appendOptionalQueryParameter(
                     postData, MESSAGE_RESPONSE, odsaOperation.messageResponse());
             appendOptionalQueryParameter(postData, MESSAGE_BUTTON, odsaOperation.messageButton());
@@ -814,7 +850,8 @@ public class EapAkaApi {
         }
     }
 
-    private void appendOptionalQueryParameter(JSONObject postData, String key, String value)
+    private void appendOptionalQueryParameter(
+            JSONObject postData, String key, @Nullable String value)
             throws JSONException {
         if (!TextUtils.isEmpty(value)) {
             postData.put(key, value);
@@ -964,9 +1001,6 @@ public class EapAkaApi {
     }
 
     private String trimString(String s, int maxLength) {
-        if (s == null) {
-            return null;
-        }
         return s.substring(0, Math.min(s.length(), maxLength));
     }
 
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaChallenge.java b/java/com/android/libraries/entitlement/eapaka/EapAkaChallenge.java
index 6563ede..e3fa8e1 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaChallenge.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaChallenge.java
@@ -47,12 +47,12 @@ public class EapAkaChallenge {
     // The identifier of Response must same as Request
     private byte mIdentifier = -1;
     // The value of AT_AUTN, network authentication token
-    private byte[] mAutn;
+    @Nullable private byte[] mAutn;
     // The value of AT_RAND, random challenge
-    private byte[] mRand;
+    @Nullable private byte[] mRand;
 
     // Base64 encoded 3G security context for SIM Authentication request
-    private String mSimAuthenticationRequest;
+    @Nullable private String mSimAuthenticationRequest;
 
     private EapAkaChallenge() {}
 
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java b/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
index c7351e0..240ae75 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
@@ -19,6 +19,8 @@ package com.android.libraries.entitlement.eapaka;
 import static com.android.libraries.entitlement.ServiceEntitlementException.ERROR_ICC_AUTHENTICATION_NOT_AVAILABLE;
 import static com.android.libraries.entitlement.eapaka.EapAkaChallenge.SUBTYPE_AKA_CHALLENGE;
 import static com.android.libraries.entitlement.eapaka.EapAkaChallenge.TYPE_EAP_AKA;
+import static com.google.common.base.Preconditions.checkNotNull;
+import static com.google.common.base.Strings.nullToEmpty;
 
 import android.content.Context;
 import android.telephony.TelephonyManager;
@@ -55,9 +57,9 @@ public class EapAkaResponse {
     private static final int MAC_LENGTH = 16;
 
     // RFC 4187 Section 9.4 EAP-Response/AKA-Challenge
-    private String mResponse;
+    @Nullable private String mResponse;
     // RFC 4187 Section 9.6 EAP-Response/AKA-Synchronization-Failure
-    private String mSynchronizationFailureResponse;
+    @Nullable private String mSynchronizationFailureResponse;
 
     private EapAkaResponse() {}
 
@@ -109,10 +111,12 @@ public class EapAkaResponse {
         EapAkaSecurityContext securityContext = EapAkaSecurityContext.from(response);
         EapAkaResponse result = new EapAkaResponse();
 
-        if (securityContext.getRes() != null
-                && securityContext.getIk() != null
-                && securityContext.getCk() != null) { // Success authentication
+        byte[] res = securityContext.getRes();
+        byte[] ik = securityContext.getIk();
+        byte[] ck = securityContext.getCk();
+        byte[] auts = securityContext.getAuts();
 
+        if (res != null && ik != null && ck != null) { // Success authentication
             // generate master key - refer to RFC 4187, section 7. Key Generation
             MasterKey mk =
                     MasterKey.create(
@@ -120,8 +124,8 @@ public class EapAkaResponse {
                                     telephonyManager.getSimOperator(),
                                     telephonyManager.getSubscriberId(),
                                     eapAkaRealm),
-                            securityContext.getIk(),
-                            securityContext.getCk());
+                            ik,
+                            ck);
             // K_aut is the key used to calculate MAC
             if (mk == null || mk.getAut() == null) {
                 throw new ServiceEntitlementException(
@@ -131,7 +135,7 @@ public class EapAkaResponse {
             // generate EAP-AKA challenge response message
             byte[] challengeResponse =
                     generateEapAkaChallengeResponse(
-                            securityContext.getRes(), eapAkaChallenge.getIdentifier(), mk.getAut());
+                            res, eapAkaChallenge.getIdentifier(), mk.getAut());
             if (challengeResponse == null) {
                 throw new ServiceEntitlementException(
                         ERROR_ICC_AUTHENTICATION_NOT_AVAILABLE,
@@ -140,11 +144,10 @@ public class EapAkaResponse {
             // base64 encoding
             result.mResponse = Base64.encodeToString(challengeResponse, Base64.NO_WRAP).trim();
 
-        } else if (securityContext.getAuts() != null) {
-
+        } else if (auts != null) {
             byte[] syncFailure =
                     generateEapAkaSynchronizationFailureResponse(
-                            securityContext.getAuts(), eapAkaChallenge.getIdentifier());
+                            auts, eapAkaChallenge.getIdentifier());
             result.mSynchronizationFailureResponse =
                     Base64.encodeToString(syncFailure, Base64.NO_WRAP).trim();
 
@@ -190,9 +193,8 @@ public class EapAkaResponse {
      * Refer to RFC 4187 section 9.6 EAP-Response/AKA-Synchronization-Failure.
      */
     @VisibleForTesting
-    @Nullable
     static byte[] generateEapAkaSynchronizationFailureResponse(
-            @Nullable byte[] auts, byte identifier) {
+            byte[] auts, byte identifier) {
         // size = 8 (header) + 2 (attribute & length) + AUTS
         byte[] message = new byte[10 + auts.length];
 
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaSecurityContext.java b/java/com/android/libraries/entitlement/eapaka/EapAkaSecurityContext.java
index 145773d..f9efd3a 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaSecurityContext.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaSecurityContext.java
@@ -41,13 +41,13 @@ class EapAkaSecurityContext {
     private boolean mValid;
 
     // User response, populated on successful authentication
-    private byte[] mRes;
+    @Nullable private byte[] mRes;
     // Cipher Key, populated on successful authentication
-    private byte[] mCk;
+    @Nullable private byte[] mCk;
     // Integrity Key, populated on successful authentication
-    private byte[] mIk;
+    @Nullable private byte[] mIk;
     // AUTS, populated on synchronization failure
-    private byte[] mAuts;
+    @Nullable private byte[] mAuts;
 
     private EapAkaSecurityContext() {}
 
@@ -123,6 +123,7 @@ class EapAkaSecurityContext {
         }
     }
 
+    @Nullable
     private byte[] parseTag(int index, byte[] src) {
         // index at the length byte
         if (index >= src.length) {
diff --git a/java/com/android/libraries/entitlement/eapaka/MasterKey.java b/java/com/android/libraries/entitlement/eapaka/MasterKey.java
index 9bb1d6b..c000eac 100644
--- a/java/com/android/libraries/entitlement/eapaka/MasterKey.java
+++ b/java/com/android/libraries/entitlement/eapaka/MasterKey.java
@@ -49,19 +49,21 @@ class MasterKey {
     private static final int LENGTH_TEKS = 160;
 
     /* Master Key */
-    private byte[] mMasterKey;
+    @Nullable private byte[] mMasterKey;
 
     /* Transient EAP Keys */
-    private byte[] mEncr;
-    private byte[] mAut;
-    private byte[] mMsk;
-    private byte[] mEmsk;
+    @Nullable private byte[] mEncr;
+    @Nullable private byte[] mAut;
+    @Nullable private byte[] mMsk;
+    @Nullable private byte[] mEmsk;
 
     private MasterKey() {
     }
 
     /** Create the {@code masterKey}. */
-    public static MasterKey create(String identity, @Nullable byte[] ik, @Nullable byte[] ck)
+    @Nullable
+    public static MasterKey create(
+            @Nullable String identity, @Nullable byte[] ik, @Nullable byte[] ck)
             throws ServiceEntitlementException {
         if (TextUtils.isEmpty(identity)
                 || ik == null
@@ -132,6 +134,7 @@ class MasterKey {
     }
 
     /** Returns {@code aut}. */
+    @Nullable
     public byte[] getAut() {
         return mAut;
     }
diff --git a/java/com/android/libraries/entitlement/http/HttpClient.java b/java/com/android/libraries/entitlement/http/HttpClient.java
index 03434a6..e2af643 100644
--- a/java/com/android/libraries/entitlement/http/HttpClient.java
+++ b/java/com/android/libraries/entitlement/http/HttpClient.java
@@ -56,7 +56,6 @@ import java.util.Map;
 public class HttpClient {
     private static final String TAG = "ServiceEntitlement";
 
-    private HttpURLConnection mConnection;
     private boolean mSaveHistory;
     private ArrayList<String> mHistory;
 
@@ -71,11 +70,11 @@ public class HttpClient {
             mHistory.add(request.toString());
         }
         logPii("HttpClient.request url: " + request.url());
-        createConnection(request);
-        logPii("HttpClient.request headers (partial): " + mConnection.getRequestProperties());
+        HttpURLConnection connection = createConnection(request);
+        logPii("HttpClient.request headers (partial): " + connection.getRequestProperties());
         try {
             if (POST.equals(request.requestMethod())) {
-                try (OutputStream out = new DataOutputStream(mConnection.getOutputStream())) {
+                try (OutputStream out = new DataOutputStream(connection.getOutputStream())) {
                     // Android JSON toString() escapes forward-slash with back-slash. It's not
                     // supported by some vendor and not mandatory in JSON spec. Undo escaping.
                     String postData = request.postData().toString().replace("\\/", "/");
@@ -83,8 +82,8 @@ public class HttpClient {
                     logPii("HttpClient.request post data: " + postData);
                 }
             }
-            mConnection.connect(); // This is to trigger SocketTimeoutException early
-            HttpResponse response = getHttpResponse(mConnection);
+            connection.connect(); // This is to trigger SocketTimeoutException early
+            HttpResponse response = getHttpResponse(connection);
             Log.d(TAG, "HttpClient.response : " + response.toShortDebugString());
             if (mSaveHistory) {
                 mHistory.add(response.toString());
@@ -94,12 +93,12 @@ public class HttpClient {
             throw new ServiceEntitlementException(
                     ERROR_HTTP_STATUS_NOT_SUCCESS,
                     "Connection error stream: "
-                            + StreamUtils.inputStreamToStringSafe(mConnection.getErrorStream())
+                            + StreamUtils.inputStreamToStringSafe(connection.getErrorStream())
                             + " IOException: "
                             + ioe.toString(),
                     ioe);
         } finally {
-            closeConnection();
+            connection.disconnect();
         }
     }
 
@@ -117,45 +116,41 @@ public class HttpClient {
         mHistory.clear();
     }
 
-    private void createConnection(HttpRequest request) throws ServiceEntitlementException {
+    private HttpURLConnection createConnection(HttpRequest request)
+            throws ServiceEntitlementException {
         try {
+            HttpURLConnection connection;
             URL url = new URL(request.url());
             UrlConnectionFactory urlConnectionFactory = request.urlConnectionFactory();
             Network network = request.network();
             if (network != null) {
-                mConnection = (HttpURLConnection) network.openConnection(url);
+                connection = (HttpURLConnection) network.openConnection(url);
             } else if (urlConnectionFactory != null) {
-                mConnection = (HttpURLConnection) urlConnectionFactory.openConnection(url);
-            } else  {
-                mConnection = (HttpURLConnection) url.openConnection();
+                connection = (HttpURLConnection) urlConnectionFactory.openConnection(url);
+            } else {
+                connection = (HttpURLConnection) url.openConnection();
             }
 
-            mConnection.setInstanceFollowRedirects(false);
+            connection.setInstanceFollowRedirects(false);
             // add HTTP headers
             for (Map.Entry<String, String> entry : request.requestProperties().entries()) {
-                mConnection.addRequestProperty(entry.getKey(), entry.getValue());
+                connection.addRequestProperty(entry.getKey(), entry.getValue());
             }
 
             // set parameters
-            mConnection.setRequestMethod(request.requestMethod());
-            mConnection.setConnectTimeout((int) SECONDS.toMillis(request.timeoutInSec()));
-            mConnection.setReadTimeout((int) SECONDS.toMillis(request.timeoutInSec()));
+            connection.setRequestMethod(request.requestMethod());
+            connection.setConnectTimeout((int) SECONDS.toMillis(request.timeoutInSec()));
+            connection.setReadTimeout((int) SECONDS.toMillis(request.timeoutInSec()));
             if (POST.equals(request.requestMethod())) {
-                mConnection.setDoOutput(true);
+                connection.setDoOutput(true);
             }
+            return connection;
         } catch (IOException ioe) {
             throw new ServiceEntitlementException(
                     ERROR_SERVER_NOT_CONNECTABLE, "Configure connection failed!", ioe);
         }
     }
 
-    private void closeConnection() {
-        if (mConnection != null) {
-            mConnection.disconnect();
-            mConnection = null;
-        }
-    }
-
     private static HttpResponse getHttpResponse(HttpURLConnection connection)
             throws ServiceEntitlementException {
         HttpResponse.Builder responseBuilder = HttpResponse.builder();
@@ -165,7 +160,9 @@ public class HttpClient {
             logPii("HttpClient.response headers: " + connection.getHeaderFields());
             if (responseCode != HttpURLConnection.HTTP_OK
                     && responseCode != HttpURLConnection.HTTP_MOVED_TEMP) {
-                throw new ServiceEntitlementException(ERROR_HTTP_STATUS_NOT_SUCCESS, responseCode,
+                throw new ServiceEntitlementException(
+                        ERROR_HTTP_STATUS_NOT_SUCCESS,
+                        responseCode,
                         connection.getHeaderField(HttpHeaders.RETRY_AFTER),
                         "Invalid connection response: " + responseCode);
             }
diff --git a/java/com/android/libraries/entitlement/odsa/AcquireConfigurationOperation.java b/java/com/android/libraries/entitlement/odsa/AcquireConfigurationOperation.java
index e1675fa..36bf029 100644
--- a/java/com/android/libraries/entitlement/odsa/AcquireConfigurationOperation.java
+++ b/java/com/android/libraries/entitlement/odsa/AcquireConfigurationOperation.java
@@ -22,6 +22,7 @@ import androidx.annotation.Nullable;
 
 import com.android.libraries.entitlement.EsimOdsaOperation;
 import com.android.libraries.entitlement.EsimOdsaOperation.CompanionService;
+import com.android.libraries.entitlement.EsimOdsaOperation.EntitlementProtocol;
 import com.android.libraries.entitlement.EsimOdsaOperation.OdsaServiceStatus;
 import com.android.libraries.entitlement.utils.Ts43Constants;
 import com.android.libraries.entitlement.utils.Ts43Constants.AppId;
@@ -110,6 +111,16 @@ public final class AcquireConfigurationOperation {
         @NonNull
         public abstract String targetTerminalEid();
 
+        /**
+         * Returns whether the subscription transfer is for cross-TS.43 platform. Used by HTTP
+         * parameter {@code old_terminal_entitlement_protocol}.
+         *
+         * <p>This is an optional param for cross-platform.
+         */
+        @NonNull
+        @EntitlementProtocol
+        public abstract String oldTerminalEntitlementProtocol();
+
         /**
          * Returns the notification token used to register for entitlement configuration request
          * from network. Used by HTTP parameter {@code notif_token}.
@@ -137,6 +148,8 @@ public final class AcquireConfigurationOperation {
                     .setTargetTerminalId("")
                     .setTargetTerminalIccid("")
                     .setTargetTerminalEid("")
+                    .setOldTerminalEntitlementProtocol(
+                            EsimOdsaOperation.ENTITLEMENT_PROTOCOL_UNKNOWN)
                     .setNotificationToken("")
                     .setNotificationAction(Ts43Constants.NOTIFICATION_ACTION_ENABLE_FCM);
         }
@@ -258,6 +271,19 @@ public final class AcquireConfigurationOperation {
             @NonNull
             public abstract Builder setTargetTerminalEid(@NonNull String targetTerminalEid);
 
+            /**
+             * Sets the entitlement protocol of the old device. Used by HTTP parameter
+             * {@code old_terminal_entitlement_protocol}.
+             *
+             * <p>This is an optional param for cross-platform.
+             *
+             * @param oldTerminalEntitlementProtocol The entitlement protocol of the old device.
+             * @return The builder.
+             */
+            @NonNull
+            public abstract Builder setOldTerminalEntitlementProtocol(
+                    @NonNull @EntitlementProtocol String oldTerminalEntitlementProtocol);
+
             /**
              * Sets the notification token used to register for entitlement configuration request
              * from network. Used by HTTP parameter {@code notif_token} if set.
diff --git a/java/com/android/libraries/entitlement/odsa/AcquireTemporaryTokenOperation.java b/java/com/android/libraries/entitlement/odsa/AcquireTemporaryTokenOperation.java
index 4f814b9..e0ea52c 100644
--- a/java/com/android/libraries/entitlement/odsa/AcquireTemporaryTokenOperation.java
+++ b/java/com/android/libraries/entitlement/odsa/AcquireTemporaryTokenOperation.java
@@ -19,6 +19,8 @@ package com.android.libraries.entitlement.odsa;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.libraries.entitlement.EsimOdsaOperation;
+import com.android.libraries.entitlement.EsimOdsaOperation.EntitlementProtocol;
 import com.android.libraries.entitlement.EsimOdsaOperation.OdsaOperation;
 import com.android.libraries.entitlement.utils.Ts43Constants;
 import com.android.libraries.entitlement.utils.Ts43Constants.AppId;
@@ -63,6 +65,16 @@ public final class AcquireTemporaryTokenOperation {
         @NonNull
         public abstract String companionTerminalId();
 
+        /**
+         * Returns whether the subscription transfer is for cross-TS.43 platform. Used by HTTP
+         * parameter {@code old_terminal_entitlement_protocol}.
+         *
+         * <p>This is an optional param for cross-platform.
+         */
+        @NonNull
+        @EntitlementProtocol
+        public abstract String targetTerminalEntitlementProtocol();
+
         /** Returns a new {@link Builder} object. */
         @NonNull
         public static Builder builder() {
@@ -70,7 +82,9 @@ public final class AcquireTemporaryTokenOperation {
                     .Builder()
                     .setAppId(Ts43Constants.APP_UNKNOWN)
                     .setOperationTargets(ImmutableList.of())
-                    .setCompanionTerminalId("");
+                    .setCompanionTerminalId("")
+                    .setTargetTerminalEntitlementProtocol(
+                            EsimOdsaOperation.ENTITLEMENT_PROTOCOL_UNKNOWN);
         }
 
         /** Builder. */
@@ -113,6 +127,19 @@ public final class AcquireTemporaryTokenOperation {
             @NonNull
             public abstract Builder setCompanionTerminalId(@NonNull String companionTerminalId);
 
+            /**
+             * Sets the entitlement protocol of primary device. Used by HTTP parameter
+             * {@code target_terminal_entitlement_protocol}.
+             *
+             * <p>This is an optional param for cross-platform.
+             *
+             * @param targetTerminalEntitlementProtocol The entitlement protocol of primary device.
+             * @return The builder.
+             */
+            @NonNull
+            public abstract Builder setTargetTerminalEntitlementProtocol(
+                    @NonNull @EntitlementProtocol String targetTerminalEntitlementProtocol);
+
             /** Returns the {@link AcquireTemporaryTokenRequest} object. */
             @NonNull
             public abstract AcquireTemporaryTokenRequest build();
@@ -149,7 +176,7 @@ public final class AcquireTemporaryTokenOperation {
             return new AutoValue_AcquireTemporaryTokenOperation_AcquireTemporaryTokenResponse
                     .Builder()
                     .setTemporaryToken("")
-                    .setTemporaryTokenExpiry(null)
+                    .setTemporaryTokenExpiry(Instant.EPOCH)
                     .setOperationTargets(ImmutableList.of());
         }
 
diff --git a/java/com/android/libraries/entitlement/odsa/CheckEligibilityOperation.java b/java/com/android/libraries/entitlement/odsa/CheckEligibilityOperation.java
index 8dc8d97..2589bbe 100644
--- a/java/com/android/libraries/entitlement/odsa/CheckEligibilityOperation.java
+++ b/java/com/android/libraries/entitlement/odsa/CheckEligibilityOperation.java
@@ -20,7 +20,9 @@ import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.libraries.entitlement.EsimOdsaOperation;
 import com.android.libraries.entitlement.EsimOdsaOperation.CompanionService;
+import com.android.libraries.entitlement.EsimOdsaOperation.EntitlementProtocol;
 import com.android.libraries.entitlement.utils.HttpConstants;
 import com.android.libraries.entitlement.utils.HttpConstants.ContentType;
 import com.android.libraries.entitlement.utils.Ts43Constants;
@@ -107,6 +109,16 @@ public final class CheckEligibilityOperation {
         @NonNull
         public abstract String companionTerminalFriendlyName();
 
+        /**
+         * Returns whether the subscription transfer is for cross-TS.43 platform. Used by HTTP
+         * parameter {@code old_terminal_entitlement_protocol}.
+         *
+         * <p>This is an optional param for cross-platform.
+         */
+        @NonNull
+        @EntitlementProtocol
+        public abstract String targetTerminalEntitlementProtocol();
+
         /**
          * Returns the notification token used to register for entitlement configuration request
          * from network. Used by HTTP parameter {@code notif_token}.
@@ -131,6 +143,8 @@ public final class CheckEligibilityOperation {
                     .setCompanionTerminalModel("")
                     .setCompanionTerminalSoftwareVersion("")
                     .setCompanionTerminalFriendlyName("")
+                    .setTargetTerminalEntitlementProtocol(
+                            EsimOdsaOperation.ENTITLEMENT_PROTOCOL_UNKNOWN)
                     .setNotificationToken("")
                     .setNotificationAction(Ts43Constants.NOTIFICATION_ACTION_ENABLE_FCM);
         }
@@ -215,6 +229,19 @@ public final class CheckEligibilityOperation {
             public abstract Builder setCompanionTerminalFriendlyName(
                     @NonNull String companionTerminalFriendlyName);
 
+            /**
+             * Sets the entitlement protocol of primary device. Used by HTTP parameter
+             * {@code target_terminal_entitlement_protocol}.
+             *
+             * <p>This is an optional param for cross-platform.
+             *
+             * @param targetTerminalEntitlementProtocol The entitlement protocol of primary device.
+             * @return The builder.
+             */
+            @NonNull
+            public abstract Builder setTargetTerminalEntitlementProtocol(
+                    @NonNull @EntitlementProtocol String targetTerminalEntitlementProtocol);
+
             /**
              * Sets the notification token used to register for entitlement configuration request
              * from network. Used by HTTP parameter {@code notif_token} if set.
diff --git a/java/com/android/libraries/entitlement/odsa/ManageSubscriptionOperation.java b/java/com/android/libraries/entitlement/odsa/ManageSubscriptionOperation.java
index 49a7f36..2398b41 100644
--- a/java/com/android/libraries/entitlement/odsa/ManageSubscriptionOperation.java
+++ b/java/com/android/libraries/entitlement/odsa/ManageSubscriptionOperation.java
@@ -22,6 +22,7 @@ import androidx.annotation.Nullable;
 
 import com.android.libraries.entitlement.EsimOdsaOperation;
 import com.android.libraries.entitlement.EsimOdsaOperation.CompanionService;
+import com.android.libraries.entitlement.EsimOdsaOperation.EntitlementProtocol;
 import com.android.libraries.entitlement.EsimOdsaOperation.MessageButton;
 import com.android.libraries.entitlement.EsimOdsaOperation.OdsaOperationType;
 import com.android.libraries.entitlement.utils.HttpConstants;
@@ -195,6 +196,16 @@ public final class ManageSubscriptionOperation {
         @NonNull
         public abstract String oldTerminalIccid();
 
+        /**
+         * Returns whether the subscription transfer is for cross-TS.43 platform. Used by HTTP
+         * parameter {@code old_terminal_entitlement_protocol}.
+         *
+         * <p>This is an optional param for cross-platform.
+         */
+        @NonNull
+        @EntitlementProtocol
+        public abstract String oldTerminalEntitlementProtocol();
+
         /**
          * Returns the identifier of the specific plan offered by an MNO. Used by HTTP parameter
          * {@code plan_id}.
@@ -255,6 +266,8 @@ public final class ManageSubscriptionOperation {
                     .setTargetTerminalModel("")
                     .setOldTerminalId("")
                     .setOldTerminalIccid("")
+                    .setOldTerminalEntitlementProtocol(
+                            EsimOdsaOperation.ENTITLEMENT_PROTOCOL_UNKNOWN)
                     .setPlanId("")
                     .setNotificationToken("")
                     .setNotificationAction(Ts43Constants.NOTIFICATION_ACTION_ENABLE_FCM)
@@ -521,6 +534,19 @@ public final class ManageSubscriptionOperation {
             @NonNull
             public abstract Builder setOldTerminalIccid(@NonNull String oldTerminalIccid);
 
+            /**
+             * Sets the entitlement protocol of the old device. Used by HTTP parameter
+             * {@code old_terminal_entitlement_protocol}.
+             *
+             * <p>This is an optional param for cross-platform.
+             *
+             * @param oldTerminalEntitlementProtocol The entitlement protocol of the old device.
+             * @return The builder.
+             */
+            @NonNull
+            public abstract Builder setOldTerminalEntitlementProtocol(
+                    @NonNull @EntitlementProtocol String oldTerminalEntitlementProtocol);
+
             /**
              * Sets the identifier of the specific plan offered by an MNO. Used by HTTP parameter
              * {@code plan_id} if set.
diff --git a/java/com/android/libraries/entitlement/utils/Ts43Constants.java b/java/com/android/libraries/entitlement/utils/Ts43Constants.java
index e9a778a..b184b4b 100644
--- a/java/com/android/libraries/entitlement/utils/Ts43Constants.java
+++ b/java/com/android/libraries/entitlement/utils/Ts43Constants.java
@@ -61,7 +61,13 @@ public final class Ts43Constants {
     /** App ID for satellite entitlement. */
     public static final String APP_SATELLITE_ENTITLEMENT = "ap2016";
 
-    /** App ID for ODSA for Cross-TS.43 platform device, Entitlement and Activation */
+    /**
+     * App ID for ODSA for Cross-TS.43 platform device, Entitlement and Activation
+     *
+     * @deprecated use {@code target_terminal_entitlement_protocol} and
+     * {@code old_terminal_entitlement_protocol} in the request instead.
+     */
+    @Deprecated
     public static final String APP_ODSA_CROSS_TS43 = "ap2017";
 
     @Retention(RetentionPolicy.SOURCE)
@@ -168,4 +174,4 @@ public final class Ts43Constants {
 
     private Ts43Constants() {
     }
-}
\ No newline at end of file
+}
diff --git a/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java b/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java
index dbf0616..ed5edca 100644
--- a/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java
+++ b/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java
@@ -204,10 +204,17 @@ public class ServiceEntitlementTest {
 
     @Test
     public void queryEntitlementStatusFromOidc_returnResult() throws Exception {
+        ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
+        when(mMockEapAkaApi.acquireOidcAuthenticationEndpoint(
+                        eq(ServiceEntitlement.APP_ODSA_PRIMARY),
+                        eq(mCarrierConfig),
+                        eq(request),
+                        any()))
+                .thenReturn(QUERY_OIDC_RESULT);
         when(mMockEapAkaApi.queryEntitlementStatusFromOidc(
                         eq(ServiceEntitlement.APP_ODSA_PRIMARY),
                         eq(mCarrierConfig),
-                        eq(null),
+                        eq(request),
                         any()))
                 .thenAnswer(
                         invocation -> {
@@ -216,6 +223,9 @@ public class ServiceEntitlementTest {
                             return mMockHttpResponse;
                         });
 
+        mServiceEntitlement.acquireOidcAuthenticationEndpoint(
+                                ServiceEntitlement.APP_ODSA_PRIMARY, request);
+
         assertThat(
                         mServiceEntitlement.queryEntitlementStatusFromOidc(
                                 ServiceEntitlement.APP_ODSA_PRIMARY))
diff --git a/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java b/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java
index 87f0851..54e5bb5 100644
--- a/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java
+++ b/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java
@@ -133,7 +133,8 @@ public class Ts43AuthenticationTest {
     public void testGetAuthToken_receivedValidToken() throws Exception {
         doReturn(HTTP_RESPONSE_WITH_TOKEN).when(mMockHttpResponse).body();
         Ts43AuthToken mToken = mTs43Authentication.getAuthToken(
-                0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION);
+                0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION,
+                ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
         assertThat(mToken.token()).isEqualTo(TOKEN);
         assertThat(mToken.validity()).isEqualTo(VALIDITY);
     }
@@ -150,15 +151,18 @@ public class Ts43AuthenticationTest {
     @Test
     public void testGetAuthToken_invalidAppId_throwException() {
         assertThrows(NullPointerException.class, () -> mTs43Authentication.getAuthToken(
-                0, null, APP_NAME, APP_VERSION));
+                0, null, APP_NAME, APP_VERSION,
+                ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML));
         assertThrows(IllegalArgumentException.class, () -> mTs43Authentication.getAuthToken(
-                0, "invalid_app_id", APP_NAME, APP_VERSION));
+                0, "invalid_app_id", APP_NAME, APP_VERSION,
+                ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML));
     }
 
     @Test
     public void testGetAuthToken_invalidSlotIndex_throwException() {
         assertThrows(IllegalArgumentException.class, () -> mTs43Authentication.getAuthToken(
-                5, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION));
+                5, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION,
+                ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML));
     }
 
     @Test
@@ -167,7 +171,8 @@ public class Ts43AuthenticationTest {
 
         try {
             mTs43Authentication.getAuthToken(
-                    0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION);
+                    0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION,
+                    ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
             fail("Expected to get exception.");
         } catch (ServiceEntitlementException e) {
             assertThat(e.getErrorCode()).isEqualTo(
@@ -179,7 +184,8 @@ public class Ts43AuthenticationTest {
     public void testGetAuthToken_validityNotAvailable() throws Exception {
         doReturn(HTTP_RESPONSE_WITHOUT_VALIDITY).when(mMockHttpResponse).body();
         Ts43AuthToken mToken = mTs43Authentication.getAuthToken(
-                0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION);
+                0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION,
+                ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
         assertThat(mToken.token()).isEqualTo(TOKEN);
         assertThat(mToken.validity()).isEqualTo(Ts43AuthToken.VALIDITY_NOT_AVAILABLE);
     }
@@ -195,7 +201,8 @@ public class Ts43AuthenticationTest {
                 .queryEntitlementStatus(any(), any(), any(), any());
         try {
             mTs43Authentication.getAuthToken(
-                    0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION);
+                    0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION,
+                    ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
             fail("Expected to get exception.");
         } catch (ServiceEntitlementException e) {
             assertThat(e.getErrorCode()).isEqualTo(
diff --git a/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java b/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
index 54e5ecb..57bc0aa 100644
--- a/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
+++ b/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
@@ -21,6 +21,7 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.verify;
 
 import android.content.Context;
 import android.telephony.TelephonyManager;
@@ -48,6 +49,7 @@ import com.google.common.collect.ImmutableList;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
@@ -85,6 +87,7 @@ public class Ts43OperationTest {
     private static final String MSISDN = "+16502530000";
 
     private static final String GENERAL_ERROR_TEXT = "error text";
+    private static final String APP_NAME = "Ts43OperationTest.class";
 
     private static final String MANAGE_SUBSCRIPTION_RESPONSE_CONTINUE_TO_WEBSHEET =
             "<?xml version=\"1.0\"?>"
@@ -319,7 +322,7 @@ public class Ts43OperationTest {
         doReturn(mTelephonyManager).when(mContext).getSystemService(Context.TELEPHONY_SERVICE);
 
         mTs43Operation = new Ts43Operation(mContext, 0, new URL(TEST_URL),
-                ENTITLEMENT_VERSION, TOKEN, Ts43Operation.TOKEN_TYPE_NORMAL);
+                ENTITLEMENT_VERSION, TOKEN, Ts43Operation.TOKEN_TYPE_NORMAL, APP_NAME);
 
         Field field = Ts43Operation.class.getDeclaredField("mServiceEntitlement");
         field.setAccessible(true);
@@ -335,6 +338,7 @@ public class Ts43OperationTest {
                 .setOperationType(EsimOdsaOperation.OPERATION_TYPE_SUBSCRIBE)
                 .setCompanionTerminalId(COMPANION_TERMINAL_ID)
                 .setCompanionTerminalEid(COMPANION_TERMINAL_EID)
+                .setOldTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .build();
 
         ManageSubscriptionResponse response = mTs43Operation.manageSubscription(request);
@@ -345,6 +349,12 @@ public class Ts43OperationTest {
         assertThat(response.subscriptionServiceUrl()).isEqualTo(new URL(SUBSCRIPTION_SERVICE_URL));
         assertThat(response.subscriptionServiceUserData())
                 .isEqualTo(SUBSCRIPTION_SERVICE_USER_DATA);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -356,6 +366,7 @@ public class Ts43OperationTest {
                 .setOperationType(EsimOdsaOperation.OPERATION_TYPE_SUBSCRIBE)
                 .setCompanionTerminalId(COMPANION_TERMINAL_ID)
                 .setCompanionTerminalEid(COMPANION_TERMINAL_EID)
+                .setOldTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .build();
 
         ManageSubscriptionResponse response = mTs43Operation.manageSubscription(request);
@@ -366,6 +377,12 @@ public class Ts43OperationTest {
         assertThat(response.downloadInfo().profileIccid()).isEqualTo(ICCID);
         assertThat(response.downloadInfo().profileSmdpAddresses())
                 .isEqualTo(ImmutableList.of(PROFILE_SMDP_ADDRESS));
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -377,6 +394,7 @@ public class Ts43OperationTest {
                 .setOperationType(EsimOdsaOperation.OPERATION_TYPE_SUBSCRIBE)
                 .setCompanionTerminalId(COMPANION_TERMINAL_ID)
                 .setCompanionTerminalEid(COMPANION_TERMINAL_EID)
+                .setOldTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .setMessageResponse(MESSAGE_RESPONSE)
                 .setMessageButton(MESSAGE_ACCEPT_PRESENT)
                 .build();
@@ -387,6 +405,12 @@ public class Ts43OperationTest {
         assertThat(response.subscriptionResult()).isEqualTo(
                 ManageSubscriptionResponse.SUBSCRIPTION_RESULT_REQUIRES_USER_INPUT);
         assertThat(response.generalErrorText()).isEqualTo(GENERAL_ERROR_TEXT);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -395,6 +419,7 @@ public class Ts43OperationTest {
 
         AcquireTemporaryTokenRequest request = AcquireTemporaryTokenRequest.builder()
                 .setAppId(Ts43Constants.APP_ODSA_PRIMARY)
+                .setTargetTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .setOperationTargets(ImmutableList.of(
                         EsimOdsaOperation.OPERATION_MANAGE_SUBSCRIPTION,
                         EsimOdsaOperation.OPERATION_ACQUIRE_CONFIGURATION))
@@ -407,6 +432,12 @@ public class Ts43OperationTest {
         assertThat(response.operationTargets()).isEqualTo(ImmutableList.of(
                 EsimOdsaOperation.OPERATION_MANAGE_SUBSCRIPTION,
                 EsimOdsaOperation.OPERATION_ACQUIRE_CONFIGURATION));
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -414,6 +445,7 @@ public class Ts43OperationTest {
         doReturn(ACQUIRE_CONFIGURATION_RESPONSE).when(mMockHttpResponse).body();
         AcquireConfigurationRequest request = AcquireConfigurationRequest.builder()
                 .setAppId(Ts43Constants.APP_ODSA_PRIMARY)
+                .setOldTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .build();
 
         AcquireConfigurationResponse response = mTs43Operation.acquireConfiguration(request);
@@ -426,6 +458,12 @@ public class Ts43OperationTest {
         assertThat(config.downloadInfo().profileSmdpAddresses()).isEqualTo(
                 ImmutableList.of(PROFILE_SMDP_ADDRESS));
         assertThat(config.serviceStatus()).isEqualTo(EsimOdsaOperation.SERVICE_STATUS_ACTIVATED);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -433,6 +471,7 @@ public class Ts43OperationTest {
         doReturn(ACQUIRE_CONFIGURATION_RESPONSE_MSG).when(mMockHttpResponse).body();
         AcquireConfigurationRequest request = AcquireConfigurationRequest.builder()
                 .setAppId(Ts43Constants.APP_ODSA_PRIMARY)
+                .setOldTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .build();
 
         AcquireConfigurationResponse response = mTs43Operation.acquireConfiguration(request);
@@ -448,6 +487,12 @@ public class Ts43OperationTest {
         assertThat(config.messageInfo().rejectButtonLabel()).isEqualTo(REJECT_BUTTON_LABEL);
         assertThat(config.messageInfo().acceptFreetext()).isEqualTo(MESSAGE_ACCEPT_PRESENT);
         assertThat(config.serviceStatus()).isEqualTo(EsimOdsaOperation.SERVICE_STATUS_ACTIVATED);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -455,6 +500,7 @@ public class Ts43OperationTest {
         doReturn(CHECK_ELIGIBILITY_RESPONSE).when(mMockHttpResponse).body();
         CheckEligibilityRequest request = CheckEligibilityRequest.builder()
                 .setAppId(Ts43Constants.APP_ODSA_PRIMARY)
+                .setTargetTerminalEntitlementProtocol(EsimOdsaOperation.ENTITLEMENT_PROTOCOL_TS43)
                 .build();
 
         CheckEligibilityResponse response = mTs43Operation.checkEligibility(request);
@@ -466,6 +512,12 @@ public class Ts43OperationTest {
                 EsimOdsaOperation.COMPANION_SERVICE_SHARED_NUMBER);
         assertThat(response.notEnabledUrl()).isEqualTo(new URL(NOT_ENABLED_URL));
         assertThat(response.notEnabledUserData()).isEqualTo(NOT_ENABLED_USER_DATA);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -480,6 +532,12 @@ public class Ts43OperationTest {
                 EsimOdsaOperation.OPERATION_RESULT_SUCCESS);
         assertThat(response.serviceStatus()).isEqualTo(
                 EsimOdsaOperation.SERVICE_STATUS_DEACTIVATED);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 
     @Test
@@ -494,5 +552,11 @@ public class Ts43OperationTest {
         assertThat(response.operationResult()).isEqualTo(
                 EsimOdsaOperation.OPERATION_RESULT_SUCCESS);
         assertThat(response.msisdn()).isEqualTo(MSISDN);
+
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
+                any());
+        assertThat(captor.getValue().appName()).contains(APP_NAME);
     }
 }
diff --git a/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java b/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java
index ca10d9f..bedd52a 100644
--- a/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java
+++ b/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java
@@ -114,6 +114,8 @@ public class EapAkaApiTest {
     private static final String LONG_MODEL_TRIMMED = "aaaaaaaaaa";
     private static final String LONG_SW_VERSION_TRIMMED = "aaaaaaaaaaaaaaaaaaaa";
     private static final String APP_VERSION = "APP_VERSION";
+    private static final String GID1 = "GID1";
+
 
     @Rule public final MockitoRule rule = MockitoJUnit.rule();
 
@@ -141,6 +143,7 @@ public class EapAkaApiTest {
                 .thenReturn(mMockTelephonyManagerForSubId);
         when(mMockTelephonyManagerForSubId.getSubscriberId()).thenReturn(IMSI);
         when(mMockTelephonyManagerForSubId.getSimOperator()).thenReturn(MCCMNC);
+        when(mMockTelephonyManagerForSubId.getGroupIdLevel1()).thenReturn(GID1);
         mEapAkaApi = new EapAkaApi(mContext, SUB_ID, mMockHttpClient, "");
         mEapAkaApiBypassAuthentication =
                 new EapAkaApi(mContext, SUB_ID, mMockHttpClient, BYPASS_EAP_AKA_RESPONSE);
@@ -1147,6 +1150,82 @@ public class EapAkaApiTest {
                 .isEqualTo(userAgent);
     }
 
+    @Test
+    public void queryEntitlementStatus_gid1Set_sendsGid1() throws Exception {
+        CarrierConfig carrierConfig = CarrierConfig.builder().setServerUrl(TEST_URL).build();
+        ServiceEntitlementRequest request =
+                ServiceEntitlementRequest.builder()
+                        .setAuthenticationToken(TOKEN)
+                        .setTerminalVendor(LONG_VENDOR)
+                        .setTerminalModel(LONG_MODEL)
+                        .setTerminalSoftwareVersion(LONG_SW_VERSION)
+                        .setEntitlementVersion("12.0")
+                        .setGid1(GID1)
+                        .build();
+
+        mEapAkaApi.queryEntitlementStatus(
+                ImmutableList.of(ServiceEntitlement.APP_PHONE_NUMBER_INFORMATION),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
+
+        verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
+        verify(mMockTelephonyManagerForSubId, times(0)).getGroupIdLevel1();
+        String urlParams = String.format("gid1=%s", GID1);
+        assertThat(mHttpRequestCaptor.getValue().url()).contains(urlParams);
+    }
+
+    @Test
+    public void queryEntitlementStatus_gid1NotSpecified_ts43Version12_getsGid1FromTelephonyManager()
+            throws Exception {
+        CarrierConfig carrierConfig = CarrierConfig.builder().setServerUrl(TEST_URL).build();
+        ServiceEntitlementRequest request =
+                ServiceEntitlementRequest.builder()
+                        .setAuthenticationToken(TOKEN)
+                        .setTerminalVendor(LONG_VENDOR)
+                        .setTerminalModel(LONG_MODEL)
+                        .setTerminalSoftwareVersion(LONG_SW_VERSION)
+                        .setEntitlementVersion("12.0")
+                        .setGid1("")
+                        .build();
+
+        mEapAkaApi.queryEntitlementStatus(
+                ImmutableList.of(ServiceEntitlement.APP_PHONE_NUMBER_INFORMATION),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
+
+        verify(mMockTelephonyManagerForSubId).getGroupIdLevel1();
+        verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
+        String urlParams = String.format("gid1=%s", GID1);
+        assertThat(mHttpRequestCaptor.getValue().url()).contains(urlParams);
+    }
+
+    @Test
+    public void queryEntitlementStatus_gid1NotSpecified_ts43VersionLessThan12_noGid1Sent()
+            throws Exception {
+        CarrierConfig carrierConfig = CarrierConfig.builder().setServerUrl(TEST_URL).build();
+        ServiceEntitlementRequest request =
+                ServiceEntitlementRequest.builder()
+                        .setAuthenticationToken(TOKEN)
+                        .setTerminalVendor(LONG_VENDOR)
+                        .setTerminalModel(LONG_MODEL)
+                        .setTerminalSoftwareVersion(LONG_SW_VERSION)
+                        .setEntitlementVersion("11.0")
+                        .setGid1("")
+                        .build();
+
+        mEapAkaApi.queryEntitlementStatus(
+                ImmutableList.of(ServiceEntitlement.APP_PHONE_NUMBER_INFORMATION),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
+
+        verify(mMockTelephonyManagerForSubId, times(0)).getGroupIdLevel1();
+        verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
+        assertThat(mHttpRequestCaptor.getValue().url()).doesNotContain("gid1");
+    }
+
     @Test
     public void performEsimOdsaOperation_noAuthenticationToken_returnsResult() throws Exception {
         when(mMockTelephonyManagerForSubId.getIccAuthentication(
```

