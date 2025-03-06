```diff
diff --git a/java/com/android/libraries/entitlement/CarrierConfig.java b/java/com/android/libraries/entitlement/CarrierConfig.java
index d0a63f8..15c35b8 100644
--- a/java/com/android/libraries/entitlement/CarrierConfig.java
+++ b/java/com/android/libraries/entitlement/CarrierConfig.java
@@ -20,6 +20,7 @@ import android.net.Network;
 
 import androidx.annotation.Nullable;
 
+import com.android.libraries.entitlement.utils.UrlConnectionFactory;
 import com.google.auto.value.AutoValue;
 
 /**
@@ -32,10 +33,10 @@ public abstract class CarrierConfig {
     /** Default value of {@link #timeoutInSec} if not set. */
     public static final int DEFAULT_TIMEOUT_IN_SEC = 30;
 
-    public static final String CLIENT_TS_43_IMS_ENTITLEMENT = "IMS-Entitlement";
-    public static final String CLIENT_TS_43_COMPANION_ODSA = "Companion-ODSA";
-    public static final String CLIENT_TS_43_PRIMARY_ODSA = "Primary-ODSA";
-    public static final String CLIENT_TS_43_SERVER_ODSA = "Server-ODSA";
+    public static final String CLIENT_TS_43_IMS_ENTITLEMENT = "client-IMS-Entitlement";
+    public static final String CLIENT_TS_43_COMPANION_ODSA = "client-Companion-ODSA";
+    public static final String CLIENT_TS_43_PRIMARY_ODSA = "client-Primary-ODSA";
+    public static final String CLIENT_TS_43_SERVER_ODSA = "client-Server-ODSA";
 
     /** The carrier's entitlement server URL. See {@link Builder#setServerUrl}. */
     public abstract String serverUrl();
@@ -56,13 +57,21 @@ public abstract class CarrierConfig {
     @Nullable
     public abstract Network network();
 
+    /** The factory to create connections. See {@link Builder#setUrlConnectionFactory}. */
+    @Nullable
+    public abstract UrlConnectionFactory urlConnectionFactory();
+
+    /** The EAP-AKA realm. See {@link Builder#setEapAkaRealm}. */
+    public abstract String eapAkaRealm();
+
     /** Returns a new {@link Builder} object. */
     public static Builder builder() {
         return new AutoValue_CarrierConfig.Builder()
                 .setServerUrl("")
                 .setClientTs43("")
                 .setUseHttpPost(false)
-                .setTimeoutInSec(DEFAULT_TIMEOUT_IN_SEC);
+                .setTimeoutInSec(DEFAULT_TIMEOUT_IN_SEC)
+                .setEapAkaRealm("nai.epc");
     }
 
     /** Builder. */
@@ -96,5 +105,17 @@ public abstract class CarrierConfig {
          * is used.
          */
         public abstract Builder setNetwork(Network network);
+
+        /**
+         * If unset, the default Android API {@link java.net.URL#openConnection}
+         * would be used. This allows callers of the lib to choose the HTTP stack.
+         */
+        public abstract Builder setUrlConnectionFactory(UrlConnectionFactory urlConnectionFactory);
+
+        /**
+         * Sets the realm for EAP-AKA. If unset, uses the standard "nai.epc" defined in 3GPP TS
+         * 23.003 clause 19.3.2.
+         */
+        public abstract Builder setEapAkaRealm(String eapAkaRealm);
     }
 }
diff --git a/java/com/android/libraries/entitlement/EapAkaHelper.java b/java/com/android/libraries/entitlement/EapAkaHelper.java
index f29cb0f..0a52a17 100644
--- a/java/com/android/libraries/entitlement/EapAkaHelper.java
+++ b/java/com/android/libraries/entitlement/EapAkaHelper.java
@@ -68,7 +68,7 @@ public class EapAkaHelper {
                 mContext.getSystemService(TelephonyManager.class)
                         .createForSubscriptionId(mSimSubscriptionId);
         return EapAkaApi.getImsiEap(
-                telephonyManager.getSimOperator(), telephonyManager.getSubscriberId());
+                telephonyManager.getSimOperator(), telephonyManager.getSubscriberId(), "nai.epc");
     }
 
     /**
@@ -102,7 +102,8 @@ public class EapAkaHelper {
         try {
             EapAkaChallenge eapAkaChallenge = EapAkaChallenge.parseEapAkaChallenge(challenge);
             com.android.libraries.entitlement.eapaka.EapAkaResponse eapAkaResponse =
-                    respondToEapAkaChallenge(mContext, mSimSubscriptionId, eapAkaChallenge);
+                    respondToEapAkaChallenge(
+                            mContext, mSimSubscriptionId, eapAkaChallenge, "nai.epc");
             return new EapAkaResponse(
                     eapAkaResponse.response(), eapAkaResponse.synchronizationFailureResponse());
         } catch (ServiceEntitlementException e) {
diff --git a/java/com/android/libraries/entitlement/ServiceEntitlement.java b/java/com/android/libraries/entitlement/ServiceEntitlement.java
index af30de6..bf1b4dd 100644
--- a/java/com/android/libraries/entitlement/ServiceEntitlement.java
+++ b/java/com/android/libraries/entitlement/ServiceEntitlement.java
@@ -27,6 +27,7 @@ import com.android.libraries.entitlement.utils.DebugUtils;
 import com.android.libraries.entitlement.utils.Ts43Constants;
 
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
 
 import java.util.List;
 
@@ -88,6 +89,11 @@ public class ServiceEntitlement {
      */
     public static final String APP_SATELLITE_ENTITLEMENT = Ts43Constants.APP_SATELLITE_ENTITLEMENT;
 
+    /**
+     * App ID for ODSA for Cross-TS.43 platform device, Entitlement and Activation.
+     */
+    public static final String APP_ODSA_CROSS_TS43 = Ts43Constants.APP_ODSA_CROSS_TS43;
+
     private final CarrierConfig carrierConfig;
     private final EapAkaApi eapAkaApi;
     private ServiceEntitlementRequest mOidcRequest;
@@ -218,12 +224,31 @@ public class ServiceEntitlement {
      * parameter {@code appIds}.
      */
     @NonNull
-    public String queryEntitlementStatus(ImmutableList<String> appIds,
-            ServiceEntitlementRequest request)
+    public String queryEntitlementStatus(
+            ImmutableList<String> appIds, ServiceEntitlementRequest request)
             throws ServiceEntitlementException {
         return getEntitlementStatusResponse(appIds, request).body();
     }
 
+    /**
+     * Retrieves service entitlement configurations for multiple app IDs in one HTTP
+     * request/response. For on device service activation (ODSA) of eSIM for companion/primary
+     * devices, use {@link #performEsimOdsa} instead.
+     *
+     * <p>Same as {@link #queryEntitlementStatus(String, ServiceEntitlementRequest)} except that
+     * multiple "app" parameters will be set in the HTTP request, in the order as they appear in
+     * parameter {@code appIds}. Additional parameters from {@code additionalHeaders} are set to the
+     * HTTP request.
+     */
+    @NonNull
+    public String queryEntitlementStatus(
+            ImmutableList<String> appIds,
+            ServiceEntitlementRequest request,
+            ImmutableMap<String, String> additionalHeaders)
+            throws ServiceEntitlementException {
+        return getEntitlementStatusResponse(appIds, request, additionalHeaders).body();
+    }
+
     /**
      * Retrieves service entitlement configurations for multiple app IDs in one HTTP
      * request/response. For on device service activation (ODSA) of eSIM for companion/primary
@@ -236,7 +261,21 @@ public class ServiceEntitlement {
     public HttpResponse getEntitlementStatusResponse(ImmutableList<String> appIds,
             ServiceEntitlementRequest request)
             throws ServiceEntitlementException {
-        return eapAkaApi.queryEntitlementStatus(appIds, carrierConfig, request);
+        return getEntitlementStatusResponse(appIds, request, ImmutableMap.of());
+    }
+
+    /**
+     * Retrieves service entitlement configurations for multiple app IDs in one HTTP
+     * request/response. For on device service activation (ODSA) of eSIM for companion/primary
+     * devices, use {@link #performEsimOdsa} instead.
+     */
+    @NonNull
+    public HttpResponse getEntitlementStatusResponse(
+            ImmutableList<String> appIds,
+            ServiceEntitlementRequest request,
+            ImmutableMap<String, String> additionalHeaders)
+            throws ServiceEntitlementException {
+        return eapAkaApi.queryEntitlementStatus(appIds, carrierConfig, request, additionalHeaders);
     }
 
     /**
@@ -244,16 +283,37 @@ public class ServiceEntitlement {
      *
      * <p>Supported {@code appId}: {@link #APP_ODSA_COMPANION}, {@link #APP_ODSA_PRIMARY}.
      *
-     * <p>Similar to {@link #queryEntitlementStatus(String, ServiceEntitlementRequest)}, this
-     * method sends an HTTP GET request to entitlement server, responds to EAP-AKA challenge if
-     * needed, and returns the raw configuration doc as a string. Additional parameters from {@code
-     * operation} are set to the HTTP request. See {@link EsimOdsaOperation} for details.
+     * <p>Similar to {@link #queryEntitlementStatus(String, ServiceEntitlementRequest)}, this method
+     * sends an HTTP GET request to entitlement server, responds to EAP-AKA challenge if needed, and
+     * returns the raw configuration doc as a string. Additional parameters from {@code operation}
+     * are set to the HTTP request. See {@link EsimOdsaOperation} for details.
      */
     @NonNull
     public String performEsimOdsa(
             String appId, ServiceEntitlementRequest request, EsimOdsaOperation operation)
             throws ServiceEntitlementException {
-        return getEsimOdsaResponse(appId, request, operation).body();
+        return performEsimOdsa(appId, request, operation, ImmutableMap.of());
+    }
+
+    /**
+     * Performs on device service activation (ODSA) of eSIM for companion/primary devices.
+     *
+     * <p>Supported {@code appId}: {@link #APP_ODSA_COMPANION}, {@link #APP_ODSA_PRIMARY}.
+     *
+     * <p>Similar to {@link #queryEntitlementStatus(String, ServiceEntitlementRequest)}, this method
+     * sends an HTTP GET request to entitlement server, responds to EAP-AKA challenge if needed, and
+     * returns the raw configuration doc as a string. Additional parameters from {@code operation}
+     * are set to the HTTP request. See {@link EsimOdsaOperation} for details. Additional parameters
+     * from {@code additionalHeaders} are set to the HTTP request.
+     */
+    @NonNull
+    public String performEsimOdsa(
+            String appId,
+            ServiceEntitlementRequest request,
+            EsimOdsaOperation operation,
+            ImmutableMap<String, String> additionalHeaders)
+            throws ServiceEntitlementException {
+        return getEsimOdsaResponse(appId, request, operation, additionalHeaders).body();
     }
 
     /**
@@ -267,7 +327,26 @@ public class ServiceEntitlement {
     public HttpResponse getEsimOdsaResponse(
             String appId, ServiceEntitlementRequest request, EsimOdsaOperation operation)
             throws ServiceEntitlementException {
-        return eapAkaApi.performEsimOdsaOperation(appId, carrierConfig, request, operation);
+        return getEsimOdsaResponse(appId, request, operation, ImmutableMap.of());
+    }
+
+    /**
+     * Retrieves the HTTP response after performing on device service activation (ODSA) of eSIM for
+     * companion/primary devices.
+     *
+     * <p>Same as {@link #performEsimOdsa(String, ServiceEntitlementRequest, EsimOdsaOperation)}
+     * except that it returns the full HTTP response instead of just the body. Additional parameters
+     * from {@code additionalHeaders} are set to the HTTP request.
+     */
+    @NonNull
+    public HttpResponse getEsimOdsaResponse(
+            String appId,
+            ServiceEntitlementRequest request,
+            EsimOdsaOperation operation,
+            ImmutableMap<String, String> additionalHeaders)
+            throws ServiceEntitlementException {
+        return eapAkaApi.performEsimOdsaOperation(
+                appId, carrierConfig, request, operation, additionalHeaders);
     }
 
     /**
@@ -284,8 +363,30 @@ public class ServiceEntitlement {
     @NonNull
     public String acquireOidcAuthenticationEndpoint(String appId, ServiceEntitlementRequest request)
             throws ServiceEntitlementException {
+        return acquireOidcAuthenticationEndpoint(appId, request, ImmutableMap.of());
+    }
+
+    /**
+     * Retrieves the endpoint for OpenID Connect(OIDC) authentication.
+     *
+     * <p>Implementation based on section 2.8.2 of TS.43
+     *
+     * <p>The user should call {@link #queryEntitlementStatusFromOidc(String url)} with the
+     * authentication result to retrieve the service entitlement configuration.
+     *
+     * @param appId an app ID string defined in TS.43 section 2.2
+     * @param request contains parameters that can be used in the HTTP request
+     * @param additionalHeaders additional headers to be set in the HTTP request
+     */
+    @NonNull
+    public String acquireOidcAuthenticationEndpoint(
+            String appId,
+            ServiceEntitlementRequest request,
+            ImmutableMap<String, String> additionalHeaders)
+            throws ServiceEntitlementException {
         mOidcRequest = request;
-        return eapAkaApi.acquireOidcAuthenticationEndpoint(appId, carrierConfig, request);
+        return eapAkaApi.acquireOidcAuthenticationEndpoint(
+                appId, carrierConfig, request, additionalHeaders);
     }
 
     /**
@@ -314,7 +415,25 @@ public class ServiceEntitlement {
     @NonNull
     public HttpResponse getEntitlementStatusResponseFromOidc(String url)
             throws ServiceEntitlementException {
-        return eapAkaApi.queryEntitlementStatusFromOidc(url, carrierConfig, mOidcRequest);
+        return getEntitlementStatusResponseFromOidc(url, ImmutableMap.of());
+    }
+
+    /**
+     * Retrieves the HTTP response containing the service entitlement configuration from OIDC
+     * authentication result.
+     *
+     * <p>Same as {@link #queryEntitlementStatusFromOidc(String)} except that it returns the full
+     * HTTP response instead of just the body.
+     *
+     * @param url the redirect url from OIDC authentication result.
+     * @param additionalHeaders additional headers to be set in the HTTP request
+     */
+    @NonNull
+    public HttpResponse getEntitlementStatusResponseFromOidc(
+            String url, ImmutableMap<String, String> additionalHeaders)
+            throws ServiceEntitlementException {
+        return eapAkaApi.queryEntitlementStatusFromOidc(
+                url, carrierConfig, mOidcRequest, additionalHeaders);
     }
 
     /**
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java b/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
index c26f74b..f155f4f 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
@@ -44,6 +44,7 @@ import com.android.libraries.entitlement.http.HttpRequest;
 import com.android.libraries.entitlement.http.HttpResponse;
 
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
 import com.google.common.net.HttpHeaders;
 
 import org.json.JSONException;
@@ -159,20 +160,31 @@ public class EapAkaApi {
     public HttpResponse queryEntitlementStatus(
             ImmutableList<String> appIds,
             CarrierConfig carrierConfig,
-            ServiceEntitlementRequest request)
+            ServiceEntitlementRequest request,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         Uri.Builder urlBuilder = null;
         JSONObject postData = null;
         if (carrierConfig.useHttpPost()) {
             postData = new JSONObject();
-            appendParametersForAuthentication(postData, request);
-            appendParametersForServiceEntitlementRequest(postData, appIds, request);
+            appendParametersForAuthentication(postData, request, carrierConfig);
+            appendParametersForServiceEntitlementRequest(
+                postData, appIds, request);
         } else {
             urlBuilder = Uri.parse(carrierConfig.serverUrl()).buildUpon();
-            appendParametersForAuthentication(urlBuilder, request);
-            appendParametersForServiceEntitlementRequest(urlBuilder, appIds, request);
+            appendParametersForAuthentication(
+                urlBuilder, request, carrierConfig);
+            appendParametersForServiceEntitlementRequest(
+                urlBuilder, appIds, request);
         }
 
+        String userAgent =
+                getUserAgent(
+                        carrierConfig.clientTs43(),
+                        request.terminalVendor(),
+                        request.terminalModel(),
+                        request.terminalSoftwareVersion());
+
         if (!TextUtils.isEmpty(request.authenticationToken())) {
             // Fast Re-Authentication flow with pre-existing auth token
             Log.d(TAG, "Fast Re-Authentication");
@@ -181,16 +193,14 @@ public class EapAkaApi {
                             postData,
                             carrierConfig,
                             request.acceptContentType(),
-                            request.terminalVendor(),
-                            request.terminalModel(),
-                            request.terminalSoftwareVersion())
+                            userAgent,
+                            additionalHeaders)
                     : httpGet(
                             urlBuilder.toString(),
                             carrierConfig,
                             request.acceptContentType(),
-                            request.terminalVendor(),
-                            request.terminalModel(),
-                            request.terminalSoftwareVersion());
+                            userAgent,
+                            additionalHeaders);
         } else {
             // Full Authentication flow
             Log.d(TAG, "Full Authentication");
@@ -200,16 +210,14 @@ public class EapAkaApi {
                                     postData,
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
-                                    request.terminalVendor(),
-                                    request.terminalModel(),
-                                    request.terminalSoftwareVersion())
+                                    userAgent,
+                                    additionalHeaders)
                             : httpGet(
                                     urlBuilder.toString(),
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
-                                    request.terminalVendor(),
-                                    request.terminalModel(),
-                                    request.terminalSoftwareVersion());
+                                    userAgent,
+                                    additionalHeaders);
             String eapAkaChallenge = getEapAkaChallenge(challengeResponse);
             if (eapAkaChallenge == null) {
                 throw new ServiceEntitlementException(
@@ -225,9 +233,8 @@ public class EapAkaApi {
                     cookies,
                     MAX_EAP_AKA_ATTEMPTS,
                     request.acceptContentType(),
-                    request.terminalVendor(),
-                    request.terminalModel(),
-                    request.terminalSoftwareVersion());
+                    userAgent,
+                    additionalHeaders);
         }
     }
 
@@ -257,9 +264,8 @@ public class EapAkaApi {
             ImmutableList<String> cookies,
             int remainingAttempts,
             String acceptContentType,
-            String terminalVendor,
-            String terminalModel,
-            String terminalSoftwareVersion)
+            String userAgent,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         if (!mBypassEapAkaResponse.isEmpty()) {
             return challengeResponse(
@@ -267,14 +273,14 @@ public class EapAkaApi {
                     carrierConfig,
                     cookies,
                     CONTENT_TYPE_EAP_RELAY_JSON + ", " + acceptContentType,
-                    terminalVendor,
-                    terminalModel,
-                    terminalSoftwareVersion);
+                    userAgent,
+                    additionalHeaders);
         }
 
         EapAkaChallenge challenge = EapAkaChallenge.parseEapAkaChallenge(eapAkaChallenge);
         EapAkaResponse eapAkaResponse =
-                EapAkaResponse.respondToEapAkaChallenge(mContext, mSimSubscriptionId, challenge);
+                EapAkaResponse.respondToEapAkaChallenge(
+                        mContext, mSimSubscriptionId, challenge, carrierConfig.eapAkaRealm());
         // This could be a successful authentication, another challenge, or synchronization failure.
         if (eapAkaResponse.response() != null) {
             HttpResponse response =
@@ -283,9 +289,8 @@ public class EapAkaApi {
                             carrierConfig,
                             cookies,
                             CONTENT_TYPE_EAP_RELAY_JSON + ", " + acceptContentType,
-                            terminalVendor,
-                            terminalModel,
-                            terminalSoftwareVersion);
+                            userAgent,
+                            additionalHeaders);
             String nextEapAkaChallenge = getEapAkaChallenge(response);
             // successful authentication
             if (nextEapAkaChallenge == null) {
@@ -300,9 +305,8 @@ public class EapAkaApi {
                         cookies,
                         remainingAttempts - 1,
                         acceptContentType,
-                        terminalVendor,
-                        terminalModel,
-                        terminalSoftwareVersion);
+                        userAgent,
+                        additionalHeaders);
             } else {
                 throw new ServiceEntitlementException(
                         ERROR_EAP_AKA_FAILURE, "Unable to EAP-AKA authenticate");
@@ -315,9 +319,8 @@ public class EapAkaApi {
                             carrierConfig,
                             cookies,
                             CONTENT_TYPE_EAP_RELAY_JSON,
-                            terminalVendor,
-                            terminalModel,
-                            terminalSoftwareVersion);
+                            userAgent,
+                            additionalHeaders);
             String nextEapAkaChallenge = getEapAkaChallenge(newChallenge);
             if (nextEapAkaChallenge == null) {
                 throw new ServiceEntitlementException(
@@ -331,9 +334,8 @@ public class EapAkaApi {
                         cookies,
                         remainingAttempts - 1,
                         acceptContentType,
-                        terminalVendor,
-                        terminalModel,
-                        terminalSoftwareVersion);
+                        userAgent,
+                        additionalHeaders);
             } else {
                 throw new ServiceEntitlementException(
                         ERROR_EAP_AKA_SYNCHRONIZATION_FAILURE,
@@ -350,9 +352,8 @@ public class EapAkaApi {
             CarrierConfig carrierConfig,
             ImmutableList<String> cookies,
             String acceptContentType,
-            String terminalVendor,
-            String terminalModel,
-            String terminalSoftwareVersion)
+            String userAgent,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         JSONObject postData = new JSONObject();
         try {
@@ -365,11 +366,10 @@ public class EapAkaApi {
                 postData,
                 carrierConfig,
                 acceptContentType,
-                terminalVendor,
-                terminalModel,
-                terminalSoftwareVersion,
+                userAgent,
                 CONTENT_TYPE_EAP_RELAY_JSON,
-                cookies);
+                cookies,
+                additionalHeaders);
     }
 
     /**
@@ -383,24 +383,30 @@ public class EapAkaApi {
             String appId,
             CarrierConfig carrierConfig,
             ServiceEntitlementRequest request,
-            EsimOdsaOperation odsaOperation)
+            EsimOdsaOperation odsaOperation,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         Uri.Builder urlBuilder = null;
         JSONObject postData = null;
         if (carrierConfig.useHttpPost()) {
             postData = new JSONObject();
-            appendParametersForAuthentication(postData, request);
+            appendParametersForAuthentication(postData, request, carrierConfig);
             appendParametersForServiceEntitlementRequest(
                     postData, ImmutableList.of(appId), request);
             appendParametersForEsimOdsaOperation(postData, odsaOperation);
         } else {
             urlBuilder = Uri.parse(carrierConfig.serverUrl()).buildUpon();
-            appendParametersForAuthentication(urlBuilder, request);
+            appendParametersForAuthentication(urlBuilder, request, carrierConfig);
             appendParametersForServiceEntitlementRequest(
                     urlBuilder, ImmutableList.of(appId), request);
             appendParametersForEsimOdsaOperation(urlBuilder, odsaOperation);
         }
-
+        String userAgent =
+                getUserAgent(
+                        carrierConfig.clientTs43(),
+                        request.terminalVendor(),
+                        request.terminalModel(),
+                        request.terminalSoftwareVersion());
         if (!TextUtils.isEmpty(request.authenticationToken())
                 || !TextUtils.isEmpty(request.temporaryToken())) {
             // Fast Re-Authentication flow with pre-existing auth token
@@ -410,16 +416,14 @@ public class EapAkaApi {
                             postData,
                             carrierConfig,
                             request.acceptContentType(),
-                            request.terminalVendor(),
-                            request.terminalModel(),
-                            request.terminalSoftwareVersion())
+                            userAgent,
+                            additionalHeaders)
                     : httpGet(
                             urlBuilder.toString(),
                             carrierConfig,
                             request.acceptContentType(),
-                            request.terminalVendor(),
-                            request.terminalModel(),
-                            request.terminalSoftwareVersion());
+                            userAgent,
+                            additionalHeaders);
         } else {
             // Full Authentication flow
             Log.d(TAG, "Full Authentication");
@@ -429,16 +433,14 @@ public class EapAkaApi {
                                     postData,
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
-                                    request.terminalVendor(),
-                                    request.terminalModel(),
-                                    request.terminalSoftwareVersion())
+                                    userAgent,
+                                    additionalHeaders)
                             : httpGet(
                                     urlBuilder.toString(),
                                     carrierConfig,
                                     CONTENT_TYPE_EAP_RELAY_JSON,
-                                    request.terminalVendor(),
-                                    request.terminalModel(),
-                                    request.terminalSoftwareVersion());
+                                    userAgent,
+                                    additionalHeaders);
             String eapAkaChallenge = getEapAkaChallenge(challengeResponse);
             if (eapAkaChallenge == null) {
                 throw new ServiceEntitlementException(
@@ -454,9 +456,8 @@ public class EapAkaApi {
                     cookies,
                     MAX_EAP_AKA_ATTEMPTS,
                     request.acceptContentType(),
-                    request.terminalVendor(),
-                    request.terminalModel(),
-                    request.terminalSoftwareVersion());
+                    userAgent,
+                    additionalHeaders);
         }
     }
 
@@ -470,7 +471,10 @@ public class EapAkaApi {
      */
     @NonNull
     public String acquireOidcAuthenticationEndpoint(
-            String appId, CarrierConfig carrierConfig, ServiceEntitlementRequest request)
+            String appId,
+            CarrierConfig carrierConfig,
+            ServiceEntitlementRequest request,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         Uri.Builder urlBuilder = null;
         JSONObject postData = null;
@@ -483,6 +487,12 @@ public class EapAkaApi {
             appendParametersForServiceEntitlementRequest(
                     urlBuilder, ImmutableList.of(appId), request);
         }
+        String userAgent =
+                getUserAgent(
+                        carrierConfig.clientTs43(),
+                        request.terminalVendor(),
+                        request.terminalModel(),
+                        request.terminalSoftwareVersion());
 
         HttpResponse response =
                 carrierConfig.useHttpPost()
@@ -490,16 +500,14 @@ public class EapAkaApi {
                                 postData,
                                 carrierConfig,
                                 request.acceptContentType(),
-                                request.terminalVendor(),
-                                request.terminalModel(),
-                                request.terminalSoftwareVersion())
+                                userAgent,
+                                additionalHeaders)
                         : httpGet(
                                 urlBuilder.toString(),
                                 carrierConfig,
                                 request.acceptContentType(),
-                                request.terminalVendor(),
-                                request.terminalModel(),
-                                request.terminalSoftwareVersion());
+                                userAgent,
+                                additionalHeaders);
         return response.location();
     }
 
@@ -513,21 +521,31 @@ public class EapAkaApi {
      */
     @NonNull
     public HttpResponse queryEntitlementStatusFromOidc(
-            String url, CarrierConfig carrierConfig, ServiceEntitlementRequest request)
+            String url,
+            CarrierConfig carrierConfig,
+            ServiceEntitlementRequest request,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         Uri.Builder urlBuilder = Uri.parse(url).buildUpon();
+        String userAgent =
+                getUserAgent(
+                        carrierConfig.clientTs43(),
+                        request.terminalVendor(),
+                        request.terminalModel(),
+                        request.terminalSoftwareVersion());
         return httpGet(
                 urlBuilder.toString(),
                 carrierConfig,
                 request.acceptContentType(),
-                request.terminalVendor(),
-                request.terminalModel(),
-                request.terminalSoftwareVersion());
+                userAgent,
+                additionalHeaders);
     }
 
     @SuppressWarnings("HardwareIds")
     private void appendParametersForAuthentication(
-            Uri.Builder urlBuilder, ServiceEntitlementRequest request) {
+            Uri.Builder urlBuilder,
+            ServiceEntitlementRequest request,
+            CarrierConfig carrierConfig) {
         if (!TextUtils.isEmpty(request.authenticationToken())) {
             // IMSI and token required for fast AuthN.
             urlBuilder
@@ -542,13 +560,14 @@ public class EapAkaApi {
                     EAP_ID,
                     getImsiEap(
                             mTelephonyManager.getSimOperator(),
-                            mTelephonyManager.getSubscriberId()));
+                            mTelephonyManager.getSubscriberId(),
+                            carrierConfig.eapAkaRealm()));
         }
     }
 
     @SuppressWarnings("HardwareIds")
     private void appendParametersForAuthentication(
-            JSONObject postData, ServiceEntitlementRequest request)
+            JSONObject postData, ServiceEntitlementRequest request, CarrierConfig carrierConfig)
             throws ServiceEntitlementException {
         try {
             if (!TextUtils.isEmpty(request.authenticationToken())) {
@@ -564,7 +583,8 @@ public class EapAkaApi {
                         EAP_ID,
                         getImsiEap(
                                 mTelephonyManager.getSimOperator(),
-                                mTelephonyManager.getSubscriberId()));
+                                mTelephonyManager.getSubscriberId(),
+                                carrierConfig.eapAkaRealm()));
             }
         } catch (JSONException jsonException) {
             // Should never happen
@@ -619,7 +639,9 @@ public class EapAkaApi {
     }
 
     private void appendParametersForServiceEntitlementRequest(
-            JSONObject postData, ImmutableList<String> appIds, ServiceEntitlementRequest request)
+            JSONObject postData,
+            ImmutableList<String> appIds,
+            ServiceEntitlementRequest request)
             throws ServiceEntitlementException {
         try {
             if (!TextUtils.isEmpty(request.notificationToken())) {
@@ -822,26 +844,24 @@ public class EapAkaApi {
             String url,
             CarrierConfig carrierConfig,
             String acceptContentType,
-            String terminalVendor,
-            String terminalModel,
-            String terminalSoftwareVersion)
+            String userAgent,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         HttpRequest.Builder builder =
                 HttpRequest.builder()
                         .setUrl(url)
                         .setRequestMethod(RequestMethod.GET)
                         .addRequestProperty(HttpHeaders.ACCEPT, acceptContentType)
+                        .addRequestProperty(HttpHeaders.USER_AGENT, userAgent)
                         .setTimeoutInSec(carrierConfig.timeoutInSec())
-                        .setNetwork(carrierConfig.network());
-        String userAgent =
-                getUserAgent(
-                        carrierConfig.clientTs43(),
-                        terminalVendor,
-                        terminalModel,
-                        terminalSoftwareVersion);
-        if (!TextUtils.isEmpty(userAgent)) {
-            builder.addRequestProperty(HttpHeaders.USER_AGENT, userAgent);
-        }
+                        .setNetwork(carrierConfig.network())
+                        .setUrlConnectionFactory(carrierConfig.urlConnectionFactory());
+        additionalHeaders.forEach(
+                (k, v) -> {
+                    if (!TextUtils.isEmpty(v)) {
+                        builder.addRequestProperty(k, v);
+                    }
+                });
         return mHttpClient.request(builder.build());
     }
 
@@ -850,19 +870,17 @@ public class EapAkaApi {
             JSONObject postData,
             CarrierConfig carrierConfig,
             String acceptContentType,
-            String terminalVendor,
-            String terminalModel,
-            String terminalSoftwareVersion)
+            String userAgent,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         return httpPost(
                 postData,
                 carrierConfig,
                 acceptContentType,
-                terminalVendor,
-                terminalModel,
-                terminalSoftwareVersion,
+                userAgent,
                 ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_JSON,
-                ImmutableList.of());
+                ImmutableList.of(),
+                additionalHeaders);
     }
 
     @NonNull
@@ -870,11 +888,10 @@ public class EapAkaApi {
             JSONObject postData,
             CarrierConfig carrierConfig,
             String acceptContentType,
-            String terminalVendor,
-            String terminalModel,
-            String terminalSoftwareVersion,
+            String userAgent,
             String contentType,
-            ImmutableList<String> cookies)
+            ImmutableList<String> cookies,
+            ImmutableMap<String, String> additionalHeaders)
             throws ServiceEntitlementException {
         HttpRequest.Builder builder =
                 HttpRequest.builder()
@@ -884,17 +901,16 @@ public class EapAkaApi {
                         .addRequestProperty(HttpHeaders.ACCEPT, acceptContentType)
                         .addRequestProperty(HttpHeaders.CONTENT_TYPE, contentType)
                         .addRequestProperty(HttpHeaders.COOKIE, cookies)
+                        .addRequestProperty(HttpHeaders.USER_AGENT, userAgent)
                         .setTimeoutInSec(carrierConfig.timeoutInSec())
-                        .setNetwork(carrierConfig.network());
-        String userAgent =
-                getUserAgent(
-                        carrierConfig.clientTs43(),
-                        terminalVendor,
-                        terminalModel,
-                        terminalSoftwareVersion);
-        if (!TextUtils.isEmpty(userAgent)) {
-            builder.addRequestProperty(HttpHeaders.USER_AGENT, userAgent);
-        }
+                        .setNetwork(carrierConfig.network())
+                        .setUrlConnectionFactory(carrierConfig.urlConnectionFactory());
+        additionalHeaders.forEach(
+                (k, v) -> {
+                    if (!TextUtils.isEmpty(v)) {
+                        builder.addRequestProperty(k, v);
+                    }
+                });
         return mHttpClient.request(builder.build());
     }
 
@@ -938,33 +954,30 @@ public class EapAkaApi {
             String terminalVendor,
             String terminalModel,
             String terminalSoftwareVersion) {
-        if (!TextUtils.isEmpty(clientTs43)
-                && !TextUtils.isEmpty(terminalVendor)
-                && !TextUtils.isEmpty(terminalModel)
-                && !TextUtils.isEmpty(terminalSoftwareVersion)) {
-            return String.format(
-                    "PRD-TS43 term-%s/%s %s/%s OS-Android/%s",
-                    trimString(terminalVendor, MAX_TERMINAL_VENDOR_LENGTH),
-                    trimString(terminalModel, MAX_TERMINAL_MODEL_LENGTH),
-                    clientTs43,
-                    mAppVersion,
-                    trimString(terminalSoftwareVersion, MAX_TERMINAL_SOFTWARE_VERSION_LENGTH));
-        }
-        return "";
+        return String.format(
+                "PRD-TS43 term-%s/%s %s/%s OS-Android/%s",
+                trimString(terminalVendor, MAX_TERMINAL_VENDOR_LENGTH),
+                trimString(terminalModel, MAX_TERMINAL_MODEL_LENGTH),
+                clientTs43,
+                mAppVersion,
+                trimString(terminalSoftwareVersion, MAX_TERMINAL_SOFTWARE_VERSION_LENGTH));
     }
 
     private String trimString(String s, int maxLength) {
+        if (s == null) {
+            return null;
+        }
         return s.substring(0, Math.min(s.length(), maxLength));
     }
 
     /**
-     * Returns the IMSI EAP value. The resulting realm part of the Root NAI in 3GPP TS 23.003 clause
-     * 19.3.2 will be in the form:
+     * Returns the IMSI EAP value. The resulting EAP value is in the format of:
      *
-     * <p>{@code 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org}
+     * <p>{@code 0<IMSI>@<realm>.mnc<MNC>.mcc<MCC>.3gppnetwork.org}
      */
     @Nullable
-    public static String getImsiEap(@Nullable String mccmnc, @Nullable String imsi) {
+    public static String getImsiEap(
+            @Nullable String mccmnc, @Nullable String imsi, String realm) {
         if (mccmnc == null || mccmnc.length() < 5 || imsi == null) {
             return null;
         }
@@ -974,7 +987,7 @@ public class EapAkaApi {
         if (mnc.length() == 2) {
             mnc = "0" + mnc;
         }
-        return "0" + imsi + "@nai.epc.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org";
+        return "0" + imsi + "@" + realm + ".mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org";
     }
 
     /** Retrieves the history of past HTTP request and responses. */
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java b/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
index 97a8b9b..c7351e0 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
@@ -81,18 +81,26 @@ public class EapAkaResponse {
      * with network provided EAP-AKA challenge request message.
      */
     public static EapAkaResponse respondToEapAkaChallenge(
-            Context context, int simSubscriptionId, EapAkaChallenge eapAkaChallenge)
+            Context context,
+            int simSubscriptionId,
+            EapAkaChallenge eapAkaChallenge,
+            String eapAkaRealm)
             throws ServiceEntitlementException {
         TelephonyManager telephonyManager =
                 context.getSystemService(TelephonyManager.class)
                         .createForSubscriptionId(simSubscriptionId);
 
         // process EAP-AKA authentication with SIM
-        String response =
-                telephonyManager.getIccAuthentication(
-                        TelephonyManager.APPTYPE_USIM,
-                        TelephonyManager.AUTHTYPE_EAP_AKA,
-                        eapAkaChallenge.getSimAuthenticationRequest());
+        String response = null;
+        try {
+            response = telephonyManager.getIccAuthentication(TelephonyManager.APPTYPE_USIM,
+                TelephonyManager.AUTHTYPE_EAP_AKA,
+                eapAkaChallenge.getSimAuthenticationRequest());
+        } catch (UnsupportedOperationException e) {
+            throw new ServiceEntitlementException(
+                ERROR_ICC_AUTHENTICATION_NOT_AVAILABLE,
+                "UnsupportedOperationException" + e.toString());
+        }
         if (response == null) {
             throw new ServiceEntitlementException(
                     ERROR_ICC_AUTHENTICATION_NOT_AVAILABLE, "EAP-AKA response is null!");
@@ -108,8 +116,10 @@ public class EapAkaResponse {
             // generate master key - refer to RFC 4187, section 7. Key Generation
             MasterKey mk =
                     MasterKey.create(
-                            EapAkaApi.getImsiEap(telephonyManager.getSimOperator(),
-                                    telephonyManager.getSubscriberId()),
+                            EapAkaApi.getImsiEap(
+                                    telephonyManager.getSimOperator(),
+                                    telephonyManager.getSubscriberId(),
+                                    eapAkaRealm),
                             securityContext.getIk(),
                             securityContext.getCk());
             // K_aut is the key used to calculate MAC
diff --git a/java/com/android/libraries/entitlement/http/HttpClient.java b/java/com/android/libraries/entitlement/http/HttpClient.java
index 88ac5d5..03434a6 100644
--- a/java/com/android/libraries/entitlement/http/HttpClient.java
+++ b/java/com/android/libraries/entitlement/http/HttpClient.java
@@ -36,6 +36,7 @@ import androidx.annotation.WorkerThread;
 import com.android.libraries.entitlement.ServiceEntitlementException;
 import com.android.libraries.entitlement.http.HttpConstants.ContentType;
 import com.android.libraries.entitlement.utils.StreamUtils;
+import com.android.libraries.entitlement.utils.UrlConnectionFactory;
 
 import com.google.common.collect.ImmutableList;
 import com.google.common.net.HttpHeaders;
@@ -119,12 +120,16 @@ public class HttpClient {
     private void createConnection(HttpRequest request) throws ServiceEntitlementException {
         try {
             URL url = new URL(request.url());
+            UrlConnectionFactory urlConnectionFactory = request.urlConnectionFactory();
             Network network = request.network();
-            if (network == null) {
-                mConnection = (HttpURLConnection) url.openConnection();
-            } else {
+            if (network != null) {
                 mConnection = (HttpURLConnection) network.openConnection(url);
+            } else if (urlConnectionFactory != null) {
+                mConnection = (HttpURLConnection) urlConnectionFactory.openConnection(url);
+            } else  {
+                mConnection = (HttpURLConnection) url.openConnection();
             }
+
             mConnection.setInstanceFollowRedirects(false);
             // add HTTP headers
             for (Map.Entry<String, String> entry : request.requestProperties().entries()) {
@@ -174,7 +179,13 @@ public class HttpClient {
         }
         responseBuilder.setCookies(getCookies(connection));
         try {
-            String responseBody = readResponse(connection);
+            // {@code CronetHttpURLConnection.getInputStream()} throws if the
+            // caller tries to read the response body of a redirect when
+            // redirects are disabled.
+            String responseBody =
+                    connection.getResponseCode() == HttpURLConnection.HTTP_MOVED_TEMP
+                            ? ""
+                            : readResponse(connection);
             logPii("HttpClient.response body: " + responseBody);
             responseBuilder.setBody(responseBody);
         } catch (IOException e) {
diff --git a/java/com/android/libraries/entitlement/http/HttpRequest.java b/java/com/android/libraries/entitlement/http/HttpRequest.java
index ec5ca7a..9907fe1 100644
--- a/java/com/android/libraries/entitlement/http/HttpRequest.java
+++ b/java/com/android/libraries/entitlement/http/HttpRequest.java
@@ -21,6 +21,7 @@ import android.net.Network;
 
 import androidx.annotation.Nullable;
 
+import com.android.libraries.entitlement.utils.UrlConnectionFactory;
 import com.android.libraries.entitlement.CarrierConfig;
 
 import com.google.auto.value.AutoValue;
@@ -54,6 +55,13 @@ public abstract class HttpRequest {
     @Nullable
     public abstract Network network();
 
+    /**
+     * The {@link UrlConnectionFactory} used for this HTTP connection.
+     * See {@link Builder#setUrlConnectionFactory}.
+     */
+    @Nullable
+    public abstract UrlConnectionFactory urlConnectionFactory();
+
     /** Builder of {@link HttpRequest}. */
     @AutoValue.Builder
     public abstract static class Builder {
@@ -106,6 +114,13 @@ public abstract class HttpRequest {
          * is used.
          */
         public abstract Builder setNetwork(@Nullable Network network);
+
+        /**
+         * If unset, the default Android API {@link java.net.URL#openConnection}
+         * would be used. This allows callers of the lib to choose the HTTP stack.
+         */
+        public abstract Builder setUrlConnectionFactory(
+                @Nullable UrlConnectionFactory urlConnectionFactory);
     }
 
     public static Builder builder() {
diff --git a/java/com/android/libraries/entitlement/utils/DebugUtils.java b/java/com/android/libraries/entitlement/utils/DebugUtils.java
index d89c572..3c5bb83 100644
--- a/java/com/android/libraries/entitlement/utils/DebugUtils.java
+++ b/java/com/android/libraries/entitlement/utils/DebugUtils.java
@@ -37,7 +37,7 @@ public final class DebugUtils {
     /** Logs PII data if allowed. */
     public static void logPii(String message) {
         if (isPiiLoggable()) {
-            Log.d(TAG, message);
+            Log.i(TAG, message);
         }
     }
 
diff --git a/java/com/android/libraries/entitlement/utils/Ts43Constants.java b/java/com/android/libraries/entitlement/utils/Ts43Constants.java
index ea7bca7..e9a778a 100644
--- a/java/com/android/libraries/entitlement/utils/Ts43Constants.java
+++ b/java/com/android/libraries/entitlement/utils/Ts43Constants.java
@@ -61,6 +61,9 @@ public final class Ts43Constants {
     /** App ID for satellite entitlement. */
     public static final String APP_SATELLITE_ENTITLEMENT = "ap2016";
 
+    /** App ID for ODSA for Cross-TS.43 platform device, Entitlement and Activation */
+    public static final String APP_ODSA_CROSS_TS43 = "ap2017";
+
     @Retention(RetentionPolicy.SOURCE)
     @StringDef({
             APP_UNKNOWN,
@@ -74,7 +77,8 @@ public final class Ts43Constants {
             APP_DIRECT_CARRIER_BILLING,
             APP_PRIVATE_USER_IDENTITY,
             APP_PHONE_NUMBER_INFORMATION,
-            APP_SATELLITE_ENTITLEMENT
+            APP_SATELLITE_ENTITLEMENT,
+            APP_ODSA_CROSS_TS43
     })
     public @interface AppId {
     }
@@ -98,6 +102,7 @@ public final class Ts43Constants {
             case APP_PRIVATE_USER_IDENTITY:
             case APP_PHONE_NUMBER_INFORMATION:
             case APP_SATELLITE_ENTITLEMENT:
+            case APP_ODSA_CROSS_TS43:
                 return true;
             default: // fall through
         }
diff --git a/java/com/android/libraries/entitlement/utils/UrlConnectionFactory.java b/java/com/android/libraries/entitlement/utils/UrlConnectionFactory.java
new file mode 100644
index 0000000..bf45e48
--- /dev/null
+++ b/java/com/android/libraries/entitlement/utils/UrlConnectionFactory.java
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.android.libraries.entitlement.utils;
+
+import java.io.IOException;
+import java.net.URL;
+import java.net.URLConnection;
+
+/**
+ * Factory for creating {@link URLConnections}.
+ */
+public interface UrlConnectionFactory {
+
+  /**
+   * Returns a {@link URLConnection} instance that represents a connection to
+   * the remote object referred to by the {@code URL}.
+   *
+   * @param url the URL to which the connection will be made.
+   */
+  public abstract URLConnection openConnection(URL url) throws IOException;
+}
diff --git a/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java b/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java
index 25812a9..dbf0616 100644
--- a/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java
+++ b/tests/src/com/android/libraries/entitlement/ServiceEntitlementTest.java
@@ -18,6 +18,8 @@ package com.android.libraries.entitlement;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.when;
 import static org.testng.Assert.expectThrows;
@@ -102,7 +104,10 @@ public class ServiceEntitlementTest {
     public void queryEntitlementStatus_appVolte_returnResult() throws Exception {
         ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
         when(mMockEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOLTE), mCarrierConfig, request))
+                        eq(ImmutableList.of(ServiceEntitlement.APP_VOLTE)),
+                        eq(mCarrierConfig),
+                        eq(request),
+                        any()))
                 .thenAnswer(
                         invocation -> {
                             when(mMockHttpResponse.body()).thenReturn(QUERY_APP_VOLTE_RESULT);
@@ -119,7 +124,10 @@ public class ServiceEntitlementTest {
     public void queryEntitlementStatus_appVowifi_returnResult() throws Exception {
         ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
         when(mMockEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), mCarrierConfig, request))
+                        eq(ImmutableList.of(ServiceEntitlement.APP_VOWIFI)),
+                        eq(mCarrierConfig),
+                        eq(request),
+                        any()))
                 .thenAnswer(
                         invocation -> {
                             when(mMockHttpResponse.body()).thenReturn(QUERY_APP_VOWIFI_RESULT);
@@ -137,10 +145,11 @@ public class ServiceEntitlementTest {
         ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
         EsimOdsaOperation odsaOperation = EsimOdsaOperation.builder().build();
         when(mMockEapAkaApi.performEsimOdsaOperation(
-                        ServiceEntitlement.APP_ODSA_COMPANION,
-                        mCarrierConfig,
-                        request,
-                        odsaOperation))
+                        eq(ServiceEntitlement.APP_ODSA_COMPANION),
+                        eq(mCarrierConfig),
+                        eq(request),
+                        eq(odsaOperation),
+                        any()))
                 .thenAnswer(
                         invocation -> {
                             when(mMockHttpResponse.body())
@@ -159,10 +168,11 @@ public class ServiceEntitlementTest {
         ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
         EsimOdsaOperation odsaOperation = EsimOdsaOperation.builder().build();
         when(mMockEapAkaApi.performEsimOdsaOperation(
-                        ServiceEntitlement.APP_ODSA_PRIMARY,
-                        mCarrierConfig,
-                        request,
-                        odsaOperation))
+                        eq(ServiceEntitlement.APP_ODSA_PRIMARY),
+                        eq(mCarrierConfig),
+                        eq(request),
+                        eq(odsaOperation),
+                        any()))
                 .thenAnswer(
                         invocation -> {
                             when(mMockHttpResponse.body())
@@ -180,7 +190,10 @@ public class ServiceEntitlementTest {
     public void acquireOidcAuthenticationEndpoint_returnResult() throws Exception {
         ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
         when(mMockEapAkaApi.acquireOidcAuthenticationEndpoint(
-                        ServiceEntitlement.APP_ODSA_COMPANION, mCarrierConfig, request))
+                        eq(ServiceEntitlement.APP_ODSA_COMPANION),
+                        eq(mCarrierConfig),
+                        eq(request),
+                        any()))
                 .thenReturn(QUERY_OIDC_RESULT);
 
         assertThat(
@@ -192,7 +205,10 @@ public class ServiceEntitlementTest {
     @Test
     public void queryEntitlementStatusFromOidc_returnResult() throws Exception {
         when(mMockEapAkaApi.queryEntitlementStatusFromOidc(
-                        ServiceEntitlement.APP_ODSA_PRIMARY, mCarrierConfig, null))
+                        eq(ServiceEntitlement.APP_ODSA_PRIMARY),
+                        eq(mCarrierConfig),
+                        eq(null),
+                        any()))
                 .thenAnswer(
                         invocation -> {
                             when(mMockHttpResponse.body())
diff --git a/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java b/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java
index f30e171..87f0851 100644
--- a/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java
+++ b/tests/src/com/android/libraries/entitlement/Ts43AuthenticationTest.java
@@ -123,8 +123,9 @@ public class Ts43AuthenticationTest {
         doReturn(Context.TELEPHONY_SERVICE).when(mContext)
                 .getSystemServiceName(TelephonyManager.class);
         doReturn(mTelephonyManager).when(mContext).getSystemService(Context.TELEPHONY_SERVICE);
-        doReturn(mMockHttpResponse).when(mMockEapAkaApi)
-                .queryEntitlementStatus(any(), any(), any());
+        doReturn(mMockHttpResponse)
+                .when(mMockEapAkaApi)
+                .queryEntitlementStatus(any(), any(), any(), any());
         doReturn(COOKIES).when(mMockHttpResponse).cookies();
     }
 
@@ -185,9 +186,13 @@ public class Ts43AuthenticationTest {
 
     @Test
     public void testGetAuthToken_httpResponseError() throws Exception {
-        doThrow(new ServiceEntitlementException(
-                ServiceEntitlementException.ERROR_HTTP_STATUS_NOT_SUCCESS, 1234, "http error"))
-                .when(mMockEapAkaApi).queryEntitlementStatus(any(), any(), any());
+        doThrow(
+                        new ServiceEntitlementException(
+                                ServiceEntitlementException.ERROR_HTTP_STATUS_NOT_SUCCESS,
+                                1234,
+                                "http error"))
+                .when(mMockEapAkaApi)
+                .queryEntitlementStatus(any(), any(), any(), any());
         try {
             mTs43Authentication.getAuthToken(
                     0, Ts43Constants.APP_ODSA_PRIMARY, APP_NAME, APP_VERSION);
diff --git a/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java b/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
index 55ca8c1..54e5ecb 100644
--- a/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
+++ b/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
@@ -307,8 +307,9 @@ public class Ts43OperationTest {
         CarrierConfig carrierConfig = CarrierConfig.builder().setServerUrl(TEST_URL).build();
         ServiceEntitlement serviceEntitlement =
                 new ServiceEntitlement(carrierConfig, mMockEapAkaApi);
-        doReturn(mMockHttpResponse).when(mMockEapAkaApi)
-                .performEsimOdsaOperation(any(), any(), any(), any());
+        doReturn(mMockHttpResponse)
+                .when(mMockEapAkaApi)
+                .performEsimOdsaOperation(any(), any(), any(), any(), any());
 
         doReturn(2).when(mTelephonyManager).getActiveModemCount();
         doReturn(IMEI).when(mTelephonyManager).getImei(0);
diff --git a/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java b/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java
index 8a4a185..ca10d9f 100644
--- a/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java
+++ b/tests/src/com/android/libraries/entitlement/eapaka/EapAkaApiTest.java
@@ -53,6 +53,7 @@ import com.android.libraries.entitlement.http.HttpRequest;
 import com.android.libraries.entitlement.http.HttpResponse;
 
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
 import com.google.common.net.HttpHeaders;
 
 import org.json.JSONException;
@@ -160,7 +161,10 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(httpResponse);
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
@@ -168,6 +172,7 @@ public class EapAkaApiTest {
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getValue().network()).isEqualTo(mMockNetwork);
         assertThat(mHttpRequestCaptor.getValue().requestMethod()).isEqualTo(RequestMethod.GET);
+        assertThat(mHttpRequestCaptor.getValue().requestProperties()).containsEntry("Key", "Value");
     }
 
     @Test
@@ -189,7 +194,10 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(httpResponse);
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
@@ -197,6 +205,7 @@ public class EapAkaApiTest {
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getValue().network()).isEqualTo(mMockNetwork);
         assertThat(mHttpRequestCaptor.getValue().requestMethod()).isEqualTo(RequestMethod.POST);
+        assertThat(mHttpRequestCaptor.getValue().requestProperties()).containsEntry("Key", "Value");
     }
 
     @Test
@@ -225,7 +234,10 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
@@ -233,6 +245,78 @@ public class EapAkaApiTest {
                 .isEqualTo(RequestMethod.GET);
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).url())
+                .contains("EAP_ID=0234107813240779%40nai.epc.mnc010.mcc234.3gppnetwork.org");
+        // Verify that the 2nd request has cookies set by the 1st response
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
+                .containsAtLeast(
+                        HTTP_HEADER_COOKIE, COOKIE_VALUE,
+                        HTTP_HEADER_COOKIE, COOKIE_VALUE_1);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).timeoutInSec())
+                .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).network()).isNull();
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).timeoutInSec())
+                .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).network()).isNull();
+    }
+
+    @Test
+    public void queryEntitlementStatus_noAuthenticationToken_altenateEapAkaRealm()
+            throws Exception {
+        when(mMockTelephonyManagerForSubId.getIccAuthentication(
+                        TelephonyManager.APPTYPE_USIM,
+                        TelephonyManager.AUTHTYPE_EAP_AKA,
+                        EAP_AKA_SECURITY_CONTEXT_REQUEST_EXPECTED))
+                .thenReturn(EAP_AKA_SECURITY_CONTEXT_RESPONSE_SUCCESS);
+        HttpResponse eapChallengeResponse =
+                HttpResponse.builder()
+                        .setContentType(ContentType.JSON)
+                        .setBody(EAP_AKA_CHALLENGE)
+                        .setCookies(ImmutableList.of(COOKIE_VALUE, COOKIE_VALUE_1))
+                        .build();
+        HttpResponse xmlResponse =
+                HttpResponse.builder()
+                        .setContentType(ContentType.XML)
+                        .setBody(RESPONSE_XML)
+                        .build();
+        when(mMockHttpClient.request(any()))
+                .thenReturn(eapChallengeResponse)
+                .thenReturn(xmlResponse);
+        CarrierConfig carrierConfig =
+                CarrierConfig.builder().setServerUrl(TEST_URL).setEapAkaRealm("wlan").build();
+        ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
+
+        HttpResponse response =
+                mEapAkaApi.queryEntitlementStatus(
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
+
+        assertThat(response).isEqualTo(xmlResponse);
+        verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
+                .isEqualTo(RequestMethod.GET);
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestMethod())
+                .isEqualTo(RequestMethod.POST);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).requestProperties())
+                .containsEntry("Key", "Value");
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
+                .containsEntry("Key", "Value");
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).url())
+                .contains("EAP_ID=0234107813240779%40wlan.mnc010.mcc234.3gppnetwork.org");
         // Verify that the 2nd request has cookies set by the 1st response
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
                 .containsAtLeast(
@@ -273,7 +357,80 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
+
+        assertThat(response).isEqualTo(xmlResponse);
+        verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
+                .isEqualTo(RequestMethod.POST);
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestMethod())
+                .isEqualTo(RequestMethod.POST);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).postData().getString("EAP_ID"))
+                .isEqualTo("0234107813240779@nai.epc.mnc010.mcc234.3gppnetwork.org");
+        // Verify that the 2nd request has cookies set by the 1st response
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
+                .containsAtLeast(
+                        HTTP_HEADER_COOKIE, COOKIE_VALUE,
+                        HTTP_HEADER_COOKIE, COOKIE_VALUE_1);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).timeoutInSec())
+                .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).network()).isNull();
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).timeoutInSec())
+                .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).network()).isNull();
+    }
+
+    @Test
+    public void queryEntitlementStatus_noAuthenticationToken_useHttpPost_altenateEapAkaRealm()
+            throws Exception {
+        when(mMockTelephonyManagerForSubId.getIccAuthentication(
+                        TelephonyManager.APPTYPE_USIM,
+                        TelephonyManager.AUTHTYPE_EAP_AKA,
+                        EAP_AKA_SECURITY_CONTEXT_REQUEST_EXPECTED))
+                .thenReturn(EAP_AKA_SECURITY_CONTEXT_RESPONSE_SUCCESS);
+        HttpResponse eapChallengeResponse =
+                HttpResponse.builder()
+                        .setContentType(ContentType.JSON)
+                        .setBody(EAP_AKA_CHALLENGE)
+                        .setCookies(ImmutableList.of(COOKIE_VALUE, COOKIE_VALUE_1))
+                        .build();
+        HttpResponse xmlResponse =
+                HttpResponse.builder()
+                        .setContentType(ContentType.XML)
+                        .setBody(RESPONSE_XML)
+                        .build();
+        when(mMockHttpClient.request(any()))
+                .thenReturn(eapChallengeResponse)
+                .thenReturn(xmlResponse);
+        CarrierConfig carrierConfig =
+                CarrierConfig.builder()
+                        .setServerUrl(TEST_URL)
+                        .setUseHttpPost(true)
+                        .setEapAkaRealm("wlan")
+                        .build();
+        ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
+
+        HttpResponse response =
+                mEapAkaApi.queryEntitlementStatus(
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
@@ -281,6 +438,12 @@ public class EapAkaApiTest {
                 .isEqualTo(RequestMethod.POST);
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).requestProperties())
+                .containsEntry("Key", "Value");
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
+                .containsEntry("Key", "Value");
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).postData().getString("EAP_ID"))
+                .isEqualTo("0234107813240779@wlan.mnc010.mcc234.3gppnetwork.org");
         // Verify that the 2nd request has cookies set by the 1st response
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
                 .containsAtLeast(
@@ -325,7 +488,8 @@ public class EapAkaApiTest {
                                 mEapAkaApi.queryEntitlementStatus(
                                         ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
                                         carrierConfig,
-                                        request));
+                                        request,
+                                        ImmutableMap.of()));
 
         assertThat(exception.getErrorCode())
                 .isEqualTo(ServiceEntitlementException.ERROR_MALFORMED_HTTP_RESPONSE);
@@ -363,7 +527,10 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         // Verify that the subsequent requests have cookies set by the 1st response
@@ -375,12 +542,30 @@ public class EapAkaApiTest {
         assertThat(mHttpRequestCaptor.getAllValues().get(0).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(0).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(1).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(1).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(2).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(2).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(2)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -411,7 +596,10 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         // Verify that the subsequent requests have cookies set by the 1st response
@@ -423,15 +611,39 @@ public class EapAkaApiTest {
         assertThat(mHttpRequestCaptor.getAllValues().get(0).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(0).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(1).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(1).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(2).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(2).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(2)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(3).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(3).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(3)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -463,7 +675,8 @@ public class EapAkaApiTest {
                                 mEapAkaApi.queryEntitlementStatus(
                                         ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
                                         carrierConfig,
-                                        request));
+                                        request,
+                                        ImmutableMap.of()));
 
         assertThat(exception.getErrorCode())
                 .isEqualTo(ServiceEntitlementException.ERROR_EAP_AKA_FAILURE);
@@ -488,13 +701,15 @@ public class EapAkaApiTest {
         ServiceEntitlementRequest request =
                 ServiceEntitlementRequest.builder().setAuthenticationToken(TOKEN).build();
 
-        mEapAkaApi.queryEntitlementStatus(appIds, carrierConfig, request);
+        mEapAkaApi.queryEntitlementStatus(
+                appIds, carrierConfig, request, ImmutableMap.of("Key", "Value"));
 
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getValue().url()).contains(ServiceEntitlement.APP_VOWIFI);
         assertThat(mHttpRequestCaptor.getValue().url()).contains(ServiceEntitlement.APP_VOLTE);
         assertThat(mHttpRequestCaptor.getValue().timeoutInSec()).isEqualTo(70);
         assertThat(mHttpRequestCaptor.getValue().network()).isNull();
+        assertThat(mHttpRequestCaptor.getValue().requestProperties()).containsEntry("Key", "Value");
     }
 
     @Test
@@ -513,7 +728,8 @@ public class EapAkaApiTest {
                                 mEapAkaApi.queryEntitlementStatus(
                                         ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
                                         carrierConfig,
-                                        request));
+                                        request,
+                                        ImmutableMap.of()));
 
         assertThat(exception.getErrorCode())
                 .isEqualTo(ServiceEntitlementException.ERROR_MALFORMED_HTTP_RESPONSE);
@@ -552,15 +768,22 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         // Verify that the 2nd/3rd request has cookie set by the 1st/2nd response
         verify(mMockHttpClient, times(3)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
                 .containsEntry(HTTP_HEADER_COOKIE, COOKIE_VALUE);
+        assertThat(mHttpRequestCaptor.getAllValues().get(1).requestProperties())
+                .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(2).requestProperties())
                 .containsEntry(HTTP_HEADER_COOKIE, COOKIE_VALUE);
+        assertThat(mHttpRequestCaptor.getAllValues().get(2).requestProperties())
+                .containsEntry("Key", "Value");
     }
 
     @Test
@@ -596,7 +819,8 @@ public class EapAkaApiTest {
                                 mEapAkaApi.queryEntitlementStatus(
                                         ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
                                         carrierConfig,
-                                        request));
+                                        request,
+                                        ImmutableMap.of()));
 
         assertThat(exception.getErrorCode())
                 .isEqualTo(ServiceEntitlementException.ERROR_MALFORMED_HTTP_RESPONSE);
@@ -639,7 +863,8 @@ public class EapAkaApiTest {
                                 mEapAkaApi.queryEntitlementStatus(
                                         ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
                                         carrierConfig,
-                                        request));
+                                        request,
+                                        ImmutableMap.of()));
 
         assertThat(exception.getErrorCode())
                 .isEqualTo(ServiceEntitlementException.ERROR_EAP_AKA_SYNCHRONIZATION_FAILURE);
@@ -672,7 +897,10 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApiBypassAuthentication.queryEntitlementStatus(
-                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                        ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         // Verify that the 2nd request has cookies set by the 1st response
@@ -684,9 +912,21 @@ public class EapAkaApiTest {
         assertThat(mHttpRequestCaptor.getAllValues().get(0).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(0).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(1).timeoutInSec())
                 .isEqualTo(CarrierConfig.DEFAULT_TIMEOUT_IN_SEC);
         assertThat(mHttpRequestCaptor.getAllValues().get(1).network()).isNull();
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         verify(mMockTelephonyManagerForSubId, times(0))
                 .getIccAuthentication(anyInt(), anyInt(), any());
         assertThat(
@@ -711,7 +951,10 @@ public class EapAkaApiTest {
                         .build();
 
         mEapAkaApi.queryEntitlementStatus(
-                ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
 
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getValue().requestProperties().get(HttpHeaders.ACCEPT))
@@ -728,11 +971,15 @@ public class EapAkaApiTest {
                 ServiceEntitlementRequest.builder().setAuthenticationToken(TOKEN).build();
 
         mEapAkaApi.queryEntitlementStatus(
-                ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                carrierConfig,
+                request,
+                ImmutableMap.of("Key", "Value"));
 
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getValue().requestProperties().get(HttpHeaders.ACCEPT))
                 .containsExactly(ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_JSON_AND_XML);
+        assertThat(mHttpRequestCaptor.getValue().requestProperties()).containsEntry("Key", "Value");
     }
 
     @Test
@@ -751,7 +998,10 @@ public class EapAkaApiTest {
                         .build();
 
         mEapAkaApi.queryEntitlementStatus(
-                ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
 
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
         String urlParams =
@@ -777,7 +1027,10 @@ public class EapAkaApiTest {
                         .build();
 
         mEapAkaApi.queryEntitlementStatus(
-                ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
 
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
         String userAgent =
@@ -827,7 +1080,10 @@ public class EapAkaApiTest {
                         .build();
 
         mEapAkaApi.queryEntitlementStatus(
-                ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
 
         verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
         String userAgent =
@@ -868,7 +1124,10 @@ public class EapAkaApiTest {
                         .build();
 
         mEapAkaApi.queryEntitlementStatus(
-                ImmutableList.of(ServiceEntitlement.APP_VOWIFI), carrierConfig, request);
+                ImmutableList.of(ServiceEntitlement.APP_VOWIFI),
+                carrierConfig,
+                request,
+                ImmutableMap.of());
 
         verify(mMockHttpClient).request(mHttpRequestCaptor.capture());
         String userAgent =
@@ -915,14 +1174,30 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.performEsimOdsaOperation(
-                        ServiceEntitlement.APP_ODSA_COMPANION, carrierConfig, request, operation);
+                        ServiceEntitlement.APP_ODSA_COMPANION,
+                        carrierConfig,
+                        request,
+                        operation,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
                 .isEqualTo(RequestMethod.GET);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -954,14 +1229,30 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.performEsimOdsaOperation(
-                        ServiceEntitlement.APP_ODSA_COMPANION, carrierConfig, request, operation);
+                        ServiceEntitlement.APP_ODSA_COMPANION,
+                        carrierConfig,
+                        request,
+                        operation,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         verify(mMockHttpClient, times(2)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
         assertThat(mHttpRequestCaptor.getAllValues().get(1).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(1)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -983,12 +1274,22 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.performEsimOdsaOperation(
-                        ServiceEntitlement.APP_ODSA_COMPANION, carrierConfig, request, operation);
+                        ServiceEntitlement.APP_ODSA_COMPANION,
+                        carrierConfig,
+                        request,
+                        operation,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         verify(mMockHttpClient, times(1)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
                 .isEqualTo(RequestMethod.GET);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -1012,12 +1313,18 @@ public class EapAkaApiTest {
 
         HttpResponse response =
                 mEapAkaApi.performEsimOdsaOperation(
-                        ServiceEntitlement.APP_ODSA_COMPANION, carrierConfig, request, operation);
+                        ServiceEntitlement.APP_ODSA_COMPANION,
+                        carrierConfig,
+                        request,
+                        operation,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
         verify(mMockHttpClient, times(1)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(mHttpRequestCaptor.getAllValues().get(0).requestProperties())
+                .containsEntry("Key", "Value");
     }
 
     @Test
@@ -1053,7 +1360,8 @@ public class EapAkaApiTest {
                                         ServiceEntitlement.APP_ODSA_COMPANION,
                                         carrierConfig,
                                         request,
-                                        operation));
+                                        operation,
+                                        ImmutableMap.of()));
 
         assertThat(exception.getErrorCode())
                 .isEqualTo(ServiceEntitlementException.ERROR_MALFORMED_HTTP_RESPONSE);
@@ -1077,12 +1385,21 @@ public class EapAkaApiTest {
 
         String endpoint =
                 mEapAkaApi.acquireOidcAuthenticationEndpoint(
-                        ServiceEntitlement.APP_ODSA_COMPANION, carrierConfig, request);
+                        ServiceEntitlement.APP_ODSA_COMPANION,
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(endpoint).isEqualTo(HTTP_HEADER_LOCATION);
         verify(mMockHttpClient, times(1)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
                 .isEqualTo(RequestMethod.GET);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -1099,12 +1416,21 @@ public class EapAkaApiTest {
 
         String endpoint =
                 mEapAkaApi.acquireOidcAuthenticationEndpoint(
-                        ServiceEntitlement.APP_ODSA_COMPANION, carrierConfig, request);
+                        ServiceEntitlement.APP_ODSA_COMPANION,
+                        carrierConfig,
+                        request,
+                        ImmutableMap.of("Key", "Value"));
 
         assertThat(endpoint).isEqualTo(HTTP_HEADER_LOCATION);
         verify(mMockHttpClient, times(1)).request(mHttpRequestCaptor.capture());
         assertThat(mHttpRequestCaptor.getAllValues().get(0).requestMethod())
                 .isEqualTo(RequestMethod.POST);
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 
     @Test
@@ -1119,9 +1445,16 @@ public class EapAkaApiTest {
         ServiceEntitlementRequest request = ServiceEntitlementRequest.builder().build();
 
         HttpResponse response =
-                mEapAkaApi.queryEntitlementStatusFromOidc(TEST_URL, carrierConfig, request);
+                mEapAkaApi.queryEntitlementStatusFromOidc(
+                        TEST_URL, carrierConfig, request, ImmutableMap.of("Key", "Value"));
 
         assertThat(response).isEqualTo(xmlResponse);
-        verify(mMockHttpClient, times(1)).request(any());
+        verify(mMockHttpClient, times(1)).request(mHttpRequestCaptor.capture());
+        assertThat(
+                mHttpRequestCaptor
+                        .getAllValues()
+                        .get(0)
+                        .requestProperties())
+                        .containsEntry("Key", "Value");
     }
 }
diff --git a/tests/src/com/android/libraries/entitlement/eapaka/EapAkaResponseTest.java b/tests/src/com/android/libraries/entitlement/eapaka/EapAkaResponseTest.java
index 073a973..2166eb2 100644
--- a/tests/src/com/android/libraries/entitlement/eapaka/EapAkaResponseTest.java
+++ b/tests/src/com/android/libraries/entitlement/eapaka/EapAkaResponseTest.java
@@ -23,6 +23,7 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.when;
+import static org.junit.Assert.assertThrows;
 
 import android.content.Context;
 import android.telephony.TelephonyManager;
@@ -31,6 +32,8 @@ import android.util.Base64;
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.runner.AndroidJUnit4;
 
+import com.android.libraries.entitlement.ServiceEntitlementException;
+
 import com.google.common.io.BaseEncoding;
 
 import org.junit.Before;
@@ -106,11 +109,25 @@ public class EapAkaResponseTest {
                         convertHexStringToBytes(EAP_AKA_CHALLENGE_RESPONSE), Base64.NO_WRAP);
 
         EapAkaResponse challengeResponse =
-                EapAkaResponse.respondToEapAkaChallenge(mContext, SUB_ID, challenge);
+                EapAkaResponse.respondToEapAkaChallenge(mContext, SUB_ID, challenge, "nai.epc");
 
         assertThat(challengeResponse.response()).isEqualTo(expectedResponse);
     }
 
+    @Test
+    public void generateEapAkaChallengeResponse_throwException() throws Exception {
+        EapAkaChallenge challenge = EapAkaChallenge.parseEapAkaChallenge(EAP_AKA_CHALLENGE_REQUEST);
+        when(mMockTelephonyManagerForSubId.getIccAuthentication(
+                TelephonyManager.APPTYPE_USIM,
+                TelephonyManager.AUTHTYPE_EAP_AKA,
+                EAP_AKA_SECURITY_CONTEXT_REQUEST_EXPECTED))
+                .thenThrow(new UnsupportedOperationException());
+
+        assertThrows(ServiceEntitlementException.class,
+                () -> EapAkaResponse.respondToEapAkaChallenge(mContext, SUB_ID, challenge,
+                    "nai.epc"));
+    }
+
     @Test
     public void generateEapAkaChallengeResponse_syncFailure() throws Exception {
         EapAkaChallenge challenge = EapAkaChallenge.parseEapAkaChallenge(EAP_AKA_CHALLENGE_REQUEST);
@@ -124,7 +141,7 @@ public class EapAkaResponseTest {
                         convertHexStringToBytes(EAP_AKA_CHALLENGE_SYNC_FAILURE), Base64.NO_WRAP);
 
         EapAkaResponse challengeResponse =
-                EapAkaResponse.respondToEapAkaChallenge(mContext, SUB_ID, challenge);
+                EapAkaResponse.respondToEapAkaChallenge(mContext, SUB_ID, challenge, "nai.epc");
 
         assertThat(challengeResponse.synchronizationFailureResponse()).isEqualTo(expectedResponse);
     }
```

