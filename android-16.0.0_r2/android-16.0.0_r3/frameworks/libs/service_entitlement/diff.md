```diff
diff --git a/OWNERS b/OWNERS
index 34b7bde..c46553d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
 mewan@google.com
 kiwonp@google.com
-akaustubh@google.com
diff --git a/java/com/android/libraries/entitlement/Ts43Operation.java b/java/com/android/libraries/entitlement/Ts43Operation.java
index ebbf924..80e4e0a 100644
--- a/java/com/android/libraries/entitlement/Ts43Operation.java
+++ b/java/com/android/libraries/entitlement/Ts43Operation.java
@@ -24,9 +24,9 @@ import android.telephony.TelephonyManager;
 import android.text.TextUtils;
 import android.util.Log;
 
-import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
 
 import com.android.libraries.entitlement.EsimOdsaOperation.OdsaServiceStatus;
 import com.android.libraries.entitlement.http.HttpConstants;
@@ -50,11 +50,10 @@ import com.android.libraries.entitlement.odsa.PlanOffer;
 import com.android.libraries.entitlement.utils.Ts43Constants;
 import com.android.libraries.entitlement.utils.Ts43XmlDoc;
 
+import com.google.auto.value.AutoValue;
 import com.google.common.base.Strings;
 import com.google.common.collect.ImmutableList;
 
-import java.lang.annotation.Retention;
-import java.lang.annotation.RetentionPolicy;
 import java.net.MalformedURLException;
 import java.net.URL;
 import java.time.Instant;
@@ -67,128 +66,329 @@ import java.util.List;
 import java.util.Objects;
 
 /** TS43 operations described in GSMA Service Entitlement Configuration spec. */
-public class Ts43Operation {
+@AutoValue
+public abstract class Ts43Operation {
     private static final String TAG = "Ts43";
 
-    /**
-     * The normal token retrieved via {@link Ts43Authentication#getAuthToken(int, String, String,
-     * String)} or {@link Ts43Authentication#getAuthToken(URL)}.
-     */
-    public static final int TOKEN_TYPE_NORMAL = 1;
-
-    /**
-     * The temporary token retrieved via {@link
-     * Ts43Operation#acquireTemporaryToken(AcquireTemporaryTokenRequest)}.
-     */
-    public static final int TOKEN_TYPE_TEMPORARY = 2;
-
-    @Retention(RetentionPolicy.SOURCE)
-    @IntDef({TOKEN_TYPE_NORMAL, TOKEN_TYPE_TEMPORARY})
-    public @interface TokenType {
-    }
-
     /** The application context. */
     @NonNull
-    private final Context mContext;
+    protected abstract Context context();
 
     /**
      * The TS.43 entitlement version to use. For example, {@code "9.0"}. If {@code null}, version
      * {@code "2.0"} will be used by default.
      */
     @NonNull
-    private final String mEntitlementVersion;
+    protected abstract String entitlementVersion();
 
     /** The entitlement server address. */
     @NonNull
-    private final URL mEntitlementServerAddress;
+    protected abstract URL entitlementServerAddress();
 
     /**
-     * The authentication token used for TS.43 operation. This token could be automatically updated
-     * after each TS.43 operation if the server provides the new token in the operation's HTTP
-     * response.
+     * The initial authentication token used for TS.43 operation. This token might be only used for
+     * the first time. Later if the server provides a new token in the operation's HTTP response,
+     * the new token will be saved into {@link #mAuthToken}. Empty string if the initial token is
+     * not available.
      */
-    @Nullable
-    private String mAuthToken;
+    @NonNull
+    protected abstract String initialAuthToken();
 
     /**
      * The temporary token retrieved from {@link
-     * #acquireTemporaryToken(AcquireTemporaryTokenRequest)}.
+     * #acquireTemporaryToken(AcquireTemporaryTokenRequest)}. Empty string if it's not available.
      */
-    @Nullable
-    private String mTemporaryToken;
+    @NonNull
+    protected abstract String temporaryToken();
 
-    /**
-     * Token type. When token type is {@link #TOKEN_TYPE_NORMAL}, {@link #mAuthToken} is used. When
-     * toke type is {@link #TOKEN_TYPE_TEMPORARY}, {@link #mTemporaryToken} is used.
-     */
-    @TokenType
-    private int mTokenType;
+    /** The logical SIM slot index involved in ODSA operation. */
+    protected abstract int slotIndex();
+
+    /** The requesting application name. Empty string if it's not available. */
+    @NonNull
+    protected abstract String appName();
 
-    private final ServiceEntitlement mServiceEntitlement;
+    /** The requesting application version. Empty string if it's not available. */
+    @NonNull
+    protected abstract String appVersion();
+
+    /** Carrier configuration. */
+    @Nullable
+    protected abstract CarrierConfig carrierConfig();
 
     /** IMEI of the device. */
-    private final String mImei;
+    @NonNull
+    protected abstract String imei();
+
+    @Nullable
+    protected abstract ServiceEntitlement serviceEntitlement();
 
-    /** used to identify the requesting application. Optional */
+    /**
+     * The auto token provided by the server in the operation's HTTP response. Empty string if it's
+     * not available.
+     */
     @NonNull
-    private final String mAppName;
+    private String mAuthToken = "";
 
     /**
-     * Constructor of Ts43Operation.
+     * Builder for {@link Ts43Operation}.
      *
-     * @param slotIndex The logical SIM slot index involved in ODSA operation.
-     * @param entitlementServerAddress The entitlement server address.
-     * @param entitlementVersion The TS.43 entitlement version to use. For example,
-     *                           {@code "9.0"}. If {@code null}, version {@code "2.0"} will be used
-     *                           by default.
-     * @param authToken The authentication token.
-     * @param tokenType The token type. Can be {@link #TOKEN_TYPE_NORMAL} or
-     *                  {@link #TOKEN_TYPE_TEMPORARY}.
-     * @param appName The name of the device application making the request or empty string
-     *                if unspecified.
+     * <p>This class provides a fluent interface for constructing instances of
+     * {@link Ts43Operation}. In order to build the {@link Ts43Operation} object,the following
+     * mandatory methods must be called: {@link #setContext(Context)},
+     * {@link #setEntitlementServerAddress(URL)}, and either {@link #setInitialAuthToken(String)}}
+     * or {@link #setTemporaryToken(String)} must be called.
      */
-    public Ts43Operation(
-            @NonNull Context context,
-            int slotIndex,
-            @NonNull URL entitlementServerAddress,
-            @Nullable String entitlementVersion,
-            @NonNull String authToken,
-            @TokenType int tokenType,
-            @NonNull String appName) {
-        mContext = context;
-        mEntitlementServerAddress = entitlementServerAddress;
-        if (entitlementVersion != null) {
-            mEntitlementVersion = entitlementVersion;
-        } else {
-            mEntitlementVersion = Ts43Constants.DEFAULT_ENTITLEMENT_VERSION;
-        }
-
-        if (tokenType == TOKEN_TYPE_NORMAL) {
-            mAuthToken = authToken;
-        } else if (tokenType == TOKEN_TYPE_TEMPORARY) {
-            mTemporaryToken = authToken;
-        } else {
-            throw new IllegalArgumentException("Invalid token type " + tokenType);
-        }
-        mTokenType = tokenType;
+    @AutoValue.Builder
+    public abstract static class Builder {
+        /**
+         * Sets the application context to be used by the built object.
+         * <p>
+         * This context will be used for various operations, such as accessing resources,
+         * starting activities, and interacting with system services.
+         * </p>
+         * <p>
+         * It is crucial to provide a valid and appropriate context here. Typically,
+         * this should be an {@link android.app.Application} context or an {@link Context}
+         * associated with an activity that outlives the built object. Using an activity
+         * context that might be destroyed before the built object can lead to memory
+         * leaks or unexpected behavior.
+         * </p>
+         *
+         * @param context The application context to use. Must not be null.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setContext(@NonNull Context context);
+
+        /**
+         * Sets the TS.43 entitlement version to use.
+         *
+         * @param version The TS.43 entitlement version to use. For example, {@code "9.0"}.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setEntitlementVersion(@NonNull String version);
+
+        /**
+         * Sets the entitlement server address.
+         *
+         * @param url The entitlement server address.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setEntitlementServerAddress(@NonNull URL url);
+
+        /**
+         * Sets the initial authentication token used for TS.43 operation. This token might be only
+         * used for the first time. Later if the server provides a new token in the operation's HTTP
+         * response, the new token will be saved into {@link #mAuthToken}.
+         *
+         * @param token The initial authentication token.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setInitialAuthToken(@NonNull String token);
+
+        /**
+         * Sets the temporary token retrieved from
+         * {@link #acquireTemporaryToken(AcquireTemporaryTokenRequest)}
+         *
+         * @param token The temporary token.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setTemporaryToken(@NonNull String token);
+
+        /**
+         * Sets the logical SIM slot index involved in ODSA operation.
+         *
+         * @param index The logical SIM slot index.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setSlotIndex(int index);
+
+        /**
+         * Sets the name of the requesting application.
+         *
+         * @param name The name of the requesting application.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setAppName(@NonNull String name);
+
+        /**
+         * Sets the version of the requesting application.
+         *
+         * @param version The version of the requesting application.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setAppVersion(@NonNull String version);
+
+        /**
+         * Sets the carrier configuration.
+         *
+         * @param carrierConfig The carrier configuration.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        public abstract Builder setCarrierConfig(@Nullable CarrierConfig carrierConfig);
+
+        /**
+         * Sets the IMEI of the device.
+         *
+         * @param imei The IMEI of the device.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @NonNull
+        protected abstract Builder setImei(@NonNull String imei);
+
+        /**
+         * Sets the service entitlement. This method is for testing only.
+         *
+         * @param serviceEntitlement The service entitlement.
+         *
+         * @return This {@code Builder} object for method chaining.
+         */
+        @VisibleForTesting
+        @NonNull
+        abstract Builder setServiceEntitlement(
+                @Nullable ServiceEntitlement serviceEntitlement);
+
+        /**
+         * @return The application context to use.
+         */
+        @NonNull
+        protected abstract Context context();
+
+        /**
+         * @return The initial authentication token.
+         */
+        @NonNull
+        protected abstract String initialAuthToken();
+
+        /**
+         * @return the temporary token retrieved from
+         * {@link #acquireTemporaryToken(AcquireTemporaryTokenRequest)}.
+         */
+        @NonNull
+        protected abstract String temporaryToken();
+
+        /**
+         * @return The carrier config.
+         */
+        @Nullable
+        protected abstract CarrierConfig carrierConfig();
+
+        /**
+         * @return The logical SIM slot index involved in ODSA operation.
+         */
+        protected abstract int slotIndex();
+
+        /**
+         * @return The service entitlement.
+         */
+        @Nullable
+        protected abstract ServiceEntitlement serviceEntitlement();
+
+        /** The entitlement server address. */
+        @NonNull
+        protected abstract URL entitlementServerAddress();
+
+        /**
+         * Builds the {@link Ts43Operation} object. (AutoValue generates its implementation).
+         *
+         * @return The built {@link Ts43Operation} object.
+         */
+        @NonNull
+        protected abstract Ts43Operation autoBuild();
+
+        /**
+         * Builds the {@link Ts43Operation} object.
+         *
+         * @return The built {@link Ts43Operation} object.
+         */
+        @NonNull
+        public Ts43Operation build() {
+            if (TextUtils.isEmpty(initialAuthToken()) && TextUtils.isEmpty(temporaryToken())) {
+                throw new IllegalArgumentException("Either initialAuthToken or temporaryToken "
+                        + "must be set.");
+            }
 
-        CarrierConfig carrierConfig =
-                CarrierConfig.builder().setServerUrl(mEntitlementServerAddress.toString()).build();
+            CarrierConfig carrierConfig = carrierConfig();
+            if (carrierConfig == null) {
+                carrierConfig = CarrierConfig.builder()
+                        .setServerUrl(entitlementServerAddress().toString())
+                        .build();
+                setCarrierConfig(carrierConfig);
+            }
 
-        mServiceEntitlement =
-                new ServiceEntitlement(
-                        mContext, carrierConfig, SubscriptionManager.getSubscriptionId(slotIndex));
+            if (serviceEntitlement() == null) {
+                setServiceEntitlement(new ServiceEntitlement(context(),
+                        carrierConfig, SubscriptionManager.getSubscriptionId(slotIndex())));
+            }
 
-        String imei = null;
-        TelephonyManager telephonyManager = mContext.getSystemService(TelephonyManager.class);
-        if (telephonyManager != null) {
-            if (slotIndex < 0 || slotIndex >= telephonyManager.getActiveModemCount()) {
-                throw new IllegalArgumentException("getAuthToken: invalid slot index " + slotIndex);
+            String imei = null;
+            TelephonyManager telephonyManager = context().getSystemService(TelephonyManager.class);
+            if (telephonyManager != null) {
+                if (slotIndex() < 0 || slotIndex() >= telephonyManager.getActiveModemCount()) {
+                    throw new IllegalArgumentException("Ts43Operation: invalid slot index "
+                            + slotIndex());
+                }
+                imei = telephonyManager.getImei(slotIndex());
             }
-            imei = telephonyManager.getImei(slotIndex);
+            setImei(Strings.nullToEmpty(imei));
+
+            // Auto generate the rest of the fields
+            return autoBuild();
         }
-        mImei = Strings.nullToEmpty(imei);
-        mAppName = appName;
+    }
+
+    /** Returns a new {@link Ts43Operation.Builder} object. */
+    public static Ts43Operation.Builder builder() {
+        return new AutoValue_Ts43Operation.Builder()
+                .setEntitlementVersion(Ts43Constants.DEFAULT_ENTITLEMENT_VERSION)
+                .setInitialAuthToken("")
+                .setTemporaryToken("")
+                .setSlotIndex(SubscriptionManager.getDefaultSubscriptionId())
+                .setAppName("")
+                .setAppVersion("")
+                .setServiceEntitlement(null)
+                .setCarrierConfig(null);
+    }
+
+    /**
+     * @return The initial service entitlement request builder.
+     */
+    @NonNull
+    private ServiceEntitlementRequest.Builder getServiceEntitlementRequestBuilder() {
+        ServiceEntitlementRequest.Builder builder =
+                ServiceEntitlementRequest.builder()
+                        .setEntitlementVersion(entitlementVersion())
+                        .setTerminalId(imei())
+                        .setAppName(appName())
+                        .setAppVersion(appVersion());
+        if (!TextUtils.isEmpty(temporaryToken())) {
+            builder.setTemporaryToken(temporaryToken());
+        } else if (!TextUtils.isEmpty(mAuthToken)) {
+            builder.setAuthenticationToken(mAuthToken);
+        } else if (!TextUtils.isEmpty(initialAuthToken())) {
+            builder.setAuthenticationToken(initialAuthToken());
+        }
+
+        return builder;
     }
 
     /**
@@ -206,17 +406,7 @@ public class Ts43Operation {
             throws ServiceEntitlementException {
         Objects.requireNonNull(checkEligibilityRequest);
 
-        ServiceEntitlementRequest.Builder builder =
-                ServiceEntitlementRequest.builder()
-                        .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(mImei)
-                        .setAppName(mAppName);
-
-        if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(checkNotNull(mAuthToken));
-        } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
-        }
+        ServiceEntitlementRequest.Builder builder = getServiceEntitlementRequestBuilder();
 
         String notificationToken = checkEligibilityRequest.notificationToken();
         if (!TextUtils.isEmpty(notificationToken)) {
@@ -244,9 +434,8 @@ public class Ts43Operation {
 
         String rawXml;
         try {
-            rawXml =
-                    mServiceEntitlement.performEsimOdsa(checkEligibilityRequest.appId(), request,
-                            operation);
+            rawXml = checkNotNull(serviceEntitlement()).performEsimOdsa(
+                    checkEligibilityRequest.appId(), request, operation);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "manageSubscription: Failed to perform ODSA operation. e=" + e);
             throw e;
@@ -308,7 +497,7 @@ public class Ts43Operation {
         }
 
         // Parse notEnabledURL
-        URL notEnabledURL = null;
+        URL notEnabledURL;
         String notEnabledURLString =
                 ts43XmlDoc.get(
                         ImmutableList.of(Ts43XmlDoc.CharacteristicType.APPLICATION),
@@ -369,18 +558,8 @@ public class Ts43Operation {
             throws ServiceEntitlementException {
         Objects.requireNonNull(manageSubscriptionRequest);
 
-        ServiceEntitlementRequest.Builder builder =
-                ServiceEntitlementRequest.builder()
-                        .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(mImei)
-                        .setAppName(mAppName)
-                        .setAcceptContentType(ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
-
-        if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(checkNotNull(mAuthToken));
-        } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
-        }
+        ServiceEntitlementRequest.Builder builder = getServiceEntitlementRequestBuilder()
+                .setAcceptContentType(ServiceEntitlementRequest.ACCEPT_CONTENT_TYPE_XML);
 
         String notificationToken = manageSubscriptionRequest.notificationToken();
         if (!TextUtils.isEmpty(notificationToken)) {
@@ -431,9 +610,8 @@ public class Ts43Operation {
 
         String rawXml;
         try {
-            rawXml =
-                    mServiceEntitlement.performEsimOdsa(
-                            manageSubscriptionRequest.appId(), request, operation);
+            rawXml = checkNotNull(serviceEntitlement()).performEsimOdsa(
+                    manageSubscriptionRequest.appId(), request, operation);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "manageSubscription: Failed to perform ODSA operation. e=" + e);
             throw e;
@@ -567,19 +745,7 @@ public class Ts43Operation {
             throws ServiceEntitlementException {
         Objects.requireNonNull(manageServiceRequest);
 
-        ServiceEntitlementRequest.Builder builder =
-                ServiceEntitlementRequest.builder()
-                        .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(mImei)
-                        .setAppName(mAppName);
-
-        if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(checkNotNull(mAuthToken));
-        } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
-        }
-
-        ServiceEntitlementRequest request = builder.build();
+        ServiceEntitlementRequest request = getServiceEntitlementRequestBuilder().build();
 
         EsimOdsaOperation operation =
                 EsimOdsaOperation.builder()
@@ -599,9 +765,8 @@ public class Ts43Operation {
 
         String rawXml;
         try {
-            rawXml =
-                    mServiceEntitlement.performEsimOdsa(manageServiceRequest.appId(), request,
-                            operation);
+            rawXml = checkNotNull(serviceEntitlement()).performEsimOdsa(
+                    manageServiceRequest.appId(), request, operation);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "manageService: Failed to perform ODSA operation. e=" + e);
             throw e;
@@ -650,11 +815,7 @@ public class Ts43Operation {
             throws ServiceEntitlementException {
         Objects.requireNonNull(acquireConfigurationRequest);
 
-        ServiceEntitlementRequest.Builder builder = ServiceEntitlementRequest.builder()
-                .setEntitlementVersion(mEntitlementVersion)
-                .setTerminalId(mImei)
-                .setAppName(mAppName)
-                .setAuthenticationToken(checkNotNull(mAuthToken));
+        ServiceEntitlementRequest.Builder builder = getServiceEntitlementRequestBuilder();
 
         String notificationToken = acquireConfigurationRequest.notificationToken();
         if (!TextUtils.isEmpty(notificationToken)) {
@@ -683,9 +844,8 @@ public class Ts43Operation {
 
         String rawXml;
         try {
-            rawXml =
-                    mServiceEntitlement.performEsimOdsa(
-                            acquireConfigurationRequest.appId(), request, operation);
+            rawXml = checkNotNull(serviceEntitlement()).performEsimOdsa(
+                    acquireConfigurationRequest.appId(), request, operation);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "acquireConfiguration: Failed to perform ODSA operation. e=" + e);
             throw e;
@@ -811,13 +971,7 @@ public class Ts43Operation {
             throws ServiceEntitlementException {
         Objects.requireNonNull(acquireTemporaryTokenRequest);
 
-        ServiceEntitlementRequest request =
-                ServiceEntitlementRequest.builder()
-                        .setEntitlementVersion(mEntitlementVersion)
-                        .setTerminalId(mImei)
-                        .setAuthenticationToken(checkNotNull(mAuthToken))
-                        .setAppName(mAppName)
-                        .build();
+        ServiceEntitlementRequest request = getServiceEntitlementRequestBuilder().build();
 
         EsimOdsaOperation operation =
                 EsimOdsaOperation.builder()
@@ -828,9 +982,8 @@ public class Ts43Operation {
 
         String rawXml;
         try {
-            rawXml =
-                    mServiceEntitlement.performEsimOdsa(
-                            acquireTemporaryTokenRequest.appId(), request, operation);
+            rawXml = checkNotNull(serviceEntitlement()).performEsimOdsa(
+                    acquireTemporaryTokenRequest.appId(), request, operation);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "acquireTemporaryToken: Failed to perform ODSA operation. e=" + e);
             throw e;
@@ -855,10 +1008,8 @@ public class Ts43Operation {
                                 ImmutableList.of(Ts43XmlDoc.CharacteristicType.APPLICATION),
                                 Ts43XmlDoc.Parm.OPERATION_TARGETS));
 
-        if (operationTargets != null) {
-            List<String> operationTargetsList = Arrays.asList(operationTargets.split("\\s*,\\s*"));
-            responseBuilder.setOperationTargets(ImmutableList.copyOf(operationTargetsList));
-        }
+        List<String> operationTargetsList = Arrays.asList(operationTargets.split("\\s*,\\s*"));
+        responseBuilder.setOperationTargets(ImmutableList.copyOf(operationTargetsList));
 
         // Parse the temporary token
         String temporaryToken =
@@ -905,23 +1056,14 @@ public class Ts43Operation {
     public GetPhoneNumberResponse getPhoneNumber(
             @NonNull GetPhoneNumberRequest getPhoneNumberRequest)
             throws ServiceEntitlementException {
-        ServiceEntitlementRequest.Builder builder =
-                ServiceEntitlementRequest.builder()
-                        .setEntitlementVersion(mEntitlementVersion);
+
+        ServiceEntitlementRequest.Builder builder = getServiceEntitlementRequestBuilder();
 
         if (!TextUtils.isEmpty(getPhoneNumberRequest.terminalId())) {
             builder.setTerminalId(getPhoneNumberRequest.terminalId());
-        } else {
-            builder.setTerminalId(mImei);
-        }
-
-        if (mTokenType == TOKEN_TYPE_NORMAL) {
-            builder.setAuthenticationToken(checkNotNull(mAuthToken));
-        } else if (mTokenType == TOKEN_TYPE_TEMPORARY) {
-            builder.setTemporaryToken(checkNotNull(mTemporaryToken));
         }
 
-        ServiceEntitlementRequest request = builder.setAppName(mAppName).build();
+        ServiceEntitlementRequest request = builder.build();
 
         EsimOdsaOperation operation =
                 EsimOdsaOperation.builder()
@@ -930,9 +1072,8 @@ public class Ts43Operation {
 
         String rawXml;
         try {
-            rawXml =
-                    mServiceEntitlement.performEsimOdsa(
-                        Ts43Constants.APP_PHONE_NUMBER_INFORMATION, request, operation);
+            rawXml = checkNotNull(serviceEntitlement()).performEsimOdsa(
+                    Ts43Constants.APP_PHONE_NUMBER_INFORMATION, request, operation);
         } catch (ServiceEntitlementException e) {
             Log.w(TAG, "getPhoneNumber: Failed to perform ODSA operation. e=" + e);
             throw e;
diff --git a/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java b/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
index 57bc0aa..359f325 100644
--- a/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
+++ b/tests/src/com/android/libraries/entitlement/Ts43OperationTest.java
@@ -18,11 +18,13 @@ package com.android.libraries.entitlement;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assert.assertThrows;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.verify;
 
+import android.annotation.NonNull;
 import android.content.Context;
 import android.telephony.TelephonyManager;
 import android.testing.AndroidTestingRunner;
@@ -53,7 +55,6 @@ import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
-import java.lang.reflect.Field;
 import java.net.URL;
 
 @RunWith(AndroidTestingRunner.class)
@@ -88,6 +89,7 @@ public class Ts43OperationTest {
 
     private static final String GENERAL_ERROR_TEXT = "error text";
     private static final String APP_NAME = "Ts43OperationTest.class";
+    private static final String APP_VERSION = "1.0";
 
     private static final String MANAGE_SUBSCRIPTION_RESPONSE_CONTINUE_TO_WEBSHEET =
             "<?xml version=\"1.0\"?>"
@@ -321,12 +323,72 @@ public class Ts43OperationTest {
                 .getSystemServiceName(TelephonyManager.class);
         doReturn(mTelephonyManager).when(mContext).getSystemService(Context.TELEPHONY_SERVICE);
 
-        mTs43Operation = new Ts43Operation(mContext, 0, new URL(TEST_URL),
-                ENTITLEMENT_VERSION, TOKEN, Ts43Operation.TOKEN_TYPE_NORMAL, APP_NAME);
+        mTs43Operation = Ts43Operation.builder()
+                .setContext(mContext)
+                .setSlotIndex(0)
+                .setEntitlementServerAddress(new URL(TEST_URL))
+                .setEntitlementVersion(ENTITLEMENT_VERSION)
+                .setInitialAuthToken(TOKEN)
+                .setAppName(APP_NAME)
+                .setAppVersion(APP_VERSION)
+                .setCarrierConfig(carrierConfig)
+                .setServiceEntitlement(serviceEntitlement)
+                .build();
+    }
+
+    @Test
+    public void testBuilder() throws Exception {
+        assertThat(Ts43Operation.builder()).isNotNull();
+
+        // Exception should be thrown if required fields are missing
+        assertThrows(IllegalArgumentException.class, () -> Ts43Operation.builder().build());
+        // Exception should be thrown if required fields are missing
+        assertThrows(IllegalArgumentException.class, () -> Ts43Operation.builder()
+                .setContext(mContext).build());
+
+        // Exception should be thrown if required fields are missing
+        assertThrows(IllegalArgumentException.class, () -> Ts43Operation.builder()
+                .setEntitlementServerAddress(new URL(TEST_URL)).build());
+
+        // Exception should be thrown if required fields are missing
+        assertThrows(IllegalArgumentException.class, () -> Ts43Operation.builder()
+                .setContext(mContext)
+                .setEntitlementServerAddress(new URL(TEST_URL)).build());
+
+        assertThat(Ts43Operation.builder()
+                .setContext(mContext)
+                .setEntitlementServerAddress(new URL(TEST_URL))
+                .setInitialAuthToken("token")
+                .build()).isNotNull();
+
+        assertThat(Ts43Operation.builder()
+                .setContext(mContext)
+                .setEntitlementServerAddress(new URL(TEST_URL))
+                .setTemporaryToken("temp token")
+                .build()).isNotNull();
+
+        // Exception should be thrown if slot index is invalid
+        assertThrows(IllegalArgumentException.class, () -> Ts43Operation.builder()
+                .setContext(mContext)
+                .setSlotIndex(3)
+                .setEntitlementServerAddress(new URL(TEST_URL))
+                .setInitialAuthToken("token")
+                .build());
+    }
 
-        Field field = Ts43Operation.class.getDeclaredField("mServiceEntitlement");
-        field.setAccessible(true);
-        field.set(mTs43Operation, serviceEntitlement);
+    private void verifyOdsaOperation(@NonNull String expectedOperation) throws Exception {
+        ArgumentCaptor<ServiceEntitlementRequest> captor =
+                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
+        ArgumentCaptor<EsimOdsaOperation> operationCaptor =
+                ArgumentCaptor.forClass(EsimOdsaOperation.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(),
+                operationCaptor.capture(), any());
+        assertThat(captor.getValue().appName()).isEqualTo(APP_NAME);
+        assertThat(captor.getValue().appVersion()).isEqualTo(APP_VERSION);
+        assertThat(captor.getValue().entitlementVersion()).isEqualTo(ENTITLEMENT_VERSION);
+        assertThat(captor.getValue().terminalId()).isEqualTo(IMEI);
+
+        assertThat(operationCaptor.getValue().operation()).isEqualTo(expectedOperation);
     }
 
     @Test
@@ -350,11 +412,7 @@ public class Ts43OperationTest {
         assertThat(response.subscriptionServiceUserData())
                 .isEqualTo(SUBSCRIPTION_SERVICE_USER_DATA);
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_MANAGE_SUBSCRIPTION);
     }
 
     @Test
@@ -378,11 +436,7 @@ public class Ts43OperationTest {
         assertThat(response.downloadInfo().profileSmdpAddresses())
                 .isEqualTo(ImmutableList.of(PROFILE_SMDP_ADDRESS));
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_MANAGE_SUBSCRIPTION);
     }
 
     @Test
@@ -406,11 +460,7 @@ public class Ts43OperationTest {
                 ManageSubscriptionResponse.SUBSCRIPTION_RESULT_REQUIRES_USER_INPUT);
         assertThat(response.generalErrorText()).isEqualTo(GENERAL_ERROR_TEXT);
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_MANAGE_SUBSCRIPTION);
     }
 
     @Test
@@ -433,11 +483,7 @@ public class Ts43OperationTest {
                 EsimOdsaOperation.OPERATION_MANAGE_SUBSCRIPTION,
                 EsimOdsaOperation.OPERATION_ACQUIRE_CONFIGURATION));
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_ACQUIRE_TEMPORARY_TOKEN);
     }
 
     @Test
@@ -459,11 +505,7 @@ public class Ts43OperationTest {
                 ImmutableList.of(PROFILE_SMDP_ADDRESS));
         assertThat(config.serviceStatus()).isEqualTo(EsimOdsaOperation.SERVICE_STATUS_ACTIVATED);
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_ACQUIRE_CONFIGURATION);
     }
 
     @Test
@@ -488,11 +530,7 @@ public class Ts43OperationTest {
         assertThat(config.messageInfo().acceptFreetext()).isEqualTo(MESSAGE_ACCEPT_PRESENT);
         assertThat(config.serviceStatus()).isEqualTo(EsimOdsaOperation.SERVICE_STATUS_ACTIVATED);
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_ACQUIRE_CONFIGURATION);
     }
 
     @Test
@@ -513,11 +551,7 @@ public class Ts43OperationTest {
         assertThat(response.notEnabledUrl()).isEqualTo(new URL(NOT_ENABLED_URL));
         assertThat(response.notEnabledUserData()).isEqualTo(NOT_ENABLED_USER_DATA);
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_CHECK_ELIGIBILITY);
     }
 
     @Test
@@ -533,11 +567,7 @@ public class Ts43OperationTest {
         assertThat(response.serviceStatus()).isEqualTo(
                 EsimOdsaOperation.SERVICE_STATUS_DEACTIVATED);
 
-        ArgumentCaptor<ServiceEntitlementRequest> captor =
-                ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        verifyOdsaOperation(EsimOdsaOperation.OPERATION_MANAGE_SERVICE);
     }
 
     @Test
@@ -555,8 +585,16 @@ public class Ts43OperationTest {
 
         ArgumentCaptor<ServiceEntitlementRequest> captor =
                 ArgumentCaptor.forClass(ServiceEntitlementRequest.class);
-        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(), any(),
-                any());
-        assertThat(captor.getValue().appName()).contains(APP_NAME);
+        ArgumentCaptor<EsimOdsaOperation> operationCaptor =
+                ArgumentCaptor.forClass(EsimOdsaOperation.class);
+        verify(mMockEapAkaApi).performEsimOdsaOperation(any(), any(), captor.capture(),
+                operationCaptor.capture(), any());
+        assertThat(captor.getValue().appName()).isEqualTo(APP_NAME);
+        assertThat(captor.getValue().appVersion()).isEqualTo(APP_VERSION);
+        assertThat(captor.getValue().entitlementVersion()).isEqualTo(ENTITLEMENT_VERSION);
+        assertThat(captor.getValue().terminalId()).isEqualTo(TERMINAL_ID);
+
+        assertThat(operationCaptor.getValue().operation()).isEqualTo(
+                EsimOdsaOperation.OPERATION_GET_PHONE_NUMBER);
     }
 }
```

